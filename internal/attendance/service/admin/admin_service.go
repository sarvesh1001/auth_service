package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
	auditservice "auth-service/internal/infrastructure/audit"
)

// AdminService handles policy, rule, profile, and correction administration.
type AdminService interface {
	// Policy management
	CreateAttendancePolicy(ctx context.Context, policy *models.AttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.AttendancePolicy, error)
	UpdateAttendancePolicy(ctx context.Context, policy *models.AttendancePolicy) error
	DeleteAttendancePolicy(ctx context.Context, policyID uuid.UUID) error
	AssignUserAttendancePolicy(ctx context.Context, userPolicy *models.UserAttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	EndUserAttendancePolicy(ctx context.Context, userID, policyID uuid.UUID, endDate time.Time) error
	GetPositionAttendancePolicy(ctx context.Context, positionID uuid.UUID) (*models.AttendancePolicy, error)
	GetUsersByAttendancePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error)

	// NEW: Polymorphic policy methods
	AssignPolicyToSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, assignedBy *uuid.UUID) error
	EndPolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, endDate time.Time) error
	GetActivePolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, date time.Time) (*models.AttendancePolicy, error)

	// Company & department rules
	GetCompanyAttendanceRules(ctx context.Context, companyID uuid.UUID) (*models.CompanyAttendanceRules, error)
	UpdateCompanyAttendanceRules(ctx context.Context, rules *models.CompanyAttendanceRules, updatedBy uuid.UUID) error
	GetDepartmentAttendanceRules(ctx context.Context, companyID, departmentID uuid.UUID) (*models.DepartmentAttendanceRules, error)
	UpsertDepartmentAttendanceRules(ctx context.Context, rules *models.DepartmentAttendanceRules) error

	// User attendance profile (overrides)
	GetUserAttendanceProfile(ctx context.Context, userID uuid.UUID) (*models.UserAttendanceProfile, error)
	UpsertUserAttendanceProfile(ctx context.Context, profile *models.UserAttendanceProfile) error

	// Rule resolution (used by ingest)
	// CHANGED: added subjectType parameter
	ResolveAttendanceRules(ctx context.Context, userID, companyID uuid.UUID, subjectType string, workCenterCode string, positionID *uuid.UUID, date time.Time) (*models.ResolvedAttendanceRules, error)

	// Validation helpers
	ValidateAttendanceEventType(ctx context.Context, eventType string) error
	ValidateAttendanceSourceType(ctx context.Context, sourceType string, sourceID *uuid.UUID) error

	// Health
	HealthCheck(ctx context.Context) error
}

type adminService struct {
	eventRepo    repository.EventRepository
	policyRepo   repository.PolicyRepository
	ruleRepo     repository.RuleRepository
	sourceRepo   repository.SourceRepository
	scheduleRepo repository.ScheduleRepository // for work center lookup, etc.
	resolver     resolver.SubjectResolver
	logger       *zap.Logger
	audit        *auditservice.AuditService
}

func NewAdminService(
	eventRepo repository.EventRepository,
	policyRepo repository.PolicyRepository,
	ruleRepo repository.RuleRepository,
	sourceRepo repository.SourceRepository,
	scheduleRepo repository.ScheduleRepository,
	resolver resolver.SubjectResolver,
	logger *zap.Logger,
	audit *auditservice.AuditService,
) AdminService {
	return &adminService{
		eventRepo:    eventRepo,
		policyRepo:   policyRepo,
		ruleRepo:     ruleRepo,
		sourceRepo:   sourceRepo,
		scheduleRepo: scheduleRepo,
		resolver:     resolver,
		logger:       logger,
		audit:        audit,
	}
}

// ------------------------------------------------------------
// Policy management
// ------------------------------------------------------------

func (s *adminService) CreateAttendancePolicy(ctx context.Context, policy *models.AttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.AttendancePolicy, error) {
	if err := s.validatePolicy(policy); err != nil {
		return nil, err
	}
	// Check duplicate policy code
	existing, err := s.policyRepo.GetPoliciesByCompany(ctx, policy.CompanyID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing policies: %w", err)
	}
	for _, p := range existing {
		if p.PolicyCode == policy.PolicyCode {
			return nil, fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
		}
	}
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.policyRepo.CreatePolicy(ctx, tx, policy); err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.logAudit(ctx, policy.CompanyID, "attendance_policy.create", policy.PolicyID, actorType, actorID, nil, policy, metadata)
	s.logger.Info("Attendance policy created", zap.String("policy_id", policy.PolicyID.String()), zap.String("policy_code", policy.PolicyCode))
	return policy, nil
}

func (s *adminService) UpdateAttendancePolicy(ctx context.Context, policy *models.AttendancePolicy) error {
	if err := s.validatePolicy(policy); err != nil {
		return err
	}
	existing, err := s.policyRepo.GetPolicyByID(ctx, policy.PolicyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("policy not found")
	}
	// Duplicate code check (excluding self)
	all, err := s.policyRepo.GetPoliciesByCompany(ctx, policy.CompanyID, false)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	for _, p := range all {
		if p.PolicyID != policy.PolicyID && p.PolicyCode == policy.PolicyCode {
			return fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
		}
	}
	policy.UpdatedAt = time.Now().UTC()

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.policyRepo.UpdatePolicy(ctx, tx, policy); err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	return tx.Commit()
}

func (s *adminService) DeleteAttendancePolicy(ctx context.Context, policyID uuid.UUID) error {
	policy, err := s.policyRepo.GetPolicyByID(ctx, policyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("policy not found")
	}
	// Check if assigned to any users
	users, err := s.policyRepo.GetUsersByPolicy(ctx, policyID, time.Now())
	if err != nil {
		return fmt.Errorf("check users: %w", err)
	}
	if len(users) > 0 {
		return fmt.Errorf("cannot delete policy assigned to %d users", len(users))
	}
	// Also check for other subjects (students, teachers)
	// TODO: implement cross-subject check if needed

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.policyRepo.DeletePolicy(ctx, policyID); err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	return tx.Commit()
}

// =============================================================================
// NEW POLYMORPHIC POLICY METHODS (for any subject)
// =============================================================================

// AssignPolicyToSubject assigns a policy to any subject (employee, student, teacher, etc.)
func (s *adminService) AssignPolicyToSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, assignedBy *uuid.UUID) error {
	if subjectType == "" || subjectID == uuid.Nil {
		return errors.New("subject_type and subject_id are required")
	}
	if policyID == uuid.Nil {
		return errors.New("policy_id is required")
	}
	if effectiveFrom.IsZero() {
		effectiveFrom = time.Now().UTC()
	}
	// Validate policy exists and is active
	policy, err := s.policyRepo.GetPolicyByID(ctx, policyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}
	if policy == nil || !policy.IsActive {
		return errors.New("policy not active or not found")
	}

	// Idempotency: check if exact assignment already exists
	// We'll use a helper method to find assignment by subject
	existing, err := s.policyRepo.GetActivePolicyBySubject(ctx, subjectType, subjectID, effectiveFrom)
	if err == nil && existing != nil {
		// If the active policy at that date is the same, return success
		if existing.PolicyID == policyID {
			s.logger.Info("Policy already assigned to subject (idempotent)",
				zap.String("subject_type", subjectType),
				zap.String("subject_id", subjectID.String()),
				zap.String("policy_id", policyID.String()),
				zap.Time("effective_from", effectiveFrom))
			return nil
		}
		// Otherwise, end the current active policy before assigning the new one
		_ = s.EndPolicyForSubject(ctx, subjectType, subjectID, existing.PolicyID, effectiveFrom)
	}

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.policyRepo.AssignPolicyToSubject(ctx, tx, subjectType, subjectID, policyID, &effectiveFrom, effectiveTo, assignedBy); err != nil {
		return fmt.Errorf("assign policy to subject: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	s.logger.Info("Policy assigned to subject",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("policy_id", policyID.String()),
		zap.Time("effective_from", effectiveFrom))
	return nil
}

// EndPolicyForSubject ends an active policy for a given subject
func (s *adminService) EndPolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, endDate time.Time) error {
	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}
	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.policyRepo.EndPolicyForSubject(ctx, subjectType, subjectID, policyID, endDate); err != nil {
		return fmt.Errorf("end policy for subject: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Info("Policy ended for subject",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("policy_id", policyID.String()),
		zap.Time("end_date", endDate))
	return nil
}

// GetActivePolicyForSubject retrieves the active policy for a given subject at a given date
func (s *adminService) GetActivePolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, date time.Time) (*models.AttendancePolicy, error) {
	return s.policyRepo.GetActivePolicyBySubject(ctx, subjectType, subjectID, date)
}

// =============================================================================
// LEGACY EMPLOYEE METHODS (kept for backward compatibility)
// =============================================================================

// AssignUserAttendancePolicy is the legacy employee-only assignment method.
// It now populates SubjectType="employee" and SubjectID=userID before calling the repository.
func (s *adminService) AssignUserAttendancePolicy(ctx context.Context, userPolicy *models.UserAttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	if userPolicy.UserID == uuid.Nil || userPolicy.PolicyID == uuid.Nil {
		return fmt.Errorf("user_id and policy_id required")
	}
	if userPolicy.EffectiveFrom.IsZero() {
		userPolicy.EffectiveFrom = time.Now().UTC()
	}
	// Set polymorphic fields for employees
	if userPolicy.SubjectType == "" {
		userPolicy.SubjectType = "employee"
	}
	if userPolicy.SubjectID == nil {
		userPolicy.SubjectID = &userPolicy.UserID
	}

	policy, err := s.policyRepo.GetPolicyByID(ctx, userPolicy.PolicyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}
	if policy == nil || !policy.IsActive {
		return fmt.Errorf("policy not active")
	}

	// Idempotency check
	existing, err := s.policyRepo.GetUserPolicyAssignment(ctx, userPolicy.UserID, userPolicy.PolicyID, userPolicy.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("check existing assignment: %w", err)
	}
	if existing != nil {
		s.logger.Info("Policy already assigned to user (idempotent)",
			zap.String("user_id", userPolicy.UserID.String()),
			zap.String("policy_id", userPolicy.PolicyID.String()),
			zap.Time("effective_from", userPolicy.EffectiveFrom))
		return nil
	}

	// End any previous active policy (if different)
	active, err := s.policyRepo.GetActivePolicyBySubject(ctx, "employee", userPolicy.UserID, userPolicy.EffectiveFrom)
	if err == nil && active != nil && active.PolicyID != userPolicy.PolicyID {
		_ = s.policyRepo.EndPolicyForSubject(ctx, "employee", userPolicy.UserID, active.PolicyID, userPolicy.EffectiveFrom)
	}

	if userPolicy.AssignedBy == nil {
		userPolicy.AssignedBy = &actorID
	}
	if userPolicy.CreatedAt.IsZero() {
		userPolicy.CreatedAt = time.Now().UTC()
	}

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.policyRepo.AssignUserPolicy(ctx, tx, userPolicy); err != nil {
		return fmt.Errorf("assign policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	s.logAudit(ctx, policy.CompanyID, "user_attendance_policy.assign", userPolicy.PolicyID,
		actorType, actorID, nil, userPolicy, metadata)
	s.logger.Info("User attendance policy assigned",
		zap.String("user_id", userPolicy.UserID.String()),
		zap.String("policy_id", userPolicy.PolicyID.String()))
	return nil
}

// EndUserAttendancePolicy is the legacy employee-only end method.
// It now uses the polymorphic EndPolicyForSubject with subjectType="employee".
func (s *adminService) EndUserAttendancePolicy(ctx context.Context, userID, policyID uuid.UUID, endDate time.Time) error {
	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}
	return s.EndPolicyForSubject(ctx, "employee", userID, policyID, endDate)
}

func (s *adminService) GetPositionAttendancePolicy(ctx context.Context, positionID uuid.UUID) (*models.AttendancePolicy, error) {
	return s.policyRepo.GetPositionPolicy(ctx, positionID)
}

func (s *adminService) GetUsersByAttendancePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error) {
	if effectiveDate.IsZero() {
		effectiveDate = time.Now()
	}
	return s.policyRepo.GetUsersByPolicy(ctx, policyID, effectiveDate)
}

// ------------------------------------------------------------
// Attendance rules
// ------------------------------------------------------------

func (s *adminService) GetCompanyAttendanceRules(ctx context.Context, companyID uuid.UUID) (*models.CompanyAttendanceRules, error) {
	return s.ruleRepo.GetCompanyRules(ctx, companyID)
}

func (s *adminService) UpdateCompanyAttendanceRules(ctx context.Context, rules *models.CompanyAttendanceRules, updatedBy uuid.UUID) error {
	if rules == nil || rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company rules and company_id required")
	}
	// Validate source types
	srcTypes, err := s.sourceRepo.GetSourceTypes(ctx, true)
	if err != nil {
		return fmt.Errorf("load source types: %w", err)
	}
	valid := make(map[string]struct{}, len(srcTypes))
	for _, st := range srcTypes {
		valid[st.SourceType] = struct{}{}
	}
	if len(rules.AllowedSourceTypes) == 0 {
		rules.AllowedSourceTypes = []string{"mobile", "web", "biometric", "rfid"}
	} else {
		seen := make(map[string]struct{})
		var validated []string
		for _, src := range rules.AllowedSourceTypes {
			src = strings.ToLower(strings.TrimSpace(src))
			if _, ok := valid[src]; !ok {
				return fmt.Errorf("invalid source type: %s", src)
			}
			if _, exists := seen[src]; !exists {
				seen[src] = struct{}{}
				validated = append(validated, src)
			}
		}
		rules.AllowedSourceTypes = validated
	}
	if rules.Timezone == "" {
		rules.Timezone = "UTC"
	}
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}
	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.ruleRepo.UpsertCompanyRules(ctx, tx, rules); err != nil {
		return fmt.Errorf("upsert company rules: %w", err)
	}
	return tx.Commit()
}

func (s *adminService) GetDepartmentAttendanceRules(ctx context.Context, companyID, departmentID uuid.UUID) (*models.DepartmentAttendanceRules, error) {
	return s.ruleRepo.GetDepartmentRules(ctx, companyID, departmentID)
}

func (s *adminService) UpsertDepartmentAttendanceRules(ctx context.Context, rules *models.DepartmentAttendanceRules) error {
	if rules == nil || rules.CompanyID == uuid.Nil || rules.DepartmentID == uuid.Nil {
		return fmt.Errorf("rules, company_id, department_id required")
	}
	// Validate against company allowed sources
	companyRules, err := s.ruleRepo.GetCompanyRules(ctx, rules.CompanyID)
	if err != nil {
		return fmt.Errorf("get company rules: %w", err)
	}
	allowed := make(map[string]bool)
	for _, src := range companyRules.AllowedSourceTypes {
		allowed[src] = true
	}
	for _, src := range rules.AllowedSourceTypes {
		if !allowed[src] {
			return fmt.Errorf("source type %s not allowed by company", src)
		}
	}
	// Validate event types (we can use a predefined list)
	for _, et := range rules.AllowedEventTypes {
		if !isValidEventType(et) {
			return fmt.Errorf("invalid event type: %s", et)
		}
	}
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}
	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.ruleRepo.UpsertDepartmentRules(ctx, tx, rules); err != nil {
		return fmt.Errorf("upsert department rules: %w", err)
	}
	return tx.Commit()
}

// ------------------------------------------------------------
// User attendance profile (overrides)
// ------------------------------------------------------------

func (s *adminService) GetUserAttendanceProfile(ctx context.Context, userID uuid.UUID) (*models.UserAttendanceProfile, error) {
	return s.ruleRepo.GetUserProfile(ctx, userID)
}

func (s *adminService) UpsertUserAttendanceProfile(ctx context.Context, profile *models.UserAttendanceProfile) error {
	if profile == nil || profile.UserID == uuid.Nil || profile.CompanyID == uuid.Nil {
		return fmt.Errorf("profile, user_id, company_id required")
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}
	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.ruleRepo.UpsertUserProfile(ctx, tx, profile); err != nil {
		return fmt.Errorf("upsert user profile: %w", err)
	}
	return tx.Commit()
}

// ------------------------------------------------------------
// Rule resolution (used by ingest)
// CHANGED: now uses polymorphic policy lookup
// ------------------------------------------------------------
func (s *adminService) ResolveAttendanceRules(ctx context.Context, userID, companyID uuid.UUID, subjectType string, workCenterCode string, positionID *uuid.UUID, date time.Time) (*models.ResolvedAttendanceRules, error) {
	now := time.Now().UTC()
	resolved := &models.ResolvedAttendanceRules{
		CompanyID:             companyID,
		AllowedSourceTypesMap: make(map[string]bool),
		AllowedEventTypesMap:  make(map[string]bool),
		AppliedAt:             now,
		SourceLevel:           "company",
		PolicySource:          "company",
	}

	// 1. Company rules (baseline)
	companyRules, err := s.ruleRepo.GetCompanyRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("get company rules: %w", err)
	}
	if companyRules == nil {
		s.logger.Warn("No company attendance rules found, using defaults",
			zap.String("company_id", companyID.String()))
		resolved.Timezone = "UTC"
		resolved.AllowMultipleCheckins = false
		resolved.AllowedSourceTypes = []string{"mobile", "web", "biometric", "rfid"}
		for _, src := range resolved.AllowedSourceTypes {
			resolved.AllowedSourceTypesMap[src] = true
		}
	} else {
		resolved.Timezone = companyRules.Timezone
		resolved.AllowMultipleCheckins = companyRules.AllowMultipleCheckins
		resolved.AllowedSourceTypes = companyRules.AllowedSourceTypes
		for _, src := range companyRules.AllowedSourceTypes {
			resolved.AllowedSourceTypesMap[src] = true
		}
	}

	// 2. Resolve policy: subject-specific > work_center > position
	var resolvedPolicy *models.AttendancePolicy

	// 2a. Try subject-specific policy (polymorphic)
	if userID != uuid.Nil && subjectType != "" {
		if p, err := s.policyRepo.GetActivePolicyBySubject(ctx, subjectType, userID, date); err == nil && p != nil && p.IsActive {
			resolvedPolicy = p
			resolved.PolicySource = "subject"
			s.logger.Debug("Resolved policy from subject assignment",
				zap.String("subject_type", subjectType),
				zap.String("subject_id", userID.String()),
				zap.String("policy_id", p.PolicyID.String()),
				zap.String("policy_code", p.PolicyCode))
		}
	}

	// 2b. Fallback to work center policy
	if resolvedPolicy == nil && workCenterCode != "" {
		if p, err := s.policyRepo.GetWorkCenterPolicy(ctx, companyID, workCenterCode); err == nil && p != nil && p.IsActive {
			resolvedPolicy = p
			resolved.PolicySource = "work_center"
			resolved.WorkCenterCode = &workCenterCode
			s.logger.Debug("Resolved policy from work center",
				zap.String("work_center", workCenterCode),
				zap.String("policy_id", p.PolicyID.String()))
		}
	}

	// 2c. Fallback to position policy
	if resolvedPolicy == nil && positionID != nil {
		if p, err := s.policyRepo.GetPositionPolicy(ctx, *positionID); err == nil && p != nil && p.IsActive {
			resolvedPolicy = p
			resolved.PolicySource = "position"
			resolved.PositionID = positionID
			s.logger.Debug("Resolved policy from position",
				zap.String("position_id", positionID.String()),
				zap.String("policy_id", p.PolicyID.String()))
		}
	}

	if resolvedPolicy != nil {
		resolved.PolicyID = &resolvedPolicy.PolicyID
		resolved.PolicyRules = &resolvedPolicy.Rules
		resolved.SourceLevel = resolved.PolicySource
		rules := resolvedPolicy.Rules
		if len(rules.AllowedSourceTypes) > 0 {
			resolved.AllowedSourceTypes = rules.AllowedSourceTypes
			resolved.AllowedSourceTypesMap = make(map[string]bool)
			for _, src := range rules.AllowedSourceTypes {
				resolved.AllowedSourceTypesMap[src] = true
			}
		}
		if rules.RequireWorkCenter != nil && *rules.RequireWorkCenter {
			resolved.RequireReference = true
		}
		resolved.RequireDevice = false
		if rules.AllowDeviceMarking != nil && *rules.AllowDeviceMarking {
			resolved.RequireDevice = true
		}
	} else {
		s.logger.Warn("No attendance policy resolved for subject",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", userID.String()),
			zap.String("company_id", companyID.String()),
			zap.String("work_center", workCenterCode))
	}

	// 3. User profile overrides (still employee‑centric; could be extended)
	if userID != uuid.Nil {
		profile, err := s.ruleRepo.GetUserProfile(ctx, userID)
		if err == nil && profile != nil {
			if len(profile.OverrideSourceTypes) > 0 || len(profile.OverrideEventTypes) > 0 {
				resolved.SourceLevel = "user_override"
			}
			if len(profile.OverrideSourceTypes) > 0 {
				resolved.AllowedSourceTypes = profile.OverrideSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, src := range profile.OverrideSourceTypes {
					resolved.AllowedSourceTypesMap[src] = true
				}
			}
			if len(profile.OverrideEventTypes) > 0 {
				resolved.AllowedEventTypes = profile.OverrideEventTypes
				resolved.AllowedEventTypesMap = make(map[string]bool)
				for _, et := range profile.OverrideEventTypes {
					resolved.AllowedEventTypesMap[et] = true
				}
				resolved.AllowAllEventTypes = false
			}
		}
	}
	if len(resolved.AllowedEventTypes) == 0 {
		resolved.AllowAllEventTypes = true
	}

	return resolved, nil
}

// ------------------------------------------------------------
// Validation helpers
// ------------------------------------------------------------

func (s *adminService) ValidateAttendanceEventType(ctx context.Context, eventType string) error {
	types, err := s.sourceRepo.GetEventTypes(ctx, true)
	if err != nil {
		return fmt.Errorf("get event types: %w", err)
	}
	for _, et := range types {
		if et.EventType == eventType && et.IsActive {
			return nil
		}
	}
	return fmt.Errorf("invalid or inactive event type: %s", eventType)
}

func (s *adminService) ValidateAttendanceSourceType(ctx context.Context, sourceType string, sourceID *uuid.UUID) error {
	st, err := s.sourceRepo.GetSourceTypeByType(ctx, sourceType)
	if err != nil {
		return fmt.Errorf("get source type: %w", err)
	}
	if st == nil {
		return fmt.Errorf("source type %s not found", sourceType)
	}
	if st.RequiresDevice && (sourceID == nil || *sourceID == uuid.Nil) {
		return fmt.Errorf("source reference required for source type %s", sourceType)
	}
	return nil
}

// ------------------------------------------------------------
// Health
// ------------------------------------------------------------

func (s *adminService) HealthCheck(ctx context.Context) error {
	if err := s.eventRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("event repo health: %w", err)
	}
	return nil
}

// ------------------------------------------------------------
// helpers
// ------------------------------------------------------------

func (s *adminService) validatePolicy(policy *models.AttendancePolicy) error {
	if policy.CompanyID == uuid.Nil {
		return fmt.Errorf("company_id required")
	}
	if policy.PolicyCode == "" {
		return fmt.Errorf("policy_code required")
	}
	if policy.PolicyType == "" {
		return fmt.Errorf("policy_type required")
	}
	return nil
}

func (s *adminService) logAudit(ctx context.Context, companyID uuid.UUID, action string, resourceID uuid.UUID, actorType string, actorID uuid.UUID, before, after interface{}, metadata map[string]interface{}) {
	if s.audit == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, "attendance", action, strings.Split(action, ".")[0], &resourceID, actorType, &actorID, beforeJSON, afterJSON, metadata)
}

func isValidEventType(et string) bool {
	valid := map[string]bool{
		"check_in": true, "check_out": true, "break_start": true, "break_end": true,
		"shift_start": true, "shift_end": true, "overtime_start": true, "overtime_end": true,
		"early_exit": true, "late_entry": true, "gate_entry": true, "gate_exit": true,
		"zone_entry": true, "zone_exit": true, "class_start": true, "class_end": true,
		"session_join": true, "session_leave": true, "leave_start": true, "leave_end": true,
		"absent_marked": true, "holiday_marked": true, "weekly_off": true,
		"manual_check_in": true, "manual_check_out": true, "manual_override": true,
		"attendance_adjustment": true, "biometric_sync": true, "system_generated": true,
		"imported_event": true, "missing_punch": true, "duplicate_punch": true,
		"invalid_punch": true, "policy_violation": true,
	}
	return valid[et]
}
