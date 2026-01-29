package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// ATTENDANCE ADMIN SERVICE (FINAL)
// ============================================
// AttendanceCorrectionRequest represents a correction request
type AttendanceCorrectionRequest struct {
	CompanyID      uuid.UUID
	ActorID        uuid.UUID
	ActorType      string
	TargetUserID   uuid.UUID
	BusinessDate   time.Time
	CorrectionType string
	EventTime      *time.Time
	OverrideStatus string
	Reason         string
}

// AttendanceAdminService handles admin and configuration operations
// DOES NOT: ingest events, resolve summaries, or handle queries
type AttendanceAdminService interface {
	// ─────────────────────────────
	// Attendance Policies (ADMIN)
	// ─────────────────────────────
	// Add to AttendanceAdminService interface
	CreateAttendanceCorrection(
		ctx context.Context,
		req *AttendanceCorrectionRequest,
	) error
	CreateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) (*attendance.AttendancePolicy, error)

	UpdateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
	) error

	DeleteAttendancePolicy(
		ctx context.Context,
		policyID uuid.UUID,
	) error

	AssignUserAttendancePolicy(
		ctx context.Context,
		userPolicy *attendance.UserAttendancePolicy,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) error

	EndUserAttendancePolicy(
		ctx context.Context,
		userID, policyID uuid.UUID,
		endDate time.Time,
	) error

	GetPositionAttendancePolicy(
		ctx context.Context,
		positionID uuid.UUID,
	) (*attendance.AttendancePolicy, error)

	GetUsersByAttendancePolicy(
		ctx context.Context,
		policyID uuid.UUID,
		effectiveDate time.Time,
	) ([]uuid.UUID, error)

	// ─────────────────────────────
	// Attendance Rules (CONFIG)
	// ─────────────────────────────
	GetCompanyAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
	) (*attendance.CompanyAttendanceRules, error)

	UpdateCompanyAttendanceRules(
		ctx context.Context,
		rules *attendance.CompanyAttendanceRules,
		updatedBy uuid.UUID,
	) error

	GetDepartmentAttendanceRules(
		ctx context.Context,
		companyID, departmentID uuid.UUID,
	) (*attendance.DepartmentAttendanceRules, error)

	UpsertDepartmentAttendanceRules(
		ctx context.Context,
		rules *attendance.DepartmentAttendanceRules,
	) error

	ResolveAttendanceRules(
		ctx context.Context,
		userID, companyID uuid.UUID,
		workCenterCode string,
		positionID *uuid.UUID,
		date time.Time,
	) (*attendance.ResolvedAttendanceRules, error)

	// ─────────────────────────────
	// User Attendance Profile
	// ─────────────────────────────
	GetUserAttendanceProfile(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.UserAttendanceProfile, error)

	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error

	// ─────────────────────────────
	// RFID / Identity Management
	// ─────────────────────────────
	AssignRFIDToEmployee(
		ctx context.Context,
		companyID, userID uuid.UUID,
		rfidTag string,
		assignedBy uuid.UUID,
	) error

	UnassignRFID(
		ctx context.Context,
		rfidID uuid.UUID,
		unassignedBy uuid.UUID,
	) error

	GetEmployeeByRFID(
		ctx context.Context,
		rfidTag string,
		companyID uuid.UUID,
	) (*attendance.EmployeeRFIDMapping, error)

	// ─────────────────────────────
	// Validation Helpers (USED BY INGEST)
	// ─────────────────────────────
	ValidateAttendanceEventType(
		ctx context.Context,
		eventType string,
	) error

	ValidateAttendanceSourceType(
		ctx context.Context,
		sourceType string,
		sourceID *uuid.UUID,
	) error

	// ─────────────────────────────
	// Health
	// ─────────────────────────────
	HealthCheck(ctx context.Context) error
}

// ============================================
// IMPLEMENTATION
// ============================================

type attendanceAdminService struct {
	attendanceRepo    repository.AttendanceRepository
	schedulingRepo    repository.SchedulingRepository
	resolutionService AttendanceResolutionService
	logger            *zap.Logger
	auditService      *AuditService
}

// NewAttendanceAdminService creates a new admin service
func NewAttendanceAdminService(
	attendanceRepo repository.AttendanceRepository,
	schedulingRepo repository.SchedulingRepository,
	resolutionService AttendanceResolutionService, // NEW
	logger *zap.Logger,
	auditService *AuditService,
) AttendanceAdminService {
	return &attendanceAdminService{
		attendanceRepo:    attendanceRepo,
		schedulingRepo:    schedulingRepo,
		resolutionService: resolutionService, // NEW
		logger:            logger,
		auditService:      auditService,
	}
}

// ============================================
// POLICY MANAGEMENT
// ============================================

func (s *attendanceAdminService) CreateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	// Validate required fields
	if policy.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return nil, fmt.Errorf("policy code is required")
	}
	if policy.PolicyType == "" {
		return nil, fmt.Errorf("policy type is required")
	}

	// Check for duplicate policy code
	existingPolicies, err := s.attendanceRepo.GetAttendancePoliciesByCompany(ctx, policy.CompanyID, false)
	if err == nil {
		for _, existing := range existingPolicies {
			if existing.PolicyCode == policy.PolicyCode {
				return nil, fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
			}
		}
	}

	// Generate ID if not provided
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	// Create the policy
	if err := s.attendanceRepo.CreateAttendancePolicy(ctx, policy); err != nil {
		s.logger.Error("Failed to create attendance policy",
			util.String("company_id", policy.CompanyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create attendance policy: %w", err)
	}

	// Log audit
	if s.auditService != nil {
		go s.logAuditAction(ctx, policy.CompanyID, "attendance_policy.create",
			policy.PolicyID, actorType, actorID, nil, policy, metadata)
	}

	s.logger.Info("Attendance policy created",
		util.String("policy_id", policy.PolicyID.String()),
		util.String("company_id", policy.CompanyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("policy_type", policy.PolicyType),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (s *attendanceAdminService) UpdateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
) error {
	startTime := time.Now()

	// Validate required fields
	if policy.PolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}
	if policy.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return fmt.Errorf("policy code is required")
	}
	if policy.PolicyType == "" {
		return fmt.Errorf("policy type is required")
	}

	// Verify policy exists
	existingPolicy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policy.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if existingPolicy == nil {
		return fmt.Errorf("attendance policy not found")
	}

	// Check for duplicate policy code (excluding current policy)
	existingPolicies, err := s.attendanceRepo.GetAttendancePoliciesByCompany(ctx, policy.CompanyID, false)
	if err == nil {
		for _, p := range existingPolicies {
			if p.PolicyID != policy.PolicyID && p.PolicyCode == policy.PolicyCode {
				return fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
			}
		}
	}

	// Update timestamp
	policy.UpdatedAt = time.Now().UTC()

	// Update the policy
	if err := s.attendanceRepo.UpdateAttendancePolicy(ctx, policy); err != nil {
		s.logger.Error("Failed to update attendance policy",
			util.String("policy_id", policy.PolicyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance policy: %w", err)
	}

	s.logger.Info("Attendance policy updated",
		util.String("policy_id", policy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("company_id", policy.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceAdminService) DeleteAttendancePolicy(
	ctx context.Context,
	policyID uuid.UUID,
) error {
	startTime := time.Now()

	if policyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}

	// Verify policy exists
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("attendance policy not found")
	}

	// Check if policy is assigned to any users
	assignedUsers, err := s.attendanceRepo.GetUsersByAttendancePolicy(ctx, policyID, time.Now())
	if err == nil && len(assignedUsers) > 0 {
		return fmt.Errorf("cannot delete policy assigned to %d users", len(assignedUsers))
	}

	// Delete the policy
	if err := s.attendanceRepo.DeleteAttendancePolicy(ctx, policyID); err != nil {
		s.logger.Error("Failed to delete attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete attendance policy: %w", err)
	}

	s.logger.Info("Attendance policy deleted",
		util.String("policy_id", policyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("company_id", policy.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceAdminService) AssignUserAttendancePolicy(
	ctx context.Context,
	userPolicy *attendance.UserAttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate required fields
	if userPolicy.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if userPolicy.PolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}
	if userPolicy.EffectiveFrom.IsZero() {
		userPolicy.EffectiveFrom = time.Now().UTC()
	}

	// Verify policy exists and is active
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, userPolicy.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("attendance policy not found")
	}
	if !policy.IsActive {
		return fmt.Errorf("attendance policy is not active")
	}

	// Check for existing active policy
	existingPolicy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userPolicy.UserID, time.Now())
	if err == nil && existingPolicy != nil {
		if existingPolicy.PolicyID == userPolicy.PolicyID {
			return nil // Already assigned
		}
		// End previous policy
		if err := s.attendanceRepo.EndUserAttendancePolicy(ctx, userPolicy.UserID,
			existingPolicy.PolicyID, userPolicy.EffectiveFrom); err != nil {
			s.logger.Warn("Failed to end previous attendance policy",
				util.String("user_id", userPolicy.UserID.String()),
				util.String("policy_id", existingPolicy.PolicyID.String()),
				util.ErrorField(err))
		}
	}

	// Set metadata
	if userPolicy.AssignedBy == nil {
		userPolicy.AssignedBy = &actorID
	}
	if userPolicy.CreatedAt.IsZero() {
		userPolicy.CreatedAt = time.Now().UTC()
	}

	// Assign the policy
	if err := s.attendanceRepo.AssignUserAttendancePolicy(ctx, userPolicy); err != nil {
		s.logger.Error("Failed to assign user attendance policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user attendance policy: %w", err)
	}

	// Log audit
	if s.auditService != nil {
		go s.logAuditAction(ctx, policy.CompanyID, "user_attendance_policy.assign",
			userPolicy.PolicyID, actorType, actorID, nil, userPolicy, metadata)
	}

	s.logger.Info("User attendance policy assigned",
		util.String("user_id", userPolicy.UserID.String()),
		util.String("policy_id", userPolicy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.Time("effective_from", userPolicy.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceAdminService) EndUserAttendancePolicy(
	ctx context.Context,
	userID, policyID uuid.UUID,
	endDate time.Time,
) error {
	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}

	err := s.attendanceRepo.EndUserAttendancePolicy(ctx, userID, policyID, endDate)
	if err != nil {
		return fmt.Errorf("failed to end user attendance policy: %w", err)
	}

	s.logger.Info("User attendance policy ended",
		util.String("user_id", userID.String()),
		util.String("policy_id", policyID.String()),
		util.Time("end_date", endDate))

	return nil
}

func (s *attendanceAdminService) GetPositionAttendancePolicy(
	ctx context.Context,
	positionID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	policy, err := s.attendanceRepo.GetPositionAttendancePolicy(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position attendance policy: %w", err)
	}
	return policy, nil
}

func (s *attendanceAdminService) GetUsersByAttendancePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	effectiveDate time.Time,
) ([]uuid.UUID, error) {
	if effectiveDate.IsZero() {
		effectiveDate = time.Now()
	}

	userIDs, err := s.attendanceRepo.GetUsersByAttendancePolicy(ctx, policyID, effectiveDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by attendance policy: %w", err)
	}
	return userIDs, nil
}

// ============================================
// ATTENDANCE RULES MANAGEMENT
// ============================================

func (s *attendanceAdminService) GetCompanyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
) (*attendance.CompanyAttendanceRules, error) {
	rules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}
	return rules, nil
}

func (s *attendanceAdminService) UpdateCompanyAttendanceRules(
	ctx context.Context,
	rules *attendance.CompanyAttendanceRules,
	updatedBy uuid.UUID,
) error {
	if rules == nil {
		return fmt.Errorf("company attendance rules are required")
	}
	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	// Load source types for validation
	sourceTypes, err := s.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to load attendance source types: %w", err)
	}

	// Build valid source types map
	validSources := make(map[string]struct{}, len(sourceTypes))
	for _, st := range sourceTypes {
		validSources[st.SourceType] = struct{}{}
	}

	// Set default allowed sources if empty
	if len(rules.AllowedSourceTypes) == 0 {
		rules.AllowedSourceTypes = []string{"mobile", "web", "biometric", "rfid"}
	} else {
		// Validate and normalize source types
		seen := make(map[string]struct{})
		validated := make([]string, 0, len(rules.AllowedSourceTypes))
		for _, src := range rules.AllowedSourceTypes {
			src = normalizeSourceType(src)
			if _, ok := validSources[src]; !ok {
				return fmt.Errorf("invalid attendance source type: %s", src)
			}
			if _, exists := seen[src]; !exists {
				seen[src] = struct{}{}
				validated = append(validated, src)
			}
		}
		rules.AllowedSourceTypes = validated
	}

	// Set default timezone
	if rules.Timezone == "" {
		rules.Timezone = "UTC"
	}

	// Set timestamps
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}

	// Save rules
	if err := s.attendanceRepo.UpsertCompanyAttendanceRules(ctx, rules); err != nil {
		s.logger.Error("Failed to update company attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update company attendance rules: %w", err)
	}

	s.logger.Info("Company attendance rules updated",
		util.String("company_id", rules.CompanyID.String()),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *attendanceAdminService) GetDepartmentAttendanceRules(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
) (*attendance.DepartmentAttendanceRules, error) {
	rules, err := s.attendanceRepo.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department attendance rules: %w", err)
	}
	return rules, nil
}

func (s *attendanceAdminService) UpsertDepartmentAttendanceRules(
	ctx context.Context,
	rules *attendance.DepartmentAttendanceRules,
) error {
	if rules == nil {
		return fmt.Errorf("department attendance rules are required")
	}
	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if rules.DepartmentID == uuid.Nil {
		return fmt.Errorf("department ID is required")
	}

	// Load company rules for validation
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, rules.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to load company attendance rules: %w", err)
	}

	// Build company allowed sources map
	companySourceMap := make(map[string]bool, len(companyRules.AllowedSourceTypes))
	for _, src := range companyRules.AllowedSourceTypes {
		companySourceMap[src] = true
	}

	// Validate department source types against company rules
	for _, src := range rules.AllowedSourceTypes {
		if !companySourceMap[src] {
			return fmt.Errorf("invalid source type '%s': not allowed by company", src)
		}
	}

	// Validate event types
	for _, eventType := range rules.AllowedEventTypes {
		if !isValidAttendanceEventType(eventType) {
			return fmt.Errorf("invalid event type '%s': not a supported attendance event", eventType)
		}
	}

	// Set timestamps
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}

	// Save rules
	if err := s.attendanceRepo.UpsertDepartmentAttendanceRules(ctx, rules); err != nil {
		s.logger.Error("Failed to upsert department attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.String("department_id", rules.DepartmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to upsert department attendance rules: %w", err)
	}

	s.logger.Info("Department attendance rules upserted",
		util.String("company_id", rules.CompanyID.String()),
		util.String("department_id", rules.DepartmentID.String()))

	return nil
}
func (s *attendanceAdminService) ResolveAttendanceRules(
	ctx context.Context,
	userID, companyID uuid.UUID,
	workCenterCode string,
	positionID *uuid.UUID,
	date time.Time,
) (*attendance.ResolvedAttendanceRules, error) {

	resolved := &attendance.ResolvedAttendanceRules{
		CompanyID:             companyID,
		AllowedSourceTypesMap: make(map[string]bool),
		AllowedEventTypesMap:  make(map[string]bool),
		AppliedAt:             time.Now().UTC(),
		SourceLevel:           "company",
		PolicySource:          "company",
	}

	// ------------------------------------------------
	// 1️⃣ COMPANY-LEVEL RULES (BASE)
	// ------------------------------------------------
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}

	resolved.Timezone = companyRules.Timezone
	resolved.AllowMultipleCheckins = companyRules.AllowMultipleCheckins
	resolved.AllowedSourceTypes = companyRules.AllowedSourceTypes

	for _, src := range companyRules.AllowedSourceTypes {
		resolved.AllowedSourceTypesMap[src] = true
	}

	// ------------------------------------------------
	// 2️⃣ POLICY RESOLUTION (NO SOURCE/EVENT LOGIC)
	// Priority:
	//   user → work_center → position
	// ------------------------------------------------
	var resolvedPolicy *attendance.AttendancePolicy

	// USER POLICY
	if userID != uuid.Nil {
		if p, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, date); err == nil && p != nil {
			resolvedPolicy = p
			resolved.PolicySource = "user"
		}
	}

	// WORK CENTER POLICY
	if resolvedPolicy == nil && workCenterCode != "" {
		if p, err := s.attendanceRepo.GetWorkCenterAttendancePolicy(ctx, companyID, workCenterCode); err == nil && p != nil && p.IsActive {
			resolvedPolicy = p
			resolved.PolicySource = "work_center"
			resolved.WorkCenterCode = &workCenterCode
		}
	}

	// POSITION POLICY
	if resolvedPolicy == nil && positionID != nil {
		if p, err := s.attendanceRepo.GetPositionAttendancePolicy(ctx, *positionID); err == nil && p != nil && p.IsActive {
			resolvedPolicy = p
			resolved.PolicySource = "position"
			resolved.PositionID = positionID
		}
	}

	// APPLY POLICY (ONLY TIMING / BEHAVIOR RULES)
	if resolvedPolicy != nil {
		resolved.PolicyID = &resolvedPolicy.PolicyID
		resolved.PolicyRules = &resolvedPolicy.Rules
		resolved.SourceLevel = resolved.PolicySource
	}

	// ------------------------------------------------
	// 3️⃣ USER-LEVEL OVERRIDES (FINAL AUTHORITY)
	// ------------------------------------------------
	if userID != uuid.Nil {
		userProfile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
		if err == nil && userProfile != nil {

			hasSourceOverrides := len(userProfile.OverrideSourceTypes) > 0
			hasEventOverrides := len(userProfile.OverrideEventTypes) > 0

			if hasSourceOverrides || hasEventOverrides {
				resolved.SourceLevel = "user_override"
			}

			// SOURCE OVERRIDES
			if hasSourceOverrides {
				resolved.AllowedSourceTypes = userProfile.OverrideSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, src := range userProfile.OverrideSourceTypes {
					resolved.AllowedSourceTypesMap[src] = true
				}
			}

			// EVENT OVERRIDES
			if hasEventOverrides {
				resolved.AllowedEventTypes = userProfile.OverrideEventTypes
				resolved.AllowedEventTypesMap = make(map[string]bool)
				for _, evt := range userProfile.OverrideEventTypes {
					resolved.AllowedEventTypesMap[evt] = true
				}
				resolved.AllowAllEventTypes = false
			}
		}
	}

	// ------------------------------------------------
	// 4️⃣ DEFAULT EVENT BEHAVIOR
	// ------------------------------------------------
	if len(resolved.AllowedEventTypes) == 0 {
		resolved.AllowAllEventTypes = true
	}

	// ------------------------------------------------
	// 5️⃣ REQUIREMENT FLAGS (POLICY-BASED)
	// ------------------------------------------------
	resolved.RequireLocation = false
	resolved.RequireDevice = false
	resolved.RequireReference = false

	if resolved.PolicyRules != nil &&
		resolved.PolicyRules.RequireWorkCenter != nil &&
		*resolved.PolicyRules.RequireWorkCenter {
		resolved.RequireReference = true
	}

	s.logger.Debug("Attendance rules resolved",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
		zap.String("source_level", resolved.SourceLevel),
		zap.String("policy_source", resolved.PolicySource),
		zap.String("work_center_code", safeString(resolved.WorkCenterCode)),
		zap.Time("date", date),
	)

	return resolved, nil
}

// Helper function to safely dereference string pointer
// ============================================
// USER ATTENDANCE PROFILE
// ============================================

func (s *attendanceAdminService) GetUserAttendanceProfile(
	ctx context.Context,
	userID uuid.UUID,
) (*attendance.UserAttendanceProfile, error) {
	profile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}
	return profile, nil
}

func (s *attendanceAdminService) UpsertUserAttendanceProfile(
	ctx context.Context,
	profile *attendance.UserAttendanceProfile,
) error {
	if profile == nil {
		return fmt.Errorf("user attendance profile is required")
	}
	if profile.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if profile.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	// Set timestamps
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}

	// Save profile
	if err := s.attendanceRepo.UpsertUserAttendanceProfile(ctx, profile); err != nil {
		s.logger.Error("Failed to upsert user attendance profile",
			util.String("user_id", profile.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to upsert user attendance profile: %w", err)
	}

	s.logger.Info("User attendance profile upserted",
		util.String("user_id", profile.UserID.String()),
		util.String("company_id", profile.CompanyID.String()))

	return nil
}

// ============================================
// RFID / IDENTITY MANAGEMENT
// ============================================

func (s *attendanceAdminService) AssignRFIDToEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	rfidTag string,
	assignedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Validate input
	if rfidTag == "" {
		return fmt.Errorf("RFID tag is required")
	}

	// Check for existing RFID assignment
	existingMapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, rfidTag)
	if err != nil {
		return fmt.Errorf("failed to check RFID mapping: %w", err)
	}
	if existingMapping != nil && existingMapping.UserID != userID && existingMapping.IsActive {
		return fmt.Errorf("RFID tag %s is already assigned to another employee", rfidTag)
	}

	// Deactivate any existing RFID for this user
	userMapping, err := s.attendanceRepo.GetEmployeeRFIDMappingByUser(ctx, userID)
	if err == nil && userMapping != nil && userMapping.IsActive {
		if err := s.attendanceRepo.DeactivateEmployeeRFIDMapping(ctx, userMapping.RFIDID); err != nil {
			s.logger.Warn("Failed to deactivate existing RFID mapping",
				util.String("user_id", userID.String()),
				util.String("rfid_tag", userMapping.RFIDTag),
				util.ErrorField(err))
		}
	}

	// Create new mapping
	mapping := &attendance.EmployeeRFIDMapping{
		RFIDID:     uuid.New(),
		UserID:     userID,
		CompanyID:  companyID,
		RFIDTag:    rfidTag,
		IsActive:   true,
		AssignedAt: time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	// Save mapping
	if err := s.attendanceRepo.CreateEmployeeRFIDMapping(ctx, mapping); err != nil {
		s.logger.Error("Failed to assign RFID to employee",
			util.String("user_id", userID.String()),
			util.String("rfid_tag", rfidTag),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign RFID to employee: %w", err)
	}

	s.logger.Info("RFID assigned to employee",
		util.String("user_id", userID.String()),
		util.String("rfid_tag", rfidTag),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceAdminService) UnassignRFID(
	ctx context.Context,
	rfidID uuid.UUID,
	unassignedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Get the mapping
	mapping, err := s.attendanceRepo.GetAttendanceSourceByID(ctx, rfidID)
	if err != nil {
		return fmt.Errorf("failed to get RFID mapping: %w", err)
	}
	if mapping == nil {
		return fmt.Errorf("RFID mapping not found")
	}

	// Deactivate the mapping
	if err := s.attendanceRepo.DeactivateEmployeeRFIDMapping(ctx, rfidID); err != nil {
		s.logger.Error("Failed to unassign RFID",
			util.String("rfid_id", rfidID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to unassign RFID: %w", err)
	}

	s.logger.Info("RFID unassigned",
		util.String("rfid_id", rfidID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceAdminService) GetEmployeeByRFID(
	ctx context.Context,
	rfidTag string,
	companyID uuid.UUID,
) (*attendance.EmployeeRFIDMapping, error) {
	mapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, rfidTag)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee by RFID: %w", err)
	}
	if mapping == nil {
		return nil, nil
	}
	if mapping.CompanyID != companyID {
		return nil, fmt.Errorf("RFID tag does not belong to this company")
	}
	if !mapping.IsActive {
		return nil, fmt.Errorf("RFID mapping is not active")
	}
	return mapping, nil
}

// ============================================
// VALIDATION HELPERS
// ============================================

func (s *attendanceAdminService) ValidateAttendanceEventType(
	ctx context.Context,
	eventType string,
) error {
	eventTypes, err := s.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate attendance event type: %w", err)
	}
	for _, et := range eventTypes {
		if et.EventType == eventType && et.IsActive {
			return nil
		}
	}
	return fmt.Errorf("invalid or inactive attendance event type: %s", eventType)
}

func (s *attendanceAdminService) ValidateAttendanceSourceType(
	ctx context.Context,
	sourceType string,
	sourceID *uuid.UUID,
) error {
	sourceTypeDef, err := s.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		return fmt.Errorf("failed to validate attendance source type: %w", err)
	}
	if sourceTypeDef.RequiresDevice && (sourceID == nil || *sourceID == uuid.Nil) {
		return fmt.Errorf("source reference is required for source type %s", sourceType)
	}
	return nil
}

// GetAttendanceSourceType is a helper used by validation
func (s *attendanceAdminService) GetAttendanceSourceType(
	ctx context.Context,
	sourceType string,
) (*attendance.AttendanceSourceType, error) {
	sourceTypes, err := s.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}
	for _, st := range sourceTypes {
		if st.SourceType == sourceType {
			return st, nil
		}
	}
	return nil, fmt.Errorf("attendance source type %s not found", sourceType)
}

// GetAttendanceEventType is a helper used by validation
func (s *attendanceAdminService) GetAttendanceEventType(
	ctx context.Context,
	eventType string,
) (*attendance.AttendanceEventType, error) {
	eventTypes, err := s.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event types: %w", err)
	}
	for _, et := range eventTypes {
		if et.EventType == eventType {
			return et, nil
		}
	}
	return nil, fmt.Errorf("attendance event type %s not found", eventType)
}

// ============================================
// HEALTH CHECK
// ============================================

func (s *attendanceAdminService) HealthCheck(ctx context.Context) error {
	if err := s.attendanceRepo.HealthCheck(ctx); err != nil {
		s.logger.Error("Attendance repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

// ============================================
// HELPER METHODS
// ============================================

func (s *attendanceAdminService) logAuditAction(
	ctx context.Context,
	companyID uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	beforeState, afterState interface{},
	metadata map[string]interface{},
) {
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var beforeJSON, afterJSON []byte
			var err error

			if beforeState != nil {
				beforeJSON, err = json.Marshal(beforeState)
				if err != nil {
					s.logger.Warn("Failed to marshal before state for audit",
						util.String("action", action),
						util.ErrorField(err))
				}
			}

			if afterState != nil {
				afterJSON, err = json.Marshal(afterState)
				if err != nil {
					s.logger.Warn("Failed to marshal after state for audit",
						util.String("action", action),
						util.ErrorField(err))
				}
			}

			s.auditService.LogAction(auditCtx,
				&companyID,
				"attendance",
				action,
				strings.Split(action, ".")[0],
				&resourceID,
				actorType,
				&actorID,
				beforeJSON,
				afterJSON,
				metadata,
			)
		}()
	}
}

func normalizeSourceType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func isValidAttendanceEventType(eventType string) bool {
	validEventTypes := map[string]bool{
		"check_in":              true,
		"check_out":             true,
		"break_start":           true,
		"break_end":             true,
		"shift_start":           true,
		"shift_end":             true,
		"overtime_start":        true,
		"overtime_end":          true,
		"early_exit":            true,
		"late_entry":            true,
		"gate_entry":            true,
		"gate_exit":             true,
		"zone_entry":            true,
		"zone_exit":             true,
		"class_start":           true,
		"class_end":             true,
		"session_join":          true,
		"session_leave":         true,
		"leave_start":           true,
		"leave_end":             true,
		"absent_marked":         true,
		"holiday_marked":        true,
		"weekly_off":            true,
		"manual_check_in":       true,
		"manual_check_out":      true,
		"manual_override":       true,
		"attendance_adjustment": true,
		"biometric_sync":        true,
		"rfid_scan":             true,
		"system_generated":      true,
		"imported_event":        true,
		"missing_punch":         true,
		"duplicate_punch":       true,
		"invalid_punch":         true,
		"policy_violation":      true,
	}
	return validEventTypes[eventType]
}
func (s *attendanceAdminService) CreateAttendanceCorrection(
	ctx context.Context,
	req *AttendanceCorrectionRequest,
) error {
	startTime := time.Now()

	// ─────────────────────────────
	// 1️⃣ Validate correction type
	// ─────────────────────────────
	if !isValidCorrectionType(req.CorrectionType) {
		return fmt.Errorf("invalid correction type: %s", req.CorrectionType)
	}

	// ─────────────────────────────
	// 2️⃣ Validate required fields
	// ─────────────────────────────
	if req.CorrectionType == "manual_check_in" || req.CorrectionType == "manual_check_out" {
		if req.EventTime == nil {
			return fmt.Errorf("event_time is required for %s", req.CorrectionType)
		}
	}

	if req.CorrectionType == "manual_override" || req.CorrectionType == "attendance_adjustment" {
		if req.OverrideStatus == "" {
			return fmt.Errorf("override_status is required for %s", req.CorrectionType)
		}
		if !isValidAttendanceStatus(req.OverrideStatus) {
			return fmt.Errorf("invalid override_status: %s", req.OverrideStatus)
		}
	}

	// ─────────────────────────────
	// 🔴 FIX: event_time must match business_date
	// ─────────────────────────────
	if req.EventTime != nil {
		eventDate := req.EventTime.In(req.BusinessDate.Location()).Format("2006-01-02")
		businessDate := req.BusinessDate.Format("2006-01-02")

		if eventDate != businessDate {
			return fmt.Errorf(
				"event_time (%s) must belong to business_date (%s)",
				eventDate,
				businessDate,
			)
		}
	}

	// ─────────────────────────────
	// 3️⃣ De-duplication check
	// ─────────────────────────────
	if req.EventTime != nil {
		existingCorrection, err := s.attendanceRepo.FindExistingCorrection(
			ctx,
			req.CompanyID,
			req.TargetUserID,
			req.CorrectionType,
			*req.EventTime,
		)
		if err != nil {
			return fmt.Errorf("failed to check existing correction: %w", err)
		}
		if existingCorrection != nil {
			return fmt.Errorf("correction already exists for this event")
		}
	}

	// ─────────────────────────────
	// 4️⃣ Determine event time
	// ─────────────────────────────
	var eventTime time.Time
	if req.EventTime != nil {
		eventTime = *req.EventTime
	} else {
		eventTime = time.Date(
			req.BusinessDate.Year(),
			req.BusinessDate.Month(),
			req.BusinessDate.Day(),
			0, 0, 0, 0,
			req.BusinessDate.Location(),
		)
	}

	// ─────────────────────────────
	// 5️⃣ Create correction event
	// ─────────────────────────────
	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         req.CompanyID,
		UserID:            req.TargetUserID,
		EventType:         req.CorrectionType,
		EventTime:         eventTime,
		SourceType:        "manual",
		SourceID:          nil,
		DeviceID:          nil,
		IPAddress:         nil,

		// ✅ Human intent lives here
		Context: attendance.EventContext{
			CorrectionReason: &req.Reason,
		},

		// ✅ System / resolution metadata
		Metadata: attendance.EventMetadata{
			IsCorrection:   boolPtr(true),
			OverrideStatus: &req.OverrideStatus,
			CorrectedBy:    &req.ActorID,
		},

		CreatedAt: time.Now().UTC(),
		CreatedBy: &req.ActorID,
	}

	// ─────────────────────────────
	// 6️⃣ Persist event
	// ─────────────────────────────
	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
		s.logger.Error("Failed to create correction event",
			zap.String("company_id", req.CompanyID.String()),
			zap.String("user_id", req.TargetUserID.String()),
			zap.String("correction_type", req.CorrectionType),
			zap.Error(err))
		return fmt.Errorf("failed to create correction event: %w", err)
	}

	// ─────────────────────────────
	// 7️⃣ Recalculate attendance day
	// ─────────────────────────────
	if err := s.resolutionService.RecalculateDay(
		ctx,
		req.CompanyID,
		req.TargetUserID,
		req.BusinessDate,
	); err != nil {
		s.logger.Warn("Correction created but recalculation failed",
			zap.String("event_id", event.AttendanceEventID.String()),
			zap.Error(err))
	}

	// ─────────────────────────────
	// 8️⃣ Audit
	// ─────────────────────────────
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"correction_type": req.CorrectionType,
			"business_date":   req.BusinessDate.Format("2006-01-02"),
			"event_time":      eventTime.Format(time.RFC3339),
			"reason":          req.Reason,
			"override_status": req.OverrideStatus,
		}

		s.logAuditAction(
			ctx,
			req.CompanyID,
			"attendance.correction.create",
			event.AttendanceEventID,
			req.ActorType,
			req.ActorID,
			nil,
			event,
			metadata,
		)
	}

	s.logger.Info("Attendance correction created",
		zap.String("event_id", event.AttendanceEventID.String()),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("user_id", req.TargetUserID.String()),
		zap.String("correction_type", req.CorrectionType),
		zap.String("business_date", req.BusinessDate.Format("2006-01-02")),
		zap.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// Helper functions
func isValidCorrectionType(correctionType string) bool {
	validTypes := map[string]bool{
		"manual_check_in":       true,
		"manual_check_out":      true,
		"attendance_adjustment": true,
		"manual_override":       true,
	}
	return validTypes[correctionType]
}

func isValidAttendanceStatus(status string) bool {
	validStatuses := []string{
		"present", "absent", "late", "half_day", "incomplete",
		"weekly_off", "holiday", "on_leave", "not_scheduled",
	}
	for _, s := range validStatuses {
		if s == status {
			return true
		}
	}
	return false
}
