package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

// AttendanceRuleService defines the business operations for attendance rules.
type AttendanceRuleService interface {
	CreateRule(ctx context.Context, input CreateAttendanceRuleInput) (*models.AttendanceRule, error)
	UpdateRuleVersion(ctx context.Context, input UpdateAttendanceRuleInput) (*models.AttendanceRule, error)
	ActivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error
	DeactivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error
	BulkDeactivateByType(ctx context.Context, companyID uuid.UUID, ruleType string, actorID uuid.UUID) error
	GetRuleByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.AttendanceRule, error)
	GetActiveRules(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.AttendanceRule, error)
	GetRulesByFilter(ctx context.Context, filter models.AttendanceRuleFilter) ([]models.AttendanceRule, int, error)
	GetRulesByType(ctx context.Context, companyID uuid.UUID, ruleType string) ([]models.AttendanceRule, error)
	ValidateRuleConsistency(rule *models.AttendanceRule) error
	ExistsActiveRuleOfType(ctx context.Context, companyID uuid.UUID, ruleType string) (bool, error)
}

// CreateAttendanceRuleInput
type CreateAttendanceRuleInput struct {
	CompanyID        uuid.UUID
	RuleType         string
	CalculationType  string
	Value            float64
	BasedOn          *string
	ThresholdMinutes int
	ComponentCode    string
	CreatedBy        uuid.UUID
}

// UpdateAttendanceRuleInput
type UpdateAttendanceRuleInput struct {
	CompanyID        uuid.UUID
	RuleID           uuid.UUID
	RuleType         string
	CalculationType  string
	Value            float64
	BasedOn          *string
	ThresholdMinutes int
	ComponentCode    string
	UpdatedBy        uuid.UUID
}

type attendanceRuleService struct {
	ruleRepo         repository.AttendanceRuleRepository
	compRepo         repository.ComponentRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

// NewAttendanceRuleService now requires idempotency and audit.
func NewAttendanceRuleService(
	ruleRepo repository.AttendanceRuleRepository,
	compRepo repository.ComponentRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) AttendanceRuleService {
	return &attendanceRuleService{
		ruleRepo:         ruleRepo,
		compRepo:         compRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// CreateRule – with idempotency and audit
func (s *attendanceRuleService) CreateRule(ctx context.Context, input CreateAttendanceRuleInput) (*models.AttendanceRule, error) {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("att_rule_create-%s-%s", input.CompanyID.String(), input.RuleType)
	}
	var cached *models.AttendanceRule
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// Validations
	if input.CompanyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if input.RuleType == "" {
		return nil, errors.New("rule_type is required")
	}
	if input.CalculationType == "" {
		return nil, errors.New("calculation_type is required")
	}
	if input.Value <= 0 {
		return nil, errors.New("value must be positive")
	}
	if input.ThresholdMinutes < 0 {
		return nil, errors.New("threshold_minutes cannot be negative")
	}
	if input.ComponentCode == "" {
		return nil, errors.New("component_code is required")
	}
	if input.CreatedBy == uuid.Nil {
		return nil, errors.New("created_by is required")
	}

	// Validate component
	comp, err := s.compRepo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to validate component: %w", err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s does not exist for company %s", input.ComponentCode, input.CompanyID)
	}

	rule := &models.AttendanceRule{
		RuleID:           uuid.New(),
		CompanyID:        input.CompanyID,
		RuleType:         input.RuleType,
		CalculationType:  input.CalculationType,
		Value:            input.Value,
		BasedOn:          input.BasedOn,
		ThresholdMinutes: input.ThresholdMinutes,
		ComponentCode:    input.ComponentCode,
		IsActive:         true,
		CreatedBy:        &input.CreatedBy,
	}

	if err := s.ValidateRuleConsistency(rule); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	beforeJSON, _ := json.Marshal(rule)
	if err := s.ruleRepo.Create(ctx, rule); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(rule)

	// Audit
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := map[string]interface{}{
		"ip":             ip,
		"company_id":     input.CompanyID.String(),
		"rule_type":      input.RuleType,
		"component_code": input.ComponentCode,
	}
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"attendance_rule.create",
		"attendance_rule",
		&rule.RuleID,
		"user",
		&input.CreatedBy,
		beforeJSON,
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, rule)
	return rule, nil
}

// UpdateRuleVersion – with idempotency and audit
func (s *attendanceRuleService) UpdateRuleVersion(ctx context.Context, input UpdateAttendanceRuleInput) (*models.AttendanceRule, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("att_rule_update-%s", input.RuleID.String())
	}
	var cached *models.AttendanceRule
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// Validations
	if input.CompanyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if input.RuleID == uuid.Nil {
		return nil, errors.New("rule_id is required")
	}
	if input.RuleType == "" {
		return nil, errors.New("rule_type is required")
	}
	if input.CalculationType == "" {
		return nil, errors.New("calculation_type is required")
	}
	if input.Value <= 0 {
		return nil, errors.New("value must be positive")
	}
	if input.ThresholdMinutes < 0 {
		return nil, errors.New("threshold_minutes cannot be negative")
	}
	if input.ComponentCode == "" {
		return nil, errors.New("component_code is required")
	}
	if input.UpdatedBy == uuid.Nil {
		return nil, errors.New("updated_by is required")
	}

	comp, err := s.compRepo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to validate component: %w", err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s does not exist", input.ComponentCode)
	}

	existing, err := s.ruleRepo.GetByID(ctx, input.CompanyID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("rule not found")
	}
	beforeJSON, _ := json.Marshal(existing)

	// Deactivate old if active
	if existing.IsActive {
		if err := s.ruleRepo.SoftDeactivate(ctx, input.CompanyID, input.RuleID, input.UpdatedBy); err != nil {
			return nil, fmt.Errorf("failed to deactivate old rule: %w", err)
		}
	}

	newRule := &models.AttendanceRule{
		RuleID:           uuid.New(),
		CompanyID:        input.CompanyID,
		RuleType:         input.RuleType,
		CalculationType:  input.CalculationType,
		Value:            input.Value,
		BasedOn:          input.BasedOn,
		ThresholdMinutes: input.ThresholdMinutes,
		ComponentCode:    input.ComponentCode,
		IsActive:         true,
		CreatedBy:        &input.UpdatedBy,
	}

	if err := s.ValidateRuleConsistency(newRule); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if err := s.ruleRepo.Create(ctx, newRule); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(newRule)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := map[string]interface{}{
		"ip":             ip,
		"old_rule_id":    input.RuleID.String(),
		"new_rule_id":    newRule.RuleID.String(),
		"component_code": input.ComponentCode,
	}
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"attendance_rule.update",
		"attendance_rule",
		&newRule.RuleID,
		"user",
		&input.UpdatedBy,
		beforeJSON,
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, newRule)
	return newRule, nil
}

// ActivateRule – with idempotency
func (s *attendanceRuleService) ActivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("att_rule_activate-%s", ruleID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	rule, err := s.ruleRepo.GetByID(ctx, companyID, ruleID)
	if err != nil {
		return err
	}
	if rule == nil {
		return errors.New("rule not found")
	}
	if rule.IsActive {
		return errors.New("rule is already active")
	}
	beforeJSON, _ := json.Marshal(rule)

	rule.IsActive = true
	rule.UpdatedAt = nil
	rule.UpdatedBy = &actorID
	if err := s.ruleRepo.Update(ctx, rule); err != nil {
		return fmt.Errorf("failed to activate rule: %w", err)
	}
	afterJSON, _ := json.Marshal(rule)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"attendance_rule.activate",
		"attendance_rule",
		&ruleID,
		"user",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// DeactivateRule – with idempotency
func (s *attendanceRuleService) DeactivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("att_rule_deactivate-%s", ruleID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	rule, err := s.ruleRepo.GetByID(ctx, companyID, ruleID)
	if err != nil {
		return err
	}
	if rule == nil {
		return errors.New("rule not found")
	}
	if !rule.IsActive {
		return errors.New("rule is already inactive")
	}
	beforeJSON, _ := json.Marshal(rule)

	if err := s.ruleRepo.SoftDeactivate(ctx, companyID, ruleID, actorID); err != nil {
		return fmt.Errorf("failed to deactivate rule: %w", err)
	}
	afterJSON, _ := json.Marshal(rule)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"attendance_rule.deactivate",
		"attendance_rule",
		&ruleID,
		"user",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// BulkDeactivateByType – with idempotency (store boolean)
func (s *attendanceRuleService) BulkDeactivateByType(ctx context.Context, companyID uuid.UUID, ruleType string, actorID uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("att_rule_bulk_deact-%s-%s", companyID.String(), ruleType)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if companyID == uuid.Nil || ruleType == "" || actorID == uuid.Nil {
		return errors.New("invalid input")
	}

	// Fetch rules to deactivate for audit
	rules, err := s.ruleRepo.GetByRuleType(ctx, companyID, ruleType)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(rules)

	if err := s.ruleRepo.BulkDeactivateByType(ctx, companyID, ruleType, actorID); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(rules) // state after – may need to fetch again; but we'll just mark as changed

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"attendance_rule.bulk_deactivate",
		"attendance_rule",
		nil,
		"user",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"ip":        ip,
			"rule_type": ruleType,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// Read methods – no idempotency, but we add audit for sensitive reads (optional)
// We'll keep them as is but remove logger.
func (s *attendanceRuleService) GetRuleByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.AttendanceRule, error) {
	if companyID == uuid.Nil || ruleID == uuid.Nil {
		return nil, errors.New("invalid IDs")
	}
	return s.ruleRepo.GetByID(ctx, companyID, ruleID)
}

func (s *attendanceRuleService) GetActiveRules(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.AttendanceRule, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	return s.ruleRepo.GetActiveByCompany(ctx, companyID, asOf)
}

func (s *attendanceRuleService) GetRulesByFilter(ctx context.Context, filter models.AttendanceRuleFilter) ([]models.AttendanceRule, int, error) {
	if filter.CompanyID == uuid.Nil {
		return nil, 0, errors.New("company_id is required in filter")
	}
	return s.ruleRepo.GetByFilter(ctx, filter)
}

func (s *attendanceRuleService) GetRulesByType(ctx context.Context, companyID uuid.UUID, ruleType string) ([]models.AttendanceRule, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if ruleType == "" {
		return nil, errors.New("rule_type is required")
	}
	return s.ruleRepo.GetByRuleType(ctx, companyID, ruleType)
}

func (s *attendanceRuleService) ValidateRuleConsistency(rule *models.AttendanceRule) error {
	// unchanged – kept as is
	if rule == nil {
		return errors.New("rule cannot be nil")
	}
	if rule.CompanyID == uuid.Nil {
		return errors.New("company_id is required")
	}
	if rule.RuleType == "" {
		return errors.New("rule_type is required")
	}
	if rule.CalculationType == "" {
		return errors.New("calculation_type is required")
	}
	if rule.Value <= 0 {
		return errors.New("value must be positive")
	}
	if rule.ThresholdMinutes < 0 {
		return errors.New("threshold_minutes cannot be negative")
	}

	switch rule.RuleType {
	case models.RuleTypeOvertime:
		if rule.BasedOn == nil {
			return errors.New("based_on is required for overtime rules")
		}
		if *rule.BasedOn != models.BasedOnDaily && *rule.BasedOn != models.BasedOnHourly {
			return fmt.Errorf("based_on for overtime must be '%s' or '%s'", models.BasedOnDaily, models.BasedOnHourly)
		}
		if rule.CalculationType != models.CalculationTypePercentage &&
			rule.CalculationType != models.CalculationTypeMultiplier &&
			rule.CalculationType != models.CalculationTypeFlat {
			return fmt.Errorf("invalid calculation_type '%s' for overtime", rule.CalculationType)
		}
	case models.RuleTypeLate:
		if rule.ThresholdMinutes == 0 {
			return errors.New("threshold_minutes must be >0 for late rules")
		}
		if rule.BasedOn != nil {
			if *rule.BasedOn != models.BasedOnDaily && *rule.BasedOn != models.BasedOnHourly {
				return fmt.Errorf("based_on for late must be '%s' or '%s' if provided", models.BasedOnDaily, models.BasedOnHourly)
			}
		}
		if rule.CalculationType != models.CalculationTypePercentage &&
			rule.CalculationType != models.CalculationTypeMultiplier &&
			rule.CalculationType != models.CalculationTypeFlat {
			return fmt.Errorf("invalid calculation_type '%s' for late", rule.CalculationType)
		}
	case models.RuleTypeAbsent:
		if rule.BasedOn != nil {
			return errors.New("based_on must be empty for absent rules")
		}
		if rule.CalculationType != models.CalculationTypeMultiplier &&
			rule.CalculationType != models.CalculationTypePercentage &&
			rule.CalculationType != models.CalculationTypeFlat {
			return fmt.Errorf("invalid calculation_type '%s' for absent", rule.CalculationType)
		}
	default:
		return fmt.Errorf("unsupported rule_type: %s", rule.RuleType)
	}

	switch rule.CalculationType {
	case models.CalculationTypePercentage:
		if rule.Value < 0 || rule.Value > 100 {
			return errors.New("percentage value must be between 0 and 100")
		}
	case models.CalculationTypeMultiplier:
		if rule.Value < 0 {
			return errors.New("multiplier value cannot be negative")
		}
	case models.CalculationTypeFlat:
	default:
		return fmt.Errorf("unsupported calculation_type: %s", rule.CalculationType)
	}
	return nil
}

func (s *attendanceRuleService) ExistsActiveRuleOfType(ctx context.Context, companyID uuid.UUID, ruleType string) (bool, error) {
	if companyID == uuid.Nil {
		return false, errors.New("company_id is required")
	}
	if ruleType == "" {
		return false, errors.New("rule_type is required")
	}
	return s.ruleRepo.ExistsActiveRuleOfType(ctx, companyID, ruleType)
}
