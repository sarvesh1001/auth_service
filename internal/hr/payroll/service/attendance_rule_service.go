package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
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

// CreateAttendanceRuleInput now includes ComponentCode.
type CreateAttendanceRuleInput struct {
	CompanyID        uuid.UUID
	RuleType         string
	CalculationType  string
	Value            float64
	BasedOn          *string
	ThresholdMinutes int
	ComponentCode    string // NEW: payroll component linked to this rule
	CreatedBy        uuid.UUID
}

// UpdateAttendanceRuleInput now includes ComponentCode.
type UpdateAttendanceRuleInput struct {
	CompanyID        uuid.UUID
	RuleID           uuid.UUID
	RuleType         string
	CalculationType  string
	Value            float64
	BasedOn          *string
	ThresholdMinutes int
	ComponentCode    string // NEW
	UpdatedBy        uuid.UUID
}

type attendanceRuleService struct {
	ruleRepo repository.AttendanceRuleRepository
	compRepo repository.ComponentRepository // NEW: to validate component existence
	logger   *zap.Logger
}

// NewAttendanceRuleService now requires a ComponentRepository.
func NewAttendanceRuleService(
	ruleRepo repository.AttendanceRuleRepository,
	compRepo repository.ComponentRepository,
	logger *zap.Logger,
) AttendanceRuleService {
	return &attendanceRuleService{
		ruleRepo: ruleRepo,
		compRepo: compRepo,
		logger:   logger,
	}
}

func (s *attendanceRuleService) CreateRule(ctx context.Context, input CreateAttendanceRuleInput) (*models.AttendanceRule, error) {
	// Basic validations
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

	// Validate that the component exists and belongs to the company.
	comp, err := s.compRepo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to validate component: %w", err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s does not exist for company %s", input.ComponentCode, input.CompanyID)
	}
	// Optionally, you can enforce that the component is of the correct type (e.g., deduction for late/absent, earning for overtime)
	// but for now we just ensure it exists.

	rule := &models.AttendanceRule{
		RuleID:           uuid.New(),
		CompanyID:        input.CompanyID,
		RuleType:         input.RuleType,
		CalculationType:  input.CalculationType,
		Value:            input.Value,
		BasedOn:          input.BasedOn,
		ThresholdMinutes: input.ThresholdMinutes,
		ComponentCode:    input.ComponentCode, // NEW
		IsActive:         true,
		CreatedBy:        &input.CreatedBy,
	}

	if err := s.ValidateRuleConsistency(rule); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if err := s.ruleRepo.Create(ctx, rule); err != nil {
		return nil, err
	}

	s.logger.Info("Attendance rule created",
		zap.String("rule_id", rule.RuleID.String()),
		zap.String("company_id", rule.CompanyID.String()),
		zap.String("rule_type", rule.RuleType),
		zap.String("component_code", rule.ComponentCode))

	return rule, nil
}

func (s *attendanceRuleService) UpdateRuleVersion(ctx context.Context, input UpdateAttendanceRuleInput) (*models.AttendanceRule, error) {
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

	// Validate component existence.
	comp, err := s.compRepo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to validate component: %w", err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s does not exist for company %s", input.ComponentCode, input.CompanyID)
	}

	existing, err := s.ruleRepo.GetByID(ctx, input.CompanyID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("rule not found")
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

	if existing.IsActive {
		if err := s.ruleRepo.SoftDeactivate(ctx, input.CompanyID, input.RuleID, input.UpdatedBy); err != nil {
			return nil, fmt.Errorf("failed to deactivate old rule: %w", err)
		}
	}

	if err := s.ruleRepo.Create(ctx, newRule); err != nil {
		return nil, err
	}

	s.logger.Info("Attendance rule version created",
		zap.String("old_rule_id", input.RuleID.String()),
		zap.String("new_rule_id", newRule.RuleID.String()),
		zap.String("company_id", input.CompanyID.String()),
		zap.String("component_code", newRule.ComponentCode))

	return newRule, nil
}

// ActivateRule, DeactivateRule, BulkDeactivateByType, GetRuleByID, GetActiveRules,
// GetRulesByFilter, GetRulesByType remain unchanged except for logging if needed.

func (s *attendanceRuleService) ActivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error {
	if companyID == uuid.Nil || ruleID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid input: all IDs must be non-nil")
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

	rule.IsActive = true
	rule.UpdatedAt = nil
	rule.UpdatedBy = &actorID

	if err := s.ruleRepo.Update(ctx, rule); err != nil {
		return fmt.Errorf("failed to activate rule: %w", err)
	}

	s.logger.Info("Attendance rule activated",
		zap.String("rule_id", ruleID.String()),
		zap.String("company_id", companyID.String()))

	return nil
}

func (s *attendanceRuleService) DeactivateRule(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error {
	if companyID == uuid.Nil || ruleID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid input: all IDs must be non-nil")
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

	if err := s.ruleRepo.SoftDeactivate(ctx, companyID, ruleID, actorID); err != nil {
		return fmt.Errorf("failed to deactivate rule: %w", err)
	}

	s.logger.Info("Attendance rule deactivated",
		zap.String("rule_id", ruleID.String()),
		zap.String("company_id", companyID.String()))

	return nil
}

func (s *attendanceRuleService) BulkDeactivateByType(ctx context.Context, companyID uuid.UUID, ruleType string, actorID uuid.UUID) error {
	if companyID == uuid.Nil {
		return errors.New("company_id is required")
	}
	if ruleType == "" {
		return errors.New("rule_type is required")
	}
	if actorID == uuid.Nil {
		return errors.New("actor_id is required")
	}

	if err := s.ruleRepo.BulkDeactivateByType(ctx, companyID, ruleType, actorID); err != nil {
		return err
	}

	s.logger.Info("Bulk deactivated attendance rules by type",
		zap.String("company_id", companyID.String()),
		zap.String("rule_type", ruleType))

	return nil
}

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

// ValidateRuleConsistency remains unchanged because it only validates rule type and calculation.
// It does not need to validate component_code.
func (s *attendanceRuleService) ValidateRuleConsistency(rule *models.AttendanceRule) error {
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
