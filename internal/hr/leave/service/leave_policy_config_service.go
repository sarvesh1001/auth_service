package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================
// INTERFACE
// =====================================

type LeavePolicyConfigService interface {

	// ============================
	// POLICY
	// ============================

	CreatePolicy(
		ctx context.Context,
		policy *models.LeavePolicy,
	) (*models.LeavePolicy, error)

	DeactivatePolicy(
		ctx context.Context,
		policyID uuid.UUID,
	) error

	GetPolicy(
		ctx context.Context,
		policyID uuid.UUID,
	) (*models.LeavePolicy, error)

	ListActivePolicies(
		ctx context.Context,
		companyID uuid.UUID,
		asOf time.Time,
	) ([]*models.LeavePolicy, error)

	// ============================
	// RULES
	// ============================
	UpdatePolicy(
		ctx context.Context,
		policyID uuid.UUID,
		update *models.LeavePolicyUpdate,
	) error

	AddPolicyRule(
		ctx context.Context,
		rule *models.LeavePolicyRule,
	) (*models.LeavePolicyRule, error)
	UpdatePolicyRule(
		ctx context.Context,
		companyID uuid.UUID,
		policyRuleID uuid.UUID,
		update *models.LeavePolicyRuleUpdate,
	) error

	RemovePolicyRule(
		ctx context.Context,
		policyRuleID uuid.UUID,
	) error

	GetPolicyRules(
		ctx context.Context,
		policyID uuid.UUID,
	) ([]*models.LeavePolicyRule, error)
}

// =====================================
// SERVICE
// =====================================

type leavePolicyConfigService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeavePolicyConfigService(
	repo repository.LeaveRepository,
	logger *zap.Logger,
) LeavePolicyConfigService {
	return &leavePolicyConfigService{
		repo:   repo,
		logger: logger.Named("leave_policy_config_service"),
	}
}

// =====================================
// POLICY
// =====================================

func (s *leavePolicyConfigService) CreatePolicy(
	ctx context.Context,
	policy *models.LeavePolicy,
) (*models.LeavePolicy, error) {

	if policy.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}
	if policy.PolicyName == "" {
		return nil, fmt.Errorf("policy_name is required")
	}
	if policy.AppliesToType == "" {
		return nil, fmt.Errorf("applies_to_type is required")
	}

	switch policy.AppliesToType {
	case "company":
		policy.AppliesToPositionID = nil
		policy.AppliesToWorkCenterCode = nil

	case "position":
		if policy.AppliesToPositionID == nil {
			return nil, fmt.Errorf("applies_to_position_id required")
		}

	case "work_center":
		if policy.AppliesToWorkCenterCode == nil {
			return nil, fmt.Errorf("applies_to_work_center_code required")
		}

	default:
		return nil, fmt.Errorf("invalid applies_to_type")
	}

	if policy.Priority <= 0 {
		return nil, fmt.Errorf("priority must be > 0")
	}

	policy.PolicyID = uuid.New()
	policy.IsActive = true
	policy.CreatedAt = time.Now().UTC()

	if err := s.repo.CreateLeavePolicy(ctx, policy); err != nil {
		s.logger.Error("CreateLeavePolicy failed", zap.Error(err))
		return nil, err
	}

	return policy, nil
}

func (s *leavePolicyConfigService) DeactivatePolicy(
	ctx context.Context,
	policyID uuid.UUID,
) error {

	if policyID == uuid.Nil {
		return fmt.Errorf("policy_id required")
	}

	return s.repo.DeactivateLeavePolicy(ctx, policyID)
}

func (s *leavePolicyConfigService) GetPolicy(
	ctx context.Context,
	policyID uuid.UUID,
) (*models.LeavePolicy, error) {

	if policyID == uuid.Nil {
		return nil, fmt.Errorf("policy_id required")
	}

	return s.repo.GetLeavePolicyByID(ctx, policyID)
}

func (s *leavePolicyConfigService) ListActivePolicies(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
) ([]*models.LeavePolicy, error) {

	return s.repo.GetActiveLeavePoliciesByCompany(ctx, companyID, asOf)
}

// =====================================
// RULES
// =====================================

func (s *leavePolicyConfigService) AddPolicyRule(
	ctx context.Context,
	rule *models.LeavePolicyRule,
) (*models.LeavePolicyRule, error) {

	if rule.PolicyID == uuid.Nil {
		return nil, fmt.Errorf("policy_id required")
	}
	if rule.LeaveTypeID == uuid.Nil {
		return nil, fmt.Errorf("leave_type_id required")
	}
	if rule.TotalDays <= 0 {
		return nil, fmt.Errorf("total_days must be > 0")
	}

	rule.PolicyRuleID = uuid.New()
	rule.CreatedAt = time.Now().UTC()

	if err := s.repo.AddPolicyRule(ctx, rule); err != nil {
		s.logger.Error("AddPolicyRule failed", zap.Error(err))
		return nil, err
	}

	return rule, nil
}

func (s *leavePolicyConfigService) RemovePolicyRule(
	ctx context.Context,
	policyRuleID uuid.UUID,
) error {

	if policyRuleID == uuid.Nil {
		return fmt.Errorf("policy_rule_id required")
	}

	return s.repo.DeletePolicyRule(ctx, policyRuleID)
}

func (s *leavePolicyConfigService) GetPolicyRules(
	ctx context.Context,
	policyID uuid.UUID,
) ([]*models.LeavePolicyRule, error) {

	if policyID == uuid.Nil {
		return nil, fmt.Errorf("policy_id required")
	}

	return s.repo.GetPolicyRules(ctx, policyID)
}
func (s *leavePolicyConfigService) UpdatePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	update *models.LeavePolicyUpdate,
) error {

	if policyID == uuid.Nil {
		return fmt.Errorf("policy_id required")
	}

	if update.AppliesToType != nil {
		switch *update.AppliesToType {
		case "company":
			update.AppliesToPositionID = nil
			update.AppliesToWorkCenterCode = nil
		case "position":
			if update.AppliesToPositionID == nil {
				return fmt.Errorf("applies_to_position_id required")
			}
		case "work_center":
			if update.AppliesToWorkCenterCode == nil {
				return fmt.Errorf("applies_to_work_center_code required")
			}
		default:
			return fmt.Errorf("invalid applies_to_type")
		}
	}

	if update.Priority != nil && *update.Priority <= 0 {
		return fmt.Errorf("priority must be > 0")
	}

	return s.repo.UpdateLeavePolicy(ctx, policyID, update)
}
func (s *leavePolicyConfigService) UpdatePolicyRule(
	ctx context.Context,
	companyID uuid.UUID,
	policyRuleID uuid.UUID,
	update *models.LeavePolicyRuleUpdate,
) error {

	if policyRuleID == uuid.Nil {
		return fmt.Errorf("policy_rule_id required")
	}

	if companyID == uuid.Nil {
		return fmt.Errorf("company_id required")
	}

	// Ensure at least one field is provided
	if update.TotalDays == nil &&
		update.AccrualMethod == nil &&
		update.CarryForwardLimit == nil {
		return fmt.Errorf("at least one field must be provided for update")
	}

	// Validate total days
	if update.TotalDays != nil && *update.TotalDays <= 0 {
		return fmt.Errorf("total_days must be > 0")
	}

	// Validate carry forward
	if update.CarryForwardLimit != nil && *update.CarryForwardLimit < 0 {
		return fmt.Errorf("carry_forward_limit cannot be negative")
	}

	// Validate accrual method
	if update.AccrualMethod != nil {
		validAccrualMethods := map[string]bool{
			"none":      true,
			"monthly":   true,
			"quarterly": true,
			"yearly":    true,
		}

		if !validAccrualMethods[*update.AccrualMethod] {
			return fmt.Errorf("invalid accrual method: %s", *update.AccrualMethod)
		}
	}

	if err := s.repo.UpdatePolicyRule(ctx, companyID, policyRuleID, update); err != nil {
		s.logger.Error("UpdatePolicyRule failed",
			zap.String("policy_rule_id", policyRuleID.String()),
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return err
	}

	return nil
}
