package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================================
// SERVICE INTERFACE
// =====================================================

type LeavePolicyResolutionService interface {
	ResolveUserLeaveEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
		reason string,
	) error

	ResolveBatchLeaveEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userIDs []uuid.UUID,
		asOf time.Time,
		reason string,
	) (*LeavePolicyResolutionResult, error)

	GetLeaveEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)

	GetUserEffectivePolicies(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) ([]*models.LeavePolicyRuleResolution, error)
}

// =====================================================
// IMPLEMENTATION
// =====================================================

type leavePolicyResolutionService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

type LeavePolicyResolutionResult struct {
	TotalUsers     int
	ProcessedUsers int
	FailedUsers    []uuid.UUID
	Errors         []string
}

func NewLeavePolicyResolutionService(
	repo repository.LeaveRepository,
	logger *zap.Logger,
) LeavePolicyResolutionService {
	return &leavePolicyResolutionService{
		repo:   repo,
		logger: logger.Named("leave_policy_resolution_service"),
	}
}

// =====================================================
// CORE LOGIC
// =====================================================
func (s *leavePolicyResolutionService) ResolveUserLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
	reason string,
) error {

	s.logger.Info("Resolving leave entitlements",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Time("as_of", asOf),
	)

	// 🔥 Snapshot user position context ONCE
	positionID, workCenterCode, err := s.repo.GetUserPositionContext(
		ctx,
		companyID,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to get user position context: %w", err)
	}

	// 1. Resolve effective policy rules
	rules, err := s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
	if err != nil {
		return fmt.Errorf("resolve policy rules failed: %w", err)
	}

	if len(rules) == 0 {
		s.logger.Debug("No applicable policy rules",
			util.String("user_id", userID.String()),
		)
		return nil
	}

	processedLeaveTypes := make(map[uuid.UUID]bool)
	processedPolicies := make(map[uuid.UUID]bool)

	// 2. Apply rules PER LEAVE TYPE (IDEMPOTENT)
	for _, rule := range rules {
		if processedLeaveTypes[rule.LeaveTypeID] {
			continue
		}

		// 🔒 Check existing active policy entitlement (position-aware)
		existing, err := s.repo.GetActivePolicyEntitlement(
			ctx,
			companyID,
			userID,
			rule.LeaveTypeID,
			positionID,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to check existing entitlement (leave_type=%s): %w",
				rule.LeaveTypeID, err,
			)
		}

		// ✅ Idempotency: same policy + same days → skip
		if existing != nil &&
			existing.PolicyID != nil &&
			*existing.PolicyID == rule.PolicyID &&
			existing.TotalDays == rule.TotalDays {

			s.logger.Debug("Skipping unchanged entitlement",
				util.String("user_id", userID.String()),
				util.String("leave_type_id", rule.LeaveTypeID.String()),
				util.String("policy_id", rule.PolicyID.String()),
			)

			processedLeaveTypes[rule.LeaveTypeID] = true
			processedPolicies[rule.PolicyID] = true
			continue
		}

		// 🔥 End old entitlement if exists / changed
		if err := s.repo.EndActivePolicyEntitlementsByLeaveType(
			ctx,
			companyID,
			userID,
			rule.LeaveTypeID,
			asOf,
			positionID,
		); err != nil {
			return fmt.Errorf(
				"end entitlement failed (leave_type=%s): %w",
				rule.LeaveTypeID, err,
			)
		}

		// ✅ Create new entitlement snapshot
		entitlement := &models.LeaveEntitlement{
			EntitlementID:  uuid.New(),
			CompanyID:      companyID,
			UserID:         userID,
			LeaveTypeID:    rule.LeaveTypeID,
			TotalDays:      rule.TotalDays,
			EffectiveFrom:  asOf,
			PolicyID:       &rule.PolicyID,
			Source:         "policy",
			CreatedAt:      time.Now().UTC(),
			PositionID:     positionID,
			WorkCenterCode: workCenterCode,
		}

		if err := s.repo.CreatePolicyLeaveEntitlement(ctx, entitlement); err != nil {
			return fmt.Errorf(
				"create entitlement failed (leave_type=%s): %w",
				rule.LeaveTypeID, err,
			)
		}

		processedLeaveTypes[rule.LeaveTypeID] = true
		processedPolicies[rule.PolicyID] = true
	}

	// 3. Audit (multi-policy resolution)
	metadata := map[string]interface{}{
		"company_id":     companyID.String(),
		"user_id":        userID.String(),
		"resolved_at":    asOf,
		"reason":         reason,
		"leave_type_ids": keysUUID(processedLeaveTypes),
		"policy_ids":     keysUUID(processedPolicies),
		"rule_count":     len(rules),
	}

	if err := s.repo.CreateLeavePolicyResolution(
		ctx,
		companyID,
		userID,
		nil, // multi-policy resolution
		reason,
		metadata,
	); err != nil {
		return fmt.Errorf("policy resolution audit failed: %w", err)
	}

	s.logger.Info("Leave entitlement resolution completed",
		util.String("user_id", userID.String()),
		util.Int("leave_types", len(processedLeaveTypes)),
		util.Int("policies", len(processedPolicies)),
	)

	return nil
}

// =====================================================
// BATCH
// =====================================================

func (s *leavePolicyResolutionService) ResolveBatchLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	asOf time.Time,
	reason string,
) (*LeavePolicyResolutionResult, error) {

	result := &LeavePolicyResolutionResult{
		TotalUsers:  len(userIDs),
		FailedUsers: []uuid.UUID{},
		Errors:      []string{},
	}

	for _, userID := range userIDs {
		if err := s.ResolveUserLeaveEntitlements(ctx, companyID, userID, asOf, reason); err != nil {
			result.FailedUsers = append(result.FailedUsers, userID)
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.ProcessedUsers++
		}
	}

	return result, nil
}

// =====================================================
// READ
// =====================================================

func (s *leavePolicyResolutionService) GetUserEffectivePolicies(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) ([]*models.LeavePolicyRuleResolution, error) {
	return s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
}

// =====================================================
// HELPERS
// =====================================================

func keysUUID(m map[uuid.UUID]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k.String())
	}
	return out
}

func (s *leavePolicyResolutionService) GetLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID *uuid.UUID,
	page, pageSize int,
) ([]*models.LeaveEntitlement, int64, error) {

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	entitlements, total, err := s.repo.GetLeaveEntitlementsByCompanyAndUser(
		ctx,
		companyID,
		userID,
		page,
		pageSize,
	)
	if err != nil {
		s.logger.Error("Failed to get leave entitlements",
			util.String("company_id", companyID.String()),
			util.Int("page", page),
			util.Int("page_size", pageSize),
			util.ErrorField(err),
		)
		return nil, 0, fmt.Errorf("failed to get leave entitlements: %w", err)
	}

	return entitlements, total, nil
}
