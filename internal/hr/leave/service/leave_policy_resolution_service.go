package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type LeavePolicyResolutionService interface {
	ResolveUserLeaveEntitlements(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time, reason string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ResolveBatchLeaveEntitlements(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID, asOf time.Time, reason string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*LeavePolicyResolutionResult, error)

	// GetLeaveEntitlements — location filter applies when locationID != nil.
	GetLeaveEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID *uuid.UUID,
		locationID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)

	GetUserEffectivePolicies(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]*models.LeavePolicyRuleResolution, error)
}

type LeavePolicyResolutionResult struct {
	TotalUsers     int
	ProcessedUsers int
	FailedUsers    []uuid.UUID
	Errors         []string
}

type leavePolicyResolutionService struct {
	repo             repository.LeaveRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeavePolicyResolutionService(
	repo repository.LeaveRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeavePolicyResolutionService {
	return &leavePolicyResolutionService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

func (s *leavePolicyResolutionService) ResolveUserLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
	reason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("resolve_user-%s-%s", userID.String(), asOf.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	positionID, workCenterCode, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to get user position context: %w", err)
	}

	rules, err := s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
	if err != nil {
		return fmt.Errorf("resolve policy rules failed: %w", err)
	}
	if len(rules) == 0 {
		_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
		return nil
	}

	processedLeaveTypes := make(map[uuid.UUID]bool)
	for _, rule := range rules {
		if processedLeaveTypes[rule.LeaveTypeID] {
			continue
		}
		existing, err := s.repo.GetActivePolicyEntitlement(ctx, companyID, userID, rule.LeaveTypeID, positionID)
		if err != nil {
			return fmt.Errorf("failed to check existing entitlement: %w", err)
		}
		if existing != nil && existing.PolicyID != nil && *existing.PolicyID == rule.PolicyID && existing.TotalDays == rule.TotalDays {
			processedLeaveTypes[rule.LeaveTypeID] = true
			continue
		}
		if err := s.repo.EndActivePolicyEntitlementsByLeaveType(ctx, companyID, userID, rule.LeaveTypeID, asOf, positionID); err != nil {
			return fmt.Errorf("failed to end entitlement: %w", err)
		}
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
			return fmt.Errorf("failed to create entitlement: %w", err)
		}
		processedLeaveTypes[rule.LeaveTypeID] = true
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"company_id": companyID.String(),
		"user_id":    userID.String(),
		"as_of":      asOf,
		"reason":     reason,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "resolution.user", "leave_entitlement",
		nil, actorType, &actorID, nil, nil, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *leavePolicyResolutionService) ResolveBatchLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	asOf time.Time,
	reason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*LeavePolicyResolutionResult, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("resolve_batch-%s", uuid.New().String())
	}
	var cached *LeavePolicyResolutionResult
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	result := &LeavePolicyResolutionResult{
		TotalUsers:  len(userIDs),
		FailedUsers: []uuid.UUID{},
		Errors:      []string{},
	}
	for _, userID := range userIDs {
		if err := s.ResolveUserLeaveEntitlements(ctx, companyID, userID, asOf, reason, actorType, actorID, metadata); err != nil {
			result.FailedUsers = append(result.FailedUsers, userID)
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.ProcessedUsers++
		}
	}

	ip, _ := ctx.Value("ip_address").(string)
	afterJSON, _ := json.Marshal(result)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"company_id": companyID.String(),
		"total":      result.TotalUsers,
		"processed":  result.ProcessedUsers,
		"failed":     len(result.FailedUsers),
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "resolution.batch", "leave_entitlement",
		nil, actorType, &actorID, nil, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, result)

	return result, nil
}

// GetLeaveEntitlements — location filter applies when locationID != nil.
func (s *leavePolicyResolutionService) GetLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID *uuid.UUID,
	locationID *uuid.UUID,
	page, pageSize int,
) ([]*models.LeaveEntitlement, int64, error) {
	return s.repo.GetLeaveEntitlementsByCompanyAndUser(ctx, companyID, userID, locationID, page, pageSize)
}

func (s *leavePolicyResolutionService) GetUserEffectivePolicies(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]*models.LeavePolicyRuleResolution, error) {
	return s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
}
