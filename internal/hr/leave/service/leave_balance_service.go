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

type LeaveBalanceService interface {
	GetCurrentBalance(ctx context.Context, entitlementID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveBalanceSnapshot, error)
	GetBalanceAsOf(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, leaveTypeID uuid.UUID, asOfDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveBalance, error)
	RecalculateAndSnapshot(ctx context.Context, entitlementID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveBalanceSnapshot, error)
}

type leaveBalanceService struct {
	repo             repository.LeaveRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeaveBalanceService(
	repo repository.LeaveRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeaveBalanceService {
	return &leaveBalanceService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// GetCurrentBalance – read, no idempotency, but audit if required
func (s *leaveBalanceService) GetCurrentBalance(
	ctx context.Context,
	entitlementID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveBalanceSnapshot, error) {
	ledgerEntries, err := s.repo.GetLeaveLedgerEntriesByEntitlement(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}
	var balance float64
	for _, e := range ledgerEntries {
		switch e.EntryType {
		case "accrual", "reversal":
			balance += float64(e.Days)
		case "consumption":
			balance -= float64(e.Days)
		}
	}
	snapshot := &models.LeaveBalanceSnapshot{
		EntitlementID: entitlementID,
		BalanceDays:   balance,
		CalculatedAt:  time.Now().UTC(),
	}

	// Audit read (optional)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"entitlement_id": entitlementID.String(),
		"balance":        balance,
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		nil, // companyID unknown, but can be fetched if needed
		"leave",
		"balance.get_current",
		"leave_balance",
		&entitlementID,
		actorType,
		&actorID,
		nil,
		nil,
		auditMeta,
	)

	return snapshot, nil
}

func (s *leaveBalanceService) RecalculateAndSnapshot(
	ctx context.Context,
	entitlementID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveBalanceSnapshot, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("snapshot-%s", entitlementID.String())
	}
	var cached *models.LeaveBalanceSnapshot
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	snapshot, err := s.GetCurrentBalance(ctx, entitlementID, actorType, actorID, metadata)
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateLeaveBalanceSnapshot(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	// Audit
	ip, _ := ctx.Value("ip_address").(string)
	afterJSON, _ := json.Marshal(snapshot)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"entitlement_id": entitlementID.String(),
		"balance":        snapshot.BalanceDays,
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		nil,
		"leave",
		"balance.snapshot",
		"leave_balance_snapshot",
		&entitlementID,
		actorType,
		&actorID,
		nil,
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, snapshot)

	return snapshot, nil
}

func (s *leaveBalanceService) GetBalanceAsOf(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	asOfDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveBalance, error) {
	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}
	balance, err := s.repo.CalculateLeaveBalance(ctx, userID, leaveTypeID, asOfDate, positionID)
	if err != nil {
		return nil, err
	}

	// Audit read
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"user_id":    userID.String(),
		"leave_type": leaveTypeID.String(),
		"as_of":      asOfDate,
		"balance":    balance.Balance,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"leave",
		"balance.get_as_of",
		"leave_balance",
		nil,
		actorType,
		&actorID,
		nil,
		nil,
		auditMeta,
	)

	return balance, nil
}
