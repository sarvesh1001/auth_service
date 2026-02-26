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

type LeaveBalanceService interface {
	GetCurrentBalance(
		ctx context.Context,
		entitlementID uuid.UUID,
	) (*models.LeaveBalanceSnapshot, error)

	GetBalanceAsOf(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		asOfDate time.Time,
	) (*models.LeaveBalance, error)

	RecalculateAndSnapshot(
		ctx context.Context,
		entitlementID uuid.UUID,
	) (*models.LeaveBalanceSnapshot, error)
}

type leaveBalanceService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeaveBalanceService(
	repo repository.LeaveRepository,
	logger *zap.Logger,
) LeaveBalanceService {
	return &leaveBalanceService{
		repo:   repo,
		logger: logger.Named("leave_balance_service"),
	}
}

// GetCurrentBalance computes the current balance exclusively from ledger entries.
func (s *leaveBalanceService) GetCurrentBalance(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*models.LeaveBalanceSnapshot, error) {

	// ✅ NEW: use only ledger entries
	ledgerEntries, err := s.repo.GetLeaveLedgerEntriesByEntitlement(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to get ledger entries for current balance",
			zap.String("entitlement_id", entitlementID.String()),
			zap.Error(err))
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

	return &models.LeaveBalanceSnapshot{
		EntitlementID: entitlementID,
		BalanceDays:   balance,
		CalculatedAt:  time.Now().UTC(),
	}, nil
}

func (s *leaveBalanceService) RecalculateAndSnapshot(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*models.LeaveBalanceSnapshot, error) {

	snapshot, err := s.GetCurrentBalance(ctx, entitlementID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateLeaveBalanceSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}

	return snapshot, nil
}

func (s *leaveBalanceService) GetBalanceAsOf(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	asOfDate time.Time,
) (*models.LeaveBalance, error) {

	// resolve user position first
	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		s.logger.Error("Failed to resolve user position",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}

	// delegate to repository method that uses ledger and position
	balance, err := s.repo.CalculateLeaveBalance(
		ctx,
		userID,
		leaveTypeID,
		asOfDate,
		positionID,
	)
	if err != nil {
		s.logger.Error("Failed to calculate leave balance",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Time("as_of_date", asOfDate),
			zap.Error(err),
		)
		return nil, err
	}

	return balance, nil
}
