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
		logger: logger,
	}
}

func (s *leaveBalanceService) GetCurrentBalance(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*models.LeaveBalanceSnapshot, error) {

	entitlement, err := s.repo.GetLeaveEntitlementByID(ctx, entitlementID)
	if err != nil || entitlement == nil {
		return nil, fmt.Errorf("entitlement not found")
	}

	accrued, err := s.repo.GetTotalAccruedDays(ctx, entitlementID)
	if err != nil {
		return nil, err
	}

	ledgerEntries, err := s.repo.GetLeaveLedgerEntriesByEntitlement(ctx, entitlementID)
	if err != nil {
		return nil, err
	}

	consumed := 0
	for _, e := range ledgerEntries {
		if e.EntryType == "consumption" {
			consumed += e.Days
		}
	}

	return &models.LeaveBalanceSnapshot{
		EntitlementID: entitlementID,
		BalanceDays:   accrued - consumed,
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
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	asOfDate time.Time,
) (*models.LeaveBalance, error) {

	balance, err := s.repo.CalculateLeaveBalance(
		ctx,
		userID,
		leaveTypeID,
		asOfDate,
	)
	if err != nil {
		s.logger.Error("Failed to calculate leave balance",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Time("as_of_date", asOfDate),
			zap.Error(err),
		)
		return nil, err
	}

	return balance, nil
}
