// internal/hr/leave/service/leave_accrual_service.go
package service

import (
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeaveAccrualService interface {
	AccrueMonthlyLeave(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error)
	RecalculateEntitlement(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveBalance, error)
	GetAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error)
	ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error)
}

type leaveAccrualService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeaveAccrualService(repo repository.LeaveRepository, logger *zap.Logger) LeaveAccrualService {
	return &leaveAccrualService{
		repo:   repo,
		logger: logger,
	}
}

func (s *leaveAccrualService) AccrueMonthlyLeave(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error) {
	// Validate accrual date (should be first day of month for monthly accruals)
	if accrualDate.Day() != 1 {
		s.logger.Warn("Accrual date is not the first day of month",
			zap.Time("accrual_date", accrualDate),
			zap.String("company_id", companyID.String()))
		// We'll continue anyway, but log warning
	}

	// Process all accruals for the company on this date
	processed, err := s.repo.ProcessLeaveAccruals(ctx, companyID, accrualDate)
	if err != nil {
		s.logger.Error("Failed to process monthly leave accruals",
			zap.String("company_id", companyID.String()),
			zap.Time("accrual_date", accrualDate),
			zap.Error(err))
		return 0, fmt.Errorf("failed to process monthly accruals: %w", err)
	}

	s.logger.Info("Monthly leave accruals processed",
		zap.String("company_id", companyID.String()),
		zap.Time("accrual_date", accrualDate),
		zap.Int("processed_count", processed))

	return processed, nil
}

func (s *leaveAccrualService) RecalculateEntitlement(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveBalance, error) {
	// Get the entitlement
	entitlement, err := s.repo.GetLeaveEntitlementByID(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to get entitlement for recalculation",
			zap.String("entitlement_id", entitlementID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get entitlement: %w", err)
	}

	if entitlement == nil {
		return nil, fmt.Errorf("entitlement not found")
	}

	// Get all accruals for this entitlement
	accruals, err := s.repo.GetLeaveAccrualsByEntitlement(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to get accruals for recalculation",
			zap.String("entitlement_id", entitlementID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get accruals: %w", err)
	}

	// Get all ledger entries for this entitlement
	ledgerEntries, err := s.repo.GetLeaveLedgerEntriesByEntitlement(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to get ledger entries for recalculation",
			zap.String("entitlement_id", entitlementID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}

	// Calculate total accrued
	totalAccrued := 0
	for _, accrual := range accruals {
		totalAccrued += accrual.DaysAccrued
	}

	// Calculate total consumed
	totalConsumed := 0
	for _, entry := range ledgerEntries {
		if entry.EntryType == "consumption" {
			totalConsumed += entry.Days
		}
	}

	// Get leave type info for the balance response
	leaveType, err := s.repo.GetLeaveTypeByID(ctx, entitlement.LeaveTypeID)
	if err != nil {
		s.logger.Error("Failed to get leave type for balance",
			zap.String("leave_type_id", entitlement.LeaveTypeID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	if leaveType == nil {
		return nil, fmt.Errorf("leave type not found")
	}

	balance := &models.LeaveBalance{
		UserID:        entitlement.UserID,
		LeaveTypeID:   entitlement.LeaveTypeID,
		LeaveTypeCode: leaveType.Code,
		LeaveTypeName: leaveType.Name,
		TotalEntitled: entitlement.TotalDays,
		Accrued:       totalAccrued,
		Consumed:      totalConsumed,
		Balance:       totalAccrued - totalConsumed,
		CarryForward:  leaveType.CarryForwardLimit,
	}

	s.logger.Info("Entitlement recalculated",
		zap.String("entitlement_id", entitlementID.String()),
		zap.Int("total_accrued", totalAccrued),
		zap.Int("total_consumed", totalConsumed),
		zap.Int("balance", balance.Balance))

	return balance, nil
}

func (s *leaveAccrualService) GetAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error) {
	return s.repo.GetLeaveAccrualsByDate(ctx, companyID, date)
}

func (s *leaveAccrualService) ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error) {
	return s.repo.ProcessLeaveAccruals(ctx, companyID, accrualDate)
}
