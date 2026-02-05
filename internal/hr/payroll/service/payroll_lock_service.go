package service

import (
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollLockService handles locking of payroll data
type PayrollLockService interface {
	LockPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
	UnlockPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
	IsPeriodLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error)
	ValidatePeriodNotLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
}

type payrollLockService struct {
	repo   repository.PayrollRepository
	logger *zap.Logger
}

func NewPayrollLockService(repo repository.PayrollRepository, logger *zap.Logger) PayrollLockService {
	return &payrollLockService{
		repo:   repo,
		logger: logger,
	}
}

func (s *payrollLockService) LockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) error {
	startTime := time.Now()

	// Validate period is not already locked
	if err := s.ValidatePeriodNotLocked(ctx, companyID, periodStart, periodEnd); err != nil {
		return err
	}

	// Lock the period
	if err := s.repo.LockPayrollPeriod(ctx, companyID, periodStart, periodEnd); err != nil {
		s.logger.Error("Failed to lock payroll period",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to lock payroll period: %w", err)
	}

	s.logger.Info("Payroll period locked",
		util.String("company_id", companyID.String()),
		util.String("period", fmt.Sprintf("%s to %s",
			periodStart.Format("2006-01-02"),
			periodEnd.Format("2006-01-02"))),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *payrollLockService) UnlockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) error {
	startTime := time.Now()

	// Unlock the period
	if err := s.repo.UnlockPayrollPeriod(ctx, companyID, periodStart, periodEnd); err != nil {
		s.logger.Error("Failed to unlock payroll period",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to unlock payroll period: %w", err)
	}

	s.logger.Info("Payroll period unlocked",
		util.String("company_id", companyID.String()),
		util.String("period", fmt.Sprintf("%s to %s",
			periodStart.Format("2006-01-02"),
			periodEnd.Format("2006-01-02"))),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *payrollLockService) IsPeriodLocked(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
) (bool, error) {
	locked, err := s.repo.IsPeriodLocked(ctx, companyID, date)
	if err != nil {
		return false, fmt.Errorf("failed to check period lock: %w", err)
	}
	return locked, nil
}

func (s *payrollLockService) ValidatePeriodNotLocked(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) error {

	locked, err := s.repo.IsPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return err
	}

	if locked {
		return fmt.Errorf(
			"payroll period %s to %s is already locked",
			periodStart.Format("2006-01-02"),
			periodEnd.Format("2006-01-02"),
		)
	}

	return nil
}
