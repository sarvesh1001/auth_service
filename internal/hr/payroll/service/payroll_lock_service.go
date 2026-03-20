package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PayrollLockService interface {
	// Governance checks
	IsPeriodLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) (bool, error)
	IsDateLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error)
	ValidateMutationAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	ValidateMutationAllowedRange(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) error

	// Control actions
	LockPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, actorID uuid.UUID, reason string) error
	UnlockPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, actorID uuid.UUID) error

	// Query
	ListLocks(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]PayrollLockInfo, error)
}

type PayrollLockInfo struct {
	LockID      uuid.UUID
	PeriodStart time.Time
	PeriodEnd   time.Time
	LockedBy    uuid.UUID
	LockedAt    time.Time
	Reason      string
}

type payrollLockService struct {
	repo   repository.PayrollRepository
	audit  *a.AuditService
	logger *zap.Logger
}

func NewPayrollLockService(
	repo repository.PayrollRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) PayrollLockService {
	return &payrollLockService{
		repo:   repo,
		audit:  audit,
		logger: logger.Named("payroll_lock_service"),
	}
}

//////////////////////////////////////////////////////////////
// GOVERNANCE CHECKS
//////////////////////////////////////////////////////////////

func (s *payrollLockService) IsPeriodLocked(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) (bool, error) {
	if companyID == uuid.Nil {
		return false, errors.New("invalid company_id")
	}
	return s.repo.IsPayrollPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
}

func (s *payrollLockService) IsDateLocked(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
) (bool, error) {
	if companyID == uuid.Nil {
		return false, errors.New("invalid company_id")
	}
	return s.repo.IsPayrollPeriodLockedRange(ctx, companyID, date, date)
}

// ValidateMutationAllowed prevents any backdated change
// that touches a locked payroll period.
func (s *payrollLockService) ValidateMutationAllowed(
	ctx context.Context,
	companyID uuid.UUID,
	effectiveFrom time.Time,
) error {
	locked, err := s.IsDateLocked(ctx, companyID, effectiveFrom)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf(
			"mutation not allowed: payroll period containing %s is locked",
			effectiveFrom.Format("2006-01-02"),
		)
	}
	return nil
}

func (s *payrollLockService) ValidateMutationAllowedRange(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) error {
	if companyID == uuid.Nil {
		return errors.New("invalid company_id")
	}
	if endDate.Before(startDate) {
		return errors.New("invalid date range")
	}
	locked, err := s.repo.IsPayrollPeriodLockedRange(
		ctx,
		companyID,
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf(
			"mutation not allowed: overlapping locked payroll period [%s - %s]",
			startDate.Format("2006-01-02"),
			endDate.Format("2006-01-02"),
		)
	}
	return nil
}

//////////////////////////////////////////////////////////////
// CONTROL ACTIONS
//////////////////////////////////////////////////////////////

func (s *payrollLockService) LockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	actorID uuid.UUID,
	reason string,
) error {
	if companyID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid company_id or actor_id")
	}
	if periodEnd.Before(periodStart) {
		return errors.New("period_end cannot be before period_start")
	}

	// Idempotency check
	locked, err := s.repo.IsPayrollPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return err
	}
	if locked {
		s.logger.Warn("attempt to lock already locked period",
			zap.String("company_id", companyID.String()),
			zap.Time("start", periodStart),
			zap.Time("end", periodEnd),
		)
		return fmt.Errorf("payroll period already locked")
	}

	lock := &models.PayrollPeriodLock{
		LockID:      uuid.New(),
		CompanyID:   companyID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		LockedBy:    &actorID,
		LockedAt:    time.Now().UTC(),
		Reason:      &reason,
	}

	if err := s.repo.CreatePayrollPeriodLock(ctx, lock); err != nil {
		return err
	}

	// Audit successful lock (non‑blocking)
	afterState, _ := json.Marshal(lock)
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"lock_created",
		"payroll_period_lock",
		&lock.LockID,
		"admin",
		&actorID,
		nil,
		afterState,
		map[string]interface{}{
			"period_start": periodStart,
			"period_end":   periodEnd,
			"reason":       reason,
		},
	); err != nil {
		s.logger.Error("Failed to audit payroll lock creation",
			zap.String("lock_id", lock.LockID.String()),
			zap.Error(err))
	}

	s.logger.Info("payroll period locked",
		zap.String("company_id", companyID.String()),
		zap.Time("start", periodStart),
		zap.Time("end", periodEnd),
		zap.String("actor_id", actorID.String()),
	)

	return nil
}

func (s *payrollLockService) UnlockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	actorID uuid.UUID,
) error {
	if companyID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid company_id or actor_id")
	}
	if periodEnd.Before(periodStart) {
		return errors.New("invalid period range")
	}

	// Optionally fetch locks before deletion to include in audit
	// For simplicity, we'll just log the period and actor.
	// If you need before state, you can extend repository to GetLocksByPeriod.

	tx, err := s.repo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 🔐 Lock payroll_run row (if exists)
	run, err := s.repo.GetPayrollRunByPeriodTx(
		ctx,
		tx,
		companyID,
		periodStart,
		periodEnd,
	)
	if err != nil {
		return err
	}

	if run != nil {
		if run.Status == models.PayrollStatusCalculated ||
			run.Status == models.PayrollStatusApproved ||
			run.Status == models.PayrollStatusPaid {
			return fmt.Errorf(
				"cannot unlock period: payroll run in state %s",
				run.Status,
			)
		}
	}

	// 🔐 Delete lock inside same TX
	if err := s.repo.DeletePayrollPeriodLockTx(
		ctx,
		tx,
		companyID,
		periodStart,
		periodEnd,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Audit successful unlock (non‑blocking)
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"lock_deleted",
		"payroll_period_lock",
		nil, // no specific lock ID because multiple could be deleted
		"admin",
		&actorID,
		nil, // before state not captured for simplicity
		nil,
		map[string]interface{}{
			"period_start": periodStart,
			"period_end":   periodEnd,
		},
	); err != nil {
		s.logger.Error("Failed to audit payroll lock deletion",
			zap.String("company_id", companyID.String()),
			zap.Time("start", periodStart),
			zap.Time("end", periodEnd),
			zap.Error(err))
	}

	s.logger.Warn("payroll period unlocked (tx safe)",
		zap.String("company_id", companyID.String()),
		zap.Time("start", periodStart),
		zap.Time("end", periodEnd),
		zap.String("actor_id", actorID.String()),
	)

	return nil
}

//////////////////////////////////////////////////////////////
// QUERY
//////////////////////////////////////////////////////////////

func (s *payrollLockService) ListLocks(
	ctx context.Context,
	companyID uuid.UUID,
	from, to time.Time,
) ([]PayrollLockInfo, error) {
	locks, err := s.repo.ListPayrollLocks(ctx, companyID, from, to)
	if err != nil {
		return nil, err
	}

	result := make([]PayrollLockInfo, 0, len(locks))
	for _, l := range locks {
		var lockedBy uuid.UUID
		if l.LockedBy != nil {
			lockedBy = *l.LockedBy
		}
		var reason string
		if l.Reason != nil {
			reason = *l.Reason
		}
		result = append(result, PayrollLockInfo{
			LockID:      l.LockID,
			PeriodStart: l.PeriodStart,
			PeriodEnd:   l.PeriodEnd,
			LockedBy:    lockedBy,
			LockedAt:    l.LockedAt,
			Reason:      reason,
		})
	}
	return result, nil
}
