package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type PayrollLockService interface {
	// Governance checks
	IsPeriodLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) (bool, error)
	IsDateLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error)
	ValidateMutationAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	ValidateMutationAllowedRange(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) error

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
	repo             repository.PayrollRepository
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewPayrollLockService(
	repo repository.PayrollRepository,
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) PayrollLockService {
	return &payrollLockService{
		repo:             repo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// --------------------------------------------
// GOVERNANCE CHECKS (no idempotency needed)
// --------------------------------------------

func (s *payrollLockService) IsPeriodLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) (bool, error) {
	if companyID == uuid.Nil {
		return false, errors.New("invalid company_id")
	}
	return s.repo.IsPayrollPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
}

func (s *payrollLockService) IsDateLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error) {
	if companyID == uuid.Nil {
		return false, errors.New("invalid company_id")
	}
	return s.repo.IsPayrollPeriodLockedRange(ctx, companyID, date, date)
}

func (s *payrollLockService) ValidateMutationAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error {
	locked, err := s.IsDateLocked(ctx, companyID, effectiveFrom)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("mutation not allowed: payroll period containing %s is locked", effectiveFrom.Format("2006-01-02"))
	}
	return nil
}

func (s *payrollLockService) ValidateMutationAllowedRange(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) error {
	if companyID == uuid.Nil {
		return errors.New("invalid company_id")
	}
	if endDate.Before(startDate) {
		return errors.New("invalid date range")
	}
	locked, err := s.repo.IsPayrollPeriodLockedRange(ctx, companyID, startDate, endDate)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("mutation not allowed: overlapping locked payroll period [%s - %s]", startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))
	}
	return nil
}

// --------------------------------------------
// CONTROL ACTIONS (with idempotency)
// --------------------------------------------

func (s *payrollLockService) LockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	actorID uuid.UUID,
	reason string,
) error {
	// 1️⃣ Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("payroll_lock-%s-%s-%s", companyID.String(), periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 2️⃣ Validation
	if companyID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid company_id or actor_id")
	}
	if periodEnd.Before(periodStart) {
		return errors.New("period_end cannot be before period_start")
	}

	// 3️⃣ Check if already locked
	locked, err := s.repo.IsPayrollPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("payroll period already locked")
	}

	// 4️⃣ Create lock
	lock := &models.PayrollPeriodLock{
		LockID:      uuid.New(),
		CompanyID:   companyID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		LockedBy:    &actorID,
		LockedAt:    time.Now().UTC(),
		Reason:      &reason,
	}

	beforeJSON, _ := json.Marshal(lock) // for audit
	if err := s.repo.CreatePayrollPeriodLock(ctx, lock); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(lock)

	// 5️⃣ Audit with IP
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"lock_created",
		"payroll_period_lock",
		&lock.LockID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"period_start": periodStart,
			"period_end":   periodEnd,
			"reason":       reason,
			"ip":           ip,
		},
	)

	// 6️⃣ Store idempotency result
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *payrollLockService) UnlockPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	actorID uuid.UUID,
) error {
	// 1️⃣ Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("payroll_unlock-%s-%s-%s", companyID.String(), periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 2️⃣ Validation
	if companyID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid company_id or actor_id")
	}
	if periodEnd.Before(periodStart) {
		return errors.New("invalid period range")
	}

	// 3️⃣ Fetch existing lock for audit (optional – we can just log the period)
	// We'll use a before state – but since we don't have a GetLockByPeriod method, we'll log the period only.

	// 4️⃣ Begin transaction for safety
	tx, err := s.repo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check payroll run status
	run, err := s.repo.GetPayrollRunByPeriodTx(ctx, tx, companyID, periodStart, periodEnd)
	if err != nil {
		return err
	}
	if run != nil {
		if run.Status == models.PayrollStatusCalculated ||
			run.Status == models.PayrollStatusApproved ||
			run.Status == models.PayrollStatusPaid {
			return fmt.Errorf("cannot unlock period: payroll run in state %s", run.Status)
		}
	}

	// Delete lock
	if err := s.repo.DeletePayrollPeriodLockTx(ctx, tx, companyID, periodStart, periodEnd); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// 5️⃣ Audit with IP
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"lock_deleted",
		"payroll_period_lock",
		nil, // no specific lock ID
		"admin",
		&actorID,
		nil, // before state not captured
		nil,
		map[string]interface{}{
			"period_start": periodStart,
			"period_end":   periodEnd,
			"ip":           ip,
		},
	)

	// 6️⃣ Store idempotency result
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

// --------------------------------------------
// QUERY (no idempotency)
// --------------------------------------------

func (s *payrollLockService) ListLocks(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]PayrollLockInfo, error) {
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
