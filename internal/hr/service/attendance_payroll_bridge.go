package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

// ============================================================
// INTERFACE
// ============================================================

type AttendancePayrollBridge interface {
	// Validates attendance completeness + finalization (does NOT check lock)
	ValidateAttendanceForPayroll(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) error

	// Returns aggregated payroll metrics
	GetPayrollAttendanceSummary(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (*PayrollAttendanceSummary, error)

	// Locks attendance after successful payroll run (fails if already locked)
	LockAttendanceForPayroll(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) error
}

// ============================================================
// RESPONSE MODEL
// ============================================================

type PayrollAttendanceSummary struct {
	TotalDays            int
	PayableDays          int
	TotalWorkedMinutes   int
	TotalOvertimeMinutes int
	TotalLossMinutes     int
}

// ============================================================
// IMPLEMENTATION
// ============================================================

type attendancePayrollBridge struct {
	summaryRepo      repository.SummaryRepository
	eventRepo        repository.EventRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewAttendancePayrollBridge(
	summaryRepo repository.SummaryRepository,
	eventRepo repository.EventRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) AttendancePayrollBridge {
	return &attendancePayrollBridge{
		summaryRepo:      summaryRepo,
		eventRepo:        eventRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// ============================================================
// VALIDATION (no lock check)
// ============================================================

func (b *attendancePayrollBridge) ValidateAttendanceForPayroll(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) error {
	if endDate.Before(startDate) {
		return fmt.Errorf("invalid date range")
	}

	expectedDays := int(endDate.Sub(startDate).Hours()/24) + 1

	summaries, err := b.summaryRepo.GetBySubjectRange(
		ctx,
		companyID,
		userID,
		"employee",
		startDate,
		endDate,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch summaries: %w", err)
	}

	if len(summaries) != expectedDays {
		return fmt.Errorf(
			"attendance incomplete: expected %d days but found %d summaries",
			expectedDays,
			len(summaries),
		)
	}

	for _, s := range summaries {
		if !s.IsFinalized {
			return fmt.Errorf(
				"attendance not finalized for date %s",
				s.AttendanceDate.Format("2006-01-02"),
			)
		}
	}

	return nil
}

// ============================================================
// AGGREGATION (with audit)
// ============================================================

func (b *attendancePayrollBridge) GetPayrollAttendanceSummary(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (*PayrollAttendanceSummary, error) {
	ip, _ := ctx.Value("ip_address").(string)

	if err := b.ValidateAttendanceForPayroll(ctx, companyID, userID, startDate, endDate); err != nil {
		return nil, err
	}

	summaries, err := b.summaryRepo.GetBySubjectRange(
		ctx,
		companyID,
		userID,
		"employee",
		startDate,
		endDate,
	)
	if err != nil {
		return nil, err
	}

	result := &PayrollAttendanceSummary{
		TotalDays: int(endDate.Sub(startDate).Hours()/24) + 1,
	}

	for _, s := range summaries {
		if s.IsPayable {
			result.PayableDays++
		}
		if s.WorkedMinutes != nil {
			result.TotalWorkedMinutes += *s.WorkedMinutes
		}
		if s.OvertimeMinutes != nil {
			result.TotalOvertimeMinutes += *s.OvertimeMinutes
		}
		if s.ExpectedMinutes != nil && s.WorkedMinutes != nil {
			loss := *s.ExpectedMinutes - *s.WorkedMinutes
			if loss > 0 {
				result.TotalLossMinutes += loss
			}
		}
	}

	// Audit read operation (if audit service is available)
	if b.auditService != nil {
		metadata := map[string]interface{}{
			"user_id":          userID.String(),
			"company_id":       companyID.String(),
			"start_date":       startDate,
			"end_date":         endDate,
			"total_days":       result.TotalDays,
			"payable_days":     result.PayableDays,
			"total_worked_min": result.TotalWorkedMinutes,
			"total_overtime":   result.TotalOvertimeMinutes,
			"total_loss":       result.TotalLossMinutes,
			"ip":               ip,
		}
		_ = b.auditService.LogAction(
			ctx,
			nil,
			&companyID,
			"payroll",
			"attendance_summary",
			"payroll_summary",
			nil,
			"system",
			nil,
			nil,
			nil,
			metadata,
		)
	}

	return result, nil
}

// ============================================================
// LOCKING (with idempotency + audit)
// ============================================================

func (b *attendancePayrollBridge) LockAttendanceForPayroll(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) error {
	ip, _ := ctx.Value("ip_address").(string)

	// 1️⃣ Idempotency key
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("payroll_lock-%s-%s-%s", companyID.String(), userID.String(), startDate.Format("2006-01-02"))
	}
	var processed bool
	if err := b.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil // already locked in this request
	}

	// 2️⃣ Validate completeness & finalization
	if err := b.ValidateAttendanceForPayroll(ctx, companyID, userID, startDate, endDate); err != nil {
		return err
	}

	// 3️⃣ Check existing locks
	summaries, err := b.summaryRepo.GetBySubjectRange(
		ctx,
		companyID,
		userID,
		"employee",
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		if s.IsPayrollLocked {
			return fmt.Errorf(
				"attendance already payroll locked for date %s",
				s.AttendanceDate.Format("2006-01-02"),
			)
		}
	}

	// 4️⃣ Perform lock in transaction
	tx, err := b.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	err = b.summaryRepo.LockBySubjectDateRange(
		ctx,
		tx,
		companyID,
		userID,
		"employee",
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit lock transaction: %w", err)
	}

	// 5️⃣ Audit
	if b.auditService != nil {
		metadata := map[string]interface{}{
			"user_id":    userID.String(),
			"company_id": companyID.String(),
			"start_date": startDate,
			"end_date":   endDate,
			"action":     "lock_attendance_payroll",
			"ip":         ip,
		}
		_ = b.auditService.LogAction(
			ctx,
			tx, // we can pass nil since lock is already committed, or we could pass tx before commit? better after commit.
			&companyID,
			"payroll",
			"lock_attendance",
			"payroll_lock",
			nil,
			"system",
			nil,
			nil,
			nil,
			metadata,
		)
	}

	// 6️⃣ Store idempotency
	_ = b.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}
