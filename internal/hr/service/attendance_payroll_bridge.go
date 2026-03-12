package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/hr/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
}

func NewAttendancePayrollBridge(
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendancePayrollBridge {
	return &attendancePayrollBridge{
		attendanceRepo: attendanceRepo,
		logger:         logger,
	}
}

// ============================================================
// VALIDATION (now without lock check)
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

	count, err := b.attendanceRepo.CountAttendanceSummariesInRange(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}

	if count != expectedDays {
		return fmt.Errorf(
			"attendance incomplete: expected %d days but found %d summaries",
			expectedDays,
			count,
		)
	}

	summaries, err := b.attendanceRepo.GetAttendanceSummariesInRange(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}

	for _, s := range summaries {
		if !s.IsFinalized {
			return fmt.Errorf(
				"attendance not finalized for date %s",
				s.AttendanceDate.Format("2006-01-02"),
			)
		}
		// ❌ Lock check removed – now allowed for reading
	}

	return nil
}

// ============================================================
// AGGREGATION
// ============================================================

func (b *attendancePayrollBridge) GetPayrollAttendanceSummary(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (*PayrollAttendanceSummary, error) {

	// Validate completeness & finalization (lock status ignored)
	if err := b.ValidateAttendanceForPayroll(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	); err != nil {
		return nil, err
	}

	summaries, err := b.attendanceRepo.GetAttendanceSummariesInRange(
		ctx,
		companyID,
		userID,
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
		// Payable days
		if s.IsPayable {
			result.PayableDays++
		}

		// Worked minutes
		if s.WorkedMinutes != nil {
			result.TotalWorkedMinutes += *s.WorkedMinutes
		}

		// Overtime minutes
		if s.OvertimeMinutes != nil {
			result.TotalOvertimeMinutes += *s.OvertimeMinutes
		}

		// Loss minutes = expected - worked (only if positive)
		if s.ExpectedMinutes != nil && s.WorkedMinutes != nil {
			loss := *s.ExpectedMinutes - *s.WorkedMinutes
			if loss > 0 {
				result.TotalLossMinutes += loss
			}
		}
	}

	// Optional: log if any summaries were already locked (just for visibility)
	for _, s := range summaries {
		if s.IsPayrollLocked {
			b.logger.Warn("attendance already payroll locked, using locked data",
				zap.String("company_id", companyID.String()),
				zap.String("user_id", userID.String()),
				zap.String("date", s.AttendanceDate.Format("2006-01-02")),
			)
			break // log once per employee
		}
	}

	return result, nil
}

// ============================================================
// LOCKING (explicit lock check)
// ============================================================

func (b *attendancePayrollBridge) LockAttendanceForPayroll(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) error {

	// 1. Validate completeness & finalization (still required)
	if err := b.ValidateAttendanceForPayroll(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	); err != nil {
		return err
	}

	// 2. Explicitly check for existing locks
	summaries, err := b.attendanceRepo.GetAttendanceSummariesInRange(
		ctx,
		companyID,
		userID,
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

	// 3. Perform the lock
	err = b.attendanceRepo.LockAttendanceSummariesInRange(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		return err
	}

	b.logger.Info(
		"Attendance locked for payroll",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate),
	)

	return nil
}
