package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// SummaryRepository defines operations for attendance daily summaries.
type SummaryRepository interface {
	// UpsertSummary creates or updates a daily summary.
	UpsertSummary(ctx context.Context, tx *sql.Tx, summary *models.AttendanceDailySummary) error

	// GetBySubjectDate retrieves a summary for a specific subject on a given date.
	GetBySubjectDate(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*models.AttendanceDailySummary, error)

	// GetBySubjectRange retrieves summaries for a subject within a date range.
	GetBySubjectRange(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceDailySummary, error)

	// GetByCompanyRange retrieves summaries for all subjects in a company within a date range (optional pagination).
	GetByCompanyRange(ctx context.Context, companyID uuid.UUID, from, to time.Time, limit, offset int) ([]*models.AttendanceDailySummary, int64, error)

	// LockForPayroll sets is_payroll_locked = true for a specific summary (uses FOR UPDATE).
	LockForPayroll(ctx context.Context, tx *sql.Tx, summaryID uuid.UUID) error

	// LockBySubjectDateRange locks all summaries for a subject in a date range (for payroll).
	LockBySubjectDateRange(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error

	// MarkFinalized sets is_finalized = true for a summary.
	MarkFinalized(ctx context.Context, summaryID uuid.UUID) error

	// DeleteByID deletes a summary (soft or hard? We'll hard delete; but we may want to soft delete later).
	DeleteByID(ctx context.Context, summaryID uuid.UUID) error
	MarkFinalizedForPeriod(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error

	// HealthCheck checks database connectivity.
	HealthCheck(ctx context.Context) error
}
