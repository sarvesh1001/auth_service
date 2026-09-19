package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

type SummaryRepository interface {
	UpsertSummary(ctx context.Context, tx *sql.Tx, summary *models.AttendanceDailySummary) error
	GetBySubjectDate(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*models.AttendanceDailySummary, error)
	GetBySubjectRange(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceDailySummary, error)

	// GetByCompanyRange returns daily summaries for a company, optionally
	// scoped to a single employment location.
	//
	// locationID == nil → no location filter (ALL scope).
	GetByCompanyRange(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		from, to time.Time,
		limit, offset int,
	) ([]*models.AttendanceDailySummary, int64, error)

	LockForPayroll(ctx context.Context, tx *sql.Tx, summaryID uuid.UUID) error
	LockBySubjectDateRange(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error
	MarkFinalized(ctx context.Context, summaryID uuid.UUID) error
	DeleteByID(ctx context.Context, summaryID uuid.UUID) error
	MarkFinalizedForPeriod(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error
	HealthCheck(ctx context.Context) error
}
