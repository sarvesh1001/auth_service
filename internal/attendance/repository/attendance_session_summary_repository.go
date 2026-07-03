package repository

import (
	"context"
	"database/sql"
	"time"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

type AttendanceSessionSummaryRepository interface {
	// Upsert creates or updates a session summary (unique on company+subject_type+subject_id+session_id).
	Upsert(ctx context.Context, tx *sql.Tx, summary *models.AttendanceSessionSummary) error
	// GetBySessionAndSubject retrieves a summary for a specific session and subject.
	GetBySessionAndSubject(ctx context.Context, tx *sql.Tx, sessionID, subjectID uuid.UUID, subjectType string) (*models.AttendanceSessionSummary, error)
	// GetBySession returns all summaries for a given session.
	GetBySession(ctx context.Context, tx *sql.Tx, sessionID uuid.UUID) ([]*models.AttendanceSessionSummary, error)
	// GetBySubject returns all summaries for a subject within a date range.
	GetBySubject(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, fromDate, toDate time.Time) ([]*models.AttendanceSessionSummary, error)
	// List returns a paginated list of session summaries matching the filter.
	List(ctx context.Context, tx *sql.Tx, filter SessionSummaryFilter, pag Pagination) ([]*models.AttendanceSessionSummary, error)
	// Count returns the total number of session summaries matching the filter.
	Count(ctx context.Context, tx *sql.Tx, filter SessionSummaryFilter) (int64, error)
}

type SessionSummaryFilter struct {
	CompanyID   *uuid.UUID
	SubjectType *string
	SubjectID   *uuid.UUID
	SessionID   *uuid.UUID
	SessionDate *time.Time
	Status      *string
}
