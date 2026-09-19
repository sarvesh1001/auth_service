package repository

import (
	"context"
	"database/sql"
	"time"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

type AttendanceSessionSummaryRepository interface {
	Upsert(ctx context.Context, tx *sql.Tx, summary *models.AttendanceSessionSummary) error
	GetBySessionAndSubject(ctx context.Context, tx *sql.Tx, sessionID, subjectID uuid.UUID, subjectType string) (*models.AttendanceSessionSummary, error)
	GetBySession(ctx context.Context, tx *sql.Tx, sessionID uuid.UUID) ([]*models.AttendanceSessionSummary, error)
	GetBySubject(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, fromDate, toDate time.Time) ([]*models.AttendanceSessionSummary, error)
	List(ctx context.Context, tx *sql.Tx, filter SessionSummaryFilter, pag Pagination) ([]*models.AttendanceSessionSummary, error)
	Count(ctx context.Context, tx *sql.Tx, filter SessionSummaryFilter) (int64, error)
}

type SessionSummaryFilter struct {
	CompanyID   *uuid.UUID
	SubjectType *string
	SubjectID   *uuid.UUID
	SessionID   *uuid.UUID
	SessionDate *time.Time
	Status      *string

	// LocationID is the employment location scope. nil = no filter (ALL).
	LocationID *uuid.UUID
}
