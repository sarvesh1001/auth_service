package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// EventFilter defines search/filter parameters for events
type EventFilter struct {
	CompanyID   uuid.UUID
	SubjectType *string    // optional: filter by subject type
	SubjectID   *uuid.UUID // optional: filter by subject ID (requires SubjectType)
	EventTypes  []string   // optional: list of event types
	SourceType  *string    // optional: source type
	DeviceID    *string    // optional: device ID
	StartDate   time.Time
	EndDate     time.Time
	Page        int
	PageSize    int

	// LocationID is the employment location scope. nil = no filter (ALL).
	LocationID *uuid.UUID
}

type EventRepository interface {
	CreateEvent(ctx context.Context, tx *sql.Tx, event *models.AttendanceEvent) error
	CreateBulkEvents(ctx context.Context, events []*models.AttendanceEvent) error
	GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.AttendanceEvent, error)
	GetEventsBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceEvent, error)
	GetEventsByCompany(ctx context.Context, companyID uuid.UUID, from, to time.Time, page, pageSize int) ([]*models.AttendanceEvent, int64, error)
	GetEventsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string, from, to time.Time) ([]*models.AttendanceEvent, error)
	CheckDuplicateRecent(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, eventType string, eventTime time.Time, windowMinutes int) (bool, error)
	ListEvents(ctx context.Context, filter EventFilter) ([]*models.AttendanceEvent, int64, error)
	CountEvents(ctx context.Context, filter EventFilter) (int64, error)
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
	FindCorrection(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, correctionType string, eventTime time.Time) (*models.AttendanceEvent, error)
	HealthCheck(ctx context.Context) error
	GetDistinctSubjects(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]SubjectRef, error)
}

type SubjectRef struct {
	SubjectType string    `json:"subject_type"`
	SubjectID   uuid.UUID `json:"subject_id"`
}
