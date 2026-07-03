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
}

// EventRepository defines operations for attendance events
type EventRepository interface {
	// CreateEvent inserts a new event (supports transaction)
	CreateEvent(ctx context.Context, tx *sql.Tx, event *models.AttendanceEvent) error

	// CreateBulkEvents inserts multiple events in a transaction
	CreateBulkEvents(ctx context.Context, events []*models.AttendanceEvent) error

	// GetEventByID retrieves an event by its ID
	GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.AttendanceEvent, error)

	// GetEventsBySubject retrieves all events for a subject within a date range
	GetEventsBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceEvent, error)

	// GetEventsByCompany retrieves events for a company with pagination
	GetEventsByCompany(ctx context.Context, companyID uuid.UUID, from, to time.Time, page, pageSize int) ([]*models.AttendanceEvent, int64, error)

	// GetEventsByDevice retrieves events from a specific device within a date range
	GetEventsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string, from, to time.Time) ([]*models.AttendanceEvent, error)

	// CheckDuplicateRecent checks if a similar event exists within a time window (idempotency)
	CheckDuplicateRecent(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, eventType string, eventTime time.Time, windowMinutes int) (bool, error)

	// ListEvents applies filters and returns paginated results
	ListEvents(ctx context.Context, filter EventFilter) ([]*models.AttendanceEvent, int64, error)

	// CountEvents counts events matching the filter (helper for pagination)
	CountEvents(ctx context.Context, filter EventFilter) (int64, error)
	// BeginTx starts a new transaction
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)

	// FindCorrection checks if a correction already exists for given parameters
	FindCorrection(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, correctionType string, eventTime time.Time) (*models.AttendanceEvent, error)

	// HealthCheck verifies database connectivity
	HealthCheck(ctx context.Context) error
	// GetDistinctSubjects returns unique subject IDs that have events in the given range
	GetDistinctSubjects(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]SubjectRef, error)
}

// SubjectRef represents a unique subject type+id combination
type SubjectRef struct {
	SubjectType string    `json:"subject_type"`
	SubjectID   uuid.UUID `json:"subject_id"`
}
