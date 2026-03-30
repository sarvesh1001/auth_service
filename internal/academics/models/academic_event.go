package models

import (
	"time"

	"github.com/google/uuid"
)

// AcademicEvent represents a scheduled event (holiday, exam, etc.).
type AcademicEvent struct {
	EventID     uuid.UUID  `json:"event_id"`
	CompanyID   uuid.UUID  `json:"company_id"`
	EventName   string     `json:"event_name"`
	EventDate   time.Time  `json:"event_date"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	Location    string     `json:"location,omitempty"`
	Description string     `json:"description,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
