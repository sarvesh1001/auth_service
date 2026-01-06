package attendance

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceEvent struct {
	AttendanceEventID uuid.UUID     `json:"attendance_event_id" db:"attendance_event_id"`
	CompanyID         uuid.UUID     `json:"company_id" db:"company_id"`
	UserID            uuid.UUID     `json:"user_id" db:"user_id"`
	EventType         string        `json:"event_type" db:"event_type"`
	EventTime         time.Time     `json:"event_time" db:"event_time"`
	SourceType        string        `json:"source_type" db:"source_type"`
	SourceID          *uuid.UUID    `json:"source_id" db:"source_id"`
	DeviceID          *string       `json:"device_id" db:"device_id"`
	IPAddress         *string       `json:"ip_address" db:"ip_address"`
	Metadata          EventMetadata `json:"metadata" db:"metadata"`
	CreatedAt         time.Time     `json:"created_at" db:"created_at"`
	CreatedBy         *uuid.UUID    `json:"created_by" db:"created_by"`
}

type EventMetadata struct {
	ShiftID    *uuid.UUID `json:"shift_id,omitempty"`
	ClassID    *uuid.UUID `json:"class_id,omitempty"`
	Reason     *string    `json:"reason,omitempty"`
	LocationID *uuid.UUID `json:"location_id,omitempty"`
}
