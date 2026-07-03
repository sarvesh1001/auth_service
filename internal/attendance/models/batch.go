package models

import (
	"time"

	"github.com/google/uuid"
)

type OfflinePunchEvent struct {
	EventType      string    `json:"event_type"`
	EventTime      time.Time `json:"event_time"`
	DeviceUserCode string    `json:"device_user_code"`
}

type AttendancePunchBatch struct {
	BatchID       uuid.UUID  `json:"batch_id" db:"batch_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	DeviceID      string     `json:"device_id" db:"device_id"`
	BatchRef      string     `json:"batch_ref" db:"batch_ref"`
	TotalEvents   int        `json:"total_events" db:"total_events"`
	Status        string     `json:"status" db:"status"`
	FailureReason *string    `json:"failure_reason,omitempty" db:"failure_reason"`
	ReceivedAt    time.Time  `json:"received_at" db:"received_at"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty" db:"processed_at"`
}

type AttendanceBatchIngestRequest struct {
	CompanyID  uuid.UUID
	DeviceID   string
	SourceType string
	BatchRef   string
	Events     []OfflinePunchEvent
}
