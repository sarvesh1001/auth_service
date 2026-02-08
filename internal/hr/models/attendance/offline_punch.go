package attendance

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
	BatchID       uuid.UUID
	CompanyID     uuid.UUID
	DeviceID      string
	BatchRef      string
	TotalEvents   int
	Status        string
	FailureReason *string
	ReceivedAt    time.Time
	ProcessedAt   *time.Time
}

type AttendanceBatchIngestRequest struct {
	CompanyID  uuid.UUID
	DeviceID   string
	SourceType string
	BatchRef   string
	Events     []OfflinePunchEvent
}
