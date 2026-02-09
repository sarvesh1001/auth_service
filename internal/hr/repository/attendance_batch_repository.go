package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

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
type AttendanceBatchStatus struct {
	BatchRef      string
	Status        string
	TotalEvents   int
	ReceivedAt    time.Time
	ProcessedAt   *time.Time
	FailureReason *string
}

type AttendanceBatchRepository interface {
	CreateBatch(ctx context.Context, batch *AttendancePunchBatch) error
	MarkProcessed(ctx context.Context, batchID uuid.UUID) error
	MarkFailed(ctx context.Context, batchID uuid.UUID, reason string) error
	ExistsByRef(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		batchRef string,
	) (bool, error)
	InsertFailure(
		ctx context.Context,
		failure *AttendancePunchFailure,
	) error

	ListFailuresByBatch(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		batchRef string,
		limit int,
		offset int,
	) ([]AttendancePunchFailureView, error)

	GetByRef(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		batchRef string,
	) (*AttendanceBatchStatus, error)
}
type AttendancePunchFailure struct {
	FailureID      uuid.UUID
	BatchID        uuid.UUID
	CompanyID      uuid.UUID
	DeviceID       string
	DeviceUserCode *string
	EventType      *string
	EventTime      *time.Time
	FailureReason  string
	RawEvent       []byte // ✅ FIX
	CreatedAt      time.Time
}

type AttendancePunchFailureView struct {
	FailureID      uuid.UUID              `json:"failure_id"`
	DeviceUserCode *string                `json:"device_user_code"`
	EventType      *string                `json:"event_type"`
	EventTime      *time.Time             `json:"event_time"`
	FailureReason  string                 `json:"failure_reason"`
	RawEvent       map[string]interface{} `json:"raw_event"`
	CreatedAt      time.Time              `json:"created_at"`
}
