package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AttendancePunchBatch matches models.AttendancePunchBatch
type AttendancePunchBatch struct {
	BatchID       uuid.UUID  `db:"batch_id"`
	CompanyID     uuid.UUID  `db:"company_id"`
	DeviceID      string     `db:"device_id"`
	BatchRef      string     `db:"batch_ref"`
	TotalEvents   int        `db:"total_events"`
	Status        string     `db:"status"`
	FailureReason *string    `db:"failure_reason"`
	ReceivedAt    time.Time  `db:"received_at"`
	ProcessedAt   *time.Time `db:"processed_at"`
}

// AttendanceBatchStatus is a lightweight read model
type AttendanceBatchStatus struct {
	BatchRef      string     `db:"batch_ref"`
	Status        string     `db:"status"`
	TotalEvents   int        `db:"total_events"`
	ReceivedAt    time.Time  `db:"received_at"`
	ProcessedAt   *time.Time `db:"processed_at"`
	FailureReason *string    `db:"failure_reason"`
}

// AttendancePunchFailure matches models? but we store raw JSON
type AttendancePunchFailure struct {
	FailureID      uuid.UUID  `db:"failure_id"`
	BatchID        uuid.UUID  `db:"batch_id"`
	CompanyID      uuid.UUID  `db:"company_id"`
	DeviceID       string     `db:"device_id"`
	DeviceUserCode *string    `db:"device_user_code"`
	EventType      *string    `db:"event_type"`
	EventTime      *time.Time `db:"event_time"`
	FailureReason  string     `db:"failure_reason"`
	RawEvent       []byte     `db:"raw_event"` // JSONB
	CreatedAt      time.Time  `db:"created_at"`
}

// AttendancePunchFailureView is used for API responses
type AttendancePunchFailureView struct {
	FailureID      uuid.UUID              `json:"failure_id"`
	DeviceUserCode *string                `json:"device_user_code"`
	EventType      *string                `json:"event_type"`
	EventTime      *time.Time             `json:"event_time"`
	FailureReason  string                 `json:"failure_reason"`
	RawEvent       map[string]interface{} `json:"raw_event"`
	CreatedAt      time.Time              `json:"created_at"`
}

// AttendanceBatchRepository defines operations for punch batches
type AttendanceBatchRepository interface {
	// CreateBatch inserts a new batch record
	CreateBatch(ctx context.Context, batch *AttendancePunchBatch) error
	ListFailuresByBatchRef(ctx context.Context, batchRef string) ([]*AttendancePunchFailureView, error)

	// MarkProcessed updates batch status to 'processed'
	MarkProcessed(ctx context.Context, batchID uuid.UUID) error

	// MarkFailed updates batch status to 'failed' with a reason
	MarkFailed(ctx context.Context, batchID uuid.UUID, reason string) error

	// ExistsByRef checks if a batch with given ref already exists (idempotency)
	ExistsByRef(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (bool, error)

	// InsertFailure stores a single failure record for a batch
	InsertFailure(ctx context.Context, failure *AttendancePunchFailure) error

	// ListFailuresByBatch retrieves failures for a specific batch with pagination
	ListFailuresByBatch(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string, limit, offset int) ([]AttendancePunchFailureView, error)

	// GetByRef returns batch status by reference
	GetByRef(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (*AttendanceBatchStatus, error)
}
