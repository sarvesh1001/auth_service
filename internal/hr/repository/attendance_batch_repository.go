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
}
