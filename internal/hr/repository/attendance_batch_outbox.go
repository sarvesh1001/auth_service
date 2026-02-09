package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AttendanceBatchOutbox struct {
	OutboxID     uuid.UUID
	EventType    string
	AggregateID  uuid.UUID
	Payload      map[string]interface{}
	CreatedAt    time.Time
	ProcessedAt  *time.Time
	ErrorMessage *string
}

type AttendanceBatchOutboxRepository interface {
	Insert(
		ctx context.Context,
		event *AttendanceBatchOutbox,
	) error

	FetchUnprocessed(
		ctx context.Context,
		limit int,
	) ([]*AttendanceBatchOutbox, error)

	MarkProcessed(
		ctx context.Context,
		outboxIDs []uuid.UUID,
	) error
	ListFailuresByBatchRef(
		ctx context.Context,
		batchRef string,
	) ([]*AttendanceBatchOutbox, error)

	MarkFailed(
		ctx context.Context,
		outboxID uuid.UUID,
		errorMessage string,
	) error
}
