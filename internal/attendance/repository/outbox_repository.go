package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type OutboxEvent struct {
	EventID       uuid.UUID         `db:"event_id"`
	AggregateType string            `db:"aggregate_type"`
	AggregateID   uuid.UUID         `db:"aggregate_id"`
	EventType     string            `db:"event_type"`
	Topic         string            `db:"topic"`
	Payload       []byte            `db:"payload"`
	Headers       map[string]string `db:"headers"`
	Status        string            `db:"status"`
	RetryCount    int               `db:"retry_count"`
	CreatedAt     time.Time         `db:"created_at"`
	ProcessedAt   *time.Time        `db:"processed_at"`
}

type OutboxRepository interface {
	Store(ctx context.Context, tx *sql.Tx, event *OutboxEvent) error
	FetchUnprocessed(ctx context.Context, limit int) ([]*OutboxEvent, error)
	MarkProcessed(ctx context.Context, eventIDs []uuid.UUID) error
	MarkFailed(ctx context.Context, eventID uuid.UUID, errorMsg string) error
	CountUnprocessed(ctx context.Context) (int64, error)
	HealthCheck(ctx context.Context) error
}
