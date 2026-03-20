package outbox

import (
	"context"
	"database/sql"
)

type Repository interface {
	Store(ctx context.Context, tx *sql.Tx, event *Event) error

	FetchPending(ctx context.Context, limit int) ([]*Event, error)

	MarkProcessed(ctx context.Context, eventID string) error

	MarkFailed(ctx context.Context, eventID string, retryCount int) error
}
