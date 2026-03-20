package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// Store inside TX
func (r *PostgresRepository) Store(ctx context.Context, tx *sql.Tx, event *Event) error {
	headers, _ := json.Marshal(event.Headers)

	_, err := tx.ExecContext(ctx, `
		INSERT INTO outbox.events (
			event_id, aggregate_type, aggregate_id,
			event_type, payload, headers
		) VALUES ($1,$2,$3,$4,$5,$6)
	`,
		event.EventID,
		event.AggregateType,
		event.AggregateID,
		event.EventType,
		event.Payload,
		headers,
	)

	return err
}

// Fetch pending events
func (r *PostgresRepository) FetchPending(ctx context.Context, limit int) ([]*Event, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT event_id, aggregate_type, aggregate_id,
		       event_type, payload, headers, retry_count
		FROM outbox.events
		WHERE status = 'pending'
		ORDER BY created_at
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event

	for rows.Next() {
		var e Event
		var headers []byte

		if err := rows.Scan(
			&e.EventID,
			&e.AggregateType,
			&e.AggregateID,
			&e.EventType,
			&e.Payload,
			&headers,
			&e.RetryCount,
		); err != nil {
			return nil, err
		}

		json.Unmarshal(headers, &e.Headers)

		events = append(events, &e)
	}

	return events, nil
}

// Mark processed
func (r *PostgresRepository) MarkProcessed(ctx context.Context, eventID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE outbox.events
		SET status = 'processed', processed_at = NOW()
		WHERE event_id = $1
	`, eventID)

	return err
}

// Mark failed
func (r *PostgresRepository) MarkFailed(ctx context.Context, eventID string, retryCount int) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE outbox.events
		SET retry_count = $2
		WHERE event_id = $1
	`, eventID, retryCount)

	return err
}
