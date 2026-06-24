package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// ============================================================
// Store inside TX
// ============================================================
func (r *PostgresRepository) Store(ctx context.Context, tx *sql.Tx, event *Event) error {
	// Validate required fields
	if event.EventID == "" {
		return errors.New("event_id cannot be empty")
	}
	if event.AggregateType == "" {
		return errors.New("aggregate_type cannot be empty")
	}
	if event.EventType == "" {
		return errors.New("event_type cannot be empty")
	}
	if event.Topic == "" {
		return errors.New("topic cannot be empty")
	}
	if len(event.Payload) == 0 {
		return errors.New("payload cannot be empty")
	}

	// Marshal headers
	var headers []byte
	var err error
	if event.Headers == nil {
		headers = []byte("null")
	} else {
		headers, err = json.Marshal(event.Headers)
		if err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO outbox.events (
			event_id,
			aggregate_type,
			aggregate_id,
			event_type,
			topic,
			payload,
			headers,
			status,
			retry_count,
			created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',0,NOW())
	`,
		event.EventID,
		event.AggregateType,
		event.AggregateID,
		event.EventType,
		event.Topic,
		event.Payload,
		headers,
	)

	return err
}

// ============================================================
// Fetch pending events with row-level locking
// ============================================================
func (r *PostgresRepository) FetchPending(ctx context.Context, limit int) ([]*Event, error) {
	// ✅ CRITICAL FIX: Use FOR UPDATE SKIP LOCKED to prevent multiple outbox
	// processors from grabbing the same event concurrently.
	rows, err := r.db.QueryContext(ctx, `
		SELECT 
			event_id,
			aggregate_type,
			aggregate_id,
			event_type,
			topic,
			payload,
			headers,
			retry_count,
			created_at
		FROM outbox.events
		WHERE status = 'pending'
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
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
			&e.Topic,
			&e.Payload,
			&headers,
			&e.RetryCount,
			&e.CreatedAt,
		); err != nil {
			return nil, err
		}

		// Unmarshal headers
		if len(headers) > 0 && string(headers) != "null" {
			if err := json.Unmarshal(headers, &e.Headers); err != nil {
				e.Headers = make(map[string]string)
			}
		} else {
			e.Headers = make(map[string]string)
		}

		events = append(events, &e)
	}

	return events, nil
}

// ============================================================
// Mark processed
// ============================================================
func (r *PostgresRepository) MarkProcessed(ctx context.Context, eventID string) error {
	if eventID == "" {
		return errors.New("event_id cannot be empty")
	}

	_, err := r.db.ExecContext(ctx, `
		UPDATE outbox.events
		SET status = 'processed',
		    processed_at = NOW()
		WHERE event_id = $1
	`, eventID)

	return err
}

// ============================================================
// Mark failed (with retry)
// ============================================================
func (r *PostgresRepository) MarkFailed(ctx context.Context, eventID string, retryCount int) error {
	if eventID == "" {
		return errors.New("event_id cannot be empty")
	}

	status := "pending"

	// optional: move to failed after max retries
	if retryCount >= 5 {
		status = "failed"
	}

	_, err := r.db.ExecContext(ctx, `
		UPDATE outbox.events
		SET retry_count = $2,
		    status = $3
		WHERE event_id = $1
	`, eventID, retryCount, status)

	return err
}
