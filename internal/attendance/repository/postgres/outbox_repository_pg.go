package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type outboxRepositoryPG struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewOutboxRepository(pgClient *client.PostgresClient, logger *zap.Logger) repository.OutboxRepository {
	return &outboxRepositoryPG{
		client: pgClient,
		logger: logger,
	}
}

func (r *outboxRepositoryPG) Store(ctx context.Context, tx *sql.Tx, event *repository.OutboxEvent) error {
	// If EventID is not set, generate one
	if event.EventID == uuid.Nil {
		event.EventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Status == "" {
		event.Status = "pending"
	}
	if event.RetryCount == 0 {
		event.RetryCount = 0
	}

	// Marshal headers to JSON
	headersJSON, err := json.Marshal(event.Headers)
	if err != nil {
		return fmt.Errorf("marshal headers: %w", err)
	}

	query := `
		INSERT INTO outbox.events (
			event_id, aggregate_type, aggregate_id, event_type,
			topic, payload, headers, status, retry_count, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	var execer interface {
		ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	}
	if tx != nil {
		execer = tx
	} else {
		execer = r.client.DB
	}

	_, err = execer.ExecContext(ctx, query,
		event.EventID,
		event.AggregateType,
		event.AggregateID,
		event.EventType,
		event.Topic,
		event.Payload,
		headersJSON,
		event.Status,
		event.RetryCount,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}

func (r *outboxRepositoryPG) FetchUnprocessed(ctx context.Context, limit int) ([]*repository.OutboxEvent, error) {
	query := `
		SELECT event_id, aggregate_type, aggregate_id, event_type,
			topic, payload, headers, status, retry_count, created_at, processed_at
		FROM outbox.events
		WHERE status = 'pending' OR (status = 'failed' AND retry_count < 3)
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := r.client.DB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed: %w", err)
	}
	defer rows.Close()

	var events []*repository.OutboxEvent
	for rows.Next() {
		evt := &repository.OutboxEvent{}
		var headersJSON []byte
		err := rows.Scan(
			&evt.EventID,
			&evt.AggregateType,
			&evt.AggregateID,
			&evt.EventType,
			&evt.Topic,
			&evt.Payload,
			&headersJSON,
			&evt.Status,
			&evt.RetryCount,
			&evt.CreatedAt,
			&evt.ProcessedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		// Unmarshal headers
		if len(headersJSON) > 0 {
			var headers map[string]string
			if err := json.Unmarshal(headersJSON, &headers); err != nil {
				// If we can't unmarshal, treat as empty map but log warning
				r.logger.Warn("failed to unmarshal headers JSON", zap.Error(err), zap.String("event_id", evt.EventID.String()))
				evt.Headers = make(map[string]string)
			} else {
				evt.Headers = headers
			}
		} else {
			evt.Headers = make(map[string]string)
		}

		events = append(events, evt)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return events, nil
}

func (r *outboxRepositoryPG) MarkProcessed(ctx context.Context, eventIDs []uuid.UUID) error {
	if len(eventIDs) == 0 {
		return nil
	}

	query := `
		UPDATE outbox.events
		SET status = 'processed', processed_at = NOW()
		WHERE event_id = ANY($1)
	`

	_, err := r.client.DB.ExecContext(ctx, query, pq.Array(eventIDs))
	if err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}
	return nil
}

func (r *outboxRepositoryPG) MarkFailed(ctx context.Context, eventID uuid.UUID, errorMsg string) error {
	query := `
		UPDATE outbox.events
		SET status = 'failed', retry_count = retry_count + 1
		WHERE event_id = $1
	`

	_, err := r.client.DB.ExecContext(ctx, query, eventID)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}

	// Optionally, store error message somewhere, e.g., in a separate error log table.
	// For simplicity, we could also update a column like `error_message`; but the schema doesn't have it.
	// We'll log it.
	r.logger.Error("Outbox event marked failed", zap.String("event_id", eventID.String()), zap.String("error", errorMsg))
	return nil
}

func (r *outboxRepositoryPG) CountUnprocessed(ctx context.Context) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM outbox.events
		WHERE status = 'pending' OR (status = 'failed' AND retry_count < 3)
	`

	var count int64
	err := r.client.DB.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count unprocessed: %w", err)
	}
	return count, nil
}

func (r *outboxRepositoryPG) HealthCheck(ctx context.Context) error {
	// Simple ping
	if err := r.client.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}
