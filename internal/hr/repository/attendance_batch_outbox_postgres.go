package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"auth-service/internal/client"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type attendanceBatchOutboxRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceBatchOutboxRepository(
	client *client.PostgresClient,
	logger *zap.Logger,
) AttendanceBatchOutboxRepository {
	return &attendanceBatchOutboxRepository{
		client: client,
		logger: logger,
	}
}

func (r *attendanceBatchOutboxRepository) Insert(
	ctx context.Context,
	event *AttendanceBatchOutbox,
) error {
	payloadBytes, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal outbox payload: %w", err)
	}

	query := `
		INSERT INTO attendance.attendance_batch_outbox (
			outbox_id,
			event_type,
			aggregate_id,
			payload,
			created_at
		) VALUES ($1,$2,$3,$4,$5)
	`

	_, err = r.client.Exec(ctx, query,
		event.OutboxID,
		event.EventType,
		event.AggregateID,
		payloadBytes,
		event.CreatedAt,
	)

	if err != nil {
		r.logger.Error(
			"failed to insert attendance batch outbox",
			util.String("event_type", event.EventType),
			util.String("aggregate_id", event.AggregateID.String()),
			util.ErrorField(err),
		)
		return err
	}

	return nil
}

func (r *attendanceBatchOutboxRepository) FetchUnprocessed(
	ctx context.Context,
	limit int,
) ([]*AttendanceBatchOutbox, error) {

	query := `
		SELECT
			outbox_id,
			event_type,
			aggregate_id,
			payload,
			created_at,
			processed_at,
			error_message
		FROM attendance.attendance_batch_outbox
		WHERE processed_at IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := r.client.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AttendanceBatchOutbox

	for rows.Next() {
		var (
			o            AttendanceBatchOutbox
			payloadBytes []byte
		)

		if err := rows.Scan(
			&o.OutboxID,
			&o.EventType,
			&o.AggregateID,
			&payloadBytes,
			&o.CreatedAt,
			&o.ProcessedAt,
			&o.ErrorMessage,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(payloadBytes, &o.Payload); err != nil {
			return nil, err
		}

		result = append(result, &o)
	}

	return result, nil
}

func (r *attendanceBatchOutboxRepository) MarkProcessed(
	ctx context.Context,
	outboxIDs []uuid.UUID,
) error {
	if len(outboxIDs) == 0 {
		return nil
	}

	query := `
		UPDATE attendance.attendance_batch_outbox
		SET processed_at = NOW()
		WHERE outbox_id = ANY($1::uuid[])
	`

	_, err := r.client.Exec(ctx, query, pq.Array(outboxIDs))
	return err
}

func (r *attendanceBatchOutboxRepository) MarkFailed(
	ctx context.Context,
	outboxID uuid.UUID,
	errorMessage string,
) error {
	query := `
		UPDATE attendance.attendance_batch_outbox
		SET error_message = $2
		WHERE outbox_id = $1
	`

	_, err := r.client.Exec(ctx, query, outboxID, errorMessage)
	return err
}
func (r *attendanceBatchOutboxRepository) ListFailuresByBatchRef(
	ctx context.Context,
	batchRef string,
) ([]*AttendanceBatchOutbox, error) {

	const q = `
        SELECT
            outbox_id,
            event_type,
            aggregate_id,
            payload,
            created_at,
            processed_at,
            error_message
        FROM attendance.attendance_batch_outbox
        WHERE payload->>'batch_ref' = $1
          AND error_message IS NOT NULL
        ORDER BY created_at ASC
    `

	rows, err := r.client.DB.QueryContext(ctx, q, batchRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AttendanceBatchOutbox

	for rows.Next() {
		var o AttendanceBatchOutbox
		if err := rows.Scan(
			&o.OutboxID,
			&o.EventType,
			&o.AggregateID,
			&o.Payload,
			&o.CreatedAt,
			&o.ProcessedAt,
			&o.ErrorMessage,
		); err != nil {
			return nil, err
		}
		result = append(result, &o)
	}

	return result, nil
}
