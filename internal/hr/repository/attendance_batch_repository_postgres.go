package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type attendanceBatchRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceBatchRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) AttendanceBatchRepository {
	return &attendanceBatchRepository{
		client: postgresClient,
		logger: logger,
	}
}
func (r *attendanceBatchRepository) CreateBatch(
	ctx context.Context,
	batch *AttendancePunchBatch,
) error {
	query := `
		INSERT INTO attendance_device_punch_batches (
			batch_id,
			company_id,
			device_id,
			batch_ref,
			total_events,
			status,
			failure_reason,
			received_at,
			processed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`

	_, err := r.client.Exec(ctx, query,
		batch.BatchID,
		batch.CompanyID,
		batch.DeviceID,
		batch.BatchRef,
		batch.TotalEvents,
		batch.Status,
		batch.FailureReason,
		batch.ReceivedAt,
		batch.ProcessedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance punch batch",
			util.String("batch_id", batch.BatchID.String()),
			util.String("company_id", batch.CompanyID.String()),
			util.String("device_id", batch.DeviceID),
			util.String("batch_ref", batch.BatchRef),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create attendance batch: %w", err)
	}

	return nil
}
func (r *attendanceBatchRepository) MarkProcessed(
	ctx context.Context,
	batchID uuid.UUID,
) error {
	query := `
		UPDATE attendance_device_punch_batches
		SET status = 'processed',
		    processed_at = NOW()
		WHERE batch_id = $1
	`

	result, err := r.client.Exec(ctx, query, batchID)
	if err != nil {
		r.logger.Error("Failed to mark batch as processed",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark batch processed: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("attendance batch not found")
	}

	return nil
}
func (r *attendanceBatchRepository) MarkFailed(
	ctx context.Context,
	batchID uuid.UUID,
	reason string,
) error {
	query := `
		UPDATE attendance_device_punch_batches
		SET status = 'failed',
		    failure_reason = $2,
		    processed_at = NOW()
		WHERE batch_id = $1
	`

	result, err := r.client.Exec(ctx, query, batchID, reason)
	if err != nil {
		r.logger.Error("Failed to mark batch as failed",
			util.String("batch_id", batchID.String()),
			util.String("reason", reason),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark batch failed: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("attendance batch not found")
	}

	return nil
}
func (r *attendanceBatchRepository) ExistsByRef(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	batchRef string,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM attendance_device_punch_batches
			WHERE company_id = $1
			  AND device_id = $2
			  AND batch_ref = $3
		)
	`

	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, deviceID, batchRef).Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to check batch existence",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.String("batch_ref", batchRef),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("failed to check batch existence: %w", err)
	}

	return exists, nil
}
func (r *attendanceBatchRepository) GetByRef(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	batchRef string,
) (*AttendanceBatchStatus, error) {
	query := `
		SELECT
			batch_ref,
			status,
			total_events,
			received_at,
			processed_at,
			failure_reason
		FROM attendance_device_punch_batches
		WHERE company_id = $1
		  AND device_id = $2
		  AND batch_ref = $3
	`

	var res AttendanceBatchStatus
	err := r.client.QueryRow(ctx, query,
		companyID,
		deviceID,
		batchRef,
	).Scan(
		&res.BatchRef,
		&res.Status,
		&res.TotalEvents,
		&res.ReceivedAt,
		&res.ProcessedAt,
		&res.FailureReason,
	)

	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (r *attendanceBatchRepository) InsertFailure(
	ctx context.Context,
	failure *AttendancePunchFailure,
) error {
	query := `
		INSERT INTO attendance_device_punch_failures (
			failure_id,
			batch_id,
			company_id,
			device_id,
			device_user_code,
			event_type,
			event_time,
			failure_reason,
			raw_event,
			created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`

	_, err := r.client.Exec(ctx, query,
		failure.FailureID,
		failure.BatchID,
		failure.CompanyID,
		failure.DeviceID,
		failure.DeviceUserCode,
		failure.EventType,
		failure.EventTime,
		failure.FailureReason,
		failure.RawEvent,
		failure.CreatedAt,
	)

	if err != nil {
		r.logger.Error(
			"Failed to insert batch punch failure",
			util.String("batch_id", failure.BatchID.String()),
			util.String("device_id", failure.DeviceID),
			util.ErrorField(err),
		)
		return err
	}

	return nil
}

func (r *attendanceBatchRepository) ListFailuresByBatch(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	batchRef string,
	limit int,
	offset int,
) ([]AttendancePunchFailureView, error) {

	query := `
		SELECT
			f.failure_id,
			f.device_user_code,
			f.event_type,
			f.event_time,
			f.failure_reason,
			f.raw_event,
			f.created_at
		FROM attendance_device_punch_failures f
		JOIN attendance_device_punch_batches b
		  ON b.batch_id = f.batch_id
		WHERE b.company_id = $1
		  AND b.device_id = $2
		  AND b.batch_ref = $3
		ORDER BY f.created_at ASC
		LIMIT $4 OFFSET $5
	`

	rows, err := r.client.Query(ctx, query,
		companyID,
		deviceID,
		batchRef,
		limit,
		offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AttendancePunchFailureView

	for rows.Next() {
		var (
			f       AttendancePunchFailureView
			rawJSON []byte // 👈 TEMP BUFFER
		)

		if err := rows.Scan(
			&f.FailureID,
			&f.DeviceUserCode,
			&f.EventType,
			&f.EventTime,
			&f.FailureReason,
			&rawJSON, // 👈 scan jsonb as []byte
			&f.CreatedAt,
		); err != nil {
			return nil, err
		}

		// 👇 decode JSONB safely
		if err := json.Unmarshal(rawJSON, &f.RawEvent); err != nil {
			return nil, err
		}

		result = append(result, f)
	}

	return result, nil
}
