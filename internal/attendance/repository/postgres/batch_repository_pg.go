package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type batchRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewAttendanceBatchRepository creates a new batch repository
func NewAttendanceBatchRepository(pg *client.PostgresClient, logger *zap.Logger) repository.AttendanceBatchRepository {
	return &batchRepository{
		client: pg,
		logger: logger.Named("batch_repo"),
	}
}

func (r *batchRepository) CreateBatch(ctx context.Context, batch *repository.AttendancePunchBatch) error {
	query := `
		INSERT INTO attendance.attendance_device_punch_batches (
			batch_id, company_id, device_id, batch_ref, total_events,
			status, failure_reason, received_at, processed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
		r.logger.Error("failed to create batch",
			zap.String("batch_id", batch.BatchID.String()),
			zap.String("company_id", batch.CompanyID.String()),
			zap.String("device_id", batch.DeviceID),
			zap.String("batch_ref", batch.BatchRef),
			zap.Error(err),
		)
		return fmt.Errorf("create batch: %w", err)
	}
	return nil
}

func (r *batchRepository) MarkProcessed(ctx context.Context, batchID uuid.UUID) error {
	query := `
		UPDATE attendance.attendance_device_punch_batches
		SET status = 'processed', processed_at = NOW()
		WHERE batch_id = $1
	`
	result, err := r.client.Exec(ctx, query, batchID)
	if err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("batch %s not found", batchID)
	}
	return nil
}

func (r *batchRepository) MarkFailed(ctx context.Context, batchID uuid.UUID, reason string) error {
	query := `
		UPDATE attendance.attendance_device_punch_batches
		SET status = 'failed', failure_reason = $2, processed_at = NOW()
		WHERE batch_id = $1
	`
	result, err := r.client.Exec(ctx, query, batchID, reason)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("batch %s not found", batchID)
	}
	return nil
}

func (r *batchRepository) ExistsByRef(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM attendance.attendance_device_punch_batches
			WHERE company_id = $1 AND device_id = $2 AND batch_ref = $3
		)
	`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, deviceID, batchRef).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

func (r *batchRepository) InsertFailure(ctx context.Context, failure *repository.AttendancePunchFailure) error {
	query := `
		INSERT INTO attendance.attendance_device_punch_failures (
			failure_id, batch_id, company_id, device_id,
			device_user_code, event_type, event_time,
			failure_reason, raw_event, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		return fmt.Errorf("insert failure: %w", err)
	}
	return nil
}

func (r *batchRepository) ListFailuresByBatch(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID, batchRef string,
	limit, offset int,
) ([]repository.AttendancePunchFailureView, error) {
	query := `
		SELECT
			f.failure_id,
			f.device_user_code,
			f.event_type,
			f.event_time,
			f.failure_reason,
			f.raw_event,
			f.created_at
		FROM attendance.attendance_device_punch_failures f
		JOIN attendance.attendance_device_punch_batches b
			ON b.batch_id = f.batch_id
		WHERE b.company_id = $1
			AND b.device_id = $2
			AND b.batch_ref = $3
		ORDER BY f.created_at ASC
		LIMIT $4 OFFSET $5
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, batchRef, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list failures: %w", err)
	}
	defer rows.Close()

	var result []repository.AttendancePunchFailureView
	for rows.Next() {
		var (
			fv      repository.AttendancePunchFailureView
			rawJSON []byte
		)
		err := rows.Scan(
			&fv.FailureID,
			&fv.DeviceUserCode,
			&fv.EventType,
			&fv.EventTime,
			&fv.FailureReason,
			&rawJSON,
			&fv.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failure: %w", err)
		}
		if err := json.Unmarshal(rawJSON, &fv.RawEvent); err != nil {
			// fallback: treat as raw string
			fv.RawEvent = map[string]interface{}{"raw": string(rawJSON)}
		}
		result = append(result, fv)
	}
	return result, nil
}

func (r *batchRepository) GetByRef(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (*repository.AttendanceBatchStatus, error) {
	query := `
		SELECT batch_ref, status, total_events, received_at, processed_at, failure_reason
		FROM attendance.attendance_device_punch_batches
		WHERE company_id = $1 AND device_id = $2 AND batch_ref = $3
	`
	var status repository.AttendanceBatchStatus
	err := r.client.QueryRow(ctx, query, companyID, deviceID, batchRef).Scan(
		&status.BatchRef,
		&status.Status,
		&status.TotalEvents,
		&status.ReceivedAt,
		&status.ProcessedAt,
		&status.FailureReason,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get by ref: %w", err)
	}
	return &status, nil
}
func (r *batchRepository) ListFailuresByBatchRef(ctx context.Context, batchRef string) ([]*repository.AttendancePunchFailureView, error) {
	query := `
		SELECT
			f.failure_id,
			f.device_user_code,
			f.event_type,
			f.event_time,
			f.failure_reason,
			f.raw_event,
			f.created_at
		FROM attendance.attendance_device_punch_failures f
		JOIN attendance.attendance_device_punch_batches b
			ON b.batch_id = f.batch_id
		WHERE b.batch_ref = $1
		ORDER BY f.created_at ASC
	`
	rows, err := r.client.Query(ctx, query, batchRef)
	if err != nil {
		return nil, fmt.Errorf("list failures by ref: %w", err)
	}
	defer rows.Close()

	var result []*repository.AttendancePunchFailureView
	for rows.Next() {
		var fv repository.AttendancePunchFailureView
		var rawJSON []byte
		err := rows.Scan(
			&fv.FailureID,
			&fv.DeviceUserCode,
			&fv.EventType,
			&fv.EventTime,
			&fv.FailureReason,
			&rawJSON,
			&fv.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failure: %w", err)
		}
		if err := json.Unmarshal(rawJSON, &fv.RawEvent); err != nil {
			fv.RawEvent = map[string]interface{}{"raw": string(rawJSON)}
		}
		result = append(result, &fv)
	}
	return result, nil
}
