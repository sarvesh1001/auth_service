package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type scheduleGenerationJobRepository struct {
	client *client.PostgresClient
}

func NewScheduleGenerationJobRepository(pg *client.PostgresClient) repository.ScheduleGenerationJobRepository {
	return &scheduleGenerationJobRepository{client: pg}
}

// ============================================================================
// Enqueue
// ============================================================================

const insertScheduleGenJobSQL = `
	INSERT INTO attendance.schedule_generation_job (
		job_id, company_id, user_id, position_id,
		job_type, status, attempts, max_attempts,
		priority, reason, payload, created_at, next_run_at
	) VALUES ($1,$2,$3,$4,$5,'queued',0,$6,$7,$8,$9,NOW(),NOW())
`

func (r *scheduleGenerationJobRepository) EnqueueUserGeneration(
	ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, payload []byte, reason string,
) error {
	return r.enqueue(ctx, tx, insertScheduleGenJobSQL,
		uuid.New(), companyID, userID, nil,
		models.ScheduleGenJobTypeGenerateUser, 3, 4, reason, payload,
		`ON CONFLICT (company_id, user_id, job_type)
		 WHERE status IN ('queued','processing') AND user_id IS NOT NULL
		 DO NOTHING`,
	)
}

func (r *scheduleGenerationJobRepository) EnqueueCompanyGeneration(
	ctx context.Context, tx *sql.Tx, companyID uuid.UUID, payload []byte, reason string,
) error {
	return r.enqueue(ctx, tx, insertScheduleGenJobSQL,
		uuid.New(), companyID, nil, nil,
		models.ScheduleGenJobTypeGenerateCompany, 3, 8, reason, payload,
		`ON CONFLICT (company_id, job_type)
		 WHERE status IN ('queued','processing')
		   AND user_id IS NULL
		   AND position_id IS NULL
		 DO NOTHING`,
	)
}

func (r *scheduleGenerationJobRepository) EnqueuePositionGeneration(
	ctx context.Context, tx *sql.Tx, companyID, positionID uuid.UUID, payload []byte, reason string,
) error {
	return r.enqueue(ctx, tx, insertScheduleGenJobSQL,
		uuid.New(), companyID, nil, positionID,
		models.ScheduleGenJobTypeGeneratePosition, 3, 6, reason, payload,
		`ON CONFLICT (company_id, position_id, job_type)
		 WHERE status IN ('queued','processing') AND position_id IS NOT NULL
		 DO NOTHING`,
	)
}

func (r *scheduleGenerationJobRepository) enqueue(
	ctx context.Context, tx *sql.Tx, baseSQL string, args ...interface{},
) error {
	if len(args) == 0 {
		return errors.New("enqueue called with no arguments")
	}
	conflict, ok := args[len(args)-1].(string)
	if !ok {
		return errors.New("enqueue: last argument must be the conflict clause")
	}
	values := args[:len(args)-1]
	query := baseSQL + "\n" + conflict

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, values...)
	} else {
		_, err = r.client.Exec(ctx, query, values...)
	}
	if err != nil {
		return fmt.Errorf("enqueue schedule generation job: %w", err)
	}
	return nil
}

// ============================================================================
// Dequeue
// ============================================================================

func (r *scheduleGenerationJobRepository) FetchNextRunnableJob(
	ctx context.Context, workerID string,
) (*models.ScheduleGenerationJob, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	const q = `
		SELECT job_id, company_id, user_id, position_id, location_id,
		       job_type, status, attempts, max_attempts, priority,
		       reason, payload, error_message,
		       created_at, next_run_at
		FROM attendance.schedule_generation_job
		WHERE status = 'queued'
		  AND (next_run_at IS NULL OR next_run_at <= NOW())
		  AND attempts < max_attempts
		ORDER BY priority ASC, created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`
	var job models.ScheduleGenerationJob
	var userID, positionID, locationID sql.NullString
	var reason, errMsg sql.NullString
	var nextRunAt sql.NullTime
	var payload []byte

	err = tx.QueryRowContext(ctx, q).Scan(
		&job.JobID, &job.CompanyID,
		&userID, &positionID, &locationID,
		&job.JobType, &job.Status,
		&job.Attempts, &job.MaxAttempts, &job.Priority,
		&reason, &payload, &errMsg,
		&job.CreatedAt, &nextRunAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		if u, parseErr := uuid.Parse(userID.String); parseErr == nil {
			job.UserID = &u
		}
	}
	if positionID.Valid {
		if p, parseErr := uuid.Parse(positionID.String); parseErr == nil {
			job.PositionID = &p
		}
	}
	if locationID.Valid {
		if l, parseErr := uuid.Parse(locationID.String); parseErr == nil {
			job.LocationID = &l
		}
	}
	if reason.Valid {
		job.Reason = &reason.String
	}
	if errMsg.Valid {
		job.ErrorMessage = &errMsg.String
	}
	if nextRunAt.Valid {
		job.NextRunAt = &nextRunAt.Time
	}
	job.Payload = payload

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE attendance.schedule_generation_job
		SET status    = 'processing',
		    started_at = $1,
		    locked_by  = $2,
		    locked_at  = $1,
		    attempts   = attempts + 1
		WHERE job_id = $3
	`, now, workerID, job.JobID); err != nil {
		return nil, err
	}

	job.Status = models.ScheduleGenJobStatusProcessing
	job.StartedAt = &now
	job.LockedBy = &workerID
	job.LockedAt = &now
	job.Attempts++

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &job, nil
}

// ============================================================================
// Mark complete / failed / release
// ============================================================================

func (r *scheduleGenerationJobRepository) MarkCompleted(ctx context.Context, jobID uuid.UUID) error {
	_, err := r.client.Exec(ctx, `
		UPDATE attendance.schedule_generation_job
		SET status        = 'completed',
		    completed_at  = $1,
		    locked_by     = NULL,
		    locked_at     = NULL,
		    error_message = NULL
		WHERE job_id = $2
	`, time.Now().UTC(), jobID)
	if err != nil {
		return fmt.Errorf("mark schedule gen job completed: %w", err)
	}
	return nil
}

func (r *scheduleGenerationJobRepository) MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	_, err := r.client.Exec(ctx, `
		UPDATE attendance.schedule_generation_job
		SET error_message = $1,
		    locked_by     = NULL,
		    locked_at     = NULL,
		    status        = CASE
		        WHEN attempts >= max_attempts THEN 'failed'
		        ELSE 'queued'
		    END,
		    next_run_at   = CASE
		        WHEN attempts >= max_attempts THEN NULL
		        ELSE NOW() + (POWER(2, attempts) * INTERVAL '15 seconds')
		    END
		WHERE job_id = $2
	`, errMsg, jobID)
	if err != nil {
		return fmt.Errorf("mark schedule gen job failed: %w", err)
	}
	return nil
}

func (r *scheduleGenerationJobRepository) ReleaseStaleLocks(
	ctx context.Context, staleThreshold time.Duration,
) (int64, error) {
	seconds := int64(staleThreshold.Seconds())
	res, err := r.client.Exec(ctx, `
		UPDATE attendance.schedule_generation_job
		SET status      = CASE
		        WHEN attempts >= max_attempts THEN 'failed'
		        ELSE 'queued'
		    END,
		    locked_by   = NULL,
		    locked_at   = NULL,
		    next_run_at = NOW()
		WHERE status = 'processing'
		  AND locked_at IS NOT NULL
		  AND locked_at < NOW() - ($1 * INTERVAL '1 second')
	`, seconds)
	if err != nil {
		return 0, fmt.Errorf("release stale schedule gen locks: %w", err)
	}
	return res.RowsAffected()
}

// ============================================================================
// MarkCompletedWithResult — persist per-user outcomes atomically
// ============================================================================

func (r *scheduleGenerationJobRepository) MarkCompletedWithResult(
	ctx context.Context,
	jobID uuid.UUID,
	outcome *models.ScheduleGenerationOutcome,
) error {
	if outcome == nil {
		outcome = &models.ScheduleGenerationOutcome{}
	}

	warningsJSON, err := json.Marshal(outcome.Warnings)
	if err != nil {
		return fmt.Errorf("marshal warnings: %w", err)
	}
	failuresJSON, err := json.Marshal(outcome.Failures)
	if err != nil {
		return fmt.Errorf("marshal failures: %w", err)
	}
	summaryJSON, err := json.Marshal(map[string]interface{}{
		"instances_created": outcome.InstancesCreated,
		"users_processed":   outcome.UsersProcessed,
		"warnings_count":    len(outcome.Warnings),
		"failures_count":    len(outcome.Failures),
	})
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}

	_, err = r.client.Exec(ctx, `
		UPDATE attendance.schedule_generation_job
		SET status         = CASE
		        WHEN jsonb_array_length($2::jsonb) > 0
		          OR jsonb_array_length($3::jsonb) > 0
		        THEN 'completed_with_warnings'
		        ELSE 'completed'
		    END,
		    completed_at   = $1,
		    warnings       = $2::jsonb,
		    failures       = $3::jsonb,
		    result_summary = $4::jsonb,
		    locked_by      = NULL,
		    locked_at      = NULL,
		    error_message  = NULL
		WHERE job_id = $5
	`, time.Now().UTC(), warningsJSON, failuresJSON, summaryJSON, jobID)
	if err != nil {
		return fmt.Errorf("mark schedule gen job completed with result: %w", err)
	}
	return nil
}

// ============================================================================
// GetByID — includes the new outcome columns
// ============================================================================

func (r *scheduleGenerationJobRepository) GetByID(
	ctx context.Context, jobID uuid.UUID,
) (*models.ScheduleGenerationJob, error) {
	const q = `
		SELECT job_id, company_id, user_id, position_id, location_id,
		       job_type, status, attempts, max_attempts, priority,
		       reason, payload, error_message,
		       warnings, failures, result_summary,
		       created_at, next_run_at, started_at, completed_at,
		       locked_by, locked_at
		FROM attendance.schedule_generation_job
		WHERE job_id = $1
	`

	var job models.ScheduleGenerationJob
	var userID, positionID, locationID sql.NullString
	var reason, errMsg, lockedBy sql.NullString
	var nextRunAt, startedAt, completedAt, lockedAt sql.NullTime
	var payload, warningsJSON, failuresJSON, summaryJSON []byte

	err := r.client.QueryRow(ctx, q, jobID).Scan(
		&job.JobID, &job.CompanyID,
		&userID, &positionID, &locationID,
		&job.JobType, &job.Status,
		&job.Attempts, &job.MaxAttempts, &job.Priority,
		&reason, &payload, &errMsg,
		&warningsJSON, &failuresJSON, &summaryJSON,
		&job.CreatedAt, &nextRunAt, &startedAt, &completedAt,
		&lockedBy, &lockedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		if u, parseErr := uuid.Parse(userID.String); parseErr == nil {
			job.UserID = &u
		}
	}
	if positionID.Valid {
		if p, parseErr := uuid.Parse(positionID.String); parseErr == nil {
			job.PositionID = &p
		}
	}
	if locationID.Valid {
		if l, parseErr := uuid.Parse(locationID.String); parseErr == nil {
			job.LocationID = &l
		}
	}
	if reason.Valid {
		job.Reason = &reason.String
	}
	if errMsg.Valid {
		job.ErrorMessage = &errMsg.String
	}
	if lockedBy.Valid {
		job.LockedBy = &lockedBy.String
	}
	if nextRunAt.Valid {
		job.NextRunAt = &nextRunAt.Time
	}
	if startedAt.Valid {
		job.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = &completedAt.Time
	}
	if lockedAt.Valid {
		job.LockedAt = &lockedAt.Time
	}
	job.Payload = payload
	job.Warnings = warningsJSON
	job.Failures = failuresJSON
	job.ResultSummary = summaryJSON

	return &job, nil
}

// ============================================================================
// Count helpers — used by the worker's periodic gauge snapshotter
// ============================================================================

func (r *scheduleGenerationJobRepository) CountQueued(ctx context.Context) (int64, error) {
	var n int64
	err := r.client.QueryRow(ctx, `
		SELECT count(*) FROM attendance.schedule_generation_job
		WHERE status = 'queued'
	`).Scan(&n)
	return n, err
}

func (r *scheduleGenerationJobRepository) CountFailed(
	ctx context.Context, since *time.Time,
) (int64, error) {
	var n int64
	var err error
	if since != nil {
		err = r.client.QueryRow(ctx, `
			SELECT count(*) FROM attendance.schedule_generation_job
			WHERE status = 'failed' AND created_at >= $1
		`, *since).Scan(&n)
	} else {
		err = r.client.QueryRow(ctx, `
			SELECT count(*) FROM attendance.schedule_generation_job
			WHERE status = 'failed'
		`).Scan(&n)
	}
	return n, err
}

func (r *scheduleGenerationJobRepository) CountStuck(
	ctx context.Context, threshold time.Duration,
) (int64, error) {
	var n int64
	err := r.client.QueryRow(ctx, `
		SELECT count(*) FROM attendance.schedule_generation_job
		WHERE status = 'processing'
		  AND locked_at < now() - ($1 * interval '1 second')
	`, int64(threshold.Seconds())).Scan(&n)
	return n, err
}
