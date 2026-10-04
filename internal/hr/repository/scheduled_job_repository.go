// internal/hr/repository/scheduled_job_repository.go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/models/employee"
)

// ============================================================================
// Interface
// ============================================================================

// ScheduledJobRepository owns the hr.scheduled_job queue. Mirrors
// leave.ResolverJobRepository: Enqueue* take a *sql.Tx so the job commits
// atomically with the business change; the worker's Fetch/Mark/Release do not.
type ScheduledJobRepository interface {
	// Probation — reminder for T-14/T-7/T-3, end_reached for T+1.
	EnqueueProbationReminder(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, runAt time.Time, probationID uuid.UUID, endDate time.Time) error
	EnqueueProbationEndReached(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, runAt time.Time, probationID uuid.UUID) error
	// In the interface
	EnqueueMonthlyAccrual(
		ctx context.Context,
		tx *sql.Tx,
		companyID uuid.UUID,
		accrualDate time.Time,
	) error
	// Notice — T-3 and T-1 reminders before the notice end date.
	// The actual notice → terminated transition is done by the daily
	// enforcer (see factory.startDailyExitEnforcer), not by this queue.
	EnqueueNoticeReminder(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, runAt time.Time, noticeID uuid.UUID, endDate time.Time) error

	// On-hold — T-3/T-1 reminders + the expiry job that restores the
	// employee's previous employment_status.
	EnqueueOnHoldReminder(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, runAt time.Time, onHoldID uuid.UUID, endDate time.Time) error
	EnqueueOnHoldExpiry(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, runAt time.Time) error

	// CancelJobs flips queued/processing rows to 'cancelled'. Called on
	// its own tx (compensating action, not a business change).
	CancelJobs(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, userID *uuid.UUID, jobType string) error

	FetchNextRunnableJob(ctx context.Context, workerID string) (*employee.ScheduledJob, error)
	MarkCompleted(ctx context.Context, jobID uuid.UUID) error
	MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error
	ReleaseStaleLocks(ctx context.Context, staleThreshold time.Duration) (int64, error)

	// ApplyOnHoldExpiry flips the on-hold row to 'ended' and restores the
	// employee_profile.employment_status to on_hold.previous_status.
	// Idempotent — a row that was already ended is a no-op.
	ApplyOnHoldExpiry(ctx context.Context, jobID uuid.UUID) error
}

// ============================================================================
// Postgres implementation
// ============================================================================

type scheduledJobRepository struct {
	client *client.PostgresClient
}

func NewScheduledJobRepository(pg *client.PostgresClient) ScheduledJobRepository {
	return &scheduledJobRepository{client: pg}
}

// ============================================================================
// Enqueue
//
// The partial unique index uq_hr_job_pending_user is keyed by
// (company_id, user_id, job_type, run_at) — so T-14 and T-7 reminders for
// the same probation are distinct rows, but re-enqueueing the exact same
// run_at is a silent no-op.
// ============================================================================

const enqueueJobSQL = `
	INSERT INTO hr.scheduled_job (
		job_id, company_id, user_id, job_type, status,
		run_at, attempts, max_attempts, priority, payload
	) VALUES ($1,$2,$3,$4,'queued',$5,0,$6,$7,$8)
`

const conflictPendingUser = `
	ON CONFLICT (company_id, user_id, job_type, run_at)
	 WHERE status IN ('queued','processing') AND user_id IS NOT NULL
	 DO NOTHING
`

// ---- Probation ----

func (r *scheduledJobRepository) EnqueueProbationReminder(
	ctx context.Context, tx *sql.Tx,
	companyID, userID uuid.UUID,
	runAt time.Time,
	probationID uuid.UUID,
	endDate time.Time,
) error {
	payload, _ := json.Marshal(map[string]any{
		"probation_id":  probationID.String(),
		"probation_end": endDate.Format("2006-01-02"),
	})
	return r.enqueue(ctx, tx, conflictPendingUser,
		uuid.New(), companyID, userID,
		employee.JobProbationReminder, runAt, 5, 5, payload,
	)
}

func (r *scheduledJobRepository) EnqueueProbationEndReached(
	ctx context.Context, tx *sql.Tx,
	companyID, userID uuid.UUID,
	runAt time.Time,
	probationID uuid.UUID,
) error {
	payload, _ := json.Marshal(map[string]any{
		"probation_id": probationID.String(),
	})
	return r.enqueue(ctx, tx, conflictPendingUser,
		uuid.New(), companyID, userID,
		employee.JobProbationEndReached, runAt, 5, 5, payload,
	)
}

// ---- Notice ----

func (r *scheduledJobRepository) EnqueueNoticeReminder(
	ctx context.Context, tx *sql.Tx,
	companyID, userID uuid.UUID,
	runAt time.Time,
	noticeID uuid.UUID,
	endDate time.Time,
) error {
	payload, _ := json.Marshal(map[string]any{
		"notice_id":  noticeID.String(),
		"notice_end": endDate.Format("2006-01-02"),
	})
	return r.enqueue(ctx, tx, conflictPendingUser,
		uuid.New(), companyID, userID,
		employee.JobNoticeReminder, runAt, 5, 5, payload,
	)
}

// ---- On-hold ----

func (r *scheduledJobRepository) EnqueueOnHoldReminder(
	ctx context.Context, tx *sql.Tx,
	companyID, userID uuid.UUID,
	runAt time.Time,
	onHoldID uuid.UUID,
	endDate time.Time,
) error {
	payload, _ := json.Marshal(map[string]any{
		"on_hold_id":  onHoldID.String(),
		"on_hold_end": endDate.Format("2006-01-02"),
	})
	return r.enqueue(ctx, tx, conflictPendingUser,
		uuid.New(), companyID, userID,
		employee.JobOnHoldReminder, runAt, 5, 5, payload,
	)
}

func (r *scheduledJobRepository) EnqueueOnHoldExpiry(
	ctx context.Context, tx *sql.Tx,
	companyID, userID uuid.UUID,
	runAt time.Time,
) error {
	return r.enqueue(ctx, tx, conflictPendingUser,
		uuid.New(), companyID, userID,
		employee.JobOnHoldExpiry, runAt, 5, 5, nil,
	)
}

// ---- shared insert ----

func (r *scheduledJobRepository) enqueue(
	ctx context.Context, tx *sql.Tx, conflictSQL string,
	args ...interface{},
) error {
	if tx == nil {
		return errors.New("scheduled job enqueue requires an active transaction")
	}
	query := enqueueJobSQL + "\n" + conflictSQL
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("enqueue scheduled job: %w", err)
	}
	return nil
}

// ============================================================================
// Cancel — flips queued/processing rows to cancelled. Idempotent.
// ============================================================================

func (r *scheduledJobRepository) CancelJobs(
	ctx context.Context, tx *sql.Tx,
	companyID uuid.UUID, userID *uuid.UUID, jobType string,
) error {
	if tx == nil {
		return errors.New("scheduled job cancel requires an active transaction")
	}
	if userID != nil {
		_, err := tx.ExecContext(ctx, `
			UPDATE hr.scheduled_job
			   SET status       = 'cancelled',
			       completed_at = NOW(),
			       locked_by    = NULL,
			       locked_at    = NULL
			 WHERE company_id = $1
			   AND user_id    = $2
			   AND job_type   = $3
			   AND status IN ('queued','processing')`,
			companyID, *userID, jobType)
		if err != nil {
			return fmt.Errorf("cancel scheduled jobs (user): %w", err)
		}
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE hr.scheduled_job
		   SET status       = 'cancelled',
		       completed_at = NOW(),
		       locked_by    = NULL,
		       locked_at    = NULL
		 WHERE company_id = $1
		   AND user_id IS NULL
		   AND job_type   = $2
		   AND status IN ('queued','processing')`,
		companyID, jobType)
	if err != nil {
		return fmt.Errorf("cancel scheduled jobs (company): %w", err)
	}
	return nil
}

// ============================================================================
// FetchNextRunnableJob — FOR UPDATE SKIP LOCKED, same shape as leave
//
// The table has only `run_at` (no `next_run_at`). Retries and stale-lock
// releases re-arm `run_at` directly, so the WHERE filter on `run_at` is
// both the initial "when to run" and the "when to retry" signal.
// ============================================================================

func (r *scheduledJobRepository) FetchNextRunnableJob(
	ctx context.Context, workerID string,
) (*employee.ScheduledJob, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	const query = `
		SELECT job_id, company_id, user_id, job_type, status,
		       run_at, attempts, max_attempts, priority, payload,
		       created_at
		FROM hr.scheduled_job
		WHERE status = 'queued'
		  AND run_at <= NOW()
		  AND attempts < max_attempts
		ORDER BY priority ASC, run_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`

	var job employee.ScheduledJob
	var userID sql.NullString
	var payload []byte

	err = tx.QueryRowContext(ctx, query).Scan(
		&job.JobID, &job.CompanyID, &userID, &job.JobType, &job.Status,
		&job.RunAt, &job.Attempts, &job.MaxAttempts, &job.Priority, &payload,
		&job.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		if u, perr := uuid.Parse(userID.String); perr == nil {
			job.UserID = &u
		}
	}
	job.Payload = payload

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE hr.scheduled_job
		   SET status     = 'processing',
		       started_at = $1,
		       locked_by  = $2,
		       locked_at  = $1,
		       attempts   = attempts + 1
		 WHERE job_id = $3
	`, now, workerID, job.JobID); err != nil {
		return nil, err
	}

	job.Status = employee.JobStatusProcessing
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
// Mark / Release — exponential backoff, same as leave
// ============================================================================

func (r *scheduledJobRepository) MarkCompleted(ctx context.Context, jobID uuid.UUID) error {
	_, err := r.client.Exec(ctx, `
		UPDATE hr.scheduled_job
		   SET status        = 'completed',
		       completed_at  = $1,
		       locked_by     = NULL,
		       locked_at     = NULL,
		       error_message = NULL
		 WHERE job_id = $2
	`, time.Now().UTC(), jobID)
	if err != nil {
		return fmt.Errorf("mark scheduled job completed: %w", err)
	}
	return nil
}

func (r *scheduledJobRepository) MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	_, err := r.client.Exec(ctx, `
		UPDATE hr.scheduled_job
		   SET error_message = $1,
		       locked_by     = NULL,
		       locked_at     = NULL,
		       status        = CASE
		           WHEN attempts >= max_attempts THEN 'failed'
		           ELSE 'queued'
		       END,
		       run_at        = CASE
		           WHEN attempts >= max_attempts THEN run_at
		           ELSE NOW() + (POWER(2, attempts) * INTERVAL '30 seconds')
		       END
		 WHERE job_id = $2
	`, errMsg, jobID)
	if err != nil {
		return fmt.Errorf("mark scheduled job failed: %w", err)
	}
	return nil
}

func (r *scheduledJobRepository) ReleaseStaleLocks(
	ctx context.Context, staleThreshold time.Duration,
) (int64, error) {
	seconds := int64(staleThreshold.Seconds())
	res, err := r.client.Exec(ctx, `
		UPDATE hr.scheduled_job
		   SET status      = CASE
		           WHEN attempts >= max_attempts THEN 'failed'
		           ELSE 'queued'
		       END,
		       locked_by   = NULL,
		       locked_at   = NULL,
		       run_at      = NOW()
		 WHERE status = 'processing'
		   AND locked_at IS NOT NULL
		   AND locked_at < NOW() - ($1 * INTERVAL '1 second')
	`, seconds)
	if err != nil {
		return 0, fmt.Errorf("release stale scheduled job locks: %w", err)
	}
	return res.RowsAffected()
}

// ============================================================================
// ApplyOnHoldExpiry — the one job type that mutates status directly.
// Mirrors the DB function apply_on_hold_expiry(p_job_id UUID), but invoked
// from Go so the audit trail stays in the worker.
// ============================================================================

func (r *scheduledJobRepository) ApplyOnHoldExpiry(ctx context.Context, jobID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Look up the job's user so we can find the on-hold row.
	var companyID, userID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		SELECT company_id, user_id
		  FROM hr.scheduled_job
		 WHERE job_id = $1
	`, jobID).Scan(&companyID, &userID); err != nil {
		return fmt.Errorf("lookup job: %w", err)
	}

	// Find and end the active on-hold row.
	var onHoldID uuid.UUID
	var previousStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT on_hold_id, previous_status
		  FROM employee_on_hold
		 WHERE company_id = $1 AND user_id = $2 AND status = 'active'
		 FOR UPDATE
	`, companyID, userID).Scan(&onHoldID, &previousStatus)
	if errors.Is(err, sql.ErrNoRows) {
		// Already ended manually — nothing to do.
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup active on_hold: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE employee_on_hold
		   SET status   = 'ended',
		       ended_at = NOW()
		 WHERE on_hold_id = $1
	`, onHoldID); err != nil {
		return fmt.Errorf("end on_hold row: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE employee_profiles
		   SET employment_status = $1, updated_at = NOW()
		 WHERE company_id = $2
		   AND user_id    = $3
		   AND employment_status = 'on_hold'
	`, previousStatus, companyID, userID); err != nil {
		return fmt.Errorf("restore employment_status: %w", err)
	}

	// 👇 NEW — close every open on-hold reminder about this employee.
	//
	// Same transaction as the state flip, so it's atomic: either both
	// the on-hold ends and the reminders close, or neither.
	//
	// Prefix match ('on_hold_%') so future on-hold reminder types
	// (extended, ended, cancelled) are caught without a code change.
	if _, err := tx.ExecContext(ctx, `
		UPDATE hr.reminder
		   SET status      = 'actioned',
		       actioned_at = NOW()
		 WHERE company_id      = $1
		   AND subject_user_id = $2
		   AND reminder_type LIKE 'on_hold_%'
		   AND status IN ('unread','read')
	`, companyID, userID); err != nil {
		return fmt.Errorf("close on-hold reminders: %w", err)
	}

	return tx.Commit()
}

// EnqueueMonthlyAccrual queues exactly one leave.accrual.monthly job per
// (company, month). Idempotent via the partial unique index
// uq_scheduled_job_monthly_accrual — a second call for the same month is
// a silent no-op.
//
// Payload is always {"accrual_date":"YYYY-MM-DD"} anchored to the 1st of
// the month so the worker can post the accrual for the correct period
// regardless of when it actually runs (deploy delay, retry, etc.).
func (r *scheduledJobRepository) EnqueueMonthlyAccrual(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	accrualDate time.Time,
) error {
	if tx == nil {
		return errors.New("enqueue monthly accrual requires an active transaction")
	}

	// Anchor to the first of the month in UTC. The worker uses this date
	// to determine which period to post for.
	anchor := time.Date(
		accrualDate.Year(),
		accrualDate.Month(),
		1,
		0, 0, 0, 0,
		time.UTC,
	)

	payload, err := json.Marshal(map[string]string{
		"accrual_date": anchor.Format("2006-01-02"),
	})
	if err != nil {
		return fmt.Errorf("marshal accrual payload: %w", err)
	}

	// The WHERE predicate on ON CONFLICT must match the partial unique
	// index uq_scheduled_job_monthly_accrual exactly — same columns,
	// same WHERE clause — or Postgres raises
	//   "there is no unique or exclusion constraint matching the
	//    ON CONFLICT specification"
	// at parse time and the whole enqueue fails.
	//
	// Index predicate (must match 1:1):
	//   WHERE user_id IS NULL
	//     AND job_type = 'leave.accrual.monthly'
	//     AND status IN ('queued', 'processing')
	const q = `
		INSERT INTO hr.scheduled_job (
			job_id, company_id, user_id, job_type, status,
			run_at, attempts, max_attempts, priority, payload
		) VALUES (
			$1, $2, NULL, $3, 'queued',
			$4, 0, 5, 3, $5
		)
		ON CONFLICT (company_id, job_type, (payload->>'accrual_date'))
			WHERE status IN ('queued','processing')
			  AND user_id IS NULL
			  AND job_type = 'leave.accrual.monthly'
			DO NOTHING
	`

	if _, err := tx.ExecContext(ctx, q,
		uuid.New(),
		companyID,
		employee.JobLeaveAccrualMonthly, // 👈 use the constant, not a literal
		anchor,
		payload,
	); err != nil {
		return fmt.Errorf("enqueue monthly accrual: %w", err)
	}
	return nil
}
