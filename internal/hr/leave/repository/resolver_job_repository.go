package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/leave/models"
)

// ============================================================================
// Interface
// ============================================================================

type ResolverJobRepository interface {
	// Enqueue* accept a *sql.Tx so the job is committed atomically with the
	// business change. Pass the caller's tx; do NOT pass nil.
	EnqueueUserResolution(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, reason string) error
	EnqueueUserResolutions(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, userIDs []uuid.UUID, reason string) error   // ← NEW
	EnqueueCompanyResolution(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, reason string) error
	EnqueuePositionResolution(ctx context.Context, tx *sql.Tx, companyID, positionID uuid.UUID, reason string) error
	EnqueueEndEntitlements(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, reason string) error

	FetchNextRunnableJob(ctx context.Context, workerID string) (*models.ResolverJob, error)
	MarkCompleted(ctx context.Context, jobID uuid.UUID) error
	MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error
	ReleaseStaleLocks(ctx context.Context, staleThreshold time.Duration) (int64, error)
}

// ============================================================================
// Postgres implementation
// ============================================================================

type resolverJobRepository struct {
	client *client.PostgresClient
}

func NewResolverJobRepository(pg *client.PostgresClient) ResolverJobRepository {
	return &resolverJobRepository{client: pg}
}

// ============================================================================
// Enqueue
// ============================================================================

const enqueueSQL = `
	INSERT INTO leave.resolver_job (
		job_id, company_id, user_id, position_id,
		job_type, status, attempts, max_attempts,
		priority, reason, created_at, next_run_at
	) VALUES ($1,$2,$3,$4,$5,'queued',0,5,$6,$7,NOW(),NOW())
`

func (r *resolverJobRepository) EnqueueUserResolution(
	ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, reason string,
) error {
	return r.enqueue(ctx, tx, enqueueSQL,
		uuid.New(), companyID, userID, nil,
		models.ResolverJobTypeResolveUser, 5, reason,
		`ON CONFLICT (company_id, user_id, job_type)
		 WHERE status IN ('queued','processing') AND user_id IS NOT NULL
		 DO NOTHING`,
	)
}

// EnqueueUserResolutions bulk-inserts resolve_user jobs for many users in a
// single statement. Uses NOT EXISTS against the pending-user partial unique
// index semantics so a re-click doesn't multiply jobs. A user with an
// existing queued/processing resolve_user job is silently skipped.
//
// Why NOT EXISTS instead of ON CONFLICT: Postgres requires the ON CONFLICT
// inference clause to name a non-partial unique constraint, and matching a
// partial index in a bulk INSERT...SELECT needs the exact predicate
// repeated — easier and more portable to express intent with NOT EXISTS.



// EnqueueUserResolutions inserts one resolve_user job per user, inside the
// caller's transaction. Duplicates (a user already having a pending or
// processing resolve_user job) are silently skipped by EnqueueUserResolution's
// ON CONFLICT predicate, which targets the partial unique index
// uq_leave_resolver_job_pending_user.
//
// Loop rather than a bulk unnest(): the underlying driver is database/sql
// and cannot bind []uuid.UUID as a parameter. Postgres will reject the
// argument at prepare time with "unsupported type []uuid.UUID" — the query
// never runs, and the caller sees a 500. For batches up to a few hundred
// users the per-row round-trip cost is negligible compared to the work each
// ResolveUserLeaveEntitlements call does downstream.
func (r *resolverJobRepository) EnqueueUserResolutions(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	reason string,
) error {
	if tx == nil {
		return errors.New("resolver job enqueue requires an active transaction")
	}
	if len(userIDs) == 0 {
		return nil
	}
	for _, uid := range userIDs {
		if err := r.EnqueueUserResolution(ctx, tx, companyID, uid, reason); err != nil {
			return fmt.Errorf("enqueue resolve_user for %s: %w", uid.String(), err)
		}
	}
	return nil
}
func (r *resolverJobRepository) EnqueueCompanyResolution(
	ctx context.Context, tx *sql.Tx, companyID uuid.UUID, reason string,
) error {
	return r.enqueue(ctx, tx, enqueueSQL,
		uuid.New(), companyID, nil, nil,
		models.ResolverJobTypeResolveCompany, 5, reason,
		`ON CONFLICT (company_id, job_type)
		 WHERE status IN ('queued','processing') AND user_id IS NULL
		 DO NOTHING`,
	)
}

func (r *resolverJobRepository) EnqueuePositionResolution(
	ctx context.Context, tx *sql.Tx, companyID, positionID uuid.UUID, reason string,
) error {
	return r.enqueue(ctx, tx, enqueueSQL,
		uuid.New(), companyID, nil, positionID,
		models.ResolverJobTypeResolvePosition, 5, reason,
		`ON CONFLICT (company_id, position_id, job_type)
		 WHERE status IN ('queued','processing') AND position_id IS NOT NULL
		 DO NOTHING`,
	)
}

func (r *resolverJobRepository) EnqueueEndEntitlements(
	ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, reason string,
) error {
	return r.enqueue(ctx, tx, enqueueSQL,
		uuid.New(), companyID, userID, nil,
		models.ResolverJobTypeEndEntitlements, 4, reason,
		`ON CONFLICT (company_id, user_id, job_type)
		 WHERE status IN ('queued','processing') AND user_id IS NOT NULL
		 DO NOTHING`,
	)
}

func (r *resolverJobRepository) enqueue(
	ctx context.Context,
	tx *sql.Tx,
	baseSQL string,
	args ...interface{},
) error {
	if tx == nil {
		return errors.New("resolver job enqueue requires an active transaction")
	}
	conflict := args[len(args)-1].(string)
	values := args[:len(args)-1]

	query := baseSQL + "\n" + conflict
	_, err := tx.ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("enqueue resolver job: %w", err)
	}
	return nil
}

// ============================================================================
// FetchNextRunnableJob — unchanged
// ============================================================================

func (r *resolverJobRepository) FetchNextRunnableJob(
	ctx context.Context, workerID string,
) (*models.ResolverJob, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
		SELECT job_id, company_id, user_id, position_id,
		       job_type, status, attempts, max_attempts,
		       priority, reason, error_message, payload,
		       created_at, next_run_at
		FROM leave.resolver_job
		WHERE status = 'queued'
		  AND (next_run_at IS NULL OR next_run_at <= NOW())
		  AND attempts < max_attempts
		ORDER BY priority ASC, created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`

	var job models.ResolverJob
	var userID, positionID sql.NullString
	var reason, errMsg sql.NullString
	var payload []byte
	var nextRunAt sql.NullTime

	err = tx.QueryRowContext(ctx, query).Scan(
		&job.JobID, &job.CompanyID,
		&userID, &positionID,
		&job.JobType, &job.Status,
		&job.Attempts, &job.MaxAttempts,
		&job.Priority, &reason, &errMsg, &payload,
		&job.CreatedAt, &nextRunAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		if u, err := uuid.Parse(userID.String); err == nil {
			job.UserID = &u
		}
	}
	if positionID.Valid {
		if p, err := uuid.Parse(positionID.String); err == nil {
			job.PositionID = &p
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
	_, err = tx.ExecContext(ctx, `
		UPDATE leave.resolver_job
		SET status    = 'processing',
		    started_at = $1,
		    locked_by  = $2,
		    locked_at  = $1,
		    attempts   = attempts + 1
		WHERE job_id = $3
	`, now, workerID, job.JobID)
	if err != nil {
		return nil, err
	}

	job.Status = models.ResolverJobStatusProcessing
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
// MarkCompleted / MarkFailed / ReleaseStaleLocks — unchanged
// ============================================================================

func (r *resolverJobRepository) MarkCompleted(ctx context.Context, jobID uuid.UUID) error {
	_, err := r.client.Exec(ctx, `
		UPDATE leave.resolver_job
		SET status         = 'completed',
		    completed_at   = $1,
		    locked_by      = NULL,
		    locked_at      = NULL,
		    error_message  = NULL
		WHERE job_id = $2
	`, time.Now().UTC(), jobID)
	if err != nil {
		return fmt.Errorf("mark resolver job completed: %w", err)
	}
	return nil
}

func (r *resolverJobRepository) MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	_, err := r.client.Exec(ctx, `
		UPDATE leave.resolver_job
		SET error_message = $1,
		    locked_by     = NULL,
		    locked_at     = NULL,
		    status        = CASE
		        WHEN attempts >= max_attempts THEN 'failed'
		        ELSE 'queued'
		    END,
		    next_run_at   = CASE
		        WHEN attempts >= max_attempts THEN NULL
		        ELSE NOW() + (POWER(2, attempts) * INTERVAL '10 seconds')
		    END
		WHERE job_id = $2
	`, errMsg, jobID)
	if err != nil {
		return fmt.Errorf("mark resolver job failed: %w", err)
	}
	return nil
}

func (r *resolverJobRepository) ReleaseStaleLocks(
	ctx context.Context, staleThreshold time.Duration,
) (int64, error) {
	seconds := int64(staleThreshold.Seconds())
	res, err := r.client.Exec(ctx, `
		UPDATE leave.resolver_job
		SET status    = CASE
		        WHEN attempts >= max_attempts THEN 'failed'
		        ELSE 'queued'
		    END,
		    locked_by = NULL,
		    locked_at = NULL,
		    next_run_at = NOW()
		WHERE status = 'processing'
		  AND locked_at IS NOT NULL
		  AND locked_at < NOW() - ($1 * INTERVAL '1 second')
	`, seconds)
	if err != nil {
		return 0, fmt.Errorf("release stale resolver locks: %w", err)
	}
	return res.RowsAffected()
}