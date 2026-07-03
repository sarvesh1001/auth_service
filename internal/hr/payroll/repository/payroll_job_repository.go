package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// ============================================================================
// PayrollJobRepository Interface
// ============================================================================

type PayrollJobRepository interface {
	Create(ctx context.Context, input *models.CreatePayrollJobInput) (*models.PayrollJob, error)
	FetchNextRunnableJob(ctx context.Context, workerID string, maxConcurrentPerCompany int) (*models.PayrollJob, error)
	MarkCompleted(ctx context.Context, jobID uuid.UUID) error
	MarkFailed(ctx context.Context, jobID uuid.UUID, errorMessage string) error
	GetByID(ctx context.Context, jobID uuid.UUID) (*models.PayrollJob, error)
	ReleaseStaleLocks(ctx context.Context, staleThreshold time.Duration) (int64, error)
	CancelEmployeeJobsForRunTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID) error

	// Employee Job Queue
	CreateEmployeeJobsForRun(
		ctx context.Context,
		runID uuid.UUID,
		userIDs []uuid.UUID,
	) error

	FetchNextEmployeeJob(
		ctx context.Context,
		workerID string,
	) (*models.PayrollEmployeeJob, error)

	MarkEmployeeJobCompleted(
		ctx context.Context,
		jobID uuid.UUID,
	) error

	MarkEmployeeJobFailed(
		ctx context.Context,
		jobID uuid.UUID,
		errMsg string,
	) error

	ReleaseStaleEmployeeJobLocks(
		ctx context.Context,
		staleThreshold time.Duration,
	) (int64, error)

	// RequeueEmployeeJob resets a failed employee job to pending for retry.
	RequeueEmployeeJob(
		ctx context.Context,
		jobID uuid.UUID,
	) error
}

// ============================================================================
// Postgres Implementation
// ============================================================================

type payrollJobRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewPayrollJobRepository(pg *client.PostgresClient, logger *zap.Logger) PayrollJobRepository {
	return &payrollJobRepository{
		client: pg,
		logger: logger,
	}
}

// ============================================================================
// Create Job
// ============================================================================

func (r *payrollJobRepository) Create(ctx context.Context, input *models.CreatePayrollJobInput) (*models.PayrollJob, error) {
	// Set defaults if not provided
	if input.MaxAttempts == 0 {
		input.MaxAttempts = 3
	}
	if input.MaxRetries == 0 {
		input.MaxRetries = 5
	}
	if input.Priority == 0 {
		input.Priority = 5 // default medium priority
	}

	job := &models.PayrollJob{
		JobID:        uuid.New(),
		CompanyID:    input.CompanyID,
		PayrollRunID: input.PayrollRunID,
		Status:       models.PayrollJobStatusQueued,
		Attempts:     0,
		MaxAttempts:  input.MaxAttempts,
		RetryCount:   0,
		MaxRetries:   input.MaxRetries,
		Priority:     input.Priority,
		CreatedAt:    time.Now().UTC(),
		NextRunAt:    nil,
	}

	query := `
		INSERT INTO payroll.payroll_job (
			job_id, company_id, payroll_run_id, status,
			attempts, max_attempts,
			retry_count, max_retries,
			priority, created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`

	_, err := r.client.Exec(ctx, query,
		job.JobID, job.CompanyID, job.PayrollRunID, job.Status,
		job.Attempts, job.MaxAttempts,
		job.RetryCount, job.MaxRetries,
		job.Priority, job.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create payroll job",
			util.String("job_id", job.JobID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to create payroll job: %w", err)
	}

	return job, nil
}

// ============================================================================
// Fetch Next Runnable Job (with company concurrency, priority, backoff)
// ============================================================================

func (r *payrollJobRepository) FetchNextRunnableJob(
	ctx context.Context,
	workerID string,
	maxConcurrentPerCompany int,
) (*models.PayrollJob, error) {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
		SELECT pj.job_id, pj.company_id, pj.payroll_run_id,
		       pj.status, pj.attempts, pj.max_attempts,
		       pj.retry_count, pj.max_retries,
		       pj.priority, pj.error_message,
		       pj.created_at, pj.next_run_at
		FROM payroll.payroll_job pj
		WHERE pj.status = 'queued'
		  AND (pj.next_run_at IS NULL OR pj.next_run_at <= NOW())
		  AND pj.attempts < pj.max_attempts
		  AND pj.retry_count < pj.max_retries   -- ✅ FIXED
		  AND (
		        SELECT COUNT(*)
		        FROM payroll.payroll_job
		        WHERE company_id = pj.company_id
		          AND status = 'processing'
		      ) < $1
		ORDER BY pj.priority ASC, pj.created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`

	row := tx.QueryRowContext(ctx, query, maxConcurrentPerCompany)

	var job models.PayrollJob
	var errorMessage sql.NullString
	var nextRunAt sql.NullTime

	err = row.Scan(
		&job.JobID,
		&job.CompanyID,
		&job.PayrollRunID,
		&job.Status,
		&job.Attempts,
		&job.MaxAttempts,
		&job.RetryCount,
		&job.MaxRetries,
		&job.Priority,
		&errorMessage,
		&job.CreatedAt,
		&nextRunAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if errorMessage.Valid {
		job.ErrorMessage = &errorMessage.String
	}
	if nextRunAt.Valid {
		job.NextRunAt = &nextRunAt.Time
	}

	now := time.Now().UTC()
	updateQuery := `
		UPDATE payroll.payroll_job
		SET status = 'processing',
		    started_at = $1,
		    locked_by = $2,
		    locked_at = $1
		WHERE job_id = $3
	`
	_, err = tx.ExecContext(ctx, updateQuery, now, workerID, job.JobID)
	if err != nil {
		return nil, err
	}

	job.Status = models.PayrollJobStatusProcessing
	job.StartedAt = &now
	job.LockedBy = &workerID
	job.LockedAt = &now

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &job, nil
}

// ============================================================================
// Mark Completed
// ============================================================================

func (r *payrollJobRepository) MarkCompleted(ctx context.Context, jobID uuid.UUID) error {
	query := `
		UPDATE payroll.payroll_job
		SET status = 'completed',
		    completed_at = $1,
		    error_message = NULL
		WHERE job_id = $2
	`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), jobID)
	if err != nil {
		r.logger.Error("Failed to mark payroll job completed",
			util.String("job_id", jobID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark job completed: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("payroll job not found")
	}

	return nil
}

// ============================================================================
// Mark Failed (with exponential backoff)
// ============================================================================

func (r *payrollJobRepository) MarkFailed(ctx context.Context, jobID uuid.UUID, errorMessage string) error {
	query := `
		UPDATE payroll.payroll_job
		SET retry_count = retry_count + 1,
		    attempts = attempts + 1,
		    error_message = $1,
		    locked_by = NULL,
		    locked_at = NULL,
		    status = CASE
		        WHEN retry_count + 1 >= max_retries
		             OR attempts + 1 >= max_attempts
		        THEN 'failed'
		        ELSE 'queued'
		    END,
		    next_run_at = CASE
		        WHEN retry_count + 1 >= max_retries
		             OR attempts + 1 >= max_attempts
		        THEN NULL
		        ELSE NOW() + (POWER(2, retry_count) * INTERVAL '10 seconds')
		    END
		WHERE job_id = $2
	`

	_, err := r.client.Exec(ctx, query, errorMessage, jobID)
	if err != nil {
		r.logger.Error("Failed to mark payroll job failed",
			util.String("job_id", jobID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark job failed: %w", err)
	}

	return nil
}

// ============================================================================
// Get By ID
// ============================================================================

func (r *payrollJobRepository) GetByID(ctx context.Context, jobID uuid.UUID) (*models.PayrollJob, error) {
	query := `
		SELECT job_id, company_id, payroll_run_id, status,
		       attempts, max_attempts, retry_count, max_retries,
		       priority, error_message,
		       created_at, started_at, completed_at, next_run_at,
		       locked_by, locked_at
		FROM payroll.payroll_job
		WHERE job_id = $1
	`

	row := r.client.QueryRow(ctx, query, jobID)

	var job models.PayrollJob
	var errorMessage sql.NullString
	var startedAt, completedAt, nextRunAt, lockedAt sql.NullTime
	var lockedBy sql.NullString

	err := row.Scan(
		&job.JobID, &job.CompanyID, &job.PayrollRunID, &job.Status,
		&job.Attempts, &job.MaxAttempts, &job.RetryCount, &job.MaxRetries,
		&job.Priority, &errorMessage,
		&job.CreatedAt, &startedAt, &completedAt, &nextRunAt,
		&lockedBy, &lockedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if errorMessage.Valid {
		job.ErrorMessage = &errorMessage.String
	}
	if startedAt.Valid {
		job.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = &completedAt.Time
	}
	if nextRunAt.Valid {
		job.NextRunAt = &nextRunAt.Time
	}
	if lockedBy.Valid {
		job.LockedBy = &lockedBy.String
	}
	if lockedAt.Valid {
		job.LockedAt = &lockedAt.Time
	}

	return &job, nil
}

// ============================================================================
// Release Stale Locks (Crash Recovery)
// ============================================================================

func (r *payrollJobRepository) ReleaseStaleLocks(
	ctx context.Context,
	staleThreshold time.Duration,
) (int64, error) {

	seconds := int64(staleThreshold.Seconds())

	query := `
		UPDATE payroll.payroll_job
		SET attempts = attempts + 1,
		    status = CASE
		        WHEN attempts + 1 >= max_attempts THEN 'failed'
		        ELSE 'queued'
		    END,
		    locked_by = NULL,
		    locked_at = NULL,
		    next_run_at = CASE
		        WHEN attempts + 1 >= max_attempts THEN NULL
		        ELSE NOW()
		    END
		WHERE status = 'processing'
		  AND locked_at IS NOT NULL
		  AND locked_at < NOW() - ($1 * INTERVAL '1 second')
	`

	result, err := r.client.Exec(ctx, query, seconds)
	if err != nil {
		return 0, fmt.Errorf("failed to release stale locks: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if rows > 0 {
		r.logger.Info("Released stale payroll job locks",
			zap.Int64("count", rows),
			zap.Int64("threshold_seconds", seconds),
		)
	}

	return rows, nil
}

// ============================================================================
// Employee Job Methods
// ============================================================================

func (r *payrollJobRepository) CreateEmployeeJobsForRun(
	ctx context.Context,
	runID uuid.UUID,
	userIDs []uuid.UUID,
) error {

	if len(userIDs) == 0 {
		return nil
	}

	query := `
	INSERT INTO payroll.payroll_employee_job (
		payroll_run_id,
		user_id,
		status
	)
	SELECT $1, unnest($2::uuid[]), 'pending'
	ON CONFLICT (payroll_run_id, user_id) DO NOTHING
	`

	_, err := r.client.Exec(ctx, query, runID, pq.Array(userIDs))
	if err != nil {
		return fmt.Errorf("failed to create employee jobs: %w", err)
	}

	return nil
}

func (r *payrollJobRepository) FetchNextEmployeeJob(
	ctx context.Context,
	workerID string,
) (*models.PayrollEmployeeJob, error) {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// ✅ Modified: include failed jobs and enforce attempts < 3
	query := `
	SELECT job_id, payroll_run_id, user_id,
	       status, attempts,
	       locked_by, locked_at,
	       error, created_at, updated_at
	FROM payroll.payroll_employee_job
	WHERE status IN ('pending','failed')
	AND attempts < 3
	ORDER BY created_at
	FOR UPDATE SKIP LOCKED
	LIMIT 1
	`

	row := tx.QueryRowContext(ctx, query)

	var job models.PayrollEmployeeJob
	var lockedBy sql.NullString
	var lockedAt sql.NullTime
	var errMsg sql.NullString

	err = row.Scan(
		&job.JobID,
		&job.PayrollRunID,
		&job.UserID,
		&job.Status,
		&job.Attempts,
		&lockedBy,
		&lockedAt,
		&errMsg,
		&job.CreatedAt,
		&job.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	updateQuery := `
	UPDATE payroll.payroll_employee_job
	SET status='processing',
	    locked_by=$1,
	    locked_at=$2,
	    attempts = attempts + 1,
	    updated_at=$2
	WHERE job_id=$3
	`

	_, err = tx.ExecContext(ctx, updateQuery, workerID, now, job.JobID)
	if err != nil {
		return nil, err
	}

	job.Status = models.EmployeeJobStatusProcessing
	job.LockedBy = &workerID
	job.LockedAt = &now
	job.Attempts++

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &job, nil
}

func (r *payrollJobRepository) MarkEmployeeJobCompleted(
	ctx context.Context,
	jobID uuid.UUID,
) error {

	query := `
	UPDATE payroll.payroll_employee_job
	SET status='completed',
	    locked_by=NULL,
	    locked_at=NULL,
	    error=NULL,
	    updated_at=NOW()
	WHERE job_id=$1
	`

	_, err := r.client.Exec(ctx, query, jobID)
	if err != nil {
		return fmt.Errorf("failed to mark employee job completed: %w", err)
	}

	return nil
}

func (r *payrollJobRepository) MarkEmployeeJobFailed(
	ctx context.Context,
	jobID uuid.UUID,
	errMsg string,
) error {

	query := `
	UPDATE payroll.payroll_employee_job
	SET status='failed',
	    error=$1,
	    locked_by=NULL,
	    locked_at=NULL,
	    updated_at=NOW()
	WHERE job_id=$2
	`

	_, err := r.client.Exec(ctx, query, errMsg, jobID)
	if err != nil {
		return fmt.Errorf("failed to mark employee job failed: %w", err)
	}

	return nil
}

func (r *payrollJobRepository) ReleaseStaleEmployeeJobLocks(
	ctx context.Context,
	staleThreshold time.Duration,
) (int64, error) {

	seconds := int64(staleThreshold.Seconds())

	query := `
	UPDATE payroll.payroll_employee_job
	SET status='pending',
	    locked_by=NULL,
	    locked_at=NULL,
	    updated_at=NOW()
	WHERE status='processing'
	AND locked_at < NOW() - ($1 * INTERVAL '1 second')
	`

	result, err := r.client.Exec(ctx, query, seconds)
	if err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}

// ============================================================================
// RequeueEmployeeJob – resets a failed employee job for retry
// ============================================================================

func (r *payrollJobRepository) RequeueEmployeeJob(
	ctx context.Context,
	jobID uuid.UUID,
) error {

	query := `
	UPDATE payroll.payroll_employee_job
	SET status='pending',
	    locked_by=NULL,
	    locked_at=NULL,
	    updated_at=NOW()
	WHERE job_id=$1
	`

	_, err := r.client.Exec(ctx, query, jobID)
	if err != nil {
		return fmt.Errorf("failed to requeue employee job: %w", err)
	}

	return nil
}

// In repository/payroll_job.go
func (r *payrollJobRepository) CountIncompleteEmployeeJobs(ctx context.Context, runID uuid.UUID) (int, error) {
	const query = `
        SELECT COUNT(*)
        FROM payroll.payroll_employee_job
        WHERE payroll_run_id = $1
          AND status IN ('pending','processing')
    `
	var count int
	err := r.client.QueryRow(ctx, query, runID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count incomplete employee jobs: %w", err)
	}
	return count, nil
}
func (r *payrollJobRepository) CancelEmployeeJobsForRunTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID) error {
	query := `
        UPDATE payroll.payroll_employee_job
        SET status = 'cancelled',
            updated_at = NOW()
        WHERE payroll_run_id = $1
          AND status IN ('pending', 'processing')
    `
	result, err := tx.ExecContext(ctx, query, runID)
	if err != nil {
		return fmt.Errorf("failed to cancel employee jobs: %w", err)
	}
	rows, _ := result.RowsAffected()
	r.logger.Info("Cancelled employee jobs for run",
		zap.String("run_id", runID.String()),
		zap.Int64("rows_cancelled", rows),
	)
	return nil
}
