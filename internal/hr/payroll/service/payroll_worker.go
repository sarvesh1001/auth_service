package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
)

// systemActor is a reserved UUID for system‑initiated background jobs.
// Use a real system user ID from your database if one exists.
var systemActor = uuid.MustParse("11111111-1111-1111-1111-111111111111")

// isRetryableError returns true if the error is a transient network or DB failure.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "bad connection") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadlock")
}

// ============================================================================
// Payroll Worker
// ============================================================================

type PayrollWorker struct {
	jobRepo                 repository.PayrollJobRepository
	engine                  PayrollEngineService
	logger                  *zap.Logger
	workerID                string
	pollDelay               time.Duration
	maxConcurrentPerCompany int
}

// NewPayrollWorker creates a new background payroll worker.
func NewPayrollWorker(
	jobRepo repository.PayrollJobRepository,
	engine PayrollEngineService,
	logger *zap.Logger,
	workerID string,
	maxConcurrentPerCompany int,
) *PayrollWorker {
	return &PayrollWorker{
		jobRepo:                 jobRepo,
		engine:                  engine,
		logger:                  logger,
		workerID:                workerID,
		pollDelay:               5 * time.Second,
		maxConcurrentPerCompany: maxConcurrentPerCompany,
	}
}

// ============================================================================
// Start Worker Loop
// ============================================================================

func (w *PayrollWorker) Start(ctx context.Context) {
	w.logger.Info("Payroll worker started",
		zap.String("worker_id", w.workerID),
		zap.Int("max_concurrent_per_company", w.maxConcurrentPerCompany),
	)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Payroll worker shutting down",
				zap.String("worker_id", w.workerID),
			)
			return
		default:
			w.runIteration(ctx)
		}
	}
}

// ============================================================================
// Single Iteration – processes employee jobs first, then run‑level jobs
// ============================================================================

func (w *PayrollWorker) runIteration(ctx context.Context) {
	// 1️⃣ Recover stale locks for both job types
	_, err := w.jobRepo.ReleaseStaleLocks(ctx, 15*time.Minute)
	if err != nil {
		w.logger.Error("Failed releasing stale payroll job locks",
			zap.String("worker_id", w.workerID),
			zap.Error(err),
		)
	}
	_, err = w.jobRepo.ReleaseStaleEmployeeJobLocks(ctx, 15*time.Minute)
	if err != nil {
		w.logger.Error("Failed releasing stale employee job locks",
			zap.String("worker_id", w.workerID),
			zap.Error(err),
		)
	}

	// 2️⃣ Try to fetch an employee job first (higher priority)
	empJob, err := w.jobRepo.FetchNextEmployeeJob(ctx, w.workerID)
	if err != nil {
		w.logger.Error("Failed fetching employee job",
			zap.String("worker_id", w.workerID),
			zap.Error(err),
		)
		return
	}
	if empJob != nil {
		w.processEmployeeJob(ctx, empJob)
		return
	}

	// 3️⃣ If no employee jobs, fetch a run‑level job
	job, err := w.jobRepo.FetchNextRunnableJob(
		ctx,
		w.workerID,
		w.maxConcurrentPerCompany,
	)
	if err != nil {
		w.logger.Error("Failed fetching payroll job",
			zap.String("worker_id", w.workerID),
			zap.Error(err),
		)
		return
	}

	if job == nil {
		// No work → sleep
		time.Sleep(w.pollDelay)
		return
	}

	w.processJob(ctx, job)
}

// ============================================================================
// Process a run‑level job
// ============================================================================

func (w *PayrollWorker) processJob(ctx context.Context, job *models.PayrollJob) {
	// Panic recovery – worker never dies
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Payroll job panicked",
				zap.String("worker_id", w.workerID),
				zap.String("job_id", job.JobID.String()),
				zap.Any("panic", r),
			)
			_ = w.jobRepo.MarkFailed(ctx, job.JobID, fmt.Sprintf("panic: %v", r))
		}
	}()

	// Check if the run has already reached a terminal state
	status, err := w.engine.GetRunExecutionStatus(ctx, job.PayrollRunID)
	if err == nil && status != nil {
		if status.Status == "approved" || status.Status == "paid" {
			w.logger.Info("Payroll run locked, skipping job",
				zap.String("worker_id", w.workerID),
				zap.String("job_id", job.JobID.String()),
				zap.String("run_id", job.PayrollRunID.String()),
				zap.String("run_status", status.Status),
			)

			_ = w.jobRepo.MarkCompleted(ctx, job.JobID)
			return
		}
	} else if err != nil {
		w.logger.Warn("Could not fetch run status, proceeding with execution",
			zap.String("run_id", job.PayrollRunID.String()),
			zap.Error(err),
		)
	}

	w.logger.Info("Processing payroll job",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
		zap.Int("attempt", job.Attempts+1),
	)

	start := time.Now()

	// Job‑level timeout (30 minutes)
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	w.logger.Info("Starting ExecuteRun",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
	)

	// Use system actor for background execution
	err = w.engine.ExecuteRun(jobCtx, job.PayrollRunID, systemActor)

	w.logger.Info("ExecuteRun finished",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
		zap.Error(err),
	)

	// Ignore context.Canceled – it's a normal signal after successful processing
	if err != nil && err != context.Canceled {
		w.logger.Error("Payroll job execution failed",
			zap.String("worker_id", w.workerID),
			zap.String("job_id", job.JobID.String()),
			zap.String("run_id", job.PayrollRunID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)

		if markErr := w.jobRepo.MarkFailed(ctx, job.JobID, err.Error()); markErr != nil {
			w.logger.Error("Failed marking payroll job as failed",
				zap.String("job_id", job.JobID.String()),
				zap.Error(markErr),
			)
		}
		return
	}

	// Mark completed (even if we got context.Canceled – it means work finished)
	if err := w.jobRepo.MarkCompleted(ctx, job.JobID); err != nil {
		w.logger.Error("Failed marking payroll job as completed",
			zap.String("job_id", job.JobID.String()),
			zap.Error(err),
		)
		return
	}

	w.logger.Info("Payroll job completed successfully",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
		zap.Duration("duration", time.Since(start)),
	)
}

// ============================================================================
// Process an employee‑level job with run finalization check
// ============================================================================

func (w *PayrollWorker) processEmployeeJob(
	ctx context.Context,
	job *models.PayrollEmployeeJob,
) {
	// Panic recovery – worker never dies
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Employee payroll job panicked",
				zap.String("worker_id", w.workerID),
				zap.String("job_id", job.JobID.String()),
				zap.Any("panic", r),
			)
			_ = w.jobRepo.MarkEmployeeJobFailed(ctx, job.JobID, fmt.Sprintf("panic: %v", r))
		}
	}()

	w.logger.Info("Processing employee payroll job",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
		zap.String("user_id", job.UserID.String()),
	)

	start := time.Now()

	// Execute employee processing (components & settings are nil → engine uses empty defaults)
	err := w.engine.ProcessEmployee(
		ctx,
		job.PayrollRunID,
		job.UserID,
		systemActor, // ✅ FIXED: use systemActor instead of uuid.Nil
		false,       // reflectLatestAdjustments = false (use snapshot)
		nil,         // components = nil → engine falls back to empty map
		nil,         // settings = nil → engine falls back to empty defaults
	)

	if err != nil {

		// Retry transient DB/network failures
		if isRetryableError(err) && job.Attempts < 3 {
			w.logger.Warn("Retryable error, re-queueing employee job",
				zap.String("job_id", job.JobID.String()),
				zap.Int("attempt", job.Attempts),
				zap.Error(err),
			)

			if requeueErr := w.jobRepo.RequeueEmployeeJob(ctx, job.JobID); requeueErr != nil {
				w.logger.Error("Failed to requeue employee job",
					zap.String("job_id", job.JobID.String()),
					zap.Error(requeueErr),
				)
			}

			return
		}

		w.logger.Error("Employee payroll job failed",
			zap.String("worker_id", w.workerID),
			zap.String("job_id", job.JobID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)

		if markErr := w.jobRepo.MarkEmployeeJobFailed(ctx, job.JobID, err.Error()); markErr != nil {
			w.logger.Error("Failed marking employee job as failed",
				zap.String("job_id", job.JobID.String()),
				zap.Error(markErr),
			)
		}
		return
	}

	// Mark completed
	if err := w.jobRepo.MarkEmployeeJobCompleted(ctx, job.JobID); err != nil {
		w.logger.Error("Failed marking employee job as completed",
			zap.String("job_id", job.JobID.String()),
			zap.Error(err),
		)
		return
	}

	w.logger.Info("Employee payroll job completed successfully",
		zap.String("worker_id", w.workerID),
		zap.String("job_id", job.JobID.String()),
		zap.String("run_id", job.PayrollRunID.String()),
		zap.String("user_id", job.UserID.String()),
		zap.Duration("duration", time.Since(start)),
	)

	// 🔥 Check if this was the last employee job – if yes, finalize the run
	remaining, err := w.engine.CountRemainingEmployeeJobs(ctx, job.PayrollRunID)
	if err != nil {
		w.logger.Error("Failed to count remaining employee jobs after completion",
			zap.String("run_id", job.PayrollRunID.String()),
			zap.Error(err),
		)
		return
	}

	if remaining == 0 {
		w.logger.Info("All employee jobs completed – finalizing payroll run",
			zap.String("run_id", job.PayrollRunID.String()),
		)

		if err := w.engine.FinalizeRun(ctx, job.PayrollRunID, systemActor); err != nil {
			w.logger.Error("Failed finalizing payroll run",
				zap.String("run_id", job.PayrollRunID.String()),
				zap.Error(err),
			)
		}
	}
}

// ============================================================================
// Bootstrap Helper
// ============================================================================

func StartPayrollWorkers(
	ctx context.Context,
	jobRepo repository.PayrollJobRepository,
	engine PayrollEngineService,
	logger *zap.Logger,
	workerCount int,
	maxConcurrentPerCompany int,
) {
	if workerCount <= 0 {
		workerCount = 1
	}
	if maxConcurrentPerCompany <= 0 {
		maxConcurrentPerCompany = 2
	}

	logger.Info("Starting payroll workers",
		zap.Int("worker_count", workerCount),
		zap.Int("max_concurrent_per_company", maxConcurrentPerCompany),
	)

	for i := 1; i <= workerCount; i++ {
		workerID := fmt.Sprintf("payroll-worker-%d", i)

		worker := NewPayrollWorker(
			jobRepo,
			engine,
			logger,
			workerID,
			maxConcurrentPerCompany,
		)

		go worker.Start(ctx)
	}
}
