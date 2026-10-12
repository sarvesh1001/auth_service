// internal/hr/worker/hr_lifecycle_worker.go
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/models/employee"
	hrrepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/workerpool"
)

// HRLifecycleWorker drains hr.scheduled_job.
//
// What runs here:
//   - probation_reminder         → dispatch notification (no status change)
//   - probation_end_reached      → dispatch notification (no status change)
//   - notice_reminder            → dispatch notification (no status change)
//   - on_hold_reminder           → dispatch notification (no status change)
//   - on_hold_expiry             → restore employee_profiles.employment_status
//   - leave.accrual.monthly      → post this month's leave accruals for the company
//
// What does NOT run here:
//   - notice → terminated — handled by the nightly
//     enforce_scheduled_employee_exits DB function + the
//     trg_close_notice_on_exit trigger.
//   - probation confirm/fail — that's an HR decision, never automatic.
//
// Concurrency model:
//
//	Uses workerpool — N concurrent workers, one job at a time each, single
//	sweeper for stale locks. Previously this was a single ticker-driven
//	serial loop, which meant 500 companies queued on the 1st of the month
//	were drained one at a time. The pool drains them 5-at-a-time on one
//	replica, and N replicas cooperate via FOR UPDATE SKIP LOCKED without
//	any coordination.
type HRLifecycleWorker struct {
	repo            hrrepo.ScheduledJobRepository
	notifier        LifecycleNotifier      // pluggable; nil = log-only
	accrual         AccrualRunner          // pluggable; nil = accrual jobs fail fast
	failureNotifier AccrualFailureNotifier // pluggable; nil = silent failure
	logger          *zap.Logger
	pool            *workerpool.Pool[employee.ScheduledJob]
}

// LifecycleNotifier is the seam between the worker and the reminder service.
// Called once per reminder-type job. The concrete implementation lives in
// lifecycle_notifier_impl.go and dispatches into ReminderService.
type LifecycleNotifier interface {
	Notify(ctx context.Context, job *employee.ScheduledJob) error
}

// AccrualRunner is the minimal surface the worker needs from the leave
// accrual service. Defining it here (instead of importing the concrete
// *hrservice.LeaveAccrualService) keeps the worker free of an import on
// the leave service package and makes the dependency graph acyclic.
//
// The signature matches hrservice.LeaveAccrualService.AccrueMonthlyLeave
// exactly, so a concrete *LeaveAccrualService satisfies this interface
// without any adapter.
type AccrualRunner interface {
	AccrueMonthlyLeave(
		ctx context.Context,
		companyID uuid.UUID,
		accrualDate time.Time,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) (int, error)
}

// AccrualFailureNotifier fires when an accrual job exhausts its retries
// and lands in terminal failure. Concrete implementation lives on
// hrservice.ReminderService; the narrow interface keeps the worker free of
// an import on the service package.
type AccrualFailureNotifier interface {
	NotifyAccrualFailure(
		ctx context.Context,
		companyID, jobID uuid.UUID,
		accrualDate time.Time,
		errMsg string,
	) error
}

func NewHRLifecycleWorker(
	repo hrrepo.ScheduledJobRepository,
	notifier LifecycleNotifier,
	accrual AccrualRunner,
	failureNotifier AccrualFailureNotifier, // may be nil
	logger *zap.Logger,
	idleInterval time.Duration,
) *HRLifecycleWorker {
	if idleInterval <= 0 {
		idleInterval = 10 * time.Second
	}
	if logger == nil {
		logger = zap.L()
	}

	w := &HRLifecycleWorker{
		repo:            repo,
		notifier:        notifier,
		accrual:         accrual,
		failureNotifier: failureNotifier,
		logger:          logger.Named("hr_lifecycle_worker"),
	}

	w.pool = workerpool.New(workerpool.Config[employee.ScheduledJob]{
		Workers:            5,
		IdleInterval:       idleInterval,
		StaleSweepInterval: 5 * time.Minute,
		StaleThreshold:     5 * time.Minute,
		WorkerIDPrefix:     "hr-lifecycle",
		Claim:              repo.FetchNextRunnableJob,
		Run:                w.runJob,
		ReleaseStale:       repo.ReleaseStaleLocks,
		OnJobClaimed: func(job *employee.ScheduledJob) {
			HRLifecycleQueueDepth.WithLabelValues("in_flight").Inc()
		},
		OnJobFinished: func(job *employee.ScheduledJob, err error, d time.Duration) {
			HRLifecycleQueueDepth.WithLabelValues("in_flight").Dec()
			HRLifecycleJobDuration.WithLabelValues(job.JobType).Observe(d.Seconds())
			if err != nil {
				HRLifecycleJobsFailed.WithLabelValues(job.JobType).Inc()
			} else {
				HRLifecycleJobsCompleted.WithLabelValues(job.JobType).Inc()
			}
		},
		OnStaleSweep: func(released int64) {
			if released > 0 {
				HRLifecycleStaleLocksReleased.Add(float64(released))
			}
		},
		Logger: logger,
	})
	return w
}

// Start launches the pool and the periodic snapshot loop. Blocks until
// ctx is cancelled. Call from a goroutine.
func (w *HRLifecycleWorker) Start(ctx context.Context) {
	w.logger.Info("hr lifecycle worker pool started",
		zap.Int("workers", 5),
		zap.Bool("accrual_wired", w.accrual != nil),
		zap.Bool("failure_notifier_wired", w.failureNotifier != nil),
	)

	go w.startSnapshotLoop(ctx)
	w.pool.Start(ctx)
}

// startSnapshotLoop publishes queue depth gauges every 60 seconds.
// The in_flight series is maintained by the pool's OnJobClaimed/OnJobFinished
// hooks and is NOT touched here.
func (w *HRLifecycleWorker) startSnapshotLoop(ctx context.Context) {
	log := w.logger.Named("snapshot")

	tick := func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if n, err := w.repo.CountQueued(cctx); err == nil {
			HRLifecycleQueueDepth.WithLabelValues("queued").Set(float64(n))
		} else {
			log.Warn("count queued failed", zap.Error(err))
		}

		if n, err := w.repo.CountStuck(cctx, 30*time.Minute); err == nil {
			HRLifecycleQueueDepth.WithLabelValues("processing_stuck").Set(float64(n))
		} else {
			log.Warn("count stuck failed", zap.Error(err))
		}

		if n, err := w.repo.CountFailed(cctx, nil); err == nil {
			HRLifecycleQueueDepth.WithLabelValues("failed").Set(float64(n))
		} else {
			log.Warn("count failed failed", zap.Error(err))
		}
	}

	tick() // immediate first sample
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// runJob dispatches on job_type. Returns error so the pool records the
// outcome in metrics; the status flip (MarkCompleted/MarkFailed) still
// happens here.
func (w *HRLifecycleWorker) runJob(ctx context.Context, job *employee.ScheduledJob) error {
	log := w.logger.With(
		zap.String("job_id", job.JobID.String()),
		zap.String("job_type", job.JobType),
		zap.String("company_id", job.CompanyID.String()),
		zap.Int("attempts", job.Attempts),
	)

	var err error
	switch job.JobType {
	case employee.JobProbationReminder,
		employee.JobProbationEndReached,
		employee.JobNoticeReminder,
		employee.JobOnHoldReminder:
		err = w.dispatchLifecycleNotification(ctx, job)

	case employee.JobOnHoldExpiry:
		err = w.repo.ApplyOnHoldExpiry(ctx, job.JobID)

	case employee.JobNoticeExpiry:
		// Reserved. The daily enforcer handles notice → terminated by
		// scanning employee_exit directly, not via the job queue. If this
		// ever fires, complete it cleanly.
		err = nil

	case employee.JobLeaveAccrualMonthly:
		err = w.handleMonthlyAccrual(ctx, job)

	default:
		err = errors.New("unknown job_type: " + job.JobType)
	}

	if err != nil {
		log.Warn("hr job failed", zap.Error(err))
		if mErr := w.repo.MarkFailed(ctx, job.JobID, err.Error()); mErr != nil {
			log.Error("mark failed also failed", zap.Error(mErr))
		}

		// Fire accrual failure notification only when the job has truly
		// exhausted retries. Transient failures flip back to 'queued' and
		// get retried — notifying on every attempt would spam HR with
		// duplicates for a passing DB blip.
		w.maybeNotifyAccrualFailure(ctx, job, err)

		return err
	}

	if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
		log.Error("mark completed failed", zap.Error(mErr))
		return mErr
	}
	log.Info("hr job completed")
	return nil
}

// maybeNotifyAccrualFailure fires the failure notification only for
// accrual jobs whose attempts have reached max_attempts. Non-accrual jobs
// and jobs with retries remaining are silently skipped.
func (w *HRLifecycleWorker) maybeNotifyAccrualFailure(
	ctx context.Context,
	job *employee.ScheduledJob,
	jobErr error,
) {
	if w.failureNotifier == nil {
		return
	}
	if job.JobType != employee.JobLeaveAccrualMonthly {
		return
	}
	// The claim already incremented attempts. A job at max_attempts has
	// no retries left — MarkFailed just moved it to terminal 'failed'.
	if job.Attempts < job.MaxAttempts {
		return
	}

	accrualDate, _ := parseAccrualDate(job.Payload)
	if accrualDate.IsZero() {
		now := time.Now().UTC()
		accrualDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}

	if nErr := w.failureNotifier.NotifyAccrualFailure(
		ctx, job.CompanyID, job.JobID, accrualDate, jobErr.Error(),
	); nErr != nil {
		w.logger.Warn("notify accrual failure failed",
			zap.String("job_id", job.JobID.String()),
			zap.Error(nErr),
		)
	} else {
		w.logger.Info("accrual failure notification dispatched",
			zap.String("job_id", job.JobID.String()),
			zap.String("company_id", job.CompanyID.String()),
		)
	}
}

func (w *HRLifecycleWorker) dispatchLifecycleNotification(ctx context.Context, job *employee.ScheduledJob) error {
	if w.notifier == nil {
		// No notifier wired — complete cleanly. Do NOT retry; the run_at
		// window would just loop forever.
		return nil
	}
	return w.notifier.Notify(ctx, job)
}

// ============================================================================
// leave.accrual.monthly
// ============================================================================
//
// Payload shape (written by scheduledJobRepository.EnqueueMonthlyAccrual):
//
//	{ "accrual_date": "2026-10-01" }
//
// The date is the FIRST day of the month the accrual is being posted for.
// Falls back to "today" when the payload is absent or malformed so a bad
// payload doesn't silently skip a company-wide accrual — worse to accrue
// against the wrong anchor day than to accrue nothing at all.
//
// Uses the workerID as actorType="system" (uuid.Nil) so the audit trail
// distinguishes worker-driven accruals from HR-triggered ones.
func (w *HRLifecycleWorker) handleMonthlyAccrual(
	ctx context.Context,
	job *employee.ScheduledJob,
) error {
	if w.accrual == nil {
		return errors.New("accrual service not configured")
	}

	accrualDate, err := parseAccrualDate(job.Payload)
	if err != nil {
		// Malformed payload — log and fall back to today so the run
		// still happens. This is the "safer default" for accruals:
		// a wrong-anchor run is trivially correctable (the ledger is
		// idempotent per (entitlement, day)); a skipped run is not.
		w.logger.Warn("accrual payload unparseable; defaulting to today",
			zap.String("job_id", job.JobID.String()),
			zap.ByteString("payload", job.Payload),
			zap.Error(err),
		)
		now := time.Now().UTC()
		accrualDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}

	log := w.logger.With(
		zap.String("job_id", job.JobID.String()),
		zap.String("company_id", job.CompanyID.String()),
		zap.Time("accrual_date", accrualDate),
	)
	log.Info("monthly accrual — processing")

	started := time.Now()
	processed, err := w.accrual.AccrueMonthlyLeave(
		ctx,
		job.CompanyID,
		accrualDate,
		"system", // actorType — worker-driven
		uuid.Nil, // actorID — no human actor
		nil,      // metadata — carried by the audit trail in the service
	)
	elapsed := time.Since(started)

	if err != nil {
		log.Error("monthly accrual — failed",
			zap.Duration("elapsed", elapsed),
			zap.Error(err),
		)
		return fmt.Errorf("accrue monthly leave: %w", err)
	}

	log.Info("monthly accrual — done",
		zap.Int("processed", processed),
		zap.Duration("elapsed", elapsed),
	)
	return nil
}

// parseAccrualDate extracts the accrual_date from a job payload. Accepts
// YYYY-MM-DD and full RFC3339. Returns an error when the payload is
// missing, not JSON, or has an empty/unparseable date — the caller decides
// whether to fall back or fail.
func parseAccrualDate(payload []byte) (time.Time, error) {
	if len(payload) == 0 {
		return time.Time{}, errors.New("empty payload")
	}
	var p struct {
		AccrualDate string `json:"accrual_date"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return time.Time{}, fmt.Errorf("unmarshal payload: %w", err)
	}
	if p.AccrualDate == "" {
		return time.Time{}, errors.New("accrual_date missing from payload")
	}
	if t, err := time.Parse("2006-01-02", p.AccrualDate); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, p.AccrualDate); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unparseable accrual_date: %q", p.AccrualDate)
}
