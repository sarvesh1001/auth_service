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
type HRLifecycleWorker struct {
	repo           hrrepo.ScheduledJobRepository
	notifier       LifecycleNotifier // pluggable; nil = log-only
	accrual        AccrualRunner     // pluggable; nil = accrual jobs fail fast
	logger         *zap.Logger
	workerID       string
	interval       time.Duration
	batch          int
	staleThreshold time.Duration
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

func NewHRLifecycleWorker(
	repo hrrepo.ScheduledJobRepository,
	notifier LifecycleNotifier,
	accrual AccrualRunner, // 👈 new — pass *hrservice.LeaveAccrualService here
	logger *zap.Logger,
	interval time.Duration,
) *HRLifecycleWorker {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if logger == nil {
		logger = zap.L()
	}
	return &HRLifecycleWorker{
		repo:           repo,
		notifier:       notifier,
		accrual:        accrual,
		logger:         logger.Named("hr_lifecycle_worker"),
		workerID:       "hr-lifecycle-1",
		interval:       interval,
		batch:          50,
		staleThreshold: 5 * time.Minute,
	}
}

func (w *HRLifecycleWorker) Start(ctx context.Context) {
	w.logger.Info("hr lifecycle worker started",
		zap.Duration("interval", w.interval),
		zap.String("worker_id", w.workerID),
		zap.Bool("accrual_wired", w.accrual != nil),
	)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("hr lifecycle worker stopping")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *HRLifecycleWorker) tick(ctx context.Context) {
	if released, err := w.repo.ReleaseStaleLocks(ctx, w.staleThreshold); err != nil {
		w.logger.Warn("release stale locks failed", zap.Error(err))
	} else if released > 0 {
		w.logger.Warn("released stale hr job locks", zap.Int64("count", released))
	}

	for i := 0; i < w.batch; i++ {
		job, err := w.repo.FetchNextRunnableJob(ctx, w.workerID)
		if err != nil {
			w.logger.Error("fetch next hr job failed", zap.Error(err))
			return
		}
		if job == nil {
			return
		}
		w.runJob(ctx, job)
	}
}

func (w *HRLifecycleWorker) runJob(ctx context.Context, job *employee.ScheduledJob) {
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
		err = w.notify(ctx, job)

	case employee.JobOnHoldExpiry:
		err = w.repo.ApplyOnHoldExpiry(ctx, job.JobID)

	case employee.JobNoticeExpiry:
		// Reserved. The daily enforcer handles notice → terminated by
		// scanning employee_exit directly, not via the job queue. If this
		// ever fires, complete it cleanly.
		err = nil

	case employee.JobLeaveAccrualMonthly: // 👈 NEW
		err = w.handleMonthlyAccrual(ctx, job)

	default:
		err = errors.New("unknown job_type: " + job.JobType)
	}

	if err != nil {
		log.Warn("hr job failed", zap.Error(err))
		if mErr := w.repo.MarkFailed(ctx, job.JobID, err.Error()); mErr != nil {
			log.Error("mark failed also failed", zap.Error(mErr))
		}
		return
	}

	if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
		log.Error("mark completed failed", zap.Error(mErr))
		return
	}
	log.Info("hr job completed")
}

func (w *HRLifecycleWorker) notify(ctx context.Context, job *employee.ScheduledJob) error {
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
