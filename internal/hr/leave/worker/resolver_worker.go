package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/leave/models"
	leaverepo "auth-service/internal/hr/leave/repository"
	leavesvc "auth-service/internal/hr/leave/service"
	"auth-service/internal/infrastructure/workerpool"
)

// ResolverWorker wraps workerpool.Pool for the leave entitlement resolver
// queue. Same concurrency model as the schedule worker: N workers, one job
// at a time each, single sweeper for stale locks.
type ResolverWorker struct {
	repo   leaverepo.ResolverJobRepository
	svc    leavesvc.LeavePolicyResolutionService
	logger *zap.Logger
	pool   *workerpool.Pool[models.ResolverJob]
}

func NewResolverWorker(
	repo leaverepo.ResolverJobRepository,
	svc leavesvc.LeavePolicyResolutionService,
	logger *zap.Logger,
	idleInterval time.Duration,
) *ResolverWorker {
	w := &ResolverWorker{
		repo:   repo,
		svc:    svc,
		logger: logger.Named("leave_resolver_worker"),
	}

	w.pool = workerpool.New(workerpool.Config[models.ResolverJob]{
		Workers:            5,
		IdleInterval:       idleInterval,
		StaleSweepInterval: 5 * time.Minute,
		StaleThreshold:     5 * time.Minute,
		WorkerIDPrefix:     "leave-resolver",
		Claim:              repo.FetchNextRunnableJob,
		Run:                w.runJob,
		ReleaseStale:       repo.ReleaseStaleLocks,
		OnJobClaimed: func(job *models.ResolverJob) {
			QueueDepth.WithLabelValues("in_flight").Inc()
		},
		OnJobFinished: func(job *models.ResolverJob, err error, d time.Duration) {
			QueueDepth.WithLabelValues("in_flight").Dec()
			JobDuration.WithLabelValues(job.JobType).Observe(d.Seconds())
			if err != nil {
				JobsFailed.WithLabelValues(job.JobType).Inc()
			} else {
				JobsCompleted.WithLabelValues(job.JobType).Inc()
			}
		},
		OnStaleSweep: func(released int64) {
			if released > 0 {
				StaleLocksReleased.Add(float64(released))
			}
		},
		Logger: logger,
	})
	return w
}

// Start launches the pool and the periodic snapshot loop.
func (w *ResolverWorker) Start(ctx context.Context) {
	go w.startSnapshotLoop(ctx)
	w.pool.Start(ctx)
}

// startSnapshotLoop publishes queue depth gauges every 60 seconds so the
// Prometheus alerts (LeaveResolverQueueDepthHigh, LeaveResolverFailures)
// have data.
func (w *ResolverWorker) startSnapshotLoop(ctx context.Context) {
	log := w.logger.Named("snapshot")

	tick := func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if n, err := w.repo.CountQueued(cctx); err == nil {
			QueueDepth.WithLabelValues("queued").Set(float64(n))
		} else {
			log.Warn("count queued failed", zap.Error(err))
		}

		if n, err := w.repo.CountStuck(cctx, 30*time.Minute); err == nil {
			QueueDepth.WithLabelValues("processing_stuck").Set(float64(n))
		} else {
			log.Warn("count stuck failed", zap.Error(err))
		}

		if n, err := w.repo.CountFailed(cctx, nil); err == nil {
			QueueDepth.WithLabelValues("failed").Set(float64(n))
		} else {
			log.Warn("count failed failed", zap.Error(err))
		}
	}

	tick()
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

// runJob dispatches on job_type. Returns error so the pool can record the
// outcome in metrics; the status flip (MarkCompleted/MarkFailed) still
// happens here.
func (w *ResolverWorker) runJob(ctx context.Context, job *models.ResolverJob) error {
	log := w.logger.With(
		zap.String("job_id", job.JobID.String()),
		zap.String("job_type", job.JobType),
		zap.String("company_id", job.CompanyID.String()),
		zap.Int("attempts", job.Attempts),
	)

	var err error
	switch job.JobType {
	case models.ResolverJobTypeResolveUser:
		err = w.resolveUser(ctx, job)
	case models.ResolverJobTypeResolveCompany:
		err = w.resolveCompany(ctx, job)
	case models.ResolverJobTypeResolvePosition:
		err = w.resolvePosition(ctx, job)
	case models.ResolverJobTypeEndEntitlements:
		err = w.endEntitlements(ctx, job)
	default:
		err = errors.New("unknown job_type: " + job.JobType)
	}

	if errors.Is(err, leavesvc.ErrNoMatchingPolicy) {
		log.Info("resolver job skipped — no matching policy for user")
		if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
			log.Error("mark completed failed", zap.Error(mErr))
		}
		return nil
	}

	if err != nil {
		log.Warn("resolver job failed", zap.Error(err))
		if mErr := w.repo.MarkFailed(ctx, job.JobID, err.Error()); mErr != nil {
			log.Error("mark failed also failed", zap.Error(mErr))
		}
		return err
	}

	if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
		log.Error("mark completed failed", zap.Error(mErr))
		return mErr
	}
	log.Info("resolver job completed")
	return nil
}

// ---------- per-type handlers (unchanged) ----------

func (w *ResolverWorker) resolveUser(ctx context.Context, job *models.ResolverJob) error {
	if job.UserID == nil {
		return errors.New("resolve_user job missing user_id")
	}
	reason := derefString(job.Reason, "system")
	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())
	return w.svc.ResolveUserLeaveEntitlements(
		jobCtx, job.CompanyID, *job.UserID,
		time.Now().UTC(), reason, "system", uuid.Nil,
		map[string]interface{}{"source": "resolver_worker", "job_id": job.JobID.String()},
	)
}

func (w *ResolverWorker) resolveCompany(ctx context.Context, job *models.ResolverJob) error {
	userIDs, err := w.svc.ListActiveEmployeeUserIDs(ctx, job.CompanyID)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return nil
	}
	reason := derefString(job.Reason, "policy change")
	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())

	const chunk = 100
	for i := 0; i < len(userIDs); i += chunk {
		end := i + chunk
		if end > len(userIDs) {
			end = len(userIDs)
		}
		if _, err := w.svc.ResolveBatchLeaveEntitlements(
			jobCtx, job.CompanyID, userIDs[i:end],
			time.Now().UTC(), reason, "system", uuid.Nil,
			map[string]interface{}{"source": "resolver_worker", "job_id": job.JobID.String()},
		); err != nil {
			return err
		}
	}
	return nil
}

func (w *ResolverWorker) resolvePosition(ctx context.Context, job *models.ResolverJob) error {
	if job.PositionID == nil {
		return errors.New("resolve_position job missing position_id")
	}
	userIDs, err := w.svc.ListActiveEmployeeUserIDsByPosition(ctx, job.CompanyID, *job.PositionID)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return nil
	}

	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())
	const chunk = 100
	for i := 0; i < len(userIDs); i += chunk {
		end := i + chunk
		if end > len(userIDs) {
			end = len(userIDs)
		}
		if _, err := w.svc.ResolveBatchLeaveEntitlements(
			jobCtx, job.CompanyID, userIDs[i:end],
			time.Now().UTC(), "position work_center change", "system", uuid.Nil,
			map[string]interface{}{
				"source": "resolver_worker",
				"job_id": job.JobID.String(),
				"chunk":  fmt.Sprintf("%d-%d", i, end),
			},
		); err != nil {
			return err
		}
	}
	return nil
}

func (w *ResolverWorker) endEntitlements(ctx context.Context, job *models.ResolverJob) error {
	if job.UserID == nil {
		return errors.New("end_entitlements job missing user_id")
	}
	return w.svc.EndActivePolicyEntitlements(ctx, job.CompanyID, *job.UserID, time.Now().UTC())
}

func derefString(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}
