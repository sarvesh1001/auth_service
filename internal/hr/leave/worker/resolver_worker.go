package worker

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/leave/models"
	leaverepo "auth-service/internal/hr/leave/repository"
	leavesvc "auth-service/internal/hr/leave/service"
)

type ResolverWorker struct {
	repo           leaverepo.ResolverJobRepository
	resolver       leavesvc.LeavePolicyResolutionService
	logger         *zap.Logger
	workerID       string
	interval       time.Duration
	batch          int
	staleThreshold time.Duration
}

func NewResolverWorker(
	repo leaverepo.ResolverJobRepository,
	resolver leavesvc.LeavePolicyResolutionService,
	logger *zap.Logger,
	interval time.Duration,
) *ResolverWorker {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &ResolverWorker{
		repo:           repo,
		resolver:       resolver,
		logger:         logger.Named("leave_resolver_worker"),
		workerID:       "leave-resolver-1",
		interval:       interval,
		batch:          50,
		staleThreshold: 5 * time.Minute,
	}
}

func (w *ResolverWorker) Start(ctx context.Context) {
	w.logger.Info("resolver worker started",
		zap.Duration("interval", w.interval),
		zap.String("worker_id", w.workerID),
	)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("resolver worker stopping")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *ResolverWorker) tick(ctx context.Context) {
	if released, err := w.repo.ReleaseStaleLocks(ctx, w.staleThreshold); err != nil {
		w.logger.Warn("release stale locks failed", zap.Error(err))
	} else if released > 0 {
		w.logger.Warn("released stale resolver locks", zap.Int64("count", released))
	}

	for i := 0; i < w.batch; i++ {
		job, err := w.repo.FetchNextRunnableJob(ctx, w.workerID)
		if err != nil {
			w.logger.Error("fetch next job failed", zap.Error(err))
			return
		}
		if job == nil {
			return
		}
		w.runJob(ctx, job)
	}
}

func (w *ResolverWorker) runJob(ctx context.Context, job *models.ResolverJob) {
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

	// ── "No matching policy" is not a failure. The user simply has no
	//    policy coverage. Complete the job cleanly so we don't burn
	//    retries, and log it at Info so ops can spot the config gap.
	if errors.Is(err, leavesvc.ErrNoMatchingPolicy) {
		log.Info("resolver job skipped — no matching policy for user")
		if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
			log.Error("mark completed failed", zap.Error(mErr))
		}
		return
	}

	if err != nil {
		log.Warn("resolver job failed", zap.Error(err))
		if mErr := w.repo.MarkFailed(ctx, job.JobID, err.Error()); mErr != nil {
			log.Error("mark failed also failed", zap.Error(mErr))
		}
		return
	}

	if mErr := w.repo.MarkCompleted(ctx, job.JobID); mErr != nil {
		log.Error("mark completed failed", zap.Error(mErr))
		return
	}
	log.Info("resolver job completed")
}

func (w *ResolverWorker) resolveUser(ctx context.Context, job *models.ResolverJob) error {
	if job.UserID == nil {
		return errors.New("resolve_user job missing user_id")
	}
	reason := derefString(job.Reason, "system")

	// Scope the idempotency key by job_id so multiple resolver jobs for the
	// same user on the same day each run. Cross-job dedup is handled at the
	// resolver_job table level (uq_leave_resolver_job_pending_user), not here.
	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())

	return w.resolver.ResolveUserLeaveEntitlements(
		jobCtx, job.CompanyID, *job.UserID,
		time.Now().UTC(), reason, "system", uuid.Nil,
		map[string]interface{}{"source": "resolver_worker", "job_id": job.JobID.String()},
	)
}

func (w *ResolverWorker) resolveCompany(ctx context.Context, job *models.ResolverJob) error {
	userIDs, err := w.resolver.ListActiveEmployeeUserIDs(ctx, job.CompanyID)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return nil
	}
	reason := derefString(job.Reason, "policy change")

	// Same idea: give every user-resolve inside this fan-out a job-scoped
	// idempotency key so re-enqueueing the same company job on the same day
	// doesn't silently no-op.
	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())

	const chunk = 100
	for i := 0; i < len(userIDs); i += chunk {
		end := i + chunk
		if end > len(userIDs) {
			end = len(userIDs)
		}
		if _, err := w.resolver.ResolveBatchLeaveEntitlements(
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
	userIDs, err := w.resolver.ListActiveEmployeeUserIDsByPosition(ctx, job.CompanyID, *job.PositionID)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return nil
	}

	jobCtx := context.WithValue(ctx, "resolver_job_id", job.JobID.String())

	_, err = w.resolver.ResolveBatchLeaveEntitlements(
		jobCtx, job.CompanyID, userIDs,
		time.Now().UTC(), "position work_center change", "system", uuid.Nil,
		map[string]interface{}{"source": "resolver_worker", "job_id": job.JobID.String()},
	)
	return err
}

func (w *ResolverWorker) endEntitlements(ctx context.Context, job *models.ResolverJob) error {
	if job.UserID == nil {
		return errors.New("end_entitlements job missing user_id")
	}
	return w.resolver.EndActivePolicyEntitlements(ctx, job.CompanyID, *job.UserID, time.Now().UTC())
}

func derefString(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}