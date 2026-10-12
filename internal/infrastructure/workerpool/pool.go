// Package workerpool provides a generic N-worker executor for
// table-backed job queues. It is the shared foundation for both the
// schedule-generation worker and the leave-resolver worker.
//
// Each pool runs:
//
//   - N worker goroutines, each claiming and running one job at a time.
//     They claim via the caller-supplied Claim func, which is expected to
//     use FOR UPDATE SKIP LOCKED (or equivalent) so multiple workers across
//     replicas cooperate without coordination.
//
//   - One sweeper goroutine that periodically releases locks older than
//     StaleThreshold. Crashed workers leave locked rows behind; the
//     sweeper resets them so the retry budget is honest.
//
// The pool knows nothing about job status, retries, or backoff. The
// caller's Run func owns all of that. The pool just orchestrates
// concurrency and lifecycle.
package workerpool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config is the parameter bundle for a pool. All fields have sensible
// defaults except Claim, Run, and ReleaseStale, which must be supplied.
type Config[T any] struct {
	// Workers is the number of concurrent worker goroutines. Each claims
	// and runs one job at a time. Recommended: 3-10. Too few and the
	// queue drains slowly; too many and Postgres sees connection
	// contention with the HTTP tier.
	Workers int

	// IdleInterval is how long a worker rests when Claim returns nil.
	// Under load, workers never rest — the loop is claim/run/claim/run
	// until the queue drains. IdleInterval only governs the empty-queue
	// case.
	IdleInterval time.Duration

	// StaleSweepInterval is how often the sweeper runs. Should be several
	// times longer than the expected worst-case job duration.
	StaleSweepInterval time.Duration

	// StaleThreshold is the age at which a locked job is considered
	// abandoned. Passed through to ReleaseStale.
	StaleThreshold time.Duration

	// WorkerIDPrefix is prepended to each worker's index to form the
	// locked_by value written to the job table. Set it to something
	// identifying the pod (e.g. include the hostname) for easier
	// debugging in multi-replica deployments.
	WorkerIDPrefix string

	// Claim fetches the next runnable job and marks it as processing in
	// the caller's storage. Return (nil, nil) when the queue is empty.
	// Errors are logged and the worker backs off for IdleInterval.
	Claim func(ctx context.Context, workerID string) (*T, error)

	// Run executes a claimed job. The caller is responsible for marking
	// the job completed or failed based on the returned error. The pool
	// does not touch job status.
	Run func(ctx context.Context, job *T) error

	// ReleaseStale resets abandoned locks older than threshold. Must be
	// safe to call concurrently with Claim/Run.
	ReleaseStale func(ctx context.Context, threshold time.Duration) (int64, error)

	// OnJobClaimed is called immediately after a successful claim and
	// before Run. Use it to increment "in-flight" metrics.
	OnJobClaimed func(job *T)

	// OnJobFinished is called after Run returns, with the run's error and
	// elapsed duration. Use it to record histograms and success/failure
	// counters.
	OnJobFinished func(job *T, err error, duration time.Duration)

	// OnStaleSweep is called after each sweep with the number of locks
	// released. Zero is a normal outcome; non-zero on a regular basis
	// indicates crashed workers or over-long jobs.
	OnStaleSweep func(released int64)

	Logger *zap.Logger
}

// Pool is a started (or startable) worker pool. Create with New, then call
// Start in a goroutine.
type Pool[T any] struct {
	cfg Config[T]
}

// New builds a Pool with defaults filled in. It does not start any
// goroutines — call Start for that.
func New[T any](cfg Config[T]) *Pool[T] {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.IdleInterval <= 0 {
		cfg.IdleInterval = 5 * time.Second
	}
	if cfg.StaleSweepInterval <= 0 {
		cfg.StaleSweepInterval = 5 * time.Minute
	}
	if cfg.StaleThreshold <= 0 {
		cfg.StaleThreshold = 10 * time.Minute
	}
	if cfg.WorkerIDPrefix == "" {
		cfg.WorkerIDPrefix = "worker"
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return &Pool[T]{cfg: cfg}
}

// Start blocks until ctx is cancelled and every worker and the sweeper
// have exited. Typical usage:
//
//	go pool.Start(rootCtx)
//
// Shutdown is triggered by cancelling ctx.
func (p *Pool[T]) Start(ctx context.Context) {
	log := p.cfg.Logger.Named("workerpool")
	log.Info("worker pool starting",
		zap.Int("workers", p.cfg.Workers),
		zap.String("prefix", p.cfg.WorkerIDPrefix),
		zap.Duration("idle_interval", p.cfg.IdleInterval),
		zap.Duration("stale_sweep_interval", p.cfg.StaleSweepInterval),
		zap.Duration("stale_threshold", p.cfg.StaleThreshold),
	)

	var wg sync.WaitGroup

	// One sweeper for the whole pool, not one per worker.
	if p.cfg.ReleaseStale != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.sweepLoop(ctx, log)
		}()
	}

	// N workers, each with a distinct ID for the locked_by column.
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		workerID := fmt.Sprintf("%s-%d", p.cfg.WorkerIDPrefix, i)
		go func(id string) {
			defer wg.Done()
			p.workerLoop(ctx, id, log)
		}(workerID)
	}

	wg.Wait()
	log.Info("worker pool stopped")
}

// sweepLoop runs the stale-lock sweep immediately once and then on the
// configured interval. The immediate sweep ensures a pod restart doesn't
// leave the previous pod's locked rows waiting a full interval.
func (p *Pool[T]) sweepLoop(ctx context.Context, log *zap.Logger) {
	p.sweepOnce(ctx, log)

	ticker := time.NewTicker(p.cfg.StaleSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.sweepOnce(ctx, log)
		}
	}
}

func (p *Pool[T]) sweepOnce(ctx context.Context, log *zap.Logger) {
	released, err := p.cfg.ReleaseStale(ctx, p.cfg.StaleThreshold)
	if err != nil {
		log.Warn("stale lock sweep failed", zap.Error(err))
		return
	}
	if released > 0 {
		log.Warn("released stale locks", zap.Int64("count", released))
	}
	if p.cfg.OnStaleSweep != nil {
		p.cfg.OnStaleSweep(released)
	}
}

// workerLoop is the per-worker claim/run cycle. It never returns until ctx
// is cancelled. There is no artificial batch limit — a worker keeps
// claiming as long as Claim returns a job. When the queue empties, the
// worker sleeps for IdleInterval and tries again.
func (p *Pool[T]) workerLoop(ctx context.Context, workerID string, log *zap.Logger) {
	workerLog := log.With(zap.String("worker_id", workerID))

	// Immediate first attempt so a fresh worker doesn't wait IdleInterval
	// before looking for work.
	for {
		if ctx.Err() != nil {
			return
		}

		job, err := p.cfg.Claim(ctx, workerID)
		if err != nil {
			workerLog.Error("claim failed", zap.Error(err))
			if !sleepCtx(ctx, p.cfg.IdleInterval) {
				return
			}
			continue
		}
		if job == nil {
			// Queue empty. Rest.
			if !sleepCtx(ctx, p.cfg.IdleInterval) {
				return
			}
			continue
		}

		if p.cfg.OnJobClaimed != nil {
			p.cfg.OnJobClaimed(job)
		}

		start := time.Now()
		runErr := p.cfg.Run(ctx, job)
		elapsed := time.Since(start)

		if p.cfg.OnJobFinished != nil {
			p.cfg.OnJobFinished(job, runErr, elapsed)
		}

		// No sleep between successful claims. Under load this loop runs
		// continuously; the sleep only kicks in when the queue is empty.
	}
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first.
// Returns true for d <= 0 if ctx is still alive.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
