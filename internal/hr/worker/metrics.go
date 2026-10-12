package worker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HRLifecycleQueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hr_lifecycle_queue_depth",
		Help: "HR lifecycle and accrual jobs by internal state.",
	}, []string{"status"})

	HRLifecycleJobsCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hr_lifecycle_jobs_completed_total",
		Help: "HR lifecycle jobs that completed successfully.",
	}, []string{"job_type"})

	HRLifecycleJobsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hr_lifecycle_jobs_failed_total",
		Help: "HR lifecycle jobs that failed.",
	}, []string{"job_type"})

	HRLifecycleJobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hr_lifecycle_job_duration_seconds",
		Buckets: []float64{0.1, 0.5, 1, 5, 15, 30, 60, 300, 600},
	}, []string{"job_type"})

	HRLifecycleStaleLocksReleased = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hr_lifecycle_stale_locks_released_total",
	})
)
