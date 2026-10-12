package worker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	QueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "leave_resolver_queue_depth",
		Help: "Leave resolver jobs by internal state (in_flight / queued / failed).",
	}, []string{"status"})

	JobsCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "leave_resolver_jobs_completed_total",
		Help: "Total leave resolver jobs that completed successfully.",
	}, []string{"job_type"})

	JobsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "leave_resolver_jobs_failed_total",
		Help: "Total leave resolver jobs that failed.",
	}, []string{"job_type"})

	JobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "leave_resolver_job_duration_seconds",
		Help:    "Duration of leave resolver jobs.",
		Buckets: []float64{0.1, 0.5, 1, 5, 15, 30, 60, 300, 600, 1800},
	}, []string{"job_type"})

	StaleLocksReleased = promauto.NewCounter(prometheus.CounterOpts{
		Name: "leave_resolver_stale_locks_released_total",
		Help: "Total stale leave-resolver job locks released by the sweeper.",
	})
)
