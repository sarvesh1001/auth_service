package scylla

import (
    "sync/atomic"
    "time"
)

// RepositoryMetrics tracks query and cache metrics for the repository
type RepositoryMetrics struct {
    TotalQueries      atomic.Int64
    FailedQueries     atomic.Int64
    CacheHits         atomic.Int64
    CacheMisses       atomic.Int64
    AvgQueryDuration  atomic.Int64 // nanoseconds
    QueryCount        atomic.Int64
}

// RecordQuery records a query's duration and success
func (m *RepositoryMetrics) RecordQuery(duration time.Duration, success bool) {
    m.TotalQueries.Add(1)
    if !success {
        m.FailedQueries.Add(1)
    }
    
    // Rolling average calculation
    count := m.QueryCount.Add(1)
    currentAvg := m.AvgQueryDuration.Load()
    newAvg := (currentAvg*(count-1) + duration.Nanoseconds()) / count
    m.AvgQueryDuration.Store(newAvg)
}

// GetStats returns current metrics as a map
func (m *RepositoryMetrics) GetStats() map[string]interface{} {
    total := m.TotalQueries.Load()
    failed := m.FailedQueries.Load()
    hits := m.CacheHits.Load()
    misses := m.CacheMisses.Load()

    successRate := float64(0)
    if total > 0 {
        successRate = float64(total-failed) / float64(total) * 100
    }
    hitRate := float64(0)
    if hits+misses > 0 {
        hitRate = float64(hits) / float64(hits+misses) * 100
    }

    return map[string]interface{}{
        "total_queries":      total,
        "failed_queries":     failed,
        "success_rate":       successRate,
        "cache_hits":         hits,
        "cache_misses":       misses,
        "cache_hit_rate":     hitRate,
        "avg_query_duration": time.Duration(m.AvgQueryDuration.Load()),
    }
}