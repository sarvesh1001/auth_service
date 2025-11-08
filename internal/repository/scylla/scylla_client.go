package scylla

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocql/gocql"
	"go.uber.org/zap"

	"auth-service/internal/config"
	"auth-service/internal/util"
)

// ✅ REMOVED: PreparedStatements struct - queries will be created dynamically
// This prevents stale prepared statements after container restarts

// ClientMetrics tracks client-level metrics for monitoring
type ClientMetrics struct {
	TotalQueries     atomic.Int64
	FailedQueries    atomic.Int64
	TotalBatches     atomic.Int64
	FailedBatches    atomic.Int64
	AvgQueryDuration atomic.Int64 // nanoseconds
	QueryCount       atomic.Int64
}

type ScyllaClient struct {
	Session   *gocql.Session
	config    *config.ScyllaConfig
	metrics   *ClientMetrics
	logger    *zap.Logger
	sessionMu sync.RWMutex // ✅ NEW: Protect session access
	isClosed  bool
}

func NewScyllaClient(cfg *config.Config, logger *zap.Logger) (*ScyllaClient, error) {
	scyllaConfig := cfg.Scylla

	cluster := gocql.NewCluster(scyllaConfig.Nodes...)
	cluster.Keyspace = scyllaConfig.Keyspace

	// Consistency and timeout settings
	cluster.Consistency = gocql.LocalQuorum
	cluster.Timeout = 10 * time.Second
	cluster.ConnectTimeout = 10 * time.Second

	// Connection pooling optimized for 500M users
	cluster.NumConns = 16 // Increased from 4 to 16 connections per host
	cluster.SocketKeepalive = 30 * time.Second
	cluster.MaxWaitSchemaAgreement = 60 * time.Second

	// Prepared statement cache - disabled to prevent stale statements
	cluster.MaxPreparedStmts = 0 // ✅ CHANGED: Disable caching
	cluster.MaxRoutingKeyInfo = 1000

	// Larger page size for batch operations
	cluster.PageSize = 5000 // Increased from 1000 to 5000

	// Optimized retry policy with exponential backoff
	cluster.RetryPolicy = &gocql.ExponentialBackoffRetryPolicy{
		Min:        time.Second,
		Max:        10 * time.Second,
		NumRetries: 3,
	}

	// Token-aware routing for better performance
	cluster.PoolConfig.HostSelectionPolicy = gocql.TokenAwareHostPolicy(
		gocql.RoundRobinHostPolicy(),
	)

	// Connection pool configuration
	cluster.ReconnectInterval = time.Second
	cluster.MaxWaitSchemaAgreement = 60 * time.Second

	// TLS configuration for production
	if !cfg.IsDevelopment() {
		cluster.SslOpts = &gocql.SslOptions{
			CaPath:                 "/root/certs/ca.pem",
			CertPath:               "/root/certs/server.pem",
			KeyPath:                "/root/certs/server.key",
			EnableHostVerification: true,
		}
	}

	// Authentication
	if scyllaConfig.Username != "" && scyllaConfig.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: scyllaConfig.Username,
			Password: scyllaConfig.Password,
		}
	}

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create scylla session: %w", err)
	}

	client := &ScyllaClient{
		Session: session,
		config:  &scyllaConfig,
		metrics: &ClientMetrics{},
		logger:  logger,
	}

	util.Info("ScyllaDB client initialized with optimized settings",
		zap.Strings("nodes", scyllaConfig.Nodes),
		zap.String("keyspace", scyllaConfig.Keyspace),
		zap.Int("num_conns", 16),
		zap.Int("page_size", 5000),
		zap.String("prepared_stmt_caching", "disabled")) // ✅ Log that caching is disabled

	return client, nil
}

// ✅ REMOVED: prepareStatements() method - no longer needed

func (s *ScyllaClient) Close() {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.Session != nil && !s.isClosed {
		s.Session.Close()
		s.isClosed = true
		util.Info("ScyllaDB client closed")
	}
}

// ✅ UPDATED: Query method with session mutex
func (s *ScyllaClient) Query(stmt string, values ...interface{}) *gocql.Query {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()

	if s.isClosed {
		s.logger.Error("Cannot create query - session is closed")
		return nil
	}

	return s.Session.Query(stmt, values...)
}

// ✅ UPDATED: Batch method with session mutex
func (s *ScyllaClient) Batch(typ gocql.BatchType) *gocql.Batch {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()

	if s.isClosed {
		s.logger.Error("Cannot create batch - session is closed")
		return nil
	}

	return s.Session.NewBatch(typ)
}

func (s *ScyllaClient) ExecuteBatch(batch *gocql.Batch) error {
	startTime := time.Now()
	s.metrics.TotalBatches.Add(1)

	s.sessionMu.RLock()
	err := s.Session.ExecuteBatch(batch)
	s.sessionMu.RUnlock()

	duration := time.Since(startTime)

	if err != nil {
		s.metrics.FailedBatches.Add(1)
		s.logger.Warn("Batch execution failed",
			util.ErrorField(err),
			util.Duration("duration", duration))
	}

	s.recordQueryDuration(duration)
	return err
}

func (s *ScyllaClient) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clusterName string
	err := s.Query(`SELECT cluster_name FROM system.local`).WithContext(ctx).Scan(&clusterName)
	if err != nil {
		return fmt.Errorf("scylla health check failed: %w", err)
	}

	util.Debug("ScyllaDB health check passed", zap.String("cluster_name", clusterName))
	return nil
}

func (s *ScyllaClient) ExecuteWithRetry(query *gocql.Query, maxRetries int) error {
	startTime := time.Now()
	s.metrics.TotalQueries.Add(1)

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if err := query.Exec(); err != nil {
			lastErr = err
			if i < maxRetries {
				// Exponential backoff: 100ms, 200ms, 400ms
				backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		} else {
			duration := time.Since(startTime)
			s.recordQueryDuration(duration)
			return nil
		}
	}

	s.metrics.FailedQueries.Add(1)
	duration := time.Since(startTime)
	s.recordQueryDuration(duration)

	s.logger.Warn("Query failed after retries",
		util.ErrorField(lastErr),
		util.Int("retries", maxRetries),
		util.Duration("total_duration", duration))

	return lastErr
}

func (s *ScyllaClient) ScanWithRetry(query *gocql.Query, dest ...interface{}) error {
	startTime := time.Now()
	s.metrics.TotalQueries.Add(1)

	var lastErr error
	maxRetries := 3

	for i := 0; i < maxRetries; i++ {
		if err := query.Scan(dest...); err != nil {
			lastErr = err
			if i < maxRetries-1 {
				// Exponential backoff
				backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		} else {
			duration := time.Since(startTime)
			s.recordQueryDuration(duration)
			return nil
		}
	}

	s.metrics.FailedQueries.Add(1)
	duration := time.Since(startTime)
	s.recordQueryDuration(duration)

	s.logger.Warn("Scan failed after retries",
		util.ErrorField(lastErr),
		util.Int("retries", maxRetries),
		util.Duration("total_duration", duration))

	return lastErr
}

// recordQueryDuration records query duration for metrics
func (s *ScyllaClient) recordQueryDuration(duration time.Duration) {
	count := s.metrics.QueryCount.Add(1)
	currentAvg := s.metrics.AvgQueryDuration.Load()
	newAvg := (currentAvg*(count-1) + duration.Nanoseconds()) / count
	s.metrics.AvgQueryDuration.Store(newAvg)
}

// GetMetrics returns current client metrics
func (s *ScyllaClient) GetMetrics() map[string]interface{} {
	total := s.metrics.TotalQueries.Load()
	failed := s.metrics.FailedQueries.Load()
	totalBatches := s.metrics.TotalBatches.Load()
	failedBatches := s.metrics.FailedBatches.Load()

	successRate := float64(0)
	if total > 0 {
		successRate = float64(total-failed) / float64(total) * 100
	}

	batchSuccessRate := float64(0)
	if totalBatches > 0 {
		batchSuccessRate = float64(totalBatches-failedBatches) / float64(totalBatches) * 100
	}

	return map[string]interface{}{
		"total_queries":      total,
		"failed_queries":     failed,
		"success_rate":       successRate,
		"total_batches":      totalBatches,
		"failed_batches":     failedBatches,
		"batch_success_rate": batchSuccessRate,
		"avg_query_duration": time.Duration(s.metrics.AvgQueryDuration.Load()).String(),
		"num_connections":    16,
		"page_size":          5000,
	}
}

// GetConnectionPoolStats returns connection pool statistics
func (s *ScyllaClient) GetConnectionPoolStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["keyspace"] = s.config.Keyspace
	stats["consistency"] = "LOCAL_QUORUM"
	stats["num_conns_per_host"] = 16
	stats["page_size"] = 5000
	stats["max_prepared_stmts"] = 0 // ✅ UPDATED: Now disabled
	stats["socket_keepalive"] = "30s"
	stats["timeout"] = "10s"

	return stats
}

// ResetMetrics resets all client metrics (useful for testing)
func (s *ScyllaClient) ResetMetrics() {
	s.metrics.TotalQueries.Store(0)
	s.metrics.FailedQueries.Store(0)
	s.metrics.TotalBatches.Store(0)
	s.metrics.FailedBatches.Store(0)
	s.metrics.AvgQueryDuration.Store(0)
	s.metrics.QueryCount.Store(0)

	s.logger.Info("Client metrics reset")
}
