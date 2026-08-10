package scylla

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"auth-service/internal/config"

	"github.com/gocql/gocql"
)

type ClientMetrics struct {
	TotalQueries     atomic.Int64
	FailedQueries    atomic.Int64
	TotalBatches     atomic.Int64
	FailedBatches    atomic.Int64
	AvgQueryDuration atomic.Int64
	QueryCount       atomic.Int64
}

type ScyllaClient struct {
	Session   *gocql.Session
	config    *config.ScyllaConfig
	metrics   *ClientMetrics
	sessionMu sync.RWMutex
	isClosed  bool
}

func NewScyllaClient(cfg *config.Config) (*ScyllaClient, error) {
	scyllaConfig := cfg.Scylla
	cluster := gocql.NewCluster(scyllaConfig.Nodes...)
	cluster.Keyspace = scyllaConfig.Keyspace
	cluster.Consistency = gocql.LocalQuorum
	cluster.Timeout = 10 * time.Second
	cluster.ConnectTimeout = 10 * time.Second
	cluster.NumConns = 16
	cluster.SocketKeepalive = 30 * time.Second
	cluster.MaxWaitSchemaAgreement = 60 * time.Second
	cluster.MaxPreparedStmts = 0
	cluster.MaxRoutingKeyInfo = 1000
	cluster.PageSize = 5000
	cluster.RetryPolicy = &gocql.ExponentialBackoffRetryPolicy{
		Min:        time.Second,
		Max:        10 * time.Second,
		NumRetries: 3,
	}
	cluster.PoolConfig.HostSelectionPolicy = gocql.TokenAwareHostPolicy(
		gocql.RoundRobinHostPolicy(),
	)
	cluster.ReconnectInterval = time.Second
	cluster.MaxWaitSchemaAgreement = 60 * time.Second

	if !cfg.IsDevelopment() {
		cluster.SslOpts = &gocql.SslOptions{
			CaPath:                 "/root/certs/ca.pem",
			CertPath:               "/root/certs/server.pem",
			KeyPath:                "/root/certs/server.key",
			EnableHostVerification: true,
		}
	}
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

	return &ScyllaClient{
		Session: session,
		config:  &scyllaConfig,
		metrics: &ClientMetrics{},
	}, nil
}

func (s *ScyllaClient) Close() {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.Session != nil && !s.isClosed {
		s.Session.Close()
		s.isClosed = true
	}
}

func (s *ScyllaClient) Query(stmt string, values ...interface{}) *gocql.Query {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	if s.isClosed {
		return nil
	}
	return s.Session.Query(stmt, values...)
}

func (s *ScyllaClient) Batch(typ gocql.BatchType) *gocql.Batch {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	if s.isClosed {
		return nil
	}
	return s.Session.NewBatch(typ)
}

func (s *ScyllaClient) ExecuteBatch(batch *gocql.Batch) error {
	start := time.Now()
	s.metrics.TotalBatches.Add(1)
	s.sessionMu.RLock()
	err := s.Session.ExecuteBatch(batch)
	s.sessionMu.RUnlock()
	s.recordQueryDuration(time.Since(start))
	if err != nil {
		s.metrics.FailedBatches.Add(1)
	}
	return err
}

func (s *ScyllaClient) HealthCheck(ctx context.Context) error {
	var clusterName string
	err := s.Query(`SELECT cluster_name FROM system.local`).WithContext(ctx).Scan(&clusterName)
	if err != nil {
		return fmt.Errorf("scylla health check failed: %w", err)
	}
	return nil
}

func (s *ScyllaClient) ExecuteWithRetry(query *gocql.Query, maxRetries int) error {
	start := time.Now()
	s.metrics.TotalQueries.Add(1)
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if err := query.Exec(); err != nil {
			lastErr = err
			if i < maxRetries {
				backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		} else {
			s.recordQueryDuration(time.Since(start))
			return nil
		}
	}
	s.metrics.FailedQueries.Add(1)
	s.recordQueryDuration(time.Since(start))
	return lastErr
}

func (s *ScyllaClient) ScanWithRetry(query *gocql.Query, dest ...interface{}) error {
	start := time.Now()
	s.metrics.TotalQueries.Add(1)
	var lastErr error
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if err := query.Scan(dest...); err != nil {
			lastErr = err
			if i < maxRetries-1 {
				backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		} else {
			s.recordQueryDuration(time.Since(start))
			return nil
		}
	}
	s.metrics.FailedQueries.Add(1)
	s.recordQueryDuration(time.Since(start))
	return lastErr
}

func (s *ScyllaClient) recordQueryDuration(duration time.Duration) {
	count := s.metrics.QueryCount.Add(1)
	currentAvg := s.metrics.AvgQueryDuration.Load()
	newAvg := (currentAvg*(count-1) + duration.Nanoseconds()) / count
	s.metrics.AvgQueryDuration.Store(newAvg)
}

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

func (s *ScyllaClient) ResetMetrics() {
	s.metrics.TotalQueries.Store(0)
	s.metrics.FailedQueries.Store(0)
	s.metrics.TotalBatches.Store(0)
	s.metrics.FailedBatches.Store(0)
	s.metrics.AvgQueryDuration.Store(0)
	s.metrics.QueryCount.Store(0)
}
