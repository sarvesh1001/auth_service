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

// PreparedStatements holds prepared statements that are actually used by the repository
type PreparedStatements struct {
    CreateUser          *gocql.Query
    CreatePhoneToUser   *gocql.Query
    GetUserByPhone      *gocql.Query
    GetUserByID         *gocql.Query
    UpdateUserProfile   *gocql.Query
    UpdateUserStatus    *gocql.Query
    UpdateUserLastLogin *gocql.Query
    UpdateKYCStatus     *gocql.Query
    UpdateUserConsent   *gocql.Query
    BanUser             *gocql.Query
    UnbanUser           *gocql.Query
}

// ClientMetrics tracks client-level metrics for monitoring
type ClientMetrics struct {
    TotalQueries      atomic.Int64
    FailedQueries     atomic.Int64
    TotalBatches      atomic.Int64
    FailedBatches     atomic.Int64
    AvgQueryDuration  atomic.Int64 // nanoseconds
    QueryCount        atomic.Int64
}

type ScyllaClient struct {
    Session      *gocql.Session
    config       *config.ScyllaConfig
    Prepared     *PreparedStatements
    prepareMutex sync.RWMutex
    isPrepared   bool
    metrics      *ClientMetrics
    logger       *zap.Logger
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
    
    // Prepared statement cache
    cluster.MaxPreparedStmts = 1000
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

    if err := client.prepareStatements(); err != nil {
        session.Close()
        return nil, fmt.Errorf("failed to prepare statements: %w", err)
    }

    util.Info("ScyllaDB client initialized with optimized settings",
        zap.Strings("nodes", scyllaConfig.Nodes),
        zap.String("keyspace", scyllaConfig.Keyspace),
        zap.Int("num_conns", 16),
        zap.Int("page_size", 5000))

    return client, nil
}

func (s *ScyllaClient) prepareStatements() error {
    s.prepareMutex.Lock()
    defer s.prepareMutex.Unlock()

    if s.isPrepared {
        return nil
    }

    prepared := &PreparedStatements{}

    // Include phone_encrypted_dek in all prepared statements
    prepared.CreateUser = s.Session.Query(`
        INSERT INTO users (
            user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
            kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
            banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
            consent_agreed, consent_version, data_region
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

    prepared.CreatePhoneToUser = s.Session.Query(`
        INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
        VALUES (?, ?, ?, ?)`)

    prepared.GetUserByID = s.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM users WHERE user_bucket = ? AND user_id = ?`)

    prepared.GetUserByPhone = s.Session.Query(`
        SELECT user_bucket, user_id FROM phone_to_user WHERE phone_hash = ?`)

    prepared.UpdateUserProfile = s.Session.Query(`
        UPDATE users SET profile_service_id = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

    prepared.UpdateUserStatus = s.Session.Query(`
        UPDATE users SET is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

    prepared.UpdateUserLastLogin = s.Session.Query(`
        UPDATE users SET last_login = ? WHERE user_bucket = ? AND user_id = ?`)

    prepared.UpdateKYCStatus = s.Session.Query(`
        UPDATE users SET kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?
        WHERE user_bucket = ? AND user_id = ?`)

    prepared.UpdateUserConsent = s.Session.Query(`
        UPDATE users SET consent_agreed = ?, consent_version = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

    prepared.BanUser = s.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

    prepared.UnbanUser = s.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

    s.Prepared = prepared
    s.isPrepared = true

    util.Info("ScyllaDB prepared statements created successfully",
        zap.Int("statement_count", 11))
    return nil
}

func (s *ScyllaClient) Close() {
    if s.Session != nil {
        s.Session.Close()
        util.Info("ScyllaDB client closed")
    }
}

func (s *ScyllaClient) Query(stmt string, values ...interface{}) *gocql.Query {
    return s.Session.Query(stmt, values...)
}

func (s *ScyllaClient) Batch(typ gocql.BatchType) *gocql.Batch {
    return s.Session.NewBatch(typ)
}

func (s *ScyllaClient) ExecuteBatch(batch *gocql.Batch) error {
    startTime := time.Now()
    s.metrics.TotalBatches.Add(1)
    
    err := s.Session.ExecuteBatch(batch)
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
    err := s.Session.Query(`SELECT cluster_name FROM system.local`).WithContext(ctx).Scan(&clusterName)
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
        "total_queries":       total,
        "failed_queries":      failed,
        "success_rate":        successRate,
        "total_batches":       totalBatches,
        "failed_batches":      failedBatches,
        "batch_success_rate":  batchSuccessRate,
        "avg_query_duration":  time.Duration(s.metrics.AvgQueryDuration.Load()).String(),
        "num_connections":     16,
        "page_size":           5000,
    }
}

// GetConnectionPoolStats returns connection pool statistics
func (s *ScyllaClient) GetConnectionPoolStats() map[string]interface{} {
    stats := make(map[string]interface{})
    
    stats["keyspace"] = s.config.Keyspace
    stats["consistency"] = "LOCAL_QUORUM"
    stats["num_conns_per_host"] = 16
    stats["page_size"] = 5000
    stats["max_prepared_stmts"] = 1000
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
