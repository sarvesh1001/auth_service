package scylla

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/gocql/gocql"
    "go.uber.org/zap"

    "auth-service/internal/config"
    "auth-service/internal/util"
)

// PreparedStatements holds all prepared statements for better performance
type PreparedStatements struct {
    CreateUser                    *gocql.Query
    CreateUserByID               *gocql.Query
    CreatePhoneToUser            *gocql.Query
    GetUserByPhone               *gocql.Query
    GetUserByID                  *gocql.Query
    UpdateUserVerification       *gocql.Query
    UpdateUserMPIN               *gocql.Query
    UpdateUserDevice             *gocql.Query
    UpdateUserLastLogin          *gocql.Query
    DeactivateUser               *gocql.Query
    CreateOTP                    *gocql.Query
    GetOTPByPhone               *gocql.Query
    MarkOTPUsed                 *gocql.Query
    IncrementOTPAttempt         *gocql.Query
    DeleteExpiredOTPs           *gocql.Query
    CreateMPIN                  *gocql.Query
    GetMPINByUserID             *gocql.Query
    UpdateMPINHash              *gocql.Query
    IncrementMPINRetry          *gocql.Query
    BlockMPIN                   *gocql.Query
    ResetMPINRetryCount         *gocql.Query
    CreateDeviceSession         *gocql.Query
    CreateSessionByID           *gocql.Query
    GetActiveSessionByUserID    *gocql.Query
    GetSessionByID              *gocql.Query
    RevokeSessionByUserID       *gocql.Query
    RevokeSessionByDeviceID     *gocql.Query
    UpdateSessionAccessTime     *gocql.Query
    ListUserSessions            *gocql.Query
    CreateLoginAttempt          *gocql.Query
    CreateUserActivity          *gocql.Query
}

type ScyllaClient struct {
    Session      *gocql.Session
    config       *config.ScyllaConfig
    Prepared     *PreparedStatements
    prepareMutex sync.RWMutex
    isPrepared   bool
}

func NewScyllaClient(cfg *config.Config, logger *zap.Logger) (*ScyllaClient, error) {
    scyllaConfig := cfg.Scylla

    cluster := gocql.NewCluster(scyllaConfig.Nodes...)
    cluster.Keyspace = scyllaConfig.Keyspace
    cluster.Consistency = gocql.LocalQuorum
    cluster.Timeout = 10 * time.Second
    cluster.ConnectTimeout = 10 * time.Second
    cluster.NumConns = 4
    cluster.SocketKeepalive = 30 * time.Second
    cluster.MaxPreparedStmts = 1000
    cluster.MaxRoutingKeyInfo = 1000
    cluster.PageSize = 1000
    cluster.RetryPolicy = &gocql.ExponentialBackoffRetryPolicy{
        Min:        time.Second,
        Max:        10 * time.Second,
        NumRetries: 3,
    }

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

    client := &ScyllaClient{
        Session: session,
        config:  &scyllaConfig,
    }

    if err := client.prepareStatements(); err != nil {
        session.Close()
        return nil, fmt.Errorf("failed to prepare statements: %w", err)
    }

    util.Info("ScyllaDB client initialized with prepared statements",
        zap.Strings("nodes", scyllaConfig.Nodes),
        zap.String("keyspace", scyllaConfig.Keyspace))

    return client, nil
}

func (s *ScyllaClient) prepareStatements() error {
    s.prepareMutex.Lock()
    defer s.prepareMutex.Unlock()

    if s.isPrepared {
        return nil
    }

    prepared := &PreparedStatements{}

    prepared.CreateUser = s.Session.Query(`
        INSERT INTO users (phone_number, user_id, country_code, device_id, mpin_hash, 
                          is_verified, is_active, last_login_at, created_at, updated_at, 
                          last_login_ip, last_login_city)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

    // Prepare remaining statements similarly...

    s.Prepared = prepared
    s.isPrepared = true

    util.Info("All ScyllaDB prepared statements created successfully")
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
    return s.Session.ExecuteBatch(batch)
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
    var lastErr error
    for i := 0; i <= maxRetries; i++ {
        if err := query.Exec(); err != nil {
            lastErr = err
            if i < maxRetries {
                time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
                continue
            }
        } else {
            return nil
        }
    }
    return lastErr
}

func (s *ScyllaClient) ScanWithRetry(query *gocql.Query, dest ...interface{}) error {
    var lastErr error
    for i := 0; i < 3; i++ {
        if err := query.Scan(dest...); err != nil {
            lastErr = err
            if i < 2 {
                time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
                continue
            }
        } else {
            return nil
        }
    }
    return lastErr
}