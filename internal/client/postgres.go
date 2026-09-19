// File: internal/client/postgres.go
// PostgreSQL client with connection pooling and health checks

package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"auth-service/internal/config"
	"auth-service/internal/util"

	_ "github.com/lib/pq" // PostgreSQL driver
	"go.uber.org/zap"
)

type PostgresClient struct {
	DB     *sql.DB
	config *config.PostgresConfig
	mu     sync.RWMutex
	logger *zap.Logger
}

func NewPostgresClient(cfg *config.Config, logger *zap.Logger) (*PostgresClient, error) {
	// Use the PostgresConfig from the main config
	pgConfig := &cfg.Postgres

	// ✅ Build connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		pgConfig.Host,
		pgConfig.Port,
		pgConfig.Username,
		pgConfig.Password,
		pgConfig.Database,
		pgConfig.SSLMode,
	)

	// ✅ Add connection timeout
	if pgConfig.ConnectionTimeout > 0 {
		connStr += fmt.Sprintf(" connect_timeout=%d", int(pgConfig.ConnectionTimeout.Seconds()))
	}

	// ✅ FIXED: Add additional connection parameters for better performance
	connStr += " application_name=auth-service"

	// ✅ Create database connection with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), pgConfig.ConnectionTimeout)
	defer cancel()

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL connection: %w", err)
	}

	// ✅ Configure connection pool
	db.SetMaxIdleConns(pgConfig.MaxIdleConns)
	db.SetMaxOpenConns(pgConfig.MaxOpenConns)
	db.SetConnMaxLifetime(pgConfig.ConnMaxLifetime)
	db.SetConnMaxIdleTime(pgConfig.ConnMaxIdleTime)

	// ✅ Test connection with timeout
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	pgClient := &PostgresClient{
		DB:     db,
		config: pgConfig,
		logger: logger,
	}

	// ✅ Log successful connection
	util.Get().Info("PostgreSQL client initialized successfully",
		zap.String("host", pgConfig.Host),
		zap.Int("port", pgConfig.Port),
		zap.String("database", pgConfig.Database),
		zap.String("ssl_mode", pgConfig.SSLMode),
		zap.Int("max_conns", pgConfig.MaxOpenConns),
		zap.Int("idle_conns", pgConfig.MaxIdleConns),
	)

	return pgClient, nil
}

// HealthCheck verifies PostgreSQL connectivity
func (p *PostgresClient) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		return fmt.Errorf("postgreSQL client not initialized")
	}

	if err := p.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("postgreSQL health check failed: %w", err)
	}

	// ✅ Additional health check: verify we can query the database
	var result int
	err := p.DB.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("postgreSQL query health check failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("postgreSQL health check returned unexpected result: %d", result)
	}

	return nil
}

// Query executes a read query
func (p *PostgresClient) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		return nil, fmt.Errorf("postgreSQL client not initialized")
	}

	return p.DB.QueryContext(ctx, query, args...)
}

// QueryRow executes a query that returns at most one row
func (p *PostgresClient) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		// Return a row that will error when scanned
		return &sql.Row{}
	}

	return p.DB.QueryRowContext(ctx, query, args...)
}

// Exec executes a write query (INSERT, UPDATE, DELETE)
func (p *PostgresClient) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		return nil, fmt.Errorf("postgreSQL client not initialized")
	}

	return p.DB.ExecContext(ctx, query, args...)
}

// BeginTx starts a transaction
func (p *PostgresClient) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		return nil, fmt.Errorf("postgreSQL client not initialized")
	}

	return p.DB.BeginTx(ctx, opts)
}

// Close gracefully closes the connection
func (p *PostgresClient) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.DB != nil {
		if err := p.DB.Close(); err != nil {
			util.Error("Failed to close PostgreSQL connection", zap.Error(err))
			return err
		}
		util.Info("PostgreSQL connection closed")
	}
	return nil
}

// GetStats returns database connection statistics
func (p *PostgresClient) GetStats() sql.DBStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.DB == nil {
		return sql.DBStats{}
	}

	return p.DB.Stats()
}

// ============================================================
// ✅ NEW — DBTX interface + WithTx helper
// ============================================================
//
// DBTX is the subset of methods shared by *sql.DB and *sql.Tx. Repository
// methods that need to participate in a transaction (or optionally take
// one) accept a DBTX as their first argument. Callers pass:
//
//   - r.client.Pool()          → runs against the pool (auto-commit)
//   - tx  (an active *sql.Tx)  → runs inside the caller's transaction
//
// This means a single repository method works in both contexts without
// needing two method variants. Where you want to keep an existing method
// signature for backward-compat, you can keep the non-Tx variant and add
// a new Tx variant that calls into the same query body.

// DBTX is satisfied by both *sql.DB and *sql.Tx.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Compile-time guarantees that both types satisfy DBTX.
var (
	_ DBTX = (*sql.DB)(nil)
	_ DBTX = (*sql.Tx)(nil)
)

// Pool returns the underlying *sql.DB as a DBTX so callers that don't
// want to hold a transaction can still pass something to a repo method
// expecting a DBTX.
//
// Usage:
//
//	rows, err := repo.ListLocations(ctx, r.client.Pool(), companyID, limit, offset)
func (p *PostgresClient) Pool() DBTX {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.DB
}

// TxFunc is the function signature accepted by WithTx. Any error returned
// causes the transaction to roll back; a nil return commits.
type TxFunc func(tx *sql.Tx) error

// WithTx runs fn inside a database transaction. Behaviour:
//
//   - begins a transaction on the pool
//   - runs fn(tx)
//   - if fn returns nil  → commits
//   - if fn returns err  → rolls back, returns the original error
//   - if fn panics       → rolls back, re-panics
//   - if Commit fails    → returns a wrapped error; the tx is considered
//     aborted by the driver
//
// The context passed in is used for Begin/Commit/Rollback. Repository
// methods called inside fn should use the tx (not the pool) so their
// statements run on the same connection.
//
// Do NOT nest calls to WithTx — the inner WithTx would begin a new
// connection-level transaction and the outer one would fail to see the
// inner's writes. If you need to compose services, thread the *sql.Tx
// through to inner service methods explicitly.
func (p *PostgresClient) WithTx(ctx context.Context, fn TxFunc) (err error) {
	p.mu.RLock()
	db := p.DB
	p.mu.RUnlock()

	if db == nil {
		return fmt.Errorf("postgreSQL client not initialized")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	defer func() {
		// Recover-panic path: always roll back before re-panicking so the
		// connection isn't left open.
		if r := recover(); r != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				util.Error("tx rollback after panic failed", zap.Error(rbErr))
			}
			panic(r)
		}

		// Error path: fn returned an error → roll back.
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				util.Error("tx rollback failed", zap.Error(rbErr))
			}
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}