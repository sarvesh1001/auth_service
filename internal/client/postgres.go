// File: internal/client/postgres.go
// PostgreSQL client with connection pooling and health checks

package client

import (
	"context"
	"database/sql"
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
