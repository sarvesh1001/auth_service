package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"auth-service/internal/config"
	"auth-service/internal/util"
)

type ClickHouseClient struct {
	conn   driver.Conn  // Changed from ch.Conn to driver.Conn
	config *config.ClickhouseConfig
	mu     sync.RWMutex
}

// NewClickHouseClient creates a new ClickHouse client with TLS support
func NewClickHouseClient(cfg *config.Config, logger *zap.Logger) (*ClickHouseClient, error) {
	chConfig := cfg.Clickhouse

	opts := &ch.Options{
		Addr: []string{extractHostPort(chConfig.URL)},
		Auth: ch.Auth{
			Username: chConfig.Username,
			Password: chConfig.Password,
			Database: chConfig.Database,
		},
		DialTimeout:          30 * time.Second,
		MaxOpenConns:         100,
		MaxIdleConns:         50,
		ConnMaxLifetime:      time.Hour,
		ConnOpenStrategy:     ch.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 10240,
	}

	// TLS configuration remains the same
	if cfg.IsProduction() || strings.HasPrefix(chConfig.URL, "https://") {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: extractHostname(chConfig.URL),
		}
		if caCertPath := util.GetEnv("CLICKHOUSE_CA_FILE", ""); caCertPath != "" {
			caCert, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read ClickHouse CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to append CA cert")
			}
			tlsConfig.RootCAs = caCertPool
		}
		opts.TLS = tlsConfig
	}

	conn, err := ch.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open ClickHouse connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	util.Info("ClickHouse client initialized successfully",
		zap.String("url", chConfig.URL),
		zap.String("database", chConfig.Database),
		zap.Int("max_conns", opts.MaxOpenConns),
		zap.Bool("tls_enabled", opts.TLS != nil),
	)

	return &ClickHouseClient{
		conn:   conn,
		config: &chConfig,
	}, nil
}

// Exec executes a write query
func (c *ClickHouseClient) Exec(ctx context.Context, query string, args ...interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.Exec(ctx, query, args...)
}

// Query executes a read query - Changed return type to driver.Rows
func (c *ClickHouseClient) QueryRows(ctx context.Context, query string, args ...interface{}) (driver.Rows, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.Query(ctx, query, args...)
}

// BatchInsert performs high-performance batch inserts - Updated to use driver.Batch
func (c *ClickHouseClient) BatchInsert(ctx context.Context, query string, data [][]interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	batch, err := c.conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, row := range data {
		if err := batch.Append(row...); err != nil {
			return fmt.Errorf("failed to append row to batch: %w", err)
		}
	}

	return batch.Send()
}

// HealthCheck verifies ClickHouse connectivity
func (c *ClickHouseClient) HealthCheck(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.Ping(ctx)
}

// Close gracefully closes the connection
func (c *ClickHouseClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			util.Error("Failed to close ClickHouse connection", zap.Error(err))
			return err
		}
		util.Info("ClickHouse connection closed")
	}
	return nil
}

// Helper functions remain the same
func extractHostPort(url string) string {
	cleanURL := strings.TrimPrefix(url, "http://")
	cleanURL = strings.TrimPrefix(cleanURL, "https://")
	if !strings.Contains(cleanURL, ":") {
		if strings.HasPrefix(url, "https://") {
			return cleanURL + ":8443"
		}
		return cleanURL + ":8123"
	}
	return cleanURL
}

func extractHostname(url string) string {
	hostPort := extractHostPort(url)
	return strings.Split(hostPort, ":")[0]
}
