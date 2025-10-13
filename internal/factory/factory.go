package factory

import (
	"context"
	"sync"

	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/util"
    "auth-service/internal/repository/scylla"
	"go.uber.org/zap"
)

type ClientFactory struct {
	config *config.Config

	// Clients
	scyllaClient     *scylla.ScyllaClient
	redisClient      *client.RedisClient
	clickhouseClient *client.ClickHouseClient

	clientsMux sync.RWMutex
	logger     *zap.Logger
}

func NewClientFactory(cfg *config.Config, logger *zap.Logger) *ClientFactory {
	return &ClientFactory{
		config: cfg,
		logger: logger,
	}
}

// ==================== CLIENT METHODS ====================

func (f *ClientFactory) GetScyllaClient() (*scylla.ScyllaClient, error) {
	f.clientsMux.Lock()
	defer f.clientsMux.Unlock()

	if f.scyllaClient == nil {
		client, err := scylla.NewScyllaClient(f.config, f.logger)
		if err != nil {
			util.Error("Failed to create Scylla client", zap.Error(err))
			return nil, err
		}
		f.scyllaClient = client
		util.Info("Scylla client initialized successfully")
	}
	return f.scyllaClient, nil
}

func (f *ClientFactory) GetRedisClient() (*client.RedisClient, error) {
	f.clientsMux.Lock()
	defer f.clientsMux.Unlock()

	if f.redisClient == nil {
		client, err := client.NewRedisClient(f.config, f.logger)
		if err != nil {
			util.Error("Failed to create Redis client", zap.Error(err))
			return nil, err
		}
		f.redisClient = client
		util.Info("Redis client initialized successfully")
	}
	return f.redisClient, nil
}

func (f *ClientFactory) GetClickHouseClient() (*client.ClickHouseClient, error) {
	f.clientsMux.Lock()
	defer f.clientsMux.Unlock()

	if f.clickhouseClient == nil {
		client, err := client.NewClickHouseClient(f.config, f.logger)
		if err != nil {
			util.Error("Failed to create ClickHouse client", zap.Error(err))
			return nil, err
		}
		f.clickhouseClient = client
		util.Info("ClickHouse client initialized successfully")
	}
	return f.clickhouseClient, nil
}

// ==================== HEALTH CHECK ====================

func (f *ClientFactory) HealthCheck(ctx context.Context) map[string]string {
	status := make(map[string]string)

	// ScyllaDB health check
	if f.scyllaClient != nil {
		if err := f.scyllaClient.HealthCheck(); err != nil {
			status["scylla"] = "unhealthy"
			util.Warn("Scylla health check failed", zap.Error(err))
		} else {
			status["scylla"] = "healthy"
		}
	} else {
		status["scylla"] = "not_initialized"
	}

	// Redis health check
	if f.redisClient != nil {
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			status["redis"] = "unhealthy"
			util.Warn("Redis health check failed", zap.Error(err))
		} else {
			status["redis"] = "healthy"
		}
	} else {
		status["redis"] = "not_initialized"
	}

	// ClickHouse health check
	if f.clickhouseClient != nil {
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			status["clickhouse"] = "unhealthy"
			util.Warn("ClickHouse health check failed", zap.Error(err))
		} else {
			status["clickhouse"] = "healthy"
		}
	} else {
		status["clickhouse"] = "not_initialized"
	}

	return status
}

// ==================== CLEANUP ====================

func (f *ClientFactory) CloseAll() {
	f.clientsMux.Lock()
	defer f.clientsMux.Unlock()

	if f.scyllaClient != nil {
		f.scyllaClient.Close()
		f.scyllaClient = nil
		util.Info("Scylla client closed")
	}

	if f.redisClient != nil {
		f.redisClient.Close()
		f.redisClient = nil
		util.Info("Redis client closed")
	}

	if f.clickhouseClient != nil {
		f.clickhouseClient.Close()
		f.clickhouseClient = nil
		util.Info("ClickHouse client closed")
	}

	util.Info("All factory clients closed and reset")
}
