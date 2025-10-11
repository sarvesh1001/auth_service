package factory

import (
    "sync"

    "auth-service/internal/client"
    "auth-service/internal/config"
    "auth-service/internal/repository/redis"
    "auth-service/internal/repository/scylla"
    "auth-service/internal/util"
	"context"
    "go.uber.org/zap"
)

type ClientFactory struct {
    config *config.Config

    // Clients
    scyllaClient *scylla.ScyllaClient
    redisClient  *client.RedisClient
    elastic      *client.ESClient
    kafkaProd    *client.KafkaProducer

    // Repository instances
    userRepo    *scylla.UserRepository
    otpRepo     *scylla.OTPRepository
    mpinRepo    *scylla.MPINRepository
    sessionRepo *scylla.DeviceSessionRepository

    // Cache instances
    otpCache       *redis.OTPCache
    mpinCache      *redis.MPINCache
    sessionCache   *redis.SessionCache
    rateLimitCache *redis.RateLimitCache

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

func (f *ClientFactory) GetElasticsearchClient() (*client.ESClient, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.elastic == nil {
        client, err := client.NewElasticsearchClient(f.config, f.logger)
        if err != nil {
            util.Error("Failed to create Elasticsearch client", zap.Error(err))
            return nil, err
        }
        f.elastic = client
        util.Info("Elasticsearch client initialized successfully")
    }
    return f.elastic, nil
}

func (f *ClientFactory) GetKafkaProducer() (*client.KafkaProducer, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.kafkaProd == nil {
        client, err := client.NewKafkaProducer(f.config, f.logger)
        if err != nil {
            util.Error("Failed to create Kafka producer", zap.Error(err))
            return nil, err
        }
        f.kafkaProd = client
        util.Info("Kafka producer initialized successfully")
    }
    return f.kafkaProd, nil
}

// ==================== REPOSITORY METHODS ====================

func (f *ClientFactory) GetUserRepository() (*scylla.UserRepository, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.userRepo == nil {
        client, err := f.GetScyllaClient()
        if err != nil {
            return nil, err
        }
        f.userRepo = scylla.NewUserRepository(client, f.logger)
        util.Debug("User repository initialized")
    }
    return f.userRepo, nil
}

func (f *ClientFactory) GetOTPRepository() (*scylla.OTPRepository, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.otpRepo == nil {
        client, err := f.GetScyllaClient()
        if err != nil {
            return nil, err
        }
        f.otpRepo = scylla.NewOTPRepository(client, f.logger)
        util.Debug("OTP repository initialized")
    }
    return f.otpRepo, nil
}

func (f *ClientFactory) GetMPINRepository() (*scylla.MPINRepository, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.mpinRepo == nil {
        client, err := f.GetScyllaClient()
        if err != nil {
            return nil, err
        }
        f.mpinRepo = scylla.NewMPINRepository(client, f.logger)
        util.Debug("MPIN repository initialized")
    }
    return f.mpinRepo, nil
}

func (f *ClientFactory) GetSessionRepository() (*scylla.DeviceSessionRepository, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.sessionRepo == nil {
        client, err := f.GetScyllaClient()
        if err != nil {
            return nil, err
        }
        f.sessionRepo = scylla.NewDeviceSessionRepository(client, f.logger)
        util.Debug("Session repository initialized")
    }
    return f.sessionRepo, nil
}

// ==================== CACHE METHODS ====================

func (f *ClientFactory) GetOTPCache() (*redis.OTPCache, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.otpCache == nil {
        client, err := f.GetRedisClient()
        if err != nil {
            return nil, err
        }
        f.otpCache = redis.NewOTPCache(client)
        util.Debug("OTP cache initialized")
    }
    return f.otpCache, nil
}

func (f *ClientFactory) GetMPINCache() (*redis.MPINCache, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.mpinCache == nil {
        client, err := f.GetRedisClient()
        if err != nil {
            return nil, err
        }
        f.mpinCache = redis.NewMPINCache(client)

        util.Debug("MPIN cache initialized")
    }
    return f.mpinCache, nil
}

func (f *ClientFactory) GetSessionCache() (*redis.SessionCache, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.sessionCache == nil {
        client, err := f.GetRedisClient()
        if err != nil {
            return nil, err
        }
        f.sessionCache = redis.NewSessionCache(client)
        util.Debug("Session cache initialized")
    }
    return f.sessionCache, nil
}

func (f *ClientFactory) GetRateLimitCache() (*redis.RateLimitCache, error) {
    f.clientsMux.Lock()
    defer f.clientsMux.Unlock()

    if f.rateLimitCache == nil {
        client, err := f.GetRedisClient()
        if err != nil {
            return nil, err
        }
        f.rateLimitCache = redis.NewRateLimitCache(client)
        util.Debug("Rate limit cache initialized")
    }
    return f.rateLimitCache, nil
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

    // Optionally close elastic and kafka if used similarly

    // Reset repositories and caches
    f.userRepo = nil
    f.otpRepo = nil
    f.mpinRepo = nil
    f.sessionRepo = nil

    f.otpCache = nil
    f.mpinCache = nil
    f.sessionCache = nil
    f.rateLimitCache = nil

    util.Info("All factory clients closed and reset")
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
        if err := f.redisClient.HealthCheck(ctx); err != nil { // ✅ pass context here
            status["redis"] = "unhealthy"
            util.Warn("Redis health check failed", zap.Error(err))
        } else {
            status["redis"] = "healthy"
        }
    } else {
        status["redis"] = "not_initialized"
    }

    return status
}
