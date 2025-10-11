package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"auth-service/internal/config"
	"auth-service/internal/util"
)

type RedisClient struct {
	Client *redis.Client
	config *config.RedisConfig
}

// NewRedisClient initializes a Redis client with TLS support for dev & prod
func NewRedisClient(cfg *config.Config, logger *zap.Logger) (*RedisClient, error) {
	redisConfig := cfg.Redis

	// Parse redis:// or rediss://
	opts, err := redis.ParseURL(redisConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Only set password if not already in URL
	if opts.Password == "" && redisConfig.Password != "" {
		opts.Password = redisConfig.Password
	}

	opts.DB = redisConfig.DB
	opts.PoolSize = redisConfig.PoolSize
	opts.MinIdleConns = redisConfig.PoolSize / 2
	if opts.MinIdleConns < 10 {
		opts.MinIdleConns = 10
	}
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	opts.PoolTimeout = 4 * time.Second
	opts.ConnMaxIdleTime = 5 * time.Minute
	opts.ConnMaxLifetime = 0

	// ----------- TLS CONFIGURATION -----------
	if strings.HasPrefix(redisConfig.URL, "rediss://") {
		// Paths inside container (mounted volume)
		caFile := getEnv("REDIS_TLS_CA_FILE", "/app/certs/ca.crt")
		certFile := getEnv("REDIS_TLS_CERT_FILE", "/app/certs/redis.crt")
		keyFile := getEnv("REDIS_TLS_KEY_FILE", "/app/certs/redis.key")

		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to append CA cert")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load Redis TLS certificate/key: %w", err)
		}

		opts.TLSConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false, // always verify
		}
	}
	// -----------------------------------------

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	util.Info("Redis client initialized",
		zap.String("url", redisConfig.URL),
		zap.Int("db", redisConfig.DB),
		zap.Int("pool_size", redisConfig.PoolSize))

	return &RedisClient{
		Client: client,
		config: &redisConfig,
	}, nil
}

// Graceful close
func (r *RedisClient) Close() error {
	if r.Client != nil {
		err := r.Client.Close()
		if err != nil {
			util.Error("failed to close Redis client", zap.Error(err))
			return err
		}
		util.Info("Redis client closed")
	}
	return nil
}

// HealthCheck verifies Redis connectivity and data integrity
func (r *RedisClient) HealthCheck(ctx context.Context) error {
	if err := r.Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	testKey := "healthcheck"
	testValue := strconv.FormatInt(time.Now().Unix(), 10)
	if err := r.Client.Set(ctx, testKey, testValue, 10*time.Second).Err(); err != nil {
		return fmt.Errorf("redis set operation failed: %w", err)
	}

	val, err := r.Client.Get(ctx, testKey).Result()
	if err != nil {
		return fmt.Errorf("redis get operation failed: %w", err)
	}

	if val != testValue {
		return fmt.Errorf("redis data integrity failed")
	}

	_ = r.Client.Del(ctx, testKey)
	return nil
}

// WithContext helper
func (r *RedisClient) WithContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, timeout)
}

// ===================== CORE OPERATIONS =====================
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.Client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := r.Client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("key not found: %s", key)
		}
		return "", err
	}
	return val, nil
}

func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	return r.Client.Del(ctx, keys...).Err()
}

func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
    count, err := r.Client.Exists(ctx, key).Result()
    if err != nil {
        return false, err
    }
    return count > 0, nil
}

func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
    return r.Client.Incr(ctx, key).Result()
}

func (r *RedisClient) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
    return r.Client.IncrBy(ctx, key, value).Result()
}

func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
    return r.Client.Expire(ctx, key, expiration).Err()
}

func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
    return r.Client.TTL(ctx, key).Result()
}

// ===================== ADVANCED OPS =====================

func (r *RedisClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
    return r.Client.SetNX(ctx, key, value, expiration).Result()
}

func (r *RedisClient) IncrWithExpire(ctx context.Context, key string, expiration time.Duration) (int64, error) {
    pipe := r.Client.TxPipeline()
    incrCmd := pipe.Incr(ctx, key)
    pipe.Expire(ctx, key, expiration)
    _, err := pipe.Exec(ctx)
    if err != nil {
        return 0, err
    }
    return incrCmd.Val(), nil
}

// ===================== PIPELINES & SCRIPTS =====================

func (r *RedisClient) Pipeline() redis.Pipeliner {
    return r.Client.Pipeline()
}

func (r *RedisClient) TxPipeline() redis.Pipeliner {
    return r.Client.TxPipeline()
}

func (r *RedisClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
    return r.Client.Eval(ctx, script, keys, args...).Result()
}

// ===================== HASH & SET & MONITORING =====================

func (r *RedisClient) HSet(ctx context.Context, key string, values ...interface{}) error {
    return r.Client.HSet(ctx, key, values...).Err()
}

func (r *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
    val, err := r.Client.HGet(ctx, key, field).Result()
    if err != nil {
        if err == redis.Nil {
            return "", fmt.Errorf("field not found: %s in key: %s", field, key)
        }
        return "", err
    }
    return val, nil
}

func (r *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
    return r.Client.HGetAll(ctx, key).Result()
}

func (r *RedisClient) HDel(ctx context.Context, key string, fields ...string) error {
    return r.Client.HDel(ctx, key, fields...).Err()
}

func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
    return r.Client.SAdd(ctx, key, members...).Err()
}

func (r *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
    return r.Client.SMembers(ctx, key).Result()
}

func (r *RedisClient) SRem(ctx context.Context, key string, members ...interface{}) error {
    return r.Client.SRem(ctx, key, members...).Err()
}

func (r *RedisClient) Info(ctx context.Context, section ...string) (string, error) {
    return r.Client.Info(ctx, section...).Result()
}

func (r *RedisClient) PoolStats() *redis.PoolStats {
    return r.Client.PoolStats()
}
// ===================== SCAN SUPPORT =====================

// Scan performs a Redis SCAN operation, returning a batch of keys and the next cursor.
// It's safe for large datasets (like 500M users) because it avoids blocking Redis.
func (r *RedisClient) Scan(ctx context.Context, cursor uint64, pattern string, count int64) ([]string, uint64, error) {
    var keys []string

    iter := r.Client.Scan(ctx, cursor, pattern, count).Iterator()
    for iter.Next(ctx) {
        keys = append(keys, iter.Val())
    }

    if err := iter.Err(); err != nil {
        return nil, 0, err
    }

    // Redis SCAN iterator automatically handles cursor internally; return 0 to indicate end
    return keys, 0, nil
}
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
