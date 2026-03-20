package idempotency

import (
	"context"
	"encoding/json"
	"time"

	"auth-service/internal/client"
)

type RedisCache struct {
	client *client.RedisClient
	ttl    time.Duration
}

func NewRedisCache(client *client.RedisClient, ttl time.Duration) *RedisCache {
	return &RedisCache{
		client: client,
		ttl:    ttl,
	}
}

// Get from Redis
func (r *RedisCache) Get(ctx context.Context, key string, target interface{}) (bool, error) {
	val, err := r.client.Get(ctx, key)
	if err != nil {
		return false, nil // cache miss
	}

	if err := json.Unmarshal([]byte(val), target); err != nil {
		return false, err
	}

	return true, nil
}

// Set in Redis
func (r *RedisCache) Set(ctx context.Context, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, data, r.ttl)
}
