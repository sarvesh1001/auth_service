package service

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "go.uber.org/zap"

    "auth-service/internal/models"
    "auth-service/internal/util"
)

type DistributedCache struct {
    redis  *redis.Client
    ttl    time.Duration
    logger *zap.Logger
}

func NewDistributedCache(redisClient *redis.Client, logger *zap.Logger) *DistributedCache {
    return &DistributedCache{
        redis:  redisClient,
        ttl:    5 * time.Minute,
        logger: logger,
    }
}

func (dc *DistributedCache) GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error) {
    key := fmt.Sprintf("user:%s", userID.String())
    val, err := dc.redis.Get(ctx, key).Result()
    if err == redis.Nil {
        return nil, nil
    }
    if err != nil {
        dc.logger.Warn("Redis GetUser failed", util.ErrorField(err))
        return nil, err
    }
    var user models.User
    if err = json.Unmarshal([]byte(val), &user); err != nil {
        dc.logger.Warn("Redis Unmarshal user failed", util.ErrorField(err))
        return nil, err
    }
    return &user, nil
}

func (dc *DistributedCache) SetUser(ctx context.Context, user *models.User) error {
    key := fmt.Sprintf("user:%s", user.UserID.String())
    data, err := json.Marshal(user)
    if err != nil {
        return err
    }
    return dc.redis.Set(ctx, key, data, dc.ttl).Err()
}

func (dc *DistributedCache) GetUserByPhone(ctx context.Context, phoneHash string) (uuid.UUID, error) {
    key := fmt.Sprintf("phone:%s", phoneHash)
    val, err := dc.redis.Get(ctx, key).Result()
    if err == redis.Nil {
        return uuid.Nil, nil
    }
    if err != nil {
        dc.logger.Warn("Redis GetUserByPhone failed", util.ErrorField(err))
        return uuid.Nil, err
    }
    return uuid.Parse(val)
}

func (dc *DistributedCache) SetPhoneMapping(ctx context.Context, phoneHash string, userID uuid.UUID) error {
    key := fmt.Sprintf("phone:%s", phoneHash)
    return dc.redis.Set(ctx, key, userID.String(), dc.ttl).Err()
}

func (dc *DistributedCache) InvalidateUser(ctx context.Context, userID uuid.UUID) error {
    key := fmt.Sprintf("user:%s", userID.String())
    if err := dc.redis.Del(ctx, key).Err(); err != nil {
        dc.logger.Warn("Redis InvalidateUser failed", util.ErrorField(err))
        return err
    }
    return nil
}

func (dc *DistributedCache) InvalidatePhone(ctx context.Context, phoneHash string) error {
    key := fmt.Sprintf("phone:%s", phoneHash)
    if err := dc.redis.Del(ctx, key).Err(); err != nil {
        dc.logger.Warn("Redis InvalidatePhone failed", util.ErrorField(err))
        return err
    }
    return nil
}
