// internal/service/distributed_cache_otp.go
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
	"auth-service/internal/service/security"
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

// ✅ NEW: Enhanced rate limiting with sliding window
type RateLimitResult struct {
	Allowed    bool
	RetryAfter int
	Remaining  int
	Limit      int
}

// ✅ NEW: AllowRateWithSlidingWindow implements sliding window rate limiting
func (dc *DistributedCache) AllowRateWithSlidingWindow(
	ctx context.Context,
	key string,
	maxRequests int,
	window time.Duration,
) (*RateLimitResult, error) {
	now := time.Now().UnixMilli()
	windowMs := window.Milliseconds()
	clearBefore := now - windowMs

	// Remove old timestamps
	_, err := dc.redis.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", clearBefore)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to clean old timestamps: %w", err)
	}

	// Get current count
	count, err := dc.redis.ZCard(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get current count: %w", err)
	}

	if count >= int64(maxRequests) {
		// Get oldest timestamp to calculate retry time
		oldest, err := dc.redis.ZRange(ctx, key, 0, 0).Result()
		if err != nil || len(oldest) == 0 {
			return &RateLimitResult{
				Allowed:    false,
				RetryAfter: int(window.Seconds()),
			}, nil
		}

		var oldestTime int64
		if err := json.Unmarshal([]byte(oldest[0]), &oldestTime); err != nil {
			return &RateLimitResult{
				Allowed:    false,
				RetryAfter: int(window.Seconds()),
			}, nil
		}

		retryAfter := int((time.UnixMilli(oldestTime).Add(window).Sub(time.Now()).Seconds()))
		if retryAfter < 0 {
			retryAfter = 1
		}

		return &RateLimitResult{
			Allowed:    false,
			RetryAfter: retryAfter,
			Remaining:  0,
			Limit:      maxRequests,
		}, nil
	}

	// Add current timestamp
	member, _ := json.Marshal(now)
	if err := dc.redis.ZAdd(ctx, key, redis.Z{
		Score:  float64(now),
		Member: member,
	}).Err(); err != nil {
		return nil, fmt.Errorf("failed to add timestamp: %w", err)
	}

	// Set expiry on the key
	if err := dc.redis.Expire(ctx, key, window).Err(); err != nil {
		dc.logger.Warn("Failed to set expiry on rate limit key", util.ErrorField(err))
	}

	return &RateLimitResult{
		Allowed:    true,
		RetryAfter: 0,
		Remaining:  maxRequests - int(count) - 1,
		Limit:      maxRequests,
	}, nil
}

// ✅ NEW: AllowRateWithIncreasingCooldown implements progressive cooldown
func (dc *DistributedCache) AllowRateWithIncreasingCooldown(
	ctx context.Context,
	key string,
	baseCooldown time.Duration,
	maxCooldown time.Duration,
) (bool, int) {

	// Get current attempt count
	countStr, err := dc.redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		dc.logger.Warn("Redis Get failed in AllowRateWithIncreasingCooldown", util.ErrorField(err))
		return true, 0
	}

	var attemptCount int
	if countStr != "" {
		fmt.Sscanf(countStr, "%d", &attemptCount)
	}

	// Calculate cooldown (increases with attempts)
	cooldown := baseCooldown * time.Duration(attemptCount+1)
	if cooldown > maxCooldown {
		cooldown = maxCooldown
	}

	// Check if in cooldown
	cooldownKey := key + ":cooldown"
	ttl, err := dc.redis.TTL(ctx, cooldownKey).Result()
	if err == nil && ttl > 0 {
		return false, int(ttl.Seconds())
	}

	// Set cooldown if this attempt exceeds limit
	if attemptCount >= 0 { // Always increment for tracking
		attemptCount++
		err = dc.redis.Set(ctx, key, fmt.Sprintf("%d", attemptCount), 24*time.Hour).Err()
		if err != nil {
			dc.logger.Warn("Redis Set failed", util.ErrorField(err))
		}

		// Set cooldown
		err = dc.redis.Set(ctx, cooldownKey, "1", cooldown).Err()
		if err != nil {
			dc.logger.Warn("Redis Set cooldown failed", util.ErrorField(err))
		}
	}

	return true, 0
}

// ✅ NEW: Store OTP replay protection
func (dc *DistributedCache) StoreOTPReplayProtection(ctx context.Context, key string, otpHash string, ttl time.Duration) error {
	return dc.redis.Set(ctx, key, otpHash, ttl).Err()
}

// ✅ NEW: Check OTP replay protection
func (dc *DistributedCache) CheckOTPReplayProtection(ctx context.Context, key string) (bool, error) {
	exists, err := dc.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// ✅ NEW: Get daily quota usage
func (dc *DistributedCache) GetDailyQuotaUsage(ctx context.Context, key string) (int64, error) {
	count, err := dc.redis.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// ✅ NEW: Increment daily quota with TTL reset
func (dc *DistributedCache) IncrementDailyQuota(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := dc.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set TTL on first increment or reset if needed
	if count == 1 {
		dc.redis.Expire(ctx, key, ttl)
	}

	return count, nil
}

// Existing methods remain the same...
func (dc *DistributedCache) SetOTPVerification(ctx context.Context, key string, otp *models.OTPVerification, ttl time.Duration) error {
	data, err := json.Marshal(otp)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	if err := dc.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to cache OTP: %w", err)
	}

	return nil
}

func (dc *DistributedCache) GetOTPVerification(ctx context.Context, key string) (*models.OTPVerification, error) {
	data, err := dc.redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("OTP not found in cache: %w", err)
	}

	var otp models.OTPVerification
	if err := json.Unmarshal(data, &otp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}

	return &otp, nil
}

func (dc *DistributedCache) DeleteOTPVerification(ctx context.Context, key string) error {
	return dc.redis.Del(ctx, key).Err()
}

func (dc *DistributedCache) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := dc.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	if count == 1 {
		dc.redis.Expire(ctx, key, ttl)
	}

	return count, nil
}

func (dc *DistributedCache) SetWithExpiry(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return dc.redis.Set(ctx, key, value, ttl).Err()
}

func (dc *DistributedCache) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := dc.redis.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

func (dc *DistributedCache) DeleteKey(ctx context.Context, key string) error {
	return dc.redis.Del(ctx, key).Err()
}

func (dc *DistributedCache) AllowRate(ctx context.Context, key string, max int, window time.Duration) (bool, int) {
	count, err := dc.redis.Incr(ctx, key).Result()
	if err != nil {
		dc.logger.Warn("Redis AllowRate INCR failed", util.ErrorField(err))
		return true, 0
	}

	if count == 1 {
		err = dc.redis.Expire(ctx, key, window).Err()
		if err != nil {
			dc.logger.Warn("Redis AllowRate EXPIRE failed", util.ErrorField(err))
		}
	}

	if count <= int64(max) {
		return true, 0
	}

	ttl, err := dc.redis.TTL(ctx, key).Result()
	if err != nil {
		ttl = window
	}

	retry := int(ttl.Seconds())
	if retry < 1 {
		retry = 1
	}

	return false, retry
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
func (dc *DistributedCache) Delete(ctx context.Context, key string) error {
	err := dc.redis.Del(ctx, key).Err()
	if err != nil {
		dc.logger.Warn("Redis Delete failed", util.String("key", key), util.ErrorField(err))
		return err
	}
	return nil
}

// ✅ NEW: IP Reputation caching
func (dc *DistributedCache) CacheIPReputation(ctx context.Context, ip string, data *security.IPInfo, ttl time.Duration) error {
	key := fmt.Sprintf("ip_rep:%s", ip)
	return dc.SetWithExpiry(ctx, key, data, ttl)
}

func (dc *DistributedCache) GetIPReputation(ctx context.Context, ip string) (*security.IPInfo, error) {
	key := fmt.Sprintf("ip_rep:%s", ip)
	var info security.IPInfo
	err := dc.Get(ctx, key, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// ✅ NEW: Bot fingerprint caching
func (dc *DistributedCache) CacheBotFingerprint(ctx context.Context, fingerprint string, isBot bool, ttl time.Duration) error {
	key := fmt.Sprintf("bot_fp:%s", fingerprint)
	return dc.SetWithExpiry(ctx, key, isBot, ttl)
}

func (dc *DistributedCache) GetBotFingerprint(ctx context.Context, fingerprint string) (bool, error) {
	key := fmt.Sprintf("bot_fp:%s", fingerprint)
	var isBot bool
	err := dc.Get(ctx, key, &isBot)
	if err != nil {
		return false, err
	}
	return isBot, nil
}

// ✅ NEW: Key existence check
func (dc *DistributedCache) KeyExists(ctx context.Context, key string) (bool, error) {
	exists, err := dc.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// ✅ NEW: Get counter value
func (dc *DistributedCache) GetCounter(ctx context.Context, key string) (int64, error) {
	val, err := dc.redis.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}
