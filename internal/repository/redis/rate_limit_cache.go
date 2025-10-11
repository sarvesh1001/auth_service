package redis

import (
    "context"
    "fmt"
    "strconv"
    "time"
	"go.uber.org/zap"             // needed for zap.Field in util calls
	redis "github.com/redis/go-redis/v9"

    "auth-service/internal/client"
    "auth-service/internal/util"
)

const (
    rateLimitPrefix     = "rate_limit:"
    tempLockPrefix      = "temp_lock:"
    ipRateLimitPrefix   = "ip_rate_limit:"
    userRateLimitPrefix = "user_rate_limit:"
    globalRateLimitPrefix = "global_rate_limit:"
    deviceRateLimitPrefix = "device_rate_limit:"
)

type RateLimitCache struct {
    client *client.RedisClient
}

func NewRateLimitCache(client *client.RedisClient) *RateLimitCache {
    return &RateLimitCache{client: client}
}

func (c *RateLimitCache) SetTemporaryLock(key string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    lockKey := tempLockPrefix + key
    success, err := c.client.SetNX(ctx, lockKey, "locked", ttl)
    if err != nil {
        util.Error("Failed to set temporary lock", zap.String("key", key), zap.Duration("ttl", ttl), zap.Error(err))
        return fmt.Errorf("failed to set temporary lock: %w", err)
    }
    if !success {
        return fmt.Errorf("temporary lock already exists for key: %s", key)
    }
    util.Debug("Temporary lock set", zap.String("key", key), zap.Duration("ttl", ttl))
    return nil
}

// ... IsUserLocked, IncrementCounter, GetCounter, ResetCounter,
//     IncrementIPCounter, GetIPCounter, SetIPLock, IsIPLocked,
//     IncrementUserCounter, GetUserCounter, SetUserLock, IsUserOperationLocked,
//     IncrementDeviceCounter, GetDeviceCounter, SetDeviceLock, IsDeviceLocked,
//     IncrementGlobalCounter, GetGlobalCounter,
//     SlidingWindowRateLimit, TokenBucketRateLimit,
//     CheckMultipleRateLimits, GetRateLimitInfo, GetRateLimitStats,
//     CleanupExpiredRateLimits, ResetMultipleCounters, SetMultipleLocks ...

func (c *RateLimitCache) IsUserLocked(key string) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    lockKey := tempLockPrefix + key

    exists, err := c.client.Exists(ctx, lockKey)
    if err != nil {
        util.Error("Failed to check user lock",
            zap.String("key", key),
            zap.Error(err))
        return false, fmt.Errorf("failed to check user lock: %w", err)
    }

    return exists, nil
}

func (c *RateLimitCache) IncrementCounter(key string, ttl time.Duration) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    rateLimitKey := rateLimitPrefix + key

    count, err := c.client.IncrWithExpire(ctx, rateLimitKey, ttl)
    if err != nil {
        util.Error("Failed to increment rate limit counter",
            zap.String("key", key),
            zap.Duration("ttl", ttl),
            zap.Error(err))
        return 0, fmt.Errorf("failed to increment rate limit counter: %w", err)
    }

    util.Debug("Rate limit counter incremented",
        zap.String("key", key),
        zap.Int64("count", count),
        zap.Duration("ttl", ttl))

    return int(count), nil
}

func (c *RateLimitCache) GetCounter(key string) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    rateLimitKey := rateLimitPrefix + key

    countStr, err := c.client.Get(ctx, rateLimitKey)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", rateLimitKey) {
            return 0, nil // No counter set yet
        }
        return 0, fmt.Errorf("failed to get rate limit counter: %w", err)
    }

    count, err := strconv.Atoi(countStr)
    if err != nil {
        util.Error("Invalid counter format",
            zap.String("key", key),
            zap.String("count_str", countStr),
            zap.Error(err))
        return 0, fmt.Errorf("invalid counter format: %w", err)
    }

    return count, nil
}

func (c *RateLimitCache) ResetCounter(key string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    keys := []string{
        rateLimitPrefix + key,
        tempLockPrefix + key,
    }

    if err := c.client.Del(ctx, keys...); err != nil {
        util.Error("Failed to reset rate limit counter",
            zap.String("key", key),
            zap.Error(err))
        return fmt.Errorf("failed to reset rate limit counter: %w", err)
    }

    util.Debug("Rate limit counter reset",
        zap.String("key", key))

    return nil
}

// Advanced rate limiting by different criteria

// IP-based rate limiting
func (c *RateLimitCache) IncrementIPCounter(ipAddress string, ttl time.Duration) (int, error) {
    key := ipRateLimitPrefix + ipAddress
    return c.IncrementCounter(key, ttl)
}

func (c *RateLimitCache) GetIPCounter(ipAddress string) (int, error) {
    key := ipRateLimitPrefix + ipAddress
    return c.GetCounter(key)
}

func (c *RateLimitCache) SetIPLock(ipAddress string, ttl time.Duration) error {
    key := ipRateLimitPrefix + ipAddress
    return c.SetTemporaryLock(key, ttl)
}

func (c *RateLimitCache) IsIPLocked(ipAddress string) (bool, error) {
    key := ipRateLimitPrefix + ipAddress
    return c.IsUserLocked(key)
}

// User-based rate limiting
func (c *RateLimitCache) IncrementUserCounter(userID string, operation string, ttl time.Duration) (int, error) {
    key := fmt.Sprintf("%s%s:%s", userRateLimitPrefix, userID, operation)
    return c.IncrementCounter(key, ttl)
}

func (c *RateLimitCache) GetUserCounter(userID string, operation string) (int, error) {
    key := fmt.Sprintf("%s%s:%s", userRateLimitPrefix, userID, operation)
    return c.GetCounter(key)
}

func (c *RateLimitCache) SetUserLock(userID string, operation string, ttl time.Duration) error {
    key := fmt.Sprintf("%s%s:%s", userRateLimitPrefix, userID, operation)
    return c.SetTemporaryLock(key, ttl)
}

func (c *RateLimitCache) IsUserOperationLocked(userID string, operation string) (bool, error) {
    key := fmt.Sprintf("%s%s:%s", userRateLimitPrefix, userID, operation)
    return c.IsUserLocked(key)
}

// Device-based rate limiting
func (c *RateLimitCache) IncrementDeviceCounter(deviceID string, operation string, ttl time.Duration) (int, error) {
    key := fmt.Sprintf("%s%s:%s", deviceRateLimitPrefix, deviceID, operation)
    return c.IncrementCounter(key, ttl)
}

func (c *RateLimitCache) GetDeviceCounter(deviceID string, operation string) (int, error) {
    key := fmt.Sprintf("%s%s:%s", deviceRateLimitPrefix, deviceID, operation)
    return c.GetCounter(key)
}

func (c *RateLimitCache) SetDeviceLock(deviceID string, operation string, ttl time.Duration) error {
    key := fmt.Sprintf("%s%s:%s", deviceRateLimitPrefix, deviceID, operation)
    return c.SetTemporaryLock(key, ttl)
}

func (c *RateLimitCache) IsDeviceLocked(deviceID string, operation string) (bool, error) {
    key := fmt.Sprintf("%s%s:%s", deviceRateLimitPrefix, deviceID, operation)
    return c.IsUserLocked(key)
}

// Global rate limiting (for system-wide limits)
func (c *RateLimitCache) IncrementGlobalCounter(operation string, ttl time.Duration) (int, error) {
    key := globalRateLimitPrefix + operation
    return c.IncrementCounter(key, ttl)
}

func (c *RateLimitCache) GetGlobalCounter(operation string) (int, error) {
    key := globalRateLimitPrefix + operation
    return c.GetCounter(key)
}

// Sliding window rate limiting
func (c *RateLimitCache) SlidingWindowRateLimit(key string, limit int, window time.Duration) (bool, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    now := time.Now().Unix()
    windowStart := now - int64(window.Seconds())

    // Use Lua script for atomic sliding window implementation
    luaScript := `
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window_start = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])

        -- Remove expired entries
        redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

        -- Count current entries
        local current_count = redis.call('ZCARD', key)

        if current_count < limit then
            -- Add current timestamp
            redis.call('ZADD', key, now, now)
            redis.call('EXPIRE', key, math.ceil(tonumber(ARGV[4])))
            return {1, current_count + 1}
        else
            return {0, current_count}
        end
    `

    result, err := c.client.Eval(ctx, luaScript, []string{rateLimitPrefix + key}, 
        now, windowStart, limit, int(window.Seconds()))
    if err != nil {
        util.Error("Failed to execute sliding window rate limit",
            zap.String("key", key),
            zap.Int("limit", limit),
            zap.Duration("window", window),
            zap.Error(err))
        return false, 0, fmt.Errorf("failed to execute sliding window rate limit: %w", err)
    }

    resultSlice, ok := result.([]interface{})
    if !ok || len(resultSlice) != 2 {
        return false, 0, fmt.Errorf("unexpected result format from sliding window script")
    }

    allowed := resultSlice[0].(int64) == 1
    currentCount := int(resultSlice[1].(int64))

    util.Debug("Sliding window rate limit check",
        zap.String("key", key),
        zap.Bool("allowed", allowed),
        zap.Int("current_count", currentCount),
        zap.Int("limit", limit))

    return allowed, currentCount, nil
}

// Token bucket rate limiting
func (c *RateLimitCache) TokenBucketRateLimit(key string, capacity, refillRate int, window time.Duration) (bool, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    now := time.Now().Unix()

    // Use Lua script for atomic token bucket implementation
    luaScript := `
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local refill_rate = tonumber(ARGV[3])
        local window_seconds = tonumber(ARGV[4])

        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or now

        -- Calculate tokens to add based on time passed
        local time_passed = now - last_refill
        local tokens_to_add = math.floor(time_passed * refill_rate / window_seconds)
        tokens = math.min(capacity, tokens + tokens_to_add)

        if tokens > 0 then
            tokens = tokens - 1
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
            redis.call('EXPIRE', key, window_seconds * 2)
            return {1, tokens}
        else
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
            redis.call('EXPIRE', key, window_seconds * 2)
            return {0, tokens}
        end
    `

    result, err := c.client.Eval(ctx, luaScript, []string{rateLimitPrefix + key}, 
        now, capacity, refillRate, int(window.Seconds()))
    if err != nil {
        util.Error("Failed to execute token bucket rate limit",
            zap.String("key", key),
            zap.Int("capacity", capacity),
            zap.Int("refill_rate", refillRate),
            zap.Error(err))
        return false, 0, fmt.Errorf("failed to execute token bucket rate limit: %w", err)
    }

    resultSlice, ok := result.([]interface{})
    if !ok || len(resultSlice) != 2 {
        return false, 0, fmt.Errorf("unexpected result format from token bucket script")
    }

    allowed := resultSlice[0].(int64) == 1
    remainingTokens := int(resultSlice[1].(int64))

    util.Debug("Token bucket rate limit check",
        zap.String("key", key),
        zap.Bool("allowed", allowed),
        zap.Int("remaining_tokens", remainingTokens),
        zap.Int("capacity", capacity))

    return allowed, remainingTokens, nil
}

// Complex rate limiting scenarios

func (c *RateLimitCache) CheckMultipleRateLimits(checks []RateLimitCheck) ([]RateLimitResult, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    pipe := c.client.Pipeline()
    var results []RateLimitResult

    // Execute all checks in pipeline for better performance
    for _, check := range checks {
        rateLimitKey := rateLimitPrefix + check.Key
        pipe.Get(ctx, rateLimitKey)
        lockKey := tempLockPrefix + check.Key
        pipe.Exists(ctx, lockKey)
    }

    pipeResults, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to execute multiple rate limit checks", zap.Error(err))
        return nil, fmt.Errorf("failed to execute multiple rate limit checks: %w", err)
    }

    // Process results
    for i, check := range checks {
        result := RateLimitResult{Key: check.Key}

        // Get counter value
        getCmd := pipeResults[i*2]
        if getCmd.Err() == nil {
            if countStr, ok := getCmd.(*redis.StringCmd); ok {
                if count, err := strconv.Atoi(countStr.Val()); err == nil {
                    result.CurrentCount = count
                    result.Allowed = count < check.Limit
                }
            }
        } else {
            result.Allowed = true // No counter means first request
        }

        // Get lock status
        existsCmd := pipeResults[i*2+1]
        if existsCmd.Err() == nil {
            if existsResult, ok := existsCmd.(*redis.IntCmd); ok {
                result.IsLocked = existsResult.Val() > 0
                if result.IsLocked {
                    result.Allowed = false
                }
            }
        }

        results = append(results, result)
    }

    return results, nil
}

// Rate limit configuration and statistics

func (c *RateLimitCache) GetRateLimitInfo(key string) (*RateLimitInfo, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    info := &RateLimitInfo{Key: key}

    // Get counter
    count, err := c.GetCounter(key)
    if err == nil {
        info.CurrentCount = count
    }

    // Get TTL
    rateLimitKey := rateLimitPrefix + key
    ttl, err := c.client.TTL(ctx, rateLimitKey)
    if err == nil {
        info.TTL = ttl
    }

    // Check if locked
    locked, err := c.IsUserLocked(key)
    if err == nil {
        info.IsLocked = locked
    }

    // Get lock TTL if locked
    if info.IsLocked {
        lockKey := tempLockPrefix + key
        lockTTL, err := c.client.TTL(ctx, lockKey)
        if err == nil {
            info.LockTTL = lockTTL
        }
    }

    return info, nil
}

// Statistics and monitoring

func (c *RateLimitCache) GetRateLimitStats() (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    stats := make(map[string]interface{})

    patterns := map[string]string{
        "rate_limits":     rateLimitPrefix + "*",
        "temp_locks":      tempLockPrefix + "*",
        "ip_rate_limits":  ipRateLimitPrefix + "*",
        "user_rate_limits": userRateLimitPrefix + "*",
        "device_rate_limits": deviceRateLimitPrefix + "*",
        "global_rate_limits": globalRateLimitPrefix + "*",
    }

    for statName, pattern := range patterns {
        keys, _, err := c.client.Scan(ctx, 0, pattern, 1000)
        if err != nil {
            util.Warn("Failed to scan keys for rate limit stats",
                zap.String("pattern", pattern),
                zap.Error(err))
            stats[statName] = 0
        } else {
            stats[statName] = len(keys)
        }
    }

    return stats, nil
}


// Cleanup operations

func (c *RateLimitCache) CleanupExpiredRateLimits() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    patterns := []string{
        rateLimitPrefix + "*",
        tempLockPrefix + "*",
        ipRateLimitPrefix + "*",
        userRateLimitPrefix + "*",
        deviceRateLimitPrefix + "*",
        globalRateLimitPrefix + "*",
    }

    totalCleaned := 0
    for _, pattern := range patterns {
        cursor := uint64(0)
        for {
            keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100)
            if err != nil {
                util.Error("Failed to scan keys for rate limit cleanup",
                    zap.String("pattern", pattern),
                    zap.Error(err))
                break
            }

            // Check TTL for each key
            for _, key := range keys {
                ttl, err := c.client.TTL(ctx, key)
                if err != nil {
                    continue
                }

                // Log keys without proper TTL
                if ttl == -1 {
                    util.Warn("Found rate limit key without TTL", zap.String("key", key))
                }
            }

            totalCleaned += len(keys)
            cursor = nextCursor
            if cursor == 0 {
                break
            }
        }
    }

    util.Info("Rate limit cleanup completed", zap.Int("keys_checked", totalCleaned))
    return nil
}

// Helper types for complex operations

type RateLimitCheck struct {
    Key   string
    Limit int
}

type RateLimitResult struct {
    Key          string
    Allowed      bool
    CurrentCount int
    IsLocked     bool
}

type RateLimitInfo struct {
    Key          string
    CurrentCount int
    TTL          time.Duration
    IsLocked     bool
    LockTTL      time.Duration
}

// Batch operations for performance

func (c *RateLimitCache) ResetMultipleCounters(keys []string) error {
    if len(keys) == 0 {
        return nil
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var allKeys []string
    for _, key := range keys {
        allKeys = append(allKeys, rateLimitPrefix+key, tempLockPrefix+key)
    }

    if err := c.client.Del(ctx, allKeys...); err != nil {
        util.Error("Failed to reset multiple rate limit counters",
            zap.Int("key_count", len(keys)),
            zap.Error(err))
        return fmt.Errorf("failed to reset multiple rate limit counters: %w", err)
    }

    util.Info("Multiple rate limit counters reset",
        zap.Int("key_count", len(keys)))

    return nil
}

func (c *RateLimitCache) SetMultipleLocks(keys []string, ttl time.Duration) error {
    if len(keys) == 0 {
        return nil
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    pipe := c.client.Pipeline()

    for _, key := range keys {
        lockKey := tempLockPrefix + key
        pipe.Set(ctx, lockKey, "locked", ttl)
    }

    _, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to set multiple temporary locks",
            zap.Int("key_count", len(keys)),
            zap.Duration("ttl", ttl),
            zap.Error(err))
        return fmt.Errorf("failed to set multiple temporary locks: %w", err)
    }

    util.Info("Multiple temporary locks set",
        zap.Int("key_count", len(keys)),
        zap.Duration("ttl", ttl))

    return nil
}
