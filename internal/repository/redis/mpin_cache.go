package redis

import (
    "context"
    "fmt"
    "strconv"
    "time"
    "strings"       // needed for strings.Split

    "auth-service/internal/client"
    "auth-service/internal/util"
    "go.uber.org/zap"
)

const (
    mpinRetryPrefix     = "mpin_retry:"
    mpinLockPrefix      = "mpin_lock:"
    mpinCooldownPrefix  = "mpin_cooldown:"
    mpinTempBlockPrefix = "mpin_temp_block:"
)

type MPINCache struct {
    client *client.RedisClient
}

func NewMPINCache(c *client.RedisClient) *MPINCache {
    return &MPINCache{client: c}
}

func (c *MPINCache) SetMPINRetryCount(userID string, count int, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    key := mpinRetryPrefix + userID
    if err := c.client.Set(ctx, key, strconv.Itoa(count), ttl); err != nil {
        util.Error("Failed to set MPIN retry count",
            zap.String("user_id", userID),
            zap.Int("count", count),
            zap.Duration("ttl", ttl),
            zap.Error(err),
        )
        return fmt.Errorf("failed to set MPIN retry count: %w", err)
    }
    util.Debug("MPIN retry count set",
        zap.String("user_id", userID),
        zap.Int("count", count),
        zap.Duration("ttl", ttl),
    )
    return nil
}

func (c *MPINCache) GetMPINRetryCount(userID string) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    key := mpinRetryPrefix + userID
    s, err := c.client.Get(ctx, key)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", key) {
            return 0, nil
        }
        util.Error("Failed to get MPIN retry count",
            zap.String("user_id", userID),
            zap.Error(err),
        )
        return 0, fmt.Errorf("failed to get MPIN retry count: %w", err)
    }
    count, err := strconv.Atoi(s)
    if err != nil {
        util.Error("Invalid MPIN retry count format",
            zap.String("user_id", userID),
            zap.String("count_str", s),
            zap.Error(err),
        )
        return 0, fmt.Errorf("invalid MPIN retry count format: %w", err)
    }
    return count, nil
}

func (c *MPINCache) IncrementMPINRetry(userID string, ttl time.Duration) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    key := mpinRetryPrefix + userID
    cnt, err := c.client.IncrWithExpire(ctx, key, ttl)
    if err != nil {
        util.Error("Failed to increment MPIN retry count",
            zap.String("user_id", userID),
            zap.Error(err),
        )
        return 0, fmt.Errorf("failed to increment MPIN retry count: %w", err)
    }
    util.Debug("MPIN retry count incremented",
        zap.String("user_id", userID),
        zap.Int64("count", cnt),
    )
    if cnt >= 5 {
        if err := c.SetMPINTempBlock(userID, 15*time.Minute); err != nil {
            util.Error("Failed to set MPIN temporary block",
                zap.String("user_id", userID),
                zap.Error(err),
            )
        }
    }
    return int(cnt), nil
}

func (c *MPINCache) ResetMPINRetryCount(userID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    key := mpinRetryPrefix + userID
    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to reset MPIN retry count",
            zap.String("user_id", userID),
            zap.Error(err),
        )
        return fmt.Errorf("failed to reset MPIN retry count: %w", err)
    }
    util.Debug("MPIN retry count reset",
        zap.String("user_id", userID),
    )
    return nil
}

// ... (rest of methods unchanged, using zap.* fields in util.X calls) ...

// ... the rest of the methods follow the same pattern: constructor accepts only *client.RedisClient,
//    all logging calls via util.Debug/Info/Warn/Error, and no import of go.uber.org/zap ...

// MPIN locking mechanisms

func (c *MPINCache) SetMPINLock(userID string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinLockPrefix + userID

    success, err := c.client.SetNX(ctx, key, "locked", ttl)
    if err != nil {
        util.Error("Failed to set MPIN lock",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to set MPIN lock: %w", err)
    }

    if !success {
        return fmt.Errorf("MPIN already locked for user: %s", userID)
    }

    util.Warn("MPIN locked for user",
        zap.String("user_id", userID),
        zap.Duration("ttl", ttl))

    return nil
}

func (c *MPINCache) IsMPINLocked(userID string) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinLockPrefix + userID

    exists, err := c.client.Exists(ctx, key)
    if err != nil {
        util.Error("Failed to check MPIN lock",
            zap.String("user_id", userID),
            zap.Error(err))
        return false, fmt.Errorf("failed to check MPIN lock: %w", err)
    }

    return exists, nil
}

func (c *MPINCache) RemoveMPINLock(userID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    keys := []string{
        mpinLockPrefix + userID,
        mpinRetryPrefix + userID,
        mpinTempBlockPrefix + userID,
    }

    if err := c.client.Del(ctx, keys...); err != nil {
        util.Error("Failed to remove MPIN lock and counters",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to remove MPIN lock: %w", err)
    }

    util.Info("MPIN lock and counters removed",
        zap.String("user_id", userID))

    return nil
}

// Temporary block mechanism (separate from permanent MPIN lock)

func (c *MPINCache) SetMPINTempBlock(userID string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinTempBlockPrefix + userID

    if err := c.client.Set(ctx, key, "blocked", ttl); err != nil {
        util.Error("Failed to set MPIN temporary block",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to set MPIN temporary block: %w", err)
    }

    util.Warn("MPIN temporarily blocked",
        zap.String("user_id", userID),
        zap.Duration("duration", ttl))

    return nil
}

func (c *MPINCache) IsMPINTempBlocked(userID string) (bool, time.Duration, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinTempBlockPrefix + userID

    exists, err := c.client.Exists(ctx, key)
    if err != nil {
        return false, 0, fmt.Errorf("failed to check MPIN temp block: %w", err)
    }

    if !exists {
        return false, 0, nil
    }

    // Get remaining TTL
    ttl, err := c.client.TTL(ctx, key)
    if err != nil {
        return true, 0, fmt.Errorf("failed to get MPIN temp block TTL: %w", err)
    }

    return true, ttl, nil
}

func (c *MPINCache) RemoveMPINTempBlock(userID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinTempBlockPrefix + userID

    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to remove MPIN temporary block",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to remove MPIN temporary block: %w", err)
    }

    util.Info("MPIN temporary block removed",
        zap.String("user_id", userID))

    return nil
}

// Cooldown mechanism (prevent rapid MPIN change attempts)

func (c *MPINCache) SetMPINCooldown(userID string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinCooldownPrefix + userID

    if err := c.client.Set(ctx, key, "cooldown", ttl); err != nil {
        util.Error("Failed to set MPIN cooldown",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to set MPIN cooldown: %w", err)
    }

    util.Debug("MPIN cooldown set",
        zap.String("user_id", userID),
        zap.Duration("ttl", ttl))

    return nil
}

func (c *MPINCache) IsMPINInCooldown(userID string) (bool, time.Duration, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := mpinCooldownPrefix + userID

    exists, err := c.client.Exists(ctx, key)
    if err != nil {
        return false, 0, fmt.Errorf("failed to check MPIN cooldown: %w", err)
    }

    if !exists {
        return false, 0, nil
    }

    // Get remaining TTL
    ttl, err := c.client.TTL(ctx, key)
    if err != nil {
        return true, 0, fmt.Errorf("failed to get MPIN cooldown TTL: %w", err)
    }

    return true, ttl, nil
}

// Batch operations

func (c *MPINCache) ResetMultipleMPINRetries(userIDs []string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var keys []string
    for _, userID := range userIDs {
        keys = append(keys, mpinRetryPrefix+userID)
    }

    if err := c.client.Del(ctx, keys...); err != nil {
        util.Error("Failed to reset multiple MPIN retry counts",
            zap.Int("count", len(userIDs)),
            zap.Error(err))
        return fmt.Errorf("failed to reset multiple MPIN retry counts: %w", err)
    }

    util.Info("Multiple MPIN retry counts reset",
        zap.Int("count", len(userIDs)))

    return nil
}

func (c *MPINCache) GetMPINStatus(userID string) (map[string]interface{}, error) {
    status := make(map[string]interface{})

    // Get retry count
    retryCount, err := c.GetMPINRetryCount(userID)
    if err == nil {
        status["retry_count"] = retryCount
    }

    // Check if locked
    locked, err := c.IsMPINLocked(userID)
    if err == nil {
        status["is_locked"] = locked
    }

    // Check if temporarily blocked
    tempBlocked, ttl, err := c.IsMPINTempBlocked(userID)
    if err == nil {
        status["is_temp_blocked"] = tempBlocked
        if tempBlocked {
            status["temp_block_ttl_seconds"] = int(ttl.Seconds())
        }
    }

    // Check cooldown
    inCooldown, cooldownTTL, err := c.IsMPINInCooldown(userID)
    if err == nil {
        status["in_cooldown"] = inCooldown
        if inCooldown {
            status["cooldown_ttl_seconds"] = int(cooldownTTL.Seconds())
        }
    }

    return status, nil
}

// Statistics and monitoring

func (c *MPINCache) GetMPINStats() (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    stats := make(map[string]interface{})

    patterns := map[string]string{
        "users_with_retries":    mpinRetryPrefix + "*",
        "locked_mpins":          mpinLockPrefix + "*",
        "temp_blocked_mpins":    mpinTempBlockPrefix + "*",
        "mpins_in_cooldown":     mpinCooldownPrefix + "*",
    }

    for statName, pattern := range patterns {
        keys, _, err := c.client.Scan(ctx, 0, pattern, 1000)
        if err != nil {
            util.Warn("Failed to scan keys for MPIN stats",
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

func (c *MPINCache) CleanupExpiredMPINData() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    patterns := []string{
        mpinRetryPrefix + "*",
        mpinLockPrefix + "*",
        mpinTempBlockPrefix + "*",
        mpinCooldownPrefix + "*",
    }

    totalCleaned := 0
    for _, pattern := range patterns {
        cursor := uint64(0)
        for {
            keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100)
            if err != nil {
                util.Error("Failed to scan keys for MPIN cleanup",
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
                    util.Warn("Found MPIN cache key without TTL", zap.String("key", key))
                }
            }

            totalCleaned += len(keys)
            cursor = nextCursor
            if cursor == 0 {
                break
            }
        }
    }

    util.Info("MPIN cache cleanup completed", zap.Int("keys_checked", totalCleaned))
    return nil
}

// Advanced security features

func (c *MPINCache) SetMPINSecurityAlert(userID string, alertType string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := fmt.Sprintf("mpin_security_alert:%s:%s", userID, alertType)

    if err := c.client.Set(ctx, key, time.Now().UTC().Format(time.RFC3339), ttl); err != nil {
        util.Error("Failed to set MPIN security alert",
            zap.String("user_id", userID),
            zap.String("alert_type", alertType),
            zap.Error(err))
        return fmt.Errorf("failed to set MPIN security alert: %w", err)
    }

    util.Warn("MPIN security alert set",
        zap.String("user_id", userID),
        zap.String("alert_type", alertType))

    return nil
}

func (c *MPINCache) GetMPINSecurityAlerts(userID string) ([]string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    pattern := fmt.Sprintf("mpin_security_alert:%s:*", userID)

    keys, _, err := c.client.Scan(ctx, 0, pattern, 100)
    if err != nil {
        return nil, fmt.Errorf("failed to get MPIN security alerts: %w", err)
    }

    var alerts []string
    for _, key := range keys {
        // Extract alert type from key
        parts := strings.Split(key, ":")
        if len(parts) >= 3 {
            alerts = append(alerts, parts[2])
        }
    }

    return alerts, nil
}
