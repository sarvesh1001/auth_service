package redis

import (
    "context"
    "fmt"
    "strconv"
    "time"
	"go.uber.org/zap"             // needed for zap.Field in util calls

    "auth-service/internal/client"
    "auth-service/internal/util"
)

const (
    otpPrefix        = "otp:"
    otpAttemptPrefix = "otp_attempts:"
    otpLockPrefix    = "otp_lock:"
)

type OTPCache struct {
    client *client.RedisClient
}

func NewOTPCache(client *client.RedisClient) *OTPCache {
    return &OTPCache{client: client}
}

func (c *OTPCache) SetOTP(phoneNumber, otpHash string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpPrefix + phoneNumber
    if err := c.client.Set(ctx, key, otpHash, ttl); err != nil {
        util.Error("Failed to set OTP in cache", zap.String("phone_number", phoneNumber), zap.Duration("ttl", ttl), zap.Error(err))
        return fmt.Errorf("failed to set OTP in cache: %w", err)
    }
    util.Debug("OTP cached successfully", zap.String("phone_number", phoneNumber), zap.Duration("ttl", ttl))
    return nil
}

// ... GetOTP, DeleteOTP, IncrementAttempts, GetAttemptCount, ResetAttempts,
//     SetOTPLock, IsOTPLocked, RemoveOTPLock, SetMultipleOTPs, GetOTPTTL,
//     GetOTPStats, CleanupExpiredOTPs — all unchanged except constructor,
//     client import, and logger calls replaced with util.X ...

func (c *OTPCache) GetOTP(phoneNumber string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpPrefix + phoneNumber

    otpHash, err := c.client.Get(ctx, key)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", key) {
            return "", fmt.Errorf("no OTP found for phone: %s", phoneNumber)
        }
        util.Error("Failed to get OTP from cache",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return "", fmt.Errorf("failed to get OTP from cache: %w", err)
    }

    return otpHash, nil
}

func (c *OTPCache) DeleteOTP(phoneNumber string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpPrefix + phoneNumber

    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to delete OTP from cache",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to delete OTP from cache: %w", err)
    }

    util.Debug("OTP deleted from cache",
        zap.String("phone_number", phoneNumber))

    return nil
}

func (c *OTPCache) IncrementAttempts(phoneNumber string, ttl time.Duration) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpAttemptPrefix + phoneNumber

    count, err := c.client.IncrWithExpire(ctx, key, ttl)
    if err != nil {
        util.Error("Failed to increment OTP attempts",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return 0, fmt.Errorf("failed to increment OTP attempts: %w", err)
    }

    util.Debug("OTP attempts incremented",
        zap.String("phone_number", phoneNumber),
        zap.Int64("count", count))

    return int(count), nil
}

func (c *OTPCache) GetAttemptCount(phoneNumber string) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpAttemptPrefix + phoneNumber

    countStr, err := c.client.Get(ctx, key)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", key) {
            return 0, nil // No attempts yet
        }
        return 0, fmt.Errorf("failed to get OTP attempt count: %w", err)
    }

    count, err := strconv.Atoi(countStr)
    if err != nil {
        util.Error("Invalid attempt count format",
            zap.String("phone_number", phoneNumber),
            zap.String("count_str", countStr),
            zap.Error(err))
        return 0, fmt.Errorf("invalid attempt count format: %w", err)
    }

    return count, nil
}

func (c *OTPCache) ResetAttempts(phoneNumber string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpAttemptPrefix + phoneNumber

    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to reset OTP attempts",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to reset OTP attempts: %w", err)
    }

    util.Debug("OTP attempts reset",
        zap.String("phone_number", phoneNumber))

    return nil
}

// Additional OTP-specific methods

func (c *OTPCache) SetOTPLock(phoneNumber string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpLockPrefix + phoneNumber

    success, err := c.client.SetNX(ctx, key, "locked", ttl)
    if err != nil {
        util.Error("Failed to set OTP lock",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to set OTP lock: %w", err)
    }

    if !success {
        return fmt.Errorf("OTP already locked for phone: %s", phoneNumber)
    }

    util.Debug("OTP lock set",
        zap.String("phone_number", phoneNumber),
        zap.Duration("ttl", ttl))

    return nil
}

func (c *OTPCache) IsOTPLocked(phoneNumber string) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpLockPrefix + phoneNumber

    exists, err := c.client.Exists(ctx, key)
    if err != nil {
        util.Error("Failed to check OTP lock",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return false, fmt.Errorf("failed to check OTP lock: %w", err)
    }

    return exists, nil
}

func (c *OTPCache) RemoveOTPLock(phoneNumber string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpLockPrefix + phoneNumber

    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to remove OTP lock",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to remove OTP lock: %w", err)
    }

    util.Debug("OTP lock removed",
        zap.String("phone_number", phoneNumber))

    return nil
}

// Batch operations for multiple OTPs
func (c *OTPCache) SetMultipleOTPs(otps map[string]string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    pipe := c.client.Pipeline()

    for phoneNumber, otpHash := range otps {
        key := otpPrefix + phoneNumber
        pipe.Set(ctx, key, otpHash, ttl)
    }

    _, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to set multiple OTPs",
            zap.Int("count", len(otps)),
            zap.Error(err))
        return fmt.Errorf("failed to set multiple OTPs: %w", err)
    }

    util.Debug("Multiple OTPs cached successfully",
        zap.Int("count", len(otps)))

    return nil
}

func (c *OTPCache) GetOTPTTL(phoneNumber string) (time.Duration, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := otpPrefix + phoneNumber

    ttl, err := c.client.TTL(ctx, key)
    if err != nil {
        util.Error("Failed to get OTP TTL",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return 0, fmt.Errorf("failed to get OTP TTL: %w", err)
    }

    return ttl, nil
}

// Statistics and monitoring
func (c *OTPCache) GetOTPStats() (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    stats := make(map[string]interface{})

    // Count active OTPs (keys with otp: prefix)
    keys, _, err := c.client.Scan(ctx, 0, otpPrefix+"*", 1000)
    if err != nil {
        util.Warn("Failed to scan OTP keys", zap.Error(err))
    } else {
        stats["active_otps"] = len(keys)
    }

    // Count OTP attempt counters
    attemptKeys, _, err := c.client.Scan(ctx, 0, otpAttemptPrefix+"*", 1000)
    if err != nil {
        util.Warn("Failed to scan OTP attempt keys", zap.Error(err))
    } else {
        stats["phones_with_attempts"] = len(attemptKeys)
    }

    // Count OTP locks
    lockKeys, _, err := c.client.Scan(ctx, 0, otpLockPrefix+"*", 1000)
    if err != nil {
        util.Warn("Failed to scan OTP lock keys", zap.Error(err))
    } else {
        stats["locked_phones"] = len(lockKeys)
    }

    return stats, nil
}

// Cleanup expired entries (usually handled by Redis TTL, but can be called manually)
func (c *OTPCache) CleanupExpiredOTPs() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // This is usually not needed as Redis handles TTL automatically
    // But can be used for manual cleanup or monitoring

    patterns := []string{
        otpPrefix + "*",
        otpAttemptPrefix + "*",
        otpLockPrefix + "*",
    }

    totalCleaned := 0
    for _, pattern := range patterns {
        cursor := uint64(0)
        for {
            keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100)
            if err != nil {
                util.Error("Failed to scan keys for cleanup",
                    zap.String("pattern", pattern),
                    zap.Error(err))
                break
            }

            // Check TTL for each key and clean if needed
            for _, key := range keys {
                ttl, err := c.client.TTL(ctx, key)
                if err != nil {
                    continue
                }

                // If TTL is -1 (no expiry set) or expired, we might want to handle it
                if ttl == -1 {
                    util.Warn("Found key without TTL", zap.String("key", key))
                }
            }

            totalCleaned += len(keys)
            cursor = nextCursor
            if cursor == 0 {
                break
            }
        }
    }

    util.Info("OTP cleanup completed", zap.Int("keys_checked", totalCleaned))
    return nil
}
