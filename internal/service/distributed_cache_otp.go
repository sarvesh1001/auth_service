package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"
)

// SetOTPVerification stores OTP verification in Redis
func (dc *DistributedCache) SetOTPVerification(ctx context.Context, key string, otp *models.OTPVerification, ttl time.Duration) error {
	data, err := json.Marshal(otp)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}
	
	if err := dc.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to cache OTP: %w", err)
	}
	
	return nil
}

// GetOTPVerification retrieves OTP verification from Redis
func (dc *DistributedCache) GetOTPVerification(ctx context.Context, key string) (*models.OTPVerification, error) {
	data, err := dc.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("OTP not found in cache: %w", err)
	}
	
	var otp models.OTPVerification
	if err := json.Unmarshal(data, &otp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}
	
	return &otp, nil
}

// DeleteOTPVerification removes OTP verification from Redis
func (dc *DistributedCache) DeleteOTPVerification(ctx context.Context, key string) error {
	return dc.client.Del(ctx, key).Err()
}

// IncrementCounter atomically increments a counter in Redis
func (dc *DistributedCache) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := dc.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	
	// Set TTL on first increment
	if count == 1 {
		dc.client.Expire(ctx, key, ttl)
	}
	
	return count, nil
}

// SetWithExpiry sets a key-value pair with expiry
func (dc *DistributedCache) SetWithExpiry(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return dc.client.Set(ctx, key, value, ttl).Err()
}

// Get retrieves a value from Redis
func (dc *DistributedCache) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := dc.client.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	
	return json.Unmarshal(data, dest)
}

// DeleteKey deletes a key from Redis
func (dc *DistributedCache) DeleteKey(ctx context.Context, key string) error {
	return dc.client.Del(ctx, key).Err()
}

// CleanupExpiredOTPs is a helper method (backup - TTL handles this)
func (s *OTPService) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	return s.otpRepo.CleanupExpiredOTPs(ctx, batchSize)
}
