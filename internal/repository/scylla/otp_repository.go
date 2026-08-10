package scylla

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"auth-service/internal/bucketing"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/models"

	"github.com/gocql/gocql"
	"golang.org/x/sync/errgroup"
)

const (
	OTPMaxBatchSize        = 100
	OTPMaxConcurrentReads  = 50
	OTPMaxConcurrentWrites = 20
	OTPDefaultTTL          = 5 * time.Minute
	OTPMaxAttempts         = 3
	OTPCleanupBatchSize    = 1000
	OTPLength              = 6
	OTPBucketWindowSeconds = 3600
)

type OTPRepository interface {
	CreateOTP(ctx context.Context, otp *models.OTPVerification) error
	GetActiveOTP(ctx context.Context, phoneHash string, purpose string) (*models.OTPVerification, error)
	ValidateOTP(ctx context.Context, phoneHash, otpHash, purpose string) (*models.OTPVerification, error)
	InvalidateOTP(ctx context.Context, phoneHash string, purpose string) error
	IncrementOTPAttempts(ctx context.Context, phoneHash string, purpose string, createdAt time.Time) (int, error)
	GetOTPAttemptsByPhone(ctx context.Context, phoneHash string, timeWindow time.Duration) (int, error)
	GetOTPsByTimeRange(ctx context.Context, phoneHash string, start, end time.Time) ([]*models.OTPVerification, error)
	CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error)
	CreateOTPsBatch(ctx context.Context, otps []*models.OTPVerification) error
	InvalidateOTPsBatch(ctx context.Context, phoneHashes []string, purpose string) error
	HealthCheck(ctx context.Context) error
	GetOTPStats(ctx context.Context) (map[string]interface{}, error)
}

type OTPRepositoryImpl struct {
	client           *ScyllaClient
	hasher           *hashing.Hasher
	bucketingManager *bucketing.BucketingManager
}

func NewOTPRepository(
	client *ScyllaClient,
	hasher *hashing.Hasher,
	bucketingManager *bucketing.BucketingManager,
) OTPRepository {
	return &OTPRepositoryImpl{
		client:           client,
		hasher:           hasher,
		bucketingManager: bucketingManager,
	}
}

func (r *OTPRepositoryImpl) getTimeBucketFromTime(t time.Time) int64 {
	return t.Unix() / OTPBucketWindowSeconds
}

func (r *OTPRepositoryImpl) CreateOTP(ctx context.Context, otp *models.OTPVerification) error {
	otp.TimeBucket = r.getTimeBucketFromTime(otp.CreatedAt)
	ttlSeconds := int(time.Until(otp.ExpiresAt).Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = int(OTPDefaultTTL.Seconds())
	}
	var ipToStore net.IP
	if otp.IPAddress != nil {
		ipToStore = otp.IPAddress
	} else {
		ipToStore = net.ParseIP("0.0.0.0")
	}

	query := r.client.Query(`
		INSERT INTO otp_verifications (
			phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
			hash_algorithm, pepper_version, attempts, expires_at,
			ip_address, device_id, provider_used
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		USING TTL ?
	`,
		otp.PhoneHash,
		otp.Purpose,
		otp.TimeBucket,
		otp.CreatedAt,
		otp.OTPHash,
		otp.OTPSalt,
		otp.HashAlgorithm,
		otp.PepperVersion,
		otp.Attempts,
		otp.ExpiresAt,
		ipToStore,
		otp.DeviceID,
		otp.ProviderUsed,
		ttlSeconds,
	)
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create OTP: %w", err)
	}
	return nil
}

func (r *OTPRepositoryImpl) GetActiveOTP(ctx context.Context, phoneHash string, purpose string) (*models.OTPVerification, error) {
	timeBucket := r.bucketingManager.GetTimeBucket(OTPBucketWindowSeconds)

	query := r.client.Query(`
		SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
		       hash_algorithm, pepper_version, attempts, expires_at,
		       ip_address, device_id, provider_used
		FROM otp_verifications
		WHERE phone_hash = ? AND purpose = ? AND time_bucket = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, phoneHash, purpose, timeBucket)

	var otp models.OTPVerification
	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&otp.PhoneHash,
		&otp.Purpose,
		&otp.TimeBucket,
		&otp.CreatedAt,
		&otp.OTPHash,
		&otp.OTPSalt,
		&otp.HashAlgorithm,
		&otp.PepperVersion,
		&otp.Attempts,
		&otp.ExpiresAt,
		&otp.IPAddress,
		&otp.DeviceID,
		&otp.ProviderUsed,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			// try previous bucket
			prevBucket := r.getTimeBucketFromTime(time.Now().Add(-time.Hour))
			prevQuery := r.client.Query(`
				SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
				       hash_algorithm, pepper_version, attempts, expires_at,
				       ip_address, device_id, provider_used
				FROM otp_verifications
				WHERE phone_hash = ? AND purpose = ? AND time_bucket = ?
				ORDER BY created_at DESC
				LIMIT 1
			`, phoneHash, purpose, prevBucket)

			err = r.client.ScanWithRetry(prevQuery.WithContext(ctx),
				&otp.PhoneHash,
				&otp.Purpose,
				&otp.TimeBucket,
				&otp.CreatedAt,
				&otp.OTPHash,
				&otp.OTPSalt,
				&otp.HashAlgorithm,
				&otp.PepperVersion,
				&otp.Attempts,
				&otp.ExpiresAt,
				&otp.IPAddress,
				&otp.DeviceID,
				&otp.ProviderUsed,
			)
			if err != nil {
				if err == gocql.ErrNotFound {
					return nil, apperrors.ErrNotFound
				}
				return nil, fmt.Errorf("failed to get active OTP from previous bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get active OTP: %w", err)
		}
	}

	if otp.IPAddress == nil {
		otp.IPAddress = net.ParseIP("0.0.0.0")
	}
	if time.Now().After(otp.ExpiresAt) {
		return nil, apperrors.ErrNotFound
	}
	if otp.Attempts >= OTPMaxAttempts {
		return nil, apperrors.ErrInvalidState
	}
	return &otp, nil
}

func (r *OTPRepositoryImpl) ValidateOTP(ctx context.Context, phoneHash, otpHash, purpose string) (*models.OTPVerification, error) {
	otp, err := r.GetActiveOTP(ctx, phoneHash, purpose)
	if err != nil {
		return nil, err
	}
	if !secureCompare(otp.OTPHash, otpHash) {
		newAttempts, _ := r.IncrementOTPAttempts(ctx, phoneHash, purpose, otp.CreatedAt)
		otp.Attempts = newAttempts
		return otp, fmt.Errorf("invalid OTP")
	}
	return otp, nil
}

func (r *OTPRepositoryImpl) InvalidateOTP(ctx context.Context, phoneHash string, purpose string) error {
	otp, err := r.GetActiveOTP(ctx, phoneHash, purpose)
	if err != nil {
		return err
	}
	query := r.client.Query(`
		DELETE FROM otp_verifications
		WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?
	`, phoneHash, purpose, otp.TimeBucket, otp.CreatedAt)
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to invalidate OTP: %w", err)
	}
	return nil
}

func (r *OTPRepositoryImpl) IncrementOTPAttempts(ctx context.Context, phoneHash string, purpose string, createdAt time.Time) (int, error) {
	timeBucket := r.getTimeBucketFromTime(createdAt)

	var currentAttempts int
	var scannedIP net.IP
	var providerUsed string
	selectQuery := r.client.Query(`
		SELECT attempts, ip_address, provider_used FROM otp_verifications
		WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?
	`, phoneHash, purpose, timeBucket, createdAt)

	err := r.client.ScanWithRetry(selectQuery.WithContext(ctx),
		&currentAttempts,
		&scannedIP,
		&providerUsed,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get current attempts: %w", err)
	}
	newAttempts := currentAttempts + 1
	updateQuery := r.client.Query(`
		UPDATE otp_verifications
		SET attempts = ?
		WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?
	`, newAttempts, phoneHash, purpose, timeBucket, createdAt)

	if err := r.client.ExecuteWithRetry(updateQuery.WithContext(ctx), 3); err != nil {
		return 0, fmt.Errorf("failed to increment OTP attempts: %w", err)
	}
	return newAttempts, nil
}

func (r *OTPRepositoryImpl) GetOTPAttemptsByPhone(ctx context.Context, phoneHash string, timeWindow time.Duration) (int, error) {
	startTime := time.Now().Add(-timeWindow)
	endTime := time.Now()
	otps, err := r.GetOTPsByTimeRange(ctx, phoneHash, startTime, endTime)
	if err != nil {
		return 0, err
	}
	return len(otps), nil
}

func (r *OTPRepositoryImpl) GetOTPsByTimeRange(ctx context.Context, phoneHash string, start, end time.Time) ([]*models.OTPVerification, error) {
	startBucket := r.getTimeBucketFromTime(start)
	endBucket := r.getTimeBucketFromTime(end)

	var allOTPs []*models.OTPVerification
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for bucket := startBucket; bucket <= endBucket; bucket++ {
		bucket := bucket
		g.Go(func() error {
			query := r.client.Query(`
				SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
				       hash_algorithm, pepper_version, attempts, expires_at,
				       ip_address, device_id, provider_used
				FROM otp_verifications
				WHERE phone_hash = ? AND time_bucket = ?
			`, phoneHash, bucket)

			iter := query.WithContext(gctx).Iter()
			defer iter.Close()

			var bucketOTPs []*models.OTPVerification
			for {
				var otp models.OTPVerification
				if !iter.Scan(
					&otp.PhoneHash,
					&otp.Purpose,
					&otp.TimeBucket,
					&otp.CreatedAt,
					&otp.OTPHash,
					&otp.OTPSalt,
					&otp.HashAlgorithm,
					&otp.PepperVersion,
					&otp.Attempts,
					&otp.ExpiresAt,
					&otp.IPAddress,
					&otp.DeviceID,
					&otp.ProviderUsed,
				) {
					break
				}
				if otp.IPAddress == nil {
					otp.IPAddress = net.ParseIP("0.0.0.0")
				}
				if otp.CreatedAt.After(start) && otp.CreatedAt.Before(end) {
					bucketOTPs = append(bucketOTPs, &otp)
				}
			}
			if err := iter.Close(); err != nil {
				return fmt.Errorf("failed to iterate OTPs: %w", err)
			}
			mu.Lock()
			allOTPs = append(allOTPs, bucketOTPs...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return allOTPs, nil
}

func (r *OTPRepositoryImpl) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	if batchSize <= 0 || batchSize > OTPCleanupBatchSize {
		batchSize = OTPCleanupBatchSize
	}
	now := time.Now()
	deletedCount := 0
	startBucket := r.getTimeBucketFromTime(now.Add(-2 * time.Hour))
	endBucket := r.bucketingManager.GetTimeBucket(OTPBucketWindowSeconds)

	batch := r.client.Batch(gocql.UnloggedBatch)
	batchCount := 0
	maxDeletes := 100

	for bucket := startBucket; bucket <= endBucket; bucket++ {
		if deletedCount >= maxDeletes {
			break
		}
		query := r.client.Query(`
			SELECT phone_hash, purpose, time_bucket, created_at, expires_at
			FROM otp_verifications
			WHERE time_bucket = ?
			LIMIT ?
		`, bucket, batchSize)

		iter := query.WithContext(ctx).Iter()
		var phoneHash, purpose string
		var timeBucket int64
		var createdAt, expiresAt time.Time
		for iter.Scan(&phoneHash, &purpose, &timeBucket, &createdAt, &expiresAt) {
			if now.After(expiresAt) {
				batch.Query(`
					DELETE FROM otp_verifications
					WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?
				`, phoneHash, purpose, timeBucket, createdAt)
				batchCount++
				deletedCount++
				if batchCount >= batchSize {
					_ = r.client.ExecuteBatch(batch)
					batch = r.client.Batch(gocql.UnloggedBatch)
					batchCount = 0
				}
			}
			if deletedCount >= maxDeletes {
				break
			}
		}
		_ = iter.Close()
	}
	if batchCount > 0 {
		_ = r.client.ExecuteBatch(batch)
	}
	return deletedCount, nil
}

func (r *OTPRepositoryImpl) CreateOTPsBatch(ctx context.Context, otps []*models.OTPVerification) error {
	if len(otps) == 0 {
		return nil
	}
	batch := r.client.Batch(gocql.UnloggedBatch)
	batchSize := 0
	for _, otp := range otps {
		otp.TimeBucket = r.getTimeBucketFromTime(otp.CreatedAt)
		ttlSeconds := int(time.Until(otp.ExpiresAt).Seconds())
		if ttlSeconds <= 0 {
			ttlSeconds = int(OTPDefaultTTL.Seconds())
		}
		var ipToStore net.IP
		if otp.IPAddress != nil {
			ipToStore = otp.IPAddress
		} else {
			ipToStore = net.ParseIP("0.0.0.0")
		}
		batch.Query(`
			INSERT INTO otp_verifications (
				phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
				hash_algorithm, pepper_version, attempts, expires_at,
				ip_address, device_id, provider_used
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			USING TTL ?
		`,
			otp.PhoneHash, otp.Purpose, otp.TimeBucket, otp.CreatedAt, otp.OTPHash, otp.OTPSalt,
			otp.HashAlgorithm, otp.PepperVersion, otp.Attempts, otp.ExpiresAt,
			ipToStore, otp.DeviceID, otp.ProviderUsed,
			ttlSeconds,
		)
		batchSize++
		if batchSize >= OTPMaxBatchSize {
			if err := r.client.ExecuteBatch(batch); err != nil {
				return fmt.Errorf("failed to execute OTP batch: %w", err)
			}
			batch = r.client.Batch(gocql.UnloggedBatch)
			batchSize = 0
		}
	}
	if batchSize > 0 {
		if err := r.client.ExecuteBatch(batch); err != nil {
			return fmt.Errorf("failed to execute final OTP batch: %w", err)
		}
	}
	return nil
}

func (r *OTPRepositoryImpl) InvalidateOTPsBatch(ctx context.Context, phoneHashes []string, purpose string) error {
	if len(phoneHashes) == 0 {
		return nil
	}
	var mu sync.Mutex
	errorCount := 0
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(OTPMaxConcurrentWrites)

	for _, phoneHash := range phoneHashes {
		phoneHash := phoneHash
		g.Go(func() error {
			if err := r.InvalidateOTP(gctx, phoneHash, purpose); err != nil {
				mu.Lock()
				errorCount++
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	return nil
}

func (r *OTPRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	err := r.client.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count)
	if err != nil {
		return fmt.Errorf("OTP repository health check failed: %w", err)
	}
	return nil
}

func (r *OTPRepositoryImpl) GetOTPStats(ctx context.Context) (map[string]interface{}, error) {
	stats := map[string]interface{}{
		"max_attempts":          OTPMaxAttempts,
		"default_ttl_seconds":   int(OTPDefaultTTL.Seconds()),
		"max_batch_size":        OTPMaxBatchSize,
		"max_concurrent_reads":  OTPMaxConcurrentReads,
		"max_concurrent_writes": OTPMaxConcurrentWrites,
		"otp_length":            OTPLength,
		"bucket_window_seconds": OTPBucketWindowSeconds,
	}
	return stats, nil
}

// Helper functions
func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		length = OTPLength
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

func HashOTP(otp, salt string) string {
	hash := sha256.Sum256([]byte(otp + salt))
	return hex.EncodeToString(hash[:])
}

func GenerateSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return hex.EncodeToString(salt), nil
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
