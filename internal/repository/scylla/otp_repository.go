// internal/repository/scylla/otp_repository.go
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
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/gocql/gocql"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// Constants for OTP operations at 500M scale
const (
	OTPMaxBatchSize        = 100
	OTPMaxConcurrentReads  = 50
	OTPMaxConcurrentWrites = 20
	OTPDefaultTTL          = 5 * time.Minute // Auto-expire after 5 minutes
	OTPMaxAttempts         = 3               // Max verification attempts
	OTPCleanupBatchSize    = 1000            // Cleanup batch size
	OTPLength              = 6               // 6-digit OTP
	OTPBucketWindowSeconds = 3600            // 1 hour bucketing
)

// OTPRepository handles all OTP-related database operations
type OTPRepositoryImpl struct {
	client           *ScyllaClient
	hasher           *hashing.Hasher
	bucketingManager *bucketing.BucketingManager
	logger           *zap.Logger

	// Prepared statements for frequently used queries
	stmtCreateOTP     *gocql.Query
	stmtGetActiveOTP  *gocql.Query
	stmtInvalidateOTP *gocql.Query
	stmtMutex         sync.RWMutex
}

// OTPRepository defines the interface for OTP operations
type OTPRepository interface {
	// Core Operations
	CreateOTP(ctx context.Context, otp *models.OTPVerification) error
	GetActiveOTP(ctx context.Context, phoneHash string, purpose string) (*models.OTPVerification, error)
	ValidateOTP(ctx context.Context, phoneHash, otpHash, purpose string) (*models.OTPVerification, error)
	InvalidateOTP(ctx context.Context, phoneHash string, purpose string) error
	IncrementOTPAttempts(ctx context.Context, phoneHash string, purpose string, createdAt time.Time) (int, error)

	// Rate Limiting & Analytics
	GetOTPAttemptsByPhone(ctx context.Context, phoneHash string, timeWindow time.Duration) (int, error)
	GetOTPsByTimeRange(ctx context.Context, phoneHash string, start, end time.Time) ([]*models.OTPVerification, error)
	CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error)

	// Bulk Operations
	CreateOTPsBatch(ctx context.Context, otps []*models.OTPVerification) error
	InvalidateOTPsBatch(ctx context.Context, phoneHashes []string, purpose string) error

	// Health & Stats
	HealthCheck(ctx context.Context) error
	GetOTPStats(ctx context.Context) (map[string]interface{}, error)
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(
	client *ScyllaClient,
	hasher *hashing.Hasher,
	bucketingManager *bucketing.BucketingManager,
	logger *zap.Logger,
) OTPRepository {
	repo := &OTPRepositoryImpl{
		client:           client,
		hasher:           hasher,
		bucketingManager: bucketingManager,
		logger:           logger,
	}

	// Prepare frequently used statements
	repo.prepareStatements()

	return repo
}

// prepareStatements prepares frequently used queries for better performance
func (r *OTPRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare CreateOTP query
	r.stmtCreateOTP = r.client.Session.Query(`
        INSERT INTO otp_verifications (
            phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
            hash_algorithm, pepper_version, attempts, expires_at,
            ip_address,device_id, provider_used
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        USING TTL ?`)

	// Prepare GetActiveOTP query
	r.stmtGetActiveOTP = r.client.Session.Query(`
        SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
               hash_algorithm, pepper_version, attempts, expires_at,
               ip_address, device_id, provider_used
        FROM otp_verifications
        WHERE phone_hash = ? AND purpose = ? AND time_bucket = ?
        ORDER BY created_at DESC
        LIMIT 1`)

	// Prepare InvalidateOTP query
	r.stmtInvalidateOTP = r.client.Session.Query(`
        DELETE FROM otp_verifications
        WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?`)

	r.logger.Info("Prepared statements initialized for OTP repository")

}

// Helper function to calculate time bucket from timestamp
func (r *OTPRepositoryImpl) getTimeBucketFromTime(t time.Time) int64 {
	return t.Unix() / OTPBucketWindowSeconds
}

// ============================================
// CORE OPERATIONS
// ============================================

// CreateOTP creates a new OTP with automatic TTL expiry
func (r *OTPRepositoryImpl) CreateOTP(ctx context.Context, otp *models.OTPVerification) error {
	startTime := time.Now()

	// Calculate time bucket using bucketingManager
	otp.TimeBucket = r.getTimeBucketFromTime(otp.CreatedAt)

	// Calculate TTL in seconds
	ttlSeconds := int(time.Until(otp.ExpiresAt).Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = int(OTPDefaultTTL.Seconds())
	}

	// ✅ FIX: Ensure valid IP address for inet column
	var ipToStore net.IP
	if otp.IPAddress != nil {
		ipToStore = otp.IPAddress
	} else {
		ipToStore = net.ParseIP("0.0.0.0")
	}

	// Log for debugging
	r.logger.Info("Creating OTP in database",
		util.String("phone_hash", otp.PhoneHash),
		util.String("purpose", otp.Purpose),
		util.Int64("time_bucket", otp.TimeBucket),
		util.Time("created_at", otp.CreatedAt),
		util.String("ip_address", ipToStore.String()),
		util.Int("ttl_seconds", ttlSeconds),
	)

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtCreateOTP.Bind(
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
		ipToStore,    // Use the validated IP
		otp.DeviceID, // <-- ADD THIS LINE
		otp.ProviderUsed,
		ttlSeconds,
	)
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create OTP: %w", err)
	}

	r.logger.Debug("OTP created successfully",
		util.String("phone_hash", otp.PhoneHash),
		util.String("purpose", otp.Purpose),
		util.Int64("time_bucket", otp.TimeBucket),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// GetActiveOTP retrieves the most recent active OTP for a phone number
func (r *OTPRepositoryImpl) GetActiveOTP(ctx context.Context, phoneHash string, purpose string) (*models.OTPVerification, error) {
	// Calculate current time bucket using bucketing manager
	timeBucket := r.bucketingManager.GetTimeBucket(OTPBucketWindowSeconds)

	// Log for debugging
	r.logger.Info("Querying active OTP",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
		util.Int64("time_bucket", timeBucket),
	)

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtGetActiveOTP.Bind(phoneHash, purpose, timeBucket)
	r.stmtMutex.RUnlock()

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
		&otp.IPAddress, // ✅ FIX: Scan directly into net.IP
		&otp.DeviceID,  // <-- ADD THIS
		&otp.ProviderUsed,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			// Try previous bucket (for OTPs created near bucket boundary)
			prevBucket := r.getTimeBucketFromTime(time.Now().Add(-time.Hour))

			r.logger.Info("Trying previous time bucket",
				util.String("phone_hash", phoneHash),
				util.String("purpose", purpose),
				util.Int64("prev_bucket", prevBucket),
			)

			r.stmtMutex.RLock()
			prevQuery := r.stmtGetActiveOTP.Bind(phoneHash, purpose, prevBucket)
			r.stmtMutex.RUnlock()

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
				&otp.IPAddress, // ✅ FIX: For previous bucket too
				&otp.DeviceID,  // <-- ADD THIS
				&otp.ProviderUsed,
			)

			if err != nil {
				r.logger.Warn("No active OTP found in current or previous bucket",
					util.String("phone_hash", phoneHash),
					util.String("purpose", purpose),
					util.Int64("current_bucket", timeBucket),
					util.Int64("prev_bucket", prevBucket),
				)
				return nil, fmt.Errorf("no active OTP found for phone hash: %s", phoneHash)
			}
		} else {
			return nil, fmt.Errorf("failed to get active OTP: %w", err)
		}
	}

	// ✅ FIX: Ensure IP address is never nil
	if otp.IPAddress == nil {
		otp.IPAddress = net.ParseIP("0.0.0.0")
	}

	r.logger.Info("Found active OTP",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
		util.Time("created_at", otp.CreatedAt),
		util.Int("attempts", otp.Attempts),
		util.String("ip_address", otp.IPAddress.String()),
	)

	// Check if OTP is expired
	if time.Now().After(otp.ExpiresAt) {
		return nil, fmt.Errorf("OTP has expired")
	}

	// Check if max attempts exceeded
	if otp.Attempts >= OTPMaxAttempts {
		return nil, fmt.Errorf("max OTP verification attempts exceeded")
	}

	return &otp, nil
}

// ValidateOTP validates an OTP and returns the OTP record if valid
func (r *OTPRepositoryImpl) ValidateOTP(ctx context.Context, phoneHash, otpHash, purpose string) (*models.OTPVerification, error) {
	otp, err := r.GetActiveOTP(ctx, phoneHash, purpose)
	if err != nil {
		return nil, err
	}

	r.logger.Info("Validating OTP hash",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
		util.String("stored_hash", otp.OTPHash[:20]+"..."),
		util.String("provided_hash", otpHash[:20]+"..."),
	)

	// Compare OTP hashes (constant-time comparison to prevent timing attacks)
	if !secureCompare(otp.OTPHash, otpHash) {
		// Increment attempt count and get the new value
		newAttempts, err := r.IncrementOTPAttempts(ctx, phoneHash, purpose, otp.CreatedAt)
		if err != nil {
			r.logger.Warn("Failed to increment OTP attempts",
				util.ErrorField(err),
				util.String("phone_hash", phoneHash),
			)
		} else {
			// Update the OTP object with new attempts for response
			otp.Attempts = newAttempts
		}

		// Return the OTP with updated attempts count even on failure
		return otp, fmt.Errorf("invalid OTP")
	}

	return otp, nil
}

// InvalidateOTP marks an OTP as used by deleting it
func (r *OTPRepositoryImpl) InvalidateOTP(ctx context.Context, phoneHash string, purpose string) error {
	// Get the active OTP first to find its created_at timestamp
	otp, err := r.GetActiveOTP(ctx, phoneHash, purpose)
	if err != nil {
		return err
	}

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtInvalidateOTP.Bind(
		phoneHash,
		purpose,
		otp.TimeBucket,
		otp.CreatedAt,
	)
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to invalidate OTP: %w", err)
	}

	r.logger.Info("OTP invalidated successfully",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
	)

	return nil
}

// IncrementOTPAttempts increments the attempt counter for an OTP
func (r *OTPRepositoryImpl) IncrementOTPAttempts(ctx context.Context, phoneHash string, purpose string, createdAt time.Time) (int, error) {
	timeBucket := r.getTimeBucketFromTime(createdAt)

	r.logger.Info("Incrementing OTP attempts",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
		util.Int64("time_bucket", timeBucket),
		util.Time("created_at", createdAt),
	)

	// First, read the current attempts value
	var currentAttempts int
	var scannedIP net.IP
	var providerUsed string

	selectQuery := r.client.Session.Query(`
        SELECT attempts, ip_address, provider_used FROM otp_verifications
        WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?`,
		phoneHash, purpose, timeBucket, createdAt,
	)

	// ✅ FIX: Scan directly into net.IP
	if err := r.client.ScanWithRetry(selectQuery.WithContext(ctx),
		&currentAttempts,
		&scannedIP, // Use net.IP directly
		&providerUsed,
	); err != nil {
		return 0, fmt.Errorf("failed to get current attempts: %w", err)
	}

	// Increment and update with the new value
	newAttempts := currentAttempts + 1

	updateQuery := r.client.Session.Query(`
        UPDATE otp_verifications
        SET attempts = ?
        WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?`,
		newAttempts, phoneHash, purpose, timeBucket, createdAt,
	)

	if err := r.client.ExecuteWithRetry(updateQuery.WithContext(ctx), 3); err != nil {
		return 0, fmt.Errorf("failed to increment OTP attempts: %w", err)
	}

	r.logger.Info("OTP attempts incremented successfully",
		util.String("phone_hash", phoneHash),
		util.String("purpose", purpose),
		util.Int("old_attempts", currentAttempts),
		util.Int("new_attempts", newAttempts),
	)

	return newAttempts, nil
}

// ============================================
// RATE LIMITING & ANALYTICS
// ============================================

// GetOTPAttemptsByPhone counts OTP creation attempts within a time window
func (r *OTPRepositoryImpl) GetOTPAttemptsByPhone(ctx context.Context, phoneHash string, timeWindow time.Duration) (int, error) {
	startTime := time.Now().Add(-timeWindow)
	endTime := time.Now()

	otps, err := r.GetOTPsByTimeRange(ctx, phoneHash, startTime, endTime)
	if err != nil {
		return 0, err
	}

	return len(otps), nil
}

// GetOTPsByTimeRange retrieves all OTPs for a phone number within a time range
func (r *OTPRepositoryImpl) GetOTPsByTimeRange(ctx context.Context, phoneHash string, start, end time.Time) ([]*models.OTPVerification, error) {
	// Calculate time buckets for the range
	startBucket := r.getTimeBucketFromTime(start)
	endBucket := r.getTimeBucketFromTime(end)

	var allOTPs []*models.OTPVerification
	var mu sync.Mutex

	// Query each time bucket in parallel
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for bucket := startBucket; bucket <= endBucket; bucket++ {
		bucket := bucket
		g.Go(func() error {
			// Query by partition key prefix (phone_hash)
			query := r.client.Session.Query(`
				SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, otp_salt,
					   hash_algorithm, pepper_version, attempts, expires_at,
					   ip_address, device_id , provider_used
				FROM otp_verifications
				WHERE phone_hash = ? AND time_bucket = ?`,
				phoneHash, bucket,
			)

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
					&otp.IPAddress, // ✅ FIX: Use net.IP directly
					&otp.DeviceID,  // <-- ADD THIS
					&otp.ProviderUsed,
				) {
					break
				}

				// ✅ FIX: Ensure IP address is never nil
				if otp.IPAddress == nil {
					otp.IPAddress = net.ParseIP("0.0.0.0")
				}

				// Filter by timestamp in application layer
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

// CleanupExpiredOTPs removes expired OTPs (backup cleanup - TTL handles most cases)
func (r *OTPRepositoryImpl) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	if batchSize <= 0 || batchSize > OTPCleanupBatchSize {
		batchSize = OTPCleanupBatchSize
	}

	now := time.Now()
	deletedCount := 0

	// Only scan last 2 hours (not 24!) - TTL handles the rest automatically
	startBucket := r.getTimeBucketFromTime(now.Add(-2 * time.Hour))
	endBucket := r.bucketingManager.GetTimeBucket(OTPBucketWindowSeconds)

	// Limit max deletes to prevent long-running cleanup
	maxDeletes := 100

	batch := r.client.Batch(gocql.UnloggedBatch)
	batchCount := 0

	r.logger.Info("Starting OTP cleanup",
		util.Int64("start_bucket", startBucket),
		util.Int64("end_bucket", endBucket),
		util.Int("max_deletes", maxDeletes),
	)

	for bucket := startBucket; bucket <= endBucket; bucket++ {
		// Stop if we've hit max deletes
		if deletedCount >= maxDeletes {
			r.logger.Info("Reached max deletes limit, stopping cleanup",
				util.Int("deleted_count", deletedCount),
			)
			break
		}

		// Add LIMIT to prevent scanning too many rows
		query := r.client.Session.Query(`
            SELECT phone_hash, purpose, time_bucket, created_at, expires_at
            FROM otp_verifications
            WHERE time_bucket = ?
            LIMIT ?`,
			bucket, batchSize,
		)

		iter := query.WithContext(ctx).Iter()

		var phoneHash, purpose string
		var timeBucket int64
		var createdAt, expiresAt time.Time

		for iter.Scan(&phoneHash, &purpose, &timeBucket, &createdAt, &expiresAt) {
			// Only delete if expired
			if now.After(expiresAt) {
				batch.Query(`
                    DELETE FROM otp_verifications
                    WHERE phone_hash = ? AND purpose = ? AND time_bucket = ? AND created_at = ?`,
					phoneHash, purpose, timeBucket, createdAt,
				)

				batchCount++
				deletedCount++

				// Execute batch when full
				if batchCount >= batchSize {
					if err := r.client.ExecuteBatch(batch); err != nil {
						r.logger.Error("Failed to execute cleanup batch",
							util.ErrorField(err),
						)
					}
					batch = r.client.Batch(gocql.UnloggedBatch)
					batchCount = 0
				}
			}

			// Stop if reached max deletes
			if deletedCount >= maxDeletes {
				break
			}
		}

		if err := iter.Close(); err != nil {
			r.logger.Warn("Error closing iterator during cleanup",
				util.ErrorField(err),
				util.Int64("bucket", bucket),
			)
		}

		// Stop if reached max deletes
		if deletedCount >= maxDeletes {
			break
		}
	}

	// Execute remaining batch
	if batchCount > 0 {
		if err := r.client.ExecuteBatch(batch); err != nil {
			r.logger.Error("Failed to execute final cleanup batch",
				util.ErrorField(err),
			)
		}
	}

	r.logger.Info("OTP cleanup completed",
		util.Int("deleted_count", deletedCount),
		util.String("note", "TTL handles most expiry automatically - this is backup only"),
		util.String("scanned_window", "last 2 hours"),
	)

	return deletedCount, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

// CreateOTPsBatch creates multiple OTPs in batch
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

		// ✅ FIX: Ensure valid IP address for each OTP
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
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			USING TTL ?`,
			otp.PhoneHash, otp.Purpose, otp.TimeBucket, otp.CreatedAt, otp.OTPHash, otp.OTPSalt,
			otp.HashAlgorithm, otp.PepperVersion, otp.Attempts, otp.ExpiresAt,
			ipToStore, otp.ProviderUsed, ttlSeconds,
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

	r.logger.Info("Batch OTP creation completed",
		util.Int("otps_created", len(otps)),
	)

	return nil
}

// InvalidateOTPsBatch invalidates multiple OTPs in batch
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
				r.logger.Warn("Failed to invalidate OTP in batch",
					util.ErrorField(err),
					util.String("phone_hash", phoneHash),
				)
			}
			return nil // Continue with other invalidations
		})
	}

	_ = g.Wait()

	r.logger.Info("Batch OTP invalidation completed",
		util.Int("total", len(phoneHashes)),
		util.Int("errors", errorCount),
	)

	return nil
}

// ============================================
// HEALTH & STATS
// ============================================

// HealthCheck performs a health check on the OTP repository
func (r *OTPRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").WithContext(ctx).Scan(&count); err != nil {
		return fmt.Errorf("OTP repository health check failed: %w", err)
	}
	return nil
}

// GetOTPStats returns OTP repository statistics
func (r *OTPRepositoryImpl) GetOTPStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count active OTPs in current time bucket
	currentBucket := r.bucketingManager.GetTimeBucket(OTPBucketWindowSeconds)
	var count int64

	query := r.client.Session.Query(`
		SELECT COUNT(*) FROM otp_verifications WHERE time_bucket = ?`,
		currentBucket,
	)

	if err := query.WithContext(ctx).Scan(&count); err == nil {
		stats["active_otps_current_bucket"] = count
	}

	stats["max_attempts"] = OTPMaxAttempts
	stats["default_ttl_seconds"] = int(OTPDefaultTTL.Seconds())
	stats["max_batch_size"] = OTPMaxBatchSize
	stats["max_concurrent_reads"] = OTPMaxConcurrentReads
	stats["max_concurrent_writes"] = OTPMaxConcurrentWrites
	stats["otp_length"] = OTPLength
	stats["bucket_window_seconds"] = OTPBucketWindowSeconds
	stats["timestamp"] = time.Now().UTC()

	return stats, nil
}

// ============================================
// HELPER FUNCTIONS
// ============================================

// GenerateOTP generates a cryptographically secure random OTP
func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		length = OTPLength
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

// HashOTP creates a secure hash of an OTP
func HashOTP(otp, salt string) string {
	hash := sha256.Sum256([]byte(otp + salt))
	return hex.EncodeToString(hash[:])
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return hex.EncodeToString(salt), nil
}

// secureCompare performs constant-time string comparison to prevent timing attacks
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
