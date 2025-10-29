package scylla

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// Constants for device operations optimized for 500M scale
const (
	// Batch operation limits
	DeviceMaxBatchSize         = 100  // Maximum devices per batch operation
	DeviceMaxConcurrentReads   = 50   // Concurrent read operations
	DeviceMaxConcurrentWrites  = 20   // Concurrent write operations

	// Cache settings
	DeviceCacheTTL            = 5 * time.Minute // Active device cache TTL
	DeviceBindingHistoryLimit = 100             // Max history records

	// Retry configuration
	DeviceMaxRetries = 3
)

// DeviceRepositoryImpl handles all device-related database operations
// Optimized for high-throughput operations at 500M user scale
type DeviceRepositoryImpl struct {
	client  *ScyllaClient
	logger  *zap.Logger
	metrics *RepositoryMetrics

	// Prepared statements for frequently used queries
	stmtBindDevice      *gocql.Query
	stmtGetActiveDevice *gocql.Query
	stmtUnbindDevice    *gocql.Query
	stmtUpdateSession   *gocql.Query
	stmtMutex           sync.RWMutex
}

// NewDeviceRepository creates a new device repository with prepared statements
func NewDeviceRepository(client *ScyllaClient, logger *zap.Logger) DeviceRepository {
	repo := &DeviceRepositoryImpl{
		client:  client,
		logger:  logger,
		metrics: &RepositoryMetrics{},
	}

	// Prepare frequently used statements
	repo.prepareStatements()

	return repo
}

// prepareStatements prepares all frequently used queries for optimal performance
// IMPORTANT: Column names MUST match schema exactly - snake_case from CQL definition
func (r *DeviceRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare bind device statement
	// Schema columns: user_id, device_id, session_id, bound_at, bind_token
	r.stmtBindDevice = r.client.Session.Query(`
        INSERT INTO user_active_device (user_id, device_id, session_id, bound_at, bind_token)
        VALUES (?, ?, ?, ?, ?)
    `)

	// Prepare get active device statement
	r.stmtGetActiveDevice = r.client.Session.Query(`
        SELECT user_id, device_id, session_id, bound_at, bind_token
        FROM user_active_device
        WHERE user_id = ?
    `)

	// Prepare unbind device statement
	r.stmtUnbindDevice = r.client.Session.Query(`
        DELETE FROM user_active_device WHERE user_id = ?
    `)

	// Prepare update session statement
	r.stmtUpdateSession = r.client.Session.Query(`
        UPDATE user_active_device SET session_id = ? WHERE user_id = ?
    `)

	r.logger.Info("Device repository prepared statements initialized",
		zap.Int("statement_count", 4))
}

// ========================================================================
// CORE DEVICE BINDING OPERATIONS
// ========================================================================

// BindUserDevice creates or updates a device binding for a user
// Implements idempotent upsert with prepared statements
func (r *DeviceRepositoryImpl) BindUserDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID, bindToken string,
) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	// Validate inputs
	if userID == uuid.Nil {
		return fmt.Errorf("invalid user ID")
	}
	if deviceID == "" {
		return fmt.Errorf("device ID cannot be empty")
	}
	if bindToken == "" {
		return fmt.Errorf("bind token cannot be empty")
	}

	// Hash the bind token for secure storage
	hashedToken := r.hashBindToken(bindToken)

	// Use prepared statement with retry logic
	r.stmtMutex.RLock()
	query := r.stmtBindDevice.Bind(
		gocql.UUID(userID),
		deviceID,
		nil, // session_id will be set later
		time.Now().UTC(),
		hashedToken,
	)
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		r.logger.Error("Failed to bind device",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
			util.String("device_id", deviceID))
		return fmt.Errorf("failed to bind device: %w", err)
	}

	r.logger.Info("Device bound successfully",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetActiveDevice retrieves the currently active device for a user
// Returns nil if no active device is found
func (r *DeviceRepositoryImpl) GetActiveDevice(
	ctx context.Context,
	userID uuid.UUID,
) (*models.UserActiveDevice, error) {
	startTime := time.Now()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Use prepared statement for read
	r.stmtMutex.RLock()
	query := r.stmtGetActiveDevice.Bind(gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	var device models.UserActiveDevice
	var scannedUserID gocql.UUID
	var scannedSessionID *gocql.UUID

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedUserID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			r.metrics.RecordQuery(time.Since(startTime), true)
			return nil, nil // No active device found
		}
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get active device: %w", err)
	}

	// Convert scanned UUIDs
	device.UserID = uuid.UUID(scannedUserID).String()
	if scannedSessionID != nil {
		sessionID := uuid.UUID(*scannedSessionID)
		device.SessionID = sessionID.String()
	}

	r.metrics.RecordQuery(time.Since(startTime), true)

	return &device, nil
}

// UnbindUserDevice removes the device binding for a user
func (r *DeviceRepositoryImpl) UnbindUserDevice(ctx context.Context, userID uuid.UUID) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	if userID == uuid.Nil {
		return fmt.Errorf("invalid user ID")
	}

	r.stmtMutex.RLock()
	query := r.stmtUnbindDevice.Bind(gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		r.logger.Error("Failed to unbind device",
			util.ErrorField(err),
			util.String("user_id", userID.String()))
		return fmt.Errorf("failed to unbind device: %w", err)
	}

	r.logger.Info("Device unbound successfully",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// UpdateDeviceSession updates the session ID for an active device
func (r *DeviceRepositoryImpl) UpdateDeviceSession(
	ctx context.Context,
	userID, sessionID uuid.UUID,
) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	if userID == uuid.Nil || sessionID == uuid.Nil {
		return fmt.Errorf("invalid user ID or session ID")
	}

	r.stmtMutex.RLock()
	query := r.stmtUpdateSession.Bind(gocql.UUID(sessionID), gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		r.logger.Error("Failed to update device session",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
			util.String("session_id", sessionID.String()))
		return fmt.Errorf("failed to update device session: %w", err)
	}

	r.logger.Debug("Device session updated",
		util.String("user_id", userID.String()),
		util.String("session_id", sessionID.String()))

	return nil
}

// ValidateDeviceBinding checks if a device binding is valid
// Uses constant-time comparison to prevent timing attacks
func (r *DeviceRepositoryImpl) ValidateDeviceBinding(
	ctx context.Context,
	userID uuid.UUID,
	deviceID, bindToken string,
) (bool, error) {
	startTime := time.Now()

	device, err := r.GetActiveDevice(ctx, userID)
	if err != nil {
		return false, err
	}

	if device == nil {
		r.metrics.RecordQuery(time.Since(startTime), true)
		return false, nil
	}

	// Verify device ID matches
	if device.DeviceID != deviceID {
		r.metrics.RecordQuery(time.Since(startTime), true)
		return false, nil
	}

	// Verify bind token using constant-time comparison
	hashedToken := r.hashBindToken(bindToken)
	isValid := subtle.ConstantTimeCompare([]byte(device.BindToken), []byte(hashedToken)) == 1

	r.metrics.RecordQuery(time.Since(startTime), true)

	return isValid, nil
}

// ========================================================================
// DEVICE ANALYTICS & MANAGEMENT
// ========================================================================

// GetDeviceBindingHistory retrieves device binding history for a user
// Note: This requires a separate table or time-series approach for production
// Current implementation returns single active device (see schema limitation)
func (r *DeviceRepositoryImpl) GetDeviceBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if limit <= 0 || limit > DeviceBindingHistoryLimit {
		limit = DeviceBindingHistoryLimit
	}

	// Get current active device
	device, err := r.GetActiveDevice(ctx, userID)
	if err != nil {
		return nil, err
	}

	r.metrics.RecordQuery(time.Since(startTime), true)

	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}

	// Return as single-item slice
	// NOTE: For full history, implement a separate device_binding_history table
	return []*models.UserActiveDevice{device}, nil
}

// GetUsersByDevice finds all users associated with a device ID
// Uses ALLOW FILTERING - should be used sparingly
func (r *DeviceRepositoryImpl) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
	}

	// WARNING: This query uses ALLOW FILTERING and may be slow
	// Consider creating a device_id-indexed materialized view for production
	query := r.client.Session.Query(`
        SELECT user_id, device_id, session_id, bound_at, bind_token
        FROM user_active_device
        WHERE device_id = ?
        ALLOW FILTERING
    `, deviceID)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedUserID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice

	for iter.Scan(&scannedUserID, &device.DeviceID, &scannedSessionID, &device.BoundAt, &device.BindToken) {
		device.UserID = uuid.UUID(scannedUserID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		devices = append(devices, &device)
		device = models.UserActiveDevice{} // Reset for next iteration
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get users by device: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved users by device",
		util.String("device_id", deviceID),
		util.Int("user_count", len(devices)))

	return devices, nil
}

// CleanupOrphanedDevices removes device bindings older than cutoff time
// Returns the number of devices cleaned up
func (r *DeviceRepositoryImpl) CleanupOrphanedDevices(
	ctx context.Context,
	cutoffTime time.Time,
) (int, error) {
	startTime := time.Now()

	// NOTE: ScyllaDB doesn't support direct DELETE with WHERE on non-key columns
	// This implementation scans all devices and deletes individually
	// For production at scale, consider TTL-based expiration instead

	query := r.client.Session.Query(`
        SELECT user_id, bound_at
        FROM user_active_device
    `)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var orphanedUserIDs []uuid.UUID
	var scannedUserID gocql.UUID
	var boundAt time.Time

	for iter.Scan(&scannedUserID, &boundAt) {
		if boundAt.Before(cutoffTime) {
			orphanedUserIDs = append(orphanedUserIDs, uuid.UUID(scannedUserID))
		}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return 0, fmt.Errorf("failed to scan for orphaned devices: %w", err)
	}

	// Delete orphaned devices in batch
	if len(orphanedUserIDs) > 0 {
		if err := r.UnbindUserDevicesBatch(ctx, orphanedUserIDs); err != nil {
			return 0, fmt.Errorf("failed to cleanup orphaned devices: %w", err)
		}
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Cleaned up orphaned devices",
		util.Int("count", len(orphanedUserIDs)),
		util.Time("cutoff_time", cutoffTime),
		util.Duration("duration", time.Since(startTime)))

	return len(orphanedUserIDs), nil
}

// ========================================================================
// BATCH OPERATIONS FOR HIGH THROUGHPUT
// ========================================================================

// BindUserDevicesBatch binds multiple devices in a single batch operation
// Uses unlogged batches for better performance (devices are independent)
func (r *DeviceRepositoryImpl) BindUserDevicesBatch(
	ctx context.Context,
	bindings []models.UserActiveDevice,
) error {
	if len(bindings) == 0 {
		return nil
	}

	startTime := time.Now()
	totalBatches := (len(bindings) + DeviceMaxBatchSize - 1) / DeviceMaxBatchSize

	r.logger.Info("Starting batch device binding",
		util.Int("total_bindings", len(bindings)),
		util.Int("batch_count", totalBatches))

	// Process in chunks
	for i := 0; i < len(bindings); i += DeviceMaxBatchSize {
		end := i + DeviceMaxBatchSize
		if end > len(bindings) {
			end = len(bindings)
		}

		chunk := bindings[i:end]
		batch := r.client.Batch(gocql.UnloggedBatch)

		for _, binding := range chunk {
			userID, err := uuid.Parse(binding.UserID)
			if err != nil {
				r.logger.Warn("Invalid user ID in batch",
					util.String("user_id", binding.UserID))
				continue
			}

			hashedToken := r.hashBindToken(binding.BindToken)

			batch.Query(`
                INSERT INTO user_active_device (user_id, device_id, session_id, bound_at, bind_token)
                VALUES (?, ?, ?, ?, ?)
            `,
				gocql.UUID(userID),
				binding.DeviceID,
				nil,
				time.Now().UTC(),
				hashedToken,
			)
		}

		if err := r.client.ExecuteBatch(batch); err != nil {
			r.logger.Error("Failed to execute device binding batch",
				util.ErrorField(err),
				util.Int("batch_size", len(chunk)))
			return fmt.Errorf("failed to bind devices batch: %w", err)
		}
	}

	r.logger.Info("Batch device binding completed",
		util.Int("total_bindings", len(bindings)),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetActiveDevicesBatch retrieves active devices for multiple users
// Uses concurrent reads with error group for optimal performance
func (r *DeviceRepositoryImpl) GetActiveDevicesBatch(
	ctx context.Context,
	userIDs []uuid.UUID,
) (map[uuid.UUID]*models.UserActiveDevice, error) {
	if len(userIDs) == 0 {
		return make(map[uuid.UUID]*models.UserActiveDevice), nil
	}

	startTime := time.Now()
	devices := make(map[uuid.UUID]*models.UserActiveDevice)
	var mu sync.Mutex

	// Use errgroup for concurrent reads
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(DeviceMaxConcurrentReads)

	for _, userID := range userIDs {
		userID := userID // Capture for goroutine
		g.Go(func() error {
			device, err := r.GetActiveDevice(gctx, userID)
			if err != nil {
				r.logger.Warn("Failed to get device in batch",
					util.ErrorField(err),
					util.String("user_id", userID.String()))
				return nil // Continue with other devices
			}

			if device != nil {
				mu.Lock()
				devices[userID] = device
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("batch device retrieval failed: %w", err)
	}

	r.logger.Info("Batch device retrieval completed",
		util.Int("requested", len(userIDs)),
		util.Int("found", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// UnbindUserDevicesBatch removes multiple device bindings
// Uses batch delete with concurrency control
func (r *DeviceRepositoryImpl) UnbindUserDevicesBatch(
	ctx context.Context,
	userIDs []uuid.UUID,
) error {
	if len(userIDs) == 0 {
		return nil
	}

	startTime := time.Now()
	var errorCount int
	var mu sync.Mutex

	// Use errgroup for concurrent deletes
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(DeviceMaxConcurrentWrites)

	for _, userID := range userIDs {
		userID := userID // Capture for goroutine
		g.Go(func() error {
			if err := r.UnbindUserDevice(gctx, userID); err != nil {
				mu.Lock()
				errorCount++
				mu.Unlock()
				r.logger.Warn("Failed to unbind device in batch",
					util.ErrorField(err),
					util.String("user_id", userID.String()))
				return nil // Continue with other devices
			}
			return nil
		})
	}

	g.Wait()

	r.logger.Info("Batch device unbinding completed",
		util.Int("total", len(userIDs)),
		util.Int("errors", errorCount),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ========================================================================
// HEALTH & MONITORING
// ========================================================================

// HealthCheck verifies repository connectivity and health
func (r *DeviceRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("device repository health check failed: %w", err)
	}
	return nil
}

// GetRepositoryStats returns performance metrics
func (r *DeviceRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := r.metrics.GetStats()

	stats["max_batch_size"] = DeviceMaxBatchSize
	stats["max_concurrent_reads"] = DeviceMaxConcurrentReads
	stats["max_concurrent_writes"] = DeviceMaxConcurrentWrites
	stats["cache_ttl_seconds"] = int(DeviceCacheTTL.Seconds())
	stats["max_retries"] = DeviceMaxRetries

	return stats, nil
}

// ========================================================================
// HELPER FUNCTIONS
// ========================================================================

// hashBindToken creates a secure hash of a bind token
// Uses SHA-256 for consistent hashing
func (r *DeviceRepositoryImpl) hashBindToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
