// internal/repository/scylla/admin_device_repository.go
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

type AdminDeviceRepository interface {
	// Core device binding operations
	BindAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID, bindToken string) error
	GetAdminActiveDevice(ctx context.Context, adminID uuid.UUID) (*models.UserActiveDevice, error)
	UnbindAdminDevice(ctx context.Context, adminID uuid.UUID) error
	UpdateAdminDeviceSession(ctx context.Context, adminID, sessionID uuid.UUID) error
	ValidateAdminDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID, bindToken string) (bool, error)

	// Device analytics & management
	GetAdminDeviceBindingHistory(ctx context.Context, adminID uuid.UUID, limit int) ([]*models.UserActiveDevice, error)
	GetAdminsByDevice(ctx context.Context, deviceID string) ([]*models.UserActiveDevice, error)
	CleanupAdminOrphanedDevices(ctx context.Context, cutoffTime time.Time) (int, error)

	// Batch operations
	GetAdminActiveDevicesBatch(ctx context.Context, adminIDs []uuid.UUID) (map[uuid.UUID]*models.UserActiveDevice, error)
	UnbindAdminDevicesBatch(ctx context.Context, adminIDs []uuid.UUID) error
	BindAdminDevicesBatch(ctx context.Context, bindings []models.UserActiveDevice) error

	// Health & monitoring
	HealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)

	// Compatibility methods
	GetUsersByDevice(ctx context.Context, deviceID string) ([]*models.UserActiveDevice, error)
	BindUserDevice(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) error
}

// AdminDeviceRepositoryImpl handles all admin device-related database operations
type AdminDeviceRepositoryImpl struct {
	client  *ScyllaClient
	logger  *zap.Logger
	metrics *RepositoryMetrics

	stmtBindDevice      *gocql.Query
	stmtGetActiveDevice *gocql.Query
	stmtUnbindDevice    *gocql.Query
	stmtUpdateSession   *gocql.Query
	stmtMutex           sync.RWMutex
}

func NewAdminDeviceRepository(client *ScyllaClient, logger *zap.Logger) *AdminDeviceRepositoryImpl {
	repo := &AdminDeviceRepositoryImpl{
		client:  client,
		logger:  logger,
		metrics: &RepositoryMetrics{},
	}
	repo.prepareStatements()
	return repo
}

func (r *AdminDeviceRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	r.stmtBindDevice = r.client.Session.Query(`
        INSERT INTO admin_active_device (admin_id, device_id, session_id, bound_at, bind_token)
        VALUES (?, ?, ?, ?, ?)
    `)

	r.stmtGetActiveDevice = r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token
        FROM admin_active_device
        WHERE admin_id = ?
    `)

	r.stmtUnbindDevice = r.client.Session.Query(`
        DELETE FROM admin_active_device WHERE admin_id = ?
    `)

	r.stmtUpdateSession = r.client.Session.Query(`
        UPDATE admin_active_device SET session_id = ? WHERE admin_id = ?
    `)

	r.logger.Info("Admin device repository prepared statements initialized")
}

// ========================================================================
// CORE DEVICE BINDING OPERATIONS
// ========================================================================

func (r *AdminDeviceRepositoryImpl) BindAdminDevice(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID, bindToken string,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if adminID == uuid.Nil {
		return fmt.Errorf("invalid admin ID")
	}
	if deviceID == "" {
		return fmt.Errorf("device ID cannot be empty")
	}
	if bindToken == "" {
		return fmt.Errorf("bind token cannot be empty")
	}

	hashedToken := r.hashBindToken(bindToken)

	r.stmtMutex.RLock()
	query := r.stmtBindDevice.Bind(
		gocql.UUID(adminID),
		deviceID,
		nil,
		time.Now().UTC(),
		hashedToken,
	)
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		r.logger.Error("Failed to bind admin device",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID))
		return fmt.Errorf("failed to bind admin device: %w", err)
	}

	r.logger.Info("Admin device bound successfully",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *AdminDeviceRepositoryImpl) GetAdminActiveDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.UserActiveDevice, error) {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return nil, fmt.Errorf("invalid admin ID")
	}

	r.stmtMutex.RLock()
	query := r.stmtGetActiveDevice.Bind(gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	var device models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedAdminID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			r.metrics.RecordQuery(time.Since(startTime), true)
			return nil, nil
		}
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get active admin device: %w", err)
	}

	device.UserID = uuid.UUID(scannedAdminID).String()
	if scannedSessionID != nil {
		sessionID := uuid.UUID(*scannedSessionID)
		device.SessionID = sessionID.String()
	}

	r.metrics.RecordQuery(time.Since(startTime), true)

	return &device, nil
}

func (r *AdminDeviceRepositoryImpl) UnbindAdminDevice(
	ctx context.Context,
	adminID uuid.UUID,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if adminID == uuid.Nil {
		return fmt.Errorf("invalid admin ID")
	}

	r.stmtMutex.RLock()
	query := r.stmtUnbindDevice.Bind(gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		r.logger.Error("Failed to unbind admin device",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()))
		return fmt.Errorf("failed to unbind admin device: %w", err)
	}

	r.logger.Info("Admin device unbound successfully",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *AdminDeviceRepositoryImpl) UpdateAdminDeviceSession(
	ctx context.Context,
	adminID, sessionID uuid.UUID,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if adminID == uuid.Nil || sessionID == uuid.Nil {
		return fmt.Errorf("invalid admin ID or session ID")
	}

	r.stmtMutex.RLock()
	query := r.stmtUpdateSession.Bind(gocql.UUID(sessionID), gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		r.logger.Error("Failed to update admin device session",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
			util.String("session_id", sessionID.String()))
		return fmt.Errorf("failed to update admin device session: %w", err)
	}

	r.logger.Debug("Admin device session updated",
		util.String("admin_id", adminID.String()),
		util.String("session_id", sessionID.String()))

	return nil
}

func (r *AdminDeviceRepositoryImpl) ValidateAdminDeviceBinding(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID, bindToken string,
) (bool, error) {
	startTime := time.Now()

	device, err := r.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		return false, err
	}

	if device == nil {
		r.metrics.RecordQuery(time.Since(startTime), true)
		return false, nil
	}

	if device.DeviceID != deviceID {
		r.metrics.RecordQuery(time.Since(startTime), true)
		return false, nil
	}

	hashedToken := r.hashBindToken(bindToken)
	isValid := subtle.ConstantTimeCompare([]byte(device.BindToken), []byte(hashedToken)) == 1

	r.metrics.RecordQuery(time.Since(startTime), true)
	return isValid, nil
}

// ========================================================================
// DEVICE ANALYTICS & MANAGEMENT
// ========================================================================

func (r *AdminDeviceRepositoryImpl) GetAdminDeviceBindingHistory(
	ctx context.Context,
	adminID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if limit <= 0 || limit > 100 {
		limit = 100
	}

	device, err := r.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		return nil, err
	}

	r.metrics.RecordQuery(time.Since(startTime), true)

	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}

	return []*models.UserActiveDevice{device}, nil
}

func (r *AdminDeviceRepositoryImpl) GetAdminsByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
	}

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token
        FROM admin_active_device
        WHERE device_id = ?
        ALLOW FILTERING
    `, deviceID)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice

	for iter.Scan(&scannedAdminID, &device.DeviceID, &scannedSessionID, &device.BoundAt, &device.BindToken) {
		device.UserID = uuid.UUID(scannedAdminID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		devices = append(devices, &device)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get admins by device: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved admins by device",
		util.String("device_id", deviceID),
		util.Int("admin_count", len(devices)))

	return devices, nil
}

func (r *AdminDeviceRepositoryImpl) CleanupAdminOrphanedDevices(
	ctx context.Context,
	cutoffTime time.Time,
) (int, error) {
	startTime := time.Now()

	query := r.client.Session.Query(`
        SELECT admin_id, bound_at
        FROM admin_active_device
    `)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var orphanedAdminIDs []uuid.UUID
	var scannedAdminID gocql.UUID
	var boundAt time.Time

	for iter.Scan(&scannedAdminID, &boundAt) {
		if boundAt.Before(cutoffTime) {
			orphanedAdminIDs = append(orphanedAdminIDs, uuid.UUID(scannedAdminID))
		}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return 0, fmt.Errorf("failed to scan for orphaned admin devices: %w", err)
	}

	if len(orphanedAdminIDs) > 0 {
		if err := r.UnbindAdminDevicesBatch(ctx, orphanedAdminIDs); err != nil {
			return 0, fmt.Errorf("failed to cleanup orphaned admin devices: %w", err)
		}
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Cleaned up orphaned admin devices",
		util.Int("count", len(orphanedAdminIDs)),
		util.Time("cutoff_time", cutoffTime),
		util.Duration("duration", time.Since(startTime)))

	return len(orphanedAdminIDs), nil
}

// ========================================================================
// BATCH OPERATIONS FOR HIGH THROUGHPUT
// ========================================================================

func (r *AdminDeviceRepositoryImpl) GetAdminActiveDevicesBatch(
	ctx context.Context,
	adminIDs []uuid.UUID,
) (map[uuid.UUID]*models.UserActiveDevice, error) {
	if len(adminIDs) == 0 {
		return make(map[uuid.UUID]*models.UserActiveDevice), nil
	}

	startTime := time.Now()
	devices := make(map[uuid.UUID]*models.UserActiveDevice)
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(50)

	for _, adminID := range adminIDs {
		adminID := adminID
		g.Go(func() error {
			device, err := r.GetAdminActiveDevice(gctx, adminID)
			if err != nil {
				r.logger.Warn("Failed to get admin device in batch",
					util.ErrorField(err),
					util.String("admin_id", adminID.String()))
				return nil
			}

			if device != nil {
				mu.Lock()
				devices[adminID] = device
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("batch admin device retrieval failed: %w", err)
	}

	r.logger.Info("Batch admin device retrieval completed",
		util.Int("requested", len(adminIDs)),
		util.Int("found", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// ========================================================================
// HEALTH & MONITORING
// ========================================================================

func (r *AdminDeviceRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device repository health check failed: %w", err)
	}
	return nil
}

func (r *AdminDeviceRepositoryImpl) GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := r.metrics.GetStats()
	stats["max_batch_size"] = 100
	stats["max_concurrent_reads"] = 50
	stats["max_concurrent_writes"] = 20
	stats["repository_type"] = "admin_device"
	return stats, nil
}

// ========================================================================
// HELPER FUNCTIONS
// ========================================================================

func (r *AdminDeviceRepositoryImpl) hashBindToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (r *AdminDeviceRepositoryImpl) BindAdminDeviceForUser(
	ctx context.Context,
	bindings []models.UserActiveDevice,
) error {
	adminBindings := make([]models.UserActiveDevice, len(bindings))
	for i, binding := range bindings {
		adminBindings[i] = binding
	}
	return r.BindAdminDevicesBatch(ctx, adminBindings)
}

// ========================================================================
// MISSING BATCH OPERATIONS - ADD THESE METHODS
// ========================================================================

func (r *AdminDeviceRepositoryImpl) UnbindAdminDevicesBatch(
	ctx context.Context,
	adminIDs []uuid.UUID,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if len(adminIDs) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	for _, adminID := range adminIDs {
		if adminID == uuid.Nil {
			continue
		}
		batch.Query(`DELETE FROM admin_active_device WHERE admin_id = ?`, gocql.UUID(adminID))
	}

	if err := r.client.ExecuteBatch(batch); err != nil {
		r.logger.Error("Failed to unbind admin devices batch",
			util.ErrorField(err),
			util.Int("admin_count", len(adminIDs)))
		return fmt.Errorf("failed to unbind admin devices batch: %w", err)
	}

	r.logger.Info("Admin devices batch unbound successfully",
		util.Int("admin_count", len(adminIDs)),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *AdminDeviceRepositoryImpl) BindAdminDevicesBatch(
	ctx context.Context,
	bindings []models.UserActiveDevice,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if len(bindings) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	now := time.Now().UTC()

	for _, binding := range bindings {
		adminID, err := uuid.Parse(binding.UserID)
		if err != nil {
			r.logger.Warn("Invalid admin ID in batch binding",
				util.String("user_id", binding.UserID))
			continue
		}

		hashedToken := r.hashBindToken(binding.BindToken)

		batch.Query(`
            INSERT INTO admin_active_device (admin_id, device_id, session_id, bound_at, bind_token)
            VALUES (?, ?, ?, ?, ?)`,
			gocql.UUID(adminID),
			binding.DeviceID,
			nil, // session_id will be set later
			now,
			hashedToken,
		)
	}

	if err := r.client.ExecuteBatch(batch); err != nil {
		r.logger.Error("Failed to bind admin devices batch",
			util.ErrorField(err),
			util.Int("binding_count", len(bindings)))
		return fmt.Errorf("failed to bind admin devices batch: %w", err)
	}

	r.logger.Info("Admin devices batch bound successfully",
		util.Int("binding_count", len(bindings)),
		util.Duration("duration", time.Since(startTime)))

	return nil
}
