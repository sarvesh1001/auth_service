package scylla

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type AdminDeviceRepository interface {
	BindAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID, bindToken string) error
	GetAdminActiveDevice(ctx context.Context, adminID uuid.UUID) (*models.UserActiveDevice, error)
	UnbindAdminDevice(ctx context.Context, adminID uuid.UUID) error
	UpdateAdminDeviceSession(ctx context.Context, adminID, sessionID uuid.UUID) error
	ValidateAdminDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID, bindToken string) (bool, error)
	GetAdminDeviceBindingHistory(ctx context.Context, adminID uuid.UUID, limit int) ([]*models.UserActiveDevice, error)
	GetAdminsByDevice(ctx context.Context, deviceID string) ([]*models.UserActiveDevice, error)
	CleanupAdminOrphanedDevices(ctx context.Context, cutoffTime time.Time) (int, error)
	GetAdminActiveDevicesBatch(ctx context.Context, adminIDs []uuid.UUID) (map[uuid.UUID]*models.UserActiveDevice, error)
	UnbindAdminDevicesBatch(ctx context.Context, adminIDs []uuid.UUID) error
	BindAdminDevicesBatch(ctx context.Context, bindings []models.UserActiveDevice) error
	HealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	GetUsersByDevice(ctx context.Context, deviceID string) ([]*models.UserActiveDevice, error)
	BindUserDevice(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) error
}

type AdminDeviceRepositoryImpl struct {
	client            *ScyllaClient
	metrics           *RepositoryMetrics
	stmtBindDevice    *gocql.Query
	stmtGetActive     *gocql.Query
	stmtUnbind        *gocql.Query
	stmtUpdateSession *gocql.Query
	stmtMutex         sync.RWMutex
}

func NewAdminDeviceRepository(client *ScyllaClient) *AdminDeviceRepositoryImpl {
	repo := &AdminDeviceRepositoryImpl{
		client:  client,
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
	r.stmtGetActive = r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token
        FROM admin_active_device
        WHERE admin_id = ?
    `)
	r.stmtUnbind = r.client.Session.Query(`
        DELETE FROM admin_active_device WHERE admin_id = ?
    `)
	r.stmtUpdateSession = r.client.Session.Query(`
        UPDATE admin_active_device SET session_id = ? WHERE admin_id = ?
    `)
}

func (r *AdminDeviceRepositoryImpl) BindAdminDevice(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID, bindToken string,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if adminID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}
	if deviceID == "" || bindToken == "" {
		return apperrors.ErrInvalidInput
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
		return fmt.Errorf("failed to bind admin device: %w", err)
	}
	return nil
}

func (r *AdminDeviceRepositoryImpl) GetAdminActiveDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.UserActiveDevice, error) {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return nil, apperrors.ErrInvalidInput
	}

	r.stmtMutex.RLock()
	query := r.stmtGetActive.Bind(gocql.UUID(adminID))
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
		return apperrors.ErrInvalidInput
	}

	r.stmtMutex.RLock()
	query := r.stmtUnbind.Bind(gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to unbind admin device: %w", err)
	}
	return nil
}

func (r *AdminDeviceRepositoryImpl) UpdateAdminDeviceSession(
	ctx context.Context,
	adminID, sessionID uuid.UUID,
) error {
	startTime := time.Now()
	defer func() { r.metrics.RecordQuery(time.Since(startTime), true) }()

	if adminID == uuid.Nil || sessionID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}

	r.stmtMutex.RLock()
	query := r.stmtUpdateSession.Bind(gocql.UUID(sessionID), gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin device session: %w", err)
	}
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
		return nil, apperrors.ErrInvalidInput
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
	return len(orphanedAdminIDs), nil
}

func (r *AdminDeviceRepositoryImpl) GetAdminActiveDevicesBatch(
	ctx context.Context,
	adminIDs []uuid.UUID,
) (map[uuid.UUID]*models.UserActiveDevice, error) {
	if len(adminIDs) == 0 {
		return make(map[uuid.UUID]*models.UserActiveDevice), nil
	}

	devices := make(map[uuid.UUID]*models.UserActiveDevice)
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(50)

	for _, adminID := range adminIDs {
		adminID := adminID
		g.Go(func() error {
			device, err := r.GetAdminActiveDevice(gctx, adminID)
			if err != nil {
				return nil // ignore individual errors
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

	return devices, nil
}

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
		return fmt.Errorf("failed to unbind admin devices batch: %w", err)
	}
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
			continue // skip invalid
		}
		hashedToken := r.hashBindToken(binding.BindToken)
		batch.Query(`
            INSERT INTO admin_active_device (admin_id, device_id, session_id, bound_at, bind_token)
            VALUES (?, ?, ?, ?, ?)`,
			gocql.UUID(adminID),
			binding.DeviceID,
			nil,
			now,
			hashedToken,
		)
	}

	if err := r.client.ExecuteBatch(batch); err != nil {
		return fmt.Errorf("failed to bind admin devices batch: %w", err)
	}
	return nil
}

func (r *AdminDeviceRepositoryImpl) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	return r.GetAdminsByDevice(ctx, deviceID)
}

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

func (r *AdminDeviceRepositoryImpl) hashBindToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// For compatibility with admin device repository
func (r *AdminDeviceRepositoryImpl) BindUserDevice(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) error {
	return r.BindAdminDevice(ctx, userID, deviceID, bindToken)
}
