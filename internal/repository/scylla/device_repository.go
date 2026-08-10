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

const (
	DeviceMaxBatchSize        = 100
	DeviceMaxConcurrentReads  = 50
	DeviceMaxConcurrentWrites = 20
	DeviceBindingHistoryLimit = 100
	DeviceMaxRetries          = 3
)

type DeviceRepositoryImpl struct {
	client *ScyllaClient
}

func NewDeviceRepository(client *ScyllaClient) DeviceRepository {
	return &DeviceRepositoryImpl{
		client: client,
	}
}

// BindUserDevice creates or updates (UPSERT) a device binding for a user.
// Uses UPDATE to be idempotent – if the row already exists, it will be overwritten.
func (r *DeviceRepositoryImpl) BindUserDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID, bindToken string,
) error {
	if userID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}
	if deviceID == "" || bindToken == "" {
		return apperrors.ErrInvalidInput
	}

	hashedToken := r.hashBindToken(bindToken)

	// Use UPDATE to overwrite existing binding (idempotent UPSERT).
	query := r.client.Query(`
		UPDATE user_active_device
		SET device_id = ?, session_id = ?, bound_at = ?, bind_token = ?
		WHERE user_id = ?
	`, deviceID, nil, time.Now().UTC(), hashedToken, gocql.UUID(userID))

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		return fmt.Errorf("failed to bind device: %w", err)
	}
	return nil
}

func (r *DeviceRepositoryImpl) GetActiveDevice(
	ctx context.Context,
	userID uuid.UUID,
) (*models.UserActiveDevice, error) {
	if userID == uuid.Nil {
		return nil, apperrors.ErrInvalidInput
	}

	query := r.client.Query(`
		SELECT user_id, device_id, session_id, bound_at, bind_token
		FROM user_active_device
		WHERE user_id = ?
	`, gocql.UUID(userID))

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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get active device: %w", err)
	}

	device.UserID = uuid.UUID(scannedUserID).String()
	if scannedSessionID != nil {
		sessionID := uuid.UUID(*scannedSessionID)
		device.SessionID = sessionID.String()
	}
	return &device, nil
}

func (r *DeviceRepositoryImpl) UnbindUserDevice(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}

	query := r.client.Query(`DELETE FROM user_active_device WHERE user_id = ?`, gocql.UUID(userID))
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		return fmt.Errorf("failed to unbind device: %w", err)
	}
	return nil
}

func (r *DeviceRepositoryImpl) UpdateDeviceSession(
	ctx context.Context,
	userID, sessionID uuid.UUID,
) error {
	if userID == uuid.Nil || sessionID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}

	query := r.client.Query(`
		UPDATE user_active_device SET session_id = ? WHERE user_id = ?
	`, gocql.UUID(sessionID), gocql.UUID(userID))

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), DeviceMaxRetries); err != nil {
		return fmt.Errorf("failed to update device session: %w", err)
	}
	return nil
}

func (r *DeviceRepositoryImpl) ValidateDeviceBinding(
	ctx context.Context,
	userID uuid.UUID,
	deviceID, bindToken string,
) (bool, error) {
	device, err := r.GetActiveDevice(ctx, userID)
	if err != nil {
		return false, err
	}
	if device == nil {
		return false, nil
	}
	if device.DeviceID != deviceID {
		return false, nil
	}

	hashedToken := r.hashBindToken(bindToken)
	return subtle.ConstantTimeCompare([]byte(device.BindToken), []byte(hashedToken)) == 1, nil
}

func (r *DeviceRepositoryImpl) GetDeviceBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	if limit <= 0 || limit > DeviceBindingHistoryLimit {
		limit = DeviceBindingHistoryLimit
	}

	device, err := r.GetActiveDevice(ctx, userID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}
	return []*models.UserActiveDevice{device}, nil
}

func (r *DeviceRepositoryImpl) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	if deviceID == "" {
		return nil, apperrors.ErrInvalidInput
	}

	query := r.client.Query(`
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
		device = models.UserActiveDevice{}
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate devices: %w", err)
	}
	return devices, nil
}

func (r *DeviceRepositoryImpl) CleanupOrphanedDevices(
	ctx context.Context,
	cutoffTime time.Time,
) (int, error) {
	query := r.client.Query(`SELECT user_id, bound_at FROM user_active_device`)
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
		return 0, fmt.Errorf("failed to scan orphaned devices: %w", err)
	}

	if len(orphanedUserIDs) > 0 {
		if err := r.UnbindUserDevicesBatch(ctx, orphanedUserIDs); err != nil {
			return 0, fmt.Errorf("failed to cleanup orphaned devices: %w", err)
		}
	}
	return len(orphanedUserIDs), nil
}

func (r *DeviceRepositoryImpl) BindUserDevicesBatch(
	ctx context.Context,
	bindings []models.UserActiveDevice,
) error {
	if len(bindings) == 0 {
		return nil
	}

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
				continue
			}
			hashedToken := r.hashBindToken(binding.BindToken)
			batch.Query(`
				UPDATE user_active_device
				SET device_id = ?, session_id = ?, bound_at = ?, bind_token = ?
				WHERE user_id = ?
			`,
				binding.DeviceID,
				nil,
				time.Now().UTC(),
				hashedToken,
				gocql.UUID(userID),
			)
		}
		if err := r.client.ExecuteBatch(batch); err != nil {
			return fmt.Errorf("failed to execute device binding batch: %w", err)
		}
	}
	return nil
}

func (r *DeviceRepositoryImpl) GetActiveDevicesBatch(
	ctx context.Context,
	userIDs []uuid.UUID,
) (map[uuid.UUID]*models.UserActiveDevice, error) {
	if len(userIDs) == 0 {
		return make(map[uuid.UUID]*models.UserActiveDevice), nil
	}

	devices := make(map[uuid.UUID]*models.UserActiveDevice)
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(DeviceMaxConcurrentReads)

	for _, userID := range userIDs {
		userID := userID
		g.Go(func() error {
			device, err := r.GetActiveDevice(gctx, userID)
			if err != nil && err != apperrors.ErrNotFound {
				return nil // ignore errors for individual users
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
	return devices, nil
}

func (r *DeviceRepositoryImpl) UnbindUserDevicesBatch(
	ctx context.Context,
	userIDs []uuid.UUID,
) error {
	if len(userIDs) == 0 {
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(DeviceMaxConcurrentWrites)
	for _, userID := range userIDs {
		userID := userID
		g.Go(func() error {
			_ = r.UnbindUserDevice(gctx, userID) // ignore errors
			return nil
		})
	}
	_ = g.Wait()
	return nil
}

func (r *DeviceRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	err := r.client.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count)
	if err != nil {
		return fmt.Errorf("device repository health check failed: %w", err)
	}
	return nil
}

func (r *DeviceRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := map[string]interface{}{
		"max_batch_size":        DeviceMaxBatchSize,
		"max_concurrent_reads":  DeviceMaxConcurrentReads,
		"max_concurrent_writes": DeviceMaxConcurrentWrites,
		"max_retries":           DeviceMaxRetries,
		"binding_history_limit": DeviceBindingHistoryLimit,
	}
	return stats, nil
}

func (r *DeviceRepositoryImpl) hashBindToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
