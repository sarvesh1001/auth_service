package scylla

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DeviceHistoryRepositoryImpl tracks device binding history
type DeviceHistoryRepositoryImpl struct {
	client  *ScyllaClient
	logger  *zap.Logger
	metrics *RepositoryMetrics
}

// NewDeviceHistoryRepository creates a new device history repository
func NewDeviceHistoryRepository(client *ScyllaClient, logger *zap.Logger) *DeviceHistoryRepositoryImpl {
	return &DeviceHistoryRepositoryImpl{
		client:  client,
		logger:  logger,
		metrics: &RepositoryMetrics{},
	}
}

// RecordBinding records a device binding event (bind or unbind)
func (r *DeviceHistoryRepositoryImpl) RecordBinding(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	sessionID *uuid.UUID,
	bindToken string,
	action string, // "bind" or "unbind"
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
	if action != "bind" && action != "unbind" {
		return fmt.Errorf("invalid action: %s", action)
	}

	now := time.Now().UTC()
	query := r.client.Session.Query(`
        INSERT INTO user_device_binding_history 
        (user_id, bound_at, device_id, session_id, bind_token, action, action_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
		gocql.UUID(userID),
		now,
		deviceID,
		sessionID,
		bindToken,
		action,
		now,
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		r.logger.Error("Failed to record device binding",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
			util.String("device_id", deviceID),
			util.String("action", action))
		return fmt.Errorf("failed to record device binding: %w", err)
	}

	r.logger.Info("Device binding recorded",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.String("action", action),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetBindingHistory retrieves complete binding history for a user
func (r *DeviceHistoryRepositoryImpl) GetBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	if limit <= 0 || limit > 100 {
		limit = 100
	}

	query := r.client.Session.Query(`
        SELECT user_id, device_id, session_id, bound_at, bind_token
        FROM user_device_binding_history
        WHERE user_id = ?
        ORDER BY action_timestamp DESC
        LIMIT ?
    `, gocql.UUID(userID), limit)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedUserID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice

	// ✅ FIX: Scan in same order as SELECT statement
	for iter.Scan(
		&scannedUserID,      // user_id
		&device.DeviceID,    // device_id
		&scannedSessionID,   // session_id
		&device.BoundAt,     // bound_at
		&device.BindToken,   // bind_token
	) {
		device.UserID = uuid.UUID(scannedUserID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		
		// Make a copy to append
		devCopy := device
		devices = append(devices, &devCopy)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		r.logger.Error("Failed to get binding history",
			util.ErrorField(err),
			util.String("user_id", userID.String()))
		return nil, fmt.Errorf("failed to get binding history: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved binding history",
		util.String("user_id", userID.String()),
		util.Int("count", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// GetUsersByDeviceFromHistory finds users by device ID from history
// Uses materialized view for efficient lookup
func (r *DeviceHistoryRepositoryImpl) GetUsersByDeviceFromHistory(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
	}

	query := r.client.Session.Query(`
        SELECT user_id, device_id, bound_at, bind_token
        FROM device_bindings_by_device_id
        WHERE device_id = ?
    `, deviceID)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedUserID gocql.UUID
	var device models.UserActiveDevice

	// ✅ FIX: Scan in same order as SELECT statement
	for iter.Scan(
		&scannedUserID,      // user_id
		&device.DeviceID,    // device_id
		&device.BoundAt,     // bound_at
		&device.BindToken,   // bind_token
	) {
		device.UserID = uuid.UUID(scannedUserID).String()
		
		// Make a copy to append
		devCopy := device
		devices = append(devices, &devCopy)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		r.logger.Error("Failed to get users by device from history",
			util.ErrorField(err),
			util.String("device_id", deviceID))
		return nil, fmt.Errorf("failed to get users by device from history: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved users by device from history",
		util.String("device_id", deviceID),
		util.Int("user_count", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// HealthCheck verifies history repository connectivity
func (r *DeviceHistoryRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("device history repository health check failed: %w", err)
	}
	return nil
}
