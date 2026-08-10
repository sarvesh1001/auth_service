package scylla

import (
	"context"
	"fmt"
	"time"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
)

type DeviceHistoryRepositoryImpl struct {
	client  *ScyllaClient
	metrics *RepositoryMetrics
}

func NewDeviceHistoryRepository(client *ScyllaClient) *DeviceHistoryRepositoryImpl {
	return &DeviceHistoryRepositoryImpl{
		client:  client,
		metrics: &RepositoryMetrics{},
	}
}

func (r *DeviceHistoryRepositoryImpl) RecordBinding(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	sessionID *uuid.UUID,
	bindToken string,
	action string,
) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	if userID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}
	if deviceID == "" {
		return apperrors.ErrInvalidInput
	}
	if action != "bind" && action != "unbind" {
		return apperrors.ErrInvalidInput
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
		return fmt.Errorf("failed to record device binding: %w", err)
	}
	return nil
}

func (r *DeviceHistoryRepositoryImpl) GetBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()
	if userID == uuid.Nil {
		return nil, apperrors.ErrInvalidInput
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

	for iter.Scan(
		&scannedUserID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
	) {
		device.UserID = uuid.UUID(scannedUserID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		devCopy := device
		devices = append(devices, &devCopy)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get binding history: %w", err)
	}
	r.metrics.RecordQuery(time.Since(startTime), true)
	return devices, nil
}

func (r *DeviceHistoryRepositoryImpl) GetUsersByDeviceFromHistory(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()
	if deviceID == "" {
		return nil, apperrors.ErrInvalidInput
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

	for iter.Scan(
		&scannedUserID,
		&device.DeviceID,
		&device.BoundAt,
		&device.BindToken,
	) {
		device.UserID = uuid.UUID(scannedUserID).String()
		devCopy := device
		devices = append(devices, &devCopy)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get users by device from history: %w", err)
	}
	r.metrics.RecordQuery(time.Since(startTime), true)
	return devices, nil
}

func (r *DeviceHistoryRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("device history repository health check failed: %w", err)
	}
	return nil
}
