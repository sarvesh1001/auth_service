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

type AdminDeviceHistoryRepository interface {
	RecordAdminBinding(ctx context.Context, adminID uuid.UUID, deviceID string, sessionID *uuid.UUID, bindToken string, action string) error
	GetAdminBindingHistory(ctx context.Context, adminID uuid.UUID, limit int) ([]*models.UserActiveDevice, error)
	GetAdminRecentBindingsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.UserActiveDevice, error)
	GetAdminBindingsByTimeRange(ctx context.Context, startTime, endTime time.Time, limit int) ([]*models.UserActiveDevice, error)
	CleanupAdminOldRecords(ctx context.Context, olderThan time.Duration) (int, error)
	GetAdminStats(ctx context.Context, adminID uuid.UUID) (map[string]interface{}, error)
	HealthCheck(ctx context.Context) error
}

type AdminDeviceHistoryRepositoryImpl struct {
	client  *ScyllaClient
	metrics *RepositoryMetrics
}

func NewAdminDeviceHistoryRepository(client *ScyllaClient) *AdminDeviceHistoryRepositoryImpl {
	return &AdminDeviceHistoryRepositoryImpl{
		client:  client,
		metrics: &RepositoryMetrics{},
	}
}

func (r *AdminDeviceHistoryRepositoryImpl) RecordAdminBinding(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	sessionID *uuid.UUID,
	bindToken string,
	action string,
) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	if adminID == uuid.Nil {
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
        INSERT INTO admin_device_binding_history
        (admin_id, device_id, session_id, bound_at, bind_token, action)
        VALUES (?, ?, ?, ?, ?, ?)
    `,
		gocql.UUID(adminID),
		deviceID,
		sessionID,
		now,
		bindToken,
		action,
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to record admin device binding: %w", err)
	}
	return nil
}

func (r *AdminDeviceHistoryRepositoryImpl) GetAdminBindingHistory(
	ctx context.Context,
	adminID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return nil, apperrors.ErrInvalidInput
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token, action
        FROM admin_device_binding_history
        WHERE admin_id = ?
        ORDER BY bound_at DESC
        LIMIT ?
    `, gocql.UUID(adminID), limit)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice
	var action string

	for iter.Scan(
		&scannedAdminID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
		&action,
	) {
		device.UserID = uuid.UUID(scannedAdminID).String()
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
		return nil, fmt.Errorf("failed to get admin binding history: %w", err)
	}
	r.metrics.RecordQuery(time.Since(startTime), true)
	return devices, nil
}

func (r *AdminDeviceHistoryRepositoryImpl) GetAdminRecentBindingsByDevice(
	ctx context.Context,
	deviceID string,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()
	if deviceID == "" {
		return nil, apperrors.ErrInvalidInput
	}
	if limit <= 0 || limit > 50 {
		limit = 50
	}

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token, action
        FROM admin_device_binding_history
        WHERE device_id = ?
        ALLOW FILTERING
        LIMIT ?
    `, deviceID, limit)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice
	var action string

	for iter.Scan(
		&scannedAdminID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
		&action,
	) {
		device.UserID = uuid.UUID(scannedAdminID).String()
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
		return nil, fmt.Errorf("failed to get recent bindings by device: %w", err)
	}
	r.metrics.RecordQuery(time.Since(startTime), true)
	return devices, nil
}

func (r *AdminDeviceHistoryRepositoryImpl) GetAdminBindingsByTimeRange(
	ctx context.Context,
	startTime, endTime time.Time,
	limit int,
) ([]*models.UserActiveDevice, error) {
	queryStart := time.Now()
	if startTime.After(endTime) {
		return nil, apperrors.ErrInvalidInput
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token, action
        FROM admin_device_binding_history
        WHERE bound_at >= ? AND bound_at <= ?
        ALLOW FILTERING
        LIMIT ?
    `, startTime, endTime, limit)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice
	var action string

	for iter.Scan(
		&scannedAdminID,
		&device.DeviceID,
		&scannedSessionID,
		&device.BoundAt,
		&device.BindToken,
		&action,
	) {
		device.UserID = uuid.UUID(scannedAdminID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		devCopy := device
		devices = append(devices, &devCopy)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(queryStart), false)
		return nil, fmt.Errorf("failed to get bindings by time range: %w", err)
	}
	r.metrics.RecordQuery(time.Since(queryStart), true)
	return devices, nil
}

func (r *AdminDeviceHistoryRepositoryImpl) CleanupAdminOldRecords(
	ctx context.Context,
	olderThan time.Duration,
) (int, error) {
	startTime := time.Now()
	cutoffTime := time.Now().Add(-olderThan)

	query := r.client.Session.Query(`
        SELECT admin_id, bound_at
        FROM admin_device_binding_history
        WHERE bound_at < ?
        ALLOW FILTERING
    `, cutoffTime)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var recordsToDelete []struct {
		adminID uuid.UUID
		boundAt time.Time
	}
	var scannedAdminID gocql.UUID
	var boundAt time.Time

	for iter.Scan(&scannedAdminID, &boundAt) {
		recordsToDelete = append(recordsToDelete, struct {
			adminID uuid.UUID
			boundAt time.Time
		}{
			adminID: uuid.UUID(scannedAdminID),
			boundAt: boundAt,
		})
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return 0, fmt.Errorf("failed to scan old admin device records: %w", err)
	}

	batchSize := 50
	deletedCount := 0
	for i := 0; i < len(recordsToDelete); i += batchSize {
		end := i + batchSize
		if end > len(recordsToDelete) {
			end = len(recordsToDelete)
		}
		batch := r.client.Batch(gocql.LoggedBatch)
		for j := i; j < end; j++ {
			record := recordsToDelete[j]
			batch.Query(`
                DELETE FROM admin_device_binding_history
                WHERE admin_id = ? AND bound_at = ?
            `, gocql.UUID(record.adminID), record.boundAt)
		}
		if err := r.client.ExecuteBatch(batch); err != nil {
			// continue despite errors
			continue
		}
		deletedCount += (end - i)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	return deletedCount, nil
}

func (r *AdminDeviceHistoryRepositoryImpl) GetAdminStats(
	ctx context.Context,
	adminID uuid.UUID,
) (map[string]interface{}, error) {
	startTime := time.Now()
	stats := make(map[string]interface{})

	var totalBindings int64
	query := r.client.Session.Query(`
        SELECT COUNT(*)
        FROM admin_device_binding_history
        WHERE admin_id = ?
    `, gocql.UUID(adminID))
	if err := query.WithContext(ctx).Scan(&totalBindings); err != nil {
		return nil, fmt.Errorf("failed to get total bindings count: %w", err)
	}
	stats["total_bindings"] = totalBindings

	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var recentActivity int64
	query = r.client.Session.Query(`
        SELECT COUNT(*)
        FROM admin_device_binding_history
        WHERE admin_id = ? AND bound_at >= ?
    `, gocql.UUID(adminID), thirtyDaysAgo)
	if err := query.WithContext(ctx).Scan(&recentActivity); err != nil {
		return nil, fmt.Errorf("failed to get recent activity count: %w", err)
	}
	stats["recent_activity_30d"] = recentActivity

	var uniqueDevices int
	query = r.client.Session.Query(`
        SELECT DISTINCT device_id
        FROM admin_device_binding_history
        WHERE admin_id = ?
        ALLOW FILTERING
    `, gocql.UUID(adminID))
	iter := query.WithContext(ctx).Iter()
	uniqueDevices = 0
	for iter.Scan() {
		uniqueDevices++
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get unique devices count: %w", err)
	}
	stats["unique_devices"] = uniqueDevices

	r.metrics.RecordQuery(time.Since(startTime), true)
	stats["query_duration_ms"] = time.Since(startTime).Milliseconds()
	return stats, nil
}

func (r *AdminDeviceHistoryRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device history repository health check failed: %w", err)
	}
	return nil
}
