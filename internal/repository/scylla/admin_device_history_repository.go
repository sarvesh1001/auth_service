// internal/repository/scylla/admin_device_history_repository.go
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
	logger  *zap.Logger
	metrics *RepositoryMetrics
}

func NewAdminDeviceHistoryRepository(client *ScyllaClient, logger *zap.Logger) *AdminDeviceHistoryRepositoryImpl {
	return &AdminDeviceHistoryRepositoryImpl{
		client:  client,
		logger:  logger,
		metrics: &RepositoryMetrics{},
	}
}

// RecordAdminBinding records an admin device binding event (bind or unbind)
func (r *AdminDeviceHistoryRepositoryImpl) RecordAdminBinding(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	sessionID *uuid.UUID,
	bindToken string,
	action string, // "bind" or "unbind"
) error {
	startTime := time.Now()
	defer func() {
		r.metrics.RecordQuery(time.Since(startTime), true)
	}()

	if adminID == uuid.Nil {
		return fmt.Errorf("invalid admin ID")
	}
	if deviceID == "" {
		return fmt.Errorf("device ID cannot be empty")
	}
	if action != "bind" && action != "unbind" {
		return fmt.Errorf("invalid action: %s", action)
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
		r.logger.Error("Failed to record admin device binding",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.String("action", action))
		return fmt.Errorf("failed to record admin device binding: %w", err)
	}

	r.logger.Info("Admin device binding recorded",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("action", action),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetAdminBindingHistory retrieves complete binding history for an admin
func (r *AdminDeviceHistoryRepositoryImpl) GetAdminBindingHistory(
	ctx context.Context,
	adminID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return nil, fmt.Errorf("invalid admin ID")
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
		r.logger.Error("Failed to get admin binding history",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()))
		return nil, fmt.Errorf("failed to get admin binding history: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved admin binding history",
		util.String("admin_id", adminID.String()),
		util.Int("count", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// GetAdminRecentBindingsByDevice finds recent admin bindings for a specific device
func (r *AdminDeviceHistoryRepositoryImpl) GetAdminRecentBindingsByDevice(
	ctx context.Context,
	deviceID string,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
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
		r.logger.Error("Failed to get recent bindings by device",
			util.ErrorField(err),
			util.String("device_id", deviceID))
		return nil, fmt.Errorf("failed to get recent bindings by device: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Retrieved recent admin bindings by device",
		util.String("device_id", deviceID),
		util.Int("count", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// GetAdminBindingsByTimeRange retrieves admin device bindings within a time range
func (r *AdminDeviceHistoryRepositoryImpl) GetAdminBindingsByTimeRange(
	ctx context.Context,
	startTime, endTime time.Time,
	limit int,
) ([]*models.UserActiveDevice, error) {
	queryStart := time.Now()

	if startTime.After(endTime) {
		return nil, fmt.Errorf("start time cannot be after end time")
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
		r.logger.Error("Failed to get bindings by time range",
			util.ErrorField(err),
			util.Time("start_time", startTime),
			util.Time("end_time", endTime))
		return nil, fmt.Errorf("failed to get bindings by time range: %w", err)
	}

	r.metrics.RecordQuery(time.Since(queryStart), true)
	r.logger.Info("Retrieved admin bindings by time range",
		util.Time("start_time", startTime),
		util.Time("end_time", endTime),
		util.Int("count", len(devices)),
		util.Duration("duration", time.Since(queryStart)))

	return devices, nil
}

// CleanupAdminOldRecords removes admin device binding records older than specified duration
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
			r.logger.Error("Failed to execute cleanup batch",
				util.ErrorField(err),
				util.Int("batch_index", i/batchSize))
			continue
		}

		deletedCount += (end - i)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	r.logger.Info("Admin device history cleanup completed",
		util.Int("deleted_records", deletedCount),
		util.Duration("older_than", olderThan),
		util.Duration("duration", time.Since(startTime)))

	return deletedCount, nil
}

// GetAdminStats returns statistics about admin device binding history
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

// This method already exists in your code, just ensure it's there
// HealthCheck verifies admin device history repository connectivity
func (r *AdminDeviceHistoryRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device history repository health check failed: %w", err)
	}
	return nil
}