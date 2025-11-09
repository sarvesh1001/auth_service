// internal/repository/scylla/admin_device_trust_repository.go
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

type AdminDeviceTrustRepository interface {
	GetAdminDeviceTrustLevel(ctx context.Context, adminID uuid.UUID, deviceID string) (*models.DeviceTrustLevel, error)
	SetAdminDeviceTrustLevel(ctx context.Context, adminID uuid.UUID, deviceID string, status models.DeviceTrustStatus) error
	MarkAdminSuccessfulLogin(ctx context.Context, adminID uuid.UUID, deviceID string, ipAddress, userAgent string) error
	GetAdminPrimaryDevice(ctx context.Context, adminID uuid.UUID) (*models.DeviceTrustLevel, error)
	BlockAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error
	RecordAdminDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error
}

type AdminDeviceTrustRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger
}

func NewAdminDeviceTrustRepository(client *ScyllaClient, logger *zap.Logger) AdminDeviceTrustRepository {
	return &AdminDeviceTrustRepositoryImpl{
		client: client,
		logger: logger,
	}
}

// GetAdminDeviceTrustLevel retrieves trust details for an admin device
func (r *AdminDeviceTrustRepositoryImpl) GetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedAdminID gocql.UUID

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, first_successful_login, last_login, 
               ip_address, user_agent, is_blocked
        FROM admin_device_trust_levels WHERE admin_id = ? AND device_id = ?`,
		gocql.UUID(adminID), deviceID,
	)

	if err := query.WithContext(ctx).Scan(
		&scannedAdminID,
		&trust.DeviceID,
		&trust.TrustStatus,
		&trust.FirstSuccessfulLogin,
		&trust.LastLogin,
		&trust.IPAddress,
		&trust.UserAgent,
		&trust.IsBlocked,
	); err != nil {
		if err == gocql.ErrNotFound {
			return &models.DeviceTrustLevel{
				UserID:      adminID,
				DeviceID:    deviceID,
				TrustStatus: models.TrustStatusUntrusted,
				IsBlocked:   false,
			}, nil
		}
		return nil, fmt.Errorf("failed to get admin device trust level: %w", err)
	}

	trust.UserID = uuid.UUID(scannedAdminID)
	return &trust, nil
}

// SetAdminDeviceTrustLevel updates the trust level for a specific admin device
func (r *AdminDeviceTrustRepositoryImpl) SetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	status models.DeviceTrustStatus,
) error {
	query := r.client.Session.Query(`
        UPDATE admin_device_trust_levels 
        SET trust_status = ?, last_login = ?
        WHERE admin_id = ? AND device_id = ?`,
		string(status),
		time.Now(),
		gocql.UUID(adminID),
		deviceID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to set admin device trust level: %w", err)
	}

	r.logger.Debug("Admin device trust level updated",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("trust_status", string(status)),
	)

	return nil
}

// MarkAdminSuccessfulLogin records a successful login and updates trust level
func (r *AdminDeviceTrustRepositoryImpl) MarkAdminSuccessfulLogin(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	ipAddress, userAgent string,
) error {
	now := time.Now()

	existing, err := r.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		r.logger.Error("Failed to get existing admin trust level", util.ErrorField(err))
	}

	newStatus := models.TrustStatusUntrusted
	if existing == nil || existing.FirstSuccessfulLogin == nil {
		newStatus = models.TrustStatusTrusted
	}

	query := r.client.Session.Query(`
        INSERT INTO admin_device_trust_levels 
        (admin_id, device_id, trust_status, first_successful_login, last_login, ip_address, user_agent, is_blocked)
        VALUES (?, ?, ?, ?, ?, ?, ?, false)`,
		gocql.UUID(adminID),
		deviceID,
		string(newStatus),
		now,
		now,
		ipAddress,
		userAgent,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to mark admin successful login: %w", err)
	}

	r.logger.Info("Admin device marked as trusted after successful login",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("trust_status", string(newStatus)),
	)

	return nil
}

// GetAdminPrimaryDevice fetches the primary trusted device for an admin
func (r *AdminDeviceTrustRepositoryImpl) GetAdminPrimaryDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedAdminID gocql.UUID

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, first_successful_login, last_login, 
               ip_address, user_agent, is_blocked
        FROM admin_device_trust_levels WHERE admin_id = ? AND trust_status = ?
        ALLOW FILTERING`,
		gocql.UUID(adminID),
		string(models.TrustStatusPrimary),
	)

	if err := query.WithContext(ctx).Scan(
		&scannedAdminID,
		&trust.DeviceID,
		&trust.TrustStatus,
		&trust.FirstSuccessfulLogin,
		&trust.LastLogin,
		&trust.IPAddress,
		&trust.UserAgent,
		&trust.IsBlocked,
	); err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("no admin primary device found")
		}
		return nil, fmt.Errorf("failed to get admin primary device: %w", err)
	}

	trust.UserID = uuid.UUID(scannedAdminID)
	return &trust, nil
}

// BlockAdminDevice marks a device as blocked for an admin
func (r *AdminDeviceTrustRepositoryImpl) BlockAdminDevice(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) error {
	query := r.client.Session.Query(`
        UPDATE admin_device_trust_levels 
        SET is_blocked = true
        WHERE admin_id = ? AND device_id = ?`,
		gocql.UUID(adminID),
		deviceID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to block admin device: %w", err)
	}

	r.logger.Info("Admin device blocked",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
	)

	return nil
}

// RecordAdminDataDeletion logs data deletion actions for admins
func (r *AdminDeviceTrustRepositoryImpl) RecordAdminDataDeletion(
	ctx context.Context,
	deletion *models.UserDataDeletion,
) error {
	var deletedByID *gocql.UUID
	if deletion.DeletedBy != nil {
		id := gocql.UUID(*deletion.DeletedBy)
		deletedByID = &id
	}

	query := r.client.Session.Query(`
        INSERT INTO admin_data_deletions 
        (deletion_id, admin_id, device_id, reason, deleted_at, data_wiped_categories, deleted_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(deletion.DeletionID),
		gocql.UUID(deletion.UserID),
		deletion.DeviceID,
		deletion.Reason,
		deletion.DeletedAt,
		deletion.DataWipedCategories,
		deletedByID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to record admin data deletion: %w", err)
	}

	return nil
}
// Add this method to AdminDeviceTrustRepositoryImpl
func (r *AdminDeviceTrustRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device trust repository health check failed: %w", err)
	}
	return nil
}