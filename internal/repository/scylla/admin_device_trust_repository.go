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

type AdminDeviceTrustRepository interface {
	GetAdminDeviceTrustLevel(ctx context.Context, adminID uuid.UUID, deviceID string) (*models.DeviceTrustLevel, error)
	SetAdminDeviceTrustLevel(ctx context.Context, adminID uuid.UUID, deviceID string, trust *models.DeviceTrustLevel) error
	MarkAdminSuccessfulLogin(ctx context.Context, adminID uuid.UUID, deviceID string, trust *models.DeviceTrustLevel) error
	GetAdminPrimaryDevice(ctx context.Context, adminID uuid.UUID) (*models.DeviceTrustLevel, error)
	BlockAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error
	RecordAdminDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error
	UpdateAdminDeviceRiskScore(ctx context.Context, adminID uuid.UUID, deviceID string, riskScore int) error
	GetAdminDevices(ctx context.Context, adminID uuid.UUID) ([]*models.DeviceTrustLevel, error)
}

type AdminDeviceTrustRepositoryImpl struct {
	client *ScyllaClient
}

func NewAdminDeviceTrustRepository(client *ScyllaClient) AdminDeviceTrustRepository {
	return &AdminDeviceTrustRepositoryImpl{
		client: client,
	}
}

func (r *AdminDeviceTrustRepositoryImpl) GetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedAdminID gocql.UUID
	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM admin_device_trust_levels WHERE admin_id = ? AND device_id = ?`,
		gocql.UUID(adminID), deviceID,
	)

	err := query.WithContext(ctx).Scan(
		&scannedAdminID,
		&trust.DeviceID,
		&trust.TrustStatus,
		&trust.DeviceFingerprint,
		&trust.OSVersion,
		&trust.AppVersion,
		&trust.LastIPAddress,
		&trust.LastIPSubnet,
		&trust.LastLocationHash,
		&trust.UserAgent,
		&trust.DeviceModel,
		&trust.FirstSuccessfulLogin,
		&trust.LastLogin,
		&trust.IsBlocked,
		&trust.RiskScore,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return &models.DeviceTrustLevel{
				UserID:      adminID,
				DeviceID:    deviceID,
				TrustStatus: models.TrustStatusUntrusted,
				IsBlocked:   false,
				RiskScore:   0,
			}, nil
		}
		return nil, fmt.Errorf("failed to get admin device trust level: %w", err)
	}
	trust.UserID = uuid.UUID(scannedAdminID)
	return &trust, nil
}

func (r *AdminDeviceTrustRepositoryImpl) SetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	query := r.client.Session.Query(`
        UPDATE admin_device_trust_levels
        SET trust_status = ?, device_fingerprint = ?, os_version = ?, app_version = ?,
            ip_address = ?, last_ip_subnet = ?, last_location_hash = ?, user_agent = ?,
            device_model = ?, last_login = ?, is_blocked = ?, risk_score = ?
        WHERE admin_id = ? AND device_id = ?`,
		string(trust.TrustStatus),
		trust.DeviceFingerprint,
		trust.OSVersion,
		trust.AppVersion,
		trust.LastIPAddress,
		trust.LastIPSubnet,
		trust.LastLocationHash,
		trust.UserAgent,
		trust.DeviceModel,
		time.Now(),
		trust.IsBlocked,
		trust.RiskScore,
		gocql.UUID(adminID),
		deviceID,
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to set admin device trust level: %w", err)
	}
	return nil
}

func (r *AdminDeviceTrustRepositoryImpl) MarkAdminSuccessfulLogin(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	now := time.Now()
	existing, err := r.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		// ignore error, proceed with untrusted
	}

	newStatus := models.TrustStatusUntrusted
	if existing == nil || existing.FirstSuccessfulLogin == nil {
		newStatus = models.TrustStatusTrusted
		trust.FirstSuccessfulLogin = &now
	}
	trust.LastLogin = &now
	trust.TrustStatus = newStatus

	query := r.client.Session.Query(`
        INSERT INTO admin_device_trust_levels
        (admin_id, device_id, trust_status, device_fingerprint, os_version, app_version,
         ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
         first_successful_login, last_login, is_blocked, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(adminID),
		deviceID,
		string(trust.TrustStatus),
		trust.DeviceFingerprint,
		trust.OSVersion,
		trust.AppVersion,
		trust.LastIPAddress,
		trust.LastIPSubnet,
		trust.LastLocationHash,
		trust.UserAgent,
		trust.DeviceModel,
		trust.FirstSuccessfulLogin,
		trust.LastLogin,
		false,
		trust.RiskScore,
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to mark admin successful login: %w", err)
	}
	return nil
}

func (r *AdminDeviceTrustRepositoryImpl) GetAdminPrimaryDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedAdminID gocql.UUID
	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM admin_device_trust_levels WHERE admin_id = ? AND trust_status = ?
        ALLOW FILTERING`,
		gocql.UUID(adminID),
		string(models.TrustStatusPrimary),
	)
	err := query.WithContext(ctx).Scan(
		&scannedAdminID,
		&trust.DeviceID,
		&trust.TrustStatus,
		&trust.DeviceFingerprint,
		&trust.OSVersion,
		&trust.AppVersion,
		&trust.LastIPAddress,
		&trust.LastIPSubnet,
		&trust.LastLocationHash,
		&trust.UserAgent,
		&trust.DeviceModel,
		&trust.FirstSuccessfulLogin,
		&trust.LastLogin,
		&trust.IsBlocked,
		&trust.RiskScore,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin primary device: %w", err)
	}
	trust.UserID = uuid.UUID(scannedAdminID)
	return &trust, nil
}

func (r *AdminDeviceTrustRepositoryImpl) BlockAdminDevice(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) error {
	query := r.client.Session.Query(`
        UPDATE admin_device_trust_levels
        SET is_blocked = true, risk_score = 100
        WHERE admin_id = ? AND device_id = ?`,
		gocql.UUID(adminID),
		deviceID,
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to block admin device: %w", err)
	}
	return nil
}

func (r *AdminDeviceTrustRepositoryImpl) UpdateAdminDeviceRiskScore(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	riskScore int,
) error {
	query := r.client.Session.Query(`
        UPDATE admin_device_trust_levels
        SET risk_score = ?
        WHERE admin_id = ? AND device_id = ?`,
		riskScore,
		gocql.UUID(adminID),
		deviceID,
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to update admin device risk score: %w", err)
	}
	return nil
}

func (r *AdminDeviceTrustRepositoryImpl) GetAdminDevices(
	ctx context.Context,
	adminID uuid.UUID,
) ([]*models.DeviceTrustLevel, error) {
	var devices []*models.DeviceTrustLevel
	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM admin_device_trust_levels WHERE admin_id = ?`,
		gocql.UUID(adminID),
	)
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var trust models.DeviceTrustLevel
	var scannedAdminID gocql.UUID
	for iter.Scan(
		&scannedAdminID,
		&trust.DeviceID,
		&trust.TrustStatus,
		&trust.DeviceFingerprint,
		&trust.OSVersion,
		&trust.AppVersion,
		&trust.LastIPAddress,
		&trust.LastIPSubnet,
		&trust.LastLocationHash,
		&trust.UserAgent,
		&trust.DeviceModel,
		&trust.FirstSuccessfulLogin,
		&trust.LastLogin,
		&trust.IsBlocked,
		&trust.RiskScore,
	) {
		trust.UserID = uuid.UUID(scannedAdminID)
		devices = append(devices, &trust)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get admin devices: %w", err)
	}
	return devices, nil
}

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

func (r *AdminDeviceTrustRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device trust repository health check failed: %w", err)
	}
	return nil
}
