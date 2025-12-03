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

type DeviceTrustRepository interface {
	GetDeviceTrustLevel(ctx context.Context, userID uuid.UUID, deviceID string) (*models.DeviceTrustLevel, error)
	SetDeviceTrustLevel(ctx context.Context, userID uuid.UUID, deviceID string, trust *models.DeviceTrustLevel) error
	MarkSuccessfulLogin(ctx context.Context, userID uuid.UUID, deviceID string, trust *models.DeviceTrustLevel) error
	GetPrimaryDevice(ctx context.Context, userID uuid.UUID) (*models.DeviceTrustLevel, error)
	BlockDevice(ctx context.Context, userID uuid.UUID, deviceID string) error
	RecordDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error
	UpdateDeviceRiskScore(ctx context.Context, userID uuid.UUID, deviceID string, riskScore int) error
	GetUserDevices(ctx context.Context, userID uuid.UUID) ([]*models.DeviceTrustLevel, error)
	HealthCheck(ctx context.Context) error
	UpdateRisk(ctx context.Context, trustLevel *models.DeviceTrustLevel) error
}

type DeviceTrustRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger
}

func NewDeviceTrustRepository(client *ScyllaClient, logger *zap.Logger) DeviceTrustRepository {
	return &DeviceTrustRepositoryImpl{
		client: client,
		logger: logger,
	}
}

func (r *DeviceTrustRepositoryImpl) GetDeviceTrustLevel(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedUserID gocql.UUID

	query := r.client.Session.Query(`
        SELECT user_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM device_trust_levels WHERE user_id = ? AND device_id = ?`,
		gocql.UUID(userID), deviceID,
	)

	if err := query.WithContext(ctx).Scan(
		&scannedUserID,
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
	); err != nil {
		if err == gocql.ErrNotFound {
			return &models.DeviceTrustLevel{
				UserID:      userID,
				DeviceID:    deviceID,
				TrustStatus: models.TrustStatusUntrusted,
				IsBlocked:   false,
				RiskScore:   0,
			}, nil
		}
		return nil, fmt.Errorf("failed to get device trust level: %w", err)
	}

	trust.UserID = uuid.UUID(scannedUserID)
	return &trust, nil
}

func (r *DeviceTrustRepositoryImpl) SetDeviceTrustLevel(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	query := r.client.Session.Query(`
        UPDATE device_trust_levels 
        SET trust_status = ?, device_fingerprint = ?, os_version = ?, app_version = ?,
            ip_address = ?, last_ip_subnet = ?, last_location_hash = ?, user_agent = ?,
            device_model = ?, last_login = ?, is_blocked = ?, risk_score = ?
        WHERE user_id = ? AND device_id = ?`,
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
		gocql.UUID(userID),
		deviceID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to set device trust level: %w", err)
	}

	r.logger.Debug("Device trust level updated",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.String("trust_status", string(trust.TrustStatus)),
		util.Int("risk_score", trust.RiskScore),
	)

	return nil
}

func (r *DeviceTrustRepositoryImpl) MarkSuccessfulLogin(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	now := time.Now()

	existing, err := r.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		r.logger.Error("Failed to get existing device trust level", util.ErrorField(err))
	}

	newStatus := models.TrustStatusUntrusted
	if existing == nil || existing.FirstSuccessfulLogin == nil {
		newStatus = models.TrustStatusTrusted
		trust.FirstSuccessfulLogin = &now
	}

	trust.LastLogin = &now
	trust.TrustStatus = newStatus

	query := r.client.Session.Query(`
        INSERT INTO device_trust_levels 
        (user_id, device_id, trust_status, device_fingerprint, os_version, app_version,
         ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
         first_successful_login, last_login, is_blocked, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(userID),
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
		return fmt.Errorf("failed to mark successful login: %w", err)
	}

	r.logger.Info("Device marked as trusted after successful login",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.String("trust_status", string(newStatus)),
		util.String("device_fingerprint", trust.DeviceFingerprint),
	)

	return nil
}

func (r *DeviceTrustRepositoryImpl) GetPrimaryDevice(
	ctx context.Context,
	userID uuid.UUID,
) (*models.DeviceTrustLevel, error) {
	var trust models.DeviceTrustLevel
	var scannedUserID gocql.UUID

	query := r.client.Session.Query(`
        SELECT user_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM device_trust_levels WHERE user_id = ? AND trust_status = ?
        ALLOW FILTERING`,
		gocql.UUID(userID),
		string(models.TrustStatusPrimary),
	)

	if err := query.WithContext(ctx).Scan(
		&scannedUserID,
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
	); err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("no primary device found")
		}
		return nil, fmt.Errorf("failed to get primary device: %w", err)
	}

	trust.UserID = uuid.UUID(scannedUserID)
	return &trust, nil
}

func (r *DeviceTrustRepositoryImpl) BlockDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) error {
	query := r.client.Session.Query(`
        UPDATE device_trust_levels 
        SET is_blocked = true, risk_score = 100
        WHERE user_id = ? AND device_id = ?`,
		gocql.UUID(userID),
		deviceID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to block device: %w", err)
	}

	r.logger.Info("Device blocked",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
	)

	return nil
}

func (r *DeviceTrustRepositoryImpl) UpdateDeviceRiskScore(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	riskScore int,
) error {
	query := r.client.Session.Query(`
        UPDATE device_trust_levels 
        SET risk_score = ?
        WHERE user_id = ? AND device_id = ?`,
		riskScore,
		gocql.UUID(userID),
		deviceID,
	)

	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to update device risk score: %w", err)
	}

	r.logger.Debug("Device risk score updated",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.Int("risk_score", riskScore),
	)

	return nil
}

func (r *DeviceTrustRepositoryImpl) GetUserDevices(
	ctx context.Context,
	userID uuid.UUID,
) ([]*models.DeviceTrustLevel, error) {
	var devices []*models.DeviceTrustLevel

	query := r.client.Session.Query(`
        SELECT user_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM device_trust_levels WHERE user_id = ?`,
		gocql.UUID(userID),
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var trust models.DeviceTrustLevel
	var scannedUserID gocql.UUID

	for iter.Scan(
		&scannedUserID,
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
		trust.UserID = uuid.UUID(scannedUserID)
		devices = append(devices, &trust)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	return devices, nil
}

func (r *DeviceTrustRepositoryImpl) RecordDataDeletion(
	ctx context.Context,
	deletion *models.UserDataDeletion,
) error {
	var deletedByID *gocql.UUID
	if deletion.DeletedBy != nil {
		id := gocql.UUID(*deletion.DeletedBy)
		deletedByID = &id
	}

	query := r.client.Session.Query(`
        INSERT INTO user_data_deletions 
        (deletion_id, user_id, device_id, reason, deleted_at, data_wiped_categories, deleted_by)
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
		return fmt.Errorf("failed to record data deletion: %w", err)
	}

	return nil
}

func (r *DeviceTrustRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("device trust repository health check failed: %w", err)
	}
	return nil
}
func (r *DeviceTrustRepositoryImpl) UpdateRisk(ctx context.Context, trustLevel *models.DeviceTrustLevel) error {
	return r.UpdateDeviceRiskScore(ctx, trustLevel.UserID, trustLevel.DeviceID, trustLevel.RiskScore)
}
