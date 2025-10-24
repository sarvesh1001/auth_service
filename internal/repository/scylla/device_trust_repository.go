// internal/repository/scylla/device_trust_repository.go

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
    SetDeviceTrustLevel(ctx context.Context, userID uuid.UUID, deviceID string, status models.DeviceTrustStatus) error
    MarkSuccessfulLogin(ctx context.Context, userID uuid.UUID, deviceID string, ipAddress, userAgent string) error
    GetPrimaryDevice(ctx context.Context, userID uuid.UUID) (*models.DeviceTrustLevel, error)
    BlockDevice(ctx context.Context, userID uuid.UUID, deviceID string) error
    RecordDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error
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

func (r *DeviceTrustRepositoryImpl) GetDeviceTrustLevel(ctx context.Context, userID uuid.UUID, deviceID string) (*models.DeviceTrustLevel, error) {
    var trust models.DeviceTrustLevel
    var scannedUserID gocql.UUID

    query := r.client.Session.Query(`
        SELECT user_id, device_id, trust_status, first_successful_login, last_login, 
               ip_address, user_agent, is_blocked
        FROM device_trust_levels WHERE user_id = ? AND device_id = ?`,
        gocql.UUID(userID), deviceID,
    )

    if err := query.WithContext(ctx).Scan(
        &scannedUserID,
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
                UserID:      userID,
                DeviceID:    deviceID,
                TrustStatus: models.TrustStatusUntrusted,
                IsBlocked:   false,
            }, nil
        }
        return nil, fmt.Errorf("failed to get device trust level: %w", err)
    }

    trust.UserID = uuid.UUID(scannedUserID)
    return &trust, nil
}

func (r *DeviceTrustRepositoryImpl) SetDeviceTrustLevel(ctx context.Context, userID uuid.UUID, deviceID string, status models.DeviceTrustStatus) error {
    query := r.client.Session.Query(`
        UPDATE device_trust_levels 
        SET trust_status = ?, last_login = ?
        WHERE user_id = ? AND device_id = ?`,
        string(status),
        time.Now(),
        gocql.UUID(userID),
        deviceID,
    )

    if err := query.WithContext(ctx).Exec(); err != nil {
        return fmt.Errorf("failed to set device trust level: %w", err)
    }

    r.logger.Debug("Device trust level updated",
        util.String("user_id", userID.String()),
        util.String("device_id", deviceID),
        util.String("trust_status", string(status)),
    )

    return nil
}

func (r *DeviceTrustRepositoryImpl) MarkSuccessfulLogin(ctx context.Context, userID uuid.UUID, deviceID string, ipAddress, userAgent string) error {
    now := time.Now()

    // Get current status to check if first login
    existing, err := r.GetDeviceTrustLevel(ctx, userID, deviceID)
    if err != nil {
        r.logger.Error("Failed to get existing trust level", util.ErrorField(err))
    }

    // If first login, mark as trusted
    newStatus := models.TrustStatusUntrusted
    if existing == nil || existing.FirstSuccessfulLogin == nil {
        newStatus = models.TrustStatusTrusted
    }

    query := r.client.Session.Query(`
        INSERT INTO device_trust_levels 
        (user_id, device_id, trust_status, first_successful_login, last_login, ip_address, user_agent, is_blocked)
        VALUES (?, ?, ?, ?, ?, ?, ?, false)`,
        gocql.UUID(userID),
        deviceID,
        string(newStatus),
        now,
        now,
        ipAddress,
        userAgent,
    )

    if err := query.WithContext(ctx).Exec(); err != nil {
        return fmt.Errorf("failed to mark successful login: %w", err)
    }

    r.logger.Info("Device marked as trusted after successful login",
        util.String("user_id", userID.String()),
        util.String("device_id", deviceID),
        util.String("trust_status", string(newStatus)),
    )

    return nil
}

func (r *DeviceTrustRepositoryImpl) GetPrimaryDevice(ctx context.Context, userID uuid.UUID) (*models.DeviceTrustLevel, error) {
    var trust models.DeviceTrustLevel
    var scannedUserID gocql.UUID

    query := r.client.Session.Query(`
        SELECT user_id, device_id, trust_status, first_successful_login, last_login, 
               ip_address, user_agent, is_blocked
        FROM device_trust_levels WHERE user_id = ? AND trust_status = ?
        ALLOW FILTERING`,
        gocql.UUID(userID),
        string(models.TrustStatusPrimary),
    )

    if err := query.WithContext(ctx).Scan(
        &scannedUserID,
        &trust.DeviceID,
        &trust.TrustStatus,
        &trust.FirstSuccessfulLogin,
        &trust.LastLogin,
        &trust.IPAddress,
        &trust.UserAgent,
        &trust.IsBlocked,
    ); err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("no primary device found")
        }
        return nil, fmt.Errorf("failed to get primary device: %w", err)
    }

    trust.UserID = uuid.UUID(scannedUserID)
    return &trust, nil
}

func (r *DeviceTrustRepositoryImpl) BlockDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
    query := r.client.Session.Query(`
        UPDATE device_trust_levels 
        SET is_blocked = true
        WHERE user_id = ? AND device_id = ?`,
        gocql.UUID(userID),
        deviceID,
    )

    if err := query.WithContext(ctx).Exec(); err != nil {
        return fmt.Errorf("failed to block device: %w", err)
    }

    return nil
}

func (r *DeviceTrustRepositoryImpl) RecordDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error {
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
