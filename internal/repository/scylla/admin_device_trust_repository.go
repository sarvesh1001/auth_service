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

// =========================================================================
// GetAdminDeviceTrustLevel
//
// Returns the trust row, or a synthetic "untrusted" record when the row
// does not exist (never returns nil,nil — callers can rely on non-nil).
// =========================================================================
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

// =========================================================================
// SetAdminDeviceTrustLevel
//
// Full upsert of the trust row EXCEPT for first_successful_login, which
// is preserved from the existing row when present. This method is used by
// callers who want to explicitly override status/risk/etc.
// =========================================================================
func (r *AdminDeviceTrustRepositoryImpl) SetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	// Preserve first_successful_login if it already exists.
	existing, _ := r.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if existing != nil && existing.FirstSuccessfulLogin != nil {
		trust.FirstSuccessfulLogin = existing.FirstSuccessfulLogin
	}
	if trust.LastLogin == nil {
		now := time.Now()
		trust.LastLogin = &now
	}

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
		trust.LastLogin,
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

// =========================================================================
// MarkAdminSuccessfulLogin
//
// ★ THE BUG FIX.
//
// Upserts the trust row after a successful admin login. Trust is STICKY:
// once Trusted or Primary, it is never downgraded by a subsequent login.
//
// Rules:
//   - first_successful_login is only set on the very first login; later
//     logins preserve the original timestamp.
//   - last_login is refreshed on every call.
//   - trust_status is preserved: Primary stays Primary, Trusted stays
//     Trusted. A new row starts as Trusted.
//   - is_blocked is preserved from the DB, never auto-cleared by a login.
//   - Risk score is preserved (not reset).
//
// Previous bug: the old version computed newStatus = Untrusted for any
// admin whose FirstSuccessfulLogin was already set — i.e., every login
// after the first silently downgraded a trusted device to untrusted.
// =========================================================================
func (r *AdminDeviceTrustRepositoryImpl) MarkAdminSuccessfulLogin(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	now := time.Now()

	existing, err := r.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return fmt.Errorf("mark_admin_successful_login: read existing: %w", err)
	}

	// --- first_successful_login: preserve once set ---
	if existing != nil && existing.FirstSuccessfulLogin != nil {
		trust.FirstSuccessfulLogin = existing.FirstSuccessfulLogin
	} else {
		trust.FirstSuccessfulLogin = &now
	}

	// --- trust_status: preserve / upgrade, NEVER downgrade ---
	switch {
	case trust.TrustStatus == models.TrustStatusPrimary:
		// Caller is explicitly promoting to Primary — honor it.
	case existing != nil && existing.TrustStatus == models.TrustStatusPrimary:
		trust.TrustStatus = models.TrustStatusPrimary
	case existing != nil && existing.TrustStatus == models.TrustStatusTrusted:
		trust.TrustStatus = models.TrustStatusTrusted
	default:
		// New device, or previously untrusted — a successful login
		// marks it Trusted.
		trust.TrustStatus = models.TrustStatusTrusted
	}

	// --- is_blocked: preserve from DB, never auto-unblock on login ---
	blocked := false
	if existing != nil {
		blocked = existing.IsBlocked
	}

	// --- last_login: always refresh ---
	trust.LastLogin = &now

	// --- risk_score: preserve from DB if caller didn't set one ---
	if trust.RiskScore == 0 && existing != nil && existing.RiskScore != 0 {
		trust.RiskScore = existing.RiskScore
	}

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
		blocked,
		trust.RiskScore,
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to mark admin successful login: %w", err)
	}
	return nil
}

// =========================================================================
// GetAdminPrimaryDevice
// =========================================================================
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

// =========================================================================
// BlockAdminDevice
// =========================================================================
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

// =========================================================================
// UpdateAdminDeviceRiskScore
// =========================================================================
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

// =========================================================================
// GetAdminDevices
//
// ★ FIXED: slice aliasing. Each iteration allocates a fresh
// DeviceTrustLevel; the previous version reused a single struct so every
// element in the returned slice pointed to the same memory.
// =========================================================================
func (r *AdminDeviceTrustRepositoryImpl) GetAdminDevices(
	ctx context.Context,
	adminID uuid.UUID,
) ([]*models.DeviceTrustLevel, error) {
	query := r.client.Session.Query(`
        SELECT admin_id, device_id, trust_status, device_fingerprint, os_version, app_version,
               ip_address, last_ip_subnet, last_location_hash, user_agent, device_model,
               first_successful_login, last_login, is_blocked, risk_score
        FROM admin_device_trust_levels WHERE admin_id = ?`,
		gocql.UUID(adminID),
	)
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.DeviceTrustLevel

	for {
		trust := &models.DeviceTrustLevel{} // fresh allocation each iteration
		var scannedAdminID gocql.UUID
		if !iter.Scan(
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
			break
		}
		trust.UserID = uuid.UUID(scannedAdminID)
		devices = append(devices, trust)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get admin devices: %w", err)
	}
	return devices, nil
}

// =========================================================================
// RecordAdminDataDeletion
// =========================================================================
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

// =========================================================================
// HealthCheck
// =========================================================================
func (r *AdminDeviceTrustRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count); err != nil {
		return fmt.Errorf("admin device trust repository health check failed: %w", err)
	}
	return nil
}
