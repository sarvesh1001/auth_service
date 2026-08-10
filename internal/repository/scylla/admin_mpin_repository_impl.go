package scylla

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/models"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
)

const (
	AdminMPINMaxFailedAttempts = 5
	AdminMPINLockoutDuration   = 30 * time.Minute
	AdminMPINBatchSize         = 100
)

type AdminMPINRepository interface {
	CreateAdminMPIN(ctx context.Context, mpin *models.MPINCredential) error
	GetAdminMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error)
	GetMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error)
	UpdateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpinHash, salt string, pepperVersion int) error
	ValidateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpin string) (*models.MPINCredential, error)
	IncrementAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
	LockAdminMPIN(ctx context.Context, adminID uuid.UUID, lockDuration time.Duration) error
	UnlockAdminMPIN(ctx context.Context, adminID uuid.UUID) error
	ResetAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) error
	UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error
	GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error)
	GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error)
	CleanupAdminUnlockedMPINs(ctx context.Context) (int, error)
	HealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error)
}

type AdminMPINRepositoryImpl struct {
	client *ScyllaClient
	mu     sync.RWMutex
}

func NewAdminMPINRepository(client *ScyllaClient) *AdminMPINRepositoryImpl {
	return &AdminMPINRepositoryImpl{
		client: client,
	}
}

func (r *AdminMPINRepositoryImpl) CreateAdminMPIN(ctx context.Context, mpin *models.MPINCredential) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        INSERT INTO admin_mpin_credentials (
            admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
            device_id, last_changed, failed_attempts, is_locked, locked_until
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(uuid.MustParse(mpin.UserID)),
		mpin.MPINHash,
		mpin.MPINSalt,
		mpin.PepperVersion,
		mpin.HashAlgorithm,
		mpin.DeviceID,
		mpin.LastChanged,
		mpin.FailedAttempts,
		mpin.IsLocked,
		mpin.LockedUntil,
	)

	if err := client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create admin MPIN: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) UpdateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpinHash, salt string, pepperVersion int) error {
	now := time.Now().UTC()
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        UPDATE admin_mpin_credentials SET
            mpin_hash = ?, mpin_salt = ?, pepper_version = ?,
            last_changed = ?, failed_attempts = 0, is_locked = false, locked_until = null
        WHERE admin_id = ?`,
		mpinHash, salt, pepperVersion, now, gocql.UUID(adminID),
	)
	if err := client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) ValidateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpin string) (*models.MPINCredential, error) {
	return r.GetAdminMPINByAdminID(ctx, adminID)
}

func (r *AdminMPINRepositoryImpl) IncrementAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	mpin, err := r.GetAdminMPINByAdminID(ctx, adminID)
	if err != nil {
		return 0, fmt.Errorf("failed to get current admin MPIN: %w", err)
	}
	newFailedAttempts := mpin.FailedAttempts + 1
	shouldLock := newFailedAttempts >= AdminMPINMaxFailedAttempts

	batch := client.Batch(gocql.LoggedBatch).WithContext(ctx)
	batch.Query(`
        UPDATE admin_mpin_credentials
        SET failed_attempts = ?, last_changed = ?
        WHERE admin_id = ?`,
		newFailedAttempts, time.Now(), gocql.UUID(adminID),
	)
	if shouldLock {
		lockedUntil := time.Now().Add(AdminMPINLockoutDuration)
		batch.Query(`
            UPDATE admin_mpin_credentials
            SET is_locked = true, locked_until = ?
            WHERE admin_id = ?`,
			lockedUntil, gocql.UUID(adminID),
		)
	}

	if err := client.ExecuteBatch(batch); err != nil {
		return 0, fmt.Errorf("failed to increment failed attempts: %w", err)
	}
	return newFailedAttempts, nil
}

func (r *AdminMPINRepositoryImpl) LockAdminMPIN(ctx context.Context, adminID uuid.UUID, lockDuration time.Duration) error {
	lockedUntil := time.Now().Add(lockDuration)
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        UPDATE admin_mpin_credentials SET is_locked = true, locked_until = ?
        WHERE admin_id = ?`,
		lockedUntil, gocql.UUID(adminID),
	)
	if err := client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to lock admin MPIN: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) UnlockAdminMPIN(ctx context.Context, adminID uuid.UUID) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        UPDATE admin_mpin_credentials SET is_locked = false, locked_until = null, failed_attempts = 0
        WHERE admin_id = ?`,
		gocql.UUID(adminID),
	)
	if err := client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to unlock admin MPIN: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) ResetAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        UPDATE admin_mpin_credentials
        SET failed_attempts = 0, last_changed = ?
        WHERE admin_id = ?`,
		time.Now(), gocql.UUID(adminID),
	)
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        UPDATE admin_mpin_credentials SET device_id = ? WHERE admin_id = ?`,
		deviceID, gocql.UUID(adminID),
	)
	return client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *AdminMPINRepositoryImpl) GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        SELECT admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM admin_mpin_credentials WHERE device_id = ? ALLOW FILTERING`,
		deviceID,
	)
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var credentials []*models.MPINCredential
	for {
		var mpin models.MPINCredential
		var scannedID gocql.UUID
		if !iter.Scan(
			&scannedID,
			&mpin.MPINHash,
			&mpin.MPINSalt,
			&mpin.PepperVersion,
			&mpin.HashAlgorithm,
			&mpin.DeviceID,
			&mpin.LastChanged,
			&mpin.FailedAttempts,
			&mpin.IsLocked,
			&mpin.LockedUntil,
		) {
			break
		}
		mpin.UserID = uuid.UUID(scannedID).String()
		credentials = append(credentials, &mpin)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate admin MPIN credentials: %w", err)
	}
	return credentials, nil
}

func (r *AdminMPINRepositoryImpl) GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        SELECT admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM admin_mpin_credentials WHERE is_locked = true LIMIT ? ALLOW FILTERING`,
		limit,
	)
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var credentials []*models.MPINCredential
	for {
		var mpin models.MPINCredential
		var scannedID gocql.UUID
		if !iter.Scan(
			&scannedID,
			&mpin.MPINHash,
			&mpin.MPINSalt,
			&mpin.PepperVersion,
			&mpin.HashAlgorithm,
			&mpin.DeviceID,
			&mpin.LastChanged,
			&mpin.FailedAttempts,
			&mpin.IsLocked,
			&mpin.LockedUntil,
		) {
			break
		}
		mpin.UserID = uuid.UUID(scannedID).String()
		credentials = append(credentials, &mpin)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate locked admin MPINs: %w", err)
	}
	return credentials, nil
}

func (r *AdminMPINRepositoryImpl) CleanupAdminUnlockedMPINs(ctx context.Context) (int, error) {
	lockedMPINs, err := r.GetAdminLockedMPINs(ctx, 1000)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	now := time.Now()
	for _, mpin := range lockedMPINs {
		if mpin.LockedUntil != nil && now.After(*mpin.LockedUntil) {
			adminID, err := uuid.Parse(mpin.UserID)
			if err != nil {
				continue
			}
			if err := r.UnlockAdminMPIN(ctx, adminID); err == nil {
				cleaned++
			}
		}
	}
	return cleaned, nil
}

func (r *AdminMPINRepositoryImpl) HealthCheck(ctx context.Context) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	var count int
	query := client.Query("SELECT COUNT(*) FROM system.local")
	if err := client.ScanWithRetry(query.WithContext(ctx), &count); err != nil {
		return fmt.Errorf("admin MPIN repository health check failed: %w", err)
	}
	return nil
}

func (r *AdminMPINRepositoryImpl) GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	lockedMPINs, err := r.GetAdminLockedMPINs(ctx, 1000)
	if err != nil {
		stats["locked_admin_mpins_error"] = err.Error()
	} else {
		stats["locked_admin_mpins_count"] = len(lockedMPINs)
	}
	stats["max_failed_attempts"] = AdminMPINMaxFailedAttempts
	stats["lockout_duration_minutes"] = int(AdminMPINLockoutDuration.Minutes())
	stats["query_caching"] = "disabled"
	return stats, nil
}

func (r *AdminMPINRepositoryImpl) GetAdminMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	return r.GetAdminMPINByAdminID(ctx, userID)
}

func (r *AdminMPINRepositoryImpl) GetMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error) {
	query := r.client.Query(`
        SELECT admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM admin_mpin_credentials WHERE admin_id = ?`,
		gocql.UUID(adminID))
	var mpin models.MPINCredential
	var scannedID gocql.UUID
	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&mpin.MPINHash,
		&mpin.MPINSalt,
		&mpin.PepperVersion,
		&mpin.HashAlgorithm,
		&mpin.DeviceID,
		&mpin.LastChanged,
		&mpin.FailedAttempts,
		&mpin.IsLocked,
		&mpin.LockedUntil,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get MPIN by admin ID: %w", err)
	}
	mpin.UserID = uuid.UUID(scannedID).String()
	return &mpin, nil
}

func (r *AdminMPINRepositoryImpl) GetAdminMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	query := client.Query(`
        SELECT admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM admin_mpin_credentials WHERE admin_id = ?`,
		gocql.UUID(adminID))

	var mpin models.MPINCredential
	var scannedID gocql.UUID
	err := client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&mpin.MPINHash,
		&mpin.MPINSalt,
		&mpin.PepperVersion,
		&mpin.HashAlgorithm,
		&mpin.DeviceID,
		&mpin.LastChanged,
		&mpin.FailedAttempts,
		&mpin.IsLocked,
		&mpin.LockedUntil,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get admin MPIN: %w", err)
	}
	mpin.UserID = uuid.UUID(scannedID).String()

	// Auto-unlock if expired
	if mpin.IsLocked && mpin.LockedUntil != nil && time.Now().After(*mpin.LockedUntil) {
		if err := r.UnlockAdminMPIN(ctx, adminID); err != nil {
			// ignore
		} else {
			mpin.IsLocked = false
			mpin.LockedUntil = nil
			mpin.FailedAttempts = 0
		}
	}
	return &mpin, nil
}

func (r *AdminMPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	return r.GetMPINByAdminID(ctx, userID)
}

// The following method belongs to AdminDeviceRepositoryImpl, but we keep it here for completeness
// (it's already defined in admin_device_repository.go, so we remove it from here to avoid duplication)
