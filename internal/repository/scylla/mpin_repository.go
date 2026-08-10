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

const (
	MPINMaxFailedAttempts = 5
	MPINLockoutDuration   = 30 * time.Second
	MPINBatchSize         = 100
)

type MPINRepositoryImpl struct {
	client *ScyllaClient
}

func NewMPINRepository(client *ScyllaClient) MPINRepository {
	return &MPINRepositoryImpl{
		client: client,
	}
}

func (r *MPINRepositoryImpl) CreateMPIN(ctx context.Context, mpin *models.MPINCredential) error {
	query := r.client.Query(`
		INSERT INTO mpin_credentials (
			user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
			device_id, last_changed, failed_attempts, is_locked, locked_until
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
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
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create MPIN: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	query := r.client.Query(`
		SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
		       device_id, last_changed, failed_attempts, is_locked, locked_until
		FROM mpin_credentials WHERE user_id = ?
	`, gocql.UUID(userID))

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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get MPIN: %w", err)
	}
	mpin.UserID = uuid.UUID(scannedID).String()

	// Auto-unlock if lock expired
	if mpin.IsLocked && mpin.LockedUntil != nil && time.Now().After(*mpin.LockedUntil) {
		if err := r.UnlockMPIN(ctx, userID); err == nil {
			mpin.IsLocked = false
			mpin.LockedUntil = nil
			mpin.FailedAttempts = 0
		}
	}
	return &mpin, nil
}

func (r *MPINRepositoryImpl) UpdateMPIN(ctx context.Context, userID uuid.UUID, mpinHash, salt string, pepperVersion int) error {
	now := time.Now().UTC()
	query := r.client.Query(`
		UPDATE mpin_credentials SET
			mpin_hash = ?, mpin_salt = ?, pepper_version = ?,
			last_changed = ?, failed_attempts = 0, is_locked = false, locked_until = null
		WHERE user_id = ?
	`, mpinHash, salt, pepperVersion, now, gocql.UUID(userID))

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update MPIN: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) ValidateMPIN(ctx context.Context, userID uuid.UUID, mpinHash string) (*models.MPINCredential, error) {
	mpin, err := r.GetMPINByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if mpin.IsLocked {
		if mpin.LockedUntil != nil && time.Now().Before(*mpin.LockedUntil) {
			return nil, fmt.Errorf("MPIN is locked until %v", mpin.LockedUntil)
		}
	}
	if mpin.FailedAttempts >= MPINMaxFailedAttempts {
		lockDuration := MPINLockoutDuration
		if err := r.LockMPIN(ctx, userID, lockDuration); err != nil {
			// ignore lock error
		}
		return nil, fmt.Errorf("MPIN locked due to too many failed attempts")
	}
	return mpin, nil
}

func (r *MPINRepositoryImpl) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	mpin, err := r.GetMPINByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	newFailedAttempts := mpin.FailedAttempts + 1
	shouldLock := newFailedAttempts >= MPINMaxFailedAttempts

	batch := r.client.Batch(gocql.LoggedBatch).WithContext(ctx)
	batch.Query(`
		UPDATE mpin_credentials
		SET failed_attempts = ?, last_changed = ?
		WHERE user_id = ?
	`, newFailedAttempts, time.Now(), gocql.UUID(userID))

	if shouldLock {
		lockedUntil := time.Now().Add(MPINLockoutDuration)
		batch.Query(`
			UPDATE mpin_credentials
			SET is_locked = true, locked_until = ?
			WHERE user_id = ?
		`, lockedUntil, gocql.UUID(userID))
	}

	if err := r.client.ExecuteBatch(batch); err != nil {
		return 0, fmt.Errorf("failed to increment failed attempts: %w", err)
	}
	return newFailedAttempts, nil
}

func (r *MPINRepositoryImpl) LockMPIN(ctx context.Context, userID uuid.UUID, lockDuration time.Duration) error {
	lockedUntil := time.Now().Add(lockDuration)
	query := r.client.Query(`
		UPDATE mpin_credentials SET is_locked = true, locked_until = ?
		WHERE user_id = ?
	`, lockedUntil, gocql.UUID(userID))
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to lock MPIN: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) UnlockMPIN(ctx context.Context, userID uuid.UUID) error {
	query := r.client.Query(`
		UPDATE mpin_credentials SET is_locked = false, locked_until = null, failed_attempts = 0
		WHERE user_id = ?
	`, gocql.UUID(userID))
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to unlock MPIN: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	query := r.client.Query(`
		UPDATE mpin_credentials
		SET failed_attempts = 0, last_changed = ?
		WHERE user_id = ?
	`, time.Now(), gocql.UUID(userID))
	if err := query.WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) UpdateMPINDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID string) error {
	query := r.client.Query(`
		UPDATE mpin_credentials SET device_id = ? WHERE user_id = ?
	`, deviceID, gocql.UUID(userID))
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *MPINRepositoryImpl) GetMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	query := r.client.Query(`
		SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
		       device_id, last_changed, failed_attempts, is_locked, locked_until
		FROM mpin_credentials WHERE device_id = ? ALLOW FILTERING
	`, deviceID)

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
		return nil, fmt.Errorf("failed to iterate MPIN credentials: %w", err)
	}
	return credentials, nil
}

func (r *MPINRepositoryImpl) GetLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := r.client.Query(`
		SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
		       device_id, last_changed, failed_attempts, is_locked, locked_until
		FROM mpin_credentials WHERE is_locked = true LIMIT ? ALLOW FILTERING
	`, limit)

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
		return nil, fmt.Errorf("failed to iterate locked MPINs: %w", err)
	}
	return credentials, nil
}

func (r *MPINRepositoryImpl) CleanupUnlockedMPINs(ctx context.Context) (int, error) {
	lockedMPINs, err := r.GetLockedMPINs(ctx, 1000)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	now := time.Now()
	for _, mpin := range lockedMPINs {
		if mpin.LockedUntil != nil && now.After(*mpin.LockedUntil) {
			userID, err := uuid.Parse(mpin.UserID)
			if err != nil {
				continue
			}
			if err := r.UnlockMPIN(ctx, userID); err != nil {
				continue
			}
			cleaned++
		}
	}
	return cleaned, nil
}

func (r *MPINRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	err := r.client.Query("SELECT COUNT(*) FROM system.local").
		WithContext(ctx).
		Scan(&count)
	if err != nil {
		return fmt.Errorf("MPIN repository health check failed: %w", err)
	}
	return nil
}

func (r *MPINRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := map[string]interface{}{
		"max_failed_attempts":      MPINMaxFailedAttempts,
		"lockout_duration_minutes": int(MPINLockoutDuration.Minutes()),
		"batch_size":               MPINBatchSize,
	}
	return stats, nil
}
