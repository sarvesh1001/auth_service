package scylla

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AdminMPINRepository interface {
	// Core MPIN operations
	CreateAdminMPIN(ctx context.Context, mpin *models.MPINCredential) error
	GetAdminMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error)
	GetMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error)
	UpdateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpinHash, salt string, pepperVersion int) error
	ValidateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpin string) (*models.MPINCredential, error)

	// Security operations
	IncrementAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
	LockAdminMPIN(ctx context.Context, adminID uuid.UUID, lockDuration time.Duration) error
	UnlockAdminMPIN(ctx context.Context, adminID uuid.UUID) error
	ResetAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) error

	// Device binding
	UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error
	GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error)

	// Management operations
	GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error)
	CleanupAdminUnlockedMPINs(ctx context.Context) (int, error)

	// Health & stats
	HealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)

	// Compatibility method
	GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error)
}

// Constants for admin MPIN
const (
	AdminMPINMaxFailedAttempts = 5
	AdminMPINLockoutDuration   = 30 * time.Minute // Longer lockout for admins
	AdminMPINBatchSize         = 100
)

// AdminMPINRepositoryImpl implements AdminMPINRepository interface
type AdminMPINRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger
	mu     sync.RWMutex
}

// NewAdminMPINRepository creates a new admin MPIN repository
func NewAdminMPINRepository(client *ScyllaClient, logger *zap.Logger) *AdminMPINRepositoryImpl {
	repo := &AdminMPINRepositoryImpl{
		client: client,
		logger: logger,
	}
	logger.Info("Admin MPIN repository initialized (dynamic queries mode)")
	return repo
}

// CreateAdminMPIN creates a new admin MPIN credential
func (r *AdminMPINRepositoryImpl) CreateAdminMPIN(ctx context.Context, mpin *models.MPINCredential) error {
	startTime := time.Now()
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

	r.logger.Debug("Admin MPIN created successfully",
		util.String("admin_id", mpin.UserID),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// // GetAdminMPINByAdminID retrieves admin MPIN credential by admin ID
// func (r *AdminMPINRepositoryImpl) GetAdminMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error) {
// 	r.mu.RLock()
// 	client := r.client
// 	r.mu.RUnlock()

// 	query := client.Query(`
//         SELECT admin_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
//                device_id, last_changed, failed_attempts, is_locked, locked_until
//         FROM admin_mpin_credentials WHERE admin_id = ?`,
// 		gocql.UUID(adminID))

// 	var mpin models.MPINCredential
// 	var scannedID gocql.UUID

// 	err := client.ScanWithRetry(query.WithContext(ctx),
// 		&scannedID,
// 		&mpin.MPINHash,
// 		&mpin.MPINSalt,
// 		&mpin.PepperVersion,
// 		&mpin.HashAlgorithm,
// 		&mpin.DeviceID,
// 		&mpin.LastChanged,
// 		&mpin.FailedAttempts,
// 		&mpin.IsLocked,
// 		&mpin.LockedUntil,
// 	)
// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, fmt.Errorf("MPIN not found for admin: %s", adminID)
// 		}
// 		return nil, fmt.Errorf("failed to get admin MPIN: %w", err)
// 	}

// 	mpin.UserID = uuid.UUID(scannedID).String()

// 	// Auto-unlock expired locks
// 	if mpin.IsLocked && mpin.LockedUntil != nil && time.Now().After(*mpin.LockedUntil) {
// 		if err := r.UnlockAdminMPIN(ctx, adminID); err != nil {
// 			r.logger.Warn("Failed to auto-unlock expired admin MPIN",
// 				util.ErrorField(err),
// 				util.String("admin_id", adminID.String()),
// 			)
// 		} else {
// 			mpin.IsLocked = false
// 			mpin.LockedUntil = nil
// 			mpin.FailedAttempts = 0
// 		}
// 	}

// 	return &mpin, nil
// }

// UpdateAdminMPIN updates admin MPIN hash and related fields
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

	r.logger.Info("Admin MPIN updated successfully",
		util.String("admin_id", adminID.String()),
		util.Int("pepper_version", pepperVersion),
	)
	return nil
}

// ValidateAdminMPIN retrieves admin MPIN for validation
func (r *AdminMPINRepositoryImpl) ValidateAdminMPIN(ctx context.Context, adminID uuid.UUID, mpin string) (*models.MPINCredential, error) {
	return r.GetAdminMPINByAdminID(ctx, adminID)
}

// IncrementAdminFailedAttempts increments failed attempts for admin MPIN
func (r *AdminMPINRepositoryImpl) IncrementAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	startTime := time.Now()
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

		r.logger.Warn("Max admin MPIN attempts reached, locking account",
			util.String("admin_id", adminID.String()),
			util.Int("failed_attempts", newFailedAttempts),
			util.Time("locked_until", lockedUntil),
		)
	}

	if err := client.ExecuteBatch(batch); err != nil {
		return 0, fmt.Errorf("failed to increment failed attempts: %w", err)
	}

	r.logger.Debug("Admin failed attempts incremented",
		util.String("admin_id", adminID.String()),
		util.Int("new_count", newFailedAttempts),
		util.Bool("locked", shouldLock),
		util.Duration("duration", time.Since(startTime)),
	)
	return newFailedAttempts, nil
}

// LockAdminMPIN locks admin MPIN
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

	r.logger.Warn("Admin MPIN locked",
		util.String("admin_id", adminID.String()),
		util.Time("locked_until", lockedUntil),
		util.Duration("duration", lockDuration),
	)
	return nil
}

// UnlockAdminMPIN unlocks admin MPIN
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

	r.logger.Info("Admin MPIN unlocked successfully",
		util.String("admin_id", adminID.String()),
	)
	return nil
}

// ResetAdminFailedAttempts resets admin failed attempts
func (r *AdminMPINRepositoryImpl) ResetAdminFailedAttempts(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()
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

	r.logger.Debug("Admin failed attempts reset",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// UpdateAdminMPINDeviceBinding updates admin device binding
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

// GetAdminMPINsByDevice retrieves MPINs by device
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

// GetAdminLockedMPINs returns locked admin MPINs
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

// CleanupAdminUnlockedMPINs cleans up expired locks
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

// AdminHealthCheck performs repository health check
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

// GetAdminRepositoryStats returns repository statistics
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

// GetAdminMPINByUserID retrieves admin MPIN by user ID
func (r *AdminMPINRepositoryImpl) GetAdminMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	return r.GetAdminMPINByAdminID(ctx, userID)
}

// For compatibility with admin device repository
func (r *AdminDeviceRepositoryImpl) BindUserDevice(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) error {
	return r.BindAdminDevice(ctx, userID, deviceID, bindToken)
}

// GetMPINByAdminID retrieves MPIN credentials for an admin
// This method is required by the interface - FIXED VERSION
func (r *AdminMPINRepositoryImpl) GetMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error) {
	// Use the same query structure as GetAdminMPINByAdminID
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
		&mpin.MPINSalt, // ✅ Fixed: Use MPINSalt, not Salt
		&mpin.PepperVersion,
		&mpin.HashAlgorithm,
		&mpin.DeviceID,
		&mpin.LastChanged, // ✅ Fixed: Use LastChanged, not CreatedAt
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

	mpin.UserID = uuid.UUID(scannedID).String() // ✅ Fixed: Convert to string
	return &mpin, nil
} // GetAdminMPINByAdminID retrieves admin MPIN credential by admin ID - FIXED VERSION
// GetAdminMPINByAdminID retrieves admin MPIN credential by admin ID - WITH DEBUG LOGGING
func (r *AdminMPINRepositoryImpl) GetAdminMPINByAdminID(ctx context.Context, adminID uuid.UUID) (*models.MPINCredential, error) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	r.logger.Debug("🔍 GetAdminMPINByAdminID called",
		util.String("admin_id", adminID.String()))

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
			r.logger.Debug("❌ MPIN not found for admin",
				util.String("admin_id", adminID.String()))
			return nil, nil // Return nil for "not found"
		}
		r.logger.Error("❌ Database error getting admin MPIN",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()))
		return nil, fmt.Errorf("failed to get admin MPIN: %w", err)
	}

	mpin.UserID = uuid.UUID(scannedID).String()

	r.logger.Debug("✅ MPIN found for admin",
		util.String("admin_id", adminID.String()),
		util.Bool("is_locked", mpin.IsLocked),
		util.Int("failed_attempts", mpin.FailedAttempts))

	// Auto-unlock expired locks
	if mpin.IsLocked && mpin.LockedUntil != nil && time.Now().After(*mpin.LockedUntil) {
		r.logger.Debug("🔄 Auto-unlocking expired MPIN lock",
			util.String("admin_id", adminID.String()))
		if err := r.UnlockAdminMPIN(ctx, adminID); err != nil {
			r.logger.Warn("Failed to auto-unlock expired admin MPIN",
				util.ErrorField(err),
				util.String("admin_id", adminID.String()),
			)
		} else {
			mpin.IsLocked = false
			mpin.LockedUntil = nil
			mpin.FailedAttempts = 0
		}
	}

	return &mpin, nil
}



// Add this method to ensure AdminMPINRepositoryImpl implements MPINRepository
func (r *AdminMPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	// For admin repository, treat userID as adminID
	return r.GetMPINByAdminID(ctx, userID)
}
