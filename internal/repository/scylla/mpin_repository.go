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

// Constants for 500M scale optimization
const (
    MPINMaxFailedAttempts = 5
    MPINLockoutDuration   = 30 * time.Minute
    MPINBatchSize         = 100
)

// MPINRepositoryImpl handles all MPIN-related database operations
type MPINRepositoryImpl struct {
    client *ScyllaClient
    logger *zap.Logger
    
    // Prepared statements for frequently used queries
    stmtGetMPINByUserID       *gocql.Query
    stmtUpdateFailedAttempts  *gocql.Query
    stmtLockMPIN             *gocql.Query
    stmtUnlockMPIN           *gocql.Query
    stmtResetFailedAttempts  *gocql.Query
    stmtMutex                sync.RWMutex
}

// NewMPINRepository creates a new MPIN repository
func NewMPINRepository(client *ScyllaClient, logger *zap.Logger) MPINRepository {
    repo := &MPINRepositoryImpl{
        client: client,
        logger: logger,
    }
    
    // Prepare frequently used statements
    repo.prepareStatements()
    
    return repo
}

// prepareStatements prepares frequently used queries for better performance
func (r *MPINRepositoryImpl) prepareStatements() {
    r.stmtMutex.Lock()
    defer r.stmtMutex.Unlock()
    
    // Prepare GetMPINByUserID query (most frequent)
    r.stmtGetMPINByUserID = r.client.Session.Query(`
        SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM mpin_credentials WHERE user_id = ?`)
    
    // Prepare increment failed attempts
    r.stmtUpdateFailedAttempts = r.client.Session.Query(`
        UPDATE mpin_credentials SET failed_attempts = failed_attempts + 1
        WHERE user_id = ?`)
    
    // Prepare lock MPIN
    r.stmtLockMPIN = r.client.Session.Query(`
        UPDATE mpin_credentials SET is_locked = true, locked_until = ?
        WHERE user_id = ?`)
    
    // Prepare unlock MPIN  
    r.stmtUnlockMPIN = r.client.Session.Query(`
        UPDATE mpin_credentials SET is_locked = false, locked_until = null, failed_attempts = 0
        WHERE user_id = ?`)
    
    // Prepare reset failed attempts
    r.stmtResetFailedAttempts = r.client.Session.Query(`
        UPDATE mpin_credentials SET failed_attempts = 0
        WHERE user_id = ?`)
    
    r.logger.Info("Prepared statements initialized for MPIN repository")
}

// CreateMPIN creates a new MPIN credential
func (r *MPINRepositoryImpl) CreateMPIN(ctx context.Context, mpin *models.MPINCredential) error {
    startTime := time.Now()
    
    query := r.client.Session.Query(`
        INSERT INTO mpin_credentials (
            user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
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
    
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to create MPIN: %w", err)
    }
    
    r.logger.Debug("MPIN created successfully",
        util.String("user_id", mpin.UserID),
        util.Duration("duration", time.Since(startTime)),
    )
    
    return nil
}

// GetMPINByUserID retrieves MPIN credential by user ID using prepared statement
func (r *MPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
    r.stmtMutex.RLock()
    query := r.stmtGetMPINByUserID.Bind(gocql.UUID(userID))
    r.stmtMutex.RUnlock()
    
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
            return nil, fmt.Errorf("MPIN not found for user: %s", userID)
        }
        return nil, fmt.Errorf("failed to get MPIN: %w", err)
    }
    
    mpin.UserID = uuid.UUID(scannedID).String()
    
    // Check if MPIN is expired due to lockout
    if mpin.IsLocked && mpin.LockedUntil != nil && time.Now().After(*mpin.LockedUntil) {
        // Auto-unlock expired locks
        if err := r.UnlockMPIN(ctx, userID); err != nil {
            r.logger.Warn("Failed to auto-unlock expired MPIN",
                util.ErrorField(err),
                util.String("user_id", userID.String()),
            )
        } else {
            mpin.IsLocked = false
            mpin.LockedUntil = nil
            mpin.FailedAttempts = 0
        }
    }
    
    return &mpin, nil
}

// UpdateMPIN updates MPIN hash and related fields
func (r *MPINRepositoryImpl) UpdateMPIN(ctx context.Context, userID uuid.UUID, mpinHash, salt string, pepperVersion int) error {
    now := time.Now().UTC()
    
    query := r.client.Session.Query(`
        UPDATE mpin_credentials SET
            mpin_hash = ?, mpin_salt = ?, pepper_version = ?, 
            last_changed = ?, failed_attempts = 0, is_locked = false, locked_until = null
        WHERE user_id = ?`,
        mpinHash, salt, pepperVersion, now, gocql.UUID(userID),
    )
    
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to update MPIN: %w", err)
    }
    
    r.logger.Info("MPIN updated successfully",
        util.String("user_id", userID.String()),
        util.Int("pepper_version", pepperVersion),
    )
    
    return nil
}

// ValidateMPIN retrieves MPIN for validation (same as GetMPINByUserID but with validation context)
func (r *MPINRepositoryImpl) ValidateMPIN(ctx context.Context, userID uuid.UUID, mpinHash string) (*models.MPINCredential, error) {
    mpin, err := r.GetMPINByUserID(ctx, userID)
    if err != nil {
        return nil, err
    }
    
    // Check if MPIN is locked
    if mpin.IsLocked {
        if mpin.LockedUntil != nil && time.Now().Before(*mpin.LockedUntil) {
            return nil, fmt.Errorf("MPIN is locked until %v", mpin.LockedUntil)
        }
    }
    
    // Check failed attempts
    if mpin.FailedAttempts >= MPINMaxFailedAttempts {
        lockDuration := MPINLockoutDuration
        if err := r.LockMPIN(ctx, userID, lockDuration); err != nil {
            r.logger.Error("Failed to lock MPIN after max attempts",
                util.ErrorField(err),
                util.String("user_id", userID.String()),
            )
        }
        return nil, fmt.Errorf("MPIN locked due to too many failed attempts")
    }
    
    return mpin, nil
}

// IncrementFailedAttempts increments failed attempts counter using prepared statement
func (r *MPINRepositoryImpl) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
    r.stmtMutex.RLock()
    query := r.stmtUpdateFailedAttempts.Bind(gocql.UUID(userID))
    r.stmtMutex.RUnlock()
    
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return 0, fmt.Errorf("failed to increment failed attempts: %w", err)
    }
    
    // Get updated count
    mpin, err := r.GetMPINByUserID(ctx, userID)
    if err != nil {
        return 0, err
    }
    
    // Auto-lock if max attempts reached
    if mpin.FailedAttempts >= MPINMaxFailedAttempts {
        if err := r.LockMPIN(ctx, userID, MPINLockoutDuration); err != nil {
            r.logger.Error("Failed to auto-lock MPIN",
                util.ErrorField(err),
                util.String("user_id", userID.String()),
            )
        }
    }
    
    return mpin.FailedAttempts, nil
}

// LockMPIN locks MPIN for specified duration using prepared statement
func (r *MPINRepositoryImpl) LockMPIN(ctx context.Context, userID uuid.UUID, lockDuration time.Duration) error {
    lockedUntil := time.Now().Add(lockDuration)
    
    r.stmtMutex.RLock()
    query := r.stmtLockMPIN.Bind(lockedUntil, gocql.UUID(userID))
    r.stmtMutex.RUnlock()
    
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to lock MPIN: %w", err)
    }
    
    r.logger.Warn("MPIN locked",
        util.String("user_id", userID.String()),
        util.Time("locked_until", lockedUntil),
        util.Duration("duration", lockDuration),
    )
    
    return nil
}

// UnlockMPIN unlocks MPIN and resets failed attempts using prepared statement
func (r *MPINRepositoryImpl) UnlockMPIN(ctx context.Context, userID uuid.UUID) error {
    r.stmtMutex.RLock()
    query := r.stmtUnlockMPIN.Bind(gocql.UUID(userID))
    r.stmtMutex.RUnlock()
    
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to unlock MPIN: %w", err)
    }
    
    r.logger.Info("MPIN unlocked",
        util.String("user_id", userID.String()),
    )
    
    return nil
}

// ResetFailedAttempts resets failed attempts counter using prepared statement
func (r *MPINRepositoryImpl) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
    r.stmtMutex.RLock()
    query := r.stmtResetFailedAttempts.Bind(gocql.UUID(userID))
    r.stmtMutex.RUnlock()
    
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateMPINDeviceBinding updates device binding for MPIN
func (r *MPINRepositoryImpl) UpdateMPINDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID string) error {
    query := r.client.Session.Query(`
        UPDATE mpin_credentials SET device_id = ? WHERE user_id = ?`,
        deviceID, gocql.UUID(userID),
    )
    
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// GetMPINsByDevice gets all MPINs bound to a specific device
func (r *MPINRepositoryImpl) GetMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
    query := r.client.Session.Query(`
        SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM mpin_credentials WHERE device_id = ? ALLOW FILTERING`,
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
        return nil, fmt.Errorf("failed to iterate MPIN credentials: %w", err)
    }
    
    return credentials, nil
}

// GetLockedMPINs gets locked MPIN credentials for maintenance
func (r *MPINRepositoryImpl) GetLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    query := r.client.Session.Query(`
        SELECT user_id, mpin_hash, mpin_salt, pepper_version, hash_algorithm,
               device_id, last_changed, failed_attempts, is_locked, locked_until
        FROM mpin_credentials WHERE is_locked = true LIMIT ? ALLOW FILTERING`,
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
        return nil, fmt.Errorf("failed to iterate locked MPINs: %w", err)
    }
    
    return credentials, nil
}

// CleanupUnlockedMPINs unlocks expired MPIN locks
func (r *MPINRepositoryImpl) CleanupUnlockedMPINs(ctx context.Context) (int, error) {
    // Get all locked MPINs
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
                r.logger.Error("Invalid user ID in MPIN cleanup",
                    util.ErrorField(err),
                    util.String("user_id", mpin.UserID),
                )
                continue
            }
            
            if err := r.UnlockMPIN(ctx, userID); err != nil {
                r.logger.Error("Failed to unlock expired MPIN",
                    util.ErrorField(err),
                    util.String("user_id", mpin.UserID),
                )
                continue
            }
            cleaned++
        }
    }
    
    if cleaned > 0 {
        r.logger.Info("MPIN cleanup completed",
            util.Int("cleaned_mpins", cleaned),
            util.Int("total_checked", len(lockedMPINs)),
        )
    }
    
    return cleaned, nil
}

// HealthCheck performs a health check on the repository
func (r *MPINRepositoryImpl) HealthCheck(ctx context.Context) error {
    var count int
    if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").WithContext(ctx).Scan(&count); err != nil {
        return fmt.Errorf("MPIN repository health check failed: %w", err)
    }
    return nil
}

// GetRepositoryStats returns repository statistics
func (r *MPINRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
    stats := make(map[string]interface{})
    
    // Get locked MPINs count
    lockedMPINs, err := r.GetLockedMPINs(ctx, 1000)
    if err != nil {
        stats["locked_mpins_error"] = err.Error()
    } else {
        stats["locked_mpins_count"] = len(lockedMPINs)
    }
    
    stats["max_failed_attempts"] = MPINMaxFailedAttempts
    stats["lockout_duration_minutes"] = int(MPINLockoutDuration.Minutes())
    stats["batch_size"] = MPINBatchSize
    
    return stats, nil
}
