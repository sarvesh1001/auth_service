package scylla

import (
    "fmt"
    "time"

    "github.com/gocql/gocql"
    "go.uber.org/zap"

    "auth-service/internal/model"
    "auth-service/internal/util"
)

type MPINRepository struct {
    client *ScyllaClient
}

func NewMPINRepository(client *ScyllaClient, logger *zap.Logger) *MPINRepository {
    // Using global util logger instead of individual logger
    return &MPINRepository{
        client: client,
    }
}

func (r *MPINRepository) CreateMPIN(mpin *model.MPIN) error {
    now := time.Now().UTC()
    mpin.LastChanged = now
    mpin.UpdatedAt = now

    // Set default values
    if mpin.RetryCount == 0 && mpin.IsBlocked {
        mpin.IsBlocked = false // Default to unblocked
    }

    query := r.client.Prepared.CreateMPIN.Bind(
        mpin.UserID, mpin.MPINHash, mpin.LastChanged,
        mpin.IsBlocked, mpin.RetryCount, mpin.UpdatedAt)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to create MPIN",
            zap.String("user_id", mpin.UserID),
            zap.Error(err))
        return fmt.Errorf("failed to create MPIN: %w", err)
    }

    util.Info("MPIN created successfully",
        zap.String("user_id", mpin.UserID))

    return nil
}

func (r *MPINRepository) GetMPINByUserID(userID string) (*model.MPIN, error) {
    mpin := &model.MPIN{}

    query := r.client.Prepared.GetMPINByUserID.Bind(userID)

    err := r.client.ScanWithRetry(query,
        &mpin.UserID, &mpin.MPINHash, &mpin.LastChanged,
        &mpin.IsBlocked, &mpin.RetryCount, &mpin.UpdatedAt)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("MPIN not found for user: %s", userID)
        }
        util.Error("Failed to get MPIN by user ID",
            zap.String("user_id", userID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get MPIN by user ID: %w", err)
    }

    return mpin, nil
}

func (r *MPINRepository) UpdateMPINHash(userID string, mpinHash string) error {
    now := time.Now().UTC()

    query := r.client.Prepared.UpdateMPINHash.Bind(mpinHash, now, now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to update MPIN hash",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to update MPIN hash: %w", err)
    }

    util.Info("MPIN hash updated successfully",
        zap.String("user_id", userID))

    return nil
}

func (r *MPINRepository) IncrementMPINRetry(userID string) error {
    now := time.Now().UTC()

    query := r.client.Prepared.IncrementMPINRetry.Bind(now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to increment MPIN retry count",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to increment MPIN retry count: %w", err)
    }

    // Get current retry count to check if we need to block
    mpin, err := r.GetMPINByUserID(userID)
    if err != nil {
        util.Error("Failed to get MPIN after incrementing retry",
            zap.String("user_id", userID),
            zap.Error(err))
        return nil // Don't fail the increment operation
    }

    util.Info("MPIN retry count incremented",
        zap.String("user_id", userID),
        zap.Int("retry_count", mpin.RetryCount))

    // Auto-block if retry count exceeds threshold (e.g., 3 attempts)
    if mpin.RetryCount >= 3 && !mpin.IsBlocked {
        if err := r.BlockMPIN(userID); err != nil {
            util.Error("Failed to auto-block MPIN after max retries",
                zap.String("user_id", userID),
                zap.Error(err))
        }
    }

    return nil
}

func (r *MPINRepository) BlockMPIN(userID string) error {
    now := time.Now().UTC()

    query := r.client.Prepared.BlockMPIN.Bind(now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to block MPIN",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to block MPIN: %w", err)
    }

    util.Warn("MPIN blocked due to excessive failed attempts",
        zap.String("user_id", userID))

    return nil
}

func (r *MPINRepository) ResetMPINRetryCount(userID string) error {
    now := time.Now().UTC()

    query := r.client.Prepared.ResetMPINRetryCount.Bind(now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to reset MPIN retry count",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to reset MPIN retry count: %w", err)
    }

    util.Info("MPIN retry count reset and unblocked",
        zap.String("user_id", userID))

    return nil
}

// Additional helper methods for MPIN management

func (r *MPINRepository) IsMPINBlocked(userID string) (bool, error) {
    var isBlocked bool
    query := r.client.Session.Query(`SELECT is_blocked FROM mpins WHERE user_id = ?`, userID)

    err := query.Scan(&isBlocked)
    if err != nil {
        if err == gocql.ErrNotFound {
            return false, fmt.Errorf("MPIN not found for user: %s", userID)
        }
        return false, fmt.Errorf("failed to check MPIN blocked status: %w", err)
    }

    return isBlocked, nil
}

func (r *MPINRepository) GetMPINRetryCount(userID string) (int, error) {
    var retryCount int
    query := r.client.Session.Query(`SELECT retry_count FROM mpins WHERE user_id = ?`, userID)

    err := query.Scan(&retryCount)
    if err != nil {
        if err == gocql.ErrNotFound {
            return 0, fmt.Errorf("MPIN not found for user: %s", userID)
        }
        return 0, fmt.Errorf("failed to get MPIN retry count: %w", err)
    }

    return retryCount, nil
}

func (r *MPINRepository) SetMPINRetryCount(userID string, count int) error {
    now := time.Now().UTC()

    query := r.client.Session.Query(`
        UPDATE mpins SET retry_count = ?, updated_at = ? WHERE user_id = ?`,
        count, now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to set MPIN retry count",
            zap.String("user_id", userID),
            zap.Int("retry_count", count),
            zap.Error(err))
        return fmt.Errorf("failed to set MPIN retry count: %w", err)
    }

    util.Info("MPIN retry count set",
        zap.String("user_id", userID),
        zap.Int("retry_count", count))

    return nil
}

func (r *MPINRepository) UnblockMPIN(userID string) error {
    now := time.Now().UTC()

    query := r.client.Session.Query(`
        UPDATE mpins SET is_blocked = false, updated_at = ? WHERE user_id = ?`,
        now, userID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to unblock MPIN",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to unblock MPIN: %w", err)
    }

    util.Info("MPIN unblocked",
        zap.String("user_id", userID))

    return nil
}

func (r *MPINRepository) GetMPINAge(userID string) (time.Duration, error) {
    var lastChanged time.Time
    query := r.client.Session.Query(`SELECT last_changed FROM mpins WHERE user_id = ?`, userID)

    err := query.Scan(&lastChanged)
    if err != nil {
        if err == gocql.ErrNotFound {
            return 0, fmt.Errorf("MPIN not found for user: %s", userID)
        }
        return 0, fmt.Errorf("failed to get MPIN age: %w", err)
    }

    return time.Since(lastChanged), nil
}

func (r *MPINRepository) ListBlockedMPINs() ([]*model.MPIN, error) {
    var blockedMPINs []*model.MPIN

    iter := r.client.Session.Query(`
        SELECT user_id, mpin_hash, last_changed, is_blocked, retry_count, updated_at
        FROM mpins WHERE is_blocked = true ALLOW FILTERING`).Iter()

    var mpin model.MPIN
    for iter.Scan(&mpin.UserID, &mpin.MPINHash, &mpin.LastChanged, 
        &mpin.IsBlocked, &mpin.RetryCount, &mpin.UpdatedAt) {
        blockedMPINs = append(blockedMPINs, &mpin)
    }

    if err := iter.Close(); err != nil {
        util.Error("Failed to list blocked MPINs", zap.Error(err))
        return nil, fmt.Errorf("failed to list blocked MPINs: %w", err)
    }

    return blockedMPINs, nil
}

func (r *MPINRepository) GetMPINStats() (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Get total MPINs count
    var totalMPINs int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM mpins`).Scan(&totalMPINs); err != nil {
        util.Warn("Failed to get total MPINs count", zap.Error(err))
    } else {
        stats["total_mpins"] = totalMPINs
    }

    // Get blocked MPINs count
    var blockedMPINs int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM mpins WHERE is_blocked = true ALLOW FILTERING`).Scan(&blockedMPINs); err != nil {
        util.Warn("Failed to get blocked MPINs count", zap.Error(err))
    } else {
        stats["blocked_mpins"] = blockedMPINs
    }

    // Get MPINs with retry attempts
    var mpinsWithRetries int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM mpins WHERE retry_count > 0 ALLOW FILTERING`).Scan(&mpinsWithRetries); err != nil {
        util.Warn("Failed to get MPINs with retries count", zap.Error(err))
    } else {
        stats["mpins_with_retries"] = mpinsWithRetries
    }

    return stats, nil
}

// Cleanup methods for maintenance

func (r *MPINRepository) CleanupOldMPINs(olderThan time.Duration) error {
    cutoffTime := time.Now().UTC().Add(-olderThan)

    // This is typically not needed as MPINs should persist
    // But can be used for deactivated users
    iter := r.client.Session.Query(`
        SELECT user_id FROM mpins 
        WHERE last_changed < ? ALLOW FILTERING`, cutoffTime).Iter()

    var userID string
    var oldMPINs []string

    for iter.Scan(&userID) {
        // Check if user is still active before deleting MPIN
        var isActive bool
        err := r.client.Session.Query(`SELECT is_active FROM users_by_id WHERE user_id = ?`, userID).Scan(&isActive)
        if err != nil || !isActive {
            oldMPINs = append(oldMPINs, userID)
        }
    }

    if err := iter.Close(); err != nil {
        return fmt.Errorf("failed to query old MPINs: %w", err)
    }

    // Delete MPINs for inactive users
    deletedCount := 0
    for _, uid := range oldMPINs {
        query := r.client.Session.Query(`DELETE FROM mpins WHERE user_id = ?`, uid)
        if err := query.Exec(); err != nil {
            util.Error("Failed to delete old MPIN", 
                zap.String("user_id", uid), 
                zap.Error(err))
        } else {
            deletedCount++
        }
    }

    util.Info("Old MPINs cleaned up", 
        zap.Int("deleted_count", deletedCount),
        zap.Duration("older_than", olderThan))

    return nil
}
