package scylla

import (
    "fmt"
    "time"

    "github.com/gocql/gocql"
    "github.com/google/uuid"
    "go.uber.org/zap"

    "auth-service/internal/model"
    "auth-service/internal/util"
)

type OTPRepository struct {
    client *ScyllaClient
}

func NewOTPRepository(client *ScyllaClient, logger *zap.Logger) *OTPRepository {
    // Using global util logger instead of individual logger
    return &OTPRepository{
        client: client,
    }
}

func (r *OTPRepository) CreateOTP(otp *model.OTP) error {
    if otp.OTPID == "" {
        otp.OTPID = uuid.New().String()
    }

    now := time.Now().UTC()
    otp.CreatedAt = now

    // Set default expiry if not provided (5 minutes)
    if otp.ExpiresAt.IsZero() {
        otp.ExpiresAt = now.Add(5 * time.Minute)
    }

    query := r.client.Prepared.CreateOTP.Bind(
        otp.PhoneNumber, otp.OTPID, otp.OTPHash, otp.ExpiresAt,
        otp.AttemptCount, otp.IsUsed, otp.DeviceID, otp.CreatedAt)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to create OTP",
            zap.String("phone_number", otp.PhoneNumber),
            zap.String("otp_id", otp.OTPID),
            zap.Error(err))
        return fmt.Errorf("failed to create OTP: %w", err)
    }

    util.Info("OTP created successfully",
        zap.String("phone_number", otp.PhoneNumber),
        zap.String("otp_id", otp.OTPID),
        zap.Time("expires_at", otp.ExpiresAt))

    return nil
}

func (r *OTPRepository) GetOTPByPhone(phoneNumber string) (*model.OTP, error) {
    otp := &model.OTP{}

    query := r.client.Prepared.GetOTPByPhone.Bind(phoneNumber)

    err := r.client.ScanWithRetry(query,
        &otp.OTPID, &otp.PhoneNumber, &otp.OTPHash, &otp.ExpiresAt,
        &otp.AttemptCount, &otp.IsUsed, &otp.DeviceID, &otp.CreatedAt)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("no active OTP found for phone: %s", phoneNumber)
        }
        util.Error("Failed to get OTP by phone",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get OTP by phone: %w", err)
    }

    // Check if OTP is expired
    if time.Now().UTC().After(otp.ExpiresAt) {
        util.Warn("Retrieved OTP is expired",
            zap.String("phone_number", phoneNumber),
            zap.String("otp_id", otp.OTPID),
            zap.Time("expires_at", otp.ExpiresAt))
        return nil, fmt.Errorf("OTP has expired")
    }

    return otp, nil
}

func (r *OTPRepository) MarkOTPUsed(otpID string) error {
    // First get the OTP to find the phone number (needed for partition key)
    var phoneNumber string
    err := r.client.Session.Query(`SELECT phone_number FROM otps WHERE otp_id = ? ALLOW FILTERING LIMIT 1`, otpID).Scan(&phoneNumber)
    if err != nil {
        if err == gocql.ErrNotFound {
            return fmt.Errorf("OTP not found with ID: %s", otpID)
        }
        return fmt.Errorf("failed to find OTP: %w", err)
    }

    query := r.client.Prepared.MarkOTPUsed.Bind(phoneNumber, otpID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to mark OTP as used",
            zap.String("otp_id", otpID),
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to mark OTP as used: %w", err)
    }

    util.Info("OTP marked as used",
        zap.String("otp_id", otpID),
        zap.String("phone_number", phoneNumber))

    return nil
}

func (r *OTPRepository) IncrementOTPAttempt(otpID string) error {
    // First get the OTP to find the phone number (needed for partition key)
    var phoneNumber string
    var currentAttempts int
    err := r.client.Session.Query(`SELECT phone_number, attempt_count FROM otps WHERE otp_id = ? ALLOW FILTERING LIMIT 1`, 
        otpID).Scan(&phoneNumber, &currentAttempts)
    if err != nil {
        if err == gocql.ErrNotFound {
            return fmt.Errorf("OTP not found with ID: %s", otpID)
        }
        return fmt.Errorf("failed to find OTP: %w", err)
    }

    query := r.client.Prepared.IncrementOTPAttempt.Bind(phoneNumber, otpID)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to increment OTP attempt",
            zap.String("otp_id", otpID),
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to increment OTP attempt: %w", err)
    }

    util.Info("OTP attempt incremented",
        zap.String("otp_id", otpID),
        zap.String("phone_number", phoneNumber),
        zap.Int("previous_attempts", currentAttempts))

    return nil
}

func (r *OTPRepository) DeleteExpiredOTPs() error {
    // Get expired OTPs first
    iter := r.client.Session.Query(`
        SELECT phone_number, otp_id FROM otps 
        WHERE expires_at < ? ALLOW FILTERING`, time.Now().UTC()).Iter()

    var phoneNumber, otpID string
    deletedCount := 0

    // Use batch delete for better performance
    batch := r.client.Session.NewBatch(gocql.UnloggedBatch)
    batchSize := 0

    for iter.Scan(&phoneNumber, &otpID) {
        batch.Query(`DELETE FROM otps WHERE phone_number = ? AND otp_id = ?`, phoneNumber, otpID)
        batchSize++

        // Execute batch when it reaches 100 items
        if batchSize >= 100 {
            if err := r.client.ExecuteBatch(batch); err != nil {
                util.Error("Failed to execute batch delete for expired OTPs", zap.Error(err))
                iter.Close()
                return fmt.Errorf("failed to delete expired OTPs: %w", err)
            }
            deletedCount += batchSize
            batch = r.client.Session.NewBatch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }

    // Execute remaining batch
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            util.Error("Failed to execute final batch delete for expired OTPs", zap.Error(err))
            iter.Close()
            return fmt.Errorf("failed to delete expired OTPs: %w", err)
        }
        deletedCount += batchSize
    }

    if err := iter.Close(); err != nil {
        util.Error("Failed to close iterator for expired OTP cleanup", zap.Error(err))
        return fmt.Errorf("failed to cleanup expired OTPs: %w", err)
    }

    util.Info("Expired OTPs deleted successfully", zap.Int("deleted_count", deletedCount))
    return nil
}

// Additional helper methods for OTP management

func (r *OTPRepository) GetOTPAttemptCount(phoneNumber string) (int, error) {
    var attemptCount int
    query := r.client.Session.Query(`
        SELECT attempt_count FROM otps 
        WHERE phone_number = ? AND is_used = false 
        LIMIT 1`, phoneNumber)

    err := query.Scan(&attemptCount)
    if err != nil {
        if err == gocql.ErrNotFound {
            return 0, nil // No active OTP found
        }
        return 0, fmt.Errorf("failed to get OTP attempt count: %w", err)
    }

    return attemptCount, nil
}

func (r *OTPRepository) InvalidateAllOTPsForPhone(phoneNumber string) error {
    // Mark all active OTPs as used for this phone number
    query := r.client.Session.Query(`
        UPDATE otps SET is_used = true 
        WHERE phone_number = ?`, phoneNumber)

    if err := r.client.ExecuteWithRetry(query, 2); err != nil {
        util.Error("Failed to invalidate OTPs for phone",
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return fmt.Errorf("failed to invalidate OTPs: %w", err)
    }

    util.Info("All OTPs invalidated for phone", zap.String("phone_number", phoneNumber))
    return nil
}

func (r *OTPRepository) CleanupOldOTPs(olderThan time.Duration) error {
    cutoffTime := time.Now().UTC().Add(-olderThan)

    // Get old OTPs
    iter := r.client.Session.Query(`
        SELECT phone_number, otp_id FROM otps 
        WHERE created_at < ? ALLOW FILTERING`, cutoffTime).Iter()

    var phoneNumber, otpID string
    deletedCount := 0

    // Use batch delete for better performance
    batch := r.client.Session.NewBatch(gocql.UnloggedBatch)
    batchSize := 0

    for iter.Scan(&phoneNumber, &otpID) {
        batch.Query(`DELETE FROM otps WHERE phone_number = ? AND otp_id = ?`, phoneNumber, otpID)
        batchSize++

        // Execute batch when it reaches 100 items
        if batchSize >= 100 {
            if err := r.client.ExecuteBatch(batch); err != nil {
                util.Error("Failed to execute batch delete for old OTPs", zap.Error(err))
                iter.Close()
                return fmt.Errorf("failed to delete old OTPs: %w", err)
            }
            deletedCount += batchSize
            batch = r.client.Session.NewBatch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }

    // Execute remaining batch
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            util.Error("Failed to execute final batch delete for old OTPs", zap.Error(err))
            iter.Close()
            return fmt.Errorf("failed to delete old OTPs: %w", err)
        }
        deletedCount += batchSize
    }

    if err := iter.Close(); err != nil {
        util.Error("Failed to close iterator for old OTP cleanup", zap.Error(err))
        return fmt.Errorf("failed to cleanup old OTPs: %w", err)
    }

    util.Info("Old OTPs cleaned up successfully", 
        zap.Int("deleted_count", deletedCount),
        zap.Duration("older_than", olderThan))

    return nil
}

func (r *OTPRepository) GetOTPStats() (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Get total OTPs count
    var totalOTPs int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM otps`).Scan(&totalOTPs); err != nil {
        util.Warn("Failed to get total OTPs count", zap.Error(err))
    } else {
        stats["total_otps"] = totalOTPs
    }

    // Get active (unused) OTPs count
    var activeOTPs int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM otps WHERE is_used = false ALLOW FILTERING`).Scan(&activeOTPs); err != nil {
        util.Warn("Failed to get active OTPs count", zap.Error(err))
    } else {
        stats["active_otps"] = activeOTPs
    }

    return stats, nil
}
