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

type UserRepository struct {
    client *ScyllaClient
}

func NewUserRepository(client *ScyllaClient, logger *zap.Logger) *UserRepository {
    // Using global util logger instead of individual logger
    return &UserRepository{
        client: client,
    }
}

func (r *UserRepository) CreateUser(user *model.User) error {
    if user.UserID == "" {
        user.UserID = uuid.New().String()
    }

    now := time.Now().UTC()
    user.CreatedAt = now
    user.UpdatedAt = now

    // Use batch operation for consistency
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Insert into main users table
    batch.Query(r.client.Prepared.CreateUser.Statement(),
        user.PhoneNumber, user.UserID, user.CountryCode, user.DeviceID,
        user.MPINHash, user.IsVerified, user.IsActive, user.LastLoginAt,
        user.CreatedAt, user.UpdatedAt, user.LastLoginIP, user.LastLoginCity)

    // Insert into users_by_id table for fast lookups
    batch.Query(r.client.Prepared.CreateUserByID.Statement(),
        user.UserID, user.PhoneNumber, user.CountryCode, user.DeviceID,
        user.MPINHash, user.IsVerified, user.IsActive, user.LastLoginAt,
        user.CreatedAt, user.UpdatedAt, user.LastLoginIP, user.LastLoginCity)

    // Insert into phone_to_user mapping
    batch.Query(r.client.Prepared.CreatePhoneToUser.Statement(),
        user.PhoneNumber, user.UserID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to create user", 
            zap.String("phone_number", user.PhoneNumber),
            zap.String("user_id", user.UserID),
            zap.Error(err))
        return fmt.Errorf("failed to create user: %w", err)
    }

    util.Info("User created successfully",
        zap.String("phone_number", user.PhoneNumber),
        zap.String("user_id", user.UserID),
        zap.String("country_code", user.CountryCode))

    return nil
}

func (r *UserRepository) GetUserByID(userID string) (*model.User, error) {
    user := &model.User{}

    query := r.client.Prepared.GetUserByID.Bind(userID)

    err := r.client.ScanWithRetry(query,
        &user.UserID, &user.PhoneNumber, &user.CountryCode, &user.DeviceID,
        &user.MPINHash, &user.IsVerified, &user.IsActive, &user.LastLoginAt,
        &user.CreatedAt, &user.UpdatedAt, &user.LastLoginIP, &user.LastLoginCity)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("user not found with ID: %s", userID)
        }
        util.Error("Failed to get user by ID", 
            zap.String("user_id", userID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get user by ID: %w", err)
    }

    return user, nil
}

func (r *UserRepository) GetUserByPhone(phoneNumber string) (*model.User, error) {
    user := &model.User{}

    query := r.client.Prepared.GetUserByPhone.Bind(phoneNumber)

    err := r.client.ScanWithRetry(query,
        &user.UserID, &user.PhoneNumber, &user.CountryCode, &user.DeviceID,
        &user.MPINHash, &user.IsVerified, &user.IsActive, &user.LastLoginAt,
        &user.CreatedAt, &user.UpdatedAt, &user.LastLoginIP, &user.LastLoginCity)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("user not found with phone: %s", phoneNumber)
        }
        util.Error("Failed to get user by phone", 
            zap.String("phone_number", phoneNumber),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get user by phone: %w", err)
    }

    return user, nil
}

func (r *UserRepository) UpdateUserVerificationStatus(userID string, isVerified bool) error {
    // First get user's phone number for the update
    user, err := r.GetUserByID(userID)
    if err != nil {
        return err
    }

    now := time.Now().UTC()

    // Use batch operation for consistency across tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update main users table
    batch.Query(r.client.Prepared.UpdateUserVerification.Statement(),
        isVerified, now, user.PhoneNumber, userID)

    // Update users_by_id table
    batch.Query(`UPDATE users_by_id SET is_verified = ?, updated_at = ? WHERE user_id = ?`,
        isVerified, now, userID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to update user verification status",
            zap.String("user_id", userID),
            zap.Bool("is_verified", isVerified),
            zap.Error(err))
        return fmt.Errorf("failed to update user verification status: %w", err)
    }

    util.Info("User verification status updated",
        zap.String("user_id", userID),
        zap.Bool("is_verified", isVerified))

    return nil
}

func (r *UserRepository) UpdateUserMPINHash(userID string, mpinHash string) error {
    // First get user's phone number for the update
    user, err := r.GetUserByID(userID)
    if err != nil {
        return err
    }

    now := time.Now().UTC()

    // Use batch operation for consistency across tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update main users table
    batch.Query(r.client.Prepared.UpdateUserMPIN.Statement(),
        mpinHash, now, user.PhoneNumber, userID)

    // Update users_by_id table
    batch.Query(`UPDATE users_by_id SET mpin_hash = ?, updated_at = ? WHERE user_id = ?`,
        mpinHash, now, userID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to update user MPIN hash",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to update user MPIN hash: %w", err)
    }

    util.Info("User MPIN hash updated",
        zap.String("user_id", userID))

    return nil
}

func (r *UserRepository) UpdateUserDevice(userID string, deviceID string) error {
    // First get user's phone number for the update
    user, err := r.GetUserByID(userID)
    if err != nil {
        return err
    }

    now := time.Now().UTC()

    // Use batch operation for consistency across tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update main users table
    batch.Query(r.client.Prepared.UpdateUserDevice.Statement(),
        deviceID, now, user.PhoneNumber, userID)

    // Update users_by_id table
    batch.Query(`UPDATE users_by_id SET device_id = ?, updated_at = ? WHERE user_id = ?`,
        deviceID, now, userID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to update user device",
            zap.String("user_id", userID),
            zap.String("device_id", deviceID),
            zap.Error(err))
        return fmt.Errorf("failed to update user device: %w", err)
    }

    util.Info("User device updated",
        zap.String("user_id", userID),
        zap.String("device_id", deviceID))

    return nil
}

func (r *UserRepository) UpdateUserLastLogin(userID string, loginIP, loginCity string) error {
    // First get user's phone number for the update
    user, err := r.GetUserByID(userID)
    if err != nil {
        return err
    }

    now := time.Now().UTC()

    // Use batch operation for consistency across tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update main users table
    batch.Query(r.client.Prepared.UpdateUserLastLogin.Statement(),
        now, loginIP, loginCity, now, user.PhoneNumber, userID)

    // Update users_by_id table
    batch.Query(`UPDATE users_by_id SET last_login_at = ?, last_login_ip = ?, last_login_city = ?, updated_at = ? WHERE user_id = ?`,
        now, loginIP, loginCity, now, userID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to update user last login",
            zap.String("user_id", userID),
            zap.String("login_ip", loginIP),
            zap.Error(err))
        return fmt.Errorf("failed to update user last login: %w", err)
    }

    util.Info("User last login updated",
        zap.String("user_id", userID),
        zap.String("login_ip", loginIP),
        zap.String("login_city", loginCity))

    return nil
}

func (r *UserRepository) DeactivateUser(userID string) error {
    // First get user's phone number for the update
    user, err := r.GetUserByID(userID)
    if err != nil {
        return err
    }

    now := time.Now().UTC()

    // Use batch operation for consistency across tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update main users table
    batch.Query(r.client.Prepared.DeactivateUser.Statement(),
        now, user.PhoneNumber, userID)

    // Update users_by_id table
    batch.Query(`UPDATE users_by_id SET is_active = false, updated_at = ? WHERE user_id = ?`,
        now, userID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to deactivate user",
            zap.String("user_id", userID),
            zap.Error(err))
        return fmt.Errorf("failed to deactivate user: %w", err)
    }

    util.Info("User deactivated",
        zap.String("user_id", userID))

    return nil
}

// Additional helper methods for user management

func (r *UserRepository) IsPhoneNumberTaken(phoneNumber string) (bool, error) {
    var userID string
    query := r.client.Session.Query(`SELECT user_id FROM phone_to_user WHERE phone_number = ? LIMIT 1`, phoneNumber)

    err := query.Scan(&userID)
    if err != nil {
        if err == gocql.ErrNotFound {
            return false, nil
        }
        return false, fmt.Errorf("failed to check phone number: %w", err)
    }

    return true, nil
}

func (r *UserRepository) GetUserStats() (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Get total users count (approximate)
    var totalUsers int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM users_by_id`).Scan(&totalUsers); err != nil {
        util.Warn("Failed to get total users count", zap.Error(err))
    } else {
        stats["total_users"] = totalUsers
    }

    // Get verified users count
    var verifiedUsers int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM users_by_id WHERE is_verified = true ALLOW FILTERING`).Scan(&verifiedUsers); err != nil {
        util.Warn("Failed to get verified users count", zap.Error(err))
    } else {
        stats["verified_users"] = verifiedUsers
    }

    // Get active users count
    var activeUsers int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM users_by_id WHERE is_active = true ALLOW FILTERING`).Scan(&activeUsers); err != nil {
        util.Warn("Failed to get active users count", zap.Error(err))
    } else {
        stats["active_users"] = activeUsers
    }

    return stats, nil
}
