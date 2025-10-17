package scylla

import (
    "context"
    "fmt"
    "time"

    "auth-service/internal/bucketing"
    "auth-service/internal/encryption"
    "auth-service/internal/hashing"
    "auth-service/internal/models"
    "auth-service/internal/util"

    "github.com/gocql/gocql"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

// UserRepository handles all user-related database operations
type UserRepositoryImpl struct {
    client            *ScyllaClient
    hasher            *hashing.Hasher
    encryptionManager *encryption.EncryptionManager
    bucketingManager  *bucketing.BucketingManager
    logger            *zap.Logger
}

// UserStatusUpdate represents a batch user status update
type UserStatusUpdate struct {
    UserID     uuid.UUID `db:"user_id"`
    IsVerified bool      `db:"is_verified"`
    IsBlocked  bool      `db:"is_blocked"`
    IsBanned   bool      `db:"is_banned"`
    UpdatedAt  time.Time `db:"updated_at"`
}

// NewUserRepository creates a new user repository
func NewUserRepository(
    client *ScyllaClient,
    hasher *hashing.Hasher,
    encryptionManager *encryption.EncryptionManager,
    bucketingManager *bucketing.BucketingManager,
    logger *zap.Logger,
) UserRepository {
    return &UserRepositoryImpl{
        client:            client,
        hasher:            hasher,
        encryptionManager: encryptionManager,
        bucketingManager:  bucketingManager,
        logger:            logger,
    }
}

// CreateUser creates a new user with proper bucketing and encryption
func (r *UserRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
    startTime := time.Now()

    // Generate user bucket
    userBucket := r.bucketingManager.GetUserBucket(user.UserID)
    user.UserBucket = userBucket

    // Encrypt phone number
    phoneStr := string(user.PhoneEncrypted)
    encryptedPhone, err := r.encryptionManager.EncryptField(ctx, phoneStr, "phone")
    if err != nil {
        return fmt.Errorf("failed to encrypt phone: %w", err)
    }

    // Insert into users
    query := r.client.Session.Query(`
        INSERT INTO users (
            user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
            device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
            kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
            banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
            consent_agreed, consent_version, data_region
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        user.UserBucket,
        gocql.UUID(user.UserID), // Convert to gocql.UUID
        user.PhoneHash,
        encryptedPhone.EncryptedValue,
        encryptedPhone.KeyID,
        user.DeviceID,
        user.DeviceFingerprint,
        user.KYCStatus,
        user.KYCLevel,
        user.KYCVerifiedAt,
        gocql.UUID(user.KYCVerifiedBy), // Convert to gocql.UUID
        gocql.UUID(user.ProfileServiceID), // Convert to gocql.UUID
        user.IsVerified,
        user.IsBlocked,
        user.IsBanned,
        gocql.UUID(user.BannedBy), // Convert to gocql.UUID
        user.BannedReason,
        user.BannedAt,
        user.CreatedAt,
        user.LastLogin,
        user.UpdatedAt,
        user.ConsentAgreed,
        user.ConsentVersion,
        user.DataRegion,
    )
    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }

    // Insert into phone_to_user
    phoneQuery := r.client.Session.Query(`
        INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
        VALUES (?, ?, ?, ?)`,
        user.PhoneHash,
        user.UserBucket,
        gocql.UUID(user.UserID), // Convert to gocql.UUID
        user.CreatedAt,
    )
    if err := r.client.ExecuteWithRetry(phoneQuery.WithContext(ctx), 3); err != nil {
        r.logger.Warn("Failed to create phone mapping, user created but mapping failed",
            util.ErrorField(err),
            util.String("user_id", user.UserID.String()),
        )
    }

    r.logger.Debug("User created successfully",
        util.String("user_id", user.UserID.String()),
        util.Int("bucket", user.UserBucket),
        util.Duration("duration", time.Since(startTime)),
    )
    return nil
}

// GetUserByID retrieves a user by their ID with proper bucketing
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
    gocqlUserID := gocql.UUID(userID)
    bucket := r.bucketingManager.GetUserBucket(userID)

    query := r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM users WHERE user_bucket = ? AND user_id = ?`,
        bucket, gocqlUserID,
    )

    var user models.User
    var encryptedPhone, phoneKeyID string
    var scannedID, scannedKYCVerifiedBy, scannedProfileServiceID, scannedBannedBy gocql.UUID

    err := r.client.ScanWithRetry(query.WithContext(ctx),
        &user.UserBucket,
        &scannedID,
        &user.PhoneHash,
        &encryptedPhone,
        &phoneKeyID,
        &user.DeviceID,
        &user.DeviceFingerprint,
        &user.KYCStatus,
        &user.KYCLevel,
        &user.KYCVerifiedAt,
        &scannedKYCVerifiedBy,
        &scannedProfileServiceID,
        &user.IsVerified,
        &user.IsBlocked,
        &user.IsBanned,
        &scannedBannedBy,
        &user.BannedReason,
        &user.BannedAt,
        &user.CreatedAt,
        &user.LastLogin,
        &user.UpdatedAt,
        &user.ConsentAgreed,
        &user.ConsentVersion,
        &user.DataRegion,
    )
    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("user not found: %s", userID)
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }

    // Convert scanned gocql.UUID back to uuid.UUID
    user.UserID = uuid.UUID(scannedID)
    user.KYCVerifiedBy = uuid.UUID(scannedKYCVerifiedBy)
    user.ProfileServiceID = uuid.UUID(scannedProfileServiceID)
    user.BannedBy = uuid.UUID(scannedBannedBy)

    // Decrypt phone number if present
    if encryptedPhone != "" {
        encData := &encryption.EncryptedData{
            EncryptedValue: encryptedPhone,
            KeyID:          phoneKeyID,
        }
        if decrypted, err := r.encryptionManager.DecryptField(ctx, encData); err == nil {
            user.PhoneEncrypted = []byte(decrypted)
        } else {
            r.logger.Warn("Failed to decrypt phone number",
                util.ErrorField(err),
                util.String("user_id", user.UserID.String()),
            )
        }
    }

    return &user, nil
}

// GetUserByPhoneHash retrieves a user by their phone hash
func (r *UserRepositoryImpl) GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error) {
    var bucket int
    var scannedID gocql.UUID

    query := r.client.Session.Query(`
        SELECT user_bucket, user_id FROM phone_to_user WHERE phone_hash = ?`,
        phoneHash,
    )
    if err := r.client.ScanWithRetry(query.WithContext(ctx), &bucket, &scannedID); err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("user not found for phone hash: %s", phoneHash)
        }
        return nil, fmt.Errorf("failed to get user by phone: %w", err)
    }

    userID := uuid.UUID(scannedID)
    return r.GetUserByID(ctx, userID)
}

// UpdateUser updates a user's information
func (r *UserRepositoryImpl) UpdateUser(ctx context.Context, user *models.User) error {
    now := time.Now().UTC()
    user.UpdatedAt = &now

    batch := r.client.Batch(gocql.LoggedBatch)

    batch.Query(`
        UPDATE users SET
            device_id          = ?,
            device_fingerprint = ?,
            profile_service_id = ?,
            data_region        = ?,
            updated_at         = ?
        WHERE user_bucket = ? AND user_id = ?`,
        user.DeviceID,
        user.DeviceFingerprint,
        gocql.UUID(user.ProfileServiceID),
        user.DataRegion,
        user.UpdatedAt,
        user.UserBucket,
        gocql.UUID(user.UserID),
    )

    if len(user.PhoneEncrypted) > 0 {
        encData, err := r.encryptionManager.EncryptField(ctx, string(user.PhoneEncrypted), "phone")
        if err != nil {
            return fmt.Errorf("failed to encrypt phone: %w", err)
        }
        batch.Query(`
            UPDATE users SET
                phone_encrypted = ?,
                phone_key_id    = ?
            WHERE user_bucket = ? AND user_id = ?`,
            encData.EncryptedValue,
            encData.KeyID,
            user.UserBucket,
            gocql.UUID(user.UserID),
        )
    }

    if err := r.client.ExecuteBatch(batch); err != nil {
        return fmt.Errorf("failed to update user: %w", err)
    }
    return nil
}

// UpdateUserProfile updates user profile service ID
func (r *UserRepositoryImpl) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()

    query := r.client.Session.Query(`
        UPDATE users SET profile_service_id = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        gocql.UUID(profileServiceID),
        now,
        bucket,
        gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateUserStatus updates user verification and status flags
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()

    query := r.client.Session.Query(`
        UPDATE users SET is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        isVerified, isBlocked, isBanned, now,
        bucket, gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateLastLogin updates user's last login timestamp
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
    bucket := r.bucketingManager.GetUserBucket(userID)

    query := r.client.Session.Query(`
        UPDATE users SET last_login = ? WHERE user_bucket = ? AND user_id = ?`,
        timestamp,
        bucket,
        gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// Batch Operations

// CreateUsersBatch creates multiple users in a batch
func (r *UserRepositoryImpl) CreateUsersBatch(ctx context.Context, users []*models.User) error {
    if len(users) == 0 {
        return nil
    }
    batch := r.client.Batch(gocql.UnloggedBatch)
    batchSize := 0
    maxBatchSize := 50

    for _, user := range users {
        userBucket := r.bucketingManager.GetUserBucket(user.UserID)
        user.UserBucket = userBucket

        encPhone, err := r.encryptionManager.EncryptField(ctx, string(user.PhoneEncrypted), "phone")
        if err != nil {
            return fmt.Errorf("failed to encrypt phone for user %s: %w", user.UserID, err)
        }

        batch.Query(`
            INSERT INTO users (
                user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
                device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
                kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
                banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
                consent_agreed, consent_version, data_region
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            user.UserBucket,
            gocql.UUID(user.UserID),
            user.PhoneHash,
            encPhone.EncryptedValue,
            encPhone.KeyID,
            user.DeviceID,
            user.DeviceFingerprint,
            user.KYCStatus,
            user.KYCLevel,
            user.KYCVerifiedAt,
            gocql.UUID(user.KYCVerifiedBy),
            gocql.UUID(user.ProfileServiceID),
            user.IsVerified,
            user.IsBlocked,
            user.IsBanned,
            gocql.UUID(user.BannedBy),
            user.BannedReason,
            user.BannedAt,
            user.CreatedAt,
            user.LastLogin,
            user.UpdatedAt,
            user.ConsentAgreed,
            user.ConsentVersion,
            user.DataRegion,
        )

        batch.Query(`
            INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
            VALUES (?, ?, ?, ?)`,
            user.PhoneHash,
            user.UserBucket,
            gocql.UUID(user.UserID),
            user.CreatedAt,
        )

        batchSize += 2
        if batchSize >= maxBatchSize {
            if err := r.client.ExecuteBatch(batch); err != nil {
                return fmt.Errorf("failed to execute user batch: %w", err)
            }
            batch = r.client.Batch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            return fmt.Errorf("failed to execute final user batch: %w", err)
        }
    }
    r.logger.Info("Batch user creation completed", util.Int("users_created", len(users)))
    return nil
}

// UpdateUsersBatch updates multiple users in batch
func (r *UserRepositoryImpl) UpdateUsersBatch(ctx context.Context, users []*models.User) error {
    if len(users) == 0 {
        return nil
    }
    batch := r.client.Batch(gocql.UnloggedBatch)
    now := time.Now().UTC()
    batchSize := 0
    maxBatchSize := 50

    for _, user := range users {
        user.UpdatedAt = &now

        var encPhoneVal, phoneKeyID string
        if len(user.PhoneEncrypted) > 0 {
            encData, err := r.encryptionManager.EncryptField(ctx, string(user.PhoneEncrypted), "phone")
            if err != nil {
                return fmt.Errorf("failed to encrypt phone for user %s: %w", user.UserID, err)
            }
            encPhoneVal = encData.EncryptedValue
            phoneKeyID = encData.KeyID
        }

        batch.Query(`
            UPDATE users SET 
                phone_encrypted = ?, phone_key_id = ?, device_id = ?, device_fingerprint = ?,
                kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?,
                profile_service_id = ?, is_verified = ?, is_blocked = ?, is_banned = ?, 
                banned_by = ?, banned_reason = ?, banned_at = ?, last_login = ?, 
                updated_at = ?, consent_agreed = ?, consent_version = ?, data_region = ?
            WHERE user_bucket = ? AND user_id = ?`,
            encPhoneVal, phoneKeyID,
            user.DeviceID, user.DeviceFingerprint,
            user.KYCStatus, user.KYCLevel, user.KYCVerifiedAt, gocql.UUID(user.KYCVerifiedBy),
            gocql.UUID(user.ProfileServiceID), user.IsVerified, user.IsBlocked, user.IsBanned,
            gocql.UUID(user.BannedBy), user.BannedReason, user.BannedAt, user.LastLogin,
            user.UpdatedAt, user.ConsentAgreed, user.ConsentVersion, user.DataRegion,
            user.UserBucket, gocql.UUID(user.UserID),
        )

        batchSize++
        if batchSize >= maxBatchSize {
            if err := r.client.ExecuteBatch(batch); err != nil {
                return fmt.Errorf("failed to execute update batch: %w", err)
            }
            batch = r.client.Batch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            return fmt.Errorf("failed to execute final update batch: %w", err)
        }
    }
    return nil
}

// GetUsersByIDBatch retrieves multiple users by their IDs
func (r *UserRepositoryImpl) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
    if len(userIDs) == 0 {
        return []*models.User{}, nil
    }
    users := make([]*models.User, 0, len(userIDs))
    errorsCh := make(chan error, len(userIDs))
    results := make(chan *models.User, len(userIDs))
    semaphore := make(chan struct{}, 10)

    for _, id := range userIDs {
        go func(uid uuid.UUID) {
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            u, err := r.GetUserByID(ctx, uid)
            if err != nil {
                errorsCh <- err
                return
            }
            results <- u
        }(id)
    }

    for i := 0; i < len(userIDs); i++ {
        select {
        case u := <-results:
            users = append(users, u)
        case err := <-errorsCh:
            r.logger.Warn("Failed to get user in batch", util.ErrorField(err))
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }
    return users, nil
}

// UpdateUserStatusBatch updates status for multiple users
func (r *UserRepositoryImpl) UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error {
    if len(updates) == 0 {
        return nil
    }
    batch := r.client.Batch(gocql.UnloggedBatch)
    now := time.Now().UTC()
    batchSize := 0
    maxBatchSize := 50

    for _, update := range updates {
        bucket := r.bucketingManager.GetUserBucket(update.UserID)
        batch.Query(`
            UPDATE users SET 
                is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
            WHERE user_bucket = ? AND user_id = ?`,
            update.IsVerified, update.IsBlocked, update.IsBanned, now,
            bucket, gocql.UUID(update.UserID),
        )
        batchSize++
        if batchSize >= maxBatchSize {
            if err := r.client.ExecuteBatch(batch); err != nil {
                return fmt.Errorf("failed to execute status update batch: %w", err)
            }
            batch = r.client.Batch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            return fmt.Errorf("failed to execute final status update batch: %w", err)
        }
    }
    return nil
}

// UpdateKYCStatus updates user's KYC status
func (r *UserRepositoryImpl) UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string, verifiedBy uuid.UUID) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    query := r.client.Session.Query(`
        UPDATE users SET kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?
        WHERE user_bucket = ? AND user_id = ?`,
        status, level, now, gocql.UUID(verifiedBy),
        bucket, gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// GetUsersByKYCStatus retrieves users by KYC status with pagination (via MV)
func (r *UserRepositoryImpl) GetUsersByKYCStatus(ctx context.Context, status string, limit int, pageState []byte) ([]*models.User, []byte, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    r.logger.Debug("Querying users_by_kyc_status MV", util.String("status", status), util.Int("limit", limit))
    q := r.client.Session.Query(`
        SELECT kyc_status, user_bucket, user_id
        FROM users_by_kyc_status
        WHERE kyc_status = ?
        LIMIT ?`, status, limit).PageState(pageState)

    iter := q.WithContext(ctx).Iter()
    defer iter.Close()

    var ids []uuid.UUID
    rowCount := 0
    for {
        var s string
        var bucket int
        var idG gocql.UUID
        if !iter.Scan(&s, &bucket, &idG) {
            break
        }
        rowCount++
        ids = append(ids, uuid.UUID(idG))
    }
    if err := iter.Close(); err != nil {
        return nil, nil, fmt.Errorf("failed to iterate KYC MV: %w", err)
    }
    r.logger.Info("MV scan completed", util.Int("rows_found", rowCount), util.Int("ids_collected", len(ids)))
    next := iter.PageState()
    if len(ids) == 0 {
        return []*models.User{}, next, nil
    }
    users, err := r.GetUsersByIDBatch(ctx, ids)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to hydrate users: %w", err)
    }
    return users, next, nil
}

// UpdateUserConsent updates user consent information
func (r *UserRepositoryImpl) UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    query := r.client.Session.Query(`
        UPDATE users SET consent_agreed = ?, consent_version = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        agreed, version, now,
        bucket, gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// BanUser bans a user with reason
func (r *UserRepositoryImpl) BanUser(ctx context.Context, userID, bannedBy uuid.UUID, reason string) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        true, gocql.UUID(bannedBy), reason, now, now,
        bucket, gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UnbanUser unbans a user
func (r *UserRepositoryImpl) UnbanUser(ctx context.Context, userID uuid.UUID) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        false, gocql.UUID(uuid.Nil), "", nil, now,
        bucket, gocql.UUID(userID),
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// GetBannedUsers retrieves banned users with pagination
// GetBannedUsers retrieves banned users with pagination using materialized view
func (r *UserRepositoryImpl) GetBannedUsers(ctx context.Context, limit int, pageState []byte) ([]*models.User, []byte, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }

    // Use the materialized view for banned users
    query := r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM banned_users 
        WHERE is_banned = true
        LIMIT ?`, limit).PageState(pageState)

    iter := query.WithContext(ctx).Iter()
    defer iter.Close()

    var users []*models.User
    for {
        var u models.User
        var encryptedPhone, phoneKeyID string
        var scannedID, scannedKYCVerifiedBy, scannedProfileServiceID, scannedBannedBy gocql.UUID
        
        if !iter.Scan(
            &u.UserBucket,
            &scannedID,
            &u.PhoneHash,
            &encryptedPhone,
            &phoneKeyID,
            &u.DeviceID,
            &u.DeviceFingerprint,
            &u.KYCStatus,
            &u.KYCLevel,
            &u.KYCVerifiedAt,
            &scannedKYCVerifiedBy,
            &scannedProfileServiceID,
            &u.IsVerified,
            &u.IsBlocked,
            &u.IsBanned,
            &scannedBannedBy,
            &u.BannedReason,
            &u.BannedAt,
            &u.CreatedAt,
            &u.LastLogin,
            &u.UpdatedAt,
            &u.ConsentAgreed,
            &u.ConsentVersion,
            &u.DataRegion,
        ) {
            break
        }
        
        // Convert gocql.UUID to uuid.UUID
        u.UserID = uuid.UUID(scannedID)
        u.KYCVerifiedBy = uuid.UUID(scannedKYCVerifiedBy)
        u.ProfileServiceID = uuid.UUID(scannedProfileServiceID)
        u.BannedBy = uuid.UUID(scannedBannedBy)
        
        users = append(users, &u)
    }
    if err := iter.Close(); err != nil {
        return nil, nil, fmt.Errorf("failed to iterate banned users: %w", err)
    }
    return users, iter.PageState(), nil
}
// HealthCheck performs a health check on the repository
func (r *UserRepositoryImpl) HealthCheck(ctx context.Context) error {
    var count int
    if err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").WithContext(ctx).Scan(&count); err != nil {
        return fmt.Errorf("user repository health check failed: %w", err)
    }
    return nil
}

// GetRepositoryStats returns repository statistics
func (r *UserRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
    stats := make(map[string]interface{})
    if r.encryptionManager != nil {
        stats["encryption_cache_size"] = r.encryptionManager.GetCacheSize()
    }
    stats["user_buckets"] = r.bucketingManager.GetUserBuckets()
    stats["event_buckets"] = r.bucketingManager.GetEventBuckets()
    return stats, nil
}