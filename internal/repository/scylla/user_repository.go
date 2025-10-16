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

	// Encrypt phone number - convert []byte to string for encryption
	phoneStr := string(user.PhoneEncrypted)
	encryptedPhone, err := r.encryptionManager.EncryptField(ctx, phoneStr, "phone")
	if err != nil {
		return fmt.Errorf("failed to encrypt phone: %w", err)
	}

	// Use raw queries since prepared statements might not be set up yet
	query := r.client.Session.Query(`
        INSERT INTO users (
            user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
            device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
            kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
            banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
            consent_agreed, consent_version, data_region
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.UserBucket,
		user.UserID,
		user.PhoneHash,
		encryptedPhone.EncryptedValue,
		encryptedPhone.KeyID,
		user.DeviceID,
		user.DeviceFingerprint,
		user.KYCStatus,
		user.KYCLevel,
		user.KYCVerifiedAt,
		user.KYCVerifiedBy,
		user.ProfileServiceID,
		user.IsVerified,
		user.IsBlocked,
		user.IsBanned,
		user.BannedBy,
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

	// Also create phone to user mapping
	phoneQuery := r.client.Session.Query(`
        INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
        VALUES (?, ?, ?, ?)`,
		user.PhoneHash,
		user.UserBucket,
		user.UserID,
		user.CreatedAt,
	)

	if err := r.client.ExecuteWithRetry(phoneQuery.WithContext(ctx), 3); err != nil {
		r.logger.Warn("Failed to create phone mapping, user created but mapping failed",
			util.ErrorField(err),
			util.String("user_id", user.UserID),
		)
		// Continue since user was created successfully
	}

	r.logger.Debug("User created successfully",
		util.String("user_id", user.UserID),
		util.Int("bucket", user.UserBucket),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// GetUserByID retrieves a user by their ID with proper bucketing
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	userBucket := r.bucketingManager.GetUserBucket(userID)

	query := r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM users WHERE user_bucket = ? AND user_id = ?`,
		userBucket, userID)

	var user models.User
	var encryptedPhone string
	var phoneKeyID string

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&user.UserBucket,
		&user.UserID,
		&user.PhoneHash,
		&encryptedPhone,
		&phoneKeyID,
		&user.DeviceID,
		&user.DeviceFingerprint,
		&user.KYCStatus,
		&user.KYCLevel,
		&user.KYCVerifiedAt,
		&user.KYCVerifiedBy,
		&user.ProfileServiceID,
		&user.IsVerified,
		&user.IsBlocked,
		&user.IsBanned,
		&user.BannedBy,
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

	// Decrypt phone number
	if encryptedPhone != "" {
		encryptedData := &encryption.EncryptedData{
			EncryptedValue: encryptedPhone,
			KeyID:          phoneKeyID,
		}

		decryptedPhone, err := r.encryptionManager.DecryptField(ctx, encryptedData)
		if err != nil {
			r.logger.Warn("Failed to decrypt phone number",
				util.ErrorField(err),
				util.String("user_id", userID.String()),
			)
			// Continue without phone number
		} else {
			user.PhoneEncrypted = []byte(decryptedPhone)
		}
	}

	return &user, nil
}

// GetUserByPhoneHash retrieves a user by their phone hash
func (r *UserRepositoryImpl) GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error) {
	// First get user ID and bucket from phone mapping
	var userID uuid.UUID
	var userBucket int

	query := r.client.Session.Query(`
        SELECT user_bucket, user_id FROM phone_to_user WHERE phone_hash = ?`,
		phoneHash)
	err := r.client.ScanWithRetry(query.WithContext(ctx), &userBucket, &userID)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("user not found for phone hash: %s", phoneHash)
		}
		return nil, fmt.Errorf("failed to get user by phone: %w", err)
	}

	// Then get the full user data
	return r.GetUserByID(ctx, userID)
}

// UpdateUser updates a user's information
func (r *UserRepositoryImpl) UpdateUser(ctx context.Context, user *models.User) error {
	now := time.Now().UTC()
	user.UpdatedAt = &now

	batch := r.client.Batch(gocql.LoggedBatch)

	// Only update the intended fields
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
		user.ProfileServiceID,
		user.DataRegion,
		user.UpdatedAt,
		user.UserBucket,
		user.UserID,
	)

	// Update phone if explicitly changed
	if len(user.PhoneEncrypted) > 0 {
		encryptedValue := string(user.PhoneEncrypted)
		encData, err := r.encryptionManager.EncryptField(ctx, encryptedValue, "phone")
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
			user.UserID,
		)
	}

	if err := r.client.ExecuteBatch(batch); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdateUserProfile updates user profile service ID
func (r *UserRepositoryImpl) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error {
	userBucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()

	// Convert google.uuid.UUID to gocql.UUID
	profileGocqlUUID := gocql.UUID(profileServiceID)

	query := r.client.Session.Query(`
        UPDATE users SET profile_service_id = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
		profileGocqlUUID,
		now,
		userBucket,
		gocql.UUID(userID), // also convert userID here
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateUserStatus updates user verification and status flags
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()

    // Convert google uuid.UUID to gocql.UUID
    gocqlUserID := gocql.UUID(userID)

    query := r.client.Session.Query(`
        UPDATE users SET is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        isVerified, isBlocked, isBanned, now, userBucket, gocqlUserID)
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateLastLogin updates user's last login timestamp
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    userGocqlUUID := gocql.UUID(userID)

    query := r.client.Session.Query(`
        UPDATE users SET last_login = ? WHERE user_bucket = ? AND user_id = ?`,
        timestamp,
        userBucket,
        userGocqlUUID,
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
	maxBatchSize := 50 // Scylla recommended batch size

	for _, user := range users {
		// Generate user bucket
		userBucket := r.bucketingManager.GetUserBucket(user.UserID)
		user.UserBucket = userBucket

		// Encrypt phone number
		phoneStr := string(user.PhoneEncrypted)
		encryptedPhone, err := r.encryptionManager.EncryptField(ctx, phoneStr, "phone")
		if err != nil {
			return fmt.Errorf("failed to encrypt phone for user %s: %w", user.UserID, err)
		}

		// Add user to batch
		batch.Query(`
            INSERT INTO users (
                user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
                device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
                kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
                banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
                consent_agreed, consent_version, data_region
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.UserBucket, user.UserID, user.PhoneHash, encryptedPhone.EncryptedValue, encryptedPhone.KeyID,
			user.DeviceID, user.DeviceFingerprint, user.KYCStatus, user.KYCLevel, user.KYCVerifiedAt,
			user.KYCVerifiedBy, user.ProfileServiceID, user.IsVerified, user.IsBlocked, user.IsBanned,
			user.BannedBy, user.BannedReason, user.BannedAt, user.CreatedAt, user.LastLogin, user.UpdatedAt,
			user.ConsentAgreed, user.ConsentVersion, user.DataRegion,
		)

		// Add phone mapping to batch
		batch.Query(`
            INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
            VALUES (?, ?, ?, ?)`,
			user.PhoneHash, user.UserBucket, user.UserID, user.CreatedAt,
		)

		batchSize += 2

		// Execute batch if we reach the maximum size
		if batchSize >= maxBatchSize {
			if err := r.client.ExecuteBatch(batch); err != nil {
				return fmt.Errorf("failed to execute user batch: %w", err)
			}
			// Create new batch
			batch = r.client.Batch(gocql.UnloggedBatch)
			batchSize = 0
		}
	}

	// Execute remaining queries
	if batchSize > 0 {
		if err := r.client.ExecuteBatch(batch); err != nil {
			return fmt.Errorf("failed to execute final user batch: %w", err)
		}
	}

	r.logger.Info("Batch user creation completed",
		util.Int("users_created", len(users)),
	)

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

		// Encrypt phone number if updated
		var encryptedPhone string
		var phoneKeyID string

		if len(user.PhoneEncrypted) > 0 {
			phoneStr := string(user.PhoneEncrypted)
			encryptedData, err := r.encryptionManager.EncryptField(ctx, phoneStr, "phone")
			if err != nil {
				return fmt.Errorf("failed to encrypt phone for user %s: %w", user.UserID, err)
			}
			encryptedPhone = encryptedData.EncryptedValue
			phoneKeyID = encryptedData.KeyID
		}

		batch.Query(`
            UPDATE users SET 
                phone_encrypted = ?, phone_key_id = ?, device_id = ?, device_fingerprint = ?,
                kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?,
                profile_service_id = ?, is_verified = ?, is_blocked = ?, is_banned = ?,
                banned_by = ?, banned_reason = ?, banned_at = ?, last_login = ?,
                updated_at = ?, consent_agreed = ?, consent_version = ?, data_region = ?
            WHERE user_bucket = ? AND user_id = ?`,
			encryptedPhone, phoneKeyID, user.DeviceID, user.DeviceFingerprint,
			user.KYCStatus, user.KYCLevel, user.KYCVerifiedAt, user.KYCVerifiedBy,
			user.ProfileServiceID, user.IsVerified, user.IsBlocked, user.IsBanned,
			user.BannedBy, user.BannedReason, user.BannedAt, user.LastLogin,
			user.UpdatedAt, user.ConsentAgreed, user.ConsentVersion, user.DataRegion,
			user.UserBucket, user.UserID,
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
	errors := make(chan error, len(userIDs))
	results := make(chan *models.User, len(userIDs))

	// Process in parallel with limited concurrency
	semaphore := make(chan struct{}, 10) // Limit concurrent queries

	for _, userID := range userIDs {
		go func(id uuid.UUID) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			user, err := r.GetUserByID(ctx, id)
			if err != nil {
				errors <- err
				return
			}
			results <- user
		}(userID)
	}

	// Collect results
	for i := 0; i < len(userIDs); i++ {
		select {
		case user := <-results:
			users = append(users, user)
		case err := <-errors:
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
		userBucket := r.bucketingManager.GetUserBucket(update.UserID)

		batch.Query(`
            UPDATE users SET 
                is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
            WHERE user_bucket = ? AND user_id = ?`,
			update.IsVerified, update.IsBlocked, update.IsBanned, now,
			userBucket, update.UserID,
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

// Compliance & KYC Operations

// UpdateKYCStatus updates user's KYC status
func (r *UserRepositoryImpl) UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string, verifiedBy uuid.UUID) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    userGocqlUUID := gocql.UUID(userID)
    verifiedByGocqlUUID := gocql.UUID(verifiedBy)

    query := r.client.Session.Query(`
        UPDATE users SET kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?
        WHERE user_bucket = ? AND user_id = ?`,
        status,
        level,
        now,
        verifiedByGocqlUUID,
        userBucket,
        userGocqlUUID,
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}
// GetUsersByKYCStatus retrieves users by KYC status with pagination (via MV)
func (r *UserRepositoryImpl) GetUsersByKYCStatus(ctx context.Context, status string, limit int, pageState []byte) ([]*models.User, []byte, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    r.logger.Debug("Querying users_by_kyc_status MV",
        util.String("status", status),
        util.Int("limit", limit),
    )
    
    q := r.client.Session.Query(`
        SELECT kyc_status, user_bucket, user_id
        FROM users_by_kyc_status
        WHERE kyc_status = ?
        LIMIT ?`,
        status, limit,
    ).PageState(pageState)

    iter := q.WithContext(ctx).Iter()
    defer iter.Close()

    var ids []uuid.UUID
    rowCount := 0
    
    for {
        var s string
        var b int
        var idG gocql.UUID
        
        if !iter.Scan(&s, &b, &idG) {
            break
        }
        
        rowCount++
        
        // ✅ CORRECT: Convert gocql.UUID to google/uuid.UUID using string representation
        googleUUID, err := uuid.Parse(idG.String())
        if err != nil {
            r.logger.Error("Failed to parse UUID from MV",
                util.ErrorField(err),
                util.String("raw_uuid", idG.String()),
            )
            continue
        }
        
        ids = append(ids, googleUUID)
        
        r.logger.Debug("Found user in MV",
            util.String("user_id", googleUUID.String()),
            util.Int("user_bucket", b),
            util.String("kyc_status", s),
        )
    }

    if err := iter.Close(); err != nil {
        r.logger.Error("Failed to iterate KYC MV",
            util.ErrorField(err),
            util.String("status", status),
        )
        return nil, nil, fmt.Errorf("failed to iterate KYC MV: %w", err)
    }
    
    r.logger.Info("MV scan completed",
        util.Int("rows_found", rowCount),
        util.Int("ids_collected", len(ids)),
    )
    
    next := iter.PageState()

    if len(ids) == 0 {
        r.logger.Warn("No users found in MV",
            util.String("kyc_status", status),
        )
        return []*models.User{}, next, nil
    }

    r.logger.Debug("Fetching full user data",
        util.Int("user_count", len(ids)),
    )
    
    users, err := r.GetUsersByIDBatch(ctx, ids)
    if err != nil {
        r.logger.Error("Failed to hydrate users",
            util.ErrorField(err),
            util.Int("id_count", len(ids)),
        )
        return nil, nil, fmt.Errorf("failed to hydrate users: %w", err)
    }
    
    r.logger.Info("Users retrieved successfully",
        util.Int("users_returned", len(users)),
    )
    
    return users, next, nil
}

// UpdateUserConsent updates user consent information
func (r *UserRepositoryImpl) UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    userGocqlUUID := gocql.UUID(userID)

    query := r.client.Session.Query(`
        UPDATE users SET consent_agreed = ?, consent_version = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        agreed,
        version,
        now,
        userBucket,
        userGocqlUUID,
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}
// Administrative Operations

// BanUser bans a user with reason
func (r *UserRepositoryImpl) BanUser(ctx context.Context, userID, bannedBy uuid.UUID, reason string) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    userGocqlUUID := gocql.UUID(userID)
    bannedByGocqlUUID := gocql.UUID(bannedBy)

    query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        true,
        bannedByGocqlUUID,
        reason,
        now,
        now,
        userBucket,
        userGocqlUUID,
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}
// UnbanUser unbans a user
func (r *UserRepositoryImpl) UnbanUser(ctx context.Context, userID uuid.UUID) error {
    userBucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()
    userGocqlUUID := gocql.UUID(userID)

    query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        false,
        "",          // banned_by cleared
        "",          // banned_reason cleared
        nil,         // banned_at cleared
        now,
        userBucket,
        userGocqlUUID,
    )
    return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}
// GetBannedUsers retrieves banned users with pagination
func (r *UserRepositoryImpl) GetBannedUsers(ctx context.Context, limit int, pageState []byte) ([]*models.User, []byte, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Query all buckets for banned users
	userBuckets := r.bucketingManager.GetUserBuckets()
	buckets := make([]interface{}, userBuckets)
	for i := 0; i < userBuckets; i++ {
		buckets[i] = i
	}

	query := r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM users 
        WHERE user_bucket IN ? AND is_banned = true
        LIMIT ?`,
		buckets, limit,
	).PageState(pageState)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var users []*models.User
	for {
		var user models.User
		var encryptedPhone string
		var phoneKeyID string

		if !iter.Scan(
			&user.UserBucket,
			&user.UserID,
			&user.PhoneHash,
			&encryptedPhone,
			&phoneKeyID,
			&user.DeviceID,
			&user.DeviceFingerprint,
			&user.KYCStatus,
			&user.KYCLevel,
			&user.KYCVerifiedAt,
			&user.KYCVerifiedBy,
			&user.ProfileServiceID,
			&user.IsVerified,
			&user.IsBlocked,
			&user.IsBanned,
			&user.BannedBy,
			&user.BannedReason,
			&user.BannedAt,
			&user.CreatedAt,
			&user.LastLogin,
			&user.UpdatedAt,
			&user.ConsentAgreed,
			&user.ConsentVersion,
			&user.DataRegion,
		) {
			break
		}

		// Skip phone decryption for banned users list for performance
		users = append(users, &user)
	}

	if err := iter.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate banned users: %w", err)
	}

	nextPageState := iter.PageState()
	return users, nextPageState, nil
}

// HealthCheck performs a health check on the repository
func (r *UserRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Try to execute a simple query
	var count int
	err := r.client.Session.Query("SELECT COUNT(*) FROM system.local").WithContext(ctx).Scan(&count)
	if err != nil {
		return fmt.Errorf("user repository health check failed: %w", err)
	}
	return nil
}

// GetRepositoryStats returns repository statistics
func (r *UserRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get cache sizes
	if r.encryptionManager != nil {
		stats["encryption_cache_size"] = r.encryptionManager.GetCacheSize()
	}

	// Add bucketing info
	stats["user_buckets"] = r.bucketingManager.GetUserBuckets()
	stats["event_buckets"] = r.bucketingManager.GetEventBuckets()

	return stats, nil
}
