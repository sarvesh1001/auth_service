package scylla

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/bucketing"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// Constants for 500M scale optimization
const (
	MaxBatchSize        = 100  // Increased from 50
	MaxConcurrentReads  = 50   // Increased from 10
	MaxConcurrentWrites = 20   // For batch write operations
)

// UserRepository handles all user-related database operations
type UserRepositoryImpl struct {
	client            *ScyllaClient
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager
	logger            *zap.Logger

	// Prepared statements for frequently used queries
	stmtGetUserByID      *gocql.Query
	stmtUpdateLastLogin  *gocql.Query
	stmtUpdateUserStatus *gocql.Query
	stmtMutex            sync.RWMutex
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
	repo := &UserRepositoryImpl{
		client:            client,
		hasher:            hasher,
		encryptionManager: encryptionManager,
		bucketingManager:  bucketingManager,
		logger:            logger,
	}

	// Prepare frequently used statements
	repo.prepareStatements()

	return repo
}

// prepareStatements prepares frequently used queries for better performance
func (r *UserRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare GetUserByID query (most frequent)
	r.stmtGetUserByID = r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region
        FROM users WHERE user_bucket = ? AND user_id = ?`)

	// Prepare UpdateLastLogin query
	r.stmtUpdateLastLogin = r.client.Session.Query(`
        UPDATE users SET last_login = ? WHERE user_bucket = ? AND user_id = ?`)

	// Prepare UpdateUserStatus query
	r.stmtUpdateUserStatus = r.client.Session.Query(`
        UPDATE users SET is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

	r.logger.Info("Prepared statements initialized for user repository")
}

// CreateUser creates a new user with proper bucketing and encryption
func (r *UserRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	startTime := time.Now()

	// Generate user bucket
	userBucket := r.bucketingManager.GetUserBucket(user.UserID)
	user.UserBucket = userBucket

	// ✅ NO NEED TO ENCRYPT - Already encrypted in service!
	// user.PhoneEncrypted already contains encrypted value
	// user.PhoneKeyID already contains the key ID
	// user.PhoneEncryptedDEK already set from service

	// Insert into users table with encrypted DEK
	query := r.client.Session.Query(`
        INSERT INTO users (
            user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
            kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
            banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
            consent_agreed, consent_version, data_region
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.UserBucket,
		gocql.UUID(user.UserID),
		user.PhoneHash,
		user.PhoneEncrypted,           // ✅ Already encrypted from service
		gocql.UUID(user.PhoneKeyID),   // ✅ Already set from service
		user.PhoneEncryptedDEK,        // ✅ Already set from service
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
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Insert into phone_to_user lookup table
	phoneQuery := r.client.Session.Query(`
        INSERT INTO phone_to_user (phone_hash, user_bucket, user_id, created_at)
        VALUES (?, ?, ?, ?)`,
		user.PhoneHash,
		user.UserBucket,
		gocql.UUID(user.UserID),
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

// ✅ FIXED: GetUserByID retrieves a user by their ID with proper bucketing - NO DECRYPTION
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	gocqlUserID := gocql.UUID(userID)
	bucket := r.bucketingManager.GetUserBucket(userID)

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtGetUserByID.Bind(bucket, gocqlUserID)
	r.stmtMutex.RUnlock()

	var user models.User
	var encryptedPhone, phoneKeyID, encryptedDEK string
	var scannedID, scannedKYCVerifiedBy, scannedProfileServiceID, scannedBannedBy gocql.UUID

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&user.UserBucket,
		&scannedID,
		&user.PhoneHash,
		&encryptedPhone,        // ✅ Read encrypted ciphertext
		&phoneKeyID,            // ✅ Read key ID
		&encryptedDEK,          // ✅ Read encrypted DEK
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

	// ✅ FIXED: Store encrypted values AS-IS without decryption
	// The service layer will decrypt when needed
	user.PhoneEncrypted = encryptedPhone   // Store base64-encoded ciphertext
	user.PhoneEncryptedDEK = encryptedDEK  // Store base64-encoded encrypted DEK

	// Parse KeyID as UUID
	if phoneKeyID != "" {
		if keyID, err := uuid.Parse(phoneKeyID); err == nil {
			user.PhoneKeyID = keyID
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

// ✅ FIXED: UpdateUser - phone should already be encrypted from service
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

	// ✅ FIXED: Only update phone if it's encrypted (has KeyID and DEK set)
	if user.PhoneKeyID != uuid.Nil && len(user.PhoneEncryptedDEK) > 0 && len(user.PhoneEncrypted) > 0 {
		// Assume phone is already encrypted from service layer
		batch.Query(`
            UPDATE users SET
                phone_encrypted      = ?,
                phone_key_id         = ?,
                phone_encrypted_dek  = ?
            WHERE user_bucket = ? AND user_id = ?`,
			user.PhoneEncrypted,
			gocql.UUID(user.PhoneKeyID),
			user.PhoneEncryptedDEK,
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

// UpdateUserStatus updates user verification and status flags using prepared statement
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtUpdateUserStatus.Bind(isVerified, isBlocked, isBanned, now, bucket, gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateLastLogin updates user's last login timestamp using prepared statement
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
	bucket := r.bucketingManager.GetUserBucket(userID)

	// Use prepared statement
	r.stmtMutex.RLock()
	query := r.stmtUpdateLastLogin.Bind(timestamp, bucket, gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// Batch Operations

// CreateUsersBatch creates multiple users in a batch with increased batch size
func (r *UserRepositoryImpl) CreateUsersBatch(ctx context.Context, users []*models.User) error {
	if len(users) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	batchSize := 0

	for _, user := range users {
		userBucket := r.bucketingManager.GetUserBucket(user.UserID)
		user.UserBucket = userBucket

		// ✅ FIXED: Expect phone already encrypted from service
		batch.Query(`
            INSERT INTO users (
                user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
                kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
                banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
                consent_agreed, consent_version, data_region
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.UserBucket,
			gocql.UUID(user.UserID),
			user.PhoneHash,
			user.PhoneEncrypted,           // ✅ Already encrypted
			gocql.UUID(user.PhoneKeyID),   // ✅ Already set
			user.PhoneEncryptedDEK,        // ✅ Already set
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
		if batchSize >= MaxBatchSize {
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

// ✅ FIXED: UpdateUsersBatch - phone data already encrypted from service
func (r *UserRepositoryImpl) UpdateUsersBatch(ctx context.Context, users []*models.User) error {
	if len(users) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	now := time.Now().UTC()
	batchSize := 0

	for _, user := range users {
		user.UpdatedAt = &now

		// ✅ FIXED: Phone is already encrypted from service layer
		batch.Query(`
            UPDATE users SET 
                phone_encrypted = ?, phone_key_id = ?, phone_encrypted_dek = ?, 
                device_id = ?, device_fingerprint = ?,
                kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?,
                profile_service_id = ?, is_verified = ?, is_blocked = ?, is_banned = ?, 
                banned_by = ?, banned_reason = ?, banned_at = ?, last_login = ?, 
                updated_at = ?, consent_agreed = ?, consent_version = ?, data_region = ?
            WHERE user_bucket = ? AND user_id = ?`,
			user.PhoneEncrypted,
			gocql.UUID(user.PhoneKeyID),
			user.PhoneEncryptedDEK,
			user.DeviceID, user.DeviceFingerprint,
			user.KYCStatus, user.KYCLevel, user.KYCVerifiedAt, gocql.UUID(user.KYCVerifiedBy),
			gocql.UUID(user.ProfileServiceID), user.IsVerified, user.IsBlocked, user.IsBanned,
			gocql.UUID(user.BannedBy), user.BannedReason, user.BannedAt, user.LastLogin,
			user.UpdatedAt, user.ConsentAgreed, user.ConsentVersion, user.DataRegion,
			user.UserBucket, gocql.UUID(user.UserID),
		)

		batchSize++
		if batchSize >= MaxBatchSize {
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

// GetUsersByIDBatch retrieves multiple users by their IDs with increased concurrency
func (r *UserRepositoryImpl) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}

	users := make([]*models.User, 0, len(userIDs))
	usersMu := sync.Mutex{}

	// Use errgroup for better concurrency control
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrentReads) // Now 50 instead of 10

	for _, id := range userIDs {
		id := id // capture
		g.Go(func() error {
			u, err := r.GetUserByID(gctx, id)
			if err != nil {
				r.logger.Warn("Failed to get user in batch",
					util.ErrorField(err),
					util.String("user_id", id.String()))
				return nil // Continue with other users
			}

			usersMu.Lock()
			users = append(users, u)
			usersMu.Unlock()
			return nil
		})
	}

	_ = g.Wait() // Ignore errors as we log them individually
	return users, nil
}

// UpdateUserStatusBatch updates status for multiple users with increased batch size
func (r *UserRepositoryImpl) UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	now := time.Now().UTC()
	batchSize := 0

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
		if batchSize >= MaxBatchSize {
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

// GetUsersByKYCStatus retrieves users by KYC status with pagination and larger page size
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
        LIMIT ?`, status, limit).
		PageSize(1000).
		PageState(pageState)

	iter := q.WithContext(ctx).Iter()
	defer iter.Close()

	// Pre-allocate slice
	ids := make([]uuid.UUID, 0, limit)
	var s string
	var bucket int
	var idG gocql.UUID

	for iter.Scan(&s, &bucket, &idG) {
		ids = append(ids, uuid.UUID(idG))
	}
	if err := iter.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate KYC MV: %w", err)
	}

	r.logger.Info("MV scan completed",
		util.Int("ids_collected", len(ids)),
	)

	next := iter.PageState()
	if len(ids) == 0 {
		return []*models.User{}, next, nil
	}

	// Hydrate user models in parallel
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

// ✅ FIXED: GetBannedUsers - NO DECRYPTION, store encrypted as-is
// GetBannedUsers retrieves banned users with pagination - uses ID hydration pattern
func (r *UserRepositoryImpl) GetBannedUsers(ctx context.Context, limit int, pageState []byte) ([]*models.User, []byte, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }

    r.logger.Debug("Querying banned_users MV", util.Int("limit", limit))

    // Step 1: Query ONLY the columns that exist in the MV
    q := r.client.Session.Query(`
        SELECT user_bucket, user_id
        FROM banned_users
        WHERE is_banned = true
        LIMIT ?`, limit).
        PageSize(1000).
        PageState(pageState)

    iter := q.WithContext(ctx).Iter()
    defer iter.Close()

    // Step 2: Collect user IDs from MV
    ids := make([]uuid.UUID, 0, limit)
    var bucket int
    var idG gocql.UUID

    for iter.Scan(&bucket, &idG) {
        ids = append(ids, uuid.UUID(idG))
    }

    if err := iter.Close(); err != nil {
        return nil, nil, fmt.Errorf("failed to iterate banned users MV: %w", err)
    }

    r.logger.Info("MV scan completed", util.Int("ids_collected", len(ids)))

    next := iter.PageState()
    if len(ids) == 0 {
        return []*models.User{}, next, nil
    }

    // Step 3: Hydrate full user models from main table (includes all encrypted fields)
    users, err := r.GetUsersByIDBatch(ctx, ids)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to hydrate banned users: %w", err)
    }

    return users, next, nil
}

// Helper to extract IDs from a slice of models.User
func extractIDs(users []*models.User) []uuid.UUID {
	ids := make([]uuid.UUID, len(users))
	for i, u := range users {
		ids[i] = u.UserID
	}
	return ids
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
	stats["max_concurrent_reads"] = MaxConcurrentReads
	stats["max_concurrent_writes"] = MaxConcurrentWrites
	stats["max_batch_size"] = MaxBatchSize
	return stats, nil
}
