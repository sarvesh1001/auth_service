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

// ============================================================================
// REPOSITORY CONSTANTS / TYPES
// ============================================================================

// Constants for 500M scale optimization
const (
	MaxBatchSize        = 100 // batching write ops
	MaxConcurrentReads  = 50  // parallel hydration
	MaxConcurrentWrites = 20  // reserved for future high-throughput batch writes
)

// UserRepositoryImpl handles all user-related DB operations against Scylla
type UserRepositoryImpl struct {
	client            *ScyllaClient
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager
	logger            *zap.Logger

	// Prepared statements for hot-path queries
	stmtGetUserByID      *gocql.Query
	stmtUpdateLastLogin  *gocql.Query
	stmtUpdateUserStatus *gocql.Query

	stmtMutex sync.RWMutex
}

// UserStatusUpdate represents a batch user status update
type UserStatusUpdate struct {
	UserID     uuid.UUID `db:"user_id"`
	IsVerified bool      `db:"is_verified"`
	IsBlocked  bool      `db:"is_blocked"`
	IsBanned   bool      `db:"is_banned"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================

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
	repo.prepareStatements()
	return repo
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *UserRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Updated: removed user_role_level and is_active from SELECT
	r.stmtGetUserByID = r.client.Session.Query(`
        SELECT user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
               device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
               kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
               banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
               consent_agreed, consent_version, data_region, company_id
        FROM users WHERE user_bucket = ? AND user_id = ?`)

	r.stmtUpdateLastLogin = r.client.Session.Query(`
        UPDATE users SET last_login = ? WHERE user_bucket = ? AND user_id = ?`)

	r.stmtUpdateUserStatus = r.client.Session.Query(`
        UPDATE users SET is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`)

	r.logger.Info("Prepared statements initialized for user repository")
}

// ============================================================================
// CORE USER OPERATIONS
// ============================================================================

// CreateUser creates a new user with proper bucketing and encryption.
func (r *UserRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	startTime := time.Now()

	userBucket := r.bucketingManager.GetUserBucket(user.UserID)
	user.UserBucket = userBucket

	// Updated: removed user_role_level and is_active from INSERT
	query := r.client.Session.Query(`
        INSERT INTO users (
            user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
            kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
            banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
            consent_agreed, consent_version, data_region, company_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.UserBucket,
		gocql.UUID(user.UserID),
		user.PhoneHash,
		user.PhoneEncrypted,
		gocql.UUID(user.PhoneKeyID),
		user.PhoneEncryptedDEK,
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
		gocql.UUID(user.CompanyID),
	)
	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Insert phone → user lookup (single row, no clustering)
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

// GetUserByID retrieves a single user by ID. No decryption is done here.
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	bucket := r.bucketingManager.GetUserBucket(userID)

	r.stmtMutex.RLock()
	query := r.stmtGetUserByID.Bind(bucket, gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	var user models.User

	var encryptedPhone string
	var encryptedDEK string
	var phoneKeyID string

	var scannedUserID gocql.UUID
	var scannedKYCVerifiedBy gocql.UUID
	var scannedProfileServiceID gocql.UUID
	var scannedBannedBy gocql.UUID
	var scannedCompanyID gocql.UUID

	// Updated: removed user_role_level and is_active from scan
	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&user.UserBucket,
		&scannedUserID,
		&user.PhoneHash,
		&encryptedPhone,
		&phoneKeyID,
		&encryptedDEK,
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
		&scannedCompanyID,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("user not found: %s", userID)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// map UUIDs back to Go UUID
	user.UserID = uuid.UUID(scannedUserID)
	user.KYCVerifiedBy = uuid.UUID(scannedKYCVerifiedBy)
	user.ProfileServiceID = uuid.UUID(scannedProfileServiceID)
	user.BannedBy = uuid.UUID(scannedBannedBy)
	user.CompanyID = uuid.UUID(scannedCompanyID)

	// store encrypted blobs as-is
	user.PhoneEncrypted = encryptedPhone
	user.PhoneEncryptedDEK = encryptedDEK

	// parse phoneKeyID (string) → uuid
	if phoneKeyID != "" {
		if keyID, err := uuid.Parse(phoneKeyID); err == nil {
			user.PhoneKeyID = keyID
		}
	}

	return &user, nil
}

// GetUserByPhoneHash retrieves a user by phone hash using phone_to_user lookup
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

	return r.GetUserByID(ctx, uuid.UUID(scannedID))
}

// GetUsersByPhoneHashIndex retrieves all user(s) for a given phone hash using MV users_by_phone_hash
func (r *UserRepositoryImpl) GetUsersByPhoneHashIndex(ctx context.Context, phoneHash string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	q := r.client.Session.Query(`
        SELECT user_bucket, user_id
        FROM users_by_phone_hash
        WHERE phone_hash = ?
        LIMIT ?`,
		phoneHash, limit,
	)

	iter := q.WithContext(ctx).Iter()
	defer iter.Close()

	var (
		bucket  int
		userIDG gocql.UUID
		userIDs []uuid.UUID
	)

	for iter.Scan(&bucket, &userIDG) {
		userIDs = append(userIDs, uuid.UUID(userIDG))
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate users_by_phone_hash: %w", err)
	}

	return r.GetUsersByIDBatch(ctx, userIDs)
}

// UpdateUser updates mutable fields for a user.
func (r *UserRepositoryImpl) UpdateUser(ctx context.Context, user *models.User) error {
	now := time.Now().UTC()
	user.UpdatedAt = &now

	batch := r.client.Batch(gocql.LoggedBatch)

	// base profile update
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

	// optional phone rotate
	if user.PhoneKeyID != uuid.Nil && len(user.PhoneEncryptedDEK) > 0 && len(user.PhoneEncrypted) > 0 {
		batch.Query(`
            UPDATE users SET
                phone_encrypted     = ?,
                phone_key_id        = ?,
                phone_encrypted_dek = ?
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

// UpdateUserProfile updates profile_service_id for a user
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

// UpdateUserStatus updates verification / block / banned flags
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()

	r.stmtMutex.RLock()
	query := r.stmtUpdateUserStatus.Bind(isVerified, isBlocked, isBanned, now, bucket, gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateLastLogin updates last_login timestamp
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
	bucket := r.bucketingManager.GetUserBucket(userID)

	r.stmtMutex.RLock()
	query := r.stmtUpdateLastLogin.Bind(timestamp, bucket, gocql.UUID(userID))
	r.stmtMutex.RUnlock()

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UpdateUserCompany sets only company_id
// func (r *UserRepositoryImpl) UpdateUserCompany(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) error {
// 	bucket := r.bucketingManager.GetUserBucket(userID)
// 	now := time.Now().UTC()

// 	query := r.client.Session.Query(`
//         UPDATE users SET company_id = ?, updated_at = ?
//         WHERE user_bucket = ? AND user_id = ?`,
// 		gocql.UUID(companyID),
// 		now,
// 		bucket,
// 		gocql.UUID(userID),
// 	)

// 	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
// 		return fmt.Errorf("failed to update user company: %w", err)
// 	}

// 	r.logger.Info("User company updated successfully",
// 		util.String("user_id", userID.String()),
// 		util.String("company_id", companyID.String()))
// 	return nil
// }
// ✅ FIXED: Update only company ID, not role level
func (r *UserRepositoryImpl) UpdateUserCompany(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) error {
    bucket := r.bucketingManager.GetUserBucket(userID)
    now := time.Now().UTC()

    query := r.client.Session.Query(`
        UPDATE users SET company_id = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
        gocql.UUID(companyID),
        now,
        bucket,
        gocql.UUID(userID),
    )

    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to update user company: %w", err)
    }

    r.logger.Info("User company updated successfully",
        util.String("user_id", userID.String()),
        util.String("company_id", companyID.String()))
    return nil
}
// REMOVED: UpdateUserCompanyAndRole - role management is now in company_employees table

// REMOVED: DeactivateUser - user activation status is now managed in company_employees table

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

// CreateUsersBatch creates many users in bulk.
func (r *UserRepositoryImpl) CreateUsersBatch(ctx context.Context, users []*models.User) error {
	if len(users) == 0 {
		return nil
	}

	batch := r.client.Batch(gocql.UnloggedBatch)
	batchSize := 0

	for _, user := range users {
		userBucket := r.bucketingManager.GetUserBucket(user.UserID)
		user.UserBucket = userBucket

		// Updated: removed user_role_level and is_active from INSERT
		batch.Query(`
            INSERT INTO users (
                user_bucket, user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                device_id, device_fingerprint, kyc_status, kyc_level, kyc_verified_at,
                kyc_verified_by, profile_service_id, is_verified, is_blocked, is_banned,
                banned_by, banned_reason, banned_at, created_at, last_login, updated_at,
                consent_agreed, consent_version, data_region, company_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.UserBucket,
			gocql.UUID(user.UserID),
			user.PhoneHash,
			user.PhoneEncrypted,
			gocql.UUID(user.PhoneKeyID),
			user.PhoneEncryptedDEK,
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
			gocql.UUID(user.CompanyID),
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

// UpdateUsersBatch performs many user updates (rotation / sync)
func (r *UserRepositoryImpl) UpdateUsersBatch(ctx context.Context, users []*models.User) error {
	if len(users) == 0 {
		return nil
	}

	now := time.Now().UTC()
	batch := r.client.Batch(gocql.UnloggedBatch)
	batchSize := 0

	for _, user := range users {
		user.UpdatedAt = &now

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
			user.LastLogin,
			user.UpdatedAt,
			user.ConsentAgreed,
			user.ConsentVersion,
			user.DataRegion,
			user.UserBucket,
			gocql.UUID(user.UserID),
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

// GetUsersByIDBatch fetches multiple users in parallel using GetUserByID
func (r *UserRepositoryImpl) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}

	users := make([]*models.User, 0, len(userIDs))
	usersMu := sync.Mutex{}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrentReads)

	for _, id := range userIDs {
		id := id // shadow loop var
		g.Go(func() error {
			u, err := r.GetUserByID(gctx, id)
			if err != nil {
				r.logger.Warn("Failed to get user in batch",
					util.ErrorField(err),
					util.String("user_id", id.String()))
				return nil // continue other users
			}
			usersMu.Lock()
			users = append(users, u)
			usersMu.Unlock()
			return nil
		})
	}

	_ = g.Wait() // errors already logged
	return users, nil
}

// UpdateUserStatusBatch bulk-updates verification / blocked / banned flags
func (r *UserRepositoryImpl) UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	now := time.Now().UTC()
	batch := r.client.Batch(gocql.UnloggedBatch)
	batchSize := 0

	for _, update := range updates {
		bucket := r.bucketingManager.GetUserBucket(update.UserID)
		batch.Query(`
            UPDATE users SET 
                is_verified = ?, is_blocked = ?, is_banned = ?, updated_at = ?
            WHERE user_bucket = ? AND user_id = ?`,
			update.IsVerified,
			update.IsBlocked,
			update.IsBanned,
			now,
			bucket,
			gocql.UUID(update.UserID),
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

// ============================================================================
// QUERY HELPERS (KYC / COMPANY / BANNED / CONSENT)
// ============================================================================

// UpdateKYCStatus updates a user's KYC state
func (r *UserRepositoryImpl) UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string, verifiedBy uuid.UUID) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()

	query := r.client.Session.Query(`
        UPDATE users SET kyc_status = ?, kyc_level = ?, kyc_verified_at = ?, kyc_verified_by = ?
        WHERE user_bucket = ? AND user_id = ?`,
		status,
		level,
		now,
		gocql.UUID(verifiedBy),
		bucket,
		gocql.UUID(userID),
	)

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// GetUsersByKYCStatus pulls users from MV users_by_kyc_status, then hydrates
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
        LIMIT ?`, status, limit,
	).
		PageSize(1000).
		PageState(pageState)

	iter := q.WithContext(ctx).Iter()
	defer iter.Close()

	ids := make([]uuid.UUID, 0, limit)
	var (
		_kycStatus string
		bucket     int
		idG        gocql.UUID
	)

	for iter.Scan(&_kycStatus, &bucket, &idG) {
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

	users, err := r.GetUsersByIDBatch(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hydrate users: %w", err)
	}
	return users, next, nil
}

// GetUsersByCompany queries company_employees table to list all users in a company
func (r *UserRepositoryImpl) GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Query company_employees table to get user IDs for this company
	q := r.client.Session.Query(`
        SELECT user_id
        FROM company_employees
        WHERE company_id = ? AND is_active = ?
        LIMIT ?`,
		gocql.UUID(companyID),
		true,
		limit,
	)

	iter := q.WithContext(ctx).Iter()
	defer iter.Close()

	var (
		userIDG gocql.UUID
		userIDs []uuid.UUID
	)

	for iter.Scan(&userIDG) {
		userIDs = append(userIDs, uuid.UUID(userIDG))
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get users by company: %w", err)
	}

	return r.GetUsersByIDBatch(ctx, userIDs)
}

// REMOVED: GetUsersByRoleLevel - role queries now go through company_employees table

// UpdateUserConsent updates consent flag & version
func (r *UserRepositoryImpl) UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()
	query := r.client.Session.Query(`
        UPDATE users SET consent_agreed = ?, consent_version = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
		agreed,
		version,
		now,
		bucket,
		gocql.UUID(userID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// BanUser bans a user with a reason
func (r *UserRepositoryImpl) BanUser(ctx context.Context, userID, bannedBy uuid.UUID, reason string) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()
	query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
		true,
		gocql.UUID(bannedBy),
		reason,
		now,
		now,
		bucket,
		gocql.UUID(userID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// UnbanUser clears ban flags
func (r *UserRepositoryImpl) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	bucket := r.bucketingManager.GetUserBucket(userID)
	now := time.Now().UTC()
	query := r.client.Session.Query(`
        UPDATE users SET is_banned = ?, banned_by = ?, banned_reason = ?, banned_at = ?, updated_at = ?
        WHERE user_bucket = ? AND user_id = ?`,
		false,
		gocql.UUID(uuid.Nil),
		"",
		nil,
		now,
		bucket,
		gocql.UUID(userID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// GetBannedUsers queries MV banned_users and then hydrates full users.
func (r *UserRepositoryImpl) GetBannedUsers(ctx context.Context, limit int, pageState []byte) ([]*models.User, []byte, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	r.logger.Debug("Querying banned_users MV",
		util.Int("limit", limit),
	)

	q := r.client.Session.Query(`
        SELECT user_bucket, user_id
        FROM banned_users
        WHERE is_banned = true
        LIMIT ?`,
		limit,
	).
		PageSize(1000).
		PageState(pageState)

	iter := q.WithContext(ctx).Iter()
	defer iter.Close()

	ids := make([]uuid.UUID, 0, limit)
	var (
		bucket int
		idG    gocql.UUID
	)

	for iter.Scan(&bucket, &idG) {
		ids = append(ids, uuid.UUID(idG))
	}

	if err := iter.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate banned users MV: %w", err)
	}

	r.logger.Info("banned_users MV scan completed",
		util.Int("ids_collected", len(ids)),
	)

	next := iter.PageState()
	if len(ids) == 0 {
		return []*models.User{}, next, nil
	}

	users, err := r.GetUsersByIDBatch(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hydrate banned users: %w", err)
	}
	return users, next, nil
}

// ============================================================================
// LOW-LEVEL / UTIL / HEALTH
// ============================================================================

// Helper to extract IDs from []*models.User
func extractIDs(users []*models.User) []uuid.UUID {
	ids := make([]uuid.UUID, len(users))
	for i, u := range users {
		ids[i] = u.UserID
	}
	return ids
}

// HealthCheck runs a trivial system.local read
func (r *UserRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM system.local`).WithContext(ctx).Scan(&count); err != nil {
		return fmt.Errorf("user repository health check failed: %w", err)
	}
	return nil
}

// GetRepositoryStats returns diagnostic info for observability / metrics
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

// // In scylla/user_repository.go - Add to UserRepositoryImpl
// func (r *UserRepositoryImpl) UpdateUserCompanyAndRole(ctx context.Context, userID uuid.UUID, companyID uuid.UUID, roleLevel string) error {
// 	bucket := r.bucketingManager.GetUserBucket(userID)
// 	now := time.Now().UTC()

// 	query := r.client.Session.Query(`
// 		UPDATE users SET company_id = ?, user_role_level = ?, updated_at = ?
// 		WHERE user_bucket = ? AND user_id = ?`,
// 		gocql.UUID(companyID),
// 		roleLevel,
// 		now,
// 		bucket,
// 		gocql.UUID(userID),
// 	)

// 	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
// 		return fmt.Errorf("failed to update user company and role: %w", err)
// 	}

// 	r.logger.Info("User company and role updated successfully",
// 		util.String("user_id", userID.String()),
// 		util.String("company_id", companyID.String()),
// 		util.String("role_level", roleLevel))
// 	return nil
// }