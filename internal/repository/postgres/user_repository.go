// internal/repository/postgres/user_repository.go
package postgres

import (
	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// Constants for 200M users optimization
const (
	MaxBatchSize       = 500  // Increased for PostgreSQL
	MaxConcurrentReads = 100  // Higher concurrency for PostgreSQL
	DefaultPageSize    = 1000 // For paginated queries
	StatementCacheSize = 50   // Prepared statements cache
)

// UserRepositoryImpl handles PostgreSQL user operations
type UserRepositoryImpl struct {
	client *client.PostgresClient
	logger *zap.Logger

	// Prepared statements cache
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex

	// Connection pool metrics
	metrics struct {
		queryCount int64
		batchCount int64
		errorCount int64
		lastReset  time.Time
		sync.RWMutex
	}
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(postgresClient *client.PostgresClient, logger *zap.Logger) UserRepository {
	repo := &UserRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt, StatementCacheSize),
	}

	repo.metrics.lastReset = time.Now()

	// Initialize prepared statements in background
	go repo.initializePreparedStatements(context.Background())

	return repo
}

// ============================================================================
// MISSING METHOD IMPLEMENTATION
// ============================================================================

// GetUserByIDWithPartition retrieves a user by ID with explicit partition hint
// This is useful for cases where you want to explicitly control partition access
func (r *UserRepositoryImpl) GetUserByIDWithPartition(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	// In PostgreSQL with hash partitioning, we can use the modulus to determine the partition
	// This is mostly for compatibility - PostgreSQL automatically routes to the correct partition
	hash := util.HashUUID(userID)
	partition := hash % 8 // Since we have 8 partitions

	r.logger.Debug("Using explicit partition access",
		util.String("user_id", userID.String()),
		util.Int("partition", partition))

	// For PostgreSQL, we can use the same query as GetUserByID since partitioning is automatic
	return r.GetUserByID(ctx, userID)
}

// ============================================================================
// EXISTING METHODS (from previous implementation)
// ============================================================================

// initializePreparedStatements initializes frequently used prepared statements
func (r *UserRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_user_by_id": `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE user_id = $1`,

		"get_user_by_phone_hash": `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE phone_hash = $1`,

		"update_user_status": `
			UPDATE users SET is_verified = $1, is_active = $2, updated_at = $3 
			WHERE user_id = $4`,

		"update_last_login": `
			UPDATE users SET last_login = $1, updated_at = $2 
			WHERE user_id = $3`,

		"get_user_by_device_fingerprint": `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE device_fingerprint = $1`,

		"get_recent_login_attempts": `
			SELECT attempt_id, user_id, success, ip_address, user_agent, attempted_at
			FROM login_attempts 
			WHERE user_id = $1 
			ORDER BY attempted_at DESC 
			LIMIT $2`,

		"add_user_device": `
			INSERT INTO user_devices (
				device_id, user_id, device_type, device_name, os_version, 
				app_version, last_active, is_active, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,

		"get_user_devices": `
			SELECT device_id, user_id, device_type, device_name, os_version, 
				app_version, last_active, is_active, created_at, updated_at
			FROM user_devices 
			WHERE user_id = $1 
			ORDER BY last_active DESC`,

		"update_kyc_status": `
			UPDATE users SET kyc_status = $1, kyc_level = $2, kyc_verified_at = $3, 
				   updated_at = $4, is_verified = $5 
			WHERE user_id = $6`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

// getStmt retrieves a prepared statement from cache
func (r *UserRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()

	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

func (r *UserRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	startTime := time.Now()

	query := `
		INSERT INTO users (
			user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			is_verified, is_active, data_region, created_at, updated_at, last_login
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err := r.client.Exec(ctx, query,
		user.UserID, user.PhoneHash, user.PhoneEncrypted, user.PhoneKeyID, user.PhoneEncryptedDEK,
		user.DeviceID, user.DeviceFingerprint, user.KYCStatus, user.KYCLevel,
		user.KYCVerifiedAt, user.IsVerified, user.IsActive, user.DataRegion,
		user.CreatedAt, user.UpdatedAt, user.LastLogin,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.recordQuery()

	r.logger.Debug("User created successfully",
		util.String("user_id", user.UserID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// GetUserByID retrieves a user by ID (automatically routes to correct partition)
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return r.getUserByIDInternal(ctx, userID, "get_user_by_id")
}

func (r *UserRepositoryImpl) getUserByIDInternal(ctx context.Context, userID uuid.UUID, stmtName string) (*models.User, error) {
	var user models.User
	var kycVerifiedAt, lastLogin sql.NullTime

	// Try to use prepared statement first
	if stmt, exists := r.getStmt(stmtName); exists {
		err := stmt.QueryRowContext(ctx, userID).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found: %s", userID)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	} else {
		// Fallback to direct query
		query := `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE user_id = $1`

		err := r.client.QueryRow(ctx, query, userID).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found: %s", userID)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	}

	// Handle nullable timestamps
	if kycVerifiedAt.Valid {
		user.KYCVerifiedAt = &kycVerifiedAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	r.recordQuery()
	return &user, nil
}

// GetUserByPhoneHash retrieves a user by phone hash using the index
func (r *UserRepositoryImpl) GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error) {
	var user models.User
	var kycVerifiedAt, lastLogin sql.NullTime

	// Try to use prepared statement first
	if stmt, exists := r.getStmt("get_user_by_phone_hash"); exists {
		err := stmt.QueryRowContext(ctx, phoneHash).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found for phone hash: %s", phoneHash)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user by phone hash: %w", err)
		}
	} else {
		// Fallback to direct query
		query := `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE phone_hash = $1`

		err := r.client.QueryRow(ctx, query, phoneHash).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found for phone hash: %s", phoneHash)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user by phone hash: %w", err)
		}
	}

	// Handle nullable timestamps
	if kycVerifiedAt.Valid {
		user.KYCVerifiedAt = &kycVerifiedAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	r.recordQuery()
	return &user, nil
}

// UpdateUser updates mutable user fields
func (r *UserRepositoryImpl) UpdateUser(ctx context.Context, user *models.User) error {
	now := time.Now().UTC()
	user.UpdatedAt = now

	query := `
		UPDATE users SET 
			device_id = $1, device_fingerprint = $2, data_region = $3,
			updated_at = $4, last_login = $5
		WHERE user_id = $6`

	result, err := r.client.Exec(ctx, query,
		user.DeviceID, user.DeviceFingerprint, user.DataRegion,
		user.UpdatedAt, user.LastLogin, user.UserID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", user.UserID)
	}

	r.recordQuery()
	return nil
}

// UpdateUserStatus updates verification and active status
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error {
	now := time.Now().UTC()

	// Try to use prepared statement first
	if stmt, exists := r.getStmt("update_user_status"); exists {
		result, err := stmt.ExecContext(ctx, isVerified, isActive, now, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update user status: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	} else {
		// Fallback to direct query
		query := `UPDATE users SET is_verified = $1, is_active = $2, updated_at = $3 WHERE user_id = $4`
		result, err := r.client.Exec(ctx, query, isVerified, isActive, now, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update user status: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	}

	r.recordQuery()
	return nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
	now := time.Now().UTC()

	// Try to use prepared statement first
	if stmt, exists := r.getStmt("update_last_login"); exists {
		result, err := stmt.ExecContext(ctx, timestamp, now, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update last login: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	} else {
		// Fallback to direct query
		query := `UPDATE users SET last_login = $1, updated_at = $2 WHERE user_id = $3`
		result, err := r.client.Exec(ctx, query, timestamp, now, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update last login: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	}

	r.recordQuery()
	return nil
}

func (r *UserRepositoryImpl) CreateUsersBatch(ctx context.Context, users []*models.User) error {
	if len(users) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO users (
			user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			is_verified, is_active, data_region, created_at, updated_at, last_login
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, user := range users {
		_, err := stmt.ExecContext(ctx,
			user.UserID, user.PhoneHash, user.PhoneEncrypted, user.PhoneKeyID, user.PhoneEncryptedDEK,
			user.DeviceID, user.DeviceFingerprint, user.KYCStatus, user.KYCLevel,
			user.KYCVerifiedAt, user.IsVerified, user.IsActive, user.DataRegion,
			user.CreatedAt, user.UpdatedAt, user.LastLogin,
		)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.UserID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.recordBatch(int64(len(users)))
	r.logger.Info("Batch user creation completed",
		util.Int("users_created", len(users)))
	return nil
}

// GetUsersByIDBatch retrieves multiple users by their IDs
func (r *UserRepositoryImpl) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}

	// Convert UUIDs to strings for the query
	idStrings := make([]string, len(userIDs))
	for i, id := range userIDs {
		idStrings[i] = id.String()
	}

	query := `
		SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			   is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE user_id = ANY($1)`

	rows, err := r.client.Query(ctx, query, pq.Array(idStrings))
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query users batch: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, len(userIDs))
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, nil
}

// UpdateUserStatusBatch updates status for multiple users
func (r *UserRepositoryImpl) UpdateUserStatusBatch(ctx context.Context, updates []models.UserStatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `UPDATE users SET is_verified = $1, is_active = $2, updated_at = $3 WHERE user_id = $4`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch update statement: %w", err)
	}
	defer stmt.Close()

	for _, update := range updates {
		_, err := stmt.ExecContext(ctx, update.IsVerified, update.IsActive, update.UpdatedAt, update.UserID)
		if err != nil {
			return fmt.Errorf("failed to update user %s: %w", update.UserID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch update transaction: %w", err)
	}

	r.recordBatch(int64(len(updates)))
	return nil
}

// UpdateKYCStatus updates a user's KYC information
func (r *UserRepositoryImpl) UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string) error {
	now := time.Now().UTC()
	isVerified := status == models.KYCStatusVerified

	// Try to use prepared statement first
	if stmt, exists := r.getStmt("update_kyc_status"); exists {
		result, err := stmt.ExecContext(ctx, status, level, now, now, isVerified, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update KYC status: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	} else {
		// Fallback to direct query
		query := `
			UPDATE users SET 
				kyc_status = $1, kyc_level = $2, kyc_verified_at = $3, 
				updated_at = $4, is_verified = $5 
			WHERE user_id = $6`

		result, err := r.client.Exec(ctx, query, status, level, now, now, isVerified, userID)
		if err != nil {
			r.recordError()
			return fmt.Errorf("failed to update KYC status: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("user not found: %s", userID)
		}
	}

	r.recordQuery()
	return nil
}

// GetUsersByKYCStatus retrieves users by KYC status with pagination
func (r *UserRepositoryImpl) GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count for pagination info
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE kyc_status = $1`
	err := r.client.QueryRow(ctx, countQuery, status).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count users by KYC status: %w", err)
	}

	// Get paginated results
	query := `
		SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			   is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE kyc_status = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, status, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query users by KYC status: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// GetUsersByCompany retrieves users belonging to a company
func (r *UserRepositoryImpl) GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `
		SELECT COUNT(*) 
		FROM company_employees ce 
		WHERE ce.company_id = $1 AND ce.is_active = true`

	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count company users: %w", err)
	}

	// Get paginated results with join
	query := `
		SELECT u.user_id, u.phone_hash, u.phone_encrypted, u.phone_key_id, u.phone_encrypted_dek, u.device_id, 
			   u.device_fingerprint, u.kyc_status, u.kyc_level, u.kyc_verified_at, 
			   u.is_verified, u.is_active, u.data_region, u.created_at, u.updated_at, u.last_login
		FROM users u
		INNER JOIN company_employees ce ON u.user_id = ce.user_id
		WHERE ce.company_id = $1 AND ce.is_active = true
		ORDER BY ce.hire_date DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query company users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// GetUsersByRegion retrieves users by data region with pagination
func (r *UserRepositoryImpl) GetUsersByRegion(ctx context.Context, region string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE data_region = $1`
	err := r.client.QueryRow(ctx, countQuery, region).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count users by region: %w", err)
	}

	// Get paginated results
	query := `
		SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			   is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE data_region = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, region, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query users by region: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan region user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating region user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// GetUsersByCreationDateRange retrieves users created within a date range
func (r *UserRepositoryImpl) GetUsersByCreationDateRange(ctx context.Context, start, end time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}

	query := `
		SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			   is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users 
		WHERE created_at BETWEEN $1 AND $2 
		ORDER BY created_at DESC 
		LIMIT $3`

	rows, err := r.client.Query(ctx, query, start, end, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query users by creation date: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan date range user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating date range user rows: %w", err)
	}

	r.recordQuery()
	return users, nil
}

// GetUsersCreatedAfter retrieves users created after a specific date with pagination
func (r *UserRepositoryImpl) GetUsersCreatedAfter(ctx context.Context, after time.Time, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE created_at > $1`
	err := r.client.QueryRow(ctx, countQuery, after).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count users created after date: %w", err)
	}

	// Get paginated results
	query := `
		SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
			   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
			   is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE created_at > $1 
		ORDER BY created_at ASC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, after, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query users created after date: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		// Handle nullable timestamps
		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// HealthCheck verifies database connectivity
func (r *UserRepositoryImpl) HealthCheck(ctx context.Context) error {
	var result int
	err := r.client.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		r.recordError()
		return fmt.Errorf("postgreSQL health check failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("postgreSQL health check returned unexpected result: %d", result)
	}

	return nil
}

// GetRepositoryStats returns performance and usage statistics
func (r *UserRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get database connection stats
	dbStats := r.client.GetStats()
	stats["db_connections"] = map[string]interface{}{
		"open_connections": dbStats.OpenConnections,
		"in_use":           dbStats.InUse,
		"idle":             dbStats.Idle,
		"wait_count":       dbStats.WaitCount,
		"wait_duration":    dbStats.WaitDuration.String(),
	}

	// Get repository metrics
	r.metrics.RLock()
	stats["repository_metrics"] = map[string]interface{}{
		"query_count": r.metrics.queryCount,
		"batch_count": r.metrics.batchCount,
		"error_count": r.metrics.errorCount,
		"uptime":      time.Since(r.metrics.lastReset).String(),
	}
	r.metrics.RUnlock()

	// Get prepared statements count
	r.stmtMutex.RLock()
	stats["prepared_statements"] = len(r.stmtCache)
	r.stmtMutex.RUnlock()

	// Get user table statistics
	var userCount int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount)
	if err == nil {
		stats["user_count"] = userCount
	}

	return stats, nil
}

// Close cleans up prepared statements
func (r *UserRepositoryImpl) Close() error {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	var lastErr error
	for name, stmt := range r.stmtCache {
		if err := stmt.Close(); err != nil {
			r.logger.Warn("Failed to close prepared statement",
				util.String("statement", name),
				util.ErrorField(err))
			lastErr = err
		}
	}

	r.stmtCache = make(map[string]*sql.Stmt)
	return lastErr
}

// ============================================================================
// PRIVATE HELPER METHODS
// ============================================================================

func (r *UserRepositoryImpl) recordQuery() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.queryCount++
}

func (r *UserRepositoryImpl) recordBatch(count int64) {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.batchCount += count
}

func (r *UserRepositoryImpl) recordError() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.errorCount++
}

// ============================================================================
// NEW REPOSITORY METHODS TO IMPLEMENT THE INTERFACE
// ============================================================================

// DeleteUser performs a hard delete of a user (use with caution)
func (r *UserRepositoryImpl) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM users WHERE user_id = $1`

	result, err := r.client.Exec(ctx, query, userID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	r.recordQuery()
	r.logger.Info("User hard deleted", util.String("user_id", userID.String()))
	return nil
}

// SoftDeleteUser marks a user as inactive (soft delete)
func (r *UserRepositoryImpl) SoftDeleteUser(ctx context.Context, userID uuid.UUID) error {
	return r.UpdateUserStatus(ctx, userID, false, false)
}

// ReactivateUser reactivates a soft-deleted user
func (r *UserRepositoryImpl) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	return r.UpdateUserStatus(ctx, userID, true, true)
}

// ArchiveInactiveUsers archives users inactive since before the given date
func (r *UserRepositoryImpl) ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error) {
	query := `
        UPDATE users 
        SET is_active = false, updated_at = $1 
        WHERE last_login < $2 AND is_active = true`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), before)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to archive inactive users: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.recordQuery()

	r.logger.Info("Inactive users archived",
		util.Int64("users_archived", rowsAffected),
		util.Time("inactive_since", before))

	return int(rowsAffected), nil
}

// UpdateUserFields performs a partial update of user fields
func (r *UserRepositoryImpl) UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return fmt.Errorf("no fields to update")
	}

	setClauses := []string{}
	params := []interface{}{}
	paramCount := 1

	// Add updated_at automatically
	fields["updated_at"] = time.Now().UTC()

	for field, value := range fields {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, paramCount))
		params = append(params, value)
		paramCount++
	}

	params = append(params, userID)
	query := fmt.Sprintf("UPDATE users SET %s WHERE user_id = $%d",
		strings.Join(setClauses, ", "), paramCount)

	result, err := r.client.Exec(ctx, query, params...)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update user fields: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	r.recordQuery()
	return nil
}

// GetRecentlyActiveUsers retrieves users active since the given time
func (r *UserRepositoryImpl) GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}

	query := `
        SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
               device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
               is_verified, is_active, data_region, created_at, updated_at, last_login
        FROM users 
        WHERE last_login >= $1 AND is_active = true
        ORDER BY last_login DESC 
        LIMIT $2`

	rows, err := r.client.Query(ctx, query, since, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query recently active users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, nil
}

// GetInactiveUsersSince retrieves users inactive since the given time
func (r *UserRepositoryImpl) GetInactiveUsersSince(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}

	query := `
        SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
               device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
               is_verified, is_active, data_region, created_at, updated_at, last_login
        FROM users 
        WHERE (last_login < $1 OR last_login IS NULL) AND is_active = true
        ORDER BY created_at ASC 
        LIMIT $2`

	rows, err := r.client.Query(ctx, query, since, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query inactive users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, nil
}

// SearchUsersByPhoneOrDevice searches users by phone hash or device ID
func (r *UserRepositoryImpl) SearchUsersByPhoneOrDevice(ctx context.Context, query string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	searchPattern := "%" + strings.ToLower(query) + "%"

	// Get total count
	var totalCount int
	countQuery := `
        SELECT COUNT(*) 
        FROM users 
        WHERE LOWER(phone_hash) LIKE $1 OR LOWER(device_id) LIKE $1 OR LOWER(device_fingerprint) LIKE $1`

	err := r.client.QueryRow(ctx, countQuery, searchPattern).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results
	searchQuery := `
        SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
               device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
               is_verified, is_active, data_region, created_at, updated_at, last_login
        FROM users 
        WHERE LOWER(phone_hash) LIKE $1 OR LOWER(device_id) LIKE $1 OR LOWER(device_fingerprint) LIKE $1
        ORDER BY created_at DESC 
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// SearchUsers performs advanced user search with multiple filters
func (r *UserRepositoryImpl) SearchUsers(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	whereClauses := []string{}
	params := []interface{}{}
	paramCount := 1

	// Build WHERE clause dynamically
	for field, value := range filters {
		switch field {
		case "phone_hash":
			whereClauses = append(whereClauses, fmt.Sprintf("phone_hash = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "device_id":
			whereClauses = append(whereClauses, fmt.Sprintf("device_id = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "kyc_status":
			whereClauses = append(whereClauses, fmt.Sprintf("kyc_status = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "data_region":
			whereClauses = append(whereClauses, fmt.Sprintf("data_region = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "is_verified":
			whereClauses = append(whereClauses, fmt.Sprintf("is_verified = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "is_active":
			whereClauses = append(whereClauses, fmt.Sprintf("is_active = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "created_after":
			whereClauses = append(whereClauses, fmt.Sprintf("created_at >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "created_before":
			whereClauses = append(whereClauses, fmt.Sprintf("created_at <= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "last_login_after":
			whereClauses = append(whereClauses, fmt.Sprintf("last_login >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		}
	}

	// Build base queries
	baseWhere := ""
	if len(whereClauses) > 0 {
		baseWhere = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", baseWhere)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count filtered users: %w", err)
	}

	// Get paginated results
	searchQuery := fmt.Sprintf(`
        SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
               device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
               is_verified, is_active, data_region, created_at, updated_at, last_login
        FROM users %s
        ORDER BY created_at DESC 
        LIMIT $%d OFFSET $%d`, baseWhere, paramCount, paramCount+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		var user models.User
		var kycVerifiedAt, lastLogin sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)
		if err != nil {
			r.logger.Warn("Failed to scan user row", util.ErrorField(err))
			continue
		}

		if kycVerifiedAt.Valid {
			user.KYCVerifiedAt = &kycVerifiedAt.Time
		}
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.recordQuery()
	return users, totalCount, nil
}

// GetUserByDeviceFingerprint retrieves a user by device fingerprint
func (r *UserRepositoryImpl) GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error) {
	var user models.User
	var kycVerifiedAt, lastLogin sql.NullTime

	// Try to use prepared statement first
	if stmt, exists := r.getStmt("get_user_by_device_fingerprint"); exists {
		err := stmt.QueryRowContext(ctx, fingerprint).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found for device fingerprint: %s", fingerprint)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user by device fingerprint: %w", err)
		}
	} else {
		// Fallback to direct query
		query := `
			SELECT user_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, device_id, 
				   device_fingerprint, kyc_status, kyc_level, kyc_verified_at, 
				   is_verified, is_active, data_region, created_at, updated_at, last_login
			FROM users WHERE device_fingerprint = $1`

		err := r.client.QueryRow(ctx, query, fingerprint).Scan(
			&user.UserID, &user.PhoneHash, &user.PhoneEncrypted, &user.PhoneKeyID, &user.PhoneEncryptedDEK,
			&user.DeviceID, &user.DeviceFingerprint, &user.KYCStatus, &user.KYCLevel,
			&kycVerifiedAt, &user.IsVerified, &user.IsActive, &user.DataRegion,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("user not found for device fingerprint: %s", fingerprint)
			}
			r.recordError()
			return nil, fmt.Errorf("failed to get user by device fingerprint: %w", err)
		}
	}

	if kycVerifiedAt.Valid {
		user.KYCVerifiedAt = &kycVerifiedAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	r.recordQuery()
	return &user, nil
}

// AddUserDevice adds a new user device
func (r *UserRepositoryImpl) AddUserDevice(ctx context.Context, device *models.UserDevice) error {
	query := `
        INSERT INTO user_devices (
            device_id, user_id, device_type, device_name, os_version, 
            app_version, last_active, is_active, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.client.Exec(ctx, query,
		device.DeviceID, device.UserID, device.DeviceType, device.DeviceName,
		device.OSVersion, device.AppVersion, device.LastActive, device.IsActive,
		device.CreatedAt, device.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to add user device: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetUserDevices retrieves all devices for a user
func (r *UserRepositoryImpl) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error) {
	query := `
        SELECT device_id, user_id, device_type, device_name, os_version, 
               app_version, last_active, is_active, created_at, updated_at
        FROM user_devices 
        WHERE user_id = $1 
        ORDER BY last_active DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query user devices: %w", err)
	}
	defer rows.Close()

	devices := make([]models.UserDevice, 0)
	for rows.Next() {
		var device models.UserDevice
		err := rows.Scan(
			&device.DeviceID, &device.UserID, &device.DeviceType, &device.DeviceName,
			&device.OSVersion, &device.AppVersion, &device.LastActive, &device.IsActive,
			&device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan device row", util.ErrorField(err))
			continue
		}
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating device rows: %w", err)
	}

	r.recordQuery()
	return devices, nil
}

// RemoveUserDevice removes a user device
func (r *UserRepositoryImpl) RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	query := `DELETE FROM user_devices WHERE user_id = $1 AND device_id = $2`

	result, err := r.client.Exec(ctx, query, userID, deviceID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to remove user device: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("device not found for user")
	}

	r.recordQuery()
	return nil
}

// RecordLoginAttempt records a user login attempt
func (r *UserRepositoryImpl) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error {
	query := `
        INSERT INTO login_attempts (
            attempt_id, user_id, success, ip_address, user_agent, attempted_at
        ) VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.client.Exec(ctx, query,
		uuid.New(), userID, success, ip, userAgent, time.Now().UTC(),
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetRecentLoginAttempts retrieves recent login attempts for a user
func (r *UserRepositoryImpl) GetRecentLoginAttempts(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginAttempt, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `
        SELECT attempt_id, user_id, success, ip_address, user_agent, attempted_at
        FROM login_attempts 
        WHERE user_id = $1 
        ORDER BY attempted_at DESC 
        LIMIT $2`

	rows, err := r.client.Query(ctx, query, userID, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query login attempts: %w", err)
	}
	defer rows.Close()

	attempts := make([]models.LoginAttempt, 0, limit)
	for rows.Next() {
		var attempt models.LoginAttempt
		err := rows.Scan(
			&attempt.AttemptID, &attempt.UserID, &attempt.Success,
			&attempt.IPAddress, &attempt.UserAgent, &attempt.AttemptedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan login attempt row", util.ErrorField(err))
			continue
		}
		attempts = append(attempts, attempt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating login attempt rows: %w", err)
	}

	r.recordQuery()
	return attempts, nil
}

// CountUsersByRegion counts users by data region
func (r *UserRepositoryImpl) CountUsersByRegion(ctx context.Context) (map[string]int, error) {
	query := `SELECT data_region, COUNT(*) FROM users GROUP BY data_region`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to count users by region: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var region string
		var count int
		err := rows.Scan(&region, &count)
		if err != nil {
			r.logger.Warn("Failed to scan region count row", util.ErrorField(err))
			continue
		}
		counts[region] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating region count rows: %w", err)
	}

	r.recordQuery()
	return counts, nil
}

// CountUsersByKYCStatus counts users by KYC status
func (r *UserRepositoryImpl) CountUsersByKYCStatus(ctx context.Context) (map[string]int, error) {
	query := `SELECT kyc_status, COUNT(*) FROM users GROUP BY kyc_status`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to count users by KYC status: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		err := rows.Scan(&status, &count)
		if err != nil {
			r.logger.Warn("Failed to scan KYC status count row", util.ErrorField(err))
			continue
		}
		counts[status] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating KYC status count rows: %w", err)
	}

	r.recordQuery()
	return counts, nil
}

// CountActiveUsers counts all active users
func (r *UserRepositoryImpl) CountActiveUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE is_active = true`

	var count int
	err := r.client.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to count active users: %w", err)
	}

	r.recordQuery()
	return count, nil
}

// CountNewUsersSince counts new users since the given date
func (r *UserRepositoryImpl) CountNewUsersSince(ctx context.Context, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE created_at >= $1`

	var count int
	err := r.client.QueryRow(ctx, query, since).Scan(&count)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to count new users: %w", err)
	}

	r.recordQuery()
	return count, nil
}

// GetUserActivityStats gets user activity statistics
func (r *UserRepositoryImpl) GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count users with recent activity
	var activeCount int
	activeQuery := `SELECT COUNT(*) FROM users WHERE last_login >= $1 AND is_active = true`
	err := r.client.QueryRow(ctx, activeQuery, since).Scan(&activeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user count: %w", err)
	}
	stats["recently_active_users"] = activeCount

	// Count new registrations
	var newRegistrations int
	newQuery := `SELECT COUNT(*) FROM users WHERE created_at >= $1`
	err = r.client.QueryRow(ctx, newQuery, since).Scan(&newRegistrations)
	if err != nil {
		return nil, fmt.Errorf("failed to get new registrations: %w", err)
	}
	stats["new_registrations"] = newRegistrations

	// Average time between registration and first login
	var avgTime sql.NullFloat64
	avgQuery := `
        SELECT AVG(EXTRACT(EPOCH FROM (last_login - created_at))) 
        FROM users 
        WHERE last_login IS NOT NULL AND created_at >= $1`

	err = r.client.QueryRow(ctx, avgQuery, since).Scan(&avgTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get average time to first login: %w", err)
	}

	if avgTime.Valid {
		stats["avg_seconds_to_first_login"] = avgTime.Float64
	} else {
		stats["avg_seconds_to_first_login"] = 0
	}

	r.recordQuery()
	return stats, nil
}

// GetKYCDistribution gets KYC status distribution
func (r *UserRepositoryImpl) GetKYCDistribution(ctx context.Context) (map[string]int, error) {
	return r.CountUsersByKYCStatus(ctx)
}

// GetActiveUserCountsByRegion gets active user counts by region
func (r *UserRepositoryImpl) GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error) {
	query := `SELECT data_region, COUNT(*) FROM users WHERE is_active = true GROUP BY data_region`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to count active users by region: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var region string
		var count int
		err := rows.Scan(&region, &count)
		if err != nil {
			r.logger.Warn("Failed to scan active region count row", util.ErrorField(err))
			continue
		}
		counts[region] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating active region count rows: %w", err)
	}

	r.recordQuery()
	return counts, nil
}

// GetUserGrowthMetrics gets user growth metrics
func (r *UserRepositoryImpl) GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// Total users
	var totalUsers int
	totalQuery := `SELECT COUNT(*) FROM users`
	err := r.client.QueryRow(ctx, totalQuery).Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get total users: %w", err)
	}
	metrics["total_users"] = totalUsers

	// Active users
	activeUsers, err := r.CountActiveUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active users: %w", err)
	}
	metrics["active_users"] = activeUsers

	// New users since date
	newUsers, err := r.CountNewUsersSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get new users: %w", err)
	}
	metrics["new_users"] = newUsers

	// Verified users
	var verifiedUsers int
	verifiedQuery := `SELECT COUNT(*) FROM users WHERE is_verified = true`
	err = r.client.QueryRow(ctx, verifiedQuery).Scan(&verifiedUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified users: %w", err)
	}
	metrics["verified_users"] = verifiedUsers

	// KYC distribution
	kycDistribution, err := r.GetKYCDistribution(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC distribution: %w", err)
	}
	metrics["kyc_distribution"] = kycDistribution

	// Region distribution
	regionDistribution, err := r.GetActiveUserCountsByRegion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get region distribution: %w", err)
	}
	metrics["region_distribution"] = regionDistribution

	// Growth rate (new users per day)
	days := time.Since(since).Hours() / 24
	if days > 0 {
		growthRate := float64(newUsers) / days
		metrics["growth_rate"] = growthRate
	} else {
		metrics["growth_rate"] = 0
	}

	r.recordQuery()
	return metrics, nil
}

// RebuildUserIndexes rebuilds user table indexes
func (r *UserRepositoryImpl) RebuildUserIndexes(ctx context.Context) error {
	indexes := []string{
		"users_pkey",
		"users_phone_hash_idx",
		"users_device_id_idx",
		"users_kyc_status_idx",
		"users_data_region_idx",
		"users_created_at_idx",
		"users_last_login_idx",
	}

	for _, index := range indexes {
		query := fmt.Sprintf("REINDEX INDEX CONCURRENTLY %s", index)
		_, err := r.client.Exec(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to rebuild index",
				util.String("index", index),
				util.ErrorField(err))
			// Continue with other indexes
		}
	}

	r.logger.Info("User indexes rebuild completed")
	return nil
}

// VacuumUserTable performs VACUUM on user table
func (r *UserRepositoryImpl) VacuumUserTable(ctx context.Context) error {
	// VACUUM cannot be run in a transaction
	query := "VACUUM (VERBOSE, ANALYZE) users"

	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to vacuum user table: %w", err)
	}

	r.logger.Info("User table vacuum completed")
	return nil
}
