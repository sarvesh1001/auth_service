package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	MaxBatchSize    = 500
	DefaultPageSize = 1000
)

// UserRepositoryImpl implements the UserRepository interface.
type UserRepositoryImpl struct {
	client *client.PostgresClient
}

// NewUserRepository creates a new user repository.
func NewUserRepository(postgresClient *client.PostgresClient) *UserRepositoryImpl {
	return &UserRepositoryImpl{
		client: postgresClient,
	}
}

// Close implements the UserRepository interface.
// No-op – no resources to clean up.
func (r *UserRepositoryImpl) Close() error {
	return nil
}

// -----------------------------------------------------------------------------
// Search methods
// -----------------------------------------------------------------------------

// SearchUsers performs a full‑text search on users.
func (r *UserRepositoryImpl) SearchUsers(ctx context.Context, req *models.UserSearchRequest) ([]*models.UserSearchResult, int, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	query := `
		SELECT
			user_id, username, full_name, phone_hash,
			kyc_status, kyc_level, is_verified, is_active,
			data_region, created_at, last_login,
			relevance_score, match_type
		FROM user_search($1, $2, $3, $4, $5, $6, $7, $8)`

	var isActive, isVerified interface{}
	var kycStatus, dataRegion interface{}
	if req.Filters != nil {
		if req.Filters.IsActive != nil {
			isActive = *req.Filters.IsActive
		}
		if req.Filters.IsVerified != nil {
			isVerified = *req.Filters.IsVerified
		}
		if req.Filters.KYCStatus != "" {
			kycStatus = req.Filters.KYCStatus
		}
		if req.Filters.DataRegion != "" {
			dataRegion = req.Filters.DataRegion
		}
	}

	args := []interface{}{
		req.Query,
		req.SearchType,
		isActive,
		kycStatus,
		dataRegion,
		isVerified,
		req.Limit,
		req.Offset,
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	results := make([]*models.UserSearchResult, 0, req.Limit)
	for rows.Next() {
		var result models.UserSearchResult
		var lastLogin sql.NullTime
		err := rows.Scan(
			&result.UserID,
			&result.Username,
			&result.FullName,
			&result.PhoneHash,
			&result.KYCStatus,
			&result.KYCLevel,
			&result.IsVerified,
			&result.IsActive,
			&result.DataRegion,
			&result.CreatedAt,
			&lastLogin,
			&result.RelevanceScore,
			&result.MatchType,
		)
		if err != nil {
			continue
		}
		if lastLogin.Valid {
			result.LastLogin = &lastLogin.Time
		}
		results = append(results, &result)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	totalCount, err := r.countSearchResults(ctx, req.Query, req.Filters)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}
	return results, totalCount, nil
}

func (r *UserRepositoryImpl) countSearchResults(ctx context.Context, query string, filters *models.UserSearchFilters) (int, error) {
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	if len(query) >= 3 {
		conditions = append(conditions,
			fmt.Sprintf("user_search_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
		args = append(args, query)
		argCounter++
	} else {
		conditions = append(conditions,
			fmt.Sprintf("(username ILIKE $%d OR full_name ILIKE $%d)", argCounter, argCounter))
		args = append(args, "%"+query+"%")
		argCounter++
	}

	if filters != nil {
		if filters.IsActive != nil {
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", argCounter))
			args = append(args, *filters.IsActive)
			argCounter++
		}
		if filters.KYCStatus != "" {
			conditions = append(conditions, fmt.Sprintf("kyc_status = $%d", argCounter))
			args = append(args, filters.KYCStatus)
			argCounter++
		}
		if filters.DataRegion != "" {
			conditions = append(conditions, fmt.Sprintf("data_region = $%d", argCounter))
			args = append(args, filters.DataRegion)
			argCounter++
		}
		if filters.IsVerified != nil {
			conditions = append(conditions, fmt.Sprintf("is_verified = $%d", argCounter))
			args = append(args, *filters.IsVerified)
			argCounter++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return 0, fmt.Errorf("failed to count search results: %w", err)
	}
	return totalCount, nil
}

// SearchUsersByUsername searches users by username (partial match).
func (r *UserRepositoryImpl) SearchUsersByUsername(ctx context.Context, username string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users
		WHERE username ILIKE $1
		ORDER BY similarity(username, $1) DESC, username ASC
		LIMIT $2`
	rows, err := r.client.Query(ctx, query, "%"+username+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search users by username: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, limit)
}

// SearchUsersByFullName searches users by full name (partial match).
func (r *UserRepositoryImpl) SearchUsersByFullName(ctx context.Context, fullName string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users
		WHERE full_name ILIKE $1
		ORDER BY similarity(full_name, $1) DESC, full_name ASC
		LIMIT $2`
	rows, err := r.client.Query(ctx, query, "%"+fullName+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search users by full name: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, limit)
}

// GetUserSuggestions returns username suggestions.
func (r *UserRepositoryImpl) GetUserSuggestions(ctx context.Context, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	query := `SELECT username, full_name, user_id FROM get_user_suggestions($1, $2)`
	rows, err := r.client.Query(ctx, query, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get user suggestions: %w", err)
	}
	defer rows.Close()
	suggestions := make([]*models.UserSuggestion, 0, limit)
	for rows.Next() {
		var s models.UserSuggestion
		if err := rows.Scan(&s.Username, &s.FullName, &s.UserID); err != nil {
			continue
		}
		suggestions = append(suggestions, &s)
	}
	return suggestions, nil
}

// GetUserByUsername returns a user by exact username. Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users WHERE username = $1`
	rows, err := r.client.Query(ctx, query, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserRow(rows)
	}
	return nil, apperrors.ErrNotFound
}

// GetUserByUsernameExact is an alias for GetUserByUsername.
func (r *UserRepositoryImpl) GetUserByUsernameExact(ctx context.Context, username string) (*models.UserByUsername, error) {
	query := `SELECT * FROM find_user_by_username($1)`
	rows, err := r.client.Query(ctx, query, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user by username: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var user models.UserByUsername
		if err := rows.Scan(
			&user.UserID,
			&user.Username,
			&user.FullName,
			&user.PhoneHash,
			&user.IsActive,
			&user.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		return &user, nil
	}
	return nil, apperrors.ErrNotFound
}

// FindUserByUsername is an alias.
func (r *UserRepositoryImpl) FindUserByUsername(ctx context.Context, username string) (*models.UserByUsername, error) {
	return r.GetUserByUsernameExact(ctx, username)
}

// SearchUsersAdvanced performs advanced search with arbitrary filters.
func (r *UserRepositoryImpl) SearchUsersAdvanced(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{}
	params := []interface{}{}
	paramCount := 1

	for field, value := range filters {
		switch field {
		case "username":
			conditions = append(conditions, fmt.Sprintf("username ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "full_name":
			conditions = append(conditions, fmt.Sprintf("full_name ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "phone_hash":
			conditions = append(conditions, fmt.Sprintf("phone_hash = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "device_id":
			conditions = append(conditions, fmt.Sprintf("device_id = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "kyc_status":
			conditions = append(conditions, fmt.Sprintf("kyc_status = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "data_region":
			conditions = append(conditions, fmt.Sprintf("data_region = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "is_verified":
			conditions = append(conditions, fmt.Sprintf("is_verified = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "created_after":
			conditions = append(conditions, fmt.Sprintf("created_at >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "created_before":
			conditions = append(conditions, fmt.Sprintf("created_at <= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "last_login_after":
			conditions = append(conditions, fmt.Sprintf("last_login >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		}
	}

	baseWhere := ""
	if len(conditions) > 0 {
		baseWhere = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", baseWhere)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count filtered users: %w", err)
	}

	searchQuery := fmt.Sprintf(`
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, baseWhere, paramCount, paramCount+1)
	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// GetUserSearchStats returns statistics about user search.
func (r *UserRepositoryImpl) GetUserSearchStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	var totalUsers, activeUsers, verifiedUsers int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get user count: %w", err)
	}
	stats["total_users"] = totalUsers

	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&activeUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user count: %w", err)
	}
	stats["active_users"] = activeUsers

	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE is_verified = true").Scan(&verifiedUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified user count: %w", err)
	}
	stats["verified_users"] = verifiedUsers

	var avgUsernameLength, avgFullNameLength float64
	err = r.client.QueryRow(ctx, `
		SELECT
			AVG(LENGTH(username)) as avg_username_length,
			AVG(LENGTH(full_name)) as avg_fullname_length
		FROM users`).Scan(&avgUsernameLength, &avgFullNameLength)
	if err != nil {
		return nil, fmt.Errorf("failed to get average name lengths: %w", err)
	}
	stats["avg_username_length"] = avgUsernameLength
	stats["avg_fullname_length"] = avgFullNameLength

	// Index usage stats
	indexQuery := `
		SELECT
			indexname,
			idx_scan as index_scans,
			idx_tup_read as tuples_read,
			idx_tup_fetch as tuples_fetched
		FROM pg_stat_user_indexes
		WHERE tablename = 'users'
		ORDER BY idx_scan DESC`
	rows, err := r.client.Query(ctx, indexQuery)
	if err == nil {
		defer rows.Close()
		var indexStats []map[string]interface{}
		for rows.Next() {
			var index string
			var scans, read, fetched int64
			if err := rows.Scan(&index, &scans, &read, &fetched); err == nil {
				indexStats = append(indexStats, map[string]interface{}{
					"index_name":     index,
					"scans":          scans,
					"tuples_read":    read,
					"tuples_fetched": fetched,
				})
			}
		}
		stats["index_usage"] = indexStats
	}
	return stats, nil
}

// -----------------------------------------------------------------------------
// CRUD operations
// -----------------------------------------------------------------------------

// CreateUser inserts a new user. Returns apperrors.ErrDuplicate if username exists.
func (r *UserRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	// Check if username already exists
	var exists bool
	err := r.client.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check username existence: %w", err)
	}
	if exists {
		return apperrors.ErrDuplicate
	}

	query := `
		INSERT INTO users (
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`
	_, err = r.client.Exec(ctx, query,
		user.UserID, user.Username, user.FullName, user.PhoneHash, user.PhoneEncrypted, user.PhoneKeyID,
		user.PhoneEncryptedDEK, user.DeviceID, user.DeviceFingerprint, user.KYCStatus, user.KYCLevel,
		user.KYCVerifiedAt, user.IsVerified, user.IsActive, user.DataRegion,
		user.CreatedAt, user.UpdatedAt, user.LastLogin,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUserByID returns a user by ID. Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE user_id = $1`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserRow(rows)
	}
	return nil, apperrors.ErrNotFound
}

// GetUserByPhoneHash returns a user by phone hash. Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error) {
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE phone_hash = $1`
	rows, err := r.client.Query(ctx, query, phoneHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by phone hash: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserRow(rows)
	}
	return nil, apperrors.ErrNotFound
}

// UpdateUser updates a user. Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE users SET
			username = $1, full_name = $2, device_id = $3, device_fingerprint = $4,
			data_region = $5, updated_at = $6, last_login = $7
		WHERE user_id = $8`
	result, err := r.client.Exec(ctx, query,
		user.Username, user.FullName, user.DeviceID, user.DeviceFingerprint,
		user.DataRegion, user.UpdatedAt, user.LastLogin, user.UserID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateUserStatus updates is_verified and is_active.
func (r *UserRepositoryImpl) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error {
	now := time.Now().UTC()
	query := `UPDATE users SET is_verified = $1, is_active = $2, updated_at = $3 WHERE user_id = $4`
	result, err := r.client.Exec(ctx, query, isVerified, isActive, now, userID)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateLastLogin updates last_login timestamp.
func (r *UserRepositoryImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error {
	now := time.Now().UTC()
	query := `UPDATE users SET last_login = $1, updated_at = $2 WHERE user_id = $3`
	result, err := r.client.Exec(ctx, query, timestamp, now, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeleteUser permanently deletes a user. Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM users WHERE user_id = $1`
	result, err := r.client.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// SoftDeleteUser deactivates a user (sets is_active=false).
func (r *UserRepositoryImpl) SoftDeleteUser(ctx context.Context, userID uuid.UUID) error {
	return r.UpdateUserStatus(ctx, userID, false, false)
}

// ReactivateUser reactivates a user (is_active=true, is_verified=true).
func (r *UserRepositoryImpl) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	return r.UpdateUserStatus(ctx, userID, true, true)
}

// ArchiveInactiveUsers archives users inactive since before.
func (r *UserRepositoryImpl) ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error) {
	query := `
		UPDATE users
		SET is_active = false, updated_at = $1
		WHERE last_login < $2 AND is_active = true`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), before)
	if err != nil {
		return 0, fmt.Errorf("failed to archive inactive users: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// UpdateUserFields updates specific fields of a user.
func (r *UserRepositoryImpl) UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return apperrors.ErrInvalidInput
	}
	setClauses := []string{}
	params := []interface{}{}
	paramCount := 1
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
		return fmt.Errorf("failed to update user fields: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// -----------------------------------------------------------------------------
// Batch operations
// -----------------------------------------------------------------------------

// CreateUsersBatch inserts multiple users in a single transaction.
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
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, user := range users {
		_, err := stmt.ExecContext(ctx,
			user.UserID, user.Username, user.FullName, user.PhoneHash, user.PhoneEncrypted, user.PhoneKeyID,
			user.PhoneEncryptedDEK, user.DeviceID, user.DeviceFingerprint, user.KYCStatus, user.KYCLevel,
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
	return nil
}

// GetUsersByIDBatch retrieves multiple users by their IDs.
func (r *UserRepositoryImpl) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}
	idStrings := make([]string, len(userIDs))
	for i, id := range userIDs {
		idStrings[i] = id.String()
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users WHERE user_id = ANY($1)`
	rows, err := r.client.Query(ctx, query, pq.Array(idStrings))
	if err != nil {
		return nil, fmt.Errorf("failed to query users batch: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, len(userIDs))
}

// UserStatusUpdate represents a batch status update.
type UserStatusUpdate struct {
	UserID     uuid.UUID
	IsVerified bool
	IsActive   bool
	UpdatedAt  time.Time
}

// UpdateUserStatusBatch updates statuses for multiple users.
func (r *UserRepositoryImpl) UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error {
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
	return nil
}

// -----------------------------------------------------------------------------
// Query helpers
// -----------------------------------------------------------------------------

// GetRecentlyActiveUsers returns users active since a given time.
func (r *UserRepositoryImpl) GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users
		WHERE last_login >= $1 AND is_active = true
		ORDER BY last_login DESC
		LIMIT $2`
	rows, err := r.client.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recently active users: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, limit)
}

// GetInactiveUsersSince returns users inactive since a given time.
func (r *UserRepositoryImpl) GetInactiveUsersSince(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users
		WHERE (last_login < $1 OR last_login IS NULL) AND is_active = true
		ORDER BY created_at ASC
		LIMIT $2`
	rows, err := r.client.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query inactive users: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, limit)
}

// SearchUsersByPhoneOrDevice searches users by phone hash or device ID.
func (r *UserRepositoryImpl) SearchUsersByPhoneOrDevice(ctx context.Context, query string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}
	searchPattern := "%" + strings.ToLower(query) + "%"

	var totalCount int
	countQuery := `
		SELECT COUNT(*)
		FROM users
		WHERE LOWER(phone_hash) LIKE $1 OR LOWER(device_id) LIKE $1 OR LOWER(device_fingerprint) LIKE $1`
	err := r.client.QueryRow(ctx, countQuery, searchPattern).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	searchQuery := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users
		WHERE LOWER(phone_hash) LIKE $1 OR LOWER(device_id) LIKE $1 OR LOWER(device_fingerprint) LIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// UpdateKYCStatus updates KYC fields for a user.
func (r *UserRepositoryImpl) UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string) error {
	now := time.Now().UTC()
	isVerified := status == models.KYCStatusVerified
	query := `
		UPDATE users SET
			kyc_status = $1, kyc_level = $2, kyc_verified_at = $3,
			updated_at = $4, is_verified = $5
		WHERE user_id = $6`
	result, err := r.client.Exec(ctx, query, status, level, now, now, isVerified, userID)
	if err != nil {
		return fmt.Errorf("failed to update KYC status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetUsersByKYCStatus returns users with a given KYC status.
func (r *UserRepositoryImpl) GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE kyc_status = $1`
	err := r.client.QueryRow(ctx, countQuery, status).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users by KYC status: %w", err)
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE kyc_status = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, status, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users by KYC status: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// GetUsersByCompany returns employees of a company.
func (r *UserRepositoryImpl) GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `
		SELECT COUNT(*)
		FROM company_employees ce
		WHERE ce.company_id = $1 AND ce.is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count company users: %w", err)
	}
	query := `
		SELECT
			u.user_id, u.username, u.full_name, u.phone_hash, u.phone_encrypted, u.phone_key_id,
			u.phone_encrypted_dek, u.device_id, u.device_fingerprint, u.kyc_status, u.kyc_level,
			u.kyc_verified_at, u.is_verified, u.is_active, u.data_region, u.created_at, u.updated_at, u.last_login
		FROM users u
		INNER JOIN company_employees ce ON u.user_id = ce.user_id
		WHERE ce.company_id = $1 AND ce.is_active = true
		ORDER BY ce.hire_date DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query company users: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// GetUserByDeviceFingerprint returns a user by device fingerprint.
// Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error) {
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE device_fingerprint = $1`
	rows, err := r.client.Query(ctx, query, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by device fingerprint: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserRow(rows)
	}
	return nil, apperrors.ErrNotFound
}

// GetUsersByRegion returns users in a given region.
func (r *UserRepositoryImpl) GetUsersByRegion(ctx context.Context, region string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE data_region = $1`
	err := r.client.QueryRow(ctx, countQuery, region).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users by region: %w", err)
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE data_region = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, region, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users by region: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// GetUsersCreatedAfter returns users created after a given time.
func (r *UserRepositoryImpl) GetUsersCreatedAfter(ctx context.Context, after time.Time, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE created_at > $1`
	err := r.client.QueryRow(ctx, countQuery, after).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users created after date: %w", err)
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users WHERE created_at > $1
		ORDER BY created_at ASC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, after, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users created after date: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// GetUsersByCreationDateRange returns users created between two dates.
func (r *UserRepositoryImpl) GetUsersByCreationDateRange(ctx context.Context, start, end time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted, phone_key_id,
			phone_encrypted_dek, device_id, device_fingerprint, kyc_status, kyc_level,
			kyc_verified_at, is_verified, is_active, data_region, created_at, updated_at, last_login
		FROM users
		WHERE created_at BETWEEN $1 AND $2
		ORDER BY created_at DESC
		LIMIT $3`
	rows, err := r.client.Query(ctx, query, start, end, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query users by creation date: %w", err)
	}
	defer rows.Close()
	return r.scanMultipleUsers(rows, limit)
}

// -----------------------------------------------------------------------------
// Aggregation and metrics
// -----------------------------------------------------------------------------

// CountUsersByRegion returns a map of region to count.
func (r *UserRepositoryImpl) CountUsersByRegion(ctx context.Context) (map[string]int, error) {
	query := `SELECT data_region, COUNT(*) FROM users GROUP BY data_region`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to count users by region: %w", err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var region string
		var count int
		if err := rows.Scan(&region, &count); err != nil {
			continue
		}
		counts[region] = count
	}
	return counts, nil
}

// CountUsersByKYCStatus returns a map of KYC status to count.
func (r *UserRepositoryImpl) CountUsersByKYCStatus(ctx context.Context) (map[string]int, error) {
	query := `SELECT kyc_status, COUNT(*) FROM users GROUP BY kyc_status`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to count users by KYC status: %w", err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		counts[status] = count
	}
	return counts, nil
}

// CountActiveUsers returns the number of active users.
func (r *UserRepositoryImpl) CountActiveUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE is_active = true`
	var count int
	err := r.client.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active users: %w", err)
	}
	return count, nil
}

// CountNewUsersSince returns the number of users created since a given time.
func (r *UserRepositoryImpl) CountNewUsersSince(ctx context.Context, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE created_at >= $1`
	var count int
	err := r.client.QueryRow(ctx, query, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count new users: %w", err)
	}
	return count, nil
}

// GetUserActivityStats returns statistics about user activity.
func (r *UserRepositoryImpl) GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	var activeCount int
	err := r.client.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE last_login >= $1 AND is_active = true`, since).Scan(&activeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user count: %w", err)
	}
	stats["recently_active_users"] = activeCount

	var newRegistrations int
	err = r.client.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE created_at >= $1`, since).Scan(&newRegistrations)
	if err != nil {
		return nil, fmt.Errorf("failed to get new registrations: %w", err)
	}
	stats["new_registrations"] = newRegistrations

	var avgTime sql.NullFloat64
	err = r.client.QueryRow(ctx, `
		SELECT AVG(EXTRACT(EPOCH FROM (last_login - created_at)))
		FROM users
		WHERE last_login IS NOT NULL AND created_at >= $1`, since).Scan(&avgTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get average time to first login: %w", err)
	}
	if avgTime.Valid {
		stats["avg_seconds_to_first_login"] = avgTime.Float64
	} else {
		stats["avg_seconds_to_first_login"] = 0
	}
	return stats, nil
}

// GetKYCDistribution returns KYC status distribution.
func (r *UserRepositoryImpl) GetKYCDistribution(ctx context.Context) (map[string]int, error) {
	return r.CountUsersByKYCStatus(ctx)
}

// GetActiveUserCountsByRegion returns active user counts by region.
func (r *UserRepositoryImpl) GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error) {
	query := `SELECT data_region, COUNT(*) FROM users WHERE is_active = true GROUP BY data_region`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to count active users by region: %w", err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var region string
		var count int
		if err := rows.Scan(&region, &count); err != nil {
			continue
		}
		counts[region] = count
	}
	return counts, nil
}

// GetUserGrowthMetrics returns various growth metrics.
func (r *UserRepositoryImpl) GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})
	var totalUsers int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get total users: %w", err)
	}
	metrics["total_users"] = totalUsers

	activeUsers, err := r.CountActiveUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active users: %w", err)
	}
	metrics["active_users"] = activeUsers

	newUsers, err := r.CountNewUsersSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get new users: %w", err)
	}
	metrics["new_users"] = newUsers

	var verifiedUsers int
	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE is_verified = true").Scan(&verifiedUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified users: %w", err)
	}
	metrics["verified_users"] = verifiedUsers

	kycDist, err := r.GetKYCDistribution(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC distribution: %w", err)
	}
	metrics["kyc_distribution"] = kycDist

	regionDist, err := r.GetActiveUserCountsByRegion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get region distribution: %w", err)
	}
	metrics["region_distribution"] = regionDist

	days := time.Since(since).Hours() / 24
	if days > 0 {
		metrics["growth_rate"] = float64(newUsers) / days
	} else {
		metrics["growth_rate"] = 0
	}
	return metrics, nil
}

// RebuildUserIndexes rebuilds all user indexes.
func (r *UserRepositoryImpl) RebuildUserIndexes(ctx context.Context) error {
	indexes := []string{
		"users_pkey",
		"users_phone_hash_idx",
		"users_device_id_idx",
		"users_kyc_status_idx",
		"users_data_region_idx",
		"users_created_at_idx",
		"users_last_login_idx",
		"idx_users_search_tsv",
		"idx_users_username_trgm",
		"idx_users_fullname_trgm",
	}
	for _, index := range indexes {
		query := fmt.Sprintf("REINDEX INDEX CONCURRENTLY %s", index)
		_, err := r.client.Exec(ctx, query)
		if err != nil {
			// ignore errors in non‑critical path
		}
	}
	return nil
}

// VacuumUserTable runs VACUUM on the users table.
func (r *UserRepositoryImpl) VacuumUserTable(ctx context.Context) error {
	query := "VACUUM (VERBOSE, ANALYZE) users"
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to vacuum user table: %w", err)
	}
	return nil
}

// GetUserByIDWithPartition is an alias to GetUserByID.
func (r *UserRepositoryImpl) GetUserByIDWithPartition(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return r.GetUserByID(ctx, userID)
}

// -----------------------------------------------------------------------------
// Device management
// -----------------------------------------------------------------------------

// AddUserDevice adds a device to a user.
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
		return fmt.Errorf("failed to add user device: %w", err)
	}
	return nil
}

// GetUserDevices returns all devices for a user.
func (r *UserRepositoryImpl) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error) {
	query := `
		SELECT device_id, user_id, device_type, device_name, os_version,
			app_version, last_active, is_active, created_at, updated_at
		FROM user_devices
		WHERE user_id = $1
		ORDER BY last_active DESC`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user devices: %w", err)
	}
	defer rows.Close()
	devices := make([]models.UserDevice, 0)
	for rows.Next() {
		var device models.UserDevice
		if err := rows.Scan(
			&device.DeviceID, &device.UserID, &device.DeviceType, &device.DeviceName,
			&device.OSVersion, &device.AppVersion, &device.LastActive, &device.IsActive,
			&device.CreatedAt, &device.UpdatedAt,
		); err != nil {
			continue
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// RemoveUserDevice removes a device from a user.
func (r *UserRepositoryImpl) RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	query := `DELETE FROM user_devices WHERE user_id = $1 AND device_id = $2`
	result, err := r.client.Exec(ctx, query, userID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to remove user device: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// -----------------------------------------------------------------------------
// Login attempts
// -----------------------------------------------------------------------------

// RecordLoginAttempt records a login attempt.
func (r *UserRepositoryImpl) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error {
	query := `
		INSERT INTO login_attempts (
			attempt_id, user_id, success, ip_address, user_agent, attempted_at
		) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.client.Exec(ctx, query,
		uuid.New(), userID, success, ip, userAgent, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}
	return nil
}

// GetRecentLoginAttempts returns recent login attempts for a user.
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
		return nil, fmt.Errorf("failed to query login attempts: %w", err)
	}
	defer rows.Close()
	attempts := make([]models.LoginAttempt, 0, limit)
	for rows.Next() {
		var attempt models.LoginAttempt
		if err := rows.Scan(
			&attempt.AttemptID, &attempt.UserID, &attempt.Success,
			&attempt.IPAddress, &attempt.UserAgent, &attempt.AttemptedAt,
		); err != nil {
			continue
		}
		attempts = append(attempts, attempt)
	}
	return attempts, nil
}

// -----------------------------------------------------------------------------
// Company employee search
// -----------------------------------------------------------------------------

// SearchCompanyEmployees searches employees within a company.
// SearchCompanyEmployees performs a search on company employees.
// It supports full‑text and autocomplete search, pagination, and optional filters.

// SearchCompanyEmployees searches employees within a specific company
func (r *UserRepositoryImpl) SearchCompanyEmployees(ctx context.Context, req *models.CompanyEmployeeSearchRequest) ([]*models.CompanyEmployeeSearchResult, int, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash,
			employee_id, role_id, role_name, department_id,
			department_name, hire_date, is_active, reports_to,
			reports_to_name, created_at, relevance_score, match_type
		FROM company_employee_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	var roleID, departmentID, reportsTo, isActive, hireDateFrom, hireDateTo interface{}
	if req.Filters != nil {
		if req.Filters.RoleID != nil {
			roleID = *req.Filters.RoleID
		}
		if req.Filters.DepartmentID != nil {
			departmentID = *req.Filters.DepartmentID
		}
		if req.Filters.IsActive != nil {
			isActive = *req.Filters.IsActive
		}
		if req.Filters.ReportsTo != nil {
			reportsTo = *req.Filters.ReportsTo
		}
		if req.Filters.HireDateFrom != nil {
			hireDateFrom = *req.Filters.HireDateFrom
		}
		if req.Filters.HireDateTo != nil {
			hireDateTo = *req.Filters.HireDateTo
		}
	}
	args := []interface{}{
		req.Query,
		req.CompanyID,
		req.SearchType,
		roleID,
		departmentID,
		isActive,
		reportsTo,
		hireDateFrom,
		hireDateTo,
		req.Limit,
		req.Offset,
	}
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search company employees: %w", err)
	}
	defer rows.Close()

	results := make([]*models.CompanyEmployeeSearchResult, 0, req.Limit)
	for rows.Next() {
		var result models.CompanyEmployeeSearchResult
		var fullName, departmentName, reportsToName sql.NullString
		var reportsToID, departmentID sql.NullString
		err := rows.Scan(
			&result.UserID,
			&result.Username,
			&fullName,
			&result.PhoneHash,
			&result.EmployeeID,
			&result.RoleID,
			&result.RoleName,
			&departmentID,
			&departmentName,
			&result.HireDate,
			&result.IsActive,
			&reportsToID,
			&reportsToName,
			&result.CreatedAt,
			&result.RelevanceScore,
			&result.MatchType,
		)
		if err != nil {
			continue
		}
		if fullName.Valid {
			result.FullName = fullName.String
		}
		if departmentName.Valid {
			result.DepartmentName = departmentName.String
		}
		if reportsToName.Valid {
			result.ReportsToName = reportsToName.String
		}
		if reportsToID.Valid {
			if id, err := uuid.Parse(reportsToID.String); err == nil {
				result.ReportsTo = &id
			}
		}
		if departmentID.Valid {
			if id, err := uuid.Parse(departmentID.String); err == nil {
				result.DepartmentID = &id
			}
		}
		results = append(results, &result)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	totalCount, err := r.countCompanyEmployeeResults(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}
	return results, totalCount, nil
}

func (r *UserRepositoryImpl) countCompanyEmployeeResults(ctx context.Context, req *models.CompanyEmployeeSearchRequest) (int, error) {
	conditions := []string{"ce.company_id = $1", "ce.is_active = true"}
	args := []interface{}{req.CompanyID}
	argCounter := 2

	if len(req.Query) >= 3 {
		conditions = append(conditions,
			fmt.Sprintf("u.user_search_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
		args = append(args, req.Query)
		argCounter++
	} else {
		conditions = append(conditions,
			fmt.Sprintf("(u.username ILIKE $%d OR u.full_name ILIKE $%d OR ce.employee_id ILIKE $%d)",
				argCounter, argCounter, argCounter))
		args = append(args, "%"+req.Query+"%")
		argCounter++
	}

	if req.Filters != nil {
		if req.Filters.RoleID != nil {
			conditions = append(conditions, fmt.Sprintf("ce.role_id = $%d", argCounter))
			args = append(args, *req.Filters.RoleID)
			argCounter++
		}
		if req.Filters.DepartmentID != nil {
			conditions = append(conditions, fmt.Sprintf("ce.department_id = $%d", argCounter))
			args = append(args, *req.Filters.DepartmentID)
			argCounter++
		}
		if req.Filters.IsActive != nil {
			conditions = append(conditions, fmt.Sprintf("ce.is_active = $%d", argCounter))
			args = append(args, *req.Filters.IsActive)
			argCounter++
		}
		if req.Filters.ReportsTo != nil {
			conditions = append(conditions, fmt.Sprintf("ce.reports_to = $%d", argCounter))
			args = append(args, *req.Filters.ReportsTo)
			argCounter++
		}
		if req.Filters.HireDateFrom != nil {
			conditions = append(conditions, fmt.Sprintf("ce.hire_date >= $%d", argCounter))
			args = append(args, *req.Filters.HireDateFrom)
			argCounter++
		}
		if req.Filters.HireDateTo != nil {
			conditions = append(conditions, fmt.Sprintf("ce.hire_date <= $%d", argCounter))
			args = append(args, *req.Filters.HireDateTo)
			argCounter++
		}
	}
	whereClause := strings.Join(conditions, " AND ")
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM users u
		INNER JOIN company_employees ce ON u.user_id = ce.user_id
		INNER JOIN roles r ON ce.role_id = r.role_id
		WHERE %s`, whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return 0, fmt.Errorf("failed to count company employee results: %w", err)
	}
	return totalCount, nil
}

// SearchCompanyEmployeesAdvanced is an advanced search with arbitrary filters.
// SearchCompanyEmployeesAdvanced performs an advanced search on company employees with arbitrary filters.
// SearchCompanyEmployeesAdvanced returns a slice of EmployeeSearchResult (no sensitive data).
func (r *UserRepositoryImpl) SearchCompanyEmployeesAdvanced(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	limit, offset int,
) ([]*models.EmployeeSearchResult, int, error) {
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"ce.company_id = $1", "ce.is_active = true"}
	params := []interface{}{companyID}
	paramCount := 2

	for field, value := range filters {
		switch field {
		case "role_id":
			conditions = append(conditions, fmt.Sprintf("ce.role_id = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "department_id":
			// ✅ FIX: use EXISTS on role_departments because ce has no department_id
			conditions = append(conditions, fmt.Sprintf(
				"EXISTS (SELECT 1 FROM role_departments rd WHERE rd.role_id = ce.role_id AND rd.department_id = $%d)",
				paramCount,
			))
			params = append(params, value)
			paramCount++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("ce.is_active = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "reports_to":
			conditions = append(conditions, fmt.Sprintf("ce.reports_to = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "hire_date_from":
			conditions = append(conditions, fmt.Sprintf("ce.hire_date >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "hire_date_to":
			conditions = append(conditions, fmt.Sprintf("ce.hire_date <= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "username":
			conditions = append(conditions, fmt.Sprintf("u.username ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "full_name":
			conditions = append(conditions, fmt.Sprintf("u.full_name ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "employee_id":
			conditions = append(conditions, fmt.Sprintf("ce.employee_id ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		}
	}

	whereClause := strings.Join(conditions, " AND ")

	// COUNT query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM users u
		INNER JOIN company_employees ce ON u.user_id = ce.user_id
		WHERE %s`, whereClause)

	var totalCount int
	if err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count company employees: %w", err)
	}

	// Data query – select only the four public fields
	dataQuery := fmt.Sprintf(`
		SELECT
			u.user_id,
			u.username,
			u.full_name,
			ce.employee_id
		FROM users u
		INNER JOIN company_employees ce ON u.user_id = ce.user_id
		WHERE %s
		ORDER BY ce.hire_date DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCount, paramCount+1)

	params = append(params, limit, offset)
	rows, err := r.client.Query(ctx, dataQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search company employees: %w", err)
	}
	defer rows.Close()

	var results []*models.EmployeeSearchResult
	for rows.Next() {
		var emp models.EmployeeSearchResult
		if err := rows.Scan(&emp.UserID, &emp.Username, &emp.FullName, &emp.EmployeeID); err != nil {
			return nil, 0, fmt.Errorf("failed to scan employee result: %w", err)
		}
		results = append(results, &emp)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return results, totalCount, nil
}

// GetCompanyEmployeeSuggestions returns employee suggestions for a company.
func (r *UserRepositoryImpl) GetCompanyEmployeeSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	query := `SELECT username, full_name, user_id, employee_id, role_name FROM get_company_employee_suggestions($1, $2, $3)`
	rows, err := r.client.Query(ctx, query, companyID, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get company employee suggestions: %w", err)
	}
	defer rows.Close()
	suggestions := make([]*models.UserSuggestion, 0, limit)
	for rows.Next() {
		var s models.UserSuggestion
		var fullName, employeeID, roleName sql.NullString
		if err := rows.Scan(
			&s.Username,
			&fullName,
			&s.UserID,
			&employeeID,
			&roleName,
		); err != nil {
			continue
		}
		if fullName.Valid {
			s.FullName = &fullName.String
		}
		if employeeID.Valid {
			s.EmployeeID = &employeeID.String
		}
		if roleName.Valid {
			s.RoleName = &roleName.String
		}
		suggestions = append(suggestions, &s)
	}
	return suggestions, nil
}

// FindCompanyEmployeeByUsername finds an employee by username in a company.
// Returns apperrors.ErrNotFound if not found.
func (r *UserRepositoryImpl) FindCompanyEmployeeByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.CompanyEmployeeUser, error) {
	query := `SELECT * FROM find_company_employee_by_username($1, $2)`
	rows, err := r.client.Query(ctx, query, companyID, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find company employee by username: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var employee models.CompanyEmployeeUser
		var fullName, roleName sql.NullString
		var tempDeptID, tempDeptName sql.NullString
		if err := rows.Scan(
			&employee.UserID,
			&employee.Username,
			&fullName,
			&employee.PhoneHash,
			&employee.EmployeeID,
			&employee.RoleID,
			&roleName,
			&tempDeptID,
			&tempDeptName,
			&employee.IsActive,
			&employee.HireDate,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee: %w", err)
		}
		if fullName.Valid {
			employee.FullName = &fullName.String
		}
		if roleName.Valid {
			employee.RoleName = &roleName.String
		}
		return &employee, nil
	}
	return nil, apperrors.ErrNotFound
}

// FindCompanyEmployeeWithDepartment is an alias that returns employee and department info (department not used).
func (r *UserRepositoryImpl) FindCompanyEmployeeWithDepartment(ctx context.Context, companyID uuid.UUID, username string) (*models.CompanyEmployeeUser, *models.Department, error) {
	emp, err := r.FindCompanyEmployeeByUsername(ctx, companyID, username)
	if err != nil {
		return nil, nil, err
	}
	// Department info is not available in this implementation; return nil.
	return emp, nil, nil
}

// GetBannedUsers returns users with is_active = false.
func (r *UserRepositoryImpl) GetBannedUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE is_active = false").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count banned users: %w", err)
	}
	query := `
		SELECT
			user_id, username, full_name, phone_hash, phone_encrypted,
			phone_key_id, phone_encrypted_dek, device_id, device_fingerprint,
			kyc_status, kyc_level, kyc_verified_at, is_verified, is_active,
			data_region, created_at, updated_at, last_login
		FROM users
		WHERE is_active = false
		ORDER BY updated_at DESC
		LIMIT $1 OFFSET $2`
	rows, err := r.client.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get banned users: %w", err)
	}
	defer rows.Close()
	users, err := r.scanMultipleUsers(rows, limit)
	if err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// -----------------------------------------------------------------------------
// Avatars
// -----------------------------------------------------------------------------

// SetUserAvatar sets a new primary avatar for the user.
func (r *UserRepositoryImpl) SetUserAvatar(
	ctx context.Context,
	userID uuid.UUID,
	avatarHash string,
	avatarObjectKey string,
	avatarMimeType string,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE user_avatars
		SET is_active = false, is_primary = false, updated_at = NOW()
		WHERE user_id = $1 AND is_primary = true
	`, userID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_avatars (
			avatar_id,
			user_id,
			avatar_type,
			avatar_hash,
			avatar_object_key,
			avatar_mime_type,
			is_active,
			is_primary,
			created_at,
			updated_at
		) VALUES (
			gen_random_uuid(),
			$1,
			'uploaded',
			$2,
			$3,
			$4,
			true,
			true,
			NOW(),
			NOW()
		)
	`, userID, avatarHash, avatarObjectKey, avatarMimeType)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetUserAvatar returns the primary avatar for the user, or nil if none.
func (r *UserRepositoryImpl) GetUserAvatar(
	ctx context.Context,
	userID uuid.UUID,
) (*models.UserAvatar, error) {
	query := `
		SELECT
			avatar_id,
			user_id,
			avatar_type,
			avatar_hash,
			avatar_object_key,
			avatar_mime_type,
			is_active,
			is_primary,
			created_at,
			updated_at
		FROM user_avatars
		WHERE user_id = $1
		  AND is_active = true
		  AND is_primary = true
		LIMIT 1`
	var avatar models.UserAvatar
	err := r.client.QueryRow(ctx, query, userID).Scan(
		&avatar.AvatarID,
		&avatar.UserID,
		&avatar.AvatarType,
		&avatar.AvatarHash,
		&avatar.AvatarObjectKey,
		&avatar.AvatarMimeType,
		&avatar.IsActive,
		&avatar.IsPrimary,
		&avatar.CreatedAt,
		&avatar.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &avatar, nil
}

// DeactivateUserAvatar deactivates the primary avatar.
func (r *UserRepositoryImpl) DeactivateUserAvatar(
	ctx context.Context,
	userID uuid.UUID,
) error {
	_, err := r.client.Exec(ctx, `
		UPDATE user_avatars
		SET is_active = false, is_primary = false, updated_at = NOW()
		WHERE user_id = $1 AND is_primary = true
	`, userID)
	return err
}

// -----------------------------------------------------------------------------
// Health and statistics
// -----------------------------------------------------------------------------

// HealthCheck checks the database connectivity.
func (r *UserRepositoryImpl) HealthCheck(ctx context.Context) error {
	var result int
	err := r.client.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("postgreSQL health check failed: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("postgreSQL health check returned unexpected result: %d", result)
	}
	return nil
}

// GetRepositoryStats returns various repository statistics.
func (r *UserRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	dbStats := r.client.GetStats()
	stats["db_connections"] = map[string]interface{}{
		"open_connections": dbStats.OpenConnections,
		"in_use":           dbStats.InUse,
		"idle":             dbStats.Idle,
		"wait_count":       dbStats.WaitCount,
		"wait_duration":    dbStats.WaitDuration.String(),
	}
	var userCount int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount)
	if err == nil {
		stats["user_count"] = userCount
	}
	return stats, nil
}

// -----------------------------------------------------------------------------
// Internal scan helpers
// -----------------------------------------------------------------------------

func (r *UserRepositoryImpl) scanUserRow(rows *sql.Rows) (*models.User, error) {
	var user models.User
	var kycVerifiedAt, lastLogin sql.NullTime
	err := rows.Scan(
		&user.UserID,
		&user.Username,
		&user.FullName,
		&user.PhoneHash,
		&user.PhoneEncrypted,
		&user.PhoneKeyID,
		&user.PhoneEncryptedDEK,
		&user.DeviceID,
		&user.DeviceFingerprint,
		&user.KYCStatus,
		&user.KYCLevel,
		&kycVerifiedAt,
		&user.IsVerified,
		&user.IsActive,
		&user.DataRegion,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	)
	if err != nil {
		return nil, err
	}
	if kycVerifiedAt.Valid {
		user.KYCVerifiedAt = &kycVerifiedAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	return &user, nil
}

func (r *UserRepositoryImpl) scanMultipleUsers(rows *sql.Rows, limit int) ([]*models.User, error) {
	users := make([]*models.User, 0, limit)
	for rows.Next() {
		user, err := r.scanUserRow(rows)
		if err != nil {
			continue
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}
	return users, nil
}

// FindCompanyEmployeeSummaryByUsername returns a minimal employee summary (user_id, employee_id, username, full_name)
// for a given company and exact username. Returns apperrors.ErrNotFound if no employee is found.
func (r *UserRepositoryImpl) FindCompanyEmployeeSummaryByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.EmployeeSummary, error) {
	query := `
        SELECT
            u.user_id,
            ce.employee_id,
            u.username,
            COALESCE(u.full_name, '') AS full_name
        FROM users u
        INNER JOIN company_employees ce ON u.user_id = ce.user_id
        WHERE ce.company_id = $1 AND u.username = $2 AND ce.is_active = true
        LIMIT 1
    `

	var summary models.EmployeeSummary
	err := r.client.QueryRow(ctx, query, companyID, username).Scan(
		&summary.UserID,
		&summary.EmployeeID,
		&summary.Username,
		&summary.FullName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find active employee summary by username: %w", err)
	}
	return &summary, nil
}

func (r *UserRepositoryImpl) IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (
        SELECT 1
        FROM company_employees
        WHERE user_id = $1 AND company_id = $2 AND is_active = true
    )`
	err := r.client.QueryRow(ctx, query, userID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check employee membership: %w", err)
	}
	return exists, nil
}
