package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

const (
	DefaultAdminPageSize = 100
	MaxAdminBatchSize    = 500
	AdminStmtCacheSize   = 50
)

type AdminRepositoryPostgres struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
	metrics   struct {
		queryCount int64
		batchCount int64
		errorCount int64
		lastReset  time.Time
		sync.RWMutex
	}
}

func NewAdminRepositoryPostgres(client *client.PostgresClient, logger *zap.Logger) *AdminRepositoryPostgres {
	repo := &AdminRepositoryPostgres{
		client:    client,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt, AdminStmtCacheSize),
	}
	repo.metrics.lastReset = time.Now()
	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ===== CORE CRUD =====

func (r *AdminRepositoryPostgres) GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE admin_id = $1`

	row := r.client.QueryRow(ctx, query, adminID)
	return r.scanAdminUser(row)
}

func (r *AdminRepositoryPostgres) GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE phone_hash = $1 
        LIMIT 1`

	row := r.client.QueryRow(ctx, query, phoneHash)
	return r.scanAdminUser(row)
}

func (r *AdminRepositoryPostgres) GetAdminByUsername(ctx context.Context, username string) (*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE username = $1 
        LIMIT 1`

	row := r.client.QueryRow(ctx, query, username)
	return r.scanAdminUser(row)
}

// ===== REPORTS_TO / HIERARCHY =====

func (r *AdminRepositoryPostgres) UpdateAdminReportsTo(ctx context.Context, adminID uuid.UUID, reportsTo *uuid.UUID) error {
	query := `
        UPDATE admin_users 
        SET reports_to = $1, admin_updated_at = $2 
        WHERE admin_id = $3`

	result, err := r.client.Exec(ctx, query, reportsTo, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update admin reports_to: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	r.logger.Info("Admin reports_to updated",
		util.String("admin_id", adminID.String()),
		util.Any("reports_to", reportsTo))

	return nil
}

func (r *AdminRepositoryPostgres) GetAdminHierarchy(ctx context.Context, adminID uuid.UUID) ([]*models.AdminHierarchy, error) {
	query := `
        WITH RECURSIVE admin_hierarchy AS (
            SELECT 
                admin_id, username, full_name, role_type, reports_to,
                0 as level, is_active
            FROM admin_users 
            WHERE admin_id = $1 AND is_active = true
            
            UNION ALL
            
            SELECT 
                au.admin_id, au.username, au.full_name, au.role_type, au.reports_to,
                ah.level + 1 as level, au.is_active
            FROM admin_users au
            INNER JOIN admin_hierarchy ah ON au.reports_to = ah.admin_id
            WHERE au.is_active = true
        )
        SELECT * FROM admin_hierarchy ORDER BY level`

	rows, err := r.client.Query(ctx, query, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin hierarchy: %w", err)
	}
	defer rows.Close()

	var hierarchy []*models.AdminHierarchy
	for rows.Next() {
		var ah models.AdminHierarchy
		err := rows.Scan(
			&ah.AdminID,
			&ah.Username,
			&ah.FullName,
			&ah.RoleType,
			&ah.ReportsTo,
			&ah.Level,
			&ah.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin hierarchy: %w", err)
		}
		hierarchy = append(hierarchy, &ah)
	}

	return hierarchy, nil
}

func (r *AdminRepositoryPostgres) GetDirectReports(ctx context.Context, adminID uuid.UUID) ([]*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE reports_to = $1 AND is_active = true
        ORDER BY username`

	rows, err := r.client.Query(ctx, query, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to get direct reports: %w", err)
	}
	defer rows.Close()

	var admins []*models.AdminUser
	for rows.Next() {
		admin, err := r.scanAdminUserFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin: %w", err)
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

func (r *AdminRepositoryPostgres) GetReportingChain(ctx context.Context, adminID uuid.UUID) ([]*models.AdminUser, error) {
	query := `
        WITH RECURSIVE reporting_chain AS (
            SELECT 
                admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
                admin_updated_at, is_active, data_access_scope, ip_whitelist,
                failed_login_attempts, last_login, username, full_name,
                0 as level
            FROM admin_users 
            WHERE admin_id = $1 AND is_active = true
            
            UNION ALL
            
            SELECT 
                au.admin_id, au.phone_hash, au.phone_encrypted, au.phone_key_id, au.phone_encrypted_dek,
                au.admin_role_id, au.role_type, au.reports_to, au.admin_created_at, au.admin_created_by,
                au.admin_updated_at, au.is_active, au.data_access_scope, au.ip_whitelist,
                au.failed_login_attempts, au.last_login, au.username, au.full_name,
                rc.level + 1 as level
            FROM admin_users au
            INNER JOIN reporting_chain rc ON au.admin_id = rc.reports_to
            WHERE au.is_active = true AND rc.reports_to IS NOT NULL
        )
        SELECT * FROM reporting_chain ORDER BY level`

	rows, err := r.client.Query(ctx, query, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reporting chain: %w", err)
	}
	defer rows.Close()

	var chain []*models.AdminUser
	for rows.Next() {
		admin, err := r.scanAdminUserFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin: %w", err)
		}
		chain = append(chain, admin)
	}

	return chain, nil
}

func (r *AdminRepositoryPostgres) CanAssignReportsTo(ctx context.Context, assignerID, targetID uuid.UUID) (bool, error) {
	var assignerRoleType, targetRoleType int

	query := `SELECT role_type FROM admin_users WHERE admin_id = $1`

	err := r.client.QueryRow(ctx, query, assignerID).Scan(&assignerRoleType)
	if err != nil {
		return false, fmt.Errorf("failed to get assigner role type: %w", err)
	}

	err = r.client.QueryRow(ctx, query, targetID).Scan(&targetRoleType)
	if err != nil {
		return false, fmt.Errorf("failed to get target role type: %w", err)
	}

	// Check role hierarchy
	if assignerRoleType == models.RoleTypeSuperAdmin {
		return true, nil
	}

	if assignerRoleType == models.RoleTypeManager {
		return targetRoleType == models.RoleTypeEmployee, nil
	}

	return false, nil
}

func (r *AdminRepositoryPostgres) BulkUpdateReportsTo(ctx context.Context, adminIDs []uuid.UUID, reportsTo *uuid.UUID) error {
	if len(adminIDs) == 0 {
		return nil
	}

	query := `
        UPDATE admin_users 
        SET reports_to = $1, admin_updated_at = $2 
        WHERE admin_id = ANY($3)`

	result, err := r.client.Exec(ctx, query, reportsTo, time.Now().UTC(), pq.Array(adminIDs))
	if err != nil {
		return fmt.Errorf("failed to bulk update reports_to: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("Bulk updated reports_to",
		util.Int64("rows_affected", rowsAffected),
		util.Any("reports_to", reportsTo),
		util.Int("admin_count", len(adminIDs)))

	return nil
}

func (r *AdminRepositoryPostgres) GetAvailableManagers(ctx context.Context, excludeID *uuid.UUID) ([]*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE is_active = true 
        AND role_type IN ($1, $2)`

	var rows *sql.Rows
	var err error

	if excludeID != nil {
		query += " AND admin_id != $3 ORDER BY username"
		rows, err = r.client.Query(ctx, query, models.RoleTypeManager, models.RoleTypeSuperAdmin, excludeID)
	} else {
		query += " ORDER BY username"
		rows, err = r.client.Query(ctx, query, models.RoleTypeManager, models.RoleTypeSuperAdmin)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get available managers: %w", err)
	}
	defer rows.Close()

	var admins []*models.AdminUser
	for rows.Next() {
		admin, err := r.scanAdminUserFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin: %w", err)
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

func (r *AdminRepositoryPostgres) GetAdminWithReportsToName(ctx context.Context, adminID uuid.UUID) (*models.AdminUserSearchResult, error) {
	query := `
        SELECT 
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, ar.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE au.admin_id = $1`

	row := r.client.QueryRow(ctx, query, adminID)

	var result models.AdminUserSearchResult
	var lastLogin sql.NullTime
	var reportsToName sql.NullString

	err := row.Scan(
		&result.AdminID,
		&result.Username,
		&result.FullName,
		&result.PhoneHash,
		&result.RoleName,
		&result.AdminRoleID,
		&result.RoleType,
		&result.ReportsTo,
		&reportsToName,
		&result.IsActive,
		&lastLogin,
		&result.AdminCreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin not found: %s", adminID)
		}
		return nil, fmt.Errorf("failed to get admin with reports to name: %w", err)
	}

	if reportsToName.Valid {
		result.ReportsToName = reportsToName.String
	}
	if lastLogin.Valid {
		result.LastLogin = &lastLogin.Time
	}

	return &result, nil
}

// ===== LISTING & FILTERING =====

func (r *AdminRepositoryPostgres) GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        ORDER BY admin_created_at DESC
        LIMIT $1`

	rows, err := r.client.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get all admins: %w", err)
	}
	defer rows.Close()

	var admins []*models.AdminUser
	for rows.Next() {
		admin, err := r.scanAdminUserFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin: %w", err)
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

func (r *AdminRepositoryPostgres) GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
        SELECT 
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, last_login, username, full_name
        FROM admin_users 
        WHERE is_active = true
        ORDER BY admin_created_at DESC
        LIMIT $1`

	rows, err := r.client.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get active admins: %w", err)
	}
	defer rows.Close()

	var admins []*models.AdminUser
	for rows.Next() {
		admin, err := r.scanAdminUserFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin: %w", err)
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

func (r *AdminRepositoryPostgres) GetAdminsByRoleType(ctx context.Context, roleType int, includeInactive bool, limit, offset int) ([]*models.AdminUserSearchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `SELECT * FROM search_admin_users_by_role_type($1, NULL, 'all', $2, $3, $4)`

	rows, err := r.client.Query(ctx, query, roleType, includeInactive, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get admins by role type: %w", err)
	}
	defer rows.Close()

	return r.scanAdminSearchResults(rows)
}

func (r *AdminRepositoryPostgres) GetAdminsByRole(ctx context.Context, adminRoleID uuid.UUID, includeInactive bool, limit, offset int) ([]*models.AdminUserSearchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
        SELECT 
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, ar.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            1.0 as relevance_score, 'all' as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE au.admin_role_id = $1`

	if !includeInactive {
		query += " AND au.is_active = true"
	}

	query += " ORDER BY au.username ASC LIMIT $2 OFFSET $3"

	rows, err := r.client.Query(ctx, query, adminRoleID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get admins by role: %w", err)
	}
	defer rows.Close()

	return r.scanAdminSearchResults(rows)
}

// ===== PROFILE MANAGEMENT =====

func (r *AdminRepositoryPostgres) UpdateAdminProfile(ctx context.Context, adminID uuid.UUID, username, fullName string) error {
	query := `
        UPDATE admin_users 
        SET username = $1, full_name = $2, admin_updated_at = $3 
        WHERE admin_id = $4`

	result, err := r.client.Exec(ctx, query, username, fullName, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update admin profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	r.logger.Info("Admin profile updated",
		util.String("admin_id", adminID.String()),
		util.String("username", username),
		util.String("full_name", fullName))

	return nil
}

// ===== PHONE & LOGIN =====

func (r *AdminRepositoryPostgres) UpdateAdminPhone(
	ctx context.Context,
	adminID uuid.UUID,
	phoneHash string,
	phoneEncrypted []byte,
	phoneKeyID uuid.UUID,
	phoneEncryptedDEK string,
) error {
	query := `
        UPDATE admin_users 
        SET phone_hash = $1, phone_encrypted = $2, phone_key_id = $3, 
            phone_encrypted_dek = $4, admin_updated_at = $5 
        WHERE admin_id = $6`

	result, err := r.client.Exec(ctx, query,
		phoneHash, phoneEncrypted, phoneKeyID, phoneEncryptedDEK, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update admin phone: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	r.logger.Info("Admin phone updated",
		util.String("admin_id", adminID.String()))

	return nil
}

func (r *AdminRepositoryPostgres) UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error {
	query := `
        UPDATE admin_users 
        SET last_login = $1, admin_updated_at = $2 
        WHERE admin_id = $3`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	return nil
}

// ===== STATUS / LIFECYCLE =====

func (r *AdminRepositoryPostgres) DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error {
	// Update reports_to for direct reports
	updateReportsQuery := `
        UPDATE admin_users 
        SET reports_to = NULL, admin_updated_at = $1 
        WHERE reports_to = $2 AND is_active = true`

	_, err := r.client.Exec(ctx, updateReportsQuery, time.Now().UTC(), adminID)
	if err != nil {
		r.logger.Warn("Failed to reassign reports when deactivating admin",
			util.String("admin_id", adminID.String()),
			util.ErrorField(err))
	}

	query := `
        UPDATE admin_users 
        SET is_active = false, admin_updated_at = $1 
        WHERE admin_id = $2`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to deactivate admin: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	r.logger.Info("Admin deactivated",
		util.String("admin_id", adminID.String()))

	return nil
}

func (r *AdminRepositoryPostgres) ActivateAdmin(ctx context.Context, adminID uuid.UUID) error {
	query := `
        UPDATE admin_users 
        SET is_active = true, admin_updated_at = $1 
        WHERE admin_id = $2`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to activate admin: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	r.logger.Info("Admin activated",
		util.String("admin_id", adminID.String()))

	return nil
}

// ===== SUPER ADMIN =====
func (r *AdminRepositoryPostgres) GetSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	query := `
        SELECT
            au.admin_id, au.phone_hash, au.phone_encrypted, au.phone_key_id, au.phone_encrypted_dek,
            au.admin_role_id, au.role_type, au.reports_to, au.admin_created_at, au.admin_created_by,
            au.admin_updated_at, au.is_active, au.data_access_scope, au.ip_whitelist,
            au.failed_login_attempts, au.last_login, au.username, au.full_name
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        WHERE au.role_type = $1 AND au.is_active = true
        LIMIT 1`

	row := r.client.QueryRow(ctx, query, models.RoleTypeSuperAdmin)
	admin, err := r.scanAdminUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get super admin: %w", err)
	}
	return admin, nil
}
func (r *AdminRepositoryPostgres) IsSuperAdminExists(ctx context.Context) (bool, error) {
	query := `
        SELECT COUNT(*) 
        FROM admin_users 
        WHERE role_type = $1 AND is_active = true`

	var count int
	err := r.client.QueryRow(ctx, query, models.RoleTypeSuperAdmin).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check super admin existence: %w", err)
	}

	return count > 0, nil
}

// ===== FAILED LOGIN ATTEMPTS =====

func (r *AdminRepositoryPostgres) IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var currentAttempts int
	query := `SELECT failed_login_attempts FROM admin_users WHERE admin_id = $1`
	err = tx.QueryRowContext(ctx, query, adminID).Scan(&currentAttempts)
	if err != nil {
		return 0, fmt.Errorf("failed to get current attempts: %w", err)
	}

	newAttempts := currentAttempts + 1
	updateQuery := `
        UPDATE admin_users 
        SET failed_login_attempts = $1, admin_updated_at = $2 
        WHERE admin_id = $3`

	result, err := tx.ExecContext(ctx, updateQuery, newAttempts, time.Now().UTC(), adminID)
	if err != nil {
		return newAttempts, fmt.Errorf("failed to increment failed attempts: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return newAttempts, fmt.Errorf("admin not found: %s", adminID)
	}

	if err := tx.Commit(); err != nil {
		return newAttempts, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return newAttempts, nil
}

func (r *AdminRepositoryPostgres) ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error {
	query := `
        UPDATE admin_users 
        SET failed_login_attempts = 0, admin_updated_at = $1 
        WHERE admin_id = $2`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), adminID)
	if err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin not found: %s", adminID)
	}

	return nil
}

// ===== SEARCH =====

func (r *AdminRepositoryPostgres) SearchAdmins(
	ctx context.Context,
	req *models.AdminSearchRequest,
) ([]*models.AdminUserSearchResult, int, error) {
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Search results
	sqlQuery := `SELECT * FROM search_admin_users($1, $2, $3, $4, $5, $6)`
	rows, err := r.client.Query(ctx, sqlQuery,
		req.Query,
		req.RoleTypeFilter,
		req.IncludeInactive,
		req.SearchType,
		req.Limit,
		req.Offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search admins: %w", err)
	}
	defer rows.Close()

	results, err := r.scanAdminSearchResults(rows)
	if err != nil {
		return nil, 0, err
	}

	// Count total results
	totalCount, err := r.countAdminSearchResults(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	return results, totalCount, nil
}

func (r *AdminRepositoryPostgres) countAdminSearchResults(ctx context.Context, req *models.AdminSearchRequest) (int, error) {
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	// Add search condition
	if req.Query != "" {
		if len(req.Query) >= 3 {
			conditions = append(conditions,
				fmt.Sprintf("au.user_search_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
			args = append(args, req.Query)
			argCounter++
		} else {
			conditions = append(conditions,
				fmt.Sprintf("(au.username ILIKE $%d OR au.full_name ILIKE $%d)", argCounter, argCounter))
			args = append(args, "%"+req.Query+"%")
			argCounter++
		}
	}

	// Add role type filter
	if req.RoleTypeFilter != nil {
		conditions = append(conditions, fmt.Sprintf("au.role_type = $%d", argCounter))
		args = append(args, *req.RoleTypeFilter)
		argCounter++
	}

	// Add active status filter
	if !req.IncludeInactive {
		conditions = append(conditions, fmt.Sprintf("au.is_active = $%d", argCounter))
		args = append(args, true)
		argCounter++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf(`
        SELECT COUNT(*) 
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        %s`, whereClause)

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return 0, fmt.Errorf("failed to count admin search results: %w", err)
	}

	return totalCount, nil
}

func (r *AdminRepositoryPostgres) GetAdminSuggestions(
	ctx context.Context,
	prefix string,
	roleTypeFilter *int,
	excludeSuperAdmin bool,
	limit int,
) ([]*models.AdminSuggestion, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	sqlQuery := `SELECT * FROM get_admin_suggestions($1, $2, $3, $4)`
	rows, err := r.client.Query(ctx, sqlQuery, prefix, roleTypeFilter, excludeSuperAdmin, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin suggestions: %w", err)
	}
	defer rows.Close()

	var suggestions []*models.AdminSuggestion
	for rows.Next() {
		var suggestion models.AdminSuggestion
		var reportsToName sql.NullString
		var reportsTo sql.NullString

		err := rows.Scan(
			&suggestion.AdminID,
			&suggestion.Username,
			&suggestion.FullName,
			&suggestion.RoleName,
			&suggestion.RoleLevel,
			&suggestion.RoleType,
			&reportsTo,
			&reportsToName,
			&suggestion.Relevance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin suggestion: %w", err)
		}

		if reportsTo.Valid {
			reportsToUUID, err := uuid.Parse(reportsTo.String)
			if err == nil {
				suggestion.ReportsTo = &reportsToUUID
			}
		}
		if reportsToName.Valid {
			suggestion.ReportsToName = reportsToName.String
		}

		suggestions = append(suggestions, &suggestion)
	}

	return suggestions, nil
}

// ===== ADMIN WITH PERMISSIONS =====

func (r *AdminRepositoryPostgres) GetAdminWithPermissions(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminWithPermissions, error) {
	query := `SELECT * FROM get_admin_with_permissions($1)`

	row := r.client.QueryRow(ctx, query, adminID)

	var admin models.AdminWithPermissions
	var permissionsJSON, departmentsJSON []byte
	var reportsToName sql.NullString
	var lastLogin sql.NullTime

	err := row.Scan(
		&admin.AdminID,
		&admin.Username,
		&admin.FullName,
		&admin.RoleName,
		&admin.RoleLevel,
		&admin.RoleType,
		&permissionsJSON,
		&departmentsJSON,
		&admin.ReportsTo,
		&reportsToName,
		&admin.IsActive,
		&lastLogin,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin not found: %s", adminID)
		}
		return nil, fmt.Errorf("failed to get admin with permissions: %w", err)
	}

	// Parse JSONB fields
	if err := json.Unmarshal(permissionsJSON, &admin.Permissions); err != nil {
		return nil, fmt.Errorf("failed to parse permissions: %w", err)
	}
	if err := json.Unmarshal(departmentsJSON, &admin.Departments); err != nil {
		return nil, fmt.Errorf("failed to parse departments: %w", err)
	}

	if reportsToName.Valid {
		admin.ReportsToName = reportsToName.String
	}
	if lastLogin.Valid {
		admin.LastLogin = &lastLogin.Time
	}

	return &admin, nil
}

func (r *AdminRepositoryPostgres) AdminHasPermission(
	ctx context.Context,
	adminID uuid.UUID,
	permissionName string,
) (bool, error) {
	query := `SELECT admin_has_permission($1, $2)`

	var hasPermission bool
	err := r.client.QueryRow(ctx, query, adminID, permissionName).Scan(&hasPermission)
	if err != nil {
		return false, fmt.Errorf("failed to check admin permission: %w", err)
	}

	return hasPermission, nil
}

func (r *AdminRepositoryPostgres) AdminHasDepartmentAccess(
	ctx context.Context,
	adminID uuid.UUID,
	departmentBitmask uint64,
) (bool, error) {
	query := `SELECT admin_has_department_access($1, $2)`

	var hasAccess bool
	err := r.client.QueryRow(ctx, query, adminID, departmentBitmask).Scan(&hasAccess)
	if err != nil {
		return false, fmt.Errorf("failed to check admin department access: %w", err)
	}

	return hasAccess, nil
}

// ===== AVATAR MANAGEMENT =====

func (r *AdminRepositoryPostgres) SetAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
	avatarHash string,
	avatarObjectKey string,
	avatarMimeType string,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Deactivate old avatar
	_, err = tx.ExecContext(ctx, `
        UPDATE admin_avatars
        SET is_active = false, is_primary = false, updated_at = NOW()
        WHERE admin_id = $1 AND is_primary = true
    `, adminID)
	if err != nil {
		return err
	}

	// Insert new avatar
	_, err = tx.ExecContext(ctx, `
        INSERT INTO admin_avatars (
            avatar_id,
            admin_id,
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
    `, adminID, avatarHash, avatarObjectKey, avatarMimeType)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	r.logger.Info("Admin avatar set",
		util.String("admin_id", adminID.String()),
		util.String("object_key", avatarObjectKey))

	return nil
}

func (r *AdminRepositoryPostgres) GetAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminAvatar, error) {
	query := `
        SELECT
            avatar_id,
            admin_id,
            avatar_type,
            avatar_hash,
            avatar_object_key,
            avatar_mime_type,
            is_active,
            is_primary,
            created_at,
            updated_at
        FROM admin_avatars
        WHERE admin_id = $1
          AND is_active = true
          AND is_primary = true
        LIMIT 1`

	var avatar models.AdminAvatar
	err := r.client.QueryRow(ctx, query, adminID).Scan(
		&avatar.AvatarID,
		&avatar.AdminID,
		&avatar.AvatarType,
		&avatar.AvatarHash,
		&avatar.AvatarObjectKey,
		&avatar.AvatarMimeType,
		&avatar.IsActive,
		&avatar.IsPrimary,
		&avatar.CreatedAt,
		&avatar.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &avatar, nil
}

func (r *AdminRepositoryPostgres) DeactivateAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
) error {
	result, err := r.client.Exec(ctx, `
        UPDATE admin_avatars
        SET is_active = false, is_primary = false, updated_at = NOW()
        WHERE admin_id = $1 AND is_primary = true
    `, adminID)

	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil
	}

	r.logger.Info("Admin avatar deactivated",
		util.String("admin_id", adminID.String()))

	return nil
}

// ===== HEALTH & STATS =====

func (r *AdminRepositoryPostgres) HealthCheck(ctx context.Context) error {
	var result int
	err := r.client.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("admin repository health check failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("admin repository health check returned unexpected result: %d", result)
	}

	return nil
}

func (r *AdminRepositoryPostgres) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalAdmins, activeAdmins int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&totalAdmins)
	if err != nil {
		return nil, fmt.Errorf("failed to count admins: %w", err)
	}
	stats["total_admins"] = totalAdmins

	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM admin_users WHERE is_active = true").Scan(&activeAdmins)
	if err != nil {
		return nil, fmt.Errorf("failed to count active admins: %w", err)
	}
	stats["active_admins"] = activeAdmins

	// Count by role type
	roleTypes := []int{models.RoleTypeEmployee, models.RoleTypeManager, models.RoleTypeSuperAdmin}
	for _, roleType := range roleTypes {
		var count int
		err = r.client.QueryRow(ctx,
			"SELECT COUNT(*) FROM admin_users WHERE role_type = $1", roleType).Scan(&count)
		if err != nil {
			continue
		}

		var roleName string
		switch roleType {
		case models.RoleTypeEmployee:
			roleName = "employee"
		case models.RoleTypeManager:
			roleName = "manager"
		case models.RoleTypeSuperAdmin:
			roleName = "super_admin"
		}
		stats[fmt.Sprintf("admins_%s", roleName)] = count
	}

	// Count admins with reports_to
	var adminsWithReports int
	err = r.client.QueryRow(ctx,
		"SELECT COUNT(*) FROM admin_users WHERE reports_to IS NOT NULL").Scan(&adminsWithReports)
	if err == nil {
		stats["admins_with_reports_to"] = adminsWithReports
	}

	var adminsWithoutReports int
	err = r.client.QueryRow(ctx,
		"SELECT COUNT(*) FROM admin_users WHERE reports_to IS NULL").Scan(&adminsWithoutReports)
	if err == nil {
		stats["admins_without_reports_to"] = adminsWithoutReports
	}

	// Check search functions existence
	var searchEnabled bool
	err = r.client.QueryRow(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM pg_proc WHERE proname = 'search_admin_users'
        )
    `).Scan(&searchEnabled)
	if err == nil {
		stats["search_enabled"] = searchEnabled
	}

	return stats, nil
}

// ===== HELPER METHODS =====
func (r *AdminRepositoryPostgres) scanAdminUser(row *sql.Row) (*models.AdminUser, error) {
	var admin models.AdminUser
	var reportsTo sql.NullString
	var adminCreatedBy sql.NullString
	var lastLogin sql.NullTime
	var dataAccessScope pq.StringArray
	var ipWhitelist pq.StringArray

	err := row.Scan(
		&admin.AdminID,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&admin.PhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&admin.AdminRoleID,
		&admin.RoleType,
		&reportsTo,
		&admin.AdminCreatedAt,
		&adminCreatedBy,
		&admin.AdminUpdatedAt,
		&admin.IsActive,
		&dataAccessScope,
		&ipWhitelist,
		&admin.FailedLoginAttempts,
		&lastLogin,
		&admin.Username,
		&admin.FullName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	// Convert pq.StringArray to []string for model
	admin.DataAccessScope = []string(dataAccessScope)
	admin.IPWhitelist = []string(ipWhitelist)

	if reportsTo.Valid {
		reportsToUUID, err := uuid.Parse(reportsTo.String)
		if err == nil {
			admin.ReportsTo = &reportsToUUID
		}
	}

	if adminCreatedBy.Valid {
		createdByUUID, err := uuid.Parse(adminCreatedBy.String)
		if err == nil {
			admin.AdminCreatedBy = &createdByUUID
		}
	}

	if lastLogin.Valid {
		admin.LastLogin = &lastLogin.Time
	}

	return &admin, nil
}
func (r *AdminRepositoryPostgres) scanAdminUserFromRows(rows *sql.Rows) (*models.AdminUser, error) {
	var admin models.AdminUser
	var reportsTo sql.NullString
	var adminCreatedBy sql.NullString
	var lastLogin sql.NullTime
	var dataAccessScope pq.StringArray
	var ipWhitelist pq.StringArray

	// First, get the column count
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Handle scanning based on number of columns
	if len(columns) == 19 {
		// For queries that include 'level' column (like GetReportingChain)
		var level int // We'll read this but not use it in AdminUser struct
		err := rows.Scan(
			&admin.AdminID,
			&admin.PhoneHash,
			&admin.PhoneEncrypted,
			&admin.PhoneKeyID,
			&admin.PhoneEncryptedDEK,
			&admin.AdminRoleID,
			&admin.RoleType,
			&reportsTo,
			&admin.AdminCreatedAt,
			&adminCreatedBy,
			&admin.AdminUpdatedAt,
			&admin.IsActive,
			&dataAccessScope,
			&ipWhitelist,
			&admin.FailedLoginAttempts,
			&lastLogin,
			&admin.Username,
			&admin.FullName,
			&level, // Scan the level column
		)

		if err != nil {
			return nil, err
		}
	} else if len(columns) == 18 {
		// For regular queries without 'level' column
		err := rows.Scan(
			&admin.AdminID,
			&admin.PhoneHash,
			&admin.PhoneEncrypted,
			&admin.PhoneKeyID,
			&admin.PhoneEncryptedDEK,
			&admin.AdminRoleID,
			&admin.RoleType,
			&reportsTo,
			&admin.AdminCreatedAt,
			&adminCreatedBy,
			&admin.AdminUpdatedAt,
			&admin.IsActive,
			&dataAccessScope,
			&ipWhitelist,
			&admin.FailedLoginAttempts,
			&lastLogin,
			&admin.Username,
			&admin.FullName,
		)

		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unexpected number of columns: %d", len(columns))
	}

	// Convert pq.StringArray to []string for model
	admin.DataAccessScope = []string(dataAccessScope)
	admin.IPWhitelist = []string(ipWhitelist)

	if reportsTo.Valid {
		reportsToUUID, err := uuid.Parse(reportsTo.String)
		if err == nil {
			admin.ReportsTo = &reportsToUUID
		}
	}

	if adminCreatedBy.Valid {
		createdByUUID, err := uuid.Parse(adminCreatedBy.String)
		if err == nil {
			admin.AdminCreatedBy = &createdByUUID
		}
	}

	if lastLogin.Valid {
		admin.LastLogin = &lastLogin.Time
	}

	return &admin, nil
}
func (r *AdminRepositoryPostgres) scanAdminSearchResults(rows *sql.Rows) ([]*models.AdminUserSearchResult, error) {
	var results []*models.AdminUserSearchResult

	for rows.Next() {
		var result models.AdminUserSearchResult
		var reportsToName sql.NullString
		var reportsTo sql.NullString
		var lastLogin sql.NullTime

		err := rows.Scan(
			&result.AdminID,
			&result.Username,
			&result.FullName,
			&result.PhoneHash,
			&result.RoleName,
			&result.AdminRoleID,
			&result.RoleType,
			&reportsTo,
			&reportsToName,
			&result.IsActive,
			&lastLogin,
			&result.AdminCreatedAt,
			&result.RelevanceScore,
			&result.MatchType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin search result: %w", err)
		}

		if reportsTo.Valid {
			reportsToUUID, err := uuid.Parse(reportsTo.String)
			if err == nil {
				result.ReportsTo = &reportsToUUID
			}
		}
		if reportsToName.Valid {
			result.ReportsToName = reportsToName.String
		}
		if lastLogin.Valid {
			result.LastLogin = &lastLogin.Time
		}

		results = append(results, &result)
	}

	return results, nil
}

// ==================== ADMIN ROLE MANAGEMENT ====================

func (r *AdminRepositoryPostgres) CreateAdminRole(ctx context.Context, role *models.AdminRole, departmentIDs []uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert admin role
	roleQuery := `
        INSERT INTO admin_roles (
            admin_role_id, role_name, role_level, role_type, is_system_role,
            description, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = tx.ExecContext(ctx, roleQuery,
		role.AdminRoleID, role.RoleName, role.RoleLevel, role.RoleType,
		role.IsSystemRole, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create admin role: %w", err)
	}

	// Assign departments if provided
	if len(departmentIDs) > 0 {
		for _, deptID := range departmentIDs {
			_, err = tx.ExecContext(ctx,
				`INSERT INTO admin_role_departments (admin_role_id, system_department_id) VALUES ($1, $2)`,
				role.AdminRoleID, deptID,
			)
			if err != nil {
				return fmt.Errorf("failed to assign department to admin role: %w", err)
			}
		}
	}

	// Grant default permissions based on role type and departments
	err = r.grantDefaultPermissions(ctx, tx, role.AdminRoleID, role.RoleType, departmentIDs)
	if err != nil {
		return fmt.Errorf("failed to grant default permissions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Admin role created successfully",
		util.String("role_id", role.AdminRoleID.String()),
		util.String("role_name", role.RoleName),
		util.Int("role_type", role.RoleType))
	return nil
}

func (r *AdminRepositoryPostgres) grantDefaultPermissions(
	ctx context.Context,
	tx *sql.Tx,
	roleID uuid.UUID,
	roleType int,
	departmentIDs []uuid.UUID,
) error {
	if roleType == models.RoleTypeSuperAdmin {
		grantQuery := `
            INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
            SELECT $1, p.permission_id, $2, NOW()
            FROM permissions p
            ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
		_, err := tx.ExecContext(ctx, grantQuery, roleID, uuid.Nil)
		if err != nil {
			return fmt.Errorf("failed to grant all permissions to super admin role: %w", err)
		}
		return nil
	}

	// For manager roles: grant all permissions for their department modules
	if roleType == models.RoleTypeManager {
		var modules []string

		// Get modules from assigned departments
		if len(departmentIDs) > 0 {
			query := `SELECT DISTINCT module_code FROM system_departments WHERE system_department_id = ANY($1)`
			rows, err := tx.QueryContext(ctx, query, pq.Array(departmentIDs))
			if err != nil {
				return err
			}
			defer rows.Close()

			for rows.Next() {
				var module string
				if err := rows.Scan(&module); err == nil {
					modules = append(modules, module)
				}
			}
		}

		// If no specific modules from departments, use default manager modules
		if len(modules) == 0 {
			modules = []string{"employee_management", "manager_management"}
		}

		// Grant all permissions for these modules
		if len(modules) > 0 {
			grantQuery := `
                INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
                SELECT $1, p.permission_id, $2, NOW()
                FROM permissions p
                WHERE p.module = ANY($3)
                AND p.requires_tier IN ('admin', 'basic')
                ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
			_, err := tx.ExecContext(ctx, grantQuery, roleID, uuid.Nil, pq.Array(modules))
			if err != nil {
				return fmt.Errorf("failed to grant permissions: %w", err)
			}
		}
		return nil
	}

	// For employee roles: DO NOT grant any default permissions
	// Specific permissions will be granted by the handler based on request
	if roleType == models.RoleTypeEmployee {
		return nil // Employee roles get no permissions by default
	}

	return nil
}
func (r *AdminRepositoryPostgres) GetAdminRole(ctx context.Context, roleID uuid.UUID) (*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles WHERE admin_role_id = $1`

	var role models.AdminRole
	err := r.client.QueryRow(ctx, query, roleID).Scan(
		&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
		&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin role not found: %s", roleID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}

	r.recordQuery()
	return &role, nil
}

func (r *AdminRepositoryPostgres) GetAdminRoles(ctx context.Context, limit, offset int, roleType *int) ([]*models.AdminRole, int, error) {
	if limit <= 0 || limit > DefaultAdminPageSize {
		limit = DefaultAdminPageSize
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	if roleType != nil {
		conditions = append(conditions, fmt.Sprintf("role_type = $%d", argCounter))
		args = append(args, *roleType)
		argCounter++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM admin_roles %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count admin roles: %w", err)
	}

	// Data query
	query := fmt.Sprintf(`
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles %s
        ORDER BY role_level DESC, role_name ASC
        LIMIT $%d OFFSET $%d`, whereClause, argCounter, argCounter+1)

	args = append(args, limit, offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query admin roles: %w", err)
	}
	defer rows.Close()

	roles := make([]*models.AdminRole, 0, limit)
	for rows.Next() {
		var role models.AdminRole
		err := rows.Scan(
			&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
			&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan admin role row", util.ErrorField(err))
			continue
		}
		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating admin role rows: %w", err)
	}

	r.recordQuery()
	return roles, totalCount, nil
}

func (r *AdminRepositoryPostgres) UpdateAdminRole(ctx context.Context, role *models.AdminRole) error {
	role.UpdatedAt = time.Now().UTC()
	query := `
        UPDATE admin_roles SET
            role_name = $1, role_level = $2, description = $3, updated_at = $4
        WHERE admin_role_id = $5 AND is_system_role = false`

	result, err := r.client.Exec(ctx, query,
		role.RoleName, role.RoleLevel, role.Description, role.UpdatedAt, role.AdminRoleID,
	)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update admin role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin role not found or is system role: %s", role.AdminRoleID)
	}

	r.recordQuery()
	r.logger.Info("Admin role updated",
		util.String("role_id", role.AdminRoleID.String()),
		util.String("role_name", role.RoleName))
	return nil
}

func (r *AdminRepositoryPostgres) DeleteAdminRole(ctx context.Context, roleID uuid.UUID) error {
	// Check if role is in use
	var inUseCount int
	checkQuery := `SELECT COUNT(*) FROM admin_users WHERE admin_role_id = $1`
	err := r.client.QueryRow(ctx, checkQuery, roleID).Scan(&inUseCount)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to check role usage: %w", err)
	}

	if inUseCount > 0 {
		return fmt.Errorf("cannot delete admin role: %d admin users are assigned to it", inUseCount)
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete role permissions
	_, err = tx.ExecContext(ctx, "DELETE FROM admin_role_permissions WHERE admin_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role permissions: %w", err)
	}

	// Delete role departments
	_, err = tx.ExecContext(ctx, "DELETE FROM admin_role_departments WHERE admin_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role departments: %w", err)
	}

	// Delete role
	deleteQuery := `DELETE FROM admin_roles WHERE admin_role_id = $1 AND is_system_role = false`
	result, err := tx.ExecContext(ctx, deleteQuery, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete admin role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin role not found or is system role: %s", roleID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Admin role deleted", util.String("role_id", roleID.String()))
	return nil
}

// ==================== ADMIN USER MANAGEMENT ====================

func (r *AdminRepositoryPostgres) CreateAdminUser(ctx context.Context, admin *models.AdminUser) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if username is unique
	var exists bool
	checkQuery := `SELECT COUNT(*) > 0 FROM admin_users WHERE username = $1`
	err = tx.QueryRowContext(ctx, checkQuery, admin.Username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check username: %w", err)
	}
	if exists {
		return fmt.Errorf("username already exists: %s", admin.Username)
	}

	// Create admin user
	query := `
        INSERT INTO admin_users (
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, username, full_name
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	_, err = tx.ExecContext(ctx, query,
		admin.AdminID, admin.PhoneHash, admin.PhoneEncrypted, admin.PhoneKeyID,
		admin.PhoneEncryptedDEK, admin.AdminRoleID, admin.RoleType, admin.ReportsTo,
		admin.AdminCreatedAt, admin.AdminCreatedBy, admin.AdminUpdatedAt, admin.IsActive,
		pq.Array(admin.DataAccessScope), pq.Array(admin.IPWhitelist),
		admin.FailedLoginAttempts, admin.Username, admin.FullName,
	)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Admin user created successfully",
		util.String("admin_id", admin.AdminID.String()),
		util.String("username", admin.Username),
		util.String("role_type", getRoleTypeName(admin.RoleType)))
	return nil
}

func (r *AdminRepositoryPostgres) UpdateAdminUser(ctx context.Context, adminID uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	// Prevent updating certain fields
	restrictedFields := []string{"admin_id", "admin_created_at", "admin_created_by"}
	for field := range updates {
		for _, restricted := range restrictedFields {
			if field == restricted {
				return fmt.Errorf("cannot update restricted field: %s", field)
			}
		}
	}

	updates["admin_updated_at"] = time.Now().UTC()
	setClauses := []string{}
	params := []interface{}{}
	paramCount := 1

	for field, value := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, paramCount))
		params = append(params, value)
		paramCount++
	}

	params = append(params, adminID)
	query := fmt.Sprintf("UPDATE admin_users SET %s WHERE admin_id = $%d",
		strings.Join(setClauses, ", "), paramCount)

	result, err := r.client.Exec(ctx, query, params...)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update admin user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin user not found: %s", adminID)
	}

	r.recordQuery()
	r.logger.Info("Admin user updated",
		util.String("admin_id", adminID.String()),
		util.Int("fields_updated", len(updates)))
	return nil
}

func (r *AdminRepositoryPostgres) DeleteAdminUser(ctx context.Context, adminID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if admin has any reports
	var reportCount int
	checkQuery := `SELECT COUNT(*) FROM admin_users WHERE reports_to = $1 AND is_active = true`
	err = tx.QueryRowContext(ctx, checkQuery, adminID).Scan(&reportCount)
	if err != nil {
		return fmt.Errorf("failed to check reports: %w", err)
	}

	if reportCount > 0 {
		// Reassign reports to NULL
		_, err = tx.ExecContext(ctx,
			"UPDATE admin_users SET reports_to = NULL, admin_updated_at = $1 WHERE reports_to = $2",
			time.Now().UTC(), adminID)
		if err != nil {
			return fmt.Errorf("failed to reassign reports: %w", err)
		}
	}

	// Delete admin user
	deleteQuery := `DELETE FROM admin_users WHERE admin_id = $1`
	result, err := tx.ExecContext(ctx, deleteQuery, adminID)
	if err != nil {
		return fmt.Errorf("failed to delete admin user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("admin user not found: %s", adminID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Admin user deleted", util.String("admin_id", adminID.String()))
	return nil
}

// ==================== PERMISSION MANAGEMENT ====================

func (r *AdminRepositoryPostgres) GetAdminRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	query := `
        SELECT p.permission_id, p.permission_name, p.description,
               p.category, p.module, p.scope, p.requires_tier, p.bit_index, p.created_at
        FROM admin_role_permissions arp
        INNER JOIN permissions p ON arp.permission_id = p.permission_id
        WHERE arp.admin_role_id = $1
        ORDER BY p.module, p.category, p.permission_name`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query admin role permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]*models.Permission, 0)
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.Scope, &perm.RequiresTier,
			&bitIndex, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *AdminRepositoryPostgres) GetAdminUserPermissions(ctx context.Context, adminID uuid.UUID) ([]*models.Permission, error) {
	query := `
        SELECT DISTINCT p.permission_id, p.permission_name, p.description,
               p.category, p.module, p.scope, p.requires_tier, p.bit_index, p.created_at
        FROM admin_users au
        INNER JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        INNER JOIN admin_role_permissions arp ON ar.admin_role_id = arp.admin_role_id
        INNER JOIN permissions p ON arp.permission_id = p.permission_id
        WHERE au.admin_id = $1 AND au.is_active = true
        ORDER BY p.module, p.category, p.permission_name`

	rows, err := r.client.Query(ctx, query, adminID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query admin user permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]*models.Permission, 0)
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.Scope, &perm.RequiresTier,
			&bitIndex, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *AdminRepositoryPostgres) GrantPermissionToAdminRole(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	query := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (admin_role_id, permission_id) DO UPDATE SET
            granted_by = EXCLUDED.granted_by,
            granted_at = EXCLUDED.granted_at`

	_, err := r.client.Exec(ctx, query, roleID, permissionID, grantedBy)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to grant permission to admin role: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Permission granted to admin role",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()))
	return nil
}

// ==================== DEPARTMENT MANAGEMENT ====================

func (r *AdminRepositoryPostgres) GetAdminRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.SystemDepartment, error) {
	query := `
        SELECT sd.system_department_id, sd.name, sd.module_code, sd.description, sd.bitmask
        FROM admin_role_departments ard
        INNER JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
        WHERE ard.admin_role_id = $1
        ORDER BY sd.name`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query admin role departments: %w", err)
	}
	defer rows.Close()

	departments := make([]*models.SystemDepartment, 0)
	for rows.Next() {
		var dept models.SystemDepartment
		err := rows.Scan(
			&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode,
			&dept.Description, &dept.Bitmask,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}
		departments = append(departments, &dept)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}

	r.recordQuery()
	return departments, nil
}

func (r *AdminRepositoryPostgres) AssignDepartmentToAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error {
	// Check if department exists
	var deptExists bool
	checkQuery := `SELECT COUNT(*) > 0 FROM system_departments WHERE system_department_id = $1`
	err := r.client.QueryRow(ctx, checkQuery, departmentID).Scan(&deptExists)
	if err != nil {
		return fmt.Errorf("failed to check department: %w", err)
	}
	if !deptExists {
		return fmt.Errorf("department not found: %s", departmentID)
	}

	// Assign department to role
	query := `
        INSERT INTO admin_role_departments (admin_role_id, system_department_id)
        VALUES ($1, $2)
        ON CONFLICT (admin_role_id, system_department_id) DO NOTHING`

	_, err = r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to assign department to admin role: %w", err)
	}

	// Sync permissions for the role based on new department
	err = r.syncRolePermissionsFromDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to sync permissions: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Department assigned to admin role",
		util.String("role_id", roleID.String()),
		util.String("department_id", departmentID.String()))
	return nil
}

func (r *AdminRepositoryPostgres) RemoveDepartmentFromAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `DELETE FROM admin_role_departments WHERE admin_role_id = $1 AND system_department_id = $2`
	result, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to remove department from admin role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found for admin role: %s", roleID)
	}

	// Sync permissions after removal
	err = r.syncRolePermissionsFromDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to sync permissions: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Department removed from admin role",
		util.String("role_id", roleID.String()),
		util.String("department_id", departmentID.String()))
	return nil
}
func (r *AdminRepositoryPostgres) syncRolePermissionsFromDepartments(ctx context.Context, roleID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var roleType int
	roleQuery := `SELECT role_type FROM admin_roles WHERE admin_role_id = $1`
	err = tx.QueryRowContext(ctx, roleQuery, roleID).Scan(&roleType)
	if err != nil {
		return fmt.Errorf("failed to get role type: %w", err)
	}

	var deptIDs []uuid.UUID
	deptQuery := `SELECT system_department_id FROM admin_role_departments WHERE admin_role_id = $1`
	rows, err := tx.QueryContext(ctx, deptQuery, roleID)
	if err != nil {
		return fmt.Errorf("failed to query departments: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var deptID uuid.UUID
		if err := rows.Scan(&deptID); err == nil {
			deptIDs = append(deptIDs, deptID)
		}
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM admin_role_permissions WHERE admin_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to clear permissions: %w", err)
	}

	// Call the updated grantDefaultPermissions function
	err = r.grantDefaultPermissions(ctx, tx, roleID, roleType, deptIDs)
	if err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ==================== SEARCH FUNCTIONS ====================

// func (r *AdminRepositoryPostgres) SearchAdminUsers(ctx context.Context, req *models.AdminUserSearchRequest) ([]*models.AdminUserSearchResult, int, error) {
// 	if req.Limit <= 0 || req.Limit > 100 {
// 		req.Limit = 50
// 	}
// 	if req.Offset < 0 {
// 		req.Offset = 0
// 	}

// 	query := `
//         SELECT
//             admin_id, username, full_name, phone_hash,
//             role_name, admin_role_id, role_type,
//             reports_to, reports_to_name,
//             is_active, last_login, admin_created_at,
//             relevance_score, match_type
//         FROM search_admin_users($1, $2, $3, $4, $5, $6)`

// 	var roleTypeFilter interface{}
// 	if req.RoleTypeFilter != nil {
// 		roleTypeFilter = *req.RoleTypeFilter
// 	}

// 	rows, err := r.client.Query(ctx, query,
// 		req.Query, roleTypeFilter, req.IncludeInactive,
// 		req.SearchType, req.Limit, req.Offset,
// 	)
// 	if err != nil {
// 		r.recordError()
// 		return nil, 0, fmt.Errorf("failed to search admin users: %w", err)
// 	}
// 	defer rows.Close()

// 	results, err := r.scanAdminSearchResults(rows)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	totalCount, err := r.countAdminUserSearchResults(ctx, req)
// 	if err != nil {
// 		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
// 	}

// 	r.recordQuery()
// 	return results, totalCount, nil
// }

// ==================== HELPER FUNCTIONS ====================

func (r *AdminRepositoryPostgres) countAdminUserSearchResults(ctx context.Context, req *models.AdminUserSearchRequest) (int, error) {
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	if req.Query != "" {
		if len(req.Query) >= 3 {
			conditions = append(conditions,
				fmt.Sprintf("au.user_search_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
			args = append(args, req.Query)
			argCounter++
		} else {
			conditions = append(conditions,
				fmt.Sprintf("(au.username ILIKE $%d OR au.full_name ILIKE $%d)", argCounter, argCounter))
			args = append(args, "%"+req.Query+"%")
			argCounter++
		}
	}

	if req.RoleTypeFilter != nil {
		conditions = append(conditions, fmt.Sprintf("au.role_type = $%d", argCounter))
		args = append(args, *req.RoleTypeFilter)
		argCounter++
	}

	if !req.IncludeInactive {
		conditions = append(conditions, fmt.Sprintf("au.is_active = $%d", argCounter))
		args = append(args, true)
		argCounter++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf(`
        SELECT COUNT(DISTINCT au.admin_id)
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        %s`, whereClause)

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return 0, fmt.Errorf("failed to count admin search results: %w", err)
	}

	return totalCount, nil
}

func getRoleTypeName(roleType int) string {
	switch roleType {
	case 1:
		return "Employee"
	case 2:
		return "Manager"
	case 4:
		return "Super Admin"
	default:
		return "Unknown"
	}
}

func (r *AdminRepositoryPostgres) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_admin_role_by_id": `
            SELECT admin_role_id, role_name, role_level, role_type,
                   is_system_role, description, created_at, updated_at
            FROM admin_roles WHERE admin_role_id = $1`,
		"get_admin_user_by_id": `
            SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                   admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
                   admin_updated_at, is_active, data_access_scope, ip_whitelist,
                   failed_login_attempts, last_login, username, full_name
            FROM admin_users WHERE admin_id = $1`,
		"get_admin_role_permissions": `
            SELECT p.permission_id, p.permission_name, p.description,
                   p.category, p.module, p.scope, p.requires_tier, p.bit_index, p.created_at
            FROM admin_role_permissions arp
            INNER JOIN permissions p ON arp.permission_id = p.permission_id
            WHERE arp.admin_role_id = $1`,
		"check_admin_permission": `
            SELECT COUNT(*) > 0
            FROM admin_users au
            INNER JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
            INNER JOIN admin_role_permissions arp ON ar.admin_role_id = arp.admin_role_id
            INNER JOIN permissions p ON arp.permission_id = p.permission_id
            WHERE au.admin_id = $1 AND au.is_active = true AND p.permission_name = $2`,
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

	r.logger.Info("Admin prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *AdminRepositoryPostgres) recordQuery() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.queryCount++
}

func (r *AdminRepositoryPostgres) recordError() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.errorCount++
}

func (r *AdminRepositoryPostgres) Close() error {
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

// ==================== BITMASK OPERATIONS ====================

func (r *AdminRepositoryPostgres) GetAdminPermissionBitmask(
	ctx context.Context,
	adminID uuid.UUID,
) ([]uint64, error) {
	// Get admin's role
	var roleID uuid.UUID
	query := `SELECT admin_role_id FROM admin_users WHERE admin_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, query, adminID).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return []uint64{}, nil
		}
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}

	// Use role permission bitmask function
	return r.GetAdminRolePermissionBitmask(ctx, roleID)
}

func (r *AdminRepositoryPostgres) GetAdminRolePermissionBitmask(
	ctx context.Context,
	roleID uuid.UUID,
) ([]uint64, error) {
	query := `
        SELECT DISTINCT p.bit_index
        FROM admin_role_permissions arp
        INNER JOIN permissions p ON arp.permission_id = p.permission_id
        WHERE arp.admin_role_id = $1 
        AND p.bit_index IS NOT NULL
        ORDER BY p.bit_index`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin role permission bitmask: %w", err)
	}
	defer rows.Close()

	var bitPositions []uint64
	for rows.Next() {
		var bitIndex int
		if err := rows.Scan(&bitIndex); err == nil && bitIndex >= 0 {
			bitPositions = append(bitPositions, uint64(bitIndex))
		}
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
	}

	r.recordQuery()
	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

func (r *AdminRepositoryPostgres) GetAdminPermissionsWithBitIndex(
	ctx context.Context,
) ([]*models.PermissionWithBitIndex, error) {
	query := `
        SELECT permission_id, permission_name, bit_index, module, category, scope
        FROM permissions
        WHERE bit_index IS NOT NULL
        AND (scope = 'admin' OR scope = 'both')
        ORDER BY bit_index`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin permissions with bit index: %w", err)
	}
	defer rows.Close()

	var permissions []*models.PermissionWithBitIndex
	for rows.Next() {
		var perm models.PermissionWithBitIndex
		err := rows.Scan(
			&perm.ID,
			&perm.Name,
			&perm.BitIndex,
			&perm.Module,
			&perm.Category,
			&perm.Scope,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission with bit index", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *AdminRepositoryPostgres) GetAdminPermissionsByBitPositions(
	ctx context.Context,
	bitPositions []uint64,
) ([]*models.Permission, error) {
	if len(bitPositions) == 0 {
		return []*models.Permission{}, nil
	}

	args := make([]interface{}, len(bitPositions))
	placeholders := make([]string, len(bitPositions))
	for i, pos := range bitPositions {
		args[i] = int(pos)
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
        SELECT permission_id, permission_name, description, category, module, 
               scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE bit_index IN (%s)
        AND (scope = 'admin' OR scope = 'both')
        ORDER BY bit_index`, strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin permissions by bit positions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID,
			&perm.PermissionName,
			&perm.Description,
			&perm.Category,
			&perm.Module,
			&perm.Scope,
			&perm.RequiresTier,
			&bitIndex,
			&perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission by bit position", util.ErrorField(err))
			continue
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *AdminRepositoryPostgres) GetAdminPermissionBitIndexes(
	ctx context.Context,
	permissionNames []string,
) (map[string]uint64, error) {
	if len(permissionNames) == 0 {
		return map[string]uint64{}, nil
	}

	args := make([]interface{}, len(permissionNames))
	placeholders := make([]string, len(permissionNames))
	for i, name := range permissionNames {
		args[i] = name
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
        SELECT permission_name, bit_index
        FROM permissions
        WHERE permission_name IN (%s) 
        AND bit_index IS NOT NULL
        AND (scope = 'admin' OR scope = 'both')`,
		strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin permission bit indexes: %w", err)
	}
	defer rows.Close()

	result := make(map[string]uint64)
	for rows.Next() {
		var name string
		var bitIndex int
		err := rows.Scan(&name, &bitIndex)
		if err != nil {
			r.logger.Warn("Failed to scan permission bit index", util.ErrorField(err))
			continue
		}
		result[name] = uint64(bitIndex)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission bit index rows: %w", err)
	}

	r.recordQuery()
	return result, nil
}

// ==================== SYSTEM DEPARTMENT OPERATIONS ====================

func (r *AdminRepositoryPostgres) GetAdminSystemDepartments(
	ctx context.Context,
) ([]*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments
        WHERE module_code IN ('employee_management', 'manager_management', 'company_management', 'super_admin')
        ORDER BY name`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin system departments: %w", err)
	}
	defer rows.Close()

	var systemDepartments []*models.SystemDepartment
	for rows.Next() {
		var dept models.SystemDepartment
		var bitmask sql.NullInt64
		err := rows.Scan(
			&dept.SystemDepartmentID,
			&dept.Name,
			&dept.ModuleCode,
			&dept.Description,
			&bitmask,
		)
		if err != nil {
			r.logger.Warn("Failed to scan system department row", util.ErrorField(err))
			continue
		}
		if bitmask.Valid {
			dept.Bitmask = uint64(bitmask.Int64)
		}
		systemDepartments = append(systemDepartments, &dept)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}

	r.recordQuery()
	return systemDepartments, nil
}

func (r *AdminRepositoryPostgres) GetAdminSystemDepartmentByModule(
	ctx context.Context,
	module string,
) (*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments
        WHERE module_code = $1 
        AND module_code IN ('employee_management', 'manager_management', 'company_management', 'super_admin')
        LIMIT 1`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, module).Scan(
		&dept.SystemDepartmentID,
		&dept.Name,
		&dept.ModuleCode,
		&dept.Description,
		&dept.Bitmask,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin system department not found for module: %s", module)
		}
		return nil, fmt.Errorf("failed to get admin system department: %w", err)
	}

	r.recordQuery()
	return &dept, nil
}

func (r *AdminRepositoryPostgres) GetAdminSystemDepartment(
	ctx context.Context,
	systemDeptID uuid.UUID,
) (*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments
        WHERE system_department_id = $1 
        AND module_code IN ('employee_management', 'manager_management', 'company_management', 'super_admin')`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, systemDeptID).Scan(
		&dept.SystemDepartmentID,
		&dept.Name,
		&dept.ModuleCode,
		&dept.Description,
		&dept.Bitmask,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin system department not found: %s", systemDeptID)
		}
		return nil, fmt.Errorf("failed to get admin system department: %w", err)
	}

	r.recordQuery()
	return &dept, nil
}

func (r *AdminRepositoryPostgres) GetAdminDepartmentBitmask(
	ctx context.Context,
	departmentName string,
) (uint64, error) {
	query := `
        SELECT bitmask
        FROM system_departments
        WHERE name = $1 
        AND module_code IN ('employee_management', 'manager_management', 'company_management', 'super_admin')`

	var bitmask uint64
	err := r.client.QueryRow(ctx, query, departmentName).Scan(&bitmask)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("admin department not found: %s", departmentName)
		}
		return 0, fmt.Errorf("failed to get admin department bitmask: %w", err)
	}

	r.recordQuery()
	return bitmask, nil
}

// ==================== MODULE PERMISSIONS ====================

func (r *AdminRepositoryPostgres) GetAdminPermissionsByModules(
	ctx context.Context,
	modules []string,
) ([]*models.Permission, error) {
	if len(modules) == 0 {
		return []*models.Permission{}, nil
	}

	query := `
        SELECT permission_id, permission_name, description, category, module, 
               scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE module = ANY($1) 
        AND (scope = 'admin' OR scope = 'both')
        ORDER BY module, bit_index`

	rows, err := r.client.Query(ctx, query, pq.Array(modules))
	if err != nil {
		return nil, fmt.Errorf("failed to query admin permissions by module: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID,
			&perm.PermissionName,
			&perm.Description,
			&perm.Category,
			&perm.Module,
			&perm.Scope,
			&perm.RequiresTier,
			&bitIndex,
			&perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *AdminRepositoryPostgres) GetAdminPermissionsBySystemDepartments(
	ctx context.Context,
	systemDeptIDs []uuid.UUID,
	module, category, tier string,
) ([]*models.Permission, error) {
	if len(systemDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}

	deptIDStrings := make([]string, len(systemDeptIDs))
	for i, id := range systemDeptIDs {
		deptIDStrings[i] = id.String()
	}

	query := `
        SELECT DISTINCT
            p.permission_id,
            p.permission_name,
            p.description,
            p.category,
            p.module,
            p.scope,
            p.requires_tier,
            p.bit_index,
            p.created_at
        FROM permissions p
        INNER JOIN system_departments sd ON p.module = sd.module_code
        WHERE sd.system_department_id = ANY($1)
        AND (p.scope = 'admin' OR p.scope = 'both')`

	args := []interface{}{pq.Array(deptIDStrings)}
	argCount := 1

	if module != "" {
		argCount++
		query += fmt.Sprintf(" AND p.module = $%d", argCount)
		args = append(args, module)
	}

	if category != "" {
		argCount++
		query += fmt.Sprintf(" AND p.category = $%d", argCount)
		args = append(args, category)
	}

	if tier != "" {
		argCount++
		query += fmt.Sprintf(" AND p.requires_tier = $%d", argCount)
		args = append(args, tier)
	}

	query += " ORDER BY p.module, p.category, p.permission_name"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin permissions by system departments: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID,
			&perm.PermissionName,
			&perm.Description,
			&perm.Category,
			&perm.Module,
			&perm.Scope,
			&perm.RequiresTier,
			&bitIndex,
			&perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// ==================== HELPER METHODS FOR INITIALIZATION ====================

func (r *AdminRepositoryPostgres) initializeBitmaskPreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_admin_permission_bitmask": `
            SELECT DISTINCT p.bit_index
            FROM admin_users au
            JOIN admin_role_permissions arp ON au.admin_role_id = arp.admin_role_id
            JOIN permissions p ON arp.permission_id = p.permission_id
            WHERE au.admin_id = $1 
            AND au.is_active = true 
            AND p.bit_index IS NOT NULL
            AND (p.scope = 'admin' OR p.scope = 'both')
            ORDER BY p.bit_index`,

		"get_admin_role_permission_bitmask": `
            SELECT p.bit_index
            FROM admin_role_permissions arp
            JOIN permissions p ON arp.permission_id = p.permission_id
            WHERE arp.admin_role_id = $1 
            AND p.bit_index IS NOT NULL
            AND (p.scope = 'admin' OR p.scope = 'both')
            ORDER BY p.bit_index`,

		"get_admin_permissions_with_bit_index": `
            SELECT permission_id, permission_name, bit_index, module, category, scope
            FROM permissions
            WHERE bit_index IS NOT NULL
            AND (scope = 'admin' OR scope = 'both')
            ORDER BY bit_index`,

		"get_admin_system_departments": `
            SELECT system_department_id, name, module_code, description, bitmask
            FROM system_departments
            WHERE module_code IN ('employee_management', 'manager_management', 'company_management', 'super_admin')
            ORDER BY name`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare bitmask statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}
		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Admin bitmask prepared statements initialized",
		util.Int("statements", len(statements)))
}

// SearchAdminsAdvanced - Advanced search with multiple filters
func (r *AdminRepositoryPostgres) SearchAdminsAdvanced(
	ctx context.Context,
	req *models.AdminAdvancedSearchRequest,
) ([]*models.AdminUserSearchResult, int, error) {
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Build dynamic query
	var conditions []string
	var args []interface{}
	argCounter := 1

	// Search query condition
	if req.Query != "" {
		if len(req.Query) >= 3 {
			conditions = append(conditions,
				fmt.Sprintf("au.user_search_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
			args = append(args, req.Query)
			argCounter++
		} else {
			conditions = append(conditions,
				fmt.Sprintf("(au.username ILIKE $%d OR au.full_name ILIKE $%d)", argCounter, argCounter))
			args = append(args, "%"+req.Query+"%")
			argCounter++
		}
	}

	// Apply filters
	if req.Filters.RoleID != nil {
		conditions = append(conditions, fmt.Sprintf("au.admin_role_id = $%d", argCounter))
		args = append(args, *req.Filters.RoleID)
		argCounter++
	}

	if req.Filters.DepartmentID != nil {
		conditions = append(conditions, fmt.Sprintf(`
            EXISTS (
                SELECT 1 FROM admin_role_departments ard 
                WHERE ard.admin_role_id = au.admin_role_id 
                AND ard.system_department_id = $%d
            )
        `, argCounter))
		args = append(args, *req.Filters.DepartmentID)
		argCounter++
	}

	if req.Filters.ReportsTo != nil {
		conditions = append(conditions, fmt.Sprintf("au.reports_to = $%d", argCounter))
		args = append(args, *req.Filters.ReportsTo)
		argCounter++
	}

	if req.Filters.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("au.admin_created_at >= $%d", argCounter))
		args = append(args, *req.Filters.CreatedAfter)
		argCounter++
	}

	if req.Filters.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("au.admin_created_at <= $%d", argCounter))
		args = append(args, *req.Filters.CreatedBefore)
		argCounter++
	}

	if req.Filters.LastLoginAfter != nil {
		conditions = append(conditions, fmt.Sprintf("au.last_login >= $%d", argCounter))
		args = append(args, *req.Filters.LastLoginAfter)
		argCounter++
	}

	if req.Filters.LastLoginBefore != nil {
		conditions = append(conditions, fmt.Sprintf("au.last_login <= $%d", argCounter))
		args = append(args, *req.Filters.LastLoginBefore)
		argCounter++
	}

	if req.Filters.HasAvatar != nil {
		if *req.Filters.HasAvatar {
			conditions = append(conditions, fmt.Sprintf(`
                EXISTS (
                    SELECT 1 FROM admin_avatars aa 
                    WHERE aa.admin_id = au.admin_id 
                    AND aa.is_active = true 
                    AND aa.is_primary = true
                )
            `))
		} else {
			conditions = append(conditions, fmt.Sprintf(`
                NOT EXISTS (
                    SELECT 1 FROM admin_avatars aa 
                    WHERE aa.admin_id = au.admin_id 
                    AND aa.is_active = true 
                    AND aa.is_primary = true
                )
            `))
		}
	}

	if req.Filters.IPWhitelist != nil {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(au.ip_whitelist)", argCounter))
		args = append(args, *req.Filters.IPWhitelist)
		argCounter++
	}

	if req.Filters.DataAccessScope != nil {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(au.data_access_scope)", argCounter))
		args = append(args, *req.Filters.DataAccessScope)
		argCounter++
	}

	// Filter by active status using req.IncludeInactive (not req.Filters.IncludeInactive)
	if !req.IncludeInactive {
		conditions = append(conditions, "au.is_active = true")
	}

	// Build WHERE clause
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf(`
        SELECT COUNT(DISTINCT au.admin_id)
        FROM admin_users au
        %s
    `, whereClause)

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Determine sort order
	sortBy := "au.username"
	if req.SortBy != "" {
		switch req.SortBy {
		case "full_name":
			sortBy = "au.full_name"
		case "created_at":
			sortBy = "au.admin_created_at"
		case "last_login":
			sortBy = "au.last_login"
		case "role_type":
			sortBy = "au.role_type"
		case "role_level":
			sortBy = "ar.role_level"
		default:
			sortBy = "au.username"
		}
	}

	sortOrder := "ASC"
	if req.SortOrder == "desc" {
		sortOrder = "DESC"
	}

	// Data query
	query := fmt.Sprintf(`
        SELECT 
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, ar.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            1.0 as relevance_score, 'advanced' as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        %s
        ORDER BY %s %s
        LIMIT $%d OFFSET $%d
    `, whereClause, sortBy, sortOrder, argCounter, argCounter+1)

	args = append(args, req.Limit, req.Offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute advanced search: %w", err)
	}
	defer rows.Close()

	results, err := r.scanAdminSearchResults(rows)
	if err != nil {
		return nil, 0, err
	}

	r.recordQuery()
	return results, totalCount, nil
}

// GetAdminsByDepartment - Get admins by department ID with pagination
func (r *AdminRepositoryPostgres) GetAdminsByDepartment(
	ctx context.Context,
	departmentID uuid.UUID,
	includeInactive bool,
	limit, offset int,
) ([]*models.AdminUserSearchResult, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	// Count query
	countQuery := `
        SELECT COUNT(DISTINCT au.admin_id)
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        JOIN admin_role_departments ard ON ar.admin_role_id = ard.admin_role_id
        WHERE ard.system_department_id = $1
    `

	if !includeInactive {
		countQuery += " AND au.is_active = true"
	}

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, departmentID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count admins by department: %w", err)
	}

	// Data query
	query := `
        SELECT DISTINCT
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, ar.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            1.0 as relevance_score, 'department' as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        JOIN admin_role_departments ard ON ar.admin_role_id = ard.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE ard.system_department_id = $1
    `

	if !includeInactive {
		query += " AND au.is_active = true"
	}

	query += " ORDER BY au.username ASC LIMIT $2 OFFSET $3"

	rows, err := r.client.Query(ctx, query, departmentID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get admins by department: %w", err)
	}
	defer rows.Close()

	results, err := r.scanAdminSearchResults(rows)
	if err != nil {
		return nil, 0, err
	}

	r.recordQuery()
	return results, totalCount, nil
}

// SearchAdminRoles - Search admin roles with filtering
func (r *AdminRepositoryPostgres) SearchAdminRoles(
	ctx context.Context,
	query string,
	roleTypeFilter *int,
	limit, offset int,
) ([]*models.AdminRole, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Build conditions
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	if query != "" {
		// Use a single ILIKE condition with OR
		conditions = append(conditions,
			fmt.Sprintf("(role_name ILIKE $%d OR description ILIKE $%d)",
				argCounter, argCounter))
		args = append(args, "%"+query+"%")
		argCounter++
	}

	if roleTypeFilter != nil {
		conditions = append(conditions, fmt.Sprintf("role_type = $%d", argCounter))
		args = append(args, *roleTypeFilter)
		argCounter++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM admin_roles %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count admin roles: %w", err)
	}

	// Build the ORDER BY clause with explicit type casting
	orderByClause := ""
	if query != "" {
		// Use explicit type casting for the query parameter
		// We need to reference the query parameter from args (which is at position 1)
		orderByClause = `
            ORDER BY 
                CASE 
                    WHEN role_name ILIKE $1 || '%' THEN 1
                    WHEN role_name ILIKE '%' || $1 || '%' THEN 2
                    WHEN description ILIKE '%' || $1 || '%' THEN 3
                    ELSE 4
                END,
                role_level DESC,
                role_name`
	} else {
		orderByClause = "ORDER BY role_level DESC, role_name"
	}

	// Build the full query
	searchQuery := fmt.Sprintf(`
        SELECT 
            admin_role_id,
            role_name,
            role_level,
            role_type,
            is_system_role,
            description,
            created_at,
            updated_at
        FROM admin_roles %s
        %s
        LIMIT $%d OFFSET $%d
    `, whereClause, orderByClause, len(args)+1, len(args)+2)

	// Add limit and offset to args
	finalArgs := make([]interface{}, len(args))
	copy(finalArgs, args)
	finalArgs = append(finalArgs, limit, offset)

	// Execute the query
	rows, err := r.client.Query(ctx, searchQuery, finalArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search admin roles: %w", err)
	}
	defer rows.Close()

	roles := make([]*models.AdminRole, 0, limit)
	for rows.Next() {
		var role models.AdminRole
		var isSystemRole bool
		err := rows.Scan(
			&role.AdminRoleID,
			&role.RoleName,
			&role.RoleLevel,
			&role.RoleType,
			&isSystemRole,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan admin role: %w", err)
		}
		role.IsSystemRole = isSystemRole
		roles = append(roles, &role)
	}

	r.recordQuery()
	return roles, totalCount, nil
}

// Implementation in PostgreSQL repository
func (r *AdminRepositoryPostgres) GetAdminWithEncryptedPhone(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
	query := `
        SELECT 
            admin_id, username, full_name, phone_hash, 
            phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, 
            is_active, admin_created_at, admin_updated_at
        FROM admin_users 
        WHERE admin_id = $1
    `

	var admin models.AdminUser
	err := r.client.QueryRow(ctx, query, adminID).Scan(
		&admin.AdminID,
		&admin.Username,
		&admin.FullName,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&admin.PhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&admin.AdminRoleID,
		&admin.RoleType,
		&admin.ReportsTo,
		&admin.IsActive,
		&admin.AdminCreatedAt,
		&admin.AdminUpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &admin, nil
}

// Add these methods to AdminRepositoryPostgres

// GetSuperAdminRole retrieves the super admin role
func (r *AdminRepositoryPostgres) GetSuperAdminRole(ctx context.Context) (*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles 
        WHERE role_type = $1 
        LIMIT 1`

	var role models.AdminRole
	err := r.client.QueryRow(ctx, query, models.RoleTypeSuperAdmin).Scan(
		&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
		&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get super admin role: %w", err)
	}

	return &role, nil
}

func (r *AdminRepositoryPostgres) CreateSuperAdminRole(
	ctx context.Context,
	role *models.AdminRole,
	departmentIDs []uuid.UUID,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Create the super admin role
	roleQuery := `
        INSERT INTO admin_roles (
            admin_role_id, role_name, role_level, role_type, is_system_role,
            description, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = tx.ExecContext(ctx, roleQuery,
		role.AdminRoleID, role.RoleName, role.RoleLevel, role.RoleType,
		role.IsSystemRole, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create super admin role: %w", err)
	}

	// 2. Assign ALL system departments (ignore provided departmentIDs, get ALL)
	deptQuery := `
        INSERT INTO admin_role_departments (admin_role_id, system_department_id, created_at)
        SELECT $1, system_department_id, NOW()
        FROM system_departments
        ON CONFLICT (admin_role_id, system_department_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, deptQuery, role.AdminRoleID)
	if err != nil {
		return fmt.Errorf("failed to assign ALL departments to super admin role: %w", err)
	}

	// 3. Grant ALL permissions (NO scope filter - get ALL permissions)
	permQuery := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, NOW()
        FROM permissions  -- NO WHERE clause - get ALL permissions
        ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, permQuery, role.AdminRoleID, uuid.Nil)
	if err != nil {
		return fmt.Errorf("failed to grant ALL permissions to super admin role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Super admin role created with ALL permissions and ALL departments",
		util.String("role_id", role.AdminRoleID.String()),
		util.String("role_name", role.RoleName))
	return nil
}

// CreateSuperAdminUser creates a super admin user
func (r *AdminRepositoryPostgres) CreateSuperAdminUser(ctx context.Context, admin *models.AdminUser) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create admin user
	query := `
        INSERT INTO admin_users (
            admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
            admin_role_id, role_type, reports_to, admin_created_at, admin_created_by,
            admin_updated_at, is_active, data_access_scope, ip_whitelist,
            failed_login_attempts, username, full_name
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	_, err = tx.ExecContext(ctx, query,
		admin.AdminID, admin.PhoneHash, admin.PhoneEncrypted, admin.PhoneKeyID,
		admin.PhoneEncryptedDEK, admin.AdminRoleID, admin.RoleType, admin.ReportsTo,
		admin.AdminCreatedAt, admin.AdminCreatedBy, admin.AdminUpdatedAt, admin.IsActive,
		pq.Array(admin.DataAccessScope), pq.Array(admin.IPWhitelist),
		admin.FailedLoginAttempts, admin.Username, admin.FullName,
	)
	if err != nil {
		return fmt.Errorf("failed to create super admin user: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Super admin user created",
		util.String("admin_id", admin.AdminID.String()),
		util.String("username", admin.Username),
		util.String("full_name", admin.FullName))

	return nil
}

// GetAllAdminPermissions gets all admin permissions
func (r *AdminRepositoryPostgres) GetAllAdminPermissions(ctx context.Context) ([]*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description,
               category, module, scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE scope IN ('admin', 'both')
        ORDER BY bit_index`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all admin permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.Scope, &perm.RequiresTier,
			&bitIndex, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}
		permissions = append(permissions, &perm)
	}

	return permissions, nil
}

func (r *AdminRepositoryPostgres) GrantAllPermissionsToRole(
	ctx context.Context,
	roleID uuid.UUID,
	grantedBy uuid.UUID,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Grant ALL permissions (no scope filter)
	permQuery := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, NOW()
        FROM permissions  -- ALL permissions
        ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, permQuery, roleID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to grant all permissions to role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("ALL permissions granted to role",
		util.String("role_id", roleID.String()),
		util.String("granted_by", grantedBy.String()))
	return nil
}

// // GrantAllPermissionsToRole grants all admin permissions to a role
// func (r *AdminRepositoryPostgres) GrantAllPermissionsToRole(
//     ctx context.Context,
//     roleID uuid.UUID,
//     grantedBy uuid.UUID,
// ) error {
//     tx, err := r.client.BeginTx(ctx, nil)
//     if err != nil {
//         return fmt.Errorf("failed to begin transaction: %w", err)
//     }
//     defer tx.Rollback()

//     // FIXED: Removed scope filter to get ALL permissions (254 permissions)
//     permQuery := `SELECT permission_id FROM permissions`
//     rows, err := tx.QueryContext(ctx, permQuery)
//     if err != nil {
//         return fmt.Errorf("failed to get permissions: %w", err)
//     }
//     defer rows.Close()

//     var permissionIDs []uuid.UUID
//     for rows.Next() {
//         var permID uuid.UUID
//         if err := rows.Scan(&permID); err != nil {
//             return fmt.Errorf("failed to scan permission ID: %w", err)
//         }
//         permissionIDs = append(permissionIDs, permID)
//     }

//     grantQuery := `
//         INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
//         VALUES ($1, $2, $3, NOW())
//         ON CONFLICT (admin_role_id, permission_id) DO NOTHING`

//     permissionCount := 0
//     for _, permID := range permissionIDs {
//         _, err := tx.ExecContext(ctx, grantQuery, roleID, permID, grantedBy)
//         if err != nil {
//             return fmt.Errorf("failed to grant permission: %w", err)
//         }
//         permissionCount++
//     }

//     if err := tx.Commit(); err != nil {
//         return fmt.Errorf("failed to commit transaction: %w", err)
//     }

//     r.logger.Info("ALL permissions granted to role",
//         util.String("role_id", roleID.String()),
//         util.Int("permissions_granted", permissionCount))
//     return nil
// }

func (r *AdminRepositoryPostgres) DebugSuperAdminInit(ctx context.Context) error {
	r.logger.Info("DEBUG: Checking database state...")

	// Check if super admin role exists
	var roleCount int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM admin_roles WHERE role_type = 4").Scan(&roleCount)
	if err != nil {
		r.logger.Error("DEBUG: Failed to count super admin roles", util.ErrorField(err))
		return err
	}
	r.logger.Info(fmt.Sprintf("DEBUG: Super admin roles found: %d", roleCount))

	// Check permissions count
	var permCount int
	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM permissions").Scan(&permCount)
	if err != nil {
		r.logger.Error("DEBUG: Failed to count permissions", util.ErrorField(err))
		return err
	}
	r.logger.Info(fmt.Sprintf("DEBUG: Total permissions in system: %d", permCount))

	// Check departments count
	var deptCount int
	err = r.client.QueryRow(ctx, "SELECT COUNT(*) FROM system_departments").Scan(&deptCount)
	if err != nil {
		r.logger.Error("DEBUG: Failed to count departments", util.ErrorField(err))
		return err
	}
	r.logger.Info(fmt.Sprintf("DEBUG: Total departments in system: %d", deptCount))

	return nil
}

// postgres/admin_repository.go - Add this method

// IsPermissionGrantedToRole checks if a permission is already granted to a role
func (r *AdminRepositoryPostgres) IsPermissionGrantedToRole(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1 FROM admin_role_permissions 
            WHERE admin_role_id = $1 AND permission_id = $2
        )`

	var exists bool
	err := r.client.QueryRow(ctx, query, roleID, permissionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check permission grant: %w", err)
	}

	return exists, nil
}

// GetPermissionByName retrieves a permission by its name
func (r *AdminRepositoryPostgres) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description, category, 
               module, scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE permission_name = $1
        AND (scope = 'admin' OR scope = 'both')`

	var perm models.Permission
	err := r.client.QueryRow(ctx, query, name).Scan(
		&perm.PermissionID, &perm.PermissionName, &perm.Description, &perm.Category,
		&perm.Module, &perm.Scope, &perm.RequiresTier, &perm.BitIndex, &perm.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("permission not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	return &perm, nil
}

// RevokePermissionFromAdminRole removes a permission from a role
func (r *AdminRepositoryPostgres) RevokePermissionFromAdminRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM admin_role_permissions WHERE admin_role_id = $1 AND permission_id = $2`
	result, err := r.client.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Permission not granted, but that's okay
		r.logger.Debug("Permission not found for revocation",
			util.String("role_id", roleID.String()),
			util.String("permission_id", permissionID.String()))
	}

	r.logger.Info("Permission revoked from admin role",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()))

	return nil
}

// GetEmployeeAdminRoles returns all admin roles available for employees (role_type = 1)
func (r *AdminRepositoryPostgres) GetEmployeeAdminRoles(ctx context.Context) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_name`

	rows, err := r.client.Query(ctx, query, models.RoleTypeEmployee)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get employee admin roles: %w", err)
	}
	defer rows.Close()

	roles := make([]*models.AdminRole, 0)
	for rows.Next() {
		var role models.AdminRole
		err := rows.Scan(
			&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
			&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan admin role row", util.ErrorField(err))
			continue
		}
		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee admin role rows: %w", err)
	}

	r.recordQuery()
	return roles, nil
}

// GetManagerAdminRoles returns all admin roles available for managers (role_type = 2)
func (r *AdminRepositoryPostgres) GetManagerAdminRoles(ctx context.Context) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_name`

	rows, err := r.client.Query(ctx, query, models.RoleTypeManager)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get manager admin roles: %w", err)
	}
	defer rows.Close()

	roles := make([]*models.AdminRole, 0)
	for rows.Next() {
		var role models.AdminRole
		err := rows.Scan(
			&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
			&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan admin role row", util.ErrorField(err))
			continue
		}
		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating manager admin role rows: %w", err)
	}

	r.recordQuery()
	return roles, nil
}

// GetAdminRolesByType returns admin roles filtered by role type
func (r *AdminRepositoryPostgres) GetAdminRolesByType(ctx context.Context, roleType int) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_level DESC, role_name`

	rows, err := r.client.Query(ctx, query, roleType)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get admin roles by type %d: %w", roleType, err)
	}
	defer rows.Close()

	roles := make([]*models.AdminRole, 0)
	for rows.Next() {
		var role models.AdminRole
		err := rows.Scan(
			&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
			&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan admin role row", util.ErrorField(err))
			continue
		}
		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating admin role rows: %w", err)
	}

	r.recordQuery()
	return roles, nil
}
func (r *AdminRepositoryPostgres) SearchAdminUsers(ctx context.Context, req *models.AdminUserSearchRequest) ([]*models.AdminUserSearchResult, int, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Ensure search_type has a default value
	if req.SearchType == "" {
		req.SearchType = "all"
	}

	query := `
        SELECT
            admin_id, username, full_name, phone_hash,
            role_name, admin_role_id, role_type,
            reports_to, reports_to_name,
            is_active, last_login, admin_created_at,
            relevance_score, match_type
        FROM search_admin_users($1, $2, $3, $4, $5, $6)`

	var roleTypeFilter interface{}
	if req.RoleTypeFilter != nil {
		roleTypeFilter = *req.RoleTypeFilter
	} else {
		roleTypeFilter = nil
	}

	rows, err := r.client.Query(ctx, query,
		req.Query,           // $1: search_query
		roleTypeFilter,      // $2: role_type_filter (NULL if not specified)
		req.IncludeInactive, // $3: include_inactive
		req.SearchType,      // $4: search_type
		req.Limit,           // $5: limit_count
		req.Offset,          // $6: offset_count
	)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search admin users: %w", err)
	}
	defer rows.Close()

	results, err := r.scanAdminSearchResults(rows)
	if err != nil {
		return nil, 0, err
	}

	totalCount, err := r.countAdminUserSearchResults(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	r.recordQuery()
	return results, totalCount, nil
}

// In AdminRepositoryPostgres
func (r *AdminRepositoryPostgres) GetAdminRoleByName(ctx context.Context, roleName string) (*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles WHERE role_name = $1`

	var role models.AdminRole
	err := r.client.QueryRow(ctx, query, roleName).Scan(
		&role.AdminRoleID, &role.RoleName, &role.RoleLevel, &role.RoleType,
		&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get admin role by name: %w", err)
	}

	r.recordQuery()
	return &role, nil
}
