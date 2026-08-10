package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/rbac"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	DefaultAdminPageSize = 100
	MaxAdminBatchSize    = 500
)

type AdminRepositoryPostgres struct {
	client *client.PostgresClient
}

// NewAdminRepositoryPostgres creates a new repository instance.
func NewAdminRepositoryPostgres(client *client.PostgresClient) *AdminRepositoryPostgres {
	return &AdminRepositoryPostgres{
		client: client,
	}
}

// Close implements the AdminRepository interface.
// No resources to clean up in this version.
func (r *AdminRepositoryPostgres) Close() error {
	return nil
}

// ---- Core Admin Queries ----

// GetAdminByID retrieves an admin by its UUID.
// Returns apperrors.ErrNotFound if not found.
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

// GetAdminByPhoneHash retrieves an admin by phone hash.
// Returns apperrors.ErrNotFound if not found.
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

// GetAdminByUsername retrieves an admin by username.
// Returns apperrors.ErrNotFound if not found.
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

// ---- Updates ----

// UpdateAdminReportsTo updates the reports_to field for an admin.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateAdminProfile updates username and full_name.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateAdminLastLogin updates last_login timestamp.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		return apperrors.ErrNotFound
	}
	return nil
}

// DeactivateAdmin deactivates an admin and updates reports_to of direct reports to NULL.
// Returns apperrors.ErrNotFound if admin does not exist.
func (r *AdminRepositoryPostgres) DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error {
	updateReportsQuery := `
        UPDATE admin_users
        SET reports_to = NULL, admin_updated_at = $1
        WHERE reports_to = $2 AND is_active = true`
	_, _ = r.client.Exec(ctx, updateReportsQuery, time.Now().UTC(), adminID) // ignore error

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
		return apperrors.ErrNotFound
	}
	return nil
}

// ActivateAdmin activates an admin.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		return apperrors.ErrNotFound
	}
	return nil
}

// IncrementAdminFailedLoginAttempts increments failed attempts and returns new count.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		if err == sql.ErrNoRows {
			return 0, apperrors.ErrNotFound
		}
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
		return newAttempts, apperrors.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return newAttempts, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return newAttempts, nil
}

// ResetAdminFailedLoginAttempts resets failed attempts to zero.
// Returns apperrors.ErrNotFound if admin does not exist.
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
		return apperrors.ErrNotFound
	}
	return nil
}

// ---- Admin User Management ----

// CreateAdminUser creates a new admin user.
// Returns apperrors.ErrDuplicate if username already exists.
func (r *AdminRepositoryPostgres) CreateAdminUser(ctx context.Context, admin *models.AdminUser) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var exists bool
	checkQuery := `SELECT COUNT(*) > 0 FROM admin_users WHERE username = $1`
	err = tx.QueryRowContext(ctx, checkQuery, admin.Username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check username: %w", err)
	}
	if exists {
		return apperrors.ErrDuplicate
	}

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
	return nil
}

// UpdateAdminUser updates fields on an admin user.
// Returns apperrors.ErrNotFound if admin not found.
// Returns apperrors.ErrInvalidInput for restricted fields or empty updates.
func (r *AdminRepositoryPostgres) UpdateAdminUser(ctx context.Context, adminID uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return apperrors.ErrInvalidInput
	}
	restrictedFields := []string{"admin_id", "admin_created_at", "admin_created_by"}
	for field := range updates {
		for _, restricted := range restrictedFields {
			if field == restricted {
				return apperrors.ErrInvalidInput
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
		return fmt.Errorf("failed to update admin user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeleteAdminUser deletes an admin user and reassigns reports.
// Returns apperrors.ErrNotFound if admin not found.
func (r *AdminRepositoryPostgres) DeleteAdminUser(ctx context.Context, adminID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var reportCount int
	checkQuery := `SELECT COUNT(*) FROM admin_users WHERE reports_to = $1 AND is_active = true`
	err = tx.QueryRowContext(ctx, checkQuery, adminID).Scan(&reportCount)
	if err != nil {
		return fmt.Errorf("failed to check reports: %w", err)
	}
	if reportCount > 0 {
		_, err = tx.ExecContext(ctx,
			"UPDATE admin_users SET reports_to = NULL, admin_updated_at = $1 WHERE reports_to = $2",
			time.Now().UTC(), adminID)
		if err != nil {
			return fmt.Errorf("failed to reassign reports: %w", err)
		}
	}
	deleteQuery := `DELETE FROM admin_users WHERE admin_id = $1`
	result, err := tx.ExecContext(ctx, deleteQuery, adminID)
	if err != nil {
		return fmt.Errorf("failed to delete admin user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ---- Hierarchical queries ----

// GetAdminHierarchy returns the reporting hierarchy for an admin.
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

// GetDirectReports returns all active admins reporting directly to the given admin.
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

// GetReportingChain returns the full reporting chain for an admin (including self).
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

// CanAssignReportsTo checks if assigner can assign reports to target.
func (r *AdminRepositoryPostgres) CanAssignReportsTo(ctx context.Context, assignerID, targetID uuid.UUID) (bool, error) {
	var assignerRoleType, targetRoleType int
	query := `SELECT role_type FROM admin_users WHERE admin_id = $1`
	err := r.client.QueryRow(ctx, query, assignerID).Scan(&assignerRoleType)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, apperrors.ErrNotFound
		}
		return false, fmt.Errorf("failed to get assigner role type: %w", err)
	}
	err = r.client.QueryRow(ctx, query, targetID).Scan(&targetRoleType)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, apperrors.ErrNotFound
		}
		return false, fmt.Errorf("failed to get target role type: %w", err)
	}
	if assignerRoleType == models.RoleTypeSuperAdmin {
		return true, nil
	}
	if assignerRoleType == models.RoleTypeManager {
		return targetRoleType == models.RoleTypeEmployee, nil
	}
	return false, nil
}

// BulkUpdateReportsTo updates reports_to for multiple admins.
func (r *AdminRepositoryPostgres) BulkUpdateReportsTo(ctx context.Context, adminIDs []uuid.UUID, reportsTo *uuid.UUID) error {
	if len(adminIDs) == 0 {
		return nil
	}
	query := `
        UPDATE admin_users
        SET reports_to = $1, admin_updated_at = $2
        WHERE admin_id = ANY($3)`
	_, err := r.client.Exec(ctx, query, reportsTo, time.Now().UTC(), pq.Array(adminIDs))
	if err != nil {
		return fmt.Errorf("failed to bulk update reports_to: %w", err)
	}
	return nil
}

// GetAvailableManagers returns active managers and super admins.
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

// GetAdminWithReportsToName returns admin details including reports_to name.
// Returns apperrors.ErrNotFound if admin does not exist.
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
			return nil, apperrors.ErrNotFound
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

// ---- List functions ----

// GetAllAdmins returns all admins with limit.
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

// GetActiveAdmins returns active admins with limit.
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

// GetAdminsByRoleType returns admins filtered by role type.
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

// GetAdminsByRole returns admins by role ID.
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

// ---- Search and Suggestions ----

// SearchAdmins performs a flexible search using the search_admin_users function.
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

// GetAdminSuggestions returns admin suggestions for autocomplete.
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

// ---- Permissions and Bitmask ----

// GetAdminWithPermissions returns admin with permissions and departments.
// Returns apperrors.ErrNotFound if admin does not exist.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin with permissions: %w", err)
	}
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

// AdminHasPermission checks if admin has a specific permission.
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

// AdminHasDepartmentAccess checks if admin has access to a department bitmask.
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

// GetAdminPermissionBitmask returns bitmask for an admin.
func (r *AdminRepositoryPostgres) GetAdminPermissionBitmask(
	ctx context.Context,
	adminID uuid.UUID,
) ([]uint64, error) {
	var roleID uuid.UUID
	query := `SELECT admin_role_id FROM admin_users WHERE admin_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, query, adminID).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return []uint64{}, nil
		}
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}
	return r.GetAdminRolePermissionBitmask(ctx, roleID)
}

// GetAdminRolePermissionBitmask returns bitmask for a role.
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
	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

// GetAdminPermissionsWithBitIndex returns all admin permissions with bit index.
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetAdminPermissionsByBitPositions returns permissions for given bit positions.
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
	return permissions, nil
}

// GetAdminPermissionBitIndexes returns mapping of permission names to bit indexes.
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
			continue
		}
		result[name] = uint64(bitIndex)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission bit index rows: %w", err)
	}
	return result, nil
}

// ---- Admin Roles ----

// CreateAdminRole creates a new admin role with default permissions.
func (r *AdminRepositoryPostgres) CreateAdminRole(ctx context.Context, role *models.AdminRole, departmentIDs []uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

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

	err = r.grantDefaultPermissions(ctx, tx, role.AdminRoleID, role.RoleType, departmentIDs)
	if err != nil {
		return fmt.Errorf("failed to grant default permissions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// GetAdminRole retrieves an admin role by ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}
	return &role, nil
}

// GetAdminRoles returns a paginated list of admin roles.
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM admin_roles %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count admin roles: %w", err)
	}
	query := fmt.Sprintf(`
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles %s
        ORDER BY role_level DESC, role_name ASC
        LIMIT $%d OFFSET $%d`, whereClause, argCounter, argCounter+1)
	args = append(args, limit, offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
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
			continue
		}
		roles = append(roles, &role)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating admin role rows: %w", err)
	}
	return roles, totalCount, nil
}

// UpdateAdminRole updates a non-system role.
// Returns apperrors.ErrNotFound if role not found or is system.
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
		return fmt.Errorf("failed to update admin role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeleteAdminRole deletes a non-system role if not in use.
// Returns apperrors.ErrConflict if role is in use.
func (r *AdminRepositoryPostgres) DeleteAdminRole(ctx context.Context, roleID uuid.UUID) error {
	var inUseCount int
	checkQuery := `SELECT COUNT(*) FROM admin_users WHERE admin_role_id = $1`
	err := r.client.QueryRow(ctx, checkQuery, roleID).Scan(&inUseCount)
	if err != nil {
		return fmt.Errorf("failed to check role usage: %w", err)
	}
	if inUseCount > 0 {
		return apperrors.ErrConflict
	}
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM admin_role_permissions WHERE admin_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role permissions: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM admin_role_departments WHERE admin_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role departments: %w", err)
	}
	deleteQuery := `DELETE FROM admin_roles WHERE admin_role_id = $1 AND is_system_role = false`
	result, err := tx.ExecContext(ctx, deleteQuery, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete admin role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// GetAdminRolePermissions returns permissions for a role.
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
	return permissions, nil
}

// GetAdminUserPermissions returns distinct permissions for an admin.
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
	return permissions, nil
}

// GrantPermissionToAdminRole grants a permission to a role.
func (r *AdminRepositoryPostgres) GrantPermissionToAdminRole(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	query := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (admin_role_id, permission_id) DO UPDATE SET
            granted_by = EXCLUDED.granted_by,
            granted_at = EXCLUDED.granted_at`
	_, err := r.client.Exec(ctx, query, roleID, permissionID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to grant permission to admin role: %w", err)
	}
	return nil
}

// RevokePermissionFromAdminRole revokes a permission from a role.
func (r *AdminRepositoryPostgres) RevokePermissionFromAdminRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM admin_role_permissions WHERE admin_role_id = $1 AND permission_id = $2`
	_, err := r.client.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}
	return nil
}

// ---- Department Helpers ----

// GetAdminRoleDepartments returns departments assigned to a role.
func (r *AdminRepositoryPostgres) GetAdminRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.SystemDepartment, error) {
	query := `
        SELECT sd.system_department_id, sd.name, sd.module_code, sd.description, sd.bitmask
        FROM admin_role_departments ard
        INNER JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
        WHERE ard.admin_role_id = $1
        ORDER BY sd.name`
	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
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
			continue
		}
		departments = append(departments, &dept)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}
	return departments, nil
}

// AssignDepartmentToAdminRole assigns a department to a role and syncs permissions.
// Returns apperrors.ErrNotFound if department does not exist.
func (r *AdminRepositoryPostgres) AssignDepartmentToAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error {
	var deptExists bool
	checkQuery := `SELECT COUNT(*) > 0 FROM system_departments WHERE system_department_id = $1`
	err := r.client.QueryRow(ctx, checkQuery, departmentID).Scan(&deptExists)
	if err != nil {
		return fmt.Errorf("failed to check department: %w", err)
	}
	if !deptExists {
		return apperrors.ErrNotFound
	}
	query := `
        INSERT INTO admin_role_departments (admin_role_id, system_department_id)
        VALUES ($1, $2)
        ON CONFLICT (admin_role_id, system_department_id) DO NOTHING`
	_, err = r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to assign department to admin role: %w", err)
	}
	err = r.syncRolePermissionsFromDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to sync permissions: %w", err)
	}
	return nil
}

// RemoveDepartmentFromAdminRole removes a department from a role and syncs permissions.
// Returns apperrors.ErrNotFound if association not found.
func (r *AdminRepositoryPostgres) RemoveDepartmentFromAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `DELETE FROM admin_role_departments WHERE admin_role_id = $1 AND system_department_id = $2`
	result, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to remove department from admin role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	err = r.syncRolePermissionsFromDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to sync permissions: %w", err)
	}
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
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
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

	err = r.grantDefaultPermissions(ctx, tx, roleID, roleType, deptIDs)
	if err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ---- System Departments ----

// GetAdminSystemDepartments returns system departments for admin modules.
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
	return systemDepartments, nil
}

// GetAdminSystemDepartmentByModule returns department by module code.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin system department: %w", err)
	}
	return &dept, nil
}

// GetAdminSystemDepartment returns department by ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin system department: %w", err)
	}
	return &dept, nil
}

// GetAdminDepartmentBitmask returns bitmask for a department name.
// Returns apperrors.ErrNotFound if not found.
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
			return 0, apperrors.ErrNotFound
		}
		return 0, fmt.Errorf("failed to get admin department bitmask: %w", err)
	}
	return bitmask, nil
}

// GetAdminPermissionsByModules returns permissions for a list of modules.
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
	return permissions, nil
}

// GetAdminPermissionsBySystemDepartments returns permissions filtered by departments.
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
	return permissions, nil
}

// ---- Advanced Search ----

// SearchAdminsAdvanced performs advanced admin search with filters.
// SearchAdminsAdvanced performs advanced admin search with filters.
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
	var conditions []string
	var args []interface{}
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
			conditions = append(conditions, `
                EXISTS (
                    SELECT 1 FROM admin_avatars aa
                    WHERE aa.admin_id = au.admin_id
                    AND aa.is_active = true
                    AND aa.is_primary = true
                )
            `)
		} else {
			conditions = append(conditions, `
                NOT EXISTS (
                    SELECT 1 FROM admin_avatars aa
                    WHERE aa.admin_id = au.admin_id
                    AND aa.is_active = true
                    AND aa.is_primary = true
                )
            `)
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
	if !req.IncludeInactive {
		conditions = append(conditions, "au.is_active = true")
	}
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
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
	return results, totalCount, nil
}

// GetAdminsByDepartment returns admins belonging to a department.
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
	return results, totalCount, nil
}

// SearchAdminRoles searches admin roles by name/description.
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
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1
	if query != "" {
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM admin_roles %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count admin roles: %w", err)
	}
	orderByClause := ""
	if query != "" {
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
	finalArgs := make([]interface{}, len(args))
	copy(finalArgs, args)
	finalArgs = append(finalArgs, limit, offset)
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
			continue
		}
		role.IsSystemRole = isSystemRole
		roles = append(roles, &role)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating role rows: %w", err)
	}
	return roles, totalCount, nil
}

// GetAdminWithEncryptedPhone returns admin with encrypted phone fields.
// Returns apperrors.ErrNotFound if not found.
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
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get admin with encrypted phone: %w", err)
	}
	return &admin, nil
}

// GetSuperAdminRole returns the super admin role.
// Returns nil, nil if none found.
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

// CreateSuperAdminRole creates a super admin role with all permissions and departments.
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
	deptQuery := `
        INSERT INTO admin_role_departments (admin_role_id, system_department_id, created_at)
        SELECT $1, system_department_id, NOW()
        FROM system_departments
        ON CONFLICT (admin_role_id, system_department_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, deptQuery, role.AdminRoleID)
	if err != nil {
		return fmt.Errorf("failed to assign ALL departments to super admin role: %w", err)
	}
	permQuery := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, NOW()
        FROM permissions
        ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, permQuery, role.AdminRoleID, uuid.Nil)
	if err != nil {
		return fmt.Errorf("failed to grant ALL permissions to super admin role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// CreateSuperAdminUser creates a super admin user.
func (r *AdminRepositoryPostgres) CreateSuperAdminUser(ctx context.Context, admin *models.AdminUser) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
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
	return nil
}

// GetAllAdminPermissions returns all permissions with scope 'admin' or 'both'.
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
	return permissions, nil
}

// GrantAllPermissionsToRole grants all permissions to a role.
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
	permQuery := `
        INSERT INTO admin_role_permissions (admin_role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, NOW()
        FROM permissions
        ON CONFLICT (admin_role_id, permission_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, permQuery, roleID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to grant all permissions to role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// IsPermissionGrantedToRole checks if a permission is granted to a role.
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

// GetPermissionByName returns a permission by name.
// Returns apperrors.ErrNotFound if not found.
func (r *AdminRepositoryPostgres) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description, category,
               module, scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE permission_name = $1`
	var perm models.Permission
	var bitIndex sql.NullInt32
	err := r.client.QueryRow(ctx, query, name).Scan(
		&perm.PermissionID, &perm.PermissionName, &perm.Description, &perm.Category,
		&perm.Module, &perm.Scope, &perm.RequiresTier, &bitIndex, &perm.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	if bitIndex.Valid {
		perm.BitIndex = int(bitIndex.Int32)
	}
	return &perm, nil
}

// GetEmployeeAdminRoles returns roles of type Employee.
func (r *AdminRepositoryPostgres) GetEmployeeAdminRoles(ctx context.Context) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_name`
	rows, err := r.client.Query(ctx, query, models.RoleTypeEmployee)
	if err != nil {
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
			continue
		}
		roles = append(roles, &role)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee admin role rows: %w", err)
	}
	return roles, nil
}

// GetManagerAdminRoles returns roles of type Manager.
func (r *AdminRepositoryPostgres) GetManagerAdminRoles(ctx context.Context) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_name`
	rows, err := r.client.Query(ctx, query, models.RoleTypeManager)
	if err != nil {
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
			continue
		}
		roles = append(roles, &role)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating manager admin role rows: %w", err)
	}
	return roles, nil
}

// GetAdminRolesByType returns roles by role type.
func (r *AdminRepositoryPostgres) GetAdminRolesByType(ctx context.Context, roleType int) ([]*models.AdminRole, error) {
	query := `
        SELECT admin_role_id, role_name, role_level, role_type,
               is_system_role, description, created_at, updated_at
        FROM admin_roles
        WHERE role_type = $1
        ORDER BY role_level DESC, role_name`
	rows, err := r.client.Query(ctx, query, roleType)
	if err != nil {
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
			continue
		}
		roles = append(roles, &role)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating admin role rows: %w", err)
	}
	return roles, nil
}

// GetAdminRoleByName returns role by name (case-sensitive).
// Returns nil, nil if not found.
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
		return nil, fmt.Errorf("failed to get admin role by name: %w", err)
	}
	return &role, nil
}

// GetAdminDepartments returns departments accessible by an admin.
func (r *AdminRepositoryPostgres) GetAdminDepartments(
	ctx context.Context,
	adminID uuid.UUID,
) ([]*models.SystemDepartment, error) {
	query := `
        SELECT DISTINCT
            sd.system_department_id,
            sd.name,
            sd.module_code,
            sd.description,
            sd.bitmask
        FROM admin_users au
        INNER JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        INNER JOIN admin_role_departments ard ON ar.admin_role_id = ard.admin_role_id
        INNER JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
        WHERE au.admin_id = $1
        AND au.is_active = true
        ORDER BY sd.name`
	rows, err := r.client.Query(ctx, query, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin departments: %w", err)
	}
	defer rows.Close()
	var departments []*models.SystemDepartment
	for rows.Next() {
		var dept models.SystemDepartment
		err := rows.Scan(
			&dept.SystemDepartmentID,
			&dept.Name,
			&dept.ModuleCode,
			&dept.Description,
			&dept.Bitmask,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan department: %w", err)
		}
		departments = append(departments, &dept)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}
	return departments, nil
}

// SearchAdminUsers performs a search using the search_admin_users function.
func (r *AdminRepositoryPostgres) SearchAdminUsers(
	ctx context.Context,
	req *models.AdminUserSearchRequest,
) ([]*models.AdminUserSearchResult, int, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.SearchType == "" {
		req.SearchType = "autocomplete"
	}
	query := `
		SELECT
			admin_id,
			username,
			full_name,
			phone_hash,
			role_name,
			admin_role_id,
			role_type,
			reports_to,
			reports_to_name,
			is_active,
			last_login,
			admin_created_at,
			relevance_score::float8 AS relevance_score,
			match_type
		FROM search_admin_users(
			$1::text,
			$2::int,
			$3::boolean,
			$4::text,
			$5::int,
			$6::int
		)
	`
	var roleTypeFilter interface{}
	if req.RoleTypeFilter != nil {
		roleTypeFilter = *req.RoleTypeFilter
	} else {
		roleTypeFilter = nil
	}
	rows, err := r.client.Query(
		ctx,
		query,
		req.Query,
		roleTypeFilter,
		req.IncludeInactive,
		req.SearchType,
		req.Limit,
		req.Offset,
	)
	if err != nil {
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
	return results, totalCount, nil
}

// UpdateAdminUserRole updates an admin's role.
// Returns apperrors.ErrNotFound if admin or role not found.
// Returns apperrors.ErrPermissionDenied if attempting to change super admin role.
func (r *AdminRepositoryPostgres) UpdateAdminUserRole(
	ctx context.Context,
	adminID uuid.UUID,
	newRoleID uuid.UUID,
) error {
	if adminID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}
	if newRoleID == uuid.Nil {
		return apperrors.ErrInvalidInput
	}
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var newRoleType int
	err = tx.QueryRowContext(
		ctx,
		`SELECT role_type FROM admin_roles WHERE admin_role_id = $1`,
		newRoleID,
	).Scan(&newRoleType)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		return fmt.Errorf("failed to fetch admin role: %w", err)
	}
	if newRoleType == models.RoleTypeSuperAdmin {
		return apperrors.ErrPermissionDenied
	}
	var currentRoleID uuid.UUID
	var currentRoleType int
	err = tx.QueryRowContext(
		ctx,
		`
		SELECT admin_role_id, role_type
		FROM admin_users
		WHERE admin_id = $1
		FOR UPDATE
		`,
		adminID,
	).Scan(&currentRoleID, &currentRoleType)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		return fmt.Errorf("failed to fetch admin user: %w", err)
	}
	if currentRoleType == models.RoleTypeSuperAdmin {
		return apperrors.ErrPermissionDenied
	}
	if currentRoleID == newRoleID {
		return nil
	}
	result, err := tx.ExecContext(
		ctx,
		`
		UPDATE admin_users
		SET admin_role_id = $1,
		    role_type     = $2,
		    admin_updated_at = NOW()
		WHERE admin_id = $3
		`,
		newRoleID,
		newRoleType,
		adminID,
	)
	if err != nil {
		return fmt.Errorf("failed to update admin user role: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// UpdateAdminPhone updates an admin's phone fields.
// Returns apperrors.ErrNotFound if admin not found.
// Returns apperrors.ErrPermissionDenied if attempting to update super admin phone.
func (r *AdminRepositoryPostgres) UpdateAdminPhone(
	ctx context.Context,
	adminID uuid.UUID,
	phoneHash string,
	phoneEncrypted []byte,
	phoneKeyID uuid.UUID,
	phoneEncryptedDEK string,
) error {
	var roleType int
	err := r.client.QueryRow(ctx,
		`SELECT role_type FROM admin_users WHERE admin_id = $1`,
		adminID,
	).Scan(&roleType)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		return fmt.Errorf("failed to get admin role type: %w", err)
	}
	if roleType == models.RoleTypeSuperAdmin {
		return apperrors.ErrPermissionDenied
	}
	query := `
		UPDATE admin_users
		SET phone_hash = $1,
		    phone_encrypted = $2,
		    phone_key_id = $3,
		    phone_encrypted_dek = $4,
		    admin_updated_at = $5
		WHERE admin_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		phoneHash,
		phoneEncrypted,
		phoneKeyID,
		phoneEncryptedDEK,
		time.Now().UTC(),
		adminID,
	)
	if err != nil {
		return fmt.Errorf("failed to update admin phone: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---- Helpers (unexported) ----

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
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
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
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columns) == 19 {
		var level int
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
			&level,
		)
		if err != nil {
			return nil, err
		}
	} else if len(columns) == 18 {
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
	if roleType == models.RoleTypeManager {
		var modules []string
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
		if len(modules) == 0 {
			modules = []string{"employee_management", "manager_management"}
		}
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
	// Employee roles get no default permissions.
	return nil
}

// ---- Health and utilities ----

// HealthCheck checks database connectivity.
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

// GetRepositoryStats returns statistics about the repository.
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

// GetSuperAdmin returns the first active super admin.
// Returns nil, nil if none found.
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
		if err == apperrors.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return admin, nil
}

// IsSuperAdminExists checks if at least one active super admin exists.
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

// SetAdminAvatar sets a new primary avatar for the admin.
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
	_, err = tx.ExecContext(ctx, `
        UPDATE admin_avatars
        SET is_active = false, is_primary = false, updated_at = NOW()
        WHERE admin_id = $1 AND is_primary = true
    `, adminID)
	if err != nil {
		return err
	}
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
	return nil
}

// GetAdminAvatar returns the primary avatar for the admin, or nil if none.
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

// DeactivateAdminAvatar deactivates the primary avatar.
func (r *AdminRepositoryPostgres) DeactivateAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
) error {
	_, err := r.client.Exec(ctx, `
        UPDATE admin_avatars
        SET is_active = false, is_primary = false, updated_at = NOW()
        WHERE admin_id = $1 AND is_primary = true
    `, adminID)
	if err != nil {
		return err
	}
	return nil
}

// DebugSuperAdminInit is a debug helper (no-op).
func (r *AdminRepositoryPostgres) DebugSuperAdminInit(ctx context.Context) error {
	return nil
}
func (r *AdminRepositoryPostgres) GetAdminOnlyPermissions(ctx context.Context) ([]*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description,
               category, module, scope, requires_tier, bit_index, created_at
        FROM permissions
        WHERE scope = 'admin'
        ORDER BY bit_index`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin-only permissions: %w", err)
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
	return permissions, nil
}
