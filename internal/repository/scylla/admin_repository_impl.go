// internal/repository/scylla/admin_repository_impl.go
// REFACTORED - No hashing or encryption in repository layer

package scylla

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"
	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminRepositoryImpl implements AdminRepository interface
// Hashing and encryption moved to Service layer, so repo only stores model data
type AdminRepositoryImpl struct {
	client   *ScyllaClient
	logger   *zap.Logger

	// Prepared statements
	stmtGetAdminByID            *gocql.Query
	stmtGetAdminByPhoneHash     *gocql.Query
	stmtGetActiveAdmins         *gocql.Query
	stmtUpdateLastLogin         *gocql.Query
	stmtIncrementFailedAttempts *gocql.Query
	stmtMutex                   sync.RWMutex
}

// NewAdminRepository creates a new admin repository
func NewAdminRepository(
	client *ScyllaClient,
	logger *zap.Logger,
) AdminRepository {
	repo := &AdminRepositoryImpl{
		client: client,
		logger: logger,
	}
	repo.prepareStatements()
	return repo
}

// GetActiveAdmins retrieves only active admins
func (r *AdminRepositoryImpl) GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// ✅ FIX: Use base table with filter instead of materialized view
	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE is_active = true LIMIT ?`,
		limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var admins []*models.AdminUser

	for {
		var admin models.AdminUser
		var scannedID gocql.UUID
		var scannedCreatedBy gocql.UUID
		var scannedPhoneKeyID gocql.UUID

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &admin.AdminRoleLevel,
			&admin.AdminPermissions, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query active admins: %w", err)
	}

	return admins, nil
}

// prepareStatements prepares frequently used queries for better performance
func (r *AdminRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare GetAdminByID query
	r.stmtGetAdminByID = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE admin_id = ?`,
	)

	// Prepare GetAdminByPhoneHash query
	r.stmtGetAdminByPhoneHash = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE phone_hash = ?`,
	)

	// ✅ FIX: Update GetActiveAdmins to use base table with filter
	r.stmtGetActiveAdmins = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE is_active = true LIMIT ?`,
	)

	// Prepare UpdateLastLogin query
	r.stmtUpdateLastLogin = r.client.Session.Query(
		`UPDATE admin_users SET last_login = ? WHERE admin_id = ?`,
	)

	r.logger.Info("Prepared statements initialized for admin repository")
}

// GetAdminsByRole retrieves all admins with specific role level
func (r *AdminRepositoryImpl) GetAdminsByRole(ctx context.Context, roleLevel string) ([]*models.AdminUser, error) {
	// ✅ FIX: Use base table with ALLOW FILTERING instead of materialized view
	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE admin_role_level = ? ALLOW FILTERING`,
		roleLevel,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var admins []*models.AdminUser

	for {
		var admin models.AdminUser
		var scannedID gocql.UUID
		var scannedCreatedBy gocql.UUID
		var scannedPhoneKeyID gocql.UUID

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &admin.AdminRoleLevel,
			&admin.AdminPermissions, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query admins by role: %w", err)
	}

	return admins, nil
}

// ===== CORE OPERATIONS =====

// CreateAdmin creates a new admin user
// EXPECTS: All fields to be pre-hashed and pre-encrypted by service layer
func (r *AdminRepositoryImpl) CreateAdmin(ctx context.Context, admin *models.AdminUser) error {
	startTime := time.Now()

	// Validate admin data
	if admin.AdminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be nil")
	}
	if admin.PhoneHash == "" {
		return fmt.Errorf("phone hash cannot be empty")
	}
	if admin.AdminRoleLevel == "" {
		return fmt.Errorf("role level cannot be empty")
	}

	// Store fields as given (no hashing/encryption here)
	query := r.client.Session.Query(
		`INSERT INTO admin_users 
		 (admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
		  admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
		  admin_updated_at, is_active, data_access_scope, ip_whitelist, 
		  failed_login_attempts, last_login) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(admin.AdminID),
		admin.PhoneHash,        // ✅ Use pre-hashed value from service
		admin.PhoneEncrypted,   // ✅ Use pre-encrypted value from service
		gocql.UUID(admin.PhoneKeyID),
		admin.PhoneEncryptedDEK,
		admin.AdminRoleLevel,
		admin.AdminPermissions,
		admin.AdminCreatedAt,
		gocql.UUID(admin.AdminCreatedBy),
		admin.AdminUpdatedAt,
		admin.IsActive,
		admin.DataAccessScope,
		admin.IPWhitelist,
		admin.FailedLoginAttempts,
		admin.LastLogin,
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to create admin: %w", err)
	}

	r.logger.Info("Admin created successfully",
		util.String("admin_id", admin.AdminID.String()),
		util.String("role_level", admin.AdminRoleLevel),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// GetAdminByID retrieves an admin by their ID
func (r *AdminRepositoryImpl) GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
	r.stmtMutex.RLock()
	query := r.stmtGetAdminByID.Bind(gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	var admin models.AdminUser
	var scannedID gocql.UUID
	var scannedCreatedBy gocql.UUID
	var scannedPhoneKeyID gocql.UUID

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&scannedPhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&admin.AdminRoleLevel,
		&admin.AdminPermissions,
		&admin.AdminCreatedAt,
		&scannedCreatedBy,
		&admin.AdminUpdatedAt,
		&admin.IsActive,
		&admin.DataAccessScope,
		&admin.IPWhitelist,
		&admin.FailedLoginAttempts,
		&admin.LastLogin,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("admin not found with ID: %s", adminID)
		}
		return nil, fmt.Errorf("failed to get admin: %w", err)
	}

	admin.AdminID = uuid.UUID(scannedID)
	admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
	admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)

	return &admin, nil
}

// GetAdminByPhoneHash retrieves an admin by their phone hash
// EXPECTS: phoneHash to be pre-hashed by service layer
// GetAdminByPhoneHash retrieves an admin by their phone hash
func (r *AdminRepositoryImpl) GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error) {
	// ✅ FIX: Add ALLOW FILTERING
	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE phone_hash = ? LIMIT 1 ALLOW FILTERING`,
		phoneHash,
	)

	var admin models.AdminUser
	var scannedID gocql.UUID
	var scannedCreatedBy gocql.UUID
	var scannedPhoneKeyID gocql.UUID

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&scannedPhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&admin.AdminRoleLevel,
		&admin.AdminPermissions,
		&admin.AdminCreatedAt,
		&scannedCreatedBy,
		&admin.AdminUpdatedAt,
		&admin.IsActive,
		&admin.DataAccessScope,
		&admin.IPWhitelist,
		&admin.FailedLoginAttempts,
		&admin.LastLogin,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("admin not found for phone hash")
		}
		return nil, fmt.Errorf("failed to get admin by phone hash: %w", err)
	}

	admin.AdminID = uuid.UUID(scannedID)
	admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
	admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)

	return &admin, nil
}

// ===== ADMIN MANAGEMENT =====

// UpdateAdminPermissions updates admin permissions
func (r *AdminRepositoryImpl) UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []string) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET admin_permissions = ?, admin_updated_at = ? WHERE admin_id = ?`,
		permissions,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin permissions: %w", err)
	}

	r.logger.Info("Admin permissions updated",
		util.String("admin_id", adminID.String()),
		util.Int("permission_count", len(permissions)),
	)

	return nil
}

// UpdateAdminRoleLevel updates admin role level (promotion/demotion)
func (r *AdminRepositoryImpl) UpdateAdminRoleLevel(ctx context.Context, adminID uuid.UUID, newRoleLevel string, changedBy uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET admin_role_level = ?, admin_updated_at = ? WHERE admin_id = ?`,
		newRoleLevel,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin role level: %w", err)
	}

	r.logger.Info("Admin role level updated",
		util.String("admin_id", adminID.String()),
		util.String("new_role", newRoleLevel),
		util.String("changed_by", changedBy.String()),
	)

	return nil
}

// ===== INVITATION & ONBOARDING =====

// InviteUserAsAdmin invites a user to become admin
// EXPECTS: phoneHash to be pre-hashed by service layer
func (r *AdminRepositoryImpl) InviteUserAsAdmin(ctx context.Context, phoneHash string, roleLevel string, permissions []string, invitedBy uuid.UUID) (*models.AdminUser, error) {
	// Check if phone is registered in users table (using pre-hashed value)
	userQuery := r.client.Session.Query(
		`SELECT user_id FROM users_by_phone_hash WHERE phone_hash = ? LIMIT 1`,
		phoneHash, // ✅ Use pre-hashed phone for lookup
	)

	var userID gocql.UUID
	if err := r.client.ScanWithRetry(userQuery.WithContext(ctx), &userID); err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("number not registered yet")
		}
		return nil, fmt.Errorf("failed to verify user registration: %w", err)
	}

	// Create admin record
	adminID := uuid.New()
	now := time.Now().UTC()

	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash, // ✅ Store pre-hashed phone
		AdminRoleLevel:      roleLevel,
		AdminPermissions:    permissions,
		AdminCreatedAt:      now,
		AdminCreatedBy:      invitedBy,
		AdminUpdatedAt:      now,
		IsActive:            true,
		DataAccessScope:     []string{models.DataAccessGlobal},
		IPWhitelist:         []string{},
		FailedLoginAttempts: 0,
		LastLogin:           time.Time{},
	}

	if err := r.CreateAdmin(ctx, admin); err != nil {
		return nil, err
	}

	r.logger.Info("User invited as admin",
		util.String("admin_id", adminID.String()),
		util.String("role_level", roleLevel),
		util.String("invited_by", invitedBy.String()),
	)

	return admin, nil
}

// RemoveAdmin soft-deletes an admin (sets is_active = false)
func (r *AdminRepositoryImpl) RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET is_active = false, admin_updated_at = ? WHERE admin_id = ?`,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to remove admin: %w", err)
	}

	r.logger.Info("Admin removed (soft delete)",
		util.String("admin_id", adminID.String()),
		util.String("removed_by", removedBy.String()),
	)

	return nil
}

// ===== OWNER MANAGEMENT =====

// // GetAdminOwner retrieves the current system owner (only one allowed)
// func (r *AdminRepositoryImpl) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
// 	// ✅ FIX: Add ALLOW FILTERING to the query
// 	query := r.client.Session.Query(
// 		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
//                 admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
//                 admin_updated_at, is_active, data_access_scope, ip_whitelist, 
//                 failed_login_attempts, last_login 
//          FROM admin_users WHERE admin_role_level = ? AND is_active = true LIMIT 1 ALLOW FILTERING`,
// 		models.RoleLevelOwner,
// 	)

// 	var admin models.AdminUser
// 	var scannedID gocql.UUID
// 	var scannedCreatedBy gocql.UUID
// 	var scannedPhoneKeyID gocql.UUID

// 	err := r.client.ScanWithRetry(query.WithContext(ctx),
// 		&scannedID,
// 		&admin.PhoneHash,
// 		&admin.PhoneEncrypted,
// 		&scannedPhoneKeyID,
// 		&admin.PhoneEncryptedDEK,
// 		&admin.AdminRoleLevel,
// 		&admin.AdminPermissions,
// 		&admin.AdminCreatedAt,
// 		&scannedCreatedBy,
// 		&admin.AdminUpdatedAt,
// 		&admin.IsActive,
// 		&admin.DataAccessScope,
// 		&admin.IPWhitelist,
// 		&admin.FailedLoginAttempts,
// 		&admin.LastLogin,
// 	)

// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, nil // ✅ Return nil, nil when no owner exists (not an error)
// 		}
// 		return nil, fmt.Errorf("failed to get owner: %w", err)
// 	}

// 	admin.AdminID = uuid.UUID(scannedID)
// 	admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
// 	admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)

// 	return &admin, nil
// }

// SetAdminOwner sets/changes the owner
// EXPECTS: phoneHash to be pre-hashed by service layer
func (r *AdminRepositoryImpl) SetAdminOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error {
	// Check if owner already exists
	owner, err := r.GetAdminOwner(ctx)
	if err == nil && owner != nil && owner.AdminID != adminID {
		return fmt.Errorf("system already has an owner - cannot add another owner")
	}

	// If creating new owner (no owner exists yet)
	if err != nil && err.Error() == "no owner found in system" {
		admin := &models.AdminUser{
			AdminID:             adminID,
			PhoneHash:           phoneHash, // ✅ Store pre-hashed phone
			AdminRoleLevel:      models.RoleLevelOwner,
			AdminPermissions:    []string{}, // Will be set based on role
			AdminCreatedAt:      time.Now().UTC(),
			AdminCreatedBy:      adminID, // Self-created for first owner
			AdminUpdatedAt:      time.Now().UTC(),
			IsActive:            true,
			DataAccessScope:     []string{models.DataAccessGlobal},
		}
		return r.CreateAdmin(ctx, admin)
	}

	// If changing owner's phone only (owner can do this themselves)
	if owner != nil && owner.AdminID == adminID {
		query := r.client.Session.Query(
			`UPDATE admin_users SET phone_hash = ?, admin_updated_at = ? WHERE admin_id = ?`,
			phoneHash, // ✅ Use pre-hashed phone
			time.Now().UTC(),
			gocql.UUID(adminID),
		)

		if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
			return fmt.Errorf("failed to update owner phone: %w", err)
		}

		r.logger.Info("Owner phone updated",
			util.String("admin_id", adminID.String()),
		)
		return nil
	}

	return fmt.Errorf("unauthorized: only owner can change owner details")
}

// IsAdminOwnerExists checks if system has an owner
func (r *AdminRepositoryImpl) IsAdminOwnerExists(ctx context.Context) (bool, error) {
	owner, err := r.GetAdminOwner(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check owner existence: %w", err)
	}
	return owner != nil, nil // ✅ Fixed: Return true if owner exists, false if nil
}

// ===== ADMIN STATUS OPERATIONS =====

// DeactivateAdmin sets is_active = false
func (r *AdminRepositoryImpl) DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET is_active = false, admin_updated_at = ? WHERE admin_id = ?`,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to deactivate admin: %w", err)
	}

	r.logger.Info("Admin deactivated", util.String("admin_id", adminID.String()))
	return nil
}

// ActivateAdmin sets is_active = true
func (r *AdminRepositoryImpl) ActivateAdmin(ctx context.Context, adminID uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET is_active = true, admin_updated_at = ? WHERE admin_id = ?`,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to activate admin: %w", err)
	}

	r.logger.Info("Admin activated", util.String("admin_id", adminID.String()))
	return nil
}

// UpdateAdminLastLogin updates admin last login timestamp
func (r *AdminRepositoryImpl) UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error {
	r.stmtMutex.RLock()
	query := r.stmtUpdateLastLogin.Bind(time.Now().UTC(), gocql.UUID(adminID))
	r.stmtMutex.RUnlock()

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// ===== FAILED ATTEMPTS TRACKING =====

// IncrementAdminFailedLoginAttempts increments failed attempts counter
func (r *AdminRepositoryImpl) IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	admin, err := r.GetAdminByID(ctx, adminID)
	if err != nil {
		return 0, err
	}

	newAttempts := admin.FailedLoginAttempts + 1

	query := r.client.Session.Query(
		`UPDATE admin_users SET failed_login_attempts = ?, admin_updated_at = ? WHERE admin_id = ?`,
		newAttempts,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return newAttempts, fmt.Errorf("failed to increment failed attempts: %w", err)
	}

	return newAttempts, nil
}

// ResetAdminFailedLoginAttempts resets failed attempts to 0
func (r *AdminRepositoryImpl) ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET failed_login_attempts = 0, admin_updated_at = ? WHERE admin_id = ?`,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}

	return nil
}

// ===== QUERY OPERATIONS =====

// GetAllAdmins retrieves all admins (active and inactive)
func (r *AdminRepositoryImpl) GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
		        admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
		        admin_updated_at, is_active, data_access_scope, ip_whitelist, 
		        failed_login_attempts, last_login 
		 FROM admin_users LIMIT ?`,
		limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var admins []*models.AdminUser

	for {
		var admin models.AdminUser
		var scannedID gocql.UUID
		var scannedCreatedBy gocql.UUID
		var scannedPhoneKeyID gocql.UUID

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &admin.AdminRoleLevel,
			&admin.AdminPermissions, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query all admins: %w", err)
	}

	return admins, nil
}

// ===== HEALTH & STATISTICS =====

// AdminHealthCheck verifies repository connectivity
func (r *AdminRepositoryImpl) AdminHealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_users`).WithContext(ctx).Scan(&count); err != nil {
		return fmt.Errorf("admin repository health check failed: %w", err)
	}
	return nil
}

// GetAdminRepositoryStats returns repository statistics
func (r *AdminRepositoryImpl) GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count total admins
	var totalAdmins int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_users`).WithContext(ctx).Scan(&totalAdmins); err != nil {
		return nil, fmt.Errorf("failed to count admins: %w", err)
	}
	stats["total_admins"] = totalAdmins

	// Count active admins
	var activeAdmins int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_users WHERE is_active = true`).WithContext(ctx).Scan(&activeAdmins); err != nil {
		return nil, fmt.Errorf("failed to count active admins: %w", err)
	}
	stats["active_admins"] = activeAdmins

	// ✅ FIX: Count by role using base table with ALLOW FILTERING
	roles := []string{models.RoleLevelOwner, models.RoleLevelSuperEmployee, models.RoleLevelEmployee}
	for _, role := range roles {
		var count int
		if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_users WHERE admin_role_level = ? ALLOW FILTERING`, role).WithContext(ctx).Scan(&count); err != nil {
			continue
		}
		stats[fmt.Sprintf("admins_%s", role)] = count
	}

	return stats, nil
}

// Add this method to ensure AdminMPINRepositoryImpl implements MPINRepository
func (r *AdminMPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	// For admin repository, treat userID as adminID
	return r.GetMPINByAdminID(ctx, userID)
}

// Add these missing methods to AdminDeviceRepositoryImpl

// GetUsersByDevice implements DeviceRepository interface
func (r *AdminDeviceRepositoryImpl) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
	}

	query := r.client.Session.Query(`
        SELECT admin_id, device_id, session_id, bound_at, bind_token
        FROM admin_active_device
        WHERE device_id = ?
        ALLOW FILTERING
    `, deviceID)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var devices []*models.UserActiveDevice
	var scannedAdminID gocql.UUID
	var scannedSessionID *gocql.UUID
	var device models.UserActiveDevice

	for iter.Scan(&scannedAdminID, &device.DeviceID, &scannedSessionID, &device.BoundAt, &device.BindToken) {
		device.UserID = uuid.UUID(scannedAdminID).String()
		if scannedSessionID != nil {
			sessionID := uuid.UUID(*scannedSessionID)
			device.SessionID = sessionID.String()
		}
		devices = append(devices, &device)
		device = models.UserActiveDevice{}
	}

	if err := iter.Close(); err != nil {
		r.metrics.RecordQuery(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to get admins by device: %w", err)
	}

	r.metrics.RecordQuery(time.Since(startTime), true)
	return devices, nil
}
// GetOwner retrieves the current system owner (only one allowed)
// This method is required by the AdminRepository interface
func (r *AdminRepositoryImpl) GetOwner(ctx context.Context) (*models.AdminUser, error) {
    return r.GetAdminOwner(ctx)
}

// GetRepositoryStats returns repository statistics
// This method is required by the AdminRepository interface
func (r *AdminRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
    return r.GetAdminRepositoryStats(ctx)
}

func (r *AdminRepositoryImpl) HealthCheck(ctx context.Context) error {
    return r.AdminHealthCheck(ctx)
}


// // UpdateAdminOwnerPhone updates owner's phone information
// func (r *AdminRepositoryImpl) UpdateAdminOwnerPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error {
//     if adminID == uuid.Nil {
//         return fmt.Errorf("invalid admin ID")
//     }
//     if phoneHash == "" {
//         return fmt.Errorf("phone hash cannot be empty")
//     }

//     query := r.client.Session.Query(
//         `UPDATE admin_users SET 
//             phone_hash = ?, 
//             phone_encrypted = ?, 
//             phone_key_id = ?, 
//             phone_encrypted_dek = ?, 
//             admin_updated_at = ? 
//          WHERE admin_id = ?`,
//         phoneHash,
//         phoneEncrypted,
//         gocql.UUID(phoneKeyID),
//         phoneEncryptedDEK,
//         time.Now().UTC(),
//         gocql.UUID(adminID),
//     )

//     if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
//         r.logger.Error("Failed to execute UpdateOwnerPhone query",
//             util.String("admin_id", adminID.String()),
//             util.ErrorField(err),
//         )
//         return fmt.Errorf("failed to update owner phone: %w", err)
//     }

//     r.logger.Info("Owner phone updated successfully",
//         util.String("admin_id", adminID.String()),
//     )
//     return nil
// }
// internal/repository/scylla/admin_repository_impl.go

// GetOwner retrieves the current system owner (only one allowed)
func (r *AdminRepositoryImpl) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
    query := r.client.Session.Query(
        `SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_level, admin_permissions, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE admin_role_level = ? ALLOW FILTERING`,
        models.RoleLevelOwner,
    )

    var admin models.AdminUser
    var scannedID gocql.UUID
    var scannedCreatedBy gocql.UUID
    var scannedPhoneKeyID gocql.UUID

    err := r.client.ScanWithRetry(query.WithContext(ctx),
        &scannedID,
        &admin.PhoneHash,
        &admin.PhoneEncrypted,
        &scannedPhoneKeyID,
        &admin.PhoneEncryptedDEK,
        &admin.AdminRoleLevel,
        &admin.AdminPermissions,
        &admin.AdminCreatedAt,
        &scannedCreatedBy,
        &admin.AdminUpdatedAt,
        &admin.IsActive,
        &admin.DataAccessScope,
        &admin.IPWhitelist,
        &admin.FailedLoginAttempts,
        &admin.LastLogin,
    )

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, nil // No owner exists yet
        }
        return nil, fmt.Errorf("failed to get owner: %w", err)
    }

    admin.AdminID = uuid.UUID(scannedID)
    admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
    admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)

    return &admin, nil
}

// UpdateAdminOwnerPhone updates owner's phone information
func (r *AdminRepositoryImpl) UpdateAdminOwnerPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error {
    if adminID == uuid.Nil {
        return fmt.Errorf("invalid admin ID")
    }
    if phoneHash == "" {
        return fmt.Errorf("phone hash cannot be empty")
    }

    query := r.client.Session.Query(
        `UPDATE admin_users SET 
            phone_hash = ?, 
            phone_encrypted = ?, 
            phone_key_id = ?, 
            phone_encrypted_dek = ?, 
            admin_updated_at = ? 
         WHERE admin_id = ?`,
        phoneHash,
        phoneEncrypted,
        gocql.UUID(phoneKeyID),
        phoneEncryptedDEK,
        time.Now().UTC(),
        gocql.UUID(adminID),
    )

    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        r.logger.Error("Failed to update owner phone",
            util.String("admin_id", adminID.String()),
            util.ErrorField(err),
        )
        return fmt.Errorf("failed to update owner phone: %w", err)
    }

    r.logger.Info("Owner phone updated successfully",
        util.String("admin_id", adminID.String()),
    )
    return nil
}

