// internal/repository/scylla/admin_repository.go
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

// AdminRepository defines the contract for admin repository operations with bitmasks

// AdminRepositoryImpl implements AdminRepository interface with bitmasks
type AdminRepositoryImpl struct {
	client   *ScyllaClient
	logger   *zap.Logger

	// Prepared statements
	stmtGetAdminByID            *gocql.Query
	stmtGetAdminByPhoneHash     *gocql.Query
	stmtGetActiveAdmins         *gocql.Query
	stmtUpdateLastLogin         *gocql.Query
	stmtIncrementFailedAttempts *gocql.Query
	stmtGetAdminsByRole         *gocql.Query
	stmtMutex                   sync.RWMutex
}

// NewAdminRepository creates a new admin repository with bitmask support
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

// prepareStatements prepares frequently used queries
func (r *AdminRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare GetAdminByID query
	// Prepare GetAdminByID query with department_bitmask
	r.stmtGetAdminByID = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
				admin_role_mask, admin_permission_mask, department_bitmask, admin_created_at, admin_created_by, 
				admin_updated_at, is_active, data_access_scope, ip_whitelist, 
				failed_login_attempts, last_login 
		FROM admin_users WHERE admin_id = ?`,
	)

	// Prepare GetAdminByPhoneHash query
	r.stmtGetAdminByPhoneHash = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE phone_hash = ? ALLOW FILTERING`,
	)

	// Prepare GetActiveAdmins query
	r.stmtGetActiveAdmins = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE is_active = true LIMIT ?`,
	)

	// Prepare GetAdminsByRole query
	r.stmtGetAdminsByRole = r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek, 
                admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE admin_role_mask = ? AND is_active = true ALLOW FILTERING`,
	)

	// Prepare UpdateLastLogin query
	r.stmtUpdateLastLogin = r.client.Session.Query(
		`UPDATE admin_users SET last_login = ? WHERE admin_id = ?`,
	)

	r.logger.Info("Prepared statements initialized for admin repository with bitmask support")
}

// ===== CORE OPERATIONS =====

// // CreateAdmin creates a new admin user with bitmask fields
// func (r *AdminRepositoryImpl) CreateAdmin(ctx context.Context, admin *models.AdminUser) error {
// 	startTime := time.Now()

// 	if admin.AdminID == uuid.Nil {
// 		return fmt.Errorf("admin ID cannot be nil")
// 	}
// 	if admin.PhoneHash == "" {
// 		return fmt.Errorf("phone hash cannot be empty")
// 	}

// 	// Convert permission mask to list of int64 for Scylla
// 	var permissionMask []int64
// 	if admin.AdminPermissionMask != nil {
// 		permissionMask = make([]int64, len(admin.AdminPermissionMask))
// 		for i, mask := range admin.AdminPermissionMask {
// 			permissionMask[i] = int64(mask)
// 		}
// 	}

// 	query := r.client.Session.Query(
// 		`INSERT INTO admin_users 
// 		 (admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
// 		  admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
// 		  admin_updated_at, is_active, data_access_scope, ip_whitelist, 
// 		  failed_login_attempts, last_login) 
// 		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(admin.AdminID),
// 		admin.PhoneHash,
// 		admin.PhoneEncrypted,
// 		gocql.UUID(admin.PhoneKeyID),
// 		admin.PhoneEncryptedDEK,
// 		int64(admin.AdminRoleMask), // Store as int64
// 		permissionMask,
// 		admin.AdminCreatedAt,
// 		gocql.UUID(admin.AdminCreatedBy),
// 		admin.AdminUpdatedAt,
// 		admin.IsActive,
// 		admin.DataAccessScope,
// 		admin.IPWhitelist,
// 		admin.FailedLoginAttempts,
// 		admin.LastLogin,
// 	)

// 	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
// 		return fmt.Errorf("failed to create admin: %w", err)
// 	}

// 	r.logger.Info("Admin created successfully",
// 		util.String("admin_id", admin.AdminID.String()),
// 		util.Uint64("role_mask", admin.AdminRoleMask),
// 		util.Duration("duration", time.Since(startTime)),
// 	)

// 	return nil
// }

// // GetAdminByID retrieves an admin by their ID
// func (r *AdminRepositoryImpl) GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
// 	r.stmtMutex.RLock()
// 	query := r.stmtGetAdminByID.Bind(gocql.UUID(adminID))
// 	r.stmtMutex.RUnlock()

// 	var admin models.AdminUser
// 	var scannedID gocql.UUID
// 	var scannedCreatedBy gocql.UUID
// 	var scannedPhoneKeyID gocql.UUID
// 	var roleMask int64
// 	var permissionMask []int64

// 	err := r.client.ScanWithRetry(query.WithContext(ctx),
// 		&scannedID,
// 		&admin.PhoneHash,
// 		&admin.PhoneEncrypted,
// 		&scannedPhoneKeyID,
// 		&admin.PhoneEncryptedDEK,
// 		&roleMask,
// 		&permissionMask,
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
// 			return nil, fmt.Errorf("admin not found with ID: %s", adminID)
// 		}
// 		return nil, fmt.Errorf("failed to get admin: %w", err)
// 	}

// 	admin.AdminID = uuid.UUID(scannedID)
// 	admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
// 	admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
// 	admin.AdminRoleMask = uint64(roleMask)
	
// 	// Convert permission mask from []int64 to []uint64
// 	if permissionMask != nil {
// 		admin.AdminPermissionMask = make([]uint64, len(permissionMask))
// 		for i, mask := range permissionMask {
// 			admin.AdminPermissionMask[i] = uint64(mask)
// 		}
// 	}

// 	return &admin, nil
// }

// GetAdminByPhoneHash retrieves an admin by their phone hash
func (r *AdminRepositoryImpl) GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error) {
	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE phone_hash = ? LIMIT 1 ALLOW FILTERING`,
		phoneHash,
	)

	var admin models.AdminUser
	var scannedID gocql.UUID
	var scannedCreatedBy gocql.UUID
	var scannedPhoneKeyID gocql.UUID
	var roleMask int64
	var permissionMask []int64

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&scannedPhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&roleMask,
		&permissionMask,
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
	admin.AdminRoleMask = uint64(roleMask)
	
	if permissionMask != nil {
		admin.AdminPermissionMask = make([]uint64, len(permissionMask))
		for i, mask := range permissionMask {
			admin.AdminPermissionMask[i] = uint64(mask)
		}
	}

	return &admin, nil
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
		        admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
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
		var roleMask int64
		var permissionMask []int64

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &roleMask,
			&permissionMask, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admin.AdminRoleMask = uint64(roleMask)
		
		if permissionMask != nil {
			admin.AdminPermissionMask = make([]uint64, len(permissionMask))
			for i, mask := range permissionMask {
				admin.AdminPermissionMask[i] = uint64(mask)
			}
		}

		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query all admins: %w", err)
	}

	return admins, nil
}

// GetActiveAdmins retrieves only active admins
func (r *AdminRepositoryImpl) GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	r.stmtMutex.RLock()
	query := r.stmtGetActiveAdmins.Bind(limit)
	r.stmtMutex.RUnlock()

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var admins []*models.AdminUser

	for {
		var admin models.AdminUser
		var scannedID gocql.UUID
		var scannedCreatedBy gocql.UUID
		var scannedPhoneKeyID gocql.UUID
		var roleMask int64
		var permissionMask []int64

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &roleMask,
			&permissionMask, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admin.AdminRoleMask = uint64(roleMask)
		
		if permissionMask != nil {
			admin.AdminPermissionMask = make([]uint64, len(permissionMask))
			for i, mask := range permissionMask {
				admin.AdminPermissionMask[i] = uint64(mask)
			}
		}

		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query active admins: %w", err)
	}

	return admins, nil
}

// GetAdminsByRole retrieves admins by role mask
func (r *AdminRepositoryImpl) GetAdminsByRole(ctx context.Context, roleMask uint64) ([]*models.AdminUser, error) {
	r.stmtMutex.RLock()
	query := r.stmtGetAdminsByRole.Bind(int64(roleMask))
	r.stmtMutex.RUnlock()

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var admins []*models.AdminUser

	for {
		var admin models.AdminUser
		var scannedID gocql.UUID
		var scannedCreatedBy gocql.UUID
		var scannedPhoneKeyID gocql.UUID
		var dbRoleMask int64
		var permissionMask []int64

		if !iter.Scan(&scannedID, &admin.PhoneHash, &admin.PhoneEncrypted,
			&scannedPhoneKeyID, &admin.PhoneEncryptedDEK, &dbRoleMask,
			&permissionMask, &admin.AdminCreatedAt, &scannedCreatedBy,
			&admin.AdminUpdatedAt, &admin.IsActive, &admin.DataAccessScope,
			&admin.IPWhitelist, &admin.FailedLoginAttempts, &admin.LastLogin) {
			break
		}

		admin.AdminID = uuid.UUID(scannedID)
		admin.AdminCreatedBy = uuid.UUID(scannedCreatedBy)
		admin.PhoneKeyID = uuid.UUID(scannedPhoneKeyID)
		admin.AdminRoleMask = uint64(dbRoleMask)
		
		if permissionMask != nil {
			admin.AdminPermissionMask = make([]uint64, len(permissionMask))
			for i, mask := range permissionMask {
				admin.AdminPermissionMask[i] = uint64(mask)
			}
		}

		admins = append(admins, &admin)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query admins by role: %w", err)
	}

	return admins, nil
}

// ===== ADMIN MANAGEMENT =====

// UpdateAdminPermissions updates admin permission mask
func (r *AdminRepositoryImpl) UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []uint64) error {
	// Convert permission mask to list of int64 for Scylla
	var permissionMask []int64
	if permissions != nil {
		permissionMask = make([]int64, len(permissions))
		for i, mask := range permissions {
			permissionMask[i] = int64(mask)
		}
	}

	query := r.client.Session.Query(
		`UPDATE admin_users SET admin_permission_mask = ?, admin_updated_at = ? WHERE admin_id = ?`,
		permissionMask,
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin permissions: %w", err)
	}

	r.logger.Info("Admin permissions updated",
		util.String("admin_id", adminID.String()),
		util.Int("permission_segments", len(permissions)),
	)

	return nil
}

// UpdateAdminRoleMask updates admin role mask (promotion/demotion)
func (r *AdminRepositoryImpl) UpdateAdminRoleMask(ctx context.Context, adminID uuid.UUID, newRoleMask uint64, changedBy uuid.UUID) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET admin_role_mask = ?, admin_updated_at = ? WHERE admin_id = ?`,
		int64(newRoleMask),
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin role mask: %w", err)
	}

	r.logger.Info("Admin role mask updated",
		util.String("admin_id", adminID.String()),
		util.Uint64("new_role_mask", newRoleMask),
		util.String("changed_by", changedBy.String()),
	)

	return nil
}

// UpdateAdminPhone updates admin phone information
func (r *AdminRepositoryImpl) UpdateAdminPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error {
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
		r.logger.Error("Failed to update admin phone",
			util.String("admin_id", adminID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update admin phone: %w", err)
	}

	r.logger.Info("Admin phone updated successfully",
		util.String("admin_id", adminID.String()),
	)
	return nil
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

// GetAdminOwner retrieves the current system owner (only one allowed)
func (r *AdminRepositoryImpl) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
	query := r.client.Session.Query(
		`SELECT admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
                admin_role_mask, admin_permission_mask, admin_created_at, admin_created_by, 
                admin_updated_at, is_active, data_access_scope, ip_whitelist, 
                failed_login_attempts, last_login 
         FROM admin_users WHERE admin_role_mask = ? AND is_active = true ALLOW FILTERING`,
		int64(models.RoleMaskOwner),
	)

	var admin models.AdminUser
	var scannedID gocql.UUID
	var scannedCreatedBy gocql.UUID
	var scannedPhoneKeyID gocql.UUID
	var roleMask int64
	var permissionMask []int64

	err := r.client.ScanWithRetry(query.WithContext(ctx),
		&scannedID,
		&admin.PhoneHash,
		&admin.PhoneEncrypted,
		&scannedPhoneKeyID,
		&admin.PhoneEncryptedDEK,
		&roleMask,
		&permissionMask,
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
	admin.AdminRoleMask = uint64(roleMask)
	
	if permissionMask != nil {
		admin.AdminPermissionMask = make([]uint64, len(permissionMask))
		for i, mask := range permissionMask {
			admin.AdminPermissionMask[i] = uint64(mask)
		}
	}

	return &admin, nil
}

// SetAdminOwner sets/changes the owner
func (r *AdminRepositoryImpl) SetAdminOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error {
	// Check if owner already exists
	owner, err := r.GetAdminOwner(ctx)
	if err == nil && owner != nil && owner.AdminID != adminID {
		return fmt.Errorf("system already has an owner - cannot add another owner")
	}

	// If creating new owner (no owner exists yet)
	if err != nil && err.Error() == "no owner found in system" {
		// Create full permission mask for owner
		fullPermissionMask := models.CreateFullPermissionMask()
		
		admin := &models.AdminUser{
			AdminID:             adminID,
			PhoneHash:           phoneHash,
			AdminRoleMask:       models.RoleMaskOwner,
			AdminPermissionMask: fullPermissionMask,
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
			phoneHash,
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
	return owner != nil, nil
}

// ===== STATUS OPERATIONS =====

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

// ===== HELPER METHODS =====

// GetOwner implements the interface method
func (r *AdminRepositoryImpl) GetOwner(ctx context.Context) (*models.AdminUser, error) {
	return r.GetAdminOwner(ctx)
}

// HealthCheck implements the interface method
func (r *AdminRepositoryImpl) HealthCheck(ctx context.Context) error {
	return r.AdminHealthCheck(ctx)
}

// GetRepositoryStats implements the interface method
func (r *AdminRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	return r.GetAdminRepositoryStats(ctx)
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

// GetAdminRepositoryStats returns repository statistics with bitmask info
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

	// Count by role mask
	roleMasks := []uint64{models.RoleMaskOwner, models.RoleMaskSuperEmployee, models.RoleMaskEmployee}
	for _, mask := range roleMasks {
		var count int
		if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_users WHERE admin_role_mask = ? ALLOW FILTERING`, int64(mask)).WithContext(ctx).Scan(&count); err != nil {
			continue
		}
		
		var roleName string
		switch mask {
		case models.RoleMaskOwner:
			roleName = "owner"
		case models.RoleMaskSuperEmployee:
			roleName = "super_employee"
		case models.RoleMaskEmployee:
			roleName = "employee"
		}
		stats[fmt.Sprintf("admins_%s", roleName)] = count
	}

	// Get permission mask statistics
	stats["permission_mask_info"] = map[string]interface{}{
		"total_permissions": 229,
		"segments_required": 4,
		"bits_per_segment": 64,
	}

	return stats, nil
}

// InviteUserAsAdmin - Note: This method is deprecated in favor of AdminService.InviteAdmin
// but kept for backward compatibility
func (r *AdminRepositoryImpl) InviteUserAsAdmin(ctx context.Context, phoneHash string, roleMask uint64, permissions []uint64, invitedBy uuid.UUID) (*models.AdminUser, error) {
	// Convert permission mask to []int64 for Scylla
	var permissionMask []int64
	if permissions != nil {
		permissionMask = make([]int64, len(permissions))
		for i, mask := range permissions {
			permissionMask[i] = int64(mask)
		}
	}

	adminID := uuid.New()
	now := time.Now().UTC()

	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		AdminRoleMask:       roleMask,
		AdminPermissionMask: permissions,
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

	r.logger.Info("User invited as admin (legacy method)",
		util.String("admin_id", adminID.String()),
		util.Uint64("role_mask", roleMask),
		util.String("invited_by", invitedBy.String()),
	)

	return admin, nil
}

// LogAdminAudit logs admin audit events with bitmask changes
func (r *AdminRepositoryImpl) LogAdminAudit(ctx context.Context, auditEvent *AdminAuditEvent) error {
	// Convert bitmasks for storage
	var oldRoleMask, newRoleMask *int64
	if auditEvent.OldRoleMask != nil {
		val := int64(*auditEvent.OldRoleMask)
		oldRoleMask = &val
	}
	if auditEvent.NewRoleMask != nil {
		val := int64(*auditEvent.NewRoleMask)
		newRoleMask = &val
	}

	// Convert permission masks
	var oldPermMask, newPermMask []int64
	if auditEvent.OldPermissionMask != nil {
		oldPermMask = make([]int64, len(auditEvent.OldPermissionMask))
		for i, mask := range auditEvent.OldPermissionMask {
			oldPermMask[i] = int64(mask)
		}
	}
	if auditEvent.NewPermissionMask != nil {
		newPermMask = make([]int64, len(auditEvent.NewPermissionMask))
		for i, mask := range auditEvent.NewPermissionMask {
			newPermMask[i] = int64(mask)
		}
	}

	query := r.client.Session.Query(
		`INSERT INTO admin_audit_log 
		 (audit_bucket, audit_id, admin_id, action_date, action_time, action_type,
		  resource_type, resource_id, operation_status, changes, ip_address,
		  old_role_mask, new_role_mask, old_permission_mask, new_permission_mask, error_message)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		auditEvent.AuditBucket,
		gocql.UUID(auditEvent.AuditID),
		gocql.UUID(auditEvent.AdminID),
		auditEvent.ActionDate,
		auditEvent.ActionTime,
		auditEvent.ActionType,
		auditEvent.ResourceType,
		gocql.UUID(auditEvent.ResourceID),
		auditEvent.OperationStatus,
		auditEvent.Changes,
		auditEvent.IPAddress,
		oldRoleMask,
		newRoleMask,
		oldPermMask,
		newPermMask,
		auditEvent.ErrorMessage,
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to log admin audit: %w", err)
	}

	return nil
}

// AdminAuditEvent represents audit event with bitmask changes
type AdminAuditEvent struct {
	AuditBucket         int
	AuditID             uuid.UUID
	AdminID             uuid.UUID
	ActionDate          string
	ActionTime          time.Time
	ActionType          string
	ResourceType        string
	ResourceID          uuid.UUID
	OperationStatus     string
	Changes             string
	IPAddress           string
	OldRoleMask         *uint64
	NewRoleMask         *uint64
	OldPermissionMask   []uint64
	NewPermissionMask   []uint64
	ErrorMessage        string
}

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


// Add this method to ensure AdminMPINRepositoryImpl implements MPINRepository
func (r *AdminMPINRepositoryImpl) GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error) {
	// For admin repository, treat userID as adminID
	return r.GetMPINByAdminID(ctx, userID)
}

// Update the CreateAdmin method to include department_bitmask
func (r *AdminRepositoryImpl) CreateAdmin(ctx context.Context, admin *models.AdminUser) error {
	startTime := time.Now()

	if admin.AdminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be nil")
	}
	if admin.PhoneHash == "" {
		return fmt.Errorf("phone hash cannot be empty")
	}

	var permissionMask []int64
	if admin.AdminPermissionMask != nil {
		permissionMask = make([]int64, len(admin.AdminPermissionMask))
		for i, mask := range admin.AdminPermissionMask {
			permissionMask[i] = int64(mask)
		}
	}

	query := r.client.Session.Query(
		`INSERT INTO admin_users
		 (admin_id, phone_hash, phone_encrypted, phone_key_id, phone_encrypted_dek,
		  admin_role_mask, admin_permission_mask, department_bitmask, admin_created_at, admin_created_by,
		  admin_updated_at, is_active, data_access_scope, ip_whitelist,
		  failed_login_attempts, last_login)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(admin.AdminID),
		admin.PhoneHash,
		admin.PhoneEncrypted,
		gocql.UUID(admin.PhoneKeyID),
		admin.PhoneEncryptedDEK,
		int64(admin.AdminRoleMask),
		permissionMask,
		int64(admin.DepartmentBitmask),
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
		util.Uint64("role_mask", admin.AdminRoleMask),
		util.Uint64("department_bitmask", admin.DepartmentBitmask),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (r *AdminRepositoryImpl) GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
    r.stmtMutex.RLock()
    query := r.stmtGetAdminByID.Bind(gocql.UUID(adminID))
    r.stmtMutex.RUnlock()

    var admin models.AdminUser
    var scannedID gocql.UUID
    var scannedCreatedBy gocql.UUID
    var scannedPhoneKeyID gocql.UUID
    var roleMask, deptBitmask int64  // Added deptBitmask
    var permissionMask []int64

    err := r.client.ScanWithRetry(query.WithContext(ctx),
        &scannedID,
        &admin.PhoneHash,
        &admin.PhoneEncrypted,
        &scannedPhoneKeyID,
        &admin.PhoneEncryptedDEK,
        &roleMask,
        &permissionMask,
        &deptBitmask,  // Added this line
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
    admin.AdminRoleMask = uint64(roleMask)
    admin.DepartmentBitmask = uint64(deptBitmask)  // Set department bitmask
    
    if permissionMask != nil {
        admin.AdminPermissionMask = make([]uint64, len(permissionMask))
        for i, mask := range permissionMask {
            admin.AdminPermissionMask[i] = uint64(mask)
        }
    }

    return &admin, nil
}
// Add new method to update department bitmask
func (r *AdminRepositoryImpl) UpdateAdminDepartmentBitmask(ctx context.Context, adminID uuid.UUID, departmentBitmask uint64) error {
	query := r.client.Session.Query(
		`UPDATE admin_users SET department_bitmask = ?, admin_updated_at = ? WHERE admin_id = ?`,
		int64(departmentBitmask),
		time.Now().UTC(),
		gocql.UUID(adminID),
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to update admin department bitmask: %w", err)
	}

	r.logger.Info("Admin department bitmask updated",
		util.String("admin_id", adminID.String()),
		util.Uint64("department_bitmask", departmentBitmask),
	)

	return nil
}