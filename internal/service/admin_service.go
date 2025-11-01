package service

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"
    "time"
    "auth-service/internal/encryption"
    "auth-service/internal/hashing"
    "auth-service/internal/models"
    "auth-service/internal/repository/scylla"
    "auth-service/internal/util"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

// AdminService handles admin related business logic
type AdminService struct {
    adminRepo     scylla.AdminRepository
    auditRepo     scylla.AuditRepository
    userRepo      scylla.UserRepository
    sessionService *SessionService
    hasher        *hashing.Hasher
    encryptionMgr *encryption.EncryptionManager
    logger        *zap.Logger
}

// NewAdminService creates admin service with injected dependencies
func NewAdminService(
    adminRepo scylla.AdminRepository,
    auditRepo scylla.AuditRepository,
    userRepo scylla.UserRepository,
    sessionService *SessionService,
    hasher *hashing.Hasher,
    encryptionMgr *encryption.EncryptionManager,
    logger *zap.Logger,
) *AdminService {
    return &AdminService{
        adminRepo:      adminRepo,
        auditRepo:      auditRepo,
        userRepo:       userRepo,
        sessionService: sessionService,
        hasher:         hasher,
        encryptionMgr:  encryptionMgr,
        logger:         logger,
    }
}

// GeneratePhoneHash generates a secure hash of phone number (same as UserService)
func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
    normalized := strings.ReplaceAll(phoneNumber, " ", "")
    normalized = strings.ReplaceAll(normalized, "-", "")
    normalized = strings.ReplaceAll(normalized, "(", "")
    normalized = strings.ReplaceAll(normalized, ")", "")

    hash := sha256.Sum256([]byte(normalized))
    return hex.EncodeToString(hash[:])
}

// InitializeOwner creates the first owner of the system
func (s *AdminService) InitializeOwner(ctx context.Context, phone string) (*models.AdminUser, error) {
    exists, err := s.adminRepo.IsOwnerExists(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to check owner existence: %w", err)
    }
    if exists {
        return nil, fmt.Errorf("system already has an owner")
    }

    // Hash and encrypt phone in service layer
    phoneHash := s.GeneratePhoneHash(phone)
    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key ID: %w", err)
    }

    ownerID := uuid.New()
    owner := &models.AdminUser{
        AdminID:           ownerID,
        PhoneHash:         phoneHash,
        PhoneEncrypted:    encryptedResult.EncryptedValue,
        PhoneKeyID:        keyID,
        PhoneEncryptedDEK: encryptedResult.EncryptedDEK,
        AdminRoleLevel:    models.RoleLevelOwner,
        AdminPermissions:  s.getOwnerPermissions(),
        AdminCreatedAt:    time.Now().UTC(),
        AdminCreatedBy:    ownerID,
        AdminUpdatedAt:    time.Now().UTC(),
        IsActive:          true,
        DataAccessScope:   []string{models.DataAccessGlobal},
        IPWhitelist:       []string{},
        FailedLoginAttempts: 0,
        LastLogin:         time.Time{},
    }

    if err := s.adminRepo.CreateAdmin(ctx, owner); err != nil {
        return nil, fmt.Errorf("failed to create owner: %w", err)
    }

    s.logAuditAction(ctx, owner.AdminID, models.ActionPromoteAdmin, models.ResourceTypeAdmin,
        owner.AdminID, models.StatusSuccess, "System owner initialized", "")

    s.logger.Info("Owner initialized", util.String("admin_id", owner.AdminID.String()))

    return owner, nil
}

// ChangeOwnerPhone allows owner to update their phone
// ChangeOwnerPhone allows owner to update their phone - FIXED VERSION
func (s *AdminService) ChangeOwnerPhone(ctx context.Context, ownerID uuid.UUID, newPhone string) error {
    // ✅ ADD: Input validation first
    if ownerID == uuid.Nil {
        return fmt.Errorf("invalid owner ID")
    }
    if newPhone == "" {
        return fmt.Errorf("new phone cannot be empty")
    }

    s.logger.Info("ChangeOwnerPhone called",
        util.String("owner_id", ownerID.String()),
        util.String("new_phone", newPhone),
    )

    // ✅ Get owner with proper nil handling
    owner, err := s.adminRepo.GetOwner(ctx)
    if err != nil {
        s.logger.Error("Failed to get owner from repository",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        return fmt.Errorf("failed to get owner: %w", err)
    }

    // ✅ CRITICAL: Check if owner is nil
    if owner == nil {
        s.logger.Error("Owner not found in database",
            util.String("owner_id", ownerID.String()),
        )
        return fmt.Errorf("owner not found in system")
    }

    s.logger.Info("Owner found",
        util.String("owner_id", owner.AdminID.String()),
        util.String("owner_role", owner.AdminRoleLevel),
    )

    // ✅ Now safely check if the requester is the actual owner
    if owner.AdminID != ownerID {
        s.logger.Warn("Unauthorized phone change attempt",
            util.String("requester_id", ownerID.String()),
            util.String("actual_owner_id", owner.AdminID.String()),
        )
        return fmt.Errorf("unauthorized: only owner can change phone")
    }

    newPhoneHash := s.GeneratePhoneHash(newPhone)
    
    // ✅ Check if new phone is same as current
    if owner.PhoneHash == newPhoneHash {
        return fmt.Errorf("new phone is the same as current phone")
    }

    // ✅ Check if new phone is already used by another admin
    existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
    if err == nil && existingAdmin != nil && existingAdmin.AdminID != ownerID {
        return fmt.Errorf("phone number is already used by another admin")
    }

    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
    if err != nil {
        s.logger.Error("Failed to encrypt new phone",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        return fmt.Errorf("failed to encrypt new phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return fmt.Errorf("failed to parse key ID: %w", err)
    }

    s.logger.Info("Phone encryption completed",
        util.String("key_id", keyID.String()),
        util.Int("encrypted_length", len(encryptedResult.EncryptedValue)),
    )

    // ✅ Use the new UpdateOwnerPhone method that handles encrypted fields
    if err := s.adminRepo.UpdateOwnerPhone(ctx, ownerID, newPhoneHash, encryptedResult.EncryptedValue, keyID, encryptedResult.EncryptedDEK); err != nil {
        s.logger.Error("Failed to update owner phone in repository",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        return fmt.Errorf("failed to update owner phone: %w", err)
    }

    s.logger.Info("Owner phone updated successfully",
        util.String("admin_id", ownerID.String()),
        util.String("new_phone_hash", newPhoneHash),
    )

    s.logAuditAction(ctx, ownerID, "CHANGE_OWNER_PHONE", models.ResourceTypeAdmin,
        ownerID, models.StatusSuccess, "Owner phone number changed", "")

    return nil
}
// InviteAdmin invites a user as admin - NO USER REGISTRATION CHECK
func (s *AdminService) InviteAdmin(ctx context.Context, phone string, roleLevel string, requesterID uuid.UUID, requesterRole string) (*models.AdminUser, error) {
    requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
    if err != nil {
        return nil, fmt.Errorf("requester not found: %w", err)
    }
    if !requester.IsActive {
        return nil, fmt.Errorf("requester is not active")
    }

    // ✅ FIXED: Validate role-based permissions
    if requester.IsEmployee() {
        return nil, fmt.Errorf("employees cannot invite admins")
    }
    if requester.IsSuperEmployee() && roleLevel != models.RoleLevelEmployee {
        return nil, fmt.Errorf("super employees can only invite as employee")
    }

    phoneHash := s.GeneratePhoneHash(phone)
    
    // ✅ Check if phone is already an admin
    existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
    if err == nil && existingAdmin != nil {
        return nil, fmt.Errorf("phone number is already an admin")
    }

    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key ID: %w", err)
    }

    // ❌ REMOVED: User registration check - admin accounts are independent

    permissions := s.getPermissionsForRole(roleLevel)

    adminID := uuid.New()
    now := time.Now().UTC()
    admin := &models.AdminUser{
        AdminID:           adminID,
        PhoneHash:         phoneHash,
        PhoneEncrypted:    encryptedResult.EncryptedValue,
        PhoneKeyID:        keyID,
        PhoneEncryptedDEK: encryptedResult.EncryptedDEK,
        AdminRoleLevel:    roleLevel,
        AdminPermissions:  permissions,
        AdminCreatedAt:    now,
        AdminCreatedBy:    requesterID,
        AdminUpdatedAt:    now,
        IsActive:          true,
        DataAccessScope:   s.getDefaultDataAccessScope(roleLevel),
        IPWhitelist:       []string{},
        FailedLoginAttempts: 0,
        LastLogin:         time.Time{},
    }

    if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
        return nil, fmt.Errorf("failed to invite user as admin: %w", err)
    }

    s.logAuditAction(ctx, requesterID, models.ActionPromoteAdmin, models.ResourceTypeAdmin,
        admin.AdminID, models.StatusSuccess, fmt.Sprintf("User invited as %s", roleLevel), "")

    s.logger.Info("User invited as admin",
        util.String("admin_id", admin.AdminID.String()),
        util.String("phone", phone),
        util.String("role_level", roleLevel),
        util.String("invited_by", requesterID.String()),
    )

    return admin, nil
}

// GetAdminByPhone retrieves admin by phone, hashing phone before lookup
func (s *AdminService) GetAdminByPhone(ctx context.Context, phone string) (*models.AdminUser, error) {
    phoneHash := s.GeneratePhoneHash(phone)
    return s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
}

// AuthenticateAdmin authenticates an admin by phone - ONLY CHECKS ADMIN TABLE
func (s *AdminService) AuthenticateAdmin(ctx context.Context, phone string) (*models.AdminUser, error) {
    phoneHash := s.GeneratePhoneHash(phone)
    admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
    if err != nil {
        return nil, fmt.Errorf("authentication failed: %w", err)
    }
    if !admin.IsActive {
        return nil, fmt.Errorf("admin account is deactivated")
    }
    if err := s.adminRepo.UpdateLastLogin(ctx, admin.AdminID); err != nil {
        s.logger.Warn("Failed to update last login",
            util.String("admin_id", admin.AdminID.String()),
            util.ErrorField(err),
        )
    }
    return admin, nil
}

// ===== HELPER METHODS =====

// getDefaultDataAccessScope returns default data access scope for role
func (s *AdminService) getDefaultDataAccessScope(roleLevel string) []string {
    switch roleLevel {
    case models.RoleLevelOwner, models.RoleLevelSuperEmployee:
        return []string{models.DataAccessGlobal}
    case models.RoleLevelEmployee:
        return []string{models.DataAccessGlobal}
    default:
        return []string{models.DataAccessGlobal}
    }
}

// PromoteAdmin promotes an admin to higher role
func (s *AdminService) PromoteAdmin(ctx context.Context, adminID uuid.UUID, newRole string, promotedBy uuid.UUID) error {
    // Get current admin
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get promoter
    promoter, err := s.adminRepo.GetAdminByID(ctx, promotedBy)
    if err != nil {
        return fmt.Errorf("promoter not found: %w", err)
    }

    // Check permission to promote
    if !promoter.CanPromoteToRole(newRole) {
        return fmt.Errorf("unauthorized: cannot promote to %s role", newRole)
    }

    // Old values for audit
    oldRole := admin.AdminRoleLevel

    // Update role level
    if err := s.adminRepo.UpdateAdminRoleLevel(ctx, adminID, newRole, promotedBy); err != nil {
        return fmt.Errorf("failed to promote admin: %w", err)
    }

    // Update permissions based on new role
    newPermissions := s.getPermissionsForRole(newRole)
    if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissions); err != nil {
        return fmt.Errorf("failed to update permissions: %w", err)
    }

    // Log audit
    s.logAuditAction(ctx, promotedBy, models.ActionUpdatePermissions, models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, fmt.Sprintf("Promoted from %s to %s", oldRole, newRole), "")

    s.logger.Info("Admin promoted",
        util.String("admin_id", adminID.String()),
        util.String("old_role", oldRole),
        util.String("new_role", newRole),
        util.String("promoted_by", promotedBy.String()),
    )

    return nil
}

// RemoveAdmin removes an admin (soft delete - sets is_active = false)
func (s *AdminService) RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error {
    // Get admin to remove
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get remover
    remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
    if err != nil {
        return fmt.Errorf("remover not found: %w", err)
    }

    // Check permission to remove
    if !remover.CanManageEmployee(admin.AdminRoleLevel) {
        return fmt.Errorf("unauthorized: cannot remove admin with role %s", admin.AdminRoleLevel)
    }

    // Cannot remove owner
    if admin.IsOwner() {
        return fmt.Errorf("cannot remove owner admin")
    }

    // Soft delete
    if err := s.adminRepo.RemoveAdmin(ctx, adminID, removedBy); err != nil {
        return fmt.Errorf("failed to remove admin: %w", err)
    }

    // Log audit
    s.logAuditAction(ctx, removedBy, "REMOVE_ADMIN", models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, "Admin removed", "")

    s.logger.Info("Admin removed",
        util.String("admin_id", adminID.String()),
        util.String("removed_by", removedBy.String()),
    )

    return nil
}

// DeactivateAdmin deactivates an admin (temporary suspend)
func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        return fmt.Errorf("admin not found: %w", err)
    }

    if !admin.IsActive {
        return fmt.Errorf("admin is already inactive")
    }

    // Cannot deactivate owner
    if admin.IsOwner() {
        return fmt.Errorf("cannot deactivate owner admin")
    }

    if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
        return fmt.Errorf("failed to deactivate admin: %w", err)
    }

    // Log audit
    s.logAuditAction(ctx, deactivatedBy, "DEACTIVATE_ADMIN", models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, "Admin deactivated", "")

    s.logger.Info("Admin deactivated",
        util.String("admin_id", adminID.String()),
    )

    return nil
}

// ActivateAdmin reactivates a deactivated admin
func (s *AdminService) ActivateAdmin(ctx context.Context, adminID uuid.UUID, activatedBy uuid.UUID) error {
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        return fmt.Errorf("admin not found: %w", err)
    }

    if admin.IsActive {
        return fmt.Errorf("admin is already active")
    }

    if err := s.adminRepo.ActivateAdmin(ctx, adminID); err != nil {
        return fmt.Errorf("failed to activate admin: %w", err)
    }

    // Log audit
    s.logAuditAction(ctx, activatedBy, "ACTIVATE_ADMIN", models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, "Admin activated", "")

    s.logger.Info("Admin activated",
        util.String("admin_id", adminID.String()),
    )

    return nil
}

// GetAdmin retrieves admin by ID
func (s *AdminService) GetAdmin(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
    return s.adminRepo.GetAdminByID(ctx, adminID)
}

// GetActiveAdmins retrieves all active admins
func (s *AdminService) GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
    return s.adminRepo.GetActiveAdmins(ctx, limit)
}

// GetAdminsByRole retrieves admins by role level
func (s *AdminService) GetAdminsByRole(ctx context.Context, roleLevel string) ([]*models.AdminUser, error) {
    return s.adminRepo.GetAdminsByRole(ctx, roleLevel)
}

// UpdateAdminPermissions updates admin permissions
func (s *AdminService) UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []string, updatedBy uuid.UUID) error {
    // Get admin
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get updater
    updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
    if err != nil {
        return fmt.Errorf("updater not found: %w", err)
    }

    // Check permission
    if !updater.CanManageEmployee(admin.AdminRoleLevel) {
        return fmt.Errorf("unauthorized: cannot update permissions for %s role", admin.AdminRoleLevel)
    }

    // Store old permissions for audit
    oldPermissions := admin.AdminPermissions

    // Update permissions
    if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, permissions); err != nil {
        return fmt.Errorf("failed to update permissions: %w", err)
    }

    // Log audit
    changedFieldsMsg := fmt.Sprintf("Old: %v, New: %v", oldPermissions, permissions)
    s.logAuditAction(ctx, updatedBy, models.ActionUpdatePermissions, models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, "Permissions updated", changedFieldsMsg)

    s.logger.Info("Admin permissions updated",
        util.String("admin_id", adminID.String()),
        util.Strings("new_permissions", permissions),
    )

    return nil
}

// RecordAdminLogin records admin login attempt
func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
    if err := s.adminRepo.UpdateLastLogin(ctx, adminID); err != nil {
        return fmt.Errorf("failed to record login: %w", err)
    }

    // Reset failed attempts on successful login
    if err := s.adminRepo.ResetFailedLoginAttempts(ctx, adminID); err != nil {
        s.logger.Warn("Failed to reset login attempts",
            util.String("admin_id", adminID.String()),
            util.ErrorField(err),
        )
    }

    // Log audit
    s.logAuditAction(ctx, adminID, models.ActionAdminLogin, models.ResourceTypeAdmin,
        adminID, models.StatusSuccess, "Admin login", "")

    return nil
}

// RecordFailedLogin records failed login attempt and checks for lockout
func (s *AdminService) RecordFailedLogin(ctx context.Context, adminID uuid.UUID) (bool, int, error) {
    attempts, err := s.adminRepo.IncrementFailedLoginAttempts(ctx, adminID)
    if err != nil {
        return false, 0, fmt.Errorf("failed to increment attempts: %w", err)
    }

    // Lock after 5 failed attempts
    const maxAttempts = 5
    shouldLockout := attempts >= maxAttempts

    if shouldLockout {
        // Deactivate admin temporarily
        if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
            s.logger.Warn("Failed to deactivate admin after lockout",
                util.String("admin_id", adminID.String()),
                util.ErrorField(err),
            )
        }

        // Log audit
        s.logAuditAction(ctx, adminID, "ADMIN_LOCKOUT", models.ResourceTypeAdmin,
            adminID, models.StatusSuccess, fmt.Sprintf("Admin locked out after %d failed attempts", maxAttempts), "")
    }

    return shouldLockout, attempts, nil
}

// getOwnerPermissions returns all permissions for owner
func (s *AdminService) getOwnerPermissions() []string {
    return []string{
        models.PermissionReadUsers,
        models.PermissionWriteUsers,
        models.PermissionBanUsers,
        models.PermissionUnbanUsers,
        models.PermissionVerifyKYC,
        models.PermissionManageAdmins,
        models.PermissionViewAuditLog,
        models.PermissionExportData,
        models.PermissionDeleteUsers,
        models.PermissionSystemConfig,
    }
}

// getPermissionsForRole returns permissions based on role
func (s *AdminService) getPermissionsForRole(roleLevel string) []string {
    switch roleLevel {
    case models.RoleLevelOwner:
        return s.getOwnerPermissions()

    case models.RoleLevelSuperEmployee:
        return []string{
            models.PermissionReadUsers,
            models.PermissionWriteUsers,
            models.PermissionBanUsers,
            models.PermissionUnbanUsers,
            models.PermissionVerifyKYC,
            models.PermissionManageAdmins,
            models.PermissionViewAuditLog,
        }

    case models.RoleLevelEmployee:
        return []string{
            models.PermissionReadUsers,
            models.PermissionWriteUsers,
            models.PermissionVerifyKYC,
            models.PermissionViewAuditLog,
        }

    default:
        return []string{}
    }
}

// logAuditAction logs an admin action to audit trail
func (s *AdminService) logAuditAction(ctx context.Context, adminID uuid.UUID, actionType, resourceType string,
    resourceID uuid.UUID, status, reason, changes string) {
    audit := models.NewAuditLog(adminID, actionType, resourceType, resourceID, status)
    audit.Reason = reason

    if changes != "" {
        audit.Changes = changes
    }

    if err := s.auditRepo.LogAdminAction(ctx, audit); err != nil {
        s.logger.Warn("Failed to log audit action",
            util.String("action", actionType),
            util.ErrorField(err),
        )
    }
}

// HealthCheck verifies admin service health
func (s *AdminService) HealthCheck(ctx context.Context) error {
    return s.adminRepo.HealthCheck(ctx)
}

// GetStats returns admin service statistics
func (s *AdminService) GetStats(ctx context.Context) (map[string]interface{}, error) {
    return s.adminRepo.GetRepositoryStats(ctx)
}

// ✅ FIXED: AuthenticateAdminWithSession - Only checks admin table
func (s *AdminService) AuthenticateAdminWithSession(ctx context.Context, phone string, deviceID string, ipAddress string) (*models.AdminUser, string, error) {
    // 1. Authenticate admin (checks only admin_users table)
    admin, err := s.AuthenticateAdmin(ctx, phone)
    if err != nil {
        return nil, "", err
    }

    // 2. Create admin session
    sessionReq := &CreateAdminSessionRequest{
        AdminID:           admin.AdminID,
        AdminRoleLevel:    admin.AdminRoleLevel,
        DeviceID:          deviceID,
        DeviceFingerprint: "admin-web",
        IPAddress:         ipAddress,
        Permissions:       admin.AdminPermissions,
    }

    session, err := s.sessionService.CreateAdminSession(ctx, sessionReq)
    if err != nil {
        return nil, "", fmt.Errorf("failed to create admin session: %w", err)
    }

    // 3. Update last login
    if err := s.adminRepo.UpdateLastLogin(ctx, admin.AdminID); err != nil {
        s.logger.Warn("Failed to update last login",
            util.String("admin_id", admin.AdminID.String()),
            util.ErrorField(err),
        )
    }

    // 4. Log audit action
    s.logAuditAction(ctx, admin.AdminID, models.ActionAdminLogin, models.ResourceTypeAdmin,
        admin.AdminID, models.StatusSuccess, "Admin login with session", "")

    // 5. Return both admin and session token
    return admin, session.SessionToken, nil
}