package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client" // ✅ NEW import for DBTX
	"auth-service/internal/encryption"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
)

type AdminService struct {
	adminRepo        postgres.AdminRepository
	companyRepo      postgres.CompanyRepository
	pgClient         *client.PostgresClient // ✅ NEW — used to hand a DBTX to repo methods
	sessionService   *SessionService
	otpService       *OTPService
	mpinService      *MPINService
	deviceService    *DeviceService
	hasher           *hashing.Hasher
	encryptionMgr    *encryption.EncryptionManager
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

// ✅ NEW — pgClient added as a parameter. All callers of NewAdminService
// must pass the PostgresClient so the service can pass a DBTX to repo methods.
func NewAdminService(
	adminRepo postgres.AdminRepository,
	companyRepo postgres.CompanyRepository,
	pgClient *client.PostgresClient,
	sessionService *SessionService,
	otpService *OTPService,
	mpinService *MPINService,
	deviceService *DeviceService,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *AdminService {
	return &AdminService{
		adminRepo:        adminRepo,
		companyRepo:      companyRepo,
		pgClient:         pgClient,
		sessionService:   sessionService,
		otpService:       otpService,
		mpinService:      mpinService,
		deviceService:    deviceService,
		hasher:           hasher,
		encryptionMgr:    encryptionMgr,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (s *AdminService) GetAdminRole(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) (*models.AdminRole, error) {
	startTime := time.Now()
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_name": role.RoleName,
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	return role, nil
}

func (s *AdminService) GetAdminRoles(ctx context.Context, requesterID uuid.UUID, limit int, offset int, roleType *int) ([]*models.AdminRole, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, appErrors.ErrPermissionDenied
	}

	roles, totalCount, err := s.adminRepo.GetAdminRoles(ctx, limit, offset, roleType)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit":       limit,
				"count":       len(roles),
				"total_count": totalCount,
				"duration":    int64(time.Since(startTime).Milliseconds()),
			})
	}
	return roles, totalCount, nil
}

func (s *AdminService) UpdateAdminRole(ctx context.Context, roleID uuid.UUID, updates *models.AdminRoleUpdateRequest, updatedBy uuid.UUID) (*models.AdminRole, error) {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_role-%s", roleID.String())
	}
	var cached *models.AdminRole
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	existingRole, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if existingRole.IsSystemRole {
		return nil, appErrors.ErrSystemRole
	}

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}
	if !updater.IsOwner() && existingRole.RoleType == models.RoleTypeManager && !updater.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	beforeJSON, _ := json.Marshal(existingRole)

	if updates.RoleName != nil && *updates.RoleName != "" {
		existingRole.RoleName = *updates.RoleName
	}
	if updates.Description != nil {
		existingRole.Description = *updates.Description
	}
	existingRole.UpdatedAt = time.Now().UTC()

	changes := make(map[string]interface{})
	if len(updates.AddDepartments) > 0 || len(updates.RemoveDepartments) > 0 {
		if err := s.processRoleDepartmentUpdates(ctx, roleID, updates, updatedBy, updater, existingRole); err != nil {
			return nil, err
		}
		changes["departments_added"] = len(updates.AddDepartments)
		changes["departments_removed"] = len(updates.RemoveDepartments)
	}
	if len(updates.AddPermissions) > 0 || len(updates.RemovePermissions) > 0 || len(updates.ReplacePermissions) > 0 {
		if err := s.processRolePermissionUpdates(ctx, roleID, updates, updatedBy, updater, existingRole); err != nil {
			return nil, err
		}
		changes["permissions_added"] = len(updates.AddPermissions)
		changes["permissions_removed"] = len(updates.RemovePermissions)
		if len(updates.ReplacePermissions) > 0 {
			changes["permissions_replaced"] = len(updates.ReplacePermissions)
		}
	}

	if err := s.adminRepo.UpdateAdminRole(ctx, existingRole); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(existingRole)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "update", "admin_role",
			&roleID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"changes":  changes,
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, existingRole)
	return existingRole, nil
}

func (s *AdminService) DeleteAdminRole(ctx context.Context, roleID uuid.UUID, deletedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_role-%s", roleID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	existingRole, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if existingRole.IsSystemRole {
		return appErrors.ErrSystemRole
	}

	deleter, err := s.adminRepo.GetAdminByID(ctx, deletedBy)
	if err != nil {
		return fmt.Errorf("%w: deleter not found", appErrors.ErrNotFound)
	}
	if !deleter.IsOwner() && existingRole.RoleType == models.RoleTypeManager && !deleter.IsSuperEmployee() {
		return appErrors.ErrPermissionDenied
	}

	admins, err := s.GetAdminsByRole(ctx, roleID, 1, 0, deletedBy)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if len(admins) > 0 {
		return appErrors.ErrRoleInUse
	}

	beforeJSON, _ := json.Marshal(existingRole)
	if err := s.adminRepo.DeleteAdminRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "delete", "admin_role",
			&roleID, "admin", &deletedBy, beforeJSON, nil, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAdminUser(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, admin) {
		return nil, appErrors.ErrPermissionDenied
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"username": admin.Username,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, nil
}

func (s *AdminService) UpdateAdminUser(ctx context.Context, adminID uuid.UUID, updates map[string]interface{}, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if len(updates) == 0 {
		return appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_user-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}

	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target admin not found", appErrors.ErrNotFound)
	}

	if updater.AdminID != adminID && !updater.IsOwner() && !updater.IsSuperEmployee() && !s.canManageAdmin(updater, targetAdmin) {
		return appErrors.ErrPermissionDenied
	}

	beforeJSON, _ := json.Marshal(targetAdmin)

	if newRoleID, ok := updates["admin_role_id"].(uuid.UUID); ok {
		newRole, err := s.adminRepo.GetAdminRole(ctx, newRoleID)
		if err != nil {
			return fmt.Errorf("%w: new role not found", appErrors.ErrNotFound)
		}
		if !updater.IsOwner() {
			if newRole.RoleType == models.RoleTypeManager && !updater.IsSuperEmployee() {
				return appErrors.ErrPermissionDenied
			}
			roleDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, newRoleID)
			if err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
			}
			for _, dept := range roleDepts {
				hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
				if err != nil || !hasAccess {
					return appErrors.ErrPermissionDenied
				}
			}
		}
		updates["role_type"] = newRole.RoleType
	}

	if username, ok := updates["username"].(string); ok && username != "" {
		existing, _ := s.adminRepo.GetAdminByUsername(ctx, username)
		if existing != nil && existing.AdminID != adminID {
			return appErrors.ErrDuplicate
		}
	}

	if err := s.adminRepo.UpdateAdminUser(ctx, adminID, updates); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(targetAdmin)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"updates":  updates,
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) DeleteAdminUser(ctx context.Context, adminID uuid.UUID, deletedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_user-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	deleter, err := s.adminRepo.GetAdminByID(ctx, deletedBy)
	if err != nil {
		return fmt.Errorf("%w: deleter not found", appErrors.ErrNotFound)
	}

	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target admin not found", appErrors.ErrNotFound)
	}

	if !deleter.IsOwner() && !deleter.IsSuperEmployee() && !s.canManageAdmin(deleter, targetAdmin) {
		return appErrors.ErrPermissionDenied
	}

	if targetAdmin.IsSuperAdmin() {
		return appErrors.ErrSuperAdminRequired
	}

	beforeJSON, _ := json.Marshal(targetAdmin)
	if err := s.adminRepo.DeleteAdminUser(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "delete", "admin_user",
			&adminID, "admin", &deletedBy, beforeJSON, nil, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) AuthenticateAdmin(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()
	phoneHash := s.GeneratePhoneHash(phone)
	admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", appErrors.ErrUnauthorized)
	}
	if !admin.IsActive {
		return nil, appErrors.ErrAdminInactive
	}

	if err := s.adminRepo.UpdateAdminLastLogin(ctx, admin.AdminID); err != nil {
		// log failure but continue
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "authenticate", "admin_user",
			&admin.AdminID, "system", nil, nil, nil, map[string]interface{}{
				"status":   "success",
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, nil
}

func (s *AdminService) AuthenticateAdminWithSession(ctx context.Context, phone string, deviceID string, ipAddress string) (*models.AdminUser, string, error) {
	startTime := time.Now()
	admin, err := s.AuthenticateAdmin(ctx, phone)
	if err != nil {
		return nil, "", err
	}

	adminWithPerms, err := s.adminRepo.GetAdminWithPermissions(ctx, admin.AdminID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	var permissionMask []uint64
	if len(adminWithPerms.Permissions) > 0 {
		perms := make([]*models.Permission, len(adminWithPerms.Permissions))
		for i := range adminWithPerms.Permissions {
			perms[i] = &adminWithPerms.Permissions[i]
		}
		permissionMask = s.buildPermissionMaskFromPermissions(perms)
	}

	sessionReq := &CreateAdminSessionRequest{
		AdminID:           admin.AdminID,
		Role:              adminWithPerms.GetRoleString(),
		DeviceID:          deviceID,
		DeviceFingerprint: "admin-web",
		IPAddress:         ipAddress,
		PermissionMask:    permissionMask,
	}
	session, err := s.sessionService.CreateAdminSession(ctx, sessionReq)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "create_session", "admin_user",
			&admin.AdminID, "admin", &admin.AdminID, nil, nil, map[string]interface{}{
				"device_id": deviceID,
				"ip":        ipAddress,
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, session.SessionToken, nil
}

func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("deactivate-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !admin.IsActive {
		return appErrors.ErrInvalidState
	}

	deactivator, err := s.adminRepo.GetAdminByID(ctx, deactivatedBy)
	if err != nil {
		return fmt.Errorf("%w: deactivator not found", appErrors.ErrNotFound)
	}
	if !deactivator.IsOwner() && !deactivator.IsSuperEmployee() && !s.canManageAdmin(deactivator, admin) {
		return appErrors.ErrPermissionDenied
	}
	if admin.IsSuperAdmin() {
		return appErrors.ErrSuperAdminRequired
	}

	beforeJSON, _ := json.Marshal(admin)
	if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "deactivate", "admin_user",
			&adminID, "admin", &deactivatedBy, beforeJSON, nil, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) ActivateAdmin(ctx context.Context, adminID uuid.UUID, activatedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("activate-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if admin.IsActive {
		return appErrors.ErrInvalidState
	}

	activator, err := s.adminRepo.GetAdminByID(ctx, activatedBy)
	if err != nil {
		return fmt.Errorf("%w: activator not found", appErrors.ErrNotFound)
	}
	if !activator.IsOwner() && !activator.IsSuperEmployee() && !s.canManageAdmin(activator, admin) {
		return appErrors.ErrPermissionDenied
	}

	beforeJSON, _ := json.Marshal(admin)
	if err := s.adminRepo.ActivateAdmin(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "activate", "admin_user",
			&adminID, "admin", &activatedBy, beforeJSON, nil, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAdminPermissions(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) ([]*models.Permission, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: admin not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, targetAdmin) {
		return nil, appErrors.ErrPermissionDenied
	}

	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_permissions", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(permissions),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return permissions, nil
}

func (s *AdminService) CheckAdminPermission(ctx context.Context, adminID uuid.UUID, permissionName string) (bool, error) {
	startTime := time.Now()
	has, err := s.adminRepo.AdminHasPermission(ctx, adminID, permissionName)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "check_permission", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"permission": permissionName,
				"has":        has,
				"duration":   int64(time.Since(startTime).Milliseconds()),
			})
	}
	return has, nil
}

func (s *AdminService) GetAdminRoleDepartments(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) ([]*models.SystemDepartment, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	_, err = s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		roleDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, dept := range roleDepts {
			has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil || !has {
				return nil, appErrors.ErrPermissionDenied
			}
		}
	}

	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_departments", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(departments),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return departments, nil
}

func (s *AdminService) AssignDepartmentToAdminRole(ctx context.Context, roleID uuid.UUID, departmentID uuid.UUID, assignedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("assign_dept-%s-%s", roleID.String(), departmentID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	assigner, err := s.adminRepo.GetAdminByID(ctx, assignedBy)
	if err != nil {
		return fmt.Errorf("%w: assigner not found", appErrors.ErrNotFound)
	}
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if !assigner.IsOwner() && role.RoleType == models.RoleTypeManager && !assigner.IsSuperEmployee() {
		return appErrors.ErrPermissionDenied
	}
	if !assigner.IsOwner() {
		// ✅ FIX: pass s.pgClient.Pool() as the DBTX (read-only, no tx needed)
		systemDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, sysDept := range systemDepts {
			if sysDept.SystemDepartmentID == departmentID {
				has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, assignedBy, sysDept.Bitmask)
				if err != nil || !has {
					return appErrors.ErrPermissionDenied
				}
				break
			}
		}
	}

	if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "assign_department", "admin_role",
			&roleID, "admin", &assignedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
				"ip":            ip,
				"duration":      int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) RemoveDepartmentFromAdminRole(ctx context.Context, roleID uuid.UUID, departmentID uuid.UUID, removedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("remove_dept-%s-%s", roleID.String(), departmentID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
	if err != nil {
		return fmt.Errorf("%w: remover not found", appErrors.ErrNotFound)
	}
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if !remover.IsOwner() && role.RoleType == models.RoleTypeManager && !remover.IsSuperEmployee() {
		return appErrors.ErrPermissionDenied
	}
	if !remover.IsOwner() {
		// ✅ FIX: pass s.pgClient.Pool()
		systemDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, sysDept := range systemDepts {
			if sysDept.SystemDepartmentID == departmentID {
				has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, removedBy, sysDept.Bitmask)
				if err != nil || !has {
					return appErrors.ErrPermissionDenied
				}
				break
			}
		}
	}

	if err := s.adminRepo.RemoveDepartmentFromAdminRole(ctx, roleID, departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "remove_department", "admin_role",
			&roleID, "admin", &removedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
				"ip":            ip,
				"duration":      int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) UpdateAdminReportsTo(ctx context.Context, adminID uuid.UUID, reportsTo *uuid.UUID, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return appErrors.ErrInvalidInput
	}
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_reports-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	assigner, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: assigner not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if !assigner.IsOwner() && !assigner.IsSuperEmployee() && !s.canManageAdmin(assigner, targetAdmin) {
		return appErrors.ErrPermissionDenied
	}

	var reportsToAdmin *models.AdminUser
	if reportsTo != nil {
		reportsToAdmin, err = s.adminRepo.GetAdminByID(ctx, *reportsTo)
		if err != nil {
			return fmt.Errorf("%w: reports_to admin not found", appErrors.ErrNotFound)
		}
		if reportsToAdmin.RoleType < targetAdmin.RoleType {
			return appErrors.ErrInvalidInput
		}
		if *reportsTo == adminID {
			return appErrors.ErrInvalidInput
		}
		chain, err := s.adminRepo.GetReportingChain(ctx, *reportsTo)
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, ca := range chain {
			if ca.AdminID == adminID {
				return appErrors.ErrInvalidInput
			}
		}
	}

	beforeJSON, _ := json.Marshal(targetAdmin)
	if err := s.adminRepo.UpdateAdminReportsTo(ctx, adminID, reportsTo); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(targetAdmin)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_reports_to", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetDirectReports(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	_, err = s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() {
		chain, err := s.adminRepo.GetReportingChain(ctx, adminID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		found := false
		for _, ca := range chain {
			if ca.AdminID == requesterID {
				found = true
				break
			}
		}
		if !found {
			return nil, appErrors.ErrPermissionDenied
		}
	}

	reports, err := s.adminRepo.GetDirectReports(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_direct_reports", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(reports),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return reports, nil
}

func (s *AdminService) GetReportingChain(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	_, err = s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() {
		chain, err := s.adminRepo.GetReportingChain(ctx, adminID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		found := false
		for _, ca := range chain {
			if ca.AdminID == requesterID {
				found = true
				break
			}
		}
		if !found {
			return nil, appErrors.ErrPermissionDenied
		}
	}

	chain, err := s.adminRepo.GetReportingChain(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_reporting_chain", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depth":    len(chain),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return chain, nil
}

func (s *AdminService) UpdateAdminProfile(ctx context.Context, adminID uuid.UUID, username string, fullName string, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil || username == "" || fullName == "" {
		return appErrors.ErrInvalidInput
	}
	if !isValidUsername(username) {
		return appErrors.ErrInvalidInput
	}
	if len(fullName) < 2 || len(fullName) > 100 {
		return appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("profile-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if updater.AdminID != adminID && !updater.IsOwner() && !updater.IsSuperEmployee() && !s.canManageAdmin(updater, targetAdmin) {
		return appErrors.ErrPermissionDenied
	}

	if username != targetAdmin.Username {
		existing, _ := s.adminRepo.GetAdminByUsername(ctx, username)
		if existing != nil {
			return appErrors.ErrDuplicate
		}
	}

	beforeJSON, _ := json.Marshal(targetAdmin)
	if err := s.adminRepo.UpdateAdminProfile(ctx, adminID, username, fullName); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(targetAdmin)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_profile", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"new_username": username,
				"new_fullname": fullName,
				"ip":           ip,
				"duration":     int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) UpdateAdminPhone(ctx context.Context, adminID uuid.UUID, newPhone string, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil || newPhone == "" {
		return appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("phone-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if updater.AdminID != adminID && !updater.IsOwner() && !updater.IsSuperEmployee() && !s.canManageAdmin(updater, targetAdmin) {
		return appErrors.ErrPermissionDenied
	}

	newPhoneHash := s.GeneratePhoneHash(newPhone)
	existing, _ := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
	if existing != nil && existing.AdminID != adminID {
		return appErrors.ErrDuplicate
	}

	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, _ := uuid.Parse(encryptedResult.KeyID)
	phoneEncrypted := []byte(encryptedResult.EncryptedValue)

	if err := s.adminRepo.UpdateAdminPhone(ctx, adminID, newPhoneHash, phoneEncrypted, keyID, encryptedResult.EncryptedDEK); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_phone", "admin_user",
			&adminID, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) BulkUpdateReportsTo(ctx context.Context, adminIDs []uuid.UUID, reportsTo *uuid.UUID, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if len(adminIDs) == 0 {
		return appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bulk_reports-%s", uuid.New().String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}

	for _, adminID := range adminIDs {
		if adminID == uuid.Nil {
			return appErrors.ErrInvalidInput
		}
		target, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return fmt.Errorf("%w: target %s not found", appErrors.ErrNotFound, adminID)
		}
		if !updater.IsOwner() && !updater.IsSuperEmployee() && !s.canManageAdmin(updater, target) {
			return appErrors.ErrPermissionDenied
		}
		if reportsTo != nil && *reportsTo == adminID {
			return appErrors.ErrInvalidInput
		}
		if reportsTo != nil {
			reportsToAdmin, err := s.adminRepo.GetAdminByID(ctx, *reportsTo)
			if err != nil {
				return fmt.Errorf("%w: reports_to admin not found", appErrors.ErrNotFound)
			}
			if reportsToAdmin.RoleType < target.RoleType {
				return appErrors.ErrInvalidInput
			}
			chain, err := s.adminRepo.GetReportingChain(ctx, *reportsTo)
			if err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
			}
			for _, ca := range chain {
				if ca.AdminID == adminID {
					return appErrors.ErrInvalidInput
				}
			}
		}
	}

	if err := s.adminRepo.BulkUpdateReportsTo(ctx, adminIDs, reportsTo); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "bulk_update_reports_to", "admin_user",
			nil, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"admin_count": len(adminIDs),
				"ip":          ip,
				"duration":    int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAllAdmins(ctx context.Context, requesterID uuid.UUID, limit int) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	admins, err := s.adminRepo.GetAllAdmins(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_all", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit":    limit,
				"count":    len(admins),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admins, nil
}

func (s *AdminService) GetActiveAdmins(ctx context.Context, requesterID uuid.UUID, limit int) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	admins, err := s.adminRepo.GetActiveAdmins(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_active", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit":    limit,
				"count":    len(admins),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admins, nil
}

func (s *AdminService) GetAdminsByRole(ctx context.Context, roleID uuid.UUID, limit int, offset int, requesterID uuid.UUID) ([]*models.AdminUserSearchResult, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	_, err = s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		depts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, dept := range depts {
			has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil || !has {
				return nil, appErrors.ErrPermissionDenied
			}
		}
	}

	admins, err := s.adminRepo.GetAdminsByRole(ctx, roleID, false, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_by_role", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_id":  roleID.String(),
				"count":    len(admins),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admins, nil
}

func (s *AdminService) GetAdminSuggestions(ctx context.Context, prefix string, requesterID uuid.UUID, roleTypeFilter *int, excludeSuperAdmin bool, limit int) ([]*models.AdminSuggestion, error) {
	startTime := time.Now()
	if prefix == "" {
		return nil, appErrors.ErrInvalidInput
	}
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() && roleTypeFilter != nil && *roleTypeFilter != models.RoleTypeEmployee {
		return nil, appErrors.ErrPermissionDenied
	}

	suggestions, err := s.adminRepo.GetAdminSuggestions(ctx, prefix, roleTypeFilter, excludeSuperAdmin, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "suggestions", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"prefix":   prefix,
				"count":    len(suggestions),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return suggestions, nil
}

func (s *AdminService) GetAdminWithPermissions(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (*models.AdminWithPermissions, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, targetAdmin) {
		return nil, appErrors.ErrPermissionDenied
	}

	adminWithPerms, err := s.adminRepo.GetAdminWithPermissions(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_with_perms", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"permissions": len(adminWithPerms.Permissions),
				"departments": len(adminWithPerms.Departments),
				"duration":    int64(time.Since(startTime).Milliseconds()),
			})
	}
	return adminWithPerms, nil
}

func (s *AdminService) IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	startTime := time.Now()
	attempts, err := s.adminRepo.IncrementAdminFailedLoginAttempts(ctx, adminID)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	const maxAttempts = 5
	if attempts >= maxAttempts {
		if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
			// log failure but continue
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "failed_login", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"attempts": attempts,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return attempts, nil
}

func (s *AdminService) ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()
	if err := s.adminRepo.ResetAdminFailedLoginAttempts(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "reset_failed_attempts", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return nil
}

func (s *AdminService) SetAdminAvatar(ctx context.Context, adminID uuid.UUID, avatarHash string, avatarObjectKey string, avatarMimeType string, setBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil || avatarHash == "" || avatarObjectKey == "" {
		return appErrors.ErrInvalidInput
	}
	validMimeTypes := map[string]bool{"image/jpeg": true, "image/jpg": true, "image/png": true, "image/gif": true, "image/webp": true, "image/svg+xml": true}
	if !validMimeTypes[avatarMimeType] {
		return appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("avatar-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	requester, err := s.adminRepo.GetAdminByID(ctx, setBy)
	if err != nil {
		return fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() {
		return appErrors.ErrPermissionDenied
	}

	existing, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err := s.adminRepo.SetAdminAvatar(ctx, adminID, avatarHash, avatarObjectKey, avatarMimeType); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	metadata := map[string]interface{}{
		"new_hash":   avatarHash,
		"object_key": avatarObjectKey,
		"mime":       avatarMimeType,
		"ip":         ip,
		"duration":   int64(time.Since(startTime).Milliseconds()),
	}
	if existing != nil {
		metadata["old_hash"] = existing.AvatarHash
		metadata["old_key"] = existing.AvatarObjectKey
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "set_avatar", "admin_user",
			&adminID, "admin", &setBy, nil, nil, metadata)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAdminAvatar(ctx context.Context, adminID uuid.UUID) (*models.AdminAvatar, error) {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return nil, appErrors.ErrInvalidInput
	}
	_, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: admin not found", appErrors.ErrNotFound)
	}

	avatar, err := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar": avatar != nil,
				"duration":   int64(time.Since(startTime).Milliseconds()),
			})
	}
	return avatar, nil
}

func (s *AdminService) DeactivateAdminAvatar(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return appErrors.ErrInvalidInput
	}
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("deactivate_avatar-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	requester, err := s.adminRepo.GetAdminByID(ctx, deactivatedBy)
	if err != nil {
		return fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() {
		return appErrors.ErrPermissionDenied
	}

	existing, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if existing == nil {
		return nil
	}

	if err := s.adminRepo.DeactivateAdminAvatar(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "deactivate_avatar", "admin_user",
			&adminID, "admin", &deactivatedBy, nil, nil, map[string]interface{}{
				"old_hash": existing.AvatarHash,
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAdminAvatarWithFallback(ctx context.Context, adminID uuid.UUID) (*models.AdminAvatar, string, error) {
	startTime := time.Now()
	avatar, err := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err != nil && err != sql.ErrNoRows {
		return nil, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var initials string
	if avatar == nil {
		admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
		}
		initials = s.generateInitialsFromName(admin.FullName)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar_fallback", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar":   avatar != nil,
				"has_initials": initials != "",
				"duration":     int64(time.Since(startTime).Milliseconds()),
			})
	}
	return avatar, initials, nil
}

func (s *AdminService) GetAvatarInfo(ctx context.Context, adminID uuid.UUID) (*models.AdminAvatarInfo, error) {
	startTime := time.Now()
	avatar, err := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var initials string
	if avatar == nil {
		admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
		}
		initials = s.generateInitialsFromName(admin.FullName)
	}
	info := &models.AdminAvatarInfo{
		AdminID:   adminID,
		HasAvatar: avatar != nil,
		Avatar:    avatar,
		Initials:  initials,
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar_info", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar":   info.HasAvatar,
				"has_initials": info.Initials != "",
				"duration":     int64(time.Since(startTime).Milliseconds()),
			})
	}
	return info, nil
}

func (s *AdminService) BulkGetAvatarInfo(ctx context.Context, adminIDs []uuid.UUID) (map[uuid.UUID]*models.AdminAvatarInfo, error) {
	startTime := time.Now()
	if len(adminIDs) == 0 {
		return make(map[uuid.UUID]*models.AdminAvatarInfo), nil
	}
	result := make(map[uuid.UUID]*models.AdminAvatarInfo)
	for _, adminID := range adminIDs {
		info, err := s.GetAvatarInfo(ctx, adminID)
		if err != nil {
			continue
		}
		result[adminID] = info
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "bulk_avatar_info", "admin_user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"requested": len(adminIDs),
				"returned":  len(result),
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	return result, nil
}

func (s *AdminService) GetAvailableManagers(ctx context.Context, excludeID *uuid.UUID, requesterID uuid.UUID) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	managers, err := s.adminRepo.GetAvailableManagers(ctx, excludeID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "available_managers", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(managers),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return managers, nil
}

func (s *AdminService) GetAdminWithReportsToName(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (*models.AdminUserSearchResult, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, targetAdmin) {
		return nil, appErrors.ErrPermissionDenied
	}

	result, err := s.adminRepo.GetAdminWithReportsToName(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_with_reports_to", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"has_reports_to": result.ReportsTo != nil,
				"duration":       int64(time.Since(startTime).Milliseconds()),
			})
	}
	return result, nil
}

func (s *AdminService) GetAdminHierarchy(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) ([]*models.AdminHierarchy, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: target not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, targetAdmin) {
		return nil, appErrors.ErrPermissionDenied
	}

	hierarchy, err := s.adminRepo.GetAdminHierarchy(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "hierarchy", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depth":    len(hierarchy),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return hierarchy, nil
}

func (s *AdminService) CanAssignReportsTo(ctx context.Context, assignerID uuid.UUID, targetID uuid.UUID) (bool, error) {
	startTime := time.Now()
	can, err := s.adminRepo.CanAssignReportsTo(ctx, assignerID, targetID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "can_assign_reports_to", "admin_user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"assigner": assignerID.String(),
				"target":   targetID.String(),
				"result":   can,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return can, nil
}

func (s *AdminService) GetAdminByPhone(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()
	phoneHash := s.GeneratePhoneHash(phone)
	admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_by_phone", "admin_user",
			&admin.AdminID, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, nil
}

func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, adminID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "record_login", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return nil
}

func (s *AdminService) RecordFailedLogin(ctx context.Context, adminID uuid.UUID) (bool, int, error) {
	startTime := time.Now()
	attempts, err := s.IncrementAdminFailedLoginAttempts(ctx, adminID)
	if err != nil {
		return false, 0, err
	}
	shouldLockout := attempts >= 5

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "record_failed_login", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"attempts": attempts,
				"lockout":  shouldLockout,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return shouldLockout, attempts, nil
}

func (s *AdminService) GetAdminWithDetails(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, []string, []string, error) {
	startTime := time.Now()
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	permissions, _ := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	departments, _ := s.adminRepo.GetAdminRoleDepartments(ctx, admin.AdminRoleID)

	permNames := make([]string, len(permissions))
	for i, p := range permissions {
		permNames[i] = p.PermissionName
	}
	deptNames := make([]string, len(departments))
	for i, d := range departments {
		deptNames[i] = d.Name
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_details", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"permissions": len(permNames),
				"departments": len(deptNames),
				"duration":    int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, permNames, deptNames, nil
}

func (s *AdminService) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
	startTime := time.Now()
	admin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_owner", "admin_user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admin, nil
}

func (s *AdminService) GetSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	return s.GetAdminOwner(ctx)
}

func (s *AdminService) HealthCheck(ctx context.Context) error {
	startTime := time.Now()
	if err := s.adminRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_service", "health_check", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return nil
}

func (s *AdminService) GetStats(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()
	stats, err := s.adminRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_service", "get_stats", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return stats, nil
}

// helper functions remain unchanged
func (s *AdminService) generateInitialsFromName(fullName string) string {
	if fullName == "" {
		return ""
	}
	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return ""
	}
	var initialsBuilder strings.Builder
	if len(parts) > 0 {
		initialsBuilder.WriteString(strings.ToUpper(string(parts[0][0])))
	}
	if len(parts) > 1 {
		initialsBuilder.WriteString(strings.ToUpper(string(parts[len(parts)-1][0])))
	}
	return initialsBuilder.String()
}

func (s *AdminService) canUpdateAdminProfile(requester, target *models.AdminUser) bool {
	if requester.IsOwner() {
		return true
	}
	if requester.IsSuperEmployee() && target.IsEmployee() {
		return true
	}
	if requester.IsManager() && target.IsEmployee() {
		return s.canManageAdmin(requester, target)
	}
	return requester.AdminID == target.AdminID
}

func (s *AdminService) canChangePhone(requester, target *models.AdminUser) bool {
	if requester.IsOwner() {
		return true
	}
	if requester.IsSuperEmployee() && target.IsEmployee() {
		return true
	}
	return requester.AdminID == target.AdminID
}

func (s *AdminService) isUsernameTaken(ctx context.Context, username string, excludeAdminID uuid.UUID) bool {
	admin, err := s.adminRepo.GetAdminByUsername(ctx, username)
	if err != nil {
		return false
	}
	return admin != nil && admin.AdminID != excludeAdminID
}

func getRoleStringFromMask(roleMask uint64) string {
	switch roleMask {
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

func isValidRoleMask(roleMask uint64) bool {
	return roleMask == 1 || roleMask == 2 || roleMask == 4
}

func (s *AdminService) SearchAdminsWithFilters(ctx context.Context, requesterID uuid.UUID, req *models.AdminSearchRequest) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		if req.RoleTypeFilter != nil {
			switch *req.RoleTypeFilter {
			case models.RoleTypeEmployee:
			case models.RoleTypeManager:
				return nil, 0, appErrors.ErrPermissionDenied
			case models.RoleTypeSuperAdmin:
				return nil, 0, appErrors.ErrPermissionDenied
			default:
				return nil, 0, appErrors.ErrInvalidInput
			}
		}
	}

	userSearchReq := &models.AdminUserSearchRequest{
		Query:           req.Query,
		RoleTypeFilter:  req.RoleTypeFilter,
		IncludeInactive: req.IncludeInactive,
		SearchType:      req.SearchType,
		Limit:           req.Limit,
		Offset:          req.Offset,
	}
	results, totalCount, err := s.adminRepo.SearchAdminUsers(ctx, userSearchReq)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "search_filters", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query":    req.Query,
				"count":    len(results),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return results, totalCount, nil
}

func (s *AdminService) SearchAdminsAdvanced(ctx context.Context, requesterID uuid.UUID, req *models.AdminAdvancedSearchRequest) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, appErrors.ErrPermissionDenied
	}
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	results, totalCount, err := s.adminRepo.SearchAdminsAdvanced(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "advanced_search", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query":    req.Query,
				"count":    len(results),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return results, totalCount, nil
}

func (s *AdminService) GetAdminsByDepartment(ctx context.Context, departmentID uuid.UUID, requesterID uuid.UUID, includeInactive bool, limit, offset int) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() {
		// ✅ FIX: pass s.pgClient.Pool()
		systemDept, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), departmentID)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
		}
		hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, systemDept.Bitmask)
		if err != nil || !hasAccess {
			return nil, 0, appErrors.ErrPermissionDenied
		}
	}

	admins, totalCount, err := s.adminRepo.GetAdminsByDepartment(ctx, departmentID, includeInactive, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_by_department", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"department": departmentID.String(),
				"count":      len(admins),
				"duration":   int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admins, totalCount, nil
}

func countFilters(filters models.AdminSearchFilter) int {
	count := 0
	if filters.RoleID != nil {
		count++
	}
	if filters.DepartmentID != nil {
		count++
	}
	if filters.ReportsTo != nil {
		count++
	}
	if filters.CreatedAfter != nil {
		count++
	}
	if filters.CreatedBefore != nil {
		count++
	}
	if filters.LastLoginAfter != nil {
		count++
	}
	if filters.LastLoginBefore != nil {
		count++
	}
	if filters.HasAvatar != nil {
		count++
	}
	if filters.IPWhitelist != nil {
		count++
	}
	if filters.DataAccessScope != nil {
		count++
	}
	return count
}

func (s *AdminService) buildPermissionMaskFromPermissions(permissions []*models.Permission) []uint64 {
	if len(permissions) == 0 {
		return make([]uint64, 13)
	}
	var bitPositions []uint64
	for _, perm := range permissions {
		if perm.BitIndex >= 0 {
			bitPositions = append(bitPositions, uint64(perm.BitIndex))
		}
	}
	mask := rbac.BuildMaskFromBitPositions(bitPositions)
	if len(mask) < 13 {
		fullMask := make([]uint64, 13)
		copy(fullMask, mask)
		return fullMask
	}
	return mask
}

func (s *AdminService) GetAdminPermissionMask(ctx context.Context, adminID uuid.UUID) ([]uint64, error) {
	startTime := time.Now()
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	mask := s.buildPermissionMaskFromPermissions(permissions)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_permission_mask", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return mask, nil
}

func (s *AdminService) SearchAdminUsers(ctx context.Context, req *models.AdminUserSearchRequest, requesterID uuid.UUID) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		if req.RoleTypeFilter != nil && *req.RoleTypeFilter != models.RoleTypeEmployee {
			return nil, 0, appErrors.ErrPermissionDenied
		}
	}

	results, total, err := s.adminRepo.SearchAdminUsers(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "search_users", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query":    req.Query,
				"count":    len(results),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return results, total, nil
}

func (s *AdminService) CreateAdminUser(ctx context.Context, req *models.AdminCreateRequest, createdBy uuid.UUID) (*models.AdminUser, error) {
	startTime := time.Now()
	if req.Username == "" || req.FullName == "" || req.PhoneNumber == "" || req.AdminRoleID == uuid.Nil {
		return nil, appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_user-%s", uuid.New().String())
	}
	var cached *models.AdminUser
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	creator, err := s.adminRepo.GetAdminByID(ctx, createdBy)
	if err != nil {
		return nil, fmt.Errorf("%w: creator not found", appErrors.ErrNotFound)
	}

	adminRole, err := s.adminRepo.GetAdminRole(ctx, req.AdminRoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: admin role not found", appErrors.ErrNotFound)
	}

	switch adminRole.RoleType {
	case models.RoleTypeEmployee:
		if !creator.IsOwner() && !creator.IsSuperEmployee() {
			return nil, appErrors.ErrPermissionDenied
		}
	case models.RoleTypeManager:
		if !creator.IsOwner() && !creator.IsSuperEmployee() {
			return nil, appErrors.ErrPermissionDenied
		}
	case models.RoleTypeSuperAdmin:
		return nil, appErrors.ErrInvalidInput
	default:
		return nil, appErrors.ErrInvalidInput
	}

	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, req.PhoneNumber, "phone")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, _ := uuid.Parse(encryptedResult.KeyID)
	phoneEncrypted := []byte(encryptedResult.EncryptedValue)

	existing, _ := s.adminRepo.GetAdminByUsername(ctx, req.Username)
	if existing != nil {
		return nil, appErrors.ErrDuplicate
	}
	existingPhone, _ := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if existingPhone != nil {
		return nil, appErrors.ErrDuplicate
	}

	if req.ReportsTo != nil {
		reportsToAdmin, err := s.adminRepo.GetAdminByID(ctx, *req.ReportsTo)
		if err != nil {
			return nil, fmt.Errorf("%w: reports_to not found", appErrors.ErrNotFound)
		}
		if reportsToAdmin.RoleType < adminRole.RoleType {
			return nil, appErrors.ErrInvalidInput
		}
	}

	adminID := uuid.New()
	now := time.Now().UTC()
	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		PhoneEncrypted:      phoneEncrypted,
		PhoneKeyID:          keyID,
		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
		AdminRoleID:         req.AdminRoleID,
		RoleType:            adminRole.RoleType,
		ReportsTo:           req.ReportsTo,
		AdminCreatedAt:      now,
		AdminCreatedBy:      &createdBy,
		AdminUpdatedAt:      now,
		IsActive:            true,
		DataAccessScope:     req.DataAccessScope,
		IPWhitelist:         req.IPWhitelist,
		FailedLoginAttempts: 0,
		Username:            req.Username,
		FullName:            req.FullName,
	}

	beforeJSON, _ := json.Marshal(admin)
	if err := s.adminRepo.CreateAdminUser(ctx, admin); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(admin)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "create", "admin_user",
			&adminID, "admin", &createdBy, beforeJSON, afterJSON, map[string]interface{}{
				"username": req.Username,
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, admin)
	return admin, nil
}

func (s *AdminService) GetAdminsByRoleType(ctx context.Context, roleType int, requesterID uuid.UUID, includeInactive bool, limit int, offset int) ([]*models.AdminUserSearchResult, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	switch roleType {
	case models.RoleTypeEmployee:
	case models.RoleTypeManager:
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			return nil, appErrors.ErrPermissionDenied
		}
	case models.RoleTypeSuperAdmin:
		if !requester.IsOwner() {
			return nil, appErrors.ErrPermissionDenied
		}
	default:
		return nil, appErrors.ErrInvalidInput
	}

	admins, err := s.adminRepo.GetAdminsByRoleType(ctx, roleType, includeInactive, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_by_role_type", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_type": roleType,
				"count":     len(admins),
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	return admins, nil
}

func (s *AdminService) CheckAdminDepartmentAccess(ctx context.Context, adminID uuid.UUID, departmentName string) (bool, error) {
	startTime := time.Now()
	// ✅ FIX: pass s.pgClient.Pool()
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var targetDept *models.SystemDepartment
	for _, dept := range systemDepts {
		if dept.Name == departmentName {
			targetDept = dept
			break
		}
	}
	if targetDept == nil {
		return false, fmt.Errorf("%w: department %s not found", appErrors.ErrNotFound, departmentName)
	}

	hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, adminID, targetDept.Bitmask)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "check_department_access", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"department": departmentName,
				"has":        hasAccess,
				"duration":   int64(time.Since(startTime).Milliseconds()),
			})
	}
	return hasAccess, nil
}

func (s *AdminService) SearchAdminsByName(ctx context.Context, name string, requesterID uuid.UUID, limit int, offset int) ([]*models.AdminUserSearchResult, int, error) {
	req := &models.AdminSearchRequest{
		Query:           name,
		SearchType:      "fulltext",
		IncludeInactive: false,
		Limit:           limit,
		Offset:          offset,
	}
	return s.SearchAdminsWithFilters(ctx, requesterID, req)
}

func (s *AdminService) SearchAdminEmployees(ctx context.Context, query string, requesterID uuid.UUID, limit int, offset int) ([]*models.AdminUserSearchResult, int, error) {
	roleType := models.RoleTypeEmployee
	req := &models.AdminSearchRequest{
		Query:           query,
		RoleTypeFilter:  &roleType,
		SearchType:      "fulltext",
		IncludeInactive: false,
		Limit:           limit,
		Offset:          offset,
	}
	return s.SearchAdminsWithFilters(ctx, requesterID, req)
}

func (s *AdminService) SearchAdminManagers(ctx context.Context, query string, requesterID uuid.UUID, limit int, offset int) ([]*models.AdminUserSearchResult, int, error) {
	roleType := models.RoleTypeManager
	req := &models.AdminSearchRequest{
		Query:           query,
		RoleTypeFilter:  &roleType,
		SearchType:      "fulltext",
		IncludeInactive: false,
		Limit:           limit,
		Offset:          offset,
	}
	return s.SearchAdminsWithFilters(ctx, requesterID, req)
}

func (s *AdminService) GetAdminPhoneNumber(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (string, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return "", fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() {
		return "", appErrors.ErrPermissionDenied
	}

	targetAdmin, err := s.adminRepo.GetAdminWithEncryptedPhone(ctx, adminID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(targetAdmin.PhoneEncrypted),
		KeyID:          targetAdmin.PhoneKeyID.String(),
		EncryptedDEK:   targetAdmin.PhoneEncryptedDEK,
		Version:        "v1",
		CreatedAt:      targetAdmin.AdminCreatedAt,
	}
	decryptedPhone, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		return "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_phone", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"accessed": true,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return decryptedPhone, nil
}

func (s *AdminService) InitDefaultSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	phoneNumber := "+917206583437"
	username := "sarvesh"
	fullName := "Sarvesh Chhabra"
	return s.InitSuperAdmin(ctx, phoneNumber, username, fullName)
}

func (s *AdminService) CheckAndInitSuperAdmin(ctx context.Context) (bool, *models.AdminUser, error) {
	existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil && err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if existingSuperAdmin != nil {
		return false, existingSuperAdmin, nil
	}
	admin, err := s.InitSuperAdmin(ctx, "+917206583437", "sarvesh", "Sarvesh Chhabra")
	if err != nil {
		return false, nil, err
	}
	return true, admin, nil
}

func (s *AdminService) InitSuperAdmin(ctx context.Context, phoneNumber, username, fullName string) (*models.AdminUser, error) {
	startTime := time.Now()
	if phoneNumber == "" || username == "" || fullName == "" {
		return nil, appErrors.ErrInvalidInput
	}

	existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if existingSuperAdmin != nil {
		return existingSuperAdmin, nil
	}

	superAdminRole, err := s.adminRepo.GetSuperAdminRole(ctx)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var roleID uuid.UUID
	var roleCreated bool
	if superAdminRole == nil {
		roleID = uuid.New()
		now := time.Now().UTC()
		superAdminRole = &models.AdminRole{
			AdminRoleID:  roleID,
			RoleName:     "Super Admin",
			RoleLevel:    s.getRoleLevel(models.RoleTypeSuperAdmin),
			RoleType:     models.RoleTypeSuperAdmin,
			IsSystemRole: true,
			Description:  "System super administrator with full access",
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		// ✅ FIX: pass s.pgClient.Pool()
		allDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		deptIDs := make([]uuid.UUID, len(allDepts))
		for i, d := range allDepts {
			deptIDs[i] = d.SystemDepartmentID
		}
		if err := s.adminRepo.CreateSuperAdminRole(ctx, superAdminRole, deptIDs); err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		roleCreated = true
	} else {
		roleID = superAdminRole.AdminRoleID
		_ = s.adminRepo.GrantAllPermissionsToRole(ctx, roleID, uuid.Nil)
		// ✅ FIX: pass s.pgClient.Pool()
		allDepts, _ := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
		for _, d := range allDepts {
			_ = s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, d.SystemDepartmentID)
		}
	}

	phoneHash := s.GeneratePhoneHash(phoneNumber)
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, _ := uuid.Parse(encryptedResult.KeyID)
	phoneEncrypted := []byte(encryptedResult.EncryptedValue)

	adminID := uuid.New()
	now := time.Now().UTC()
	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		PhoneEncrypted:      phoneEncrypted,
		PhoneKeyID:          keyID,
		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
		AdminRoleID:         roleID,
		RoleType:            models.RoleTypeSuperAdmin,
		ReportsTo:           nil,
		AdminCreatedAt:      now,
		AdminCreatedBy:      &adminID,
		AdminUpdatedAt:      now,
		IsActive:            true,
		DataAccessScope:     []string{"*"},
		IPWhitelist:         []string{"*"},
		FailedLoginAttempts: 0,
		Username:            username,
		FullName:            fullName,
	}

	if err := s.adminRepo.CreateSuperAdminUser(ctx, admin); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "init_super_admin", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"username":     username,
				"full_name":    fullName,
				"duration":     int64(time.Since(startTime).Milliseconds()),
				"created":      true,
				"role_created": roleCreated,
			})
	}
	return admin, nil
}

func (s *AdminService) CreateAdminRole(ctx context.Context, req *models.AdminRoleCreateRequest, createdBy uuid.UUID) (*models.AdminRole, error) {
	startTime := time.Now()
	if req.RoleName == "" || req.RoleType == 0 || len(req.DepartmentIDs) == 0 {
		return nil, appErrors.ErrInvalidInput
	}
	if req.RoleType != models.RoleTypeEmployee && req.RoleType != models.RoleTypeManager {
		return nil, appErrors.ErrInvalidInput
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_role-%s", uuid.New().String())
	}
	var cached *models.AdminRole
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	creator, err := s.adminRepo.GetAdminByID(ctx, createdBy)
	if err != nil {
		return nil, fmt.Errorf("%w: creator not found", appErrors.ErrNotFound)
	}
	if req.RoleType == models.RoleTypeManager && !creator.IsOwner() && !creator.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	// ✅ FIX: pass s.pgClient.Pool()
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	deptIDs := make([]uuid.UUID, 0, len(req.DepartmentIDs))
	for _, deptID := range req.DepartmentIDs {
		found := false
		for _, sysDept := range systemDepts {
			if sysDept.SystemDepartmentID == deptID {
				if !creator.IsOwner() {
					has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, createdBy, sysDept.Bitmask)
					if err != nil || !has {
						return nil, appErrors.ErrPermissionDenied
					}
				}
				deptIDs = append(deptIDs, deptID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: department %s not found", appErrors.ErrNotFound, deptID)
		}
	}

	roleID := uuid.New()
	now := time.Now().UTC()
	role := &models.AdminRole{
		AdminRoleID:  roleID,
		RoleName:     req.RoleName,
		RoleLevel:    s.getRoleLevel(req.RoleType),
		RoleType:     req.RoleType,
		IsSystemRole: false,
		Description:  req.Description,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	beforeJSON, _ := json.Marshal(role)
	if err := s.adminRepo.CreateAdminRole(ctx, role, deptIDs); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if req.RoleType == models.RoleTypeManager {
		for _, deptID := range deptIDs {
			perms, err := s.companyRepo.GetPermissionsBySystemDepartments(ctx, []uuid.UUID{deptID}, "", "", "")
			if err != nil {
				continue
			}
			for _, perm := range perms {
				_ = s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, createdBy)
			}
		}
	}

	afterJSON, _ := json.Marshal(role)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "create", "admin_role",
			&roleID, "admin", &createdBy, beforeJSON, afterJSON, map[string]interface{}{
				"role_name": req.RoleName,
				"ip":        ip,
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, role)
	return role, nil
}

func (s *AdminService) GrantPermissionToAdminRole(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, grantedBy uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("grant_perm-%s-%s", roleID.String(), permissionID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	granted, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if granted {
		return nil
	}

	if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, permissionID, grantedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "grant_permission", "admin_role",
			&roleID, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"permission_id": permissionID.String(),
				"ip":            ip,
				"duration":      int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) GetAdminRoleWithDetails(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) (*models.AdminRole, []*models.SystemDepartment, []*models.Permission, error) {
	startTime := time.Now()
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		roleDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, dept := range roleDepts {
			has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil || !has {
				return nil, nil, nil, appErrors.ErrPermissionDenied
			}
		}
	}

	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permissions, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_details", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depts":    len(departments),
				"perms":    len(permissions),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return role, departments, permissions, nil
}

func (s *AdminService) GetAvailablePermissionsForRole(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) ([]*models.Permission, error) {
	startTime := time.Now()
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if len(departments) == 0 {
		return []*models.Permission{}, nil
	}

	deptIDs := make([]uuid.UUID, len(departments))
	for i, d := range departments {
		deptIDs[i] = d.SystemDepartmentID
	}
	perms, err := s.companyRepo.GetPermissionsBySystemDepartments(ctx, deptIDs, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	current, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	currentMap := make(map[uuid.UUID]bool)
	for _, p := range current {
		currentMap[p.PermissionID] = true
	}
	var available []*models.Permission
	for _, p := range perms {
		if !currentMap[p.PermissionID] {
			available = append(available, p)
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "available_perms", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(available),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return available, nil
}

func (s *AdminService) GetAdminRoleByName(ctx context.Context, roleName string) (*models.AdminRole, error) {
	startTime := time.Now()
	role, err := s.adminRepo.GetAdminRoleByName(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if role == nil {
		return nil, appErrors.ErrNotFound
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_by_name", "admin_role",
			&role.AdminRoleID, "system", nil, nil, nil, map[string]interface{}{
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return role, nil
}

func (s *AdminService) GetEmployeeAdminRoles(ctx context.Context, requesterID uuid.UUID) ([]*models.AdminRole, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() && !requester.IsManager() {
		return nil, appErrors.ErrPermissionDenied
	}

	roles, err := s.adminRepo.GetEmployeeAdminRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_employee", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(roles),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return roles, nil
}

func (s *AdminService) GetManagerAdminRoles(ctx context.Context, requesterID uuid.UUID) ([]*models.AdminRole, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, appErrors.ErrPermissionDenied
	}

	roles, err := s.adminRepo.GetManagerAdminRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_manager", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(roles),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return roles, nil
}

func (s *AdminService) GetAdminRolesByType(ctx context.Context, roleType int, requesterID uuid.UUID) ([]*models.AdminRole, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	switch roleType {
	case models.RoleTypeEmployee:
		if !requester.IsOwner() && !requester.IsSuperEmployee() && !requester.IsManager() {
			return nil, appErrors.ErrPermissionDenied
		}
	case models.RoleTypeManager:
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			return nil, appErrors.ErrPermissionDenied
		}
	case models.RoleTypeSuperAdmin:
		if !requester.IsOwner() {
			return nil, appErrors.ErrPermissionDenied
		}
	default:
		return nil, appErrors.ErrInvalidInput
	}

	roles, err := s.adminRepo.GetAdminRolesByType(ctx, roleType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_by_type", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_type": roleType,
				"count":     len(roles),
				"duration":  int64(time.Since(startTime).Milliseconds()),
			})
	}
	return roles, nil
}

func (s *AdminService) GetAdminDepartments(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) ([]*models.SystemDepartment, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: admin not found", appErrors.ErrNotFound)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, targetAdmin) {
		return nil, appErrors.ErrPermissionDenied
	}

	departments, err := s.adminRepo.GetAdminDepartments(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_departments", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count":    len(departments),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return departments, nil
}

func (s *AdminService) UpdateAdminUserRole(ctx context.Context, adminID uuid.UUID, newRoleID uuid.UUID, updatedBy uuid.UUID) error {
	startTime := time.Now()
	if adminID == uuid.Nil || newRoleID == uuid.Nil {
		return appErrors.ErrInvalidInput
	}
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_user_role-%s", adminID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ip, _ := ctx.Value("ip_address").(string)

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("%w: updater not found", appErrors.ErrNotFound)
	}
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("%w: target admin not found", appErrors.ErrNotFound)
	}
	newRole, err := s.adminRepo.GetAdminRole(ctx, newRoleID)
	if err != nil {
		return fmt.Errorf("%w: new role not found", appErrors.ErrNotFound)
	}
	if !updater.IsOwner() && !updater.IsSuperEmployee() {
		return appErrors.ErrPermissionDenied
	}
	if targetAdmin.IsSuperAdmin() {
		return appErrors.ErrSuperAdminRequired
	}
	if newRole.RoleType == models.RoleTypeSuperAdmin {
		return appErrors.ErrInvalidInput
	}
	if !updater.IsOwner() && newRole.RoleType == models.RoleTypeManager {
		return appErrors.ErrPermissionDenied
	}
	if !updater.IsOwner() {
		roleDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, newRoleID)
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, dept := range roleDepts {
			has, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil || !has {
				return appErrors.ErrPermissionDenied
			}
		}
	}
	if targetAdmin.AdminRoleID == newRoleID {
		return nil
	}

	_ = targetAdmin.AdminRoleID
	beforeJSON, _ := json.Marshal(targetAdmin)
	if err := s.adminRepo.UpdateAdminUserRole(ctx, adminID, newRoleID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(targetAdmin)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_role", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"new_role": newRoleID.String(),
				"ip":       ip,
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *AdminService) getRoleLevel(roleType int) int {
	switch roleType {
	case models.RoleTypeSuperAdmin:
		return 4000
	case models.RoleTypeManager:
		return 3000
	case models.RoleTypeEmployee:
		return 2000
	default:
		return 1000
	}
}

func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 50 {
		return false
	}
	for _, ch := range username {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}

func (s *AdminService) processRoleDepartmentUpdates(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
	updater *models.AdminUser,
	role *models.AdminRole,
) error {
	// ✅ FIX: pass s.pgClient.Pool()
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	deptNameToID := make(map[string]uuid.UUID)
	deptNameToDept := make(map[string]*models.SystemDepartment)
	for _, dept := range systemDepts {
		deptNameToID[dept.Name] = dept.SystemDepartmentID
		deptNameToDept[dept.Name] = dept
	}

	currentDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	currentDeptNameMap := make(map[string]bool)
	for _, dept := range currentDepts {
		currentDeptNameMap[dept.Name] = true
	}

	for _, deptName := range updates.RemoveDepartments {
		deptID, exists := deptNameToID[deptName]
		if !exists {
			return fmt.Errorf("%w: department %s not found", appErrors.ErrInvalidInput, deptName)
		}
		if !currentDeptNameMap[deptName] {
			continue
		}
		if !updater.IsOwner() {
			dept, deptExists := deptNameToDept[deptName]
			if !deptExists {
				return fmt.Errorf("%w: department %s not found", appErrors.ErrInvalidInput, deptName)
			}
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil || !hasAccess {
				return appErrors.ErrPermissionDenied
			}
		}
		if err := s.adminRepo.RemoveDepartmentFromAdminRole(ctx, roleID, deptID); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}

	for _, deptName := range updates.AddDepartments {
		deptID, exists := deptNameToID[deptName]
		if !exists {
			return fmt.Errorf("%w: department %s not found", appErrors.ErrInvalidInput, deptName)
		}
		if currentDeptNameMap[deptName] {
			continue
		}
		if !updater.IsOwner() {
			dept, deptExists := deptNameToDept[deptName]
			if !deptExists {
				return fmt.Errorf("%w: department %s not found", appErrors.ErrInvalidInput, deptName)
			}
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil || !hasAccess {
				return appErrors.ErrPermissionDenied
			}
		}
		if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, deptID); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	return nil
}

func (s *AdminService) processRolePermissionUpdates(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
	updater *models.AdminUser,
	role *models.AdminRole,
) error {
	currentDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if len(currentDepts) == 0 && (len(updates.AddPermissions) > 0 || len(updates.ReplacePermissions) > 0) {
		return appErrors.ErrInvalidInput
	}

	deptModuleMap := make(map[string]bool)
	for _, dept := range currentDepts {
		deptModuleMap[dept.ModuleCode] = true
	}

	for _, permName := range updates.RemovePermissions {
		perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
		if err != nil {
			return fmt.Errorf("%w: permission %s not found", appErrors.ErrNotFound, permName)
		}
		has, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, perm.PermissionID)
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		if !has {
			continue
		}
		if err := s.adminRepo.RevokePermissionFromAdminRole(ctx, roleID, perm.PermissionID); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}

	if len(updates.ReplacePermissions) > 0 {
		currentPerms, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		for _, perm := range currentPerms {
			if err := s.adminRepo.RevokePermissionFromAdminRole(ctx, roleID, perm.PermissionID); err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
			}
		}
		for _, permName := range updates.ReplacePermissions {
			perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
			if err != nil {
				return fmt.Errorf("%w: permission %s not found", appErrors.ErrNotFound, permName)
			}
			if !deptModuleMap[perm.Module] {
				return fmt.Errorf("%w: role lacks department for module %s", appErrors.ErrInvalidInput, perm.Module)
			}
			if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, updatedBy); err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
			}
		}
		return nil
	}

	for _, permName := range updates.AddPermissions {
		perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
		if err != nil {
			return fmt.Errorf("%w: permission %s not found", appErrors.ErrNotFound, permName)
		}
		if !deptModuleMap[perm.Module] {
			return fmt.Errorf("%w: role lacks department for module %s", appErrors.ErrInvalidInput, perm.Module)
		}
		has, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, perm.PermissionID)
		if err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		if has {
			continue
		}
		if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, updatedBy); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	return nil
}

func (s *AdminService) canManageAdmin(manager, target *models.AdminUser) bool {
	if manager.IsOwner() {
		return true
	}
	if manager.IsSuperEmployee() && target.IsEmployee() {
		return true
	}
	if manager.IsManager() && target.IsEmployee() {
		managerDepts, err := s.adminRepo.GetAdminRoleDepartments(context.Background(), manager.AdminRoleID)
		if err != nil {
			return false
		}
		targetDepts, err := s.adminRepo.GetAdminRoleDepartments(context.Background(), target.AdminRoleID)
		if err != nil {
			return false
		}
		for _, targetDept := range targetDepts {
			found := false
			for _, managerDept := range managerDepts {
				if managerDept.SystemDepartmentID == targetDept.SystemDepartmentID {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

func (s *AdminService) SearchAdminRoles(ctx context.Context, query string, requesterID uuid.UUID, limit int, offset int) ([]*models.AdminRole, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, appErrors.ErrPermissionDenied
	}

	roles, totalCount, err := s.adminRepo.SearchAdminRoles(ctx, query, nil, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "search", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query":    query,
				"count":    len(roles),
				"duration": int64(time.Since(startTime).Milliseconds()),
			})
	}
	return roles, totalCount, nil
}
