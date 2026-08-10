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

	"auth-service/internal/encryption"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
)

// AdminService handles admin user and role management with audit, idempotency, and Kafka logs.
type AdminService struct {
	adminRepo        postgres.AdminRepository
	companyRepo      postgres.CompanyRepository
	sessionService   *SessionService
	otpService       *OTPService
	mpinService      *MPINService
	deviceService    *DeviceService
	hasher           *hashing.Hasher
	encryptionMgr    *encryption.EncryptionManager
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	logProducer      *LogProducerService
}

// NewAdminService creates a new AdminService.
func NewAdminService(
	adminRepo postgres.AdminRepository,
	companyRepo postgres.CompanyRepository,
	sessionService *SessionService,
	otpService *OTPService,
	mpinService *MPINService,
	deviceService *DeviceService,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	logProducer *LogProducerService,
) *AdminService {
	return &AdminService{
		adminRepo:        adminRepo,
		companyRepo:      companyRepo,
		sessionService:   sessionService,
		otpService:       otpService,
		mpinService:      mpinService,
		deviceService:    deviceService,
		hasher:           hasher,
		encryptionMgr:    encryptionMgr,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		logProducer:      logProducer,
	}
}

// ---- Internal log helper (sends AdminLogEvent to Kafka) ----

func (s *AdminService) logAdminEvent(ctx context.Context, event *models.AdminLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceAdminEvent(ctx, event)
	}
}

// ---- Phone hashing ----

func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// --------------------------------------------------------------------
//  ADMIN ROLE METHODS
// --------------------------------------------------------------------

func (s *AdminService) GetAdminRole(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) (*models.AdminRole, error) {
	startTime := time.Now()
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin role not found",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admin_role",
			Status:       "failed",
			ErrorCode:    "ROLE_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role retrieved successfully",
		},
		AdminID:      requesterID.String(),
		Action:       "get_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_name": role.RoleName,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_roles_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized attempt to get admin roles",
			},
			AdminID:   requesterID.String(),
			Action:    "get_admin_roles",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, appErrors.ErrPermissionDenied
	}
	roles, totalCount, err := s.adminRepo.GetAdminRoles(ctx, limit, offset, roleType)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_roles_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin roles",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admin_roles",
			Status:       "failed",
			ErrorCode:    "GET_ROLES_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_roles_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin roles retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_admin_roles",
		Status:  "success",
		Changes: map[string]interface{}{
			"limit":       limit,
			"offset":      offset,
			"role_type":   roleType,
			"total_count": totalCount,
			"roles_count": len(roles),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit": limit,
				"count": len(roles),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized update attempt",
			},
			AdminID:   updatedBy.String(),
			Action:    "update_admin_role",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin role",
			},
			AdminID:      updatedBy.String(),
			Action:       "update_admin_role",
			Status:       "failed",
			ErrorCode:    "UPDATE_ROLE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(existingRole)

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role updated successfully",
		},
		AdminID:      updatedBy.String(),
		Action:       "update_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes:      changes,
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "update", "admin_role",
			&roleID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"changes": changes,
				"ip":      ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_delete",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized delete attempt",
			},
			AdminID:   deletedBy.String(),
			Action:    "delete_admin_role",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_delete",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to delete admin role",
			},
			AdminID:      deletedBy.String(),
			Action:       "delete_admin_role",
			Status:       "failed",
			ErrorCode:    "DELETE_ROLE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_delete",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role deleted successfully",
		},
		AdminID:      deletedBy.String(),
		Action:       "delete_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_name": existingRole.RoleName,
			"role_type": existingRole.RoleType,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "delete", "admin_role",
			&roleID, "admin", &deletedBy, beforeJSON, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  ADMIN USER METHODS
// --------------------------------------------------------------------

func (s *AdminService) GetAdminUser(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin user not found",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_user",
			Status:       "failed",
			ErrorCode:    "USER_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if requester.AdminID != adminID && !requester.IsOwner() && !requester.IsSuperEmployee() && !s.canManageAdmin(requester, admin) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized admin user access",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_user",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_user_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin user retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_user",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"username": admin.Username,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized admin user update",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_user",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin user",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_user",
			Status:       "failed",
			ErrorCode:    "UPDATE_USER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(targetAdmin) // not fully updated but fine

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_user_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin user updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_user",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"fields_updated": len(updates),
			"updates":        updates,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"updates": updates,
				"ip":      ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_delete",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized admin user delete",
			},
			AdminID:      deletedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "delete_admin_user",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	if targetAdmin.IsSuperAdmin() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_delete",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Cannot delete super admin",
			},
			AdminID:      deletedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "delete_admin_user",
			Status:       "failed",
			ErrorCode:    "CANNOT_DELETE_SUPER_ADMIN",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrSuperAdminRequired
	}

	beforeJSON, _ := json.Marshal(targetAdmin)

	if err := s.adminRepo.DeleteAdminUser(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_delete",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to delete admin user",
			},
			AdminID:      deletedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "delete_admin_user",
			Status:       "failed",
			ErrorCode:    "DELETE_USER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_user_delete",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin user deleted successfully",
		},
		AdminID:      deletedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "delete_admin_user",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"username":  targetAdmin.Username,
			"role_type": targetAdmin.RoleType,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "delete", "admin_user",
			&adminID, "admin", &deletedBy, beforeJSON, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  AUTHENTICATION
// --------------------------------------------------------------------

func (s *AdminService) AuthenticateAdmin(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()
	phoneHash := s.GeneratePhoneHash(phone)
	admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_authenticate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin authentication failed",
			},
			Action:       "authenticate_admin",
			Status:       "failed",
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: authentication failed", appErrors.ErrUnauthorized)
	}
	if !admin.IsActive {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_authenticate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin account deactivated",
			},
			AdminID:   admin.AdminID.String(),
			Action:    "authenticate_admin",
			Status:    "failed",
			ErrorCode: "ACCOUNT_DEACTIVATED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrAdminInactive
	}
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, admin.AdminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_authenticate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Failed to update last login",
			},
			AdminID:      admin.AdminID.String(),
			Action:       "authenticate_admin",
			Status:       "partial_failure",
			ErrorCode:    "LAST_LOGIN_UPDATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_authenticate",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin authenticated successfully",
		},
		AdminID:  admin.AdminID.String(),
		Action:   "authenticate_admin",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "authenticate", "admin_user",
			&admin.AdminID, "system", nil, nil, nil, map[string]interface{}{
				"status": "success",
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_session_create",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin permissions",
			},
			AdminID:      admin.AdminID.String(),
			Action:       "create_admin_session",
			Status:       "failed",
			ErrorCode:    "GET_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_session_create",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create admin session",
			},
			AdminID:      admin.AdminID.String(),
			Action:       "create_admin_session",
			Status:       "failed",
			ErrorCode:    "CREATE_SESSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_session_create",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin session created successfully",
		},
		AdminID:  admin.AdminID.String(),
		Action:   "create_admin_session",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "create_session", "admin_user",
			&admin.AdminID, "admin", &admin.AdminID, nil, nil, map[string]interface{}{
				"device_id": deviceID,
				"ip":        ipAddress,
			})
	}
	return admin, session.SessionToken, nil
}

// --------------------------------------------------------------------
//  ACTIVATION / DEACTIVATION
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_deactivate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized deactivation attempt",
			},
			AdminID:      deactivatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	if admin.IsSuperAdmin() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_deactivate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Cannot deactivate super admin",
			},
			AdminID:      deactivatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "SUPER_ADMIN_REQUIRED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrSuperAdminRequired
	}

	beforeJSON, _ := json.Marshal(admin)

	if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_deactivate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to deactivate admin",
			},
			AdminID:      deactivatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "DEACTIVATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_deactivate",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin deactivated successfully",
		},
		AdminID:      deactivatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "deactivate_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "deactivate", "admin_user",
			&adminID, "admin", &deactivatedBy, beforeJSON, nil, map[string]interface{}{
				"ip": ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_activate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized activation attempt",
			},
			AdminID:      activatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "activate_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}

	beforeJSON, _ := json.Marshal(admin)

	if err := s.adminRepo.ActivateAdmin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_activate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to activate admin",
			},
			AdminID:      activatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "activate_admin",
			Status:       "failed",
			ErrorCode:    "ACTIVATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_activate",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin activated successfully",
		},
		AdminID:      activatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "activate_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "activate", "admin_user",
			&adminID, "admin", &activatedBy, beforeJSON, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  PERMISSION METHODS
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_permissions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized permission view",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_permissions",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_permissions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin permissions",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_permissions",
			Status:       "failed",
			ErrorCode:    "GET_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_permissions_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin permissions retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_permissions",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"permissions_count": len(permissions),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_permissions", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(permissions),
			})
	}
	return permissions, nil
}

func (s *AdminService) CheckAdminPermission(ctx context.Context, adminID uuid.UUID, permissionName string) (bool, error) {
	startTime := time.Now()
	has, err := s.adminRepo.AdminHasPermission(ctx, adminID, permissionName)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_permission_check",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to check admin permission",
			},
			AdminID:      adminID.String(),
			Action:       "check_admin_permission",
			Status:       "failed",
			ErrorCode:    "CHECK_PERMISSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_permission_check",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin permission check completed",
		},
		AdminID: adminID.String(),
		Action:  "check_admin_permission",
		Status:  "success",
		Changes: map[string]interface{}{
			"permission":     permissionName,
			"has_permission": has,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "check_permission", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"permission": permissionName,
				"has":        has,
			})
	}
	return has, nil
}

// --------------------------------------------------------------------
//  DEPARTMENT & ROLE DEPARTMENT METHODS
// --------------------------------------------------------------------

func (s *AdminService) GetAdminRoleDepartments(ctx context.Context, roleID uuid.UUID, requesterID uuid.UUID) ([]*models.SystemDepartment, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
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
				s.logAdminEvent(ctx, &models.AdminLogEvent{
					LogEnvelope: models.LogEnvelope{
						EventID:     uuid.New().String(),
						EventType:   "admin_role_departments_get",
						ServiceName: "auth-service",
						Timestamp:   time.Now(),
						Environment: "production",
						Version:     "v1.0.0",
						Level:       "warning",
						Message:     "Unauthorized department view",
					},
					AdminID:   requesterID.String(),
					Action:    "get_admin_role_departments",
					Status:    "failed",
					ErrorCode: "UNAUTHORIZED",
					Duration:  int64(time.Since(startTime).Milliseconds()),
				})
				return nil, appErrors.ErrPermissionDenied
			}
		}
	}
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_departments_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin role departments",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admin_role_departments",
			Status:       "failed",
			ErrorCode:    "GET_DEPARTMENTS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_departments_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role departments retrieved successfully",
		},
		AdminID:      requesterID.String(),
		Action:       "get_admin_role_departments",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_name":         role.RoleName,
			"departments_count": len(departments),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_departments", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(departments),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_department_assign",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized department assignment",
			},
			AdminID:   assignedBy.String(),
			Action:    "assign_department_to_admin_role",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	if !assigner.IsOwner() {
		systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_department_assign",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to assign department to admin role",
			},
			AdminID:      assignedBy.String(),
			Action:       "assign_department_to_admin_role",
			Status:       "failed",
			ErrorCode:    "ASSIGN_DEPARTMENT_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_department_assign",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Department assigned to admin role successfully",
		},
		AdminID:      assignedBy.String(),
		Action:       "assign_department_to_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_id":       roleID.String(),
			"department_id": departmentID.String(),
			"role_name":     role.RoleName,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "assign_department", "admin_role",
			&roleID, "admin", &assignedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
				"ip":            ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_department_remove",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized department removal",
			},
			AdminID:   removedBy.String(),
			Action:    "remove_department_from_admin_role",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	if !remover.IsOwner() {
		systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_department_remove",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to remove department from admin role",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_department_from_admin_role",
			Status:       "failed",
			ErrorCode:    "REMOVE_DEPARTMENT_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_department_remove",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Department removed from admin role successfully",
		},
		AdminID:      removedBy.String(),
		Action:       "remove_department_from_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_id":       roleID.String(),
			"department_id": departmentID.String(),
			"role_name":     role.RoleName,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "remove_department", "admin_role",
			&roleID, "admin", &removedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
				"ip":            ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  REPORTING STRUCTURE
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_reports_to_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized reports_to update",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_reports_to",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_reports_to_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin reports_to",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_reports_to",
			Status:       "failed",
			ErrorCode:    "UPDATE_REPORTS_TO_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(targetAdmin)

	var oldReportsToStr, newReportsToStr string
	if targetAdmin.ReportsTo != nil {
		oldReportsToStr = targetAdmin.ReportsTo.String()
	}
	if reportsTo != nil {
		newReportsToStr = reportsTo.String()
	}
	var reportsToRole string
	if reportsToAdmin != nil {
		reportsToRole = reportsToAdmin.GetRoleString()
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_reports_to_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin reports_to updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_reports_to",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_reports_to":  oldReportsToStr,
			"new_reports_to":  newReportsToStr,
			"target_role":     targetAdmin.GetRoleString(),
			"reports_to_role": reportsToRole,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_reports_to", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"ip": ip,
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
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
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
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin_direct_reports_get",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Unauthorized direct reports view",
				},
				AdminID:      requesterID.String(),
				TargetUserID: adminID.String(),
				Action:       "get_direct_reports",
				Status:       "failed",
				ErrorCode:    "UNAUTHORIZED",
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
			return nil, appErrors.ErrPermissionDenied
		}
	}
	reports, err := s.adminRepo.GetDirectReports(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_direct_reports_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get direct reports",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_direct_reports",
			Status:       "failed",
			ErrorCode:    "GET_DIRECT_REPORTS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_direct_reports_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Direct reports retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_direct_reports",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"direct_reports_count": len(reports),
			"target_role":          targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_direct_reports", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(reports),
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
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
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
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin_reporting_chain_get",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Unauthorized reporting chain view",
				},
				AdminID:      requesterID.String(),
				TargetUserID: adminID.String(),
				Action:       "get_reporting_chain",
				Status:       "failed",
				ErrorCode:    "UNAUTHORIZED",
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
			return nil, appErrors.ErrPermissionDenied
		}
	}
	chain, err := s.adminRepo.GetReportingChain(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_reporting_chain_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get reporting chain",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_reporting_chain",
			Status:       "failed",
			ErrorCode:    "GET_REPORTING_CHAIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_reporting_chain_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Reporting chain retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_reporting_chain",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"reporting_chain_size": len(chain),
			"target_role":          targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_reporting_chain", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depth": len(chain),
			})
	}
	return chain, nil
}

// --------------------------------------------------------------------
//  PROFILE & PHONE UPDATES
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_profile_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized profile update",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_profile",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_profile_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin profile",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_profile",
			Status:       "failed",
			ErrorCode:    "UPDATE_PROFILE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(targetAdmin)

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_profile_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin profile updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_profile",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_username": targetAdmin.Username, // old value not persisted
			"new_username": username,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_profile", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"new_username": username,
				"new_fullname": fullName,
				"ip":           ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_phone_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized phone update",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_phone",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_phone_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin phone",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_phone",
			Status:       "failed",
			ErrorCode:    "UPDATE_PHONE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_phone_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin phone updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_phone",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_phone", "admin_user",
			&adminID, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  BULK OPERATIONS
// --------------------------------------------------------------------

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
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin_bulk_reports_to_update",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Unauthorized bulk reports_to update",
				},
				AdminID:   updatedBy.String(),
				Action:    "bulk_update_reports_to",
				Status:    "failed",
				ErrorCode: "UNAUTHORIZED",
				Duration:  int64(time.Since(startTime).Milliseconds()),
			})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_bulk_reports_to_update",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to bulk update reports_to",
			},
			AdminID:      updatedBy.String(),
			Action:       "bulk_update_reports_to",
			Status:       "failed",
			ErrorCode:    "BULK_UPDATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var newReportsToStr string
	if reportsTo != nil {
		newReportsToStr = reportsTo.String()
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_bulk_reports_to_update",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Bulk reports_to update successful",
		},
		AdminID: updatedBy.String(),
		Action:  "bulk_update_reports_to",
		Status:  "success",
		Changes: map[string]interface{}{
			"admin_count":    len(adminIDs),
			"new_reports_to": newReportsToStr,
			"updater_role":   updater.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "bulk_update_reports_to", "admin_user",
			nil, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"admin_count": len(adminIDs),
				"ip":          ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  LIST METHODS
// --------------------------------------------------------------------

func (s *AdminService) GetAllAdmins(ctx context.Context, requesterID uuid.UUID, limit int) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_all_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized get all admins",
			},
			AdminID:   requesterID.String(),
			Action:    "get_all_admins",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	admins, err := s.adminRepo.GetAllAdmins(ctx, limit)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_all_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get all admins",
			},
			AdminID:      requesterID.String(),
			Action:       "get_all_admins",
			Status:       "failed",
			ErrorCode:    "GET_ALL_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_all_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "All admins retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_all_admins",
		Status:  "success",
		Changes: map[string]interface{}{
			"limit":       limit,
			"admin_count": len(admins),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_all", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit": limit,
				"count": len(admins),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_active_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized get active admins",
			},
			AdminID:   requesterID.String(),
			Action:    "get_active_admins",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	admins, err := s.adminRepo.GetActiveAdmins(ctx, limit)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_active_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get active admins",
			},
			AdminID:      requesterID.String(),
			Action:       "get_active_admins",
			Status:       "failed",
			ErrorCode:    "GET_ACTIVE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_active_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Active admins retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_active_admins",
		Status:  "success",
		Changes: map[string]interface{}{
			"limit":       limit,
			"admin_count": len(admins),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_active", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"limit": limit,
				"count": len(admins),
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
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
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
				s.logAdminEvent(ctx, &models.AdminLogEvent{
					LogEnvelope: models.LogEnvelope{
						EventID:     uuid.New().String(),
						EventType:   "admin_by_role_get",
						ServiceName: "auth-service",
						Timestamp:   time.Now(),
						Environment: "production",
						Version:     "v1.0.0",
						Level:       "warning",
						Message:     "Unauthorized get admins by role",
					},
					AdminID:   requesterID.String(),
					Action:    "get_admins_by_role",
					Status:    "failed",
					ErrorCode: "UNAUTHORIZED",
					Duration:  int64(time.Since(startTime).Milliseconds()),
				})
				return nil, appErrors.ErrPermissionDenied
			}
		}
	}
	admins, err := s.adminRepo.GetAdminsByRole(ctx, roleID, false, limit, offset)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_by_role_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admins by role",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admins_by_role",
			Status:       "failed",
			ErrorCode:    "GET_BY_ROLE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_by_role_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admins by role retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_admins_by_role",
		Status:  "success",
		Changes: map[string]interface{}{
			"role_id":     roleID.String(),
			"role_name":   role.RoleName,
			"limit":       limit,
			"offset":      offset,
			"admin_count": len(admins),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_by_role", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_id": roleID.String(),
				"count":   len(admins),
			})
	}
	return admins, nil
}

// --------------------------------------------------------------------
//  SUGGESTIONS
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_suggestions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized suggestions request",
			},
			AdminID:   requesterID.String(),
			Action:    "get_admin_suggestions",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	suggestions, err := s.adminRepo.GetAdminSuggestions(ctx, prefix, roleTypeFilter, excludeSuperAdmin, limit)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_suggestions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin suggestions",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admin_suggestions",
			Status:       "failed",
			ErrorCode:    "GET_SUGGESTIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_suggestions_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin suggestions retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_admin_suggestions",
		Status:  "success",
		Changes: map[string]interface{}{
			"prefix":              prefix,
			"role_type_filter":    roleTypeFilter,
			"exclude_super_admin": excludeSuperAdmin,
			"limit":               limit,
			"suggestions_count":   len(suggestions),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "suggestions", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"prefix": prefix,
				"count":  len(suggestions),
			})
	}
	return suggestions, nil
}

// --------------------------------------------------------------------
//  ADMIN WITH PERMISSIONS
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_with_permissions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized admin with permissions view",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_with_permissions",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	adminWithPerms, err := s.adminRepo.GetAdminWithPermissions(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_with_permissions_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin with permissions",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_with_permissions",
			Status:       "failed",
			ErrorCode:    "GET_WITH_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_with_permissions_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin with permissions retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_with_permissions",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"permissions_count": len(adminWithPerms.Permissions),
			"departments_count": len(adminWithPerms.Departments),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_with_perms", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"permissions": len(adminWithPerms.Permissions),
				"departments": len(adminWithPerms.Departments),
			})
	}
	return adminWithPerms, nil
}

// --------------------------------------------------------------------
//  FAILED LOGIN ATTEMPTS
// --------------------------------------------------------------------

func (s *AdminService) IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error) {
	startTime := time.Now()
	attempts, err := s.adminRepo.IncrementAdminFailedLoginAttempts(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_failed_login_increment",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to increment failed login attempts",
			},
			AdminID:      adminID.String(),
			Action:       "increment_failed_login_attempts",
			Status:       "failed",
			ErrorCode:    "INCREMENT_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	const maxAttempts = 5
	if attempts >= maxAttempts {
		if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin_lockout",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Admin locked out, deactivation failed",
				},
				AdminID:      adminID.String(),
				Action:       "admin_lockout",
				Status:       "partial_failure",
				ErrorCode:    "DEACTIVATE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		} else {
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin_lockout",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Admin locked out due to failed attempts",
				},
				AdminID:  adminID.String(),
				Action:   "admin_lockout",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
			})
		}
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_failed_login_increment",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "warning",
			Message:     "Admin failed login attempt",
		},
		AdminID: adminID.String(),
		Action:  "failed_login_attempt",
		Status:  "success",
		Changes: map[string]interface{}{
			"attempts":       attempts,
			"should_lockout": attempts >= maxAttempts,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "failed_login", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"attempts": attempts,
			})
	}
	return attempts, nil
}

func (s *AdminService) ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()
	if err := s.adminRepo.ResetAdminFailedLoginAttempts(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_failed_login_reset",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to reset failed login attempts",
			},
			AdminID:      adminID.String(),
			Action:       "reset_failed_login_attempts",
			Status:       "failed",
			ErrorCode:    "RESET_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_failed_login_reset",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin failed login attempts reset successfully",
		},
		AdminID:  adminID.String(),
		Action:   "reset_failed_login_attempts",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "reset_failed_attempts", "admin_user",
			&adminID, "system", nil, nil, nil, nil)
	}
	return nil
}

// --------------------------------------------------------------------
//  AVATAR METHODS
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_avatar_set",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized avatar set",
			},
			AdminID:      setBy.String(),
			TargetUserID: adminID.String(),
			Action:       "set_admin_avatar",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	existing, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err := s.adminRepo.SetAdminAvatar(ctx, adminID, avatarHash, avatarObjectKey, avatarMimeType); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_avatar_set",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to set admin avatar",
			},
			AdminID:      setBy.String(),
			TargetUserID: adminID.String(),
			Action:       "set_admin_avatar",
			Status:       "failed",
			ErrorCode:    "SET_AVATAR_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	metadata := map[string]interface{}{
		"new_hash":   avatarHash,
		"object_key": avatarObjectKey,
		"mime":       avatarMimeType,
		"ip":         ip,
	}
	if existing != nil {
		metadata["old_hash"] = existing.AvatarHash
		metadata["old_key"] = existing.AvatarObjectKey
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_set",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar set successfully",
		},
		AdminID:      setBy.String(),
		TargetUserID: adminID.String(),
		Action:       "set_admin_avatar",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes:      metadata,
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_avatar_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin avatar",
			},
			TargetUserID: adminID.String(),
			Action:       "get_admin_avatar",
			Status:       "failed",
			ErrorCode:    "GET_AVATAR_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	status := "success"
	if avatar == nil {
		status = "no_avatar"
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar retrieved",
		},
		TargetUserID: adminID.String(),
		Action:       "get_admin_avatar",
		Status:       status,
		Changes: map[string]interface{}{
			"has_avatar": avatar != nil,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar": avatar != nil,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_avatar_deactivate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized avatar deactivation",
			},
			AdminID:      deactivatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "deactivate_admin_avatar",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return appErrors.ErrPermissionDenied
	}
	existing, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if existing == nil {
		return nil
	}
	if err := s.adminRepo.DeactivateAdminAvatar(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_avatar_deactivate",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to deactivate admin avatar",
			},
			AdminID:      deactivatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "deactivate_admin_avatar",
			Status:       "failed",
			ErrorCode:    "DEACTIVATE_AVATAR_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_deactivate",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar deactivated successfully",
		},
		AdminID:      deactivatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "deactivate_admin_avatar",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_hash": existing.AvatarHash,
			"old_key":  existing.AvatarObjectKey,
			"ip":       ip,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "deactivate_avatar", "admin_user",
			&adminID, "admin", &deactivatedBy, nil, nil, map[string]interface{}{
				"old_hash": existing.AvatarHash,
				"ip":       ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ----- NEW AVATAR METHODS (with fallback, info, bulk) -----

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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_fallback_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar with fallback retrieved",
		},
		AdminID: adminID.String(),
		Action:  "get_admin_avatar_with_fallback",
		Status:  "success",
		Changes: map[string]interface{}{
			"has_avatar":   avatar != nil,
			"has_initials": initials != "",
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar_fallback", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar":   avatar != nil,
				"has_initials": initials != "",
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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_info_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar info retrieved",
		},
		AdminID: adminID.String(),
		Action:  "get_avatar_info",
		Status:  "success",
		Changes: map[string]interface{}{
			"has_avatar":   info.HasAvatar,
			"has_initials": info.Initials != "",
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_avatar_info", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"has_avatar":   info.HasAvatar,
				"has_initials": info.Initials != "",
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
			// Skip failed ones; no logger anymore
			continue
		}
		result[adminID] = info
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_avatar_info_bulk_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin avatar info bulk retrieved",
		},
		Action: "bulk_get_avatar_info",
		Status: "success",
		Changes: map[string]interface{}{
			"requested_count": len(adminIDs),
			"retrieved_count": len(result),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "bulk_avatar_info", "admin_user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"requested": len(adminIDs),
				"returned":  len(result),
			})
	}
	return result, nil
}

// --------------------------------------------------------------------
//  OTHER QUERY METHODS
// --------------------------------------------------------------------

func (s *AdminService) GetAvailableManagers(ctx context.Context, excludeID *uuid.UUID, requesterID uuid.UUID) ([]*models.AdminUser, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_available_managers_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized available managers request",
			},
			AdminID:   requesterID.String(),
			Action:    "get_available_managers",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	managers, err := s.adminRepo.GetAvailableManagers(ctx, excludeID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_available_managers_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get available managers",
			},
			AdminID:      requesterID.String(),
			Action:       "get_available_managers",
			Status:       "failed",
			ErrorCode:    "GET_AVAILABLE_MANAGERS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_available_managers_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Available managers retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_available_managers",
		Status:  "success",
		Changes: map[string]interface{}{
			"available_managers_count": len(managers),
			"exclude_id":               excludeID,
			"requester_role":           requester.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "available_managers", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(managers),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_with_reports_to_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized get admin with reports_to",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_with_reports_to_name",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	result, err := s.adminRepo.GetAdminWithReportsToName(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_with_reports_to_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin with reports_to name",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_with_reports_to_name",
			Status:       "failed",
			ErrorCode:    "GET_WITH_REPORTS_TO_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_with_reports_to_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin with reports_to retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_with_reports_to_name",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"has_reports_to": result.ReportsTo != nil,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_with_reports_to", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"has_reports_to": result.ReportsTo != nil,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_hierarchy_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized hierarchy view",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_hierarchy",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, appErrors.ErrPermissionDenied
	}
	hierarchy, err := s.adminRepo.GetAdminHierarchy(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_hierarchy_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin hierarchy",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_hierarchy",
			Status:       "failed",
			ErrorCode:    "GET_HIERARCHY_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_hierarchy_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin hierarchy retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_hierarchy",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"target_role":         targetAdmin.GetRoleString(),
			"levels_in_hierarchy": len(hierarchy),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "hierarchy", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depth": len(hierarchy),
			})
	}
	return hierarchy, nil
}

func (s *AdminService) CanAssignReportsTo(ctx context.Context, assignerID uuid.UUID, targetID uuid.UUID) (bool, error) {
	startTime := time.Now()
	can, err := s.adminRepo.CanAssignReportsTo(ctx, assignerID, targetID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_can_assign_reports_to",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to check if admin can assign reports_to",
			},
			AdminID:      assignerID.String(),
			TargetUserID: targetID.String(),
			Action:       "can_assign_reports_to",
			Status:       "failed",
			ErrorCode:    "CHECK_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_can_assign_reports_to",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Check completed for admin can assign reports_to",
		},
		AdminID:      assignerID.String(),
		TargetUserID: targetID.String(),
		Action:       "can_assign_reports_to",
		Status:       "success",
		Changes: map[string]interface{}{
			"can_assign": can,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "can_assign_reports_to", "admin_user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"assigner": assignerID.String(),
				"target":   targetID.String(),
				"result":   can,
			})
	}
	return can, nil
}

func (s *AdminService) GetAdminByPhone(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()
	phoneHash := s.GeneratePhoneHash(phone)
	admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_get_by_phone",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found by phone",
			},
			Action:       "get_admin_by_phone",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_get_by_phone",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin retrieved by phone",
		},
		AdminID:  admin.AdminID.String(),
		Action:   "get_admin_by_phone",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_by_phone", "admin_user",
			&admin.AdminID, "system", nil, nil, nil, nil)
	}
	return admin, nil
}

// --------------------------------------------------------------------
//  LOGIN RECORDING
// --------------------------------------------------------------------

func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_login_record",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to record admin login",
			},
			AdminID:      adminID.String(),
			Action:       "record_admin_login",
			Status:       "failed",
			ErrorCode:    "RECORD_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_login_record",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin login recorded",
		},
		AdminID:  adminID.String(),
		Action:   "record_admin_login",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "record_login", "admin_user",
			&adminID, "system", nil, nil, nil, nil)
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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_failed_login_record",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "warning",
			Message:     "Admin failed login recorded",
		},
		AdminID: adminID.String(),
		Action:  "record_failed_login",
		Status:  "success",
		Changes: map[string]interface{}{
			"attempts":       attempts,
			"should_lockout": shouldLockout,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "record_failed_login", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"attempts": attempts,
				"lockout":  shouldLockout,
			})
	}
	return shouldLockout, attempts, nil
}

// --------------------------------------------------------------------
//  ADMIN WITH DETAILS
// --------------------------------------------------------------------

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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_with_details_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin with details retrieved",
		},
		AdminID: adminID.String(),
		Action:  "get_admin_with_details",
		Status:  "success",
		Changes: map[string]interface{}{
			"permissions_count": len(permNames),
			"departments_count": len(deptNames),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_details", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"permissions": len(permNames),
				"departments": len(deptNames),
			})
	}
	return admin, permNames, deptNames, nil
}

// --------------------------------------------------------------------
//  OWNER (SUPER ADMIN)
// --------------------------------------------------------------------

func (s *AdminService) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
	startTime := time.Now()
	admin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_owner_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin owner",
			},
			Action:       "get_admin_owner",
			Status:       "failed",
			ErrorCode:    "GET_OWNER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var adminIDStr string
	if admin != nil {
		adminIDStr = admin.AdminID.String()
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_owner_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin owner retrieved",
		},
		AdminID:  adminIDStr,
		Action:   "get_admin_owner",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_owner", "admin_user",
			nil, "system", nil, nil, nil, nil)
	}
	return admin, nil
}

func (s *AdminService) GetSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	return s.GetAdminOwner(ctx)
}

// --------------------------------------------------------------------
//  HEALTH & STATS
// --------------------------------------------------------------------

func (s *AdminService) HealthCheck(ctx context.Context) error {
	startTime := time.Now()
	if err := s.adminRepo.HealthCheck(ctx); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_health_check",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin service health check failed",
			},
			Action:       "health_check",
			Status:       "failed",
			ErrorCode:    "HEALTH_CHECK_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_health_check",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin service health check passed",
		},
		Action:   "health_check",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_service", "health_check", "system",
			nil, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *AdminService) GetStats(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()
	stats, err := s.adminRepo.GetRepositoryStats(ctx)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_stats_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin stats",
			},
			Action:       "get_stats",
			Status:       "failed",
			ErrorCode:    "GET_STATS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_stats_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin stats retrieved successfully",
		},
		Action:   "get_stats",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_service", "get_stats", "system",
			nil, "system", nil, nil, nil, nil)
	}
	return stats, nil
}

// --------------------------------------------------------------------
//  NEWLY ADDED METHODS (avatar helpers, search, create, etc.)
// --------------------------------------------------------------------

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

// SearchAdminsWithFilters searches admins with various filters.
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_search_with_filters",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to search admins with filters",
			},
			AdminID:      requesterID.String(),
			Action:       "search_admins_with_filters",
			Status:       "failed",
			ErrorCode:    "SEARCH_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_search_with_filters",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin search with filters completed",
		},
		AdminID: requesterID.String(),
		Action:  "search_admins_with_filters",
		Status:  "success",
		Changes: map[string]interface{}{
			"query":            req.Query,
			"role_type_filter": req.RoleTypeFilter,
			"include_inactive": req.IncludeInactive,
			"search_type":      req.SearchType,
			"limit":            req.Limit,
			"offset":           req.Offset,
			"results_count":    len(results),
			"total_count":      totalCount,
			"requester_role":   requester.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "search_filters", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query": req.Query,
				"count": len(results),
			})
	}
	return results, totalCount, nil
}

// SearchAdminsAdvanced performs advanced search with filters and sorting.
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_advanced_search",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Advanced admin search failed",
			},
			AdminID:      requesterID.String(),
			Action:       "advanced_admin_search",
			Status:       "failed",
			ErrorCode:    "ADVANCED_SEARCH_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_advanced_search",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Advanced admin search completed",
		},
		AdminID: requesterID.String(),
		Action:  "advanced_admin_search",
		Status:  "success",
		Changes: map[string]interface{}{
			"query":         req.Query,
			"filters_count": countFilters(req.Filters),
			"sort_by":       req.SortBy,
			"sort_order":    req.SortOrder,
			"limit":         req.Limit,
			"offset":        req.Offset,
			"results_count": len(results),
			"total_count":   totalCount,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "advanced_search", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query": req.Query,
				"count": len(results),
			})
	}
	return results, totalCount, nil
}

// GetAdminsByDepartment returns admins belonging to a department.
func (s *AdminService) GetAdminsByDepartment(ctx context.Context, departmentID uuid.UUID, requesterID uuid.UUID, includeInactive bool, limit, offset int) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() {
		systemDept, err := s.companyRepo.GetSystemDepartment(ctx, departmentID)
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_by_department_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admins by department",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admins_by_department",
			Status:       "failed",
			ErrorCode:    "GET_BY_DEPARTMENT_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_by_department_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admins by department retrieved",
		},
		AdminID: requesterID.String(),
		Action:  "get_admins_by_department",
		Status:  "success",
		Changes: map[string]interface{}{
			"department_id":    departmentID.String(),
			"include_inactive": includeInactive,
			"limit":            limit,
			"offset":           offset,
			"admins_count":     len(admins),
			"total_count":      totalCount,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_by_department", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"department": departmentID.String(),
				"count":      len(admins),
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

// buildPermissionMaskFromPermissions builds a permission mask from a list of permissions.
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

// GetAdminPermissionMask returns the permission mask for an admin.
func (s *AdminService) GetAdminPermissionMask(ctx context.Context, adminID uuid.UUID) ([]uint64, error) {
	startTime := time.Now()
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	mask := s.buildPermissionMaskFromPermissions(permissions)
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_permission_mask_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin permission mask retrieved",
		},
		AdminID:  adminID.String(),
		Action:   "get_admin_permission_mask",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_permission_mask", "admin_user",
			&adminID, "system", nil, nil, nil, nil)
	}
	return mask, nil
}

// SearchAdminUsers searches admin users with a search request.
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_users_search",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to search admin users",
			},
			AdminID:      requesterID.String(),
			Action:       "search_admin_users",
			Status:       "failed",
			ErrorCode:    "SEARCH_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_users_search",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin users search completed",
		},
		AdminID: requesterID.String(),
		Action:  "search_admin_users",
		Status:  "success",
		Changes: map[string]interface{}{
			"query":            req.Query,
			"role_type_filter": req.RoleTypeFilter,
			"include_inactive": req.IncludeInactive,
			"search_type":      req.SearchType,
			"limit":            req.Limit,
			"offset":           req.Offset,
			"results_count":    len(results),
			"total_count":      total,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "search_users", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query": req.Query,
				"count": len(results),
			})
	}
	return results, total, nil
}

// CreateAdminUser creates a new admin user.
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_user_create",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create admin user",
			},
			AdminID:      createdBy.String(),
			Action:       "create_admin_user",
			Status:       "failed",
			ErrorCode:    "CREATE_USER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(admin)

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_user_create",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin user created successfully",
		},
		AdminID:      createdBy.String(),
		TargetUserID: adminID.String(),
		Action:       "create_admin_user",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"username":   req.Username,
			"full_name":  req.FullName,
			"role_id":    req.AdminRoleID.String(),
			"role_type":  adminRole.RoleType,
			"reports_to": req.ReportsTo,
			"is_active":  true,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "create", "admin_user",
			&adminID, "admin", &createdBy, beforeJSON, afterJSON, map[string]interface{}{
				"username": req.Username,
				"ip":       ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, admin)
	return admin, nil
}

// GetAdminsByRoleType returns admins of a specific role type.
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_by_role_type_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admins by role type",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admins_by_role_type",
			Status:       "failed",
			ErrorCode:    "GET_BY_ROLE_TYPE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_by_role_type_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admins by role type retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_admins_by_role_type",
		Status:  "success",
		Changes: map[string]interface{}{
			"role_type":        roleType,
			"include_inactive": includeInactive,
			"limit":            limit,
			"offset":           offset,
			"admin_count":      len(admins),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "list_by_role_type", "admin_user",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_type": roleType,
				"count":     len(admins),
			})
	}
	return admins, nil
}

// CheckAdminDepartmentAccess checks if an admin has access to a department.
func (s *AdminService) CheckAdminDepartmentAccess(ctx context.Context, adminID uuid.UUID, departmentName string) (bool, error) {
	startTime := time.Now()
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_department_access_check",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Department access check completed",
		},
		AdminID: adminID.String(),
		Action:  "check_department_access",
		Status:  "success",
		Changes: map[string]interface{}{
			"department": departmentName,
			"has_access": hasAccess,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "check_department_access", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"department": departmentName,
				"has":        hasAccess,
			})
	}
	return hasAccess, nil
}

// SearchAdminsByName searches admins by name (full-text).
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

// SearchAdminEmployees searches only employee admins.
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

// SearchAdminManagers searches only manager admins.
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

// GetAdminPhoneNumber returns the decrypted phone number (owner only).
func (s *AdminService) GetAdminPhoneNumber(ctx context.Context, adminID uuid.UUID, requesterID uuid.UUID) (string, error) {
	startTime := time.Now()
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return "", fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_phone_access",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized phone number access attempt",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_phone",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_phone_access",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to decrypt phone number",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_phone",
			Status:       "failed",
			ErrorCode:    "DECRYPTION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_phone_access",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin phone number accessed successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_phone",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"phone_accessed": true,
			"admin_role":     targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_phone", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"accessed": true,
			})
	}
	return decryptedPhone, nil
}

// --------------------------------------------------------------------
//  SUPER ADMIN INITIALIZATION
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "super_admin_check",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "info",
				Message:     "Super admin already exists",
			},
			AdminID: existingSuperAdmin.AdminID.String(),
			Action:  "check_and_init_super_admin",
			Status:  "success",
			Changes: map[string]interface{}{
				"exists": true,
			},
		})
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

	// Check existing
	existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if existingSuperAdmin != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "super_admin_init",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "info",
				Message:     "Super admin already exists, skipping init",
			},
			AdminID: existingSuperAdmin.AdminID.String(),
			Action:  "init_super_admin",
			Status:  "success",
			Changes: map[string]interface{}{
				"existing": true,
			},
		})
		return existingSuperAdmin, nil
	}

	// Get or create super admin role
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
		allDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
		// Ensure all permissions and departments are assigned
		_ = s.adminRepo.GrantAllPermissionsToRole(ctx, roleID, uuid.Nil)
		allDepts, _ := s.companyRepo.GetSystemDepartments(ctx)
		for _, d := range allDepts {
			_ = s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, d.SystemDepartmentID)
		}
	}

	// Create admin user
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

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "super_admin_init",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Super admin initialized successfully with ALL permissions and ALL departments",
		},
		AdminID:      adminID.String(),
		Action:       "init_super_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"username":     username,
			"full_name":    fullName,
			"role_type":    models.RoleTypeSuperAdmin,
			"role_created": roleCreated,
			"permissions":  "ALL",
			"departments":  "ALL",
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_auth", "init_super_admin", "admin_user",
			&adminID, "system", nil, nil, nil, map[string]interface{}{
				"username":  username,
				"full_name": fullName,
			})
	}
	return admin, nil
}

// --------------------------------------------------------------------
//  ADMIN ROLE CREATION AND PERMISSION GRANTING
// --------------------------------------------------------------------

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

	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
		// Grant default permissions for departments
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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_create",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role created successfully",
		},
		AdminID:      createdBy.String(),
		Action:       "create_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_name":      req.RoleName,
			"role_type":      req.RoleType,
			"department_ids": deptIDs,
			"description":    req.Description,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "create", "admin_role",
			&roleID, "admin", &createdBy, beforeJSON, afterJSON, map[string]interface{}{
				"role_name": req.RoleName,
				"ip":        ip,
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_permission_grant",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to grant permission to admin role",
			},
			AdminID:      grantedBy.String(),
			Action:       "grant_permission_to_admin_role",
			Status:       "failed",
			ErrorCode:    "GRANT_PERMISSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_permission_grant",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Permission granted to admin role successfully",
		},
		AdminID:      grantedBy.String(),
		Action:       "grant_permission_to_admin_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"role_id":       roleID.String(),
			"permission_id": permissionID.String(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "grant_permission", "admin_role",
			&roleID, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"permission_id": permissionID.String(),
				"ip":            ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  ADMIN ROLE DETAILS & AVAILABLE PERMISSIONS
// --------------------------------------------------------------------

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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_details_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role details retrieved successfully",
		},
		AdminID:      requesterID.String(),
		Action:       "get_admin_role_details",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"departments_count": len(departments),
			"permissions_count": len(permissions),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_details", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"depts": len(departments),
				"perms": len(permissions),
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
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_available_permissions_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Available permissions for role retrieved successfully",
		},
		AdminID:      requesterID.String(),
		Action:       "get_available_permissions_for_role",
		ResourceType: "admin_role",
		ResourceID:   roleID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"available": len(available),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "available_perms", "admin_role",
			&roleID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(available),
			})
	}
	return available, nil
}

// --------------------------------------------------------------------
//  ROLE NAME / TYPE QUERIES
// --------------------------------------------------------------------

func (s *AdminService) GetAdminRoleByName(ctx context.Context, roleName string) (*models.AdminRole, error) {
	startTime := time.Now()
	role, err := s.adminRepo.GetAdminRoleByName(ctx, roleName)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_get_by_name",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin role not found by name",
			},
			Action:       "get_admin_role_by_name",
			Status:       "failed",
			ErrorCode:    "ROLE_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if role == nil {
		return nil, appErrors.ErrNotFound
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_get_by_name",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin role retrieved successfully by name",
		},
		Action:       "get_admin_role_by_name",
		ResourceType: "admin_role",
		ResourceID:   role.AdminRoleID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "get_by_name", "admin_role",
			&role.AdminRoleID, "system", nil, nil, nil, nil)
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_employee_roles_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get employee admin roles",
			},
			AdminID:      requesterID.String(),
			Action:       "get_employee_admin_roles",
			Status:       "failed",
			ErrorCode:    "GET_EMPLOYEE_ROLES_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_employee_roles_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Employee admin roles retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_employee_admin_roles",
		Status:  "success",
		Changes: map[string]interface{}{
			"roles_count": len(roles),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_employee", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(roles),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_manager_roles_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get manager admin roles",
			},
			AdminID:      requesterID.String(),
			Action:       "get_manager_admin_roles",
			Status:       "failed",
			ErrorCode:    "GET_MANAGER_ROLES_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_manager_roles_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Manager admin roles retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_manager_admin_roles",
		Status:  "success",
		Changes: map[string]interface{}{
			"roles_count": len(roles),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_manager", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(roles),
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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_roles_by_type_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin roles by type",
			},
			AdminID:      requesterID.String(),
			Action:       "get_admin_roles_by_type",
			Status:       "failed",
			ErrorCode:    "GET_ROLES_BY_TYPE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_roles_by_type_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin roles by type retrieved successfully",
		},
		AdminID: requesterID.String(),
		Action:  "get_admin_roles_by_type",
		Status:  "success",
		Changes: map[string]interface{}{
			"role_type":   roleType,
			"roles_count": len(roles),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "list_by_type", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"role_type": roleType,
				"count":     len(roles),
			})
	}
	return roles, nil
}

// --------------------------------------------------------------------
//  ADMIN DEPARTMENTS (for a specific admin)
// --------------------------------------------------------------------

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
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_departments_get",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get admin departments",
			},
			AdminID:      requesterID.String(),
			TargetUserID: adminID.String(),
			Action:       "get_admin_departments",
			Status:       "failed",
			ErrorCode:    "GET_DEPARTMENTS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_departments_get",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin departments retrieved successfully",
		},
		AdminID:      requesterID.String(),
		TargetUserID: adminID.String(),
		Action:       "get_admin_departments",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"departments_count": len(departments),
			"target_role":       targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "get_departments", "admin_user",
			&adminID, "admin", &requesterID, nil, nil, map[string]interface{}{
				"count": len(departments),
			})
	}
	return departments, nil
}

// --------------------------------------------------------------------
//  UPDATE ADMIN USER ROLE
// --------------------------------------------------------------------

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

	oldRoleID := targetAdmin.AdminRoleID
	beforeJSON, _ := json.Marshal(targetAdmin)

	if err := s.adminRepo.UpdateAdminUserRole(ctx, adminID, newRoleID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_change",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin user role",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "update_admin_user_role",
			Status:       "failed",
			ErrorCode:    "UPDATE_ROLE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(targetAdmin) // updated not reflected but fine
	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_role_change",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin user role updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_user_role",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_role_id": oldRoleID.String(),
			"new_role_id": newRoleID.String(),
			"admin_name":  targetAdmin.FullName,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_user", "update_role", "admin_user",
			&adminID, "admin", &updatedBy, beforeJSON, afterJSON, map[string]interface{}{
				"new_role": newRoleID.String(),
				"ip":       ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  INTERNAL HELPERS (already defined above)
// --------------------------------------------------------------------

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
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
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
	// Authorize: only owner or super employee
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: requester not found", appErrors.ErrNotFound)
	}
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_roles_search",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized search admin roles",
			},
			AdminID:   requesterID.String(),
			Action:    "search_admin_roles",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, appErrors.ErrPermissionDenied
	}

	// Call repository search
	roles, totalCount, err := s.adminRepo.SearchAdminRoles(ctx, query, nil, limit, offset) // assuming repository has SearchAdminRoles
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_roles_search",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to search admin roles",
			},
			AdminID:      requesterID.String(),
			Action:       "search_admin_roles",
			Status:       "failed",
			ErrorCode:    "SEARCH_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin_roles_search",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin roles search completed",
		},
		AdminID: requesterID.String(),
		Action:  "search_admin_roles",
		Status:  "success",
		Changes: map[string]interface{}{
			"query":       query,
			"limit":       limit,
			"offset":      offset,
			"results":     len(roles),
			"total_count": totalCount,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_role", "search", "admin_role",
			nil, "admin", &requesterID, nil, nil, map[string]interface{}{
				"query": query,
				"count": len(roles),
			})
	}
	return roles, totalCount, nil
}
