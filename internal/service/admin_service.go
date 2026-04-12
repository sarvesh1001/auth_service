// Remove unused imports
package service

import (
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/util"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AdminService struct {
	adminRepo      postgres.AdminRepository
	companyRepo    postgres.CompanyRepository
	sessionService *SessionService
	otpService     *OTPService
	mpinService    *MPINService
	deviceService  *DeviceService
	hasher         *hashing.Hasher
	encryptionMgr  *encryption.EncryptionManager
	logProducer    *LogProducerService
	logger         *zap.Logger
}

func NewAdminService(
	adminRepo postgres.AdminRepository,
	companyRepo postgres.CompanyRepository,
	sessionService *SessionService,
	otpService *OTPService,
	mpinService *MPINService,
	deviceService *DeviceService,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) *AdminService {
	return &AdminService{
		adminRepo:      adminRepo,
		companyRepo:    companyRepo,
		sessionService: sessionService,
		otpService:     otpService,
		mpinService:    mpinService,
		deviceService:  deviceService,
		hasher:         hasher,
		encryptionMgr:  encryptionMgr,
		logger:         logger,
	}
}

func (s *AdminService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

func (s *AdminService) logAdminEvent(ctx context.Context, event *models.AdminLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceAdminEvent(ctx, event)
	}
}

// GeneratePhoneHash generates a SHA256 hash of a phone number
func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// ==============================
// ADMIN ROLE MANAGEMENT METHODS
// ==============================

// // CreateAdminRole creates a new admin role with departments
// func (s *AdminService) CreateAdminRole(
//     ctx context.Context,
//     req *models.AdminRoleCreateRequest,
//     createdBy uuid.UUID,
// ) (*models.AdminRole, error) {
//     startTime := time.Now()

//     // Validate input
//     if req.RoleName == "" {
//         return nil, fmt.Errorf("role name cannot be empty")
//     }
//     if req.RoleType == 0 {
//         return nil, fmt.Errorf("role type must be specified")
//     }
//     if req.RoleType != models.RoleTypeEmployee && req.RoleType != models.RoleTypeManager {
//         return nil, fmt.Errorf("invalid role type. Must be employee (1) or manager (2)")
//     }

//     // Get creator admin
//     creator, err := s.adminRepo.GetAdminByID(ctx, createdBy)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin_role_create",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Creator not found",
//             },
//             AdminID:      createdBy.String(),
//             Action:       "create_admin_role",
//             Status:       "failed",
//             ErrorCode:    "CREATOR_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("creator not found: %w", err)
//     }

//     // Check if creator has permission to create this type of role
//     if req.RoleType == models.RoleTypeManager {
//         if !creator.IsOwner() && !creator.IsSuperEmployee() {
//             s.logAdminEvent(ctx, &models.AdminLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   "admin_role_create",
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: "production",
//                     Version:     "v1.0.0",
//                     Level:       "warning",
//                     Message:     "Unauthorized to create manager role",
//                 },
//                 AdminID:   createdBy.String(),
//                 Action:    "create_admin_role",
//                 Status:    "failed",
//                 ErrorCode: "UNAUTHORIZED",
//                 Duration:  int64(time.Since(startTime).Milliseconds()),
//             })
//             return nil, fmt.Errorf("unauthorized: only owner or super employee can create manager roles")
//         }
//     }

//     // Validate departments
//     if len(req.DepartmentIDs) == 0 {
//         return nil, fmt.Errorf("at least one department must be specified")
//     }

//     // Check if creator has access to all specified departments
//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get system departments: %w", err)
//     }

//     departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentIDs))
//     departmentMap := make(map[uuid.UUID]*models.SystemDepartment)

//     for _, deptID := range req.DepartmentIDs {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if sysDept.SystemDepartmentID == deptID {
//                 // Check if creator has access to this department
//                 if !creator.IsOwner() {
//                     hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, createdBy, sysDept.Bitmask)
//                     if err != nil {
//                         return nil, fmt.Errorf("failed to check department access: %w", err)
//                     }
//                     if !hasAccess {
//                         return nil, fmt.Errorf("creator does not have access to department: %s", sysDept.Name)
//                     }
//                 }
//                 departmentIDs = append(departmentIDs, deptID)
//                 departmentMap[deptID] = sysDept
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             return nil, fmt.Errorf("department not found: %s", deptID)
//         }
//     }

//     // Create role
//     roleID := uuid.New()
//     now := time.Now().UTC()

//     role := &models.AdminRole{
//         AdminRoleID:   roleID,
//         RoleName:      req.RoleName,
//         RoleLevel:     s.getRoleLevel(req.RoleType),
//         RoleType:      req.RoleType,
//         IsSystemRole:  false,
//         Description:   req.Description,
//         CreatedAt:     now,
//         UpdatedAt:     now,
//     }

//     // Create role in repository
//     if err := s.adminRepo.CreateAdminRole(ctx, role, departmentIDs); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin_role_create",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to create admin role",
//             },
//             AdminID:      createdBy.String(),
//             Action:       "create_admin_role",
//             Status:       "failed",
//             ErrorCode:    "CREATE_ROLE_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to create admin role: %w", err)
//     }

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin_role_create",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin role created successfully",
//         },
//         AdminID:      createdBy.String(),
//         Action:       "create_admin_role",
//         ResourceType: "admin_role",
//         ResourceID:   roleID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "role_name":     req.RoleName,
//             "role_type":     req.RoleType,
//             "department_ids": departmentIDs,
//             "description":   req.Description,
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     return role, nil
// }

// GetAdminRole retrieves an admin role by ID
func (s *AdminService) GetAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	requesterID uuid.UUID,
) (*models.AdminRole, error) {
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
		return nil, fmt.Errorf("admin role not found: %w", err)
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

	return role, nil
}

// GetAdminRoles retrieves all admin roles with pagination
func (s *AdminService) GetAdminRoles(
	ctx context.Context,
	requesterID uuid.UUID,
	limit int,
	offset int,
	roleType *int,
) ([]*models.AdminRole, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, fmt.Errorf("unauthorized: cannot view admin roles")
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
		return nil, 0, fmt.Errorf("failed to get admin roles: %w", err)
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

	return roles, totalCount, nil
}

// UpdateAdminRole updates an existing admin role
func (s *AdminService) UpdateAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
) (*models.AdminRole, error) {
	startTime := time.Now()

	// Get existing role
	existingRole, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("admin role not found: %w", err)
	}

	if existingRole.IsSystemRole {
		return nil, fmt.Errorf("cannot update system role")
	}

	// Get updater info
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return nil, fmt.Errorf("updater not found: %w", err)
	}

	// Authorization check
	if !updater.IsOwner() {
		if existingRole.RoleType == models.RoleTypeManager {
			if !updater.IsSuperEmployee() {
				return nil, fmt.Errorf("unauthorized: only owner or super employee can update manager roles")
			}
		}
	}

	// Update basic role info
	if updates.RoleName != nil && *updates.RoleName != "" {
		existingRole.RoleName = *updates.RoleName
	}

	if updates.Description != nil {
		existingRole.Description = *updates.Description
	}

	existingRole.UpdatedAt = time.Now().UTC()

	// Track changes for logging
	changes := make(map[string]interface{})

	// Validate and process department changes
	if len(updates.AddDepartments) > 0 || len(updates.RemoveDepartments) > 0 {
		if err := s.processRoleDepartmentUpdates(ctx, roleID, updates, updatedBy, updater, existingRole); err != nil {
			return nil, err
		}
		changes["departments_added"] = len(updates.AddDepartments)
		changes["departments_removed"] = len(updates.RemoveDepartments)
	}

	// Validate and process permission changes
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

	// Update the role
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
		return nil, fmt.Errorf("failed to update admin role: %w", err)
	}

	// Log the successful update
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

	return existingRole, nil
}

func (s *AdminService) processRoleDepartmentUpdates(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
	updater *models.AdminUser,
	role *models.AdminRole,
) error {
	// Get all system departments to map names to IDs
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
	if err != nil {
		return fmt.Errorf("failed to get system departments: %w", err)
	}

	// Create maps for lookup
	deptNameToID := make(map[string]uuid.UUID)
	deptNameToDept := make(map[string]*models.SystemDepartment)
	for _, dept := range systemDepts {
		deptNameToID[dept.Name] = dept.SystemDepartmentID
		deptNameToDept[dept.Name] = dept
	}

	// Get current role departments
	currentDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get current role departments: %w", err)
	}

	// Create a map of current department names (not IDs)
	currentDeptNameMap := make(map[string]bool)
	currentDeptIDMap := make(map[uuid.UUID]bool) // Keep this for other checks if needed
	for _, dept := range currentDepts {
		currentDeptNameMap[dept.Name] = true
		currentDeptIDMap[dept.SystemDepartmentID] = true
	}

	// Process removals
	for _, deptName := range updates.RemoveDepartments {
		deptID, exists := deptNameToID[deptName]
		if !exists {
			return fmt.Errorf("department not found: %s", deptName)
		}

		if !currentDeptNameMap[deptName] {
			continue
		}

		if !updater.IsOwner() {
			dept, deptExists := deptNameToDept[deptName]
			if !deptExists {
				return fmt.Errorf("failed to get department: %s", deptName)
			}
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil {
				return fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return fmt.Errorf("updater does not have access to department: %s", deptName)
			}
		}

		if err := s.adminRepo.RemoveDepartmentFromAdminRole(ctx, roleID, deptID); err != nil {
			return fmt.Errorf("failed to remove department from role: %w", err)
		}
	}

	// Process additions
	for _, deptName := range updates.AddDepartments {
		deptID, exists := deptNameToID[deptName]
		if !exists {
			return fmt.Errorf("department not found: %s", deptName)
		}

		if currentDeptNameMap[deptName] {
			continue
		}

		if !updater.IsOwner() {
			dept, deptExists := deptNameToDept[deptName]
			if !deptExists {
				return fmt.Errorf("failed to get department: %s", deptName)
			}
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil {
				return fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return fmt.Errorf("updater does not have access to department: %s", deptName)
			}
		}

		if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, deptID); err != nil {
			return fmt.Errorf("failed to assign department to role: %w", err)
		}
	}

	return nil
}

// Helper function to process permission updates
func (s *AdminService) processRolePermissionUpdates(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
	updater *models.AdminUser,
	role *models.AdminRole,
) error {
	// Get current role departments
	currentDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role departments: %w", err)
	}

	if len(currentDepts) == 0 && (len(updates.AddPermissions) > 0 || len(updates.ReplacePermissions) > 0) {
		return fmt.Errorf("role must have at least one department assigned before adding permissions")
	}

	// Create department module map for validation
	deptModuleMap := make(map[string]bool)
	for _, dept := range currentDepts {
		deptModuleMap[dept.ModuleCode] = true
	}

	// Process permission removals
	for _, permName := range updates.RemovePermissions {
		perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
		if err != nil {
			return fmt.Errorf("permission not found: %w", err)
		}

		// Check if permission exists for role
		hasPerm, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, perm.PermissionID)
		if err != nil {
			return fmt.Errorf("failed to check permission: %w", err)
		}

		if !hasPerm {
			continue // Permission not granted
		}

		if err := s.adminRepo.RevokePermissionFromAdminRole(ctx, roleID, perm.PermissionID); err != nil {
			return fmt.Errorf("failed to revoke permission: %w", err)
		}
	}

	// Handle complete replacement of permissions
	if len(updates.ReplacePermissions) > 0 {
		// First, get all current permissions
		currentPerms, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
		if err != nil {
			return fmt.Errorf("failed to get current permissions: %w", err)
		}

		// Remove all existing permissions
		for _, perm := range currentPerms {
			if err := s.adminRepo.RevokePermissionFromAdminRole(ctx, roleID, perm.PermissionID); err != nil {
				return fmt.Errorf("failed to revoke existing permission: %w", err)
			}
		}

		// Add new permissions
		for _, permName := range updates.ReplacePermissions {
			perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
			if err != nil {
				return fmt.Errorf("permission not found: %w", err)
			}

			// Check if role has department for this permission
			if !deptModuleMap[perm.Module] {
				return fmt.Errorf("role does not have department for permission '%s' (requires module: %s)", permName, perm.Module)
			}

			if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, updatedBy); err != nil {
				return fmt.Errorf("failed to grant permission: %w", err)
			}
		}

		return nil
	}

	// Process permission additions
	for _, permName := range updates.AddPermissions {
		perm, err := s.adminRepo.GetPermissionByName(ctx, permName)
		if err != nil {
			return fmt.Errorf("permission not found: %w", err)
		}

		// Check if role has department for this permission
		if !deptModuleMap[perm.Module] {
			return fmt.Errorf("role does not have department for permission '%s' (requires module: %s)", permName, perm.Module)
		}

		// Check if permission already granted
		hasPerm, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, perm.PermissionID)
		if err != nil {
			return fmt.Errorf("failed to check permission: %w", err)
		}

		if hasPerm {
			continue // Permission already granted
		}

		if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, updatedBy); err != nil {
			return fmt.Errorf("failed to grant permission: %w", err)
		}
	}

	return nil
}

// DeleteAdminRole deletes an admin role
func (s *AdminService) DeleteAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	deletedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Get existing role
	existingRole, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("admin role not found: %w", err)
	}

	// Check if role is system role
	if existingRole.IsSystemRole {
		return fmt.Errorf("cannot delete system role")
	}

	// Get deleter admin
	deleter, err := s.adminRepo.GetAdminByID(ctx, deletedBy)
	if err != nil {
		return fmt.Errorf("deleter not found: %w", err)
	}

	// Check permissions
	if !deleter.IsOwner() {
		if existingRole.RoleType == models.RoleTypeManager {
			if !deleter.IsSuperEmployee() {
				return fmt.Errorf("unauthorized: only owner or super employee can delete manager roles")
			}
		}
	}

	// Check if role is in use
	admins, err := s.GetAdminsByRole(ctx, roleID, 1, 0, deletedBy)
	if err != nil {
		return fmt.Errorf("failed to check role usage: %w", err)
	}
	if len(admins) > 0 {
		return fmt.Errorf("cannot delete role: %d admin users are assigned to it", len(admins))
	}

	// Delete role from repository
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
		return fmt.Errorf("failed to delete admin role: %w", err)
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

	return nil
}

// ================================
// ADMIN USER MANAGEMENT METHODS
// ================================

// GetAdminUser retrieves an admin user by ID
func (s *AdminService) GetAdminUser(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) (*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
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
		return nil, fmt.Errorf("admin user not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			// Check if requester can manage this admin
			if !s.canManageAdmin(requester, admin) {
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
				return nil, fmt.Errorf("unauthorized: cannot view this admin user")
			}
		}
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

	return admin, nil
}

// UpdateAdminUser updates an existing admin user
func (s *AdminService) UpdateAdminUser(
	ctx context.Context,
	adminID uuid.UUID,
	updates map[string]interface{},
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	// Get updater admin
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if updater.AdminID != adminID {
		if !updater.IsOwner() && !updater.IsSuperEmployee() {
			if !s.canManageAdmin(updater, targetAdmin) {
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
				return fmt.Errorf("unauthorized: cannot update this admin user")
			}
		}
	}

	// Check if updating admin_role_id
	if newRoleID, ok := updates["admin_role_id"].(uuid.UUID); ok {
		newRole, err := s.adminRepo.GetAdminRole(ctx, newRoleID)
		if err != nil {
			return fmt.Errorf("new admin role not found: %w", err)
		}

		// Check if updater can assign this role
		if !updater.IsOwner() {
			if newRole.RoleType == models.RoleTypeManager {
				if !updater.IsSuperEmployee() {
					return fmt.Errorf("unauthorized: only owner or super employee can assign manager role")
				}
			}

			// Check if updater has access to role's departments
			roleDepartments, err := s.adminRepo.GetAdminRoleDepartments(ctx, newRoleID)
			if err != nil {
				return fmt.Errorf("failed to get role departments: %w", err)
			}

			for _, dept := range roleDepartments {
				hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
				if err != nil {
					return fmt.Errorf("failed to check department access: %w", err)
				}
				if !hasAccess {
					return fmt.Errorf("updater does not have access to department: %s", dept.Name)
				}
			}
		}

		updates["role_type"] = newRole.RoleType
	}

	// Check if updating username
	if username, ok := updates["username"].(string); ok && username != "" {
		existingAdmin, _ := s.adminRepo.GetAdminByUsername(ctx, username)
		if existingAdmin != nil && existingAdmin.AdminID != adminID {
			return fmt.Errorf("username already exists")
		}
	}

	// Update admin in repository
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
		return fmt.Errorf("failed to update admin user: %w", err)
	}

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

	return nil
}

// DeleteAdminUser deletes an admin user
func (s *AdminService) DeleteAdminUser(
	ctx context.Context,
	adminID uuid.UUID,
	deletedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Get deleter admin
	deleter, err := s.adminRepo.GetAdminByID(ctx, deletedBy)
	if err != nil {
		return fmt.Errorf("deleter not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if !deleter.IsOwner() && !deleter.IsSuperEmployee() {
		if !s.canManageAdmin(deleter, targetAdmin) {
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
			return fmt.Errorf("unauthorized: cannot delete this admin user")
		}
	}

	// Check if target admin is super admin
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
		return fmt.Errorf("cannot delete super admin")
	}

	// Delete admin from repository
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
		return fmt.Errorf("failed to delete admin user: %w", err)
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

	return nil
}

// ================================
// ADMIN AUTHENTICATION METHODS
// ================================

// AuthenticateAdmin authenticates an admin by phone
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
		return nil, fmt.Errorf("authentication failed: %w", err)
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
		return nil, fmt.Errorf("admin account is deactivated")
	}

	// Update last login
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, admin.AdminID); err != nil {
		s.logger.Warn("Failed to update last login",
			zap.String("admin_id", admin.AdminID.String()),
			zap.Error(err),
		)
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

	return admin, nil
}
func (s *AdminService) AuthenticateAdminWithSession(
	ctx context.Context,
	phone string,
	deviceID string,
	ipAddress string,
) (*models.AdminUser, string, error) {
	startTime := time.Now()
	admin, err := s.AuthenticateAdmin(ctx, phone)
	if err != nil {
		return nil, "", err
	}

	adminWithPerms, err := s.adminRepo.GetAdminWithPermissions(ctx, admin.AdminID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get admin permissions: %w", err)
	}

	var permissionMask []uint64
	if len(adminWithPerms.Permissions) > 0 {
		// Convert []models.Permission to []*models.Permission
		perms := make([]*models.Permission, len(adminWithPerms.Permissions))
		for i := range adminWithPerms.Permissions {
			perms[i] = &adminWithPerms.Permissions[i]
		}
		permissionMask = s.buildPermissionMaskFromPermissions(perms)
	}

	sessionReq := &CreateAdminSessionRequest{
		AdminID:           admin.AdminID,
		Role:              adminWithPerms.GetRoleString(), // Use role string
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
		return nil, "", fmt.Errorf("failed to create admin session: %w", err)
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

	return admin, session.SessionToken, nil
}

// ================================
// ADMIN STATUS MANAGEMENT METHODS
// ================================

// DeactivateAdmin deactivates an admin user
func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
	startTime := time.Now()

	// Get target admin
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	// Check if already inactive
	if !admin.IsActive {
		return fmt.Errorf("admin is already inactive")
	}

	// Get deactivator admin
	deactivator, err := s.adminRepo.GetAdminByID(ctx, deactivatedBy)
	if err != nil {
		return fmt.Errorf("deactivator not found: %w", err)
	}

	// Check permissions
	if !deactivator.IsOwner() && !deactivator.IsSuperEmployee() {
		if !s.canManageAdmin(deactivator, admin) {
			return fmt.Errorf("unauthorized: cannot deactivate this admin")
		}
	}

	// Check if trying to deactivate super admin
	if admin.IsSuperAdmin() {
		return fmt.Errorf("cannot deactivate super admin")
	}

	// Deactivate admin
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
		return fmt.Errorf("failed to deactivate admin: %w", err)
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

	return nil
}

// ActivateAdmin activates an admin user
func (s *AdminService) ActivateAdmin(ctx context.Context, adminID uuid.UUID, activatedBy uuid.UUID) error {
	startTime := time.Now()

	// Get target admin
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	// Check if already active
	if admin.IsActive {
		return fmt.Errorf("admin is already active")
	}

	// Get activator admin
	activator, err := s.adminRepo.GetAdminByID(ctx, activatedBy)
	if err != nil {
		return fmt.Errorf("activator not found: %w", err)
	}

	// Check permissions
	if !activator.IsOwner() && !activator.IsSuperEmployee() {
		if !s.canManageAdmin(activator, admin) {
			return fmt.Errorf("unauthorized: cannot activate this admin")
		}
	}

	// Activate admin
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
		return fmt.Errorf("failed to activate admin: %w", err)
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

	return nil
}

// ================================
// ADMIN PERMISSION METHODS
// ================================

// GetAdminPermissions retrieves permissions for an admin user
func (s *AdminService) GetAdminPermissions(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.Permission, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !s.canManageAdmin(requester, targetAdmin) {
				return nil, fmt.Errorf("unauthorized: cannot view this admin's permissions")
			}
		}
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
		return nil, fmt.Errorf("failed to get admin permissions: %w", err)
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

	return permissions, nil
}

// CheckAdminPermission checks if an admin has a specific permission
func (s *AdminService) CheckAdminPermission(
	ctx context.Context,
	adminID uuid.UUID,
	permissionName string,
) (bool, error) {
	startTime := time.Now()

	hasPermission, err := s.adminRepo.AdminHasPermission(ctx, adminID, permissionName)
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
		return false, fmt.Errorf("failed to check admin permission: %w", err)
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
			"has_permission": hasPermission,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return hasPermission, nil
}

// ================================
// ADMIN DEPARTMENT METHODS
// ================================

// GetAdminRoleDepartments retrieves departments for an admin role
func (s *AdminService) GetAdminRoleDepartments(
	ctx context.Context,
	roleID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.SystemDepartment, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get role
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("admin role not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Check if requester can view this role's departments
		roleDepartments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role departments: %w", err)
		}

		for _, dept := range roleDepartments {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil {
				return nil, fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return nil, fmt.Errorf("unauthorized: cannot view departments for this role")
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
		return nil, fmt.Errorf("failed to get admin role departments: %w", err)
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

	return departments, nil
}

// AssignDepartmentToAdminRole assigns a department to an admin role
func (s *AdminService) AssignDepartmentToAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	departmentID uuid.UUID,
	assignedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Get assigner admin
	assigner, err := s.adminRepo.GetAdminByID(ctx, assignedBy)
	if err != nil {
		return fmt.Errorf("assigner not found: %w", err)
	}

	// Get role
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("admin role not found: %w", err)
	}

	// Check permissions
	if !assigner.IsOwner() {
		if role.RoleType == models.RoleTypeManager {
			if !assigner.IsSuperEmployee() {
				return fmt.Errorf("unauthorized: only owner or super employee can assign departments to manager roles")
			}
		}
	}

	// Check if assigner has access to this department
	if !assigner.IsOwner() {
		systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
		if err != nil {
			return fmt.Errorf("failed to get system departments: %w", err)
		}

		for _, sysDept := range systemDepartments {
			if sysDept.SystemDepartmentID == departmentID {
				hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, assignedBy, sysDept.Bitmask)
				if err != nil {
					return fmt.Errorf("failed to check department access: %w", err)
				}
				if !hasAccess {
					return fmt.Errorf("assigner does not have access to department: %s", sysDept.Name)
				}
				break
			}
		}
	}

	// Assign department to role
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
		return fmt.Errorf("failed to assign department to admin role: %w", err)
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

	return nil
}

// RemoveDepartmentFromAdminRole removes a department from an admin role
func (s *AdminService) RemoveDepartmentFromAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	departmentID uuid.UUID,
	removedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Get remover admin
	remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
	if err != nil {
		return fmt.Errorf("remover not found: %w", err)
	}

	// Get role
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("admin role not found: %w", err)
	}

	// Check permissions
	if !remover.IsOwner() {
		if role.RoleType == models.RoleTypeManager {
			if !remover.IsSuperEmployee() {
				return fmt.Errorf("unauthorized: only owner or super employee can remove departments from manager roles")
			}
		}
	}

	// Check if remover has access to this department
	if !remover.IsOwner() {
		systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
		if err != nil {
			return fmt.Errorf("failed to get system departments: %w", err)
		}

		for _, sysDept := range systemDepartments {
			if sysDept.SystemDepartmentID == departmentID {
				hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, removedBy, sysDept.Bitmask)
				if err != nil {
					return fmt.Errorf("failed to check department access: %w", err)
				}
				if !hasAccess {
					return fmt.Errorf("remover does not have access to department: %s", sysDept.Name)
				}
				break
			}
		}
	}

	// Remove department from role
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
		return fmt.Errorf("failed to remove department from admin role: %w", err)
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

	return nil
}

// ================================
// ADMIN SEARCH METHODS
// ================================

// SearchAdminRoles searches for admin roles
func (s *AdminService) SearchAdminRoles(
	ctx context.Context,
	query string,
	requesterID uuid.UUID,
	limit int,
	offset int,
) ([]*models.AdminRole, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, fmt.Errorf("unauthorized: cannot search admin roles")
	}

	roles, totalCount, err := s.adminRepo.SearchAdminRoles(ctx, query, nil, limit, offset)
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
		return nil, 0, fmt.Errorf("failed to search admin roles: %w", err)
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

	return roles, totalCount, nil
}

// ================================
// ADMIN REPORTS TO METHODS
// ================================
func (s *AdminService) UpdateAdminReportsTo(
	ctx context.Context,
	adminID uuid.UUID,
	reportsTo *uuid.UUID,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()
	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}

	assigner, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("assigner not found: %w", err)
	}

	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	if !assigner.IsOwner() && !assigner.IsSuperEmployee() {
		if !s.canManageAdmin(assigner, targetAdmin) {
			return fmt.Errorf("unauthorized: cannot update reports_to for this admin")
		}
	}

	var reportsToAdmin *models.AdminUser
	if reportsTo != nil {
		reportsToAdmin, err = s.adminRepo.GetAdminByID(ctx, *reportsTo)
		if err != nil {
			return fmt.Errorf("reports_to admin not found: %w", err)
		}
		if reportsToAdmin.RoleType < targetAdmin.RoleType {
			return fmt.Errorf("reports_to admin must have higher or equal role level")
		}
		if *reportsTo == adminID {
			return fmt.Errorf("admin cannot report to themselves")
		}

		reportingChain, err := s.adminRepo.GetReportingChain(ctx, *reportsTo)
		if err != nil {
			return fmt.Errorf("failed to check reporting chain: %w", err)
		}
		for _, chainAdmin := range reportingChain {
			if chainAdmin.AdminID == adminID {
				return fmt.Errorf("circular reporting chain detected")
			}
		}
	}

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
		return fmt.Errorf("failed to update reports_to: %w", err)
	}

	var oldReportsToStr, newReportsToStr string
	if targetAdmin.ReportsTo != nil {
		oldReportsToStr = targetAdmin.ReportsTo.String()
	}
	if reportsTo != nil {
		newReportsToStr = reportsTo.String()
	}

	// Fix: Use the reportsToAdmin variable
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
			"reports_to_role": reportsToRole, // Now using the variable
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

// GetDirectReports gets direct reports for an admin
func (s *AdminService) GetDirectReports(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			// Check if requester is in the reporting chain
			reportingChain, err := s.adminRepo.GetReportingChain(ctx, adminID)
			if err != nil {
				return nil, fmt.Errorf("failed to get reporting chain: %w", err)
			}

			requesterInChain := false
			for _, chainAdmin := range reportingChain {
				if chainAdmin.AdminID == requesterID {
					requesterInChain = true
					break
				}
			}

			if !requesterInChain {
				return nil, fmt.Errorf("unauthorized: cannot view direct reports for this admin")
			}
		}
	}

	directReports, err := s.adminRepo.GetDirectReports(ctx, adminID)
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
		return nil, fmt.Errorf("failed to get direct reports: %w", err)
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
			"direct_reports_count": len(directReports),
			"target_role":          targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return directReports, nil
}

// GetReportingChain gets the reporting chain for an admin
func (s *AdminService) GetReportingChain(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			// Check if requester is in the reporting chain
			reportingChain, err := s.adminRepo.GetReportingChain(ctx, adminID)
			if err != nil {
				return nil, fmt.Errorf("failed to get reporting chain: %w", err)
			}

			requesterInChain := false
			for _, chainAdmin := range reportingChain {
				if chainAdmin.AdminID == requesterID {
					requesterInChain = true
					break
				}
			}

			if !requesterInChain {
				return nil, fmt.Errorf("unauthorized: cannot view reporting chain for this admin")
			}
		}
	}

	reportingChain, err := s.adminRepo.GetReportingChain(ctx, adminID)
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
		return nil, fmt.Errorf("failed to get reporting chain: %w", err)
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
			"reporting_chain_size": len(reportingChain),
			"target_role":          targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return reportingChain, nil
}

// ================================
// ADMIN PROFILE METHODS
// ================================

// UpdateAdminProfile updates an admin's profile
func (s *AdminService) UpdateAdminProfile(
	ctx context.Context,
	adminID uuid.UUID,
	username string,
	fullName string,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if fullName == "" {
		return fmt.Errorf("full name cannot be empty")
	}

	// Validate username format
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username format. Must be 3-50 characters, alphanumeric with underscores")
	}

	// Validate full name length
	if len(fullName) < 2 || len(fullName) > 100 {
		return fmt.Errorf("full name must be between 2 and 100 characters")
	}

	// Get updater admin
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if updater.AdminID != adminID {
		if !updater.IsOwner() && !updater.IsSuperEmployee() {
			if !s.canManageAdmin(updater, targetAdmin) {
				return fmt.Errorf("unauthorized: cannot update this admin's profile")
			}
		}
	}

	// Check if username is taken
	if username != targetAdmin.Username {
		existingAdmin, _ := s.adminRepo.GetAdminByUsername(ctx, username)
		if existingAdmin != nil {
			return fmt.Errorf("username already taken")
		}
	}

	oldUsername := targetAdmin.Username
	oldFullName := targetAdmin.FullName

	// Update profile
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
		return fmt.Errorf("failed to update profile: %w", err)
	}

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
			"old_username":  oldUsername,
			"new_username":  username,
			"old_full_name": oldFullName,
			"new_full_name": fullName,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// UpdateAdminPhone updates an admin's phone number
func (s *AdminService) UpdateAdminPhone(
	ctx context.Context,
	adminID uuid.UUID,
	newPhone string,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}
	if newPhone == "" {
		return fmt.Errorf("new phone cannot be empty")
	}

	// Get updater admin
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if updater.AdminID != adminID {
		if !updater.IsOwner() && !updater.IsSuperEmployee() {
			if !s.canManageAdmin(updater, targetAdmin) {
				return fmt.Errorf("unauthorized: cannot update this admin's phone")
			}
		}
	}

	newPhoneHash := s.GeneratePhoneHash(newPhone)

	// Check if phone already exists
	existingAdmin, _ := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
	if existingAdmin != nil && existingAdmin.AdminID != adminID {
		return fmt.Errorf("phone number already exists")
	}

	// Encrypt new phone
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
	if err != nil {
		return fmt.Errorf("failed to encrypt new phone: %w", err)
	}

	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		return fmt.Errorf("failed to parse key ID: %w", err)
	}

	phoneEncryptedBytes := []byte(encryptedResult.EncryptedValue)

	// Update phone
	if err := s.adminRepo.UpdateAdminPhone(ctx, adminID, newPhoneHash, phoneEncryptedBytes, keyID, encryptedResult.EncryptedDEK); err != nil {
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
		return fmt.Errorf("failed to update admin phone: %w", err)
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

	return nil
}

// ================================
// ADMIN BULK OPERATIONS
// ================================

func (s *AdminService) BulkUpdateReportsTo(
	ctx context.Context,
	adminIDs []uuid.UUID,
	reportsTo *uuid.UUID,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if len(adminIDs) == 0 {
		return fmt.Errorf("no admin IDs provided")
	}

	// Get updater admin
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	// Check permissions for each admin
	for _, adminID := range adminIDs {
		if adminID == uuid.Nil {
			return fmt.Errorf("invalid admin ID in list")
		}

		targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return fmt.Errorf("target admin not found: %w", err)
		}

		// Check permissions
		if !updater.IsOwner() && !updater.IsSuperEmployee() {
			if !s.canManageAdmin(updater, targetAdmin) {
				return fmt.Errorf("unauthorized: cannot update reports_to for admin %s", adminID)
			}
		}

		// Check circular reporting
		if reportsTo != nil && *reportsTo == adminID {
			return fmt.Errorf("admin %s cannot report to themselves", adminID)
		}

		// If reports_to is provided, validate it
		if reportsTo != nil {
			reportsToAdmin, err := s.adminRepo.GetAdminByID(ctx, *reportsTo)
			if err != nil {
				return fmt.Errorf("reports_to admin not found: %w", err)
			}

			if reportsToAdmin.RoleType < targetAdmin.RoleType {
				return fmt.Errorf("reports_to admin must have higher or equal role level for admin %s", adminID)
			}

			reportingChain, err := s.adminRepo.GetReportingChain(ctx, *reportsTo)
			if err != nil {
				return fmt.Errorf("failed to check reporting chain: %w", err)
			}

			for _, chainAdmin := range reportingChain {
				if chainAdmin.AdminID == adminID {
					return fmt.Errorf("circular reporting chain detected for admin %s", adminID)
				}
			}
		}
	}

	// Bulk update reports_to
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
		return fmt.Errorf("failed to bulk update reports_to: %w", err)
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

	return nil
}

// ================================
// ADMIN LIST METHODS
// ================================

// GetAllAdmins gets all admins with pagination
func (s *AdminService) GetAllAdmins(
	ctx context.Context,
	requesterID uuid.UUID,
	limit int,
) ([]*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, fmt.Errorf("unauthorized: cannot view all admins")
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
		return nil, fmt.Errorf("failed to get all admins: %w", err)
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

	return admins, nil
}

// GetActiveAdmins gets active admins with pagination
func (s *AdminService) GetActiveAdmins(
	ctx context.Context,
	requesterID uuid.UUID,
	limit int,
) ([]*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, fmt.Errorf("unauthorized: cannot view active admins")
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
		return nil, fmt.Errorf("failed to get active admins: %w", err)
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

	return admins, nil
}

// GetAdminsByRole gets admins by role with pagination
func (s *AdminService) GetAdminsByRole(
	ctx context.Context,
	roleID uuid.UUID,
	limit int,
	offset int,
	requesterID uuid.UUID,
) ([]*models.AdminUserSearchResult, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get role
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("admin role not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Check if requester can view admins in this role
		roleDepartments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role departments: %w", err)
		}

		for _, dept := range roleDepartments {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil {
				return nil, fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return nil, fmt.Errorf("unauthorized: cannot view admins in this role")
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
		return nil, fmt.Errorf("failed to get admins by role: %w", err)
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

	return admins, nil
}

// // GetAdminsByRoleType gets admins by role type
// func (s *AdminService) GetAdminsByRoleType(
//     ctx context.Context,
//     roleType int,
//     requesterID uuid.UUID,
//     includeInactive bool,
//     limit int,
//     offset int,
// ) ([]*models.AdminUserSearchResult, error) {
//     startTime := time.Now()

//     // Get requester admin
//     requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
//     if err != nil {
//         return nil, fmt.Errorf("requester not found: %w", err)
//     }

//     // Check permissions based on role type
//     switch roleType {
//     case models.RoleTypeEmployee:
//         // Employees can view other employees
//     case models.RoleTypeManager:
//         if !requester.IsOwner() && !requester.IsSuperEmployee() {
//             return nil, fmt.Errorf("unauthorized: cannot view managers")
//         }
//     case models.RoleTypeSuperAdmin:
//         if !requester.IsOwner() {
//             return nil, fmt.Errorf("unauthorized: cannot view super admins")
//         }
//     default:
//         return nil, fmt.Errorf("invalid role type")
//     }

//     admins, err := s.adminRepo.GetAdminsByRoleType(ctx, roleType, includeInactive, limit, offset)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin_by_role_type_get",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get admins by role type",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "get_admins_by_role_type",
//             Status:       "failed",
//             ErrorCode:    "GET_BY_ROLE_TYPE_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to get admins by role type: %w", err)
//     }

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin_by_role_type_get",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admins by role type retrieved successfully",
//         },
//         AdminID:   requesterID.String(),
//         Action:    "get_admins_by_role_type",
//         Status:    "success",
//         Changes: map[string]interface{}{
//             "role_type":        roleType,
//             "include_inactive": includeInactive,
//             "limit":            limit,
//             "offset":           offset,
//             "admin_count":      len(admins),
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     return admins, nil
// }

// ================================
// ADMIN SUGGESTIONS AND QUICK SEARCH
// ================================

// GetAdminSuggestions gets admin suggestions for autocomplete
func (s *AdminService) GetAdminSuggestions(
	ctx context.Context,
	prefix string,
	requesterID uuid.UUID,
	roleTypeFilter *int,
	excludeSuperAdmin bool,
	limit int,
) ([]*models.AdminSuggestion, error) {
	startTime := time.Now()

	if prefix == "" {
		return nil, fmt.Errorf("prefix cannot be empty")
	}

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Regular employees can only get suggestions for employees
		if roleTypeFilter != nil && *roleTypeFilter != models.RoleTypeEmployee {
			return nil, fmt.Errorf("unauthorized: cannot get suggestions for this role type")
		}
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
		return nil, fmt.Errorf("failed to get admin suggestions: %w", err)
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

	return suggestions, nil
}

// GetAdminWithPermissions gets admin with permissions and departments
func (s *AdminService) GetAdminWithPermissions(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) (*models.AdminWithPermissions, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !s.canManageAdmin(requester, targetAdmin) {
				return nil, fmt.Errorf("unauthorized: cannot view this admin's permissions")
			}
		}
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
		return nil, fmt.Errorf("failed to get admin with permissions: %w", err)
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

	return adminWithPerms, nil
}

// ================================
// ADMIN FAILED LOGIN METHODS
// ================================

// IncrementAdminFailedLoginAttempts increments failed login attempts for an admin
func (s *AdminService) IncrementAdminFailedLoginAttempts(
	ctx context.Context,
	adminID uuid.UUID,
) (int, error) {
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
		return 0, fmt.Errorf("failed to increment attempts: %w", err)
	}

	const maxAttempts = 5
	shouldLockout := attempts >= maxAttempts

	if shouldLockout {
		// Deactivate admin after max attempts
		if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
			s.logger.Warn("Failed to deactivate admin after lockout",
				zap.String("admin_id", adminID.String()),
				zap.Error(err),
			)
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
			"should_lockout": shouldLockout,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return attempts, nil
}

// ResetAdminFailedLoginAttempts resets failed login attempts for an admin
func (s *AdminService) ResetAdminFailedLoginAttempts(
	ctx context.Context,
	adminID uuid.UUID,
) error {
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
		return fmt.Errorf("failed to reset failed attempts: %w", err)
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

	return nil
}

// ================================
// ADMIN AVATAR METHODS
// ================================

// SetAdminAvatar sets an avatar for an admin
func (s *AdminService) SetAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
	avatarHash string,
	avatarObjectKey string,
	avatarMimeType string,
	setBy uuid.UUID,
) error {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}
	if avatarHash == "" {
		return fmt.Errorf("avatar hash cannot be empty")
	}
	if avatarObjectKey == "" {
		return fmt.Errorf("avatar object key cannot be empty")
	}

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, setBy)
	if err != nil {
		return fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID && !requester.IsOwner() {
		return fmt.Errorf("unauthorized: cannot set avatar for this admin")
	}

	// Validate MIME type
	validMimeTypes := map[string]bool{
		"image/jpeg":    true,
		"image/jpg":     true,
		"image/png":     true,
		"image/gif":     true,
		"image/webp":    true,
		"image/svg+xml": true,
	}
	if !validMimeTypes[avatarMimeType] {
		return fmt.Errorf("invalid avatar mime type: %s", avatarMimeType)
	}

	// Get existing avatar
	existingAvatar, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)

	// Set avatar
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
		return fmt.Errorf("failed to set admin avatar: %w", err)
	}

	changes := map[string]interface{}{
		"new_avatar_hash": avatarHash,
		"new_object_key":  avatarObjectKey,
		"mime_type":       avatarMimeType,
		"set_by":          setBy.String(),
	}
	if existingAvatar != nil {
		changes["old_avatar_hash"] = existingAvatar.AvatarHash
		changes["old_object_key"] = existingAvatar.AvatarObjectKey
		changes["replaced_existing"] = true
	} else {
		changes["replaced_existing"] = false
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
		Changes:      changes,
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// GetAdminAvatar gets an admin's avatar
func (s *AdminService) GetAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminAvatar, error) {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return nil, fmt.Errorf("admin ID cannot be empty")
	}

	// Check if admin exists
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
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
		return nil, fmt.Errorf("failed to get admin avatar: %w", err)
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
			"admin_role": admin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return avatar, nil
}

// DeactivateAdminAvatar deactivates an admin's avatar
func (s *AdminService) DeactivateAdminAvatar(
	ctx context.Context,
	adminID uuid.UUID,
	deactivatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, deactivatedBy)
	if err != nil {
		return fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID && !requester.IsOwner() {
		return fmt.Errorf("unauthorized: cannot deactivate avatar for this admin")
	}

	// Get existing avatar
	existingAvatar, _ := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if existingAvatar == nil {
		return nil // No avatar to deactivate
	}

	// Deactivate avatar
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
		return fmt.Errorf("failed to deactivate admin avatar: %w", err)
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
			"old_avatar_hash": existingAvatar.AvatarHash,
			"old_object_key":  existingAvatar.AvatarObjectKey,
			"deactivated_by":  deactivatedBy.String(),
			"admin_role":      targetAdmin.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// ================================
// ADMIN HELPER METHODS
// ================================

// GetAvailableManagers gets available managers for reporting
func (s *AdminService) GetAvailableManagers(
	ctx context.Context,
	excludeID *uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.AdminUser, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, fmt.Errorf("unauthorized: cannot view available managers")
	}

	availableManagers, err := s.adminRepo.GetAvailableManagers(ctx, excludeID)
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
		return nil, fmt.Errorf("failed to get available managers: %w", err)
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
			"available_managers_count": len(availableManagers),
			"exclude_id":               excludeID,
			"requester_role":           requester.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return availableManagers, nil
}

// GetAdminWithReportsToName gets admin with reports_to name
func (s *AdminService) GetAdminWithReportsToName(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) (*models.AdminUserSearchResult, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !s.canManageAdmin(requester, targetAdmin) {
				return nil, fmt.Errorf("unauthorized: cannot view this admin's details")
			}
		}
	}

	adminWithReportsTo, err := s.adminRepo.GetAdminWithReportsToName(ctx, adminID)
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
		return nil, fmt.Errorf("failed to get admin with reports_to name: %w", err)
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
			"target_role":    targetAdmin.GetRoleString(),
			"has_reports_to": adminWithReportsTo.ReportsTo != nil,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return adminWithReportsTo, nil
}

// ================================
// ADMIN SYSTEM METHODS
// ================================

// HealthCheck performs a health check on the admin service
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
		return fmt.Errorf("admin service health check failed: %w", err)
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

	return nil
}

// GetStats gets admin service statistics
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
		return nil, fmt.Errorf("failed to get admin stats: %w", err)
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

	return stats, nil
}

// ================================
// HELPER FUNCTIONS
// ================================

// canManageAdmin checks if one admin can manage another
func (s *AdminService) canManageAdmin(manager, target *models.AdminUser) bool {
	// Owner can manage everyone
	if manager.IsOwner() {
		return true
	}

	// Super employee can manage employees
	if manager.IsSuperEmployee() && target.IsEmployee() {
		return true
	}

	// Managers can only manage employees in their departments
	if manager.IsManager() && target.IsEmployee() {
		// Check if manager has access to target's departments
		managerDepts, err := s.adminRepo.GetAdminRoleDepartments(context.Background(), manager.AdminRoleID)
		if err != nil {
			s.logger.Warn("Failed to get manager departments",
				zap.String("manager_id", manager.AdminID.String()),
				zap.Error(err),
			)
			return false
		}

		targetDepts, err := s.adminRepo.GetAdminRoleDepartments(context.Background(), target.AdminRoleID)
		if err != nil {
			s.logger.Warn("Failed to get target departments",
				zap.String("target_id", target.AdminID.String()),
				zap.Error(err),
			)
			return false
		}

		// Check if target departments are subset of manager departments
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

// getRoleLevel returns the role level based on role type
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

// isValidUsername validates username format
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

// getRoleString returns role string for logging
func getRoleString(admin *models.AdminUser) string {
	if admin == nil {
		return ""
	}
	return admin.GetRoleString()
}

// GetAdminHierarchy gets the complete hierarchy for an admin
func (s *AdminService) GetAdminHierarchy(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.AdminHierarchy, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Get target admin
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("target admin not found: %w", err)
	}

	// Check permissions
	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			// Check if requester can view this admin's hierarchy
			if !s.canManageAdmin(requester, targetAdmin) {
				return nil, fmt.Errorf("unauthorized: cannot view hierarchy for this admin")
			}
		}
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
		return nil, fmt.Errorf("failed to get admin hierarchy: %w", err)
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

	return hierarchy, nil
}

// CanAssignReportsTo checks if an admin can assign reports_to to another admin
func (s *AdminService) CanAssignReportsTo(
	ctx context.Context,
	assignerID uuid.UUID,
	targetID uuid.UUID,
) (bool, error) {
	startTime := time.Now()

	canAssign, err := s.adminRepo.CanAssignReportsTo(ctx, assignerID, targetID)
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
		return false, fmt.Errorf("failed to check if admin can assign reports_to: %w", err)
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
			"can_assign": canAssign,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return canAssign, nil
}

// GetAdminByPhone retrieves admin by phone number
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
		return nil, fmt.Errorf("admin not found: %w", err)
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

	return admin, nil
}

// RecordAdminLogin records a successful admin login
func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()

	// Update last login
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
		return fmt.Errorf("failed to record admin login: %w", err)
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

	return nil
}

// RecordFailedLogin records a failed login attempt
func (s *AdminService) RecordFailedLogin(
	ctx context.Context,
	adminID uuid.UUID,
) (bool, int, error) {
	startTime := time.Now()

	// Increment failed attempts and check if should lockout
	attempts, err := s.IncrementAdminFailedLoginAttempts(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_failed_login_record",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to record admin failed login",
			},
			AdminID:      adminID.String(),
			Action:       "record_failed_login",
			Status:       "failed",
			ErrorCode:    "RECORD_FAILED_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return false, 0, fmt.Errorf("failed to record admin failed login: %w", err)
	}

	const maxAttempts = 5
	shouldLockout := attempts >= maxAttempts

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

	return shouldLockout, attempts, nil
}

// GetAdminWithDetails gets admin with all details
func (s *AdminService) GetAdminWithDetails(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminUser, []string, []string, error) {
	startTime := time.Now()

	// Get admin
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin not found: %w", err)
	}

	// Get permissions
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		return admin, nil, nil, nil // Return admin even if permissions fail
	}

	// Get departments
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, admin.AdminRoleID)
	if err != nil {
		return admin, nil, nil, nil // Return admin even if departments fail
	}

	// Convert to string arrays
	permissionNames := make([]string, 0, len(permissions))
	for _, perm := range permissions {
		permissionNames = append(permissionNames, perm.PermissionName)
	}

	departmentNames := make([]string, 0, len(departments))
	for _, dept := range departments {
		departmentNames = append(departmentNames, dept.Name)
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
			"permissions_count": len(permissionNames),
			"departments_count": len(departmentNames),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return admin, permissionNames, departmentNames, nil
}

func (s *AdminService) GetAdminOwner(ctx context.Context) (*models.AdminUser, error) {
	startTime := time.Now()
	admin, err := s.adminRepo.GetSuperAdmin(ctx)

	// Always safe-check admin before accessing its fields
	var adminIDStr string
	if admin != nil {
		adminIDStr = admin.AdminID.String()
	}

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
			AdminID:      adminIDStr, // Safe - checked above
			Action:       "get_admin_owner",
			Status:       "failed",
			ErrorCode:    "GET_OWNER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to get admin owner: %w", err)
	}

	// No error from repository
	if admin == nil {
		// No super admin exists - this is normal, not an error
		return nil, nil
	}

	// Success case - admin exists
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
		AdminID:  adminIDStr, // Safe - checked above
		Action:   "get_admin_owner",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	return admin, nil
}

// GetAdminAvatarWithFallback gets admin avatar with fallback
func (s *AdminService) GetAdminAvatarWithFallback(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminAvatar, string, error) {
	startTime := time.Now()

	// Get avatar
	avatar, err := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err != nil && err != sql.ErrNoRows {
		return nil, "", fmt.Errorf("failed to get admin avatar: %w", err)
	}

	var initials string
	// If no avatar, generate initials from name
	if avatar == nil {
		admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return nil, "", fmt.Errorf("admin not found: %w", err)
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

	return avatar, initials, nil
}

// GetAvatarInfo gets avatar info for an admin
func (s *AdminService) GetAvatarInfo(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.AdminAvatarInfo, error) {
	startTime := time.Now()

	// Get avatar
	avatar, err := s.adminRepo.GetAdminAvatar(ctx, adminID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get admin avatar: %w", err)
	}

	var initials string
	// If no avatar, generate initials
	if avatar == nil {
		admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
		if err != nil {
			return nil, fmt.Errorf("admin not found: %w", err)
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

	return info, nil
}

// BulkGetAvatarInfo gets avatar info for multiple admins
func (s *AdminService) BulkGetAvatarInfo(
	ctx context.Context,
	adminIDs []uuid.UUID,
) (map[uuid.UUID]*models.AdminAvatarInfo, error) {
	startTime := time.Now()

	if len(adminIDs) == 0 {
		return make(map[uuid.UUID]*models.AdminAvatarInfo), nil
	}

	result := make(map[uuid.UUID]*models.AdminAvatarInfo)
	for _, adminID := range adminIDs {
		info, err := s.GetAvatarInfo(ctx, adminID)
		if err != nil {
			// Log error but continue with other admins
			s.logger.Warn("Failed to get avatar info",
				zap.String("admin_id", adminID.String()),
				zap.Error(err),
			)
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

	return result, nil
}

// generateInitialsFromName generates initials from full name
func (s *AdminService) generateInitialsFromName(fullName string) string {
	if fullName == "" {
		return ""
	}

	// Split name into parts
	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return ""
	}

	// Get first character of first and last parts
	var initialsBuilder strings.Builder
	if len(parts) > 0 {
		initialsBuilder.WriteString(strings.ToUpper(string(parts[0][0])))
	}
	if len(parts) > 1 {
		initialsBuilder.WriteString(strings.ToUpper(string(parts[len(parts)-1][0])))
	}

	return initialsBuilder.String()
}

// Helper method: Check if requester can update target admin profile
func (s *AdminService) canUpdateAdminProfile(requester, target *models.AdminUser) bool {
	// Owner can update anyone
	if requester.IsOwner() {
		return true
	}

	// Super employee can update employees
	if requester.IsSuperEmployee() && target.IsEmployee() {
		return true
	}

	// Managers can update employees in their departments
	if requester.IsManager() && target.IsEmployee() {
		return s.canManageAdmin(requester, target)
	}

	// Admins can update their own profile
	return requester.AdminID == target.AdminID
}

// Helper method: Check if requester can change target admin phone
func (s *AdminService) canChangePhone(requester, target *models.AdminUser) bool {
	// Owner can change anyone's phone
	if requester.IsOwner() {
		return true
	}

	// Super employee can change employee phones
	if requester.IsSuperEmployee() && target.IsEmployee() {
		return true
	}

	// Admins can change their own phone
	return requester.AdminID == target.AdminID
}

// Helper method: Check if username is taken
func (s *AdminService) isUsernameTaken(ctx context.Context, username string, excludeAdminID uuid.UUID) bool {
	admin, err := s.adminRepo.GetAdminByUsername(ctx, username)
	if err != nil {
		return false // If error, assume not taken
	}
	return admin != nil && admin.AdminID != excludeAdminID
}

// Helper method: Get role string from mask
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

// Helper method: Check if role mask is valid
func isValidRoleMask(roleMask uint64) bool {
	return roleMask == 1 || roleMask == 2 || roleMask == 4
}

// ================================
// COMPREHENSIVE ADMIN SEARCH WITH FILTERS
// ================================

func (s *AdminService) SearchAdminsWithFilters(
	ctx context.Context,
	requesterID uuid.UUID,
	req *models.AdminSearchRequest,
) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Check if requester can search
		if req.RoleTypeFilter != nil {
			switch *req.RoleTypeFilter {
			case models.RoleTypeEmployee:
				// Employees can search other employees
			case models.RoleTypeManager:
				return nil, 0, fmt.Errorf("unauthorized: cannot search managers")
			case models.RoleTypeSuperAdmin:
				return nil, 0, fmt.Errorf("unauthorized: cannot search super admins")
			default:
				return nil, 0, fmt.Errorf("invalid role type filter")
			}
		}
	}

	// Call repository search
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
		return nil, 0, fmt.Errorf("failed to search admins: %w", err)
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

	return results, totalCount, nil
}

// SearchAdminsAdvanced - Advanced search with multiple filters
func (s *AdminService) SearchAdminsAdvanced(
	ctx context.Context,
	requesterID uuid.UUID,
	req *models.AdminAdvancedSearchRequest,
) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions for advanced search
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, 0, fmt.Errorf("unauthorized: advanced search requires owner or super employee role")
	}

	// Validate limit
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Call repository
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
		return nil, 0, fmt.Errorf("advanced search failed: %w", err)
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

	return results, totalCount, nil
}
func (s *AdminService) GetAdminsByDepartment(
	ctx context.Context,
	departmentID uuid.UUID,
	requesterID uuid.UUID,
	includeInactive bool,
	limit, offset int,
) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check if requester has access to this department
	if !requester.IsOwner() {
		systemDept, err := s.companyRepo.GetSystemDepartment(ctx, departmentID)
		if err != nil {
			return nil, 0, fmt.Errorf("department not found: %w", err)
		}

		hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, systemDept.Bitmask)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to check department access: %w", err)
		}
		if !hasAccess {
			return nil, 0, fmt.Errorf("unauthorized: no access to department")
		}
	}

	// Get admins with total count
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
		return nil, 0, fmt.Errorf("failed to get admins by department: %w", err)
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

	return admins, totalCount, nil
}

// Helper function to count filters
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

// Add to AdminService in service/admin.go
func (s *AdminService) buildPermissionMaskFromPermissions(permissions []*models.Permission) []uint64 {
	// We now support 800 permissions → 13 uint64 blocks
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

	// Ensure mask always has 13 blocks (hard requirement)
	if len(mask) < 13 {
		fullMask := make([]uint64, 13)
		copy(fullMask, mask)
		return fullMask
	}

	return mask
}

func (s *AdminService) GetAdminPermissionMask(ctx context.Context, adminID uuid.UUID) ([]uint64, error) {
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin permissions: %w", err)
	}

	return s.buildPermissionMaskFromPermissions(permissions), nil
}

// SearchAdminUsers searches for admin users with filters
func (s *AdminService) SearchAdminUsers(
	ctx context.Context,
	req *models.AdminUserSearchRequest,
	requesterID uuid.UUID,
) ([]*models.AdminUserSearchResult, int, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, 0, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions based on role type
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Regular employees can only search employees
		if req.RoleTypeFilter != nil && *req.RoleTypeFilter != models.RoleTypeEmployee {
			return nil, 0, fmt.Errorf("unauthorized: cannot search for this role type")
		}
	}

	// Call repository
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
		return nil, 0, fmt.Errorf("failed to search admin users: %w", err)
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

	return results, total, nil
}

// CreateAdminUser creates a new admin user with phone encryption
func (s *AdminService) CreateAdminUser(
	ctx context.Context,
	req *models.AdminCreateRequest,
	createdBy uuid.UUID,
) (*models.AdminUser, error) {
	startTime := time.Now()

	// Validate input
	if req.Username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if req.FullName == "" {
		return nil, fmt.Errorf("full name cannot be empty")
	}
	if req.PhoneNumber == "" {
		return nil, fmt.Errorf("phone number cannot be empty")
	}
	if req.AdminRoleID == uuid.Nil {
		return nil, fmt.Errorf("admin role ID cannot be empty")
	}

	// Get creator admin
	creator, err := s.adminRepo.GetAdminByID(ctx, createdBy)
	if err != nil {
		return nil, fmt.Errorf("creator not found: %w", err)
	}

	// Get admin role
	adminRole, err := s.adminRepo.GetAdminRole(ctx, req.AdminRoleID)
	if err != nil {
		return nil, fmt.Errorf("admin role not found: %w", err)
	}

	// Check permissions based on role type
	switch adminRole.RoleType {
	case models.RoleTypeEmployee:
		if !creator.IsOwner() && !creator.IsSuperEmployee() {
			return nil, fmt.Errorf("unauthorized: only owner or super employee can create employee admin")
		}
	case models.RoleTypeManager:
		if !creator.IsOwner() && !creator.IsSuperEmployee() {
			return nil, fmt.Errorf("unauthorized: only owner or super employee can create manager admin")
		}
	case models.RoleTypeSuperAdmin:
		return nil, fmt.Errorf("cannot create super admin through service")
	default:
		return nil, fmt.Errorf("invalid role type")
	}

	// Generate phone hash
	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)

	// Encrypt phone number
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, req.PhoneNumber, "phone")
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt phone number: %w", err)
	}

	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	phoneEncryptedBytes := []byte(encryptedResult.EncryptedValue)

	// Check if username already exists
	existingAdmin, _ := s.adminRepo.GetAdminByUsername(ctx, req.Username)
	if existingAdmin != nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if phone already exists
	existingPhoneAdmin, _ := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if existingPhoneAdmin != nil {
		return nil, fmt.Errorf("phone number already exists")
	}

	// Validate reports_to if provided
	if req.ReportsTo != nil {
		reportsToAdmin, err := s.adminRepo.GetAdminByID(ctx, *req.ReportsTo)
		if err != nil {
			return nil, fmt.Errorf("reports_to admin not found: %w", err)
		}
		if reportsToAdmin.RoleType < adminRole.RoleType {
			return nil, fmt.Errorf("reports_to admin must have higher or equal role level")
		}
	}

	// Create admin user
	adminID := uuid.New()
	now := time.Now().UTC()

	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		PhoneEncrypted:      phoneEncryptedBytes,
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

	// Create admin in repository
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
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

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

	return admin, nil
}

// GetAdminsByRoleType gets admins by role type (returns only 2 values)
func (s *AdminService) GetAdminsByRoleType(
	ctx context.Context,
	roleType int,
	requesterID uuid.UUID,
	includeInactive bool,
	limit int,
	offset int,
) ([]*models.AdminUserSearchResult, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check permissions based on role type
	switch roleType {
	case models.RoleTypeEmployee:
		// Employees can view other employees
	case models.RoleTypeManager:
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			return nil, fmt.Errorf("unauthorized: cannot view managers")
		}
	case models.RoleTypeSuperAdmin:
		if !requester.IsOwner() {
			return nil, fmt.Errorf("unauthorized: cannot view super admins")
		}
	default:
		return nil, fmt.Errorf("invalid role type")
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
		return nil, fmt.Errorf("failed to get admins by role type: %w", err)
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

	return admins, nil
}
func (s *AdminService) CheckAdminDepartmentAccess(
	ctx context.Context,
	adminID uuid.UUID,
	departmentName string,
) (bool, error) {
	// Get all system departments
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get system departments: %w", err)
	}

	var targetDept *models.SystemDepartment
	for _, dept := range systemDepts {
		if dept.Name == departmentName {
			targetDept = dept
			break
		}
	}

	if targetDept == nil {
		return false, fmt.Errorf("department not found: %s", departmentName)
	}

	// Check if admin has access to this department
	hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, adminID, targetDept.Bitmask)
	if err != nil {
		return false, fmt.Errorf("failed to check department access: %w", err)
	}

	return hasAccess, nil
}

// SearchAdminsByName searches admins by name
func (s *AdminService) SearchAdminsByName(
	ctx context.Context,
	name string,
	requesterID uuid.UUID,
	limit int,
	offset int,
) ([]*models.AdminUserSearchResult, int, error) {
	req := &models.AdminSearchRequest{
		Query:           name,
		SearchType:      "fulltext",
		IncludeInactive: false,
		Limit:           limit,
		Offset:          offset,
	}

	return s.SearchAdminsWithFilters(ctx, requesterID, req)
}

// SearchAdminEmployees searches admin employees
func (s *AdminService) SearchAdminEmployees(
	ctx context.Context,
	query string,
	requesterID uuid.UUID,
	limit int,
	offset int,
) ([]*models.AdminUserSearchResult, int, error) {
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

// SearchAdminManagers searches admin managers
func (s *AdminService) SearchAdminManagers(
	ctx context.Context,
	query string,
	requesterID uuid.UUID,
	limit int,
	offset int,
) ([]*models.AdminUserSearchResult, int, error) {
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

// GetAdminPhoneNumber retrieves and decrypts an admin's phone number (super admin only)
func (s *AdminService) GetAdminPhoneNumber(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) (string, error) {
	startTime := time.Now()

	// Get requester admin
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return "", fmt.Errorf("requester not found: %w", err)
	}

	// Only super admin (owner) can access decrypted phone numbers
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
		return "", fmt.Errorf("unauthorized: only owner can access decrypted phone numbers")
	}

	// Get target admin with encrypted phone details
	targetAdmin, err := s.adminRepo.GetAdminWithEncryptedPhone(ctx, adminID)
	if err != nil {
		return "", fmt.Errorf("admin not found: %w", err)
	}

	// ✅ CORRECT: Create EncryptedData struct with proper fields
	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(targetAdmin.PhoneEncrypted),
		KeyID:          targetAdmin.PhoneKeyID.String(),
		EncryptedDEK:   targetAdmin.PhoneEncryptedDEK,
		// ❌ REMOVED: FieldType - Not a valid field in EncryptedData
		// ✅ ADD if needed: Version and CreatedAt (check if they're required)
		Version:   "v1",                       // This might be stored or known from your encryption version
		CreatedAt: targetAdmin.AdminCreatedAt, // Use appropriate timestamp
	}

	// Decrypt the phone number
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
		return "", fmt.Errorf("failed to decrypt phone number: %w", err)
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

	return decryptedPhone, nil
}

// func (s *AdminService) InitSuperAdmin(
//     ctx context.Context,
//     phoneNumber string,
//     username string,
//     fullName string,
// ) (*models.AdminUser, error) {
//     startTime := time.Now()
//     s.logger.Info("Initializing super admin...",
//         zap.String("phone", phoneNumber),
//         zap.String("username", username),
//         zap.String("full_name", fullName))

//     if phoneNumber == "" {
//         return nil, fmt.Errorf("phone number cannot be empty")
//     }
//     if username == "" {
//         return nil, fmt.Errorf("username cannot be empty")
//     }
//     if fullName == "" {
//         return nil, fmt.Errorf("full name cannot be empty")
//     }

//     // Check if super admin already exists
//     existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
//     if err != nil && err != sql.ErrNoRows {
//         return nil, fmt.Errorf("failed to check for existing super admin: %w", err)
//     }
//     if existingSuperAdmin != nil {
//         s.logger.Warn("Super admin already exists",
//             zap.String("admin_id", existingSuperAdmin.AdminID.String()),
//             zap.String("username", existingSuperAdmin.Username))
//         return existingSuperAdmin, nil
//     }

//     // Check if super admin role exists
//     superAdminRole, err := s.adminRepo.GetSuperAdminRole(ctx)
//     if err != nil && err != sql.ErrNoRows {
//         return nil, fmt.Errorf("failed to check for super admin role: %w", err)
//     }

//     var roleID uuid.UUID
//     var roleCreated bool = false

//     if superAdminRole == nil {
//         // Create new super admin role with ALL permissions and departments
//         roleID = uuid.New()
//         now := time.Now().UTC()

//         superAdminRole = &models.AdminRole{
//             AdminRoleID:   roleID,
//             RoleName:      "Super Admin",
//             RoleLevel:     s.getRoleLevel(models.RoleTypeSuperAdmin),
//             RoleType:      models.RoleTypeSuperAdmin,
//             IsSystemRole:  true,
//             Description:   "System super administrator with full access to ALL permissions and ALL departments",
//             CreatedAt:     now,
//             UpdatedAt:     now,
//         }

//         // Get ALL system departments
//         allSystemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//         if err != nil {
//             return nil, fmt.Errorf("failed to get ALL system departments: %w", err)
//         }

//         // Create department IDs array (though we'll ignore it in CreateSuperAdminRole)
//         departmentIDs := make([]uuid.UUID, 0, len(allSystemDepartments))
//         for _, dept := range allSystemDepartments {
//             departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
//         }

//         // Create the super admin role with ALL permissions and ALL departments
//         if err := s.adminRepo.CreateSuperAdminRole(ctx, superAdminRole, departmentIDs); err != nil {
//             return nil, fmt.Errorf("failed to create super admin role with ALL permissions: %w", err)
//         }

//         roleCreated = true
//         s.logger.Info("✅ Created new super admin role with ALL permissions and ALL departments",
//             zap.String("role_id", roleID.String()),
//             zap.String("role_name", superAdminRole.RoleName),
//             zap.Int("total_departments", len(allSystemDepartments)))
//     } else {
//         // Use existing super admin role, but ensure it has ALL permissions
//         roleID = superAdminRole.AdminRoleID

//         // Ensure existing role has ALL permissions
//         if err := s.adminRepo.GrantAllPermissionsToRole(ctx, roleID, uuid.Nil); err != nil {
//             s.logger.Warn("Failed to grant all permissions to existing super admin role",
//                 zap.String("role_id", roleID.String()),
//                 zap.Error(err))
//         } else {
//             s.logger.Info("✅ Granted ALL permissions to existing super admin role",
//                 zap.String("role_id", roleID.String()),
//                 zap.String("role_name", superAdminRole.RoleName))
//         }

//         // Ensure existing role has ALL departments
//         allDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//         if err != nil {
//             s.logger.Warn("Failed to get all departments for super admin role",
//                 zap.String("role_id", roleID.String()),
//                 zap.Error(err))
//         } else {
//             for _, dept := range allDepartments {
//                 if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, dept.SystemDepartmentID); err != nil {
//                     s.logger.Debug("Department assignment to super admin role",
//                         zap.String("role_id", roleID.String()),
//                         zap.String("department_id", dept.SystemDepartmentID.String()),
//                         zap.Error(err))
//                 }
//             }
//             s.logger.Info("✅ Ensured ALL departments assigned to existing super admin role",
//                 zap.String("role_id", roleID.String()),
//                 zap.Int("total_departments", len(allDepartments)))
//         }

//         s.logger.Info("Using existing super admin role",
//             zap.String("role_id", roleID.String()),
//             zap.String("role_name", superAdminRole.RoleName))
//     }

//     // Check for duplicate phone/username
//     phoneHash := s.GeneratePhoneHash(phoneNumber)
//     existingPhoneAdmin, _ := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
//     if existingPhoneAdmin != nil {
//         return nil, fmt.Errorf("phone number already exists for admin: %s", existingPhoneAdmin.Username)
//     }

//     existingUsernameAdmin, _ := s.adminRepo.GetAdminByUsername(ctx, username)
//     if existingUsernameAdmin != nil {
//         return nil, fmt.Errorf("username already exists")
//     }

//     // Encrypt phone number
//     encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
//     if err != nil {
//         return nil, fmt.Errorf("failed to encrypt phone number: %w", err)
//     }
//     keyID, err := uuid.Parse(encryptedResult.KeyID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to parse key ID: %w", err)
//     }
//     phoneEncryptedBytes := []byte(encryptedResult.EncryptedValue)

//     // Create super admin user
//     adminID := uuid.New()
//     now := time.Now().UTC()
//     admin := &models.AdminUser{
//         AdminID:             adminID,
//         PhoneHash:           phoneHash,
//         PhoneEncrypted:      phoneEncryptedBytes,
//         PhoneKeyID:          keyID,
//         PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
//         AdminRoleID:         roleID,
//         RoleType:            models.RoleTypeSuperAdmin,
//         ReportsTo:           nil,
//         AdminCreatedAt:      now,
//         AdminCreatedBy:      &adminID,
//         AdminUpdatedAt:      now,
//         IsActive:            true,
//         DataAccessScope:     []string{"*"},
//         IPWhitelist:         []string{"*"},
//         FailedLoginAttempts: 0,
//         Username:            username,
//         FullName:            fullName,
//     }

//     if err := s.adminRepo.CreateSuperAdminUser(ctx, admin); err != nil {
//         return nil, fmt.Errorf("failed to create super admin user: %w", err)
//     }

//     // Verify permissions were granted
//     permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
//     if err != nil {
//         s.logger.Warn("Failed to verify super admin permissions",
//             zap.String("admin_id", adminID.String()),
//             zap.Error(err))
//     } else {
//         s.logger.Info("✅ Super admin permissions verified",
//             zap.String("admin_id", adminID.String()),
//             zap.Int("total_permissions", len(permissions)))
//     }

//     // Verify departments were assigned
//     departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
//     if err != nil {
//         s.logger.Warn("Failed to verify super admin departments",
//             zap.String("admin_id", adminID.String()),
//             zap.Error(err))
//     } else {
//         s.logger.Info("✅ Super admin departments verified",
//             zap.String("admin_id", adminID.String()),
//             zap.Int("total_departments", len(departments)))
//     }

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "super_admin_init",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Super admin initialized successfully with ALL permissions and ALL departments",
//         },
//         AdminID:      adminID.String(),
//         Action:       "init_super_admin",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "username":              username,
//             "full_name":             fullName,
//             "role_type":             models.RoleTypeSuperAdmin,
//             "is_active":             true,
//             "phone":                 phoneNumber,
//             "role_id":               roleID.String(),
//             "role_created":          roleCreated,
//             "permissions_granted":   "ALL",
//             "permissions_count":     len(permissions),
//             "departments_assigned":  "ALL",
//             "departments_count":     len(departments),
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     s.logger.Info("🎉 Super admin initialized SUCCESSFULLY",
//         zap.String("admin_id", adminID.String()),
//         zap.String("username", username),
//         zap.String("full_name", fullName),
//         zap.String("role_id", roleID.String()),
//         zap.Int("permissions", len(permissions)),
//         zap.Int("departments", len(departments)),
//         zap.Bool("role_created", roleCreated),
//         zap.Duration("duration", time.Since(startTime)))

//     return admin, nil
// }

// InitDefaultSuperAdmin initializes the default super admin (Sarvesh Chhabra)
func (s *AdminService) InitDefaultSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	// Default super admin details
	phoneNumber := "+917206583437"
	username := "sarvesh"
	fullName := "Sarvesh Chhabra"

	return s.InitSuperAdmin(ctx, phoneNumber, username, fullName)
}

// CheckAndInitSuperAdmin checks if super admin exists and initializes if not
func (s *AdminService) CheckAndInitSuperAdmin(ctx context.Context) (bool, *models.AdminUser, error) {
	// Check if super admin already exists
	existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil && err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("failed to check for super admin: %w", err)
	}

	if existingSuperAdmin != nil {
		s.logger.Info("Super admin already exists",
			zap.String("admin_id", existingSuperAdmin.AdminID.String()),
			zap.String("username", existingSuperAdmin.Username))
		return false, existingSuperAdmin, nil
	}

	// Initialize default super admin
	admin, err := s.InitDefaultSuperAdmin(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("failed to initialize super admin: %w", err)
	}

	return true, admin, nil
}

// GetSuperAdmin gets the super admin (owner)
func (s *AdminService) GetSuperAdmin(ctx context.Context) (*models.AdminUser, error) {
	return s.GetAdminOwner(ctx)
}

func (s *AdminService) InitSuperAdmin(
	ctx context.Context,
	phoneNumber string,
	username string,
	fullName string,
) (*models.AdminUser, error) {
	startTime := time.Now()
	s.logger.Info("🔧 INITIALIZING SUPER ADMIN...",
		zap.String("phone", phoneNumber),
		zap.String("username", username),
		zap.String("full_name", fullName))

	// Debug current state
	s.logger.Info("🔍 Checking current database state...")
	if err := s.adminRepo.(*postgres.AdminRepositoryPostgres).DebugSuperAdminInit(ctx); err != nil {
		s.logger.Warn("Failed to debug database state", zap.Error(err))
	}

	// Validation checks...
	if phoneNumber == "" {
		return nil, fmt.Errorf("phone number cannot be empty")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if fullName == "" {
		return nil, fmt.Errorf("full name cannot be empty")
	}

	// Check if super admin already exists
	s.logger.Info("🔍 Checking for existing super admin...")
	existingSuperAdmin, err := s.adminRepo.GetSuperAdmin(ctx)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Error("❌ Failed to check for existing super admin", zap.Error(err))
		return nil, fmt.Errorf("failed to check for existing super admin: %w", err)
	}

	if existingSuperAdmin != nil {
		s.logger.Warn("⚠️ Super admin already exists",
			zap.String("admin_id", existingSuperAdmin.AdminID.String()),
			zap.String("username", existingSuperAdmin.Username))

		// Check if existing super admin has permissions
		permissions, _ := s.adminRepo.GetAdminUserPermissions(ctx, existingSuperAdmin.AdminID)
		s.logger.Info(fmt.Sprintf("📊 Existing super admin has %d permissions", len(permissions)))

		return existingSuperAdmin, nil
	}
	s.logger.Info("✅ No existing super admin found, proceeding with initialization")

	// Check if super admin role exists
	s.logger.Info("🔍 Checking for super admin role...")
	superAdminRole, err := s.adminRepo.GetSuperAdminRole(ctx)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Error("❌ Failed to check for super admin role", zap.Error(err))
		return nil, fmt.Errorf("failed to check for super admin role: %w", err)
	}

	var roleID uuid.UUID
	var roleCreated bool = false

	if superAdminRole == nil {
		s.logger.Info("🆕 Creating new super admin role...")

		// Create new super admin role
		roleID = uuid.New()
		now := time.Now().UTC()

		superAdminRole = &models.AdminRole{
			AdminRoleID:  roleID,
			RoleName:     "Super Admin",
			RoleLevel:    s.getRoleLevel(models.RoleTypeSuperAdmin),
			RoleType:     models.RoleTypeSuperAdmin,
			IsSystemRole: true,
			Description:  "System super administrator with full access to ALL permissions and ALL departments",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Get ALL system departments
		s.logger.Info("📋 Getting all system departments...")
		allSystemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
		if err != nil {
			s.logger.Error("❌ Failed to get system departments", zap.Error(err))
			return nil, fmt.Errorf("failed to get ALL system departments: %w", err)
		}

		s.logger.Info(fmt.Sprintf("📊 Found %d system departments", len(allSystemDepartments)))

		// Create department IDs array
		departmentIDs := make([]uuid.UUID, 0, len(allSystemDepartments))
		for _, dept := range allSystemDepartments {
			departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
			s.logger.Debug(fmt.Sprintf("Department: %s (ID: %s)", dept.Name, dept.SystemDepartmentID.String()))
		}

		// Create the super admin role with ALL permissions and ALL departments
		s.logger.Info("🚀 Creating super admin role with ALL permissions and ALL departments...")
		if err := s.adminRepo.CreateSuperAdminRole(ctx, superAdminRole, departmentIDs); err != nil {
			s.logger.Error("❌ FAILED to create super admin role", zap.Error(err))
			return nil, fmt.Errorf("failed to create super admin role with ALL permissions: %w", err)
		}

		roleCreated = true
		s.logger.Info("✅ Created new super admin role with ALL permissions and ALL departments",
			zap.String("role_id", roleID.String()),
			zap.String("role_name", superAdminRole.RoleName),
			zap.Int("total_departments", len(allSystemDepartments)))
	} else {
		s.logger.Info("🔄 Using existing super admin role...")
		roleID = superAdminRole.AdminRoleID

		s.logger.Info(fmt.Sprintf("Existing role: %s (ID: %s)", superAdminRole.RoleName, roleID.String()))

		// Ensure existing role has ALL permissions
		s.logger.Info("🔐 Ensuring existing role has ALL permissions...")
		if err := s.adminRepo.GrantAllPermissionsToRole(ctx, roleID, uuid.Nil); err != nil {
			s.logger.Warn("⚠️ Failed to grant all permissions to existing super admin role",
				zap.String("role_id", roleID.String()),
				zap.Error(err))
		} else {
			s.logger.Info("✅ Granted ALL permissions to existing super admin role",
				zap.String("role_id", roleID.String()),
				zap.String("role_name", superAdminRole.RoleName))
		}

		// Ensure existing role has ALL departments
		s.logger.Info("🏢 Ensuring existing role has ALL departments...")
		allDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
		if err != nil {
			s.logger.Warn("⚠️ Failed to get all departments for super admin role",
				zap.String("role_id", roleID.String()),
				zap.Error(err))
		} else {
			s.logger.Info(fmt.Sprintf("Found %d departments to assign", len(allDepartments)))
			for _, dept := range allDepartments {
				if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, dept.SystemDepartmentID); err != nil {
					s.logger.Debug("Department assignment to super admin role",
						zap.String("role_id", roleID.String()),
						zap.String("department_id", dept.SystemDepartmentID.String()),
						zap.Error(err))
				}
			}
			s.logger.Info("✅ Ensured ALL departments assigned to existing super admin role",
				zap.String("role_id", roleID.String()),
				zap.Int("total_departments", len(allDepartments)))
		}

		s.logger.Info("Using existing super admin role",
			zap.String("role_id", roleID.String()),
			zap.String("role_name", superAdminRole.RoleName))
	}

	// Check for duplicate phone/username
	s.logger.Info("🔍 Checking for duplicate phone/username...")
	phoneHash := s.GeneratePhoneHash(phoneNumber)
	existingPhoneAdmin, _ := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if existingPhoneAdmin != nil {
		s.logger.Error("❌ Phone number already exists")
		return nil, fmt.Errorf("phone number already exists for admin: %s", existingPhoneAdmin.Username)
	}

	existingUsernameAdmin, _ := s.adminRepo.GetAdminByUsername(ctx, username)
	if existingUsernameAdmin != nil {
		s.logger.Error("❌ Username already exists")
		return nil, fmt.Errorf("username already exists")
	}

	// Encrypt phone number
	s.logger.Info("🔐 Encrypting phone number...")
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
	if err != nil {
		s.logger.Error("❌ Failed to encrypt phone number", zap.Error(err))
		return nil, fmt.Errorf("failed to encrypt phone number: %w", err)
	}
	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		s.logger.Error("❌ Failed to parse key ID", zap.Error(err))
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}
	phoneEncryptedBytes := []byte(encryptedResult.EncryptedValue)

	// Create super admin user
	s.logger.Info("👤 Creating super admin user...")
	adminID := uuid.New()
	now := time.Now().UTC()
	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		PhoneEncrypted:      phoneEncryptedBytes,
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
		s.logger.Error("❌ FAILED to create super admin user", zap.Error(err))
		return nil, fmt.Errorf("failed to create super admin user: %w", err)
	}

	s.logger.Info("✅ Super admin user created successfully")

	// Verify permissions were granted
	s.logger.Info("🔍 Verifying permissions...")
	permissions, err := s.adminRepo.GetAdminUserPermissions(ctx, adminID)
	if err != nil {
		s.logger.Warn("⚠️ Failed to verify super admin permissions",
			zap.String("admin_id", adminID.String()),
			zap.Error(err))
	} else {
		s.logger.Info("✅ Super admin permissions verified",
			zap.String("admin_id", adminID.String()),
			zap.Int("total_permissions", len(permissions)))
	}

	// Verify departments were assigned
	s.logger.Info("🔍 Verifying departments...")
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		s.logger.Warn("⚠️ Failed to verify super admin departments",
			zap.String("admin_id", adminID.String()),
			zap.Error(err))
	} else {
		s.logger.Info("✅ Super admin departments verified",
			zap.String("admin_id", adminID.String()),
			zap.Int("total_departments", len(departments)))
	}

	// Log event
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
			"username":             username,
			"full_name":            fullName,
			"role_type":            models.RoleTypeSuperAdmin,
			"is_active":            true,
			"phone":                phoneNumber,
			"role_id":              roleID.String(),
			"role_created":         roleCreated,
			"permissions_granted":  "ALL",
			"permissions_count":    len(permissions),
			"departments_assigned": "ALL",
			"departments_count":    len(departments),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("🎉 SUPER ADMIN INITIALIZATION COMPLETE!",
		zap.String("admin_id", adminID.String()),
		zap.String("username", username),
		zap.String("full_name", fullName),
		zap.String("role_id", roleID.String()),
		zap.Int("permissions", len(permissions)),
		zap.Int("departments", len(departments)),
		zap.Bool("role_created", roleCreated),
		zap.Duration("duration", time.Since(startTime)))

	return admin, nil
}

// service/admin_service.go - Update CreateAdminRole method
func (s *AdminService) CreateAdminRole(
	ctx context.Context,
	req *models.AdminRoleCreateRequest,
	createdBy uuid.UUID,
) (*models.AdminRole, error) {
	startTime := time.Now()
	if req.RoleName == "" {
		return nil, fmt.Errorf("role name cannot be empty")
	}
	if req.RoleType == 0 {
		return nil, fmt.Errorf("role type must be specified")
	}
	if req.RoleType != models.RoleTypeEmployee && req.RoleType != models.RoleTypeManager {
		return nil, fmt.Errorf("invalid role type. Must be employee (1) or manager (2)")
	}
	creator, err := s.adminRepo.GetAdminByID(ctx, createdBy)
	if err != nil {
		return nil, fmt.Errorf("creator not found: %w", err)
	}
	if req.RoleType == models.RoleTypeManager {
		if !creator.IsOwner() && !creator.IsSuperEmployee() {
			return nil, fmt.Errorf("unauthorized: only owner or super employee can create manager roles")
		}
	}
	if len(req.DepartmentIDs) == 0 {
		return nil, fmt.Errorf("at least one department must be specified")
	}
	systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system departments: %w", err)
	}
	departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentIDs))
	departmentMap := make(map[uuid.UUID]*models.SystemDepartment)
	for _, deptID := range req.DepartmentIDs {
		found := false
		for _, sysDept := range systemDepartments {
			if sysDept.SystemDepartmentID == deptID {
				if !creator.IsOwner() {
					hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, createdBy, sysDept.Bitmask)
					if err != nil {
						return nil, fmt.Errorf("failed to check department access: %w", err)
					}
					if !hasAccess {
						return nil, fmt.Errorf("creator does not have access to department: %s", sysDept.Name)
					}
				}
				departmentIDs = append(departmentIDs, deptID)
				departmentMap[deptID] = sysDept
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("department not found: %s", deptID)
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
	if err := s.adminRepo.CreateAdminRole(ctx, role, departmentIDs); err != nil {
		return nil, fmt.Errorf("failed to create admin role: %w", err)
	}

	// ONLY grant all permissions to manager roles automatically
	// Employee roles get specific permissions via the handler
	if req.RoleType == models.RoleTypeManager {
		for _, deptID := range departmentIDs {
			permissions, err := s.companyRepo.GetPermissionsBySystemDepartments(
				ctx,
				[]uuid.UUID{deptID},
				"", "", "",
			)
			if err != nil {
				s.logger.Warn("Failed to get permissions for department",
					zap.String("role_id", roleID.String()),
					zap.String("department_id", deptID.String()),
					zap.Error(err))
				continue
			}
			for _, perm := range permissions {
				if err := s.adminRepo.GrantPermissionToAdminRole(ctx, roleID, perm.PermissionID, createdBy); err != nil {
					s.logger.Warn("Failed to grant permission to role",
						zap.String("role_id", roleID.String()),
						zap.String("permission_id", perm.PermissionID.String()),
						zap.Error(err))
				}
			}
		}
	}

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
			"department_ids": departmentIDs,
			"description":    req.Description,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	return role, nil
}
func (s *AdminService) GrantPermissionToAdminRole(
	ctx context.Context,
	roleID uuid.UUID,
	permissionID uuid.UUID,
	grantedBy uuid.UUID,
) error {
	startTime := time.Now()

	// Check if permission is already granted
	granted, err := s.adminRepo.IsPermissionGrantedToRole(ctx, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to check permission grant: %w", err)
	}

	if granted {
		// Permission already granted, nothing to do
		s.logger.Debug("Permission already granted to role",
			zap.String("role_id", roleID.String()),
			zap.String("permission_id", permissionID.String()))
		return nil
	}

	// Grant the permission
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
		return fmt.Errorf("failed to grant permission to admin role: %w", err)
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
			"granted_by":    grantedBy.String(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// GetAdminRoleWithDetails gets role with departments and permissions
func (s *AdminService) GetAdminRoleWithDetails(
	ctx context.Context,
	roleID uuid.UUID,
	requesterID uuid.UUID,
) (*models.AdminRole, []*models.SystemDepartment, []*models.Permission, error) {
	startTime := time.Now()

	// Get role
	role, err := s.adminRepo.GetAdminRole(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin role not found: %w", err)
	}

	// Authorization check
	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("requester not found: %w", err)
	}

	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		// Check if requester has access to all role departments
		roleDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get role departments: %w", err)
		}

		for _, dept := range roleDepts {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, requesterID, dept.Bitmask)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return nil, nil, nil, fmt.Errorf("unauthorized: cannot view this role")
			}
		}
	}

	// Get departments
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get role departments: %w", err)
	}

	// Get permissions
	permissions, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	// Log the event
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

	return role, departments, permissions, nil
}

// GetAvailablePermissionsForRole gets all permissions available for a role based on its departments
func (s *AdminService) GetAvailablePermissionsForRole(
	ctx context.Context,
	roleID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.Permission, error) {
	startTime := time.Now()

	// Get role departments
	departments, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role departments: %w", err)
	}

	if len(departments) == 0 {
		return []*models.Permission{}, nil
	}

	// Get department IDs
	deptIDs := make([]uuid.UUID, len(departments))
	for i, dept := range departments {
		deptIDs[i] = dept.SystemDepartmentID
	}

	// Get permissions for these departments
	permissions, err := s.companyRepo.GetPermissionsBySystemDepartments(
		ctx, deptIDs, "", "", "",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	// Get current role permissions
	currentPerms, err := s.adminRepo.GetAdminRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current permissions: %w", err)
	}

	// Create a map of current permission IDs
	currentPermMap := make(map[uuid.UUID]bool)
	for _, perm := range currentPerms {
		currentPermMap[perm.PermissionID] = true
	}

	// Filter out already granted permissions
	var availablePerms []*models.Permission
	for _, perm := range permissions {
		if !currentPermMap[perm.PermissionID] {
			availablePerms = append(availablePerms, perm)
		}
	}

	// Log the event
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
			"departments_count":     len(departments),
			"total_permissions":     len(permissions),
			"available_permissions": len(availablePerms),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return availablePerms, nil
}

func (s *AdminService) processRoleDepartmentUpdatesByName(
	ctx context.Context,
	roleID uuid.UUID,
	updates *models.AdminRoleUpdateRequest,
	updatedBy uuid.UUID,
	updater *models.AdminUser,
	role *models.AdminRole,
) error {
	// Get all system departments
	systemDepts, err := s.companyRepo.GetSystemDepartments(ctx)
	if err != nil {
		return fmt.Errorf("failed to get system departments: %w", err)
	}

	// Create a map from department name to department
	deptNameMap := make(map[string]*models.SystemDepartment)
	deptIDMap := make(map[uuid.UUID]*models.SystemDepartment)
	for _, dept := range systemDepts {
		deptNameMap[dept.Name] = dept
		deptIDMap[dept.SystemDepartmentID] = dept
	}

	// Get current role departments
	currentDepts, err := s.adminRepo.GetAdminRoleDepartments(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get current role departments: %w", err)
	}

	currentDeptNameMap := make(map[string]bool)
	currentDeptIDMap := make(map[uuid.UUID]bool)
	for _, dept := range currentDepts {
		currentDeptNameMap[dept.Name] = true
		currentDeptIDMap[dept.SystemDepartmentID] = true
	}

	// Process department removals by name
	for _, deptName := range updates.RemoveDepartments {
		dept, exists := deptNameMap[deptName]
		if !exists {
			return fmt.Errorf("department not found: %s", deptName)
		}

		if !currentDeptIDMap[dept.SystemDepartmentID] {
			continue // Department not currently assigned, skip
		}

		if !updater.IsOwner() {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil {
				return fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return fmt.Errorf("updater does not have access to department: %s", deptName)
			}
		}

		if err := s.adminRepo.RemoveDepartmentFromAdminRole(ctx, roleID, dept.SystemDepartmentID); err != nil {
			return fmt.Errorf("failed to remove department from role: %w", err)
		}
	}

	// Process department additions by name
	for _, deptName := range updates.AddDepartments {
		dept, exists := deptNameMap[deptName]
		if !exists {
			return fmt.Errorf("department not found: %s", deptName)
		}

		if currentDeptIDMap[dept.SystemDepartmentID] {
			continue // Department already assigned, skip
		}

		if !updater.IsOwner() {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil {
				return fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return fmt.Errorf("updater does not have access to department: %s", deptName)
			}
		}

		if err := s.adminRepo.AssignDepartmentToAdminRole(ctx, roleID, dept.SystemDepartmentID); err != nil {
			return fmt.Errorf("failed to assign department to role: %w", err)
		}
	}

	return nil
}

// GetEmployeeAdminRoles gets all admin roles available for employees
func (s *AdminService) GetEmployeeAdminRoles(
	ctx context.Context,
	requesterID uuid.UUID,
) ([]*models.AdminRole, error) {
	startTime := time.Now()

	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Only owner, super employee, or managers can view employee roles
	if !requester.IsOwner() && !requester.IsSuperEmployee() && !requester.IsManager() {
		return nil, fmt.Errorf("unauthorized: cannot view employee admin roles")
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
		return nil, fmt.Errorf("failed to get employee admin roles: %w", err)
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

	return roles, nil
}

// GetManagerAdminRoles gets all admin roles available for managers
func (s *AdminService) GetManagerAdminRoles(
	ctx context.Context,
	requesterID uuid.UUID,
) ([]*models.AdminRole, error) {
	startTime := time.Now()

	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Only owner or super employee can view manager roles
	if !requester.IsOwner() && !requester.IsSuperEmployee() {
		return nil, fmt.Errorf("unauthorized: cannot view manager admin roles")
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
		return nil, fmt.Errorf("failed to get manager admin roles: %w", err)
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

	return roles, nil
}

// GetAdminRolesByType gets admin roles filtered by role type
func (s *AdminService) GetAdminRolesByType(
	ctx context.Context,
	roleType int,
	requesterID uuid.UUID,
) ([]*models.AdminRole, error) {
	startTime := time.Now()

	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	// Check authorization based on role type being requested
	switch roleType {
	case models.RoleTypeEmployee:
		// Employees, managers, super employees, and owners can view employee roles
		if !requester.IsOwner() && !requester.IsSuperEmployee() &&
			!requester.IsManager() && !requester.IsEmployee() {
			return nil, fmt.Errorf("unauthorized: cannot view employee admin roles")
		}

	case models.RoleTypeManager:
		// Only owner or super employee can view manager roles
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			return nil, fmt.Errorf("unauthorized: cannot view manager admin roles")
		}

	case models.RoleTypeSuperAdmin:
		// Only owner can view super admin roles
		if !requester.IsOwner() {
			return nil, fmt.Errorf("unauthorized: cannot view super admin roles")
		}

	default:
		return nil, fmt.Errorf("invalid role type: %d", roleType)
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
		return nil, fmt.Errorf("failed to get admin roles by type %d: %w", roleType, err)
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

	return roles, nil
}
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
		return nil, fmt.Errorf("admin role not found: %w", err)
	}

	// IMPORTANT: Check if role is nil before accessing its fields
	if role == nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin_role_get_by_name",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin role is nil",
			},
			Action:       "get_admin_role_by_name",
			Status:       "failed",
			ErrorCode:    "ROLE_NIL",
			ErrorMessage: "admin role is nil",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("admin role is nil")
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
		ResourceID:   role.AdminRoleID.String(), // Safe to access now
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})
	return role, nil
}

// GetAdminDepartments gets all departments assigned to an admin user
func (s *AdminService) GetAdminDepartments(
	ctx context.Context,
	adminID uuid.UUID,
	requesterID uuid.UUID,
) ([]*models.SystemDepartment, error) {
	startTime := time.Now()

	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
	}

	if requester.AdminID != adminID {
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !s.canManageAdmin(requester, targetAdmin) {
				return nil, fmt.Errorf("unauthorized: cannot view this admin's departments")
			}
		}
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
		return nil, fmt.Errorf("failed to get admin departments: %w", err)
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

	return departments, nil
}

func (s *AdminService) UpdateAdminUserRole(
	ctx context.Context,
	adminID uuid.UUID,
	newRoleID uuid.UUID,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	// 1. Validate inputs
	if adminID == uuid.Nil {
		return fmt.Errorf("admin ID cannot be empty")
	}
	if newRoleID == uuid.Nil {
		return fmt.Errorf("new role ID cannot be empty")
	}

	// 2. Get the updater (who is making the change)
	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	// 3. Get the target admin (who is being updated)
	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("target admin not found: %w", err)
	}

	// 4. Get the new role details
	newRole, err := s.adminRepo.GetAdminRole(ctx, newRoleID)
	if err != nil {
		return fmt.Errorf("new admin role not found: %w", err)
	}

	// 5. Authorization checks
	// a. Updater must be owner or super employee
	if !updater.IsOwner() && !updater.IsSuperEmployee() {
		return fmt.Errorf("unauthorized: only owner or super employee can change admin roles")
	}

	// b. Cannot change owner's role
	if targetAdmin.IsSuperAdmin() {
		return fmt.Errorf("cannot change role of owner (super admin) user")
	}

	// c. Cannot assign owner role
	if newRole.RoleType == models.RoleTypeSuperAdmin {
		return fmt.Errorf("cannot assign owner (super admin) role")
	}

	// d. If updater is not owner, they cannot assign manager roles
	if !updater.IsOwner() {
		if newRole.RoleType == models.RoleTypeManager {
			return fmt.Errorf("unauthorized: only owner can assign manager role")
		}

		// e. Check department access for non-owners
		roleDepartments, err := s.adminRepo.GetAdminRoleDepartments(ctx, newRoleID)
		if err != nil {
			return fmt.Errorf("failed to get role departments: %w", err)
		}

		for _, dept := range roleDepartments {
			hasAccess, err := s.adminRepo.AdminHasDepartmentAccess(ctx, updatedBy, dept.Bitmask)
			if err != nil {
				return fmt.Errorf("failed to check department access: %w", err)
			}
			if !hasAccess {
				return fmt.Errorf("updater does not have access to department: %s", dept.Name)
			}
		}
	}

	// f. Check if trying to change to same role
	if targetAdmin.AdminRoleID == newRoleID {
		s.logger.Info("Admin already has the requested role",
			util.String("admin_id", adminID.String()),
			util.String("role_id", newRoleID.String()))
		return nil
	}

	// 6. Update the admin user's role
	oldRoleID := targetAdmin.AdminRoleID

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
		return fmt.Errorf("failed to update admin user role: %w", err)
	}

	// 7. Log the successful change
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
			"old_role_id":    oldRoleID.String(),
			"new_role_id":    newRoleID.String(),
			"admin_name":     targetAdmin.FullName,
			"admin_username": targetAdmin.Username,
			"updater_role":   updater.GetRoleString(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin user role updated successfully",
		util.String("admin_id", adminID.String()),
		util.String("username", targetAdmin.Username),
		util.String("old_role_id", oldRoleID.String()),
		util.String("new_role_id", newRoleID.String()),
		util.String("updated_by", updatedBy.String()),
		util.String("updater_role", updater.GetRoleString()))

	return nil
}
