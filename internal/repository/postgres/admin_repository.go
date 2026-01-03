package postgres

import (
	"context"

	"auth-service/internal/models"

	"github.com/google/uuid"
)

type AdminRepository interface {
	// =========================================================
	// CORE CRUD
	// =========================================================
	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)
	GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error)
	GetAdminByUsername(ctx context.Context, username string) (*models.AdminUser, error)

	// =========================================================
	// REPORTING / HIERARCHY
	// =========================================================
	UpdateAdminReportsTo(ctx context.Context, adminID uuid.UUID, reportsTo *uuid.UUID) error
	GetAdminHierarchy(ctx context.Context, adminID uuid.UUID) ([]*models.AdminHierarchy, error)
	GetDirectReports(ctx context.Context, adminID uuid.UUID) ([]*models.AdminUser, error)
	GetReportingChain(ctx context.Context, adminID uuid.UUID) ([]*models.AdminUser, error)
	CanAssignReportsTo(ctx context.Context, assignerID, targetID uuid.UUID) (bool, error)
	BulkUpdateReportsTo(ctx context.Context, adminIDs []uuid.UUID, reportsTo *uuid.UUID) error
	GetAvailableManagers(ctx context.Context, excludeID *uuid.UUID) ([]*models.AdminUser, error)
	GetAdminWithReportsToName(ctx context.Context, adminID uuid.UUID) (*models.AdminUserSearchResult, error)
	GetAdminWithEncryptedPhone(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)

	// =========================================================
	// LISTING & FILTERING
	// =========================================================
	GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetAdminsByRoleType(
		ctx context.Context,
		roleType int,
		includeInactive bool,
		limit, offset int,
	) ([]*models.AdminUserSearchResult, error)
	GetAdminsByRole(
		ctx context.Context,
		adminRoleID uuid.UUID,
		includeInactive bool,
		limit, offset int,
	) ([]*models.AdminUserSearchResult, error)

	// =========================================================
	// PROFILE / PHONE / LOGIN
	// =========================================================
	UpdateAdminProfile(ctx context.Context, adminID uuid.UUID, username, fullName string) error
	UpdateAdminPhone(
		ctx context.Context,
		adminID uuid.UUID,
		phoneHash string,
		phoneEncrypted []byte,
		phoneKeyID uuid.UUID,
		phoneEncryptedDEK string,
	) error
	UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error

	// =========================================================
	// STATUS / LIFECYCLE
	// =========================================================
	DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error
	ActivateAdmin(ctx context.Context, adminID uuid.UUID) error

	// =========================================================
	// SUPER ADMIN
	// =========================================================
	GetSuperAdmin(ctx context.Context) (*models.AdminUser, error)
	IsSuperAdminExists(ctx context.Context) (bool, error)

	// New methods for owner initialization
	GetSuperAdminRole(ctx context.Context) (*models.AdminRole, error)
	CreateSuperAdminRole(ctx context.Context, role *models.AdminRole, departmentIDs []uuid.UUID) error
	CreateSuperAdminUser(ctx context.Context, admin *models.AdminUser) error
	GetAllAdminPermissions(ctx context.Context) ([]*models.Permission, error)
	GrantAllPermissionsToRole(ctx context.Context, roleID uuid.UUID, grantedBy uuid.UUID) error

	// =========================================================
	// FAILED LOGIN ATTEMPTS
	// =========================================================
	IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
	ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error

	// =========================================================
	// SEARCH
	// =========================================================
	SearchAdmins(
		ctx context.Context,
		req *models.AdminSearchRequest,
	) ([]*models.AdminUserSearchResult, int, error)

	GetAdminSuggestions(
		ctx context.Context,
		prefix string,
		roleTypeFilter *int,
		excludeSuperAdmin bool,
		limit int,
	) ([]*models.AdminSuggestion, error)

	SearchAdminUsers(
		ctx context.Context,
		req *models.AdminUserSearchRequest,
	) ([]*models.AdminUserSearchResult, int, error)

	// =========================================================
	// ADMIN WITH PERMISSIONS
	// =========================================================
	GetAdminWithPermissions(ctx context.Context, adminID uuid.UUID) (*models.AdminWithPermissions, error)
	AdminHasPermission(ctx context.Context, adminID uuid.UUID, permissionName string) (bool, error)
	AdminHasDepartmentAccess(ctx context.Context, adminID uuid.UUID, departmentBitmask uint64) (bool, error)

	// =========================================================
	// AVATAR MANAGEMENT
	// =========================================================
	SetAdminAvatar(
		ctx context.Context,
		adminID uuid.UUID,
		avatarHash string,
		avatarObjectKey string,
		avatarMimeType string,
	) error
	GetAdminAvatar(ctx context.Context, adminID uuid.UUID) (*models.AdminAvatar, error)
	DeactivateAdminAvatar(ctx context.Context, adminID uuid.UUID) error

	// =========================================================
	// HEALTH & STATS
	// =========================================================
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)

	// =========================================================
	// ADMIN ROLE MANAGEMENT
	// =========================================================
	CreateAdminRole(ctx context.Context, role *models.AdminRole, departmentIDs []uuid.UUID) error
	GetAdminRole(ctx context.Context, roleID uuid.UUID) (*models.AdminRole, error)
	GetAdminRoles(
		ctx context.Context,
		limit, offset int,
		roleType *int,
	) ([]*models.AdminRole, int, error)
	UpdateAdminRole(ctx context.Context, role *models.AdminRole) error
	DeleteAdminRole(ctx context.Context, roleID uuid.UUID) error

	// =========================================================
	// ADMIN USER MANAGEMENT
	// =========================================================
	CreateAdminUser(ctx context.Context, admin *models.AdminUser) error
	UpdateAdminUser(ctx context.Context, adminID uuid.UUID, updates map[string]interface{}) error
	DeleteAdminUser(ctx context.Context, adminID uuid.UUID) error

	// =========================================================
	// PERMISSION MANAGEMENT
	// =========================================================
	GetAdminRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error)
	GetAdminUserPermissions(ctx context.Context, adminID uuid.UUID) ([]*models.Permission, error)
	GrantPermissionToAdminRole(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error

	// =========================================================
	// DEPARTMENT MANAGEMENT
	// =========================================================
	GetAdminRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.SystemDepartment, error)
	AssignDepartmentToAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error
	RemoveDepartmentFromAdminRole(ctx context.Context, roleID, departmentID uuid.UUID) error

	// =========================================================
	// BITMASK OPERATIONS
	// =========================================================
	GetAdminPermissionBitmask(ctx context.Context, adminID uuid.UUID) ([]uint64, error)
	GetAdminRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error)
	GetAdminPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error)
	GetAdminPermissionsByBitPositions(ctx context.Context, bitPositions []uint64) ([]*models.Permission, error)
	GetAdminPermissionBitIndexes(
		ctx context.Context,
		permissionNames []string,
	) (map[string]uint64, error)

	// =========================================================
	// SYSTEM DEPARTMENTS
	// =========================================================
	GetAdminSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error)
	GetAdminSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error)
	GetAdminSystemDepartment(ctx context.Context, systemDeptID uuid.UUID) (*models.SystemDepartment, error)
	GetAdminDepartmentBitmask(ctx context.Context, departmentName string) (uint64, error)

	// =========================================================
	// MODULE PERMISSIONS
	// =========================================================
	GetAdminPermissionsByModules(ctx context.Context, modules []string) ([]*models.Permission, error)
	GetAdminPermissionsBySystemDepartments(
		ctx context.Context,
		systemDeptIDs []uuid.UUID,
		module, category, tier string,
	) ([]*models.Permission, error)

	GetAdminsByDepartment(
		ctx context.Context,
		departmentID uuid.UUID,
		includeInactive bool,
		limit, offset int,
	) ([]*models.AdminUserSearchResult, int, error)

	SearchAdminsAdvanced(
		ctx context.Context,
		req *models.AdminAdvancedSearchRequest,
	) ([]*models.AdminUserSearchResult, int, error)

	SearchAdminRoles(
		ctx context.Context,
		query string,
		roleTypeFilter *int,
		limit, offset int,
	) ([]*models.AdminRole, int, error)

	// =========================================================
	// LIFECYCLE
	// =========================================================
	Close() error
	DebugSuperAdminInit(ctx context.Context) error
	IsPermissionGrantedToRole(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error)
	GetPermissionByName(ctx context.Context, name string) (*models.Permission, error)
	RevokePermissionFromAdminRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetEmployeeAdminRoles(ctx context.Context) ([]*models.AdminRole, error)
	GetManagerAdminRoles(ctx context.Context) ([]*models.AdminRole, error)
	GetAdminRolesByType(ctx context.Context, roleType int) ([]*models.AdminRole, error)
	GetAdminRoleByName(ctx context.Context, roleName string) (*models.AdminRole, error)
	GetAdminDepartments(ctx context.Context, adminID uuid.UUID) ([]*models.SystemDepartment, error)
	UpdateAdminUserRole(ctx context.Context, adminID, newRoleID uuid.UUID) error
}
