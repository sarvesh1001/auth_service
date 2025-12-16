package postgres

import (
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

type CompanyRepository interface {
	// ============================================================
	// Company Operations
	// ============================================================
	CreateCompany(ctx context.Context, company *models.Company, additionalDepartments []string) error
	GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error)
	GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error)
	UpdateCompany(ctx context.Context, company *models.Company) error
	UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error
	UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int) error
	GetCompaniesByStatus(ctx context.Context, status string, limit, offset int) ([]*models.Company, int, error)
	GetCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error)
	GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error)
	DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string) error
	DeleteCompany(ctx context.Context, companyID uuid.UUID) error
	ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error)
	CheckCompanyExists(ctx context.Context, companyName string, ownerUserID uuid.UUID) (bool, error)
	GetSystemDepartment(ctx context.Context, systemDeptID uuid.UUID) (*models.SystemDepartment, error)

	// Department operations
	UpdateDepartmentName(ctx context.Context, departmentID uuid.UUID, newName string) error
	GetDepartmentBySystemID(ctx context.Context, companyID, systemDepartmentID uuid.UUID) (*models.Department, error)

	// Permission operations
	GetPermissionsByNames(ctx context.Context, permissionNames []string) ([]*models.Permission, error)
	GetUserPermissionNames(ctx context.Context, userID uuid.UUID) ([]string, error)

	// Role operations
	CreateRoleWithDetails(ctx context.Context, role *models.Role, departmentID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error

	// Employee hierarchy

	// ============================================================
	// System Department Operations
	// ============================================================
	GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error)
	GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error)

	// ============================================================
	// Department Operations
	// ============================================================
	CreateDepartment(ctx context.Context, department *models.Department) error
	GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error)
	GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error)
	UpdateDepartment(ctx context.Context, department *models.Department) error
	DeactivateDepartment(ctx context.Context, departmentID uuid.UUID) error
	GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error)
	GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error)

	// ============================================================
	// Role-Department Mapping Operations
	// ============================================================
	DeleteDepartment(ctx context.Context, departmentID uuid.UUID) error
	CreateRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error
	RemoveRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error
	GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error)
    RemoveAllRoleDepartments(ctx context.Context, departmentID uuid.UUID) error

	// ============================================================
	// Role & Permission Operations
	// ============================================================
	CreateRole(ctx context.Context, role *models.Role, departmentIDs []uuid.UUID) error
	GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error)
	GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error)
	GetSystemRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel int) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) error
	DeleteRole(ctx context.Context, roleID uuid.UUID) error

	// Role-Permission Management
	GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error
	RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error)
	GrantMultipleRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error
	RevokeMultipleRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	ReplaceRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error
	CheckRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error)
	CopyRolePermissions(ctx context.Context, sourceRoleID, targetRoleID, grantedBy uuid.UUID) error
	InitializeDefaultPermissions(ctx context.Context, companyID uuid.UUID, createdBy uuid.UUID) error

	// ============================================================
	// Employee Operations
	// ============================================================
	CreateEmployee(ctx context.Context, employee *models.CompanyEmployee) error
	GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
	GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error)
	UpdateEmployee(ctx context.Context, employee *models.CompanyEmployee) error
	UpdateEmployeeRole(ctx context.Context, companyID, userID, roleID uuid.UUID) error
	// UpdateEmployeeDepartment(ctx context.Context, companyID, userID, departmentID uuid.UUID) error
	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error

	// Employee Queries
	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	GetEmployeesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	GetEmployeesByDepartment(ctx context.Context, departmentID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	GetEmployeesByRole(ctx context.Context, roleID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error)
	GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error)
	GetEmployeeDepartment(ctx context.Context, companyID, userID uuid.UUID) (*models.Department, error)
    GetEmployeeDepartments(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Department, error)

	// ============================================================
	// Permission & RBAC Queries
	// ============================================================
	GetAllPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermissionsByCategory(ctx context.Context, category string) ([]*models.Permission, error)
	GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error)
	CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error)
	CheckUserPermissionDetailed(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (*models.PermissionCheckResult, error)
	GetUserPermissions(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Permission, error)
	GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error)

	// Permission Management
	CreatePermission(ctx context.Context, permission *models.Permission) error
	CreateMultiplePermissions(ctx context.Context, permissions []*models.Permission) error
	GetPermissionByName(ctx context.Context, permissionName string) (*models.Permission, error)
	UpdatePermission(ctx context.Context, permission *models.Permission) error
	DeletePermission(ctx context.Context, permissionID uuid.UUID) error

	// 🔵 BITMASK METHODS
	GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error)
	GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error)
	GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error)
	GetPermissionsByBitPositions(ctx context.Context, bitPositions []uint64) ([]*models.Permission, error)
	GetPermissionBitIndexes(ctx context.Context, permissionNames []string) (map[string]uint64, error)

	// ============================================================
	// Analytics & Reporting
	// ============================================================
	GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error)
	GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error)
	GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error)
	GetPermissionsBySystemDepartments(ctx context.Context, systemDeptIDs []uuid.UUID, module, category, tier string) ([]*models.Permission, error)

	// ============================================================
	// 🔍 ADVANCED COMPANY SEARCH METHODS (NEW)
	// ============================================================
	SearchCompaniesByName(
		ctx context.Context,
		searchQuery string,
		searchType string,
		filters *models.CompanySearchFilters,
		limit, offset int,
	) ([]*models.Company, int, error)

	SearchCompaniesByOwnerAndName(
		ctx context.Context,
		ownerID uuid.UUID,
		searchQuery string,
		isActive *bool,
		limit, offset int,
	) ([]*models.Company, int, error)

	GetCompanySuggestions(
		ctx context.Context,
		prefix string,
		limit int,
	) ([]string, error)

	GetCompanySearchStats(
		ctx context.Context,
	) (map[string]interface{}, error)

	// ============================================================
	// Utility Methods
	// ============================================================
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	Close() error

	GetPermissionsByCompanyModules(
        ctx context.Context,
        companyID uuid.UUID,
        module, category, tier string,
    ) ([]*models.Permission, error)	
	GetSystemDepartmentsWithBitmask(ctx context.Context) ([]*models.SystemDepartment, error)
	GetDepartmentBitmask(ctx context.Context, departmentName string) (uint64, error)
	// Keep only one of these:
	// Add this method to the CompanyRepository interface
	GetModulePermissions(
		ctx context.Context,
		modules []string,
		category, tier string,
	) ([]*models.Permission, error)	// OR rename the second one:
	GetPermissionsByModules(ctx context.Context, modules []string) ([]*models.Permission, error)
	GetAdminPermissions(ctx context.Context) ([]*models.Permission, error)
}

