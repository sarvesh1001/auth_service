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
	CreateCompany(
		ctx context.Context,
		company *models.Company,
		additionalDepartments []string,
		ownerPositionTitle string,
	) error
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
	) ([]*models.Permission, error) // OR rename the second one:
	GetPermissionsByModules(ctx context.Context, modules []string) ([]*models.Permission, error)
	CreateSubDepartment(
		ctx context.Context,
		companyID uuid.UUID,
		parentDepartmentID uuid.UUID,
		departmentName string,
		systemDepartmentID uuid.UUID,
	) (*models.Department, error)

	// UpdateDepartmentName updates only the department name
	UpdateDepartmentName(
		ctx context.Context,
		departmentID uuid.UUID,
		newName string,
	) error

	// UpdateDepartmentParent changes the parent of a department
	UpdateDepartmentParent(
		ctx context.Context,
		departmentID uuid.UUID,
		parentDepartmentID *uuid.UUID,
	) error

	// MoveDepartmentWithEmployees moves a department under a new parent
	// (transactional operation)
	MoveDepartmentWithEmployees(
		ctx context.Context,
		departmentID uuid.UUID,
		newParentDepartmentID *uuid.UUID,
	) error

	// =====================================================
	// DEPARTMENT — READ OPERATIONS
	// =====================================================

	// GetDepartment retrieves a department by ID
	GetDepartment(
		ctx context.Context,
		departmentID uuid.UUID,
	) (*models.Department, error)

	// GetRootDepartments returns all root-level departments for a company
	GetRootDepartments(
		ctx context.Context,
		companyID uuid.UUID,
	) ([]*models.Department, error)

	// GetDepartmentChildren returns immediate child departments
	GetDepartmentChildren(
		ctx context.Context,
		departmentID uuid.UUID,
	) ([]*models.Department, error)

	// GetSubDepartments returns all active sub-departments
	GetSubDepartments(
		ctx context.Context,
		parentDepartmentID uuid.UUID,
	) ([]*models.Department, error)

	// GetDepartmentParents returns all parents up to root
	GetDepartmentParents(
		ctx context.Context,
		departmentID uuid.UUID,
	) ([]*models.Department, error)

	// GetDepartmentTree returns the entire subtree starting from a department
	GetDepartmentTree(
		ctx context.Context,
		departmentID uuid.UUID,
	) ([]*models.DepartmentTree, error)

	// =====================================================
	// POSITION — WRITE OPERATIONS
	// =====================================================

	// CreatePosition creates a new position
	CreatePosition(
		ctx context.Context,
		position *models.Position,
	) error

	// UpdatePosition updates position details
	UpdatePosition(
		ctx context.Context,
		position *models.Position,
	) error

	// UpdatePositionStatus opens or closes a position
	UpdatePositionStatus(
		ctx context.Context,
		positionID uuid.UUID,
		isOpen bool,
	) error

	// DeletePosition permanently deletes a position
	DeletePosition(
		ctx context.Context,
		positionID uuid.UUID,
	) error

	// =====================================================
	// POSITION — READ OPERATIONS
	// =====================================================

	// GetPosition retrieves a position by ID
	GetPosition(
		ctx context.Context,
		positionID uuid.UUID,
	) (*models.Position, error)

	// GetPositionsByCompany returns paginated positions for a company
	GetPositionsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		limit int,
		offset int,
		onlyOpen bool,
	) ([]*models.Position, int, error)
	// GetCompanyByID returns company with max_departments included
	GetCompanyByID(ctx context.Context, companyID uuid.UUID) (*models.Company, error)

	// GetActiveDepartmentCount returns active department count for a company
	GetActiveDepartmentCount(ctx context.Context, companyID uuid.UUID) (int, error)

	// GetCompanyDepartmentInfo returns quota & usage info
	GetCompanyDepartmentInfo(ctx context.Context, companyID uuid.UUID) (*CompanyDepartmentInfo, error)

	// CheckDepartmentLimit validates if a new department can be created
	CheckDepartmentLimit(ctx context.Context, companyID uuid.UUID) error

	// UpdateMaxDepartments updates department quota safely
	UpdateMaxDepartments(ctx context.Context, companyID uuid.UUID, newMaxDepartments int) error
	// GetPositionsByDepartment returns paginated positions for a department
	GetPositionsByDepartment(
		ctx context.Context,
		departmentID uuid.UUID,
		limit int,
		offset int,
		onlyOpen bool,
	) ([]*models.Position, int, error)
	SoftDeleteDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error
	CreateCompanyDepartment(
		ctx context.Context,
		companyID uuid.UUID,
		departmentName string,
		systemDepartmentID uuid.UUID,
	) (*models.Department, error)
	GetDepartmentByID(
		ctx context.Context,
		departmentID uuid.UUID,
	) (*models.Department, error)
	PositionExists(
		ctx context.Context,
		companyID, departmentID uuid.UUID,
		title string,
	) (bool, error)
	// In the interface definition
	SearchDepartments(
		ctx context.Context,
		companyID uuid.UUID,
		searchQuery string,
		limit int,
		offset int,
		includeInactive bool,
	) ([]*models.DepartmentSearchResult, int, error)
	ActivateDepartment(
		ctx context.Context,
		companyID uuid.UUID,
		departmentID uuid.UUID,
	) error
	GetDepartmentSuggestions(
		ctx context.Context,
		companyID uuid.UUID,
		prefix string,
		limit int,
	) ([]*models.Department, error)

	// UpdateEmployeePosition assigns or removes a position for an employee
	// positionID == nil means "remove position"
	UpdateEmployeePosition(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		positionID *uuid.UUID,
	) error

	// GetEmployeeWithPosition retrieves employee details along with position (if any)
	GetEmployeeWithPosition(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
	) (*models.CompanyEmployee, *models.Position, error)

	GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error)
}
