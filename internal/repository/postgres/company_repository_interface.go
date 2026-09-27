package postgres

import (
	"auth-service/internal/client"
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

// CompanyRepository defines the persistence contract for companies,
// departments, roles, employees, permissions, positions, and jobs.
//
// Convention:
//   - Methods that take `db client.DBTX` can be called with either
//     r.client.Pool() (auto-commit) or an active *sql.Tx (transactional).
//   - Methods WITHOUT `db client.DBTX` either call r.client directly
//     (read-only pool access) or manage their own transaction internally
//     via r.client.BeginTx.
type CompanyRepository interface {
	// ============================================================
	// Company Operations
	// ============================================================
	CreateCompany(
		ctx context.Context,
		company *models.Company,
		additionalDepartments []string,
		ownerPositionTitle string,
		positionDetails *models.Position,
		workCenterDetails *models.WorkCenter,
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

	// ============================================================
	// System Department Operations
	// ============================================================
	GetSystemDepartment(ctx context.Context, db client.DBTX, systemDeptID uuid.UUID) (*models.SystemDepartment, error)
	GetSystemDepartments(ctx context.Context, db client.DBTX) ([]*models.SystemDepartment, error)
	GetSystemDepartmentByModule(ctx context.Context, db client.DBTX, module string) (*models.SystemDepartment, error)
	GetSystemDepartmentsWithBitmask(ctx context.Context, db client.DBTX) ([]*models.SystemDepartment, error)
	GetDepartmentBitmask(ctx context.Context, db client.DBTX, departmentName string) (uint64, error)

	// ============================================================
	// Department Operations
	// ============================================================
	CreateDepartment(ctx context.Context, department *models.Department) error
	GetDepartmentsByCompany(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error)
	UpdateDepartment(ctx context.Context, department *models.Department) error
	DeactivateDepartment(ctx context.Context, departmentID uuid.UUID) error
	GetDepartmentHierarchy(ctx context.Context, db client.DBTX, companyID uuid.UUID) ([]*models.Department, error)
	GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error)
	GetDepartmentBySystemID(ctx context.Context, companyID, systemDepartmentID uuid.UUID) (*models.Department, error)
	DeleteDepartment(ctx context.Context, db client.DBTX, departmentID uuid.UUID) error

	// ============================================================
	// Role-Department Mapping Operations
	// ============================================================
	CreateRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error
	RemoveRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error
	GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error)
	RemoveAllRoleDepartments(ctx context.Context, db client.DBTX, departmentID uuid.UUID) error
	GetRoleDepartmentsForPermission(ctx context.Context, db client.DBTX, roleID uuid.UUID) ([]*models.Department, error)
	AddRoleDepartments(ctx context.Context, db client.DBTX, roleID uuid.UUID, departmentIDs []uuid.UUID) error
	RemoveRoleDepartments(ctx context.Context, db client.DBTX, roleID uuid.UUID, departmentIDs []uuid.UUID) error

	// ============================================================
	// Role & Permission Operations
	// ============================================================
	CreateRole(ctx context.Context, role *models.Role, departmentIDs []uuid.UUID) error
	CreateRoleWithDetails(ctx context.Context, role *models.Role, departmentID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error
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
	ClearRolePermissions(ctx context.Context, db client.DBTX, roleID uuid.UUID) error
	AddRolePermissions(ctx context.Context, db client.DBTX, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error
	RemoveRolePermissions(ctx context.Context, db client.DBTX, roleID uuid.UUID, permissionIDs []uuid.UUID) error

	// ============================================================
	// Employee Operations
	// ============================================================
	CreateEmployee(ctx context.Context, db client.DBTX, employee *models.CompanyEmployee) error
	GetEmployee(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
	GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error)
	UpdateEmployee(ctx context.Context, employee *models.CompanyEmployee) error
	UpdateEmployeeRole(ctx context.Context, companyID, userID, roleID uuid.UUID) error
	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
	UpdateEmployeeOfCompany(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID, updates map[string]interface{}) error
	UpdateEmployeePosition(ctx context.Context, db client.DBTX, companyID uuid.UUID, userID uuid.UUID, positionID *uuid.UUID) error

	// Employee Queries
	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	GetEmployeesByDepartment(ctx context.Context, db client.DBTX, departmentID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	GetEmployeesByRole(ctx context.Context, db client.DBTX, roleID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error)
	GetUsersByRoleLevel(ctx context.Context, db client.DBTX, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error)
	GetEmployeeDepartment(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) (*models.Department, error)
	GetEmployeeDepartments(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) ([]*models.Department, error)
	GetEmployeeWithPosition(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) (*models.EmployeeWithPositionDetails, error)
	GetEmployeeSummariesByCompany(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit, offset int) ([]models.EmployeeSummary, int, error)
	GetEmployeesByCompany(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error)
	GetDepartmentsByUserID(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) ([]*models.Department, error)

	// ============================================================
	// Permission & RBAC Queries
	// ============================================================
	GetAllPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermissionsByCategory(ctx context.Context, category string) ([]*models.Permission, error)
	GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error)
	GetPermissionsByNames(ctx context.Context, permissionNames []string) ([]*models.Permission, error)
	CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error)
	CheckUserPermissionDetailed(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (*models.PermissionCheckResult, error)
	GetUserPermissions(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Permission, error)
	GetUserPermissionNames(ctx context.Context, userID uuid.UUID) ([]string, error)
	GetUsersWithPermission(ctx context.Context, db client.DBTX, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error)

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
	GetPermissionsByCompanyModules(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error)
	GetModulePermissions(ctx context.Context, modules []string, category, tier string) ([]*models.Permission, error)
	GetPermissionsByModules(ctx context.Context, db client.DBTX, modules []string) ([]*models.Permission, error)

	// ============================================================
	// Advanced Company Search
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

	GetCompanySuggestions(ctx context.Context, prefix string, limit int) ([]string, error)
	GetCompanySearchStats(ctx context.Context) (map[string]interface{}, error)

	// ============================================================
	// Department — Read Operations
	// ============================================================
	GetDepartment(ctx context.Context, db client.DBTX, departmentID uuid.UUID) (*models.Department, error)
	GetDepartmentByID(ctx context.Context, db client.DBTX, departmentID uuid.UUID) (*models.Department, error)
	GetDepartmentByName(ctx context.Context, db client.DBTX, companyID uuid.UUID, departmentName string) (*models.Department, error)
	GetRootDepartments(ctx context.Context, db client.DBTX, companyID uuid.UUID) ([]*models.Department, error)
	GetDepartmentChildren(ctx context.Context, db client.DBTX, departmentID uuid.UUID) ([]*models.Department, error)
	GetSubDepartments(ctx context.Context, db client.DBTX, parentDepartmentID uuid.UUID) ([]*models.Department, error)
	GetDepartmentParents(ctx context.Context, db client.DBTX, departmentID uuid.UUID) ([]*models.Department, error)
	GetDepartmentTree(ctx context.Context, db client.DBTX, departmentID uuid.UUID) ([]*models.DepartmentTree, error)
	GetDeactivatedDepartments(ctx context.Context, db client.DBTX, companyID uuid.UUID) ([]*models.Department, error)
	GetDepartmentSuggestions(ctx context.Context, db client.DBTX, companyID uuid.UUID, prefix string, limit int) ([]*models.Department, error)
	SearchDepartments(ctx context.Context, db client.DBTX, companyID uuid.UUID, searchQuery string, limit int, offset int, includeInactive bool) ([]*models.DepartmentSearchResult, int, error)

	// ============================================================
	// Department — Write Operations
	// ============================================================
	UpdateDepartmentName(ctx context.Context, departmentID uuid.UUID, newName string) error
	UpdateDepartmentParent(ctx context.Context, db client.DBTX, departmentID uuid.UUID, parentDepartmentID *uuid.UUID) error
	MoveDepartmentWithEmployees(ctx context.Context, departmentID uuid.UUID, newParentDepartmentID *uuid.UUID) error
	CreateSubDepartment(ctx context.Context, companyID uuid.UUID, parentDepartmentID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error)
	CreateCompanyDepartment(ctx context.Context, db client.DBTX, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error)
	SoftDeleteDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error
	ActivateDepartment(ctx context.Context, companyID uuid.UUID, departmentID uuid.UUID) error
	UpdateEmployeeTx(ctx context.Context, db client.DBTX, emp *models.CompanyEmployee) error

	// ============================================================
	// Department Quotas
	// ============================================================
	GetCompanyByID(ctx context.Context, db client.DBTX, companyID uuid.UUID) (*models.Company, error)
	GetActiveDepartmentCount(ctx context.Context, db client.DBTX, companyID uuid.UUID) (int, error)
	CheckDepartmentLimit(ctx context.Context, db client.DBTX, companyID uuid.UUID) error
	GetCompanyDepartmentInfo(ctx context.Context, db client.DBTX, companyID uuid.UUID) (*models.CompanyDepartmentInfo, error)

	// ============================================================
	// Job Operations  👈 NEW
	//
	// A job is a *definition*: "Cashier", "Line Operator". It carries
	// no location and no work center — those live on the seat
	// (positions). One job can back N positions across N sites.
	// ============================================================
	//
	// FindOrCreateJob is idempotent on (company_id, job_code). It
	// returns the existing job if one exists with the same code —
	// otherwise it inserts a new row. Used by CreateCompany and by
	// service-layer code that creates positions from a title.
	FindOrCreateJob(
		ctx context.Context,
		db client.DBTX,
		companyID uuid.UUID,
		jobCode, jobTitle string,
		isSchedulable, attendanceRequired, overtimeAllowed bool,
	) (*models.Job, error)

	GetJobByID(ctx context.Context, jobID uuid.UUID) (*models.Job, error)
	ListJobsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.Job, error)
	UpdateJob(ctx context.Context, job *models.Job) error

	// DeactivateJob sets is_active = false. It does NOT delete the row —
	// existing positions keep referencing it. New positions cannot be
	// created against an inactive job.
	DeactivateJob(ctx context.Context, jobID uuid.UUID) error

	// ============================================================
	// Position Operations  👈 CHANGED
	//
	// Reads now return *models.PositionView, which carries the joined
	// job_title, job_code, is_schedulable, attendance_required,
	// overtime_allowed, department_name, location_name, and
	// work_center_name alongside the seat's own fields.
	//
	// Writes take a *models.Position — the view is read-only.
	// ============================================================
	CreatePosition(ctx context.Context, db client.DBTX, position *models.Position) error
	UpdatePosition(ctx context.Context, db client.DBTX, position *models.Position) error
	UpdatePositionStatus(ctx context.Context, db client.DBTX, positionID uuid.UUID, isOpen bool) error
	DeletePosition(ctx context.Context, db client.DBTX, positionID uuid.UUID) error

	GetPosition(ctx context.Context, db client.DBTX, positionID uuid.UUID) (*models.PositionView, error)
	GetPositionsByCompany(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit int, offset int, onlyOpen bool) ([]*models.PositionView, int, error)
	GetPositionsByDepartment(ctx context.Context, db client.DBTX, departmentID uuid.UUID, limit int, offset int, onlyOpen bool) ([]*models.PositionView, int, error)
	GetOpenPositions(ctx context.Context, db client.DBTX, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.PositionView, int, error)

	// PositionExists now checks the seat's uniqueness using title_override
	// (which may be NULL → falls back to jobs.job_title) plus location_id.
	// NULL title_override and NULL location_id are treated as equal via
	// COALESCE in the SQL, matching the uq_positions_dept_title_loc index.
	PositionExists(
		ctx context.Context,
		db client.DBTX,
		companyID, departmentID uuid.UUID,
		titleOverride *string,
		locationID *uuid.UUID,
	) (bool, error)

	WorkCenterExists(ctx context.Context, db client.DBTX, companyID uuid.UUID, workCenterCode string) (bool, error)

	// ============================================================
	// Employee Location Settings
	// ============================================================
	UpdateEmployeeLocationSettings(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID, primaryLocationID *uuid.UUID, accessScope string) error

	// SetWorkCenterLocation links a work center to a location AND
	// backfills positions.location_id for any seat that uses this work
	// center and still has NULL location_id. Both writes happen so the
	// enforce_position_location_matches_work_center trigger stays happy.
	SetWorkCenterLocation(ctx context.Context, db client.DBTX, companyID uuid.UUID, workCenterCode string, locationID uuid.UUID) error

	// ============================================================
	// Utility
	// ============================================================
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	Close() error
}
