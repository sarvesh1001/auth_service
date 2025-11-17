// internal/service/company_service.go
package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CompanyService struct {
	companyRepo postgres.CompanyRepository
	userService *UserService
	logger      *zap.Logger
}

type BulkAssignment struct {
	UserID       uuid.UUID `json:"user_id"`
	RoleID       uuid.UUID `json:"role_id"`
	DepartmentID uuid.UUID `json:"department_id,omitempty"`
	ReportsTo    uuid.UUID `json:"reports_to,omitempty"`
}

func NewCompanyService(
	companyRepo postgres.CompanyRepository,
	userService *UserService,
	logger *zap.Logger,
) *CompanyService {
	return &CompanyService{
		companyRepo: companyRepo,
		userService: userService,
		logger:      logger,
	}
}

// ============================================================================
// COMPANY CONTEXT & PERMISSION FLOW
// ============================================================================

type CompanyContext struct {
	CompanyID        string   `json:"company_id"`
	EmployeeID       string   `json:"employee_id"`
	RoleID           string   `json:"role_id"`
	RoleLevel        int      `json:"role_level"`
	RoleName         string   `json:"role_name"`
	DepartmentID     string   `json:"department_id"`
	DepartmentName   string   `json:"department_name"`
	SystemModule     string   `json:"system_module"`
	Permissions      []string `json:"permissions"`
	SubscriptionTier string   `json:"subscription_tier"`
	IsOwner          bool     `json:"is_owner"`
	IsManager        bool     `json:"is_manager"`
}

type PermissionCheckRequest struct {
	CompanyID      uuid.UUID `json:"company_id" validate:"required"`
	UserID         uuid.UUID `json:"user_id" validate:"required"`
	PermissionName string    `json:"permission_name" validate:"required"`
	Module         string    `json:"module,omitempty"`
}

type PermissionCheckResult struct {
	HasPermission bool              `json:"has_permission"`
	IsOwner       bool              `json:"is_owner"`
	Checks        map[string]bool   `json:"checks"`
	Details       *PermissionDetail `json:"details,omitempty"`
	Message       string            `json:"message,omitempty"`
}

type PermissionDetail struct {
	CompanyID      string `json:"company_id"`
	UserID         string `json:"user_id"`
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	DepartmentID   string `json:"department_id"`
	SystemModule   string `json:"system_module"`
	PermissionName string `json:"permission_name"`
	RequiredModule string `json:"required_module"`
}

// ============================================================================
// CORE PERMISSION CHECKING (IMPLEMENTS THE NEW FLOW)
// ============================================================================

// CheckPermission implements the full RBAC flow: User → Employee → Role → Dept → Module → Permission
func (s *CompanyService) CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResult, error) {
	start := time.Now()
	result := &PermissionCheckResult{
		HasPermission: false,
		Checks:        make(map[string]bool),
	}

	// 1. Check if user is company owner
	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("company not found: %w", err)
	}

	if company.OwnerUserID == req.UserID {
		result.HasPermission = true
		result.IsOwner = true
		result.Checks["is_owner"] = true
		result.Checks["has_employee_record"] = true
		result.Checks["role_has_permission"] = true
		result.Checks["role_belongs_to_department"] = true
		result.Checks["module_access"] = true

		s.logger.Debug("Owner permission granted",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.UserID.String()),
			util.String("permission", req.PermissionName),
			util.Duration("duration", time.Since(start)))

		return result, nil
	}

	// 2. Get employee record (USER → EMPLOYEE)
	employee, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, req.UserID)
	if err != nil {
		result.Checks["has_employee_record"] = false
		result.Message = "User is not an active employee of this company"
		return result, nil
	}

	if !employee.IsActive {
		result.Checks["has_employee_record"] = false
		result.Message = "Employee record is not active"
		return result, nil
	}
	result.Checks["has_employee_record"] = true

	// 3. Check if employee has department
	if employee.DepartmentID == nil {
		result.Checks["has_department"] = false
		result.Message = "Employee is not assigned to any department"
		return result, nil
	}
	result.Checks["has_department"] = true

	// 4. Get role and department details
	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	department, err := s.companyRepo.GetDepartment(ctx, *employee.DepartmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department: %w", err)
	}

	// 5. Check role has permission (ROLE → PERMISSION)
	permission, err := s.companyRepo.GetPermissionByName(ctx, req.PermissionName)
	if err != nil {
		result.Checks["role_has_permission"] = false
		result.Message = fmt.Sprintf("Permission not found: %s", req.PermissionName)
		return result, nil
	}

	hasPermission, err := s.companyRepo.CheckRolePermission(ctx, employee.RoleID, permission.PermissionID)
	if err != nil {
		return nil, fmt.Errorf("failed to check role permission: %w", err)
	}
	result.Checks["role_has_permission"] = hasPermission
	if !hasPermission {
		result.Message = "Role does not have the required permission"
		return result, nil
	}

	// 6. Check role belongs to department (ROLE ↔ DEPARTMENT)
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role departments: %w", err)
	}

	roleInDepartment := false
	for _, dept := range roleDepartments {
		if dept.DepartmentID == *employee.DepartmentID {
			roleInDepartment = true
			break
		}
	}
	result.Checks["role_belongs_to_department"] = roleInDepartment
	if !roleInDepartment {
		result.Message = "Role is not assigned to employee's department"
		return result, nil
	}

	// 7. Check module access (DEPARTMENT → SYSTEM_DEPARTMENT → MODULE)
	if department.SystemDepartmentID == nil {
		result.Checks["module_access"] = false
		result.Message = "Department is not linked to any system module"
		return result, nil
	}

	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get system department: %w", err)
	}

	moduleMatch := permission.Module == systemDept.ModuleCode
	result.Checks["module_access"] = moduleMatch

	if !moduleMatch {
		result.Message = fmt.Sprintf("Permission module '%s' does not match department module '%s'",
			permission.Module, systemDept.ModuleCode)
		return result, nil
	}

	// 8. All checks passed - permission granted
	result.HasPermission = true
	result.Details = &PermissionDetail{
		CompanyID:      req.CompanyID.String(),
		UserID:         req.UserID.String(),
		RoleID:         employee.RoleID.String(),
		RoleName:       role.RoleName,
		DepartmentID:   department.DepartmentID.String(),
		SystemModule:   systemDept.ModuleCode,
		PermissionName: req.PermissionName,
		RequiredModule: permission.Module,
	}

	s.logger.Debug("Permission check completed",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", req.UserID.String()),
		util.String("permission", req.PermissionName),
		util.Bool("granted", true),
		util.Duration("duration", time.Since(start)))

	return result, nil
}

// ============================================================================
// COMPANY CREATION & SETUP (NEW FLOW)
// ============================================================================

type CreateCompanyRequest struct {
	CompanyName        string   `json:"company_name" validate:"required"`
	OwnerPhone         string   `json:"owner_phone" validate:"required"`
	SubscriptionTier   string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
	MaxEmployees       int      `json:"max_employees" validate:"required,min=1,max=2000"`
	DataRegion         string   `json:"data_region" validate:"required"`
	SubscriptionMonths int      `json:"subscription_months" validate:"required,min=1,max=36"`
	SubscriptionDays   int      `json:"subscription_days" validate:"min=0,max=30"`
	Departments        []string `json:"departments"`
}

func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest) (*models.Company, error) {
	start := time.Now()

	ownerUser, err := s.userService.CreateUserForCompanyOwner(ctx, req.OwnerPhone, req.DataRegion)
	if err != nil {
		return nil, fmt.Errorf("failed to create user for company owner: %w", err)
	}

	exists, err := s.companyRepo.CheckCompanyExists(ctx, req.CompanyName, ownerUser.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate company: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("company with name '%s' already exists for this owner", req.CompanyName)
	}

	companyID := uuid.New()
	now := time.Now().UTC()
	subscriptionEnd := now.AddDate(0, req.SubscriptionMonths, req.SubscriptionDays)

	company := &models.Company{
		CompanyID:             companyID,
		CompanyName:           req.CompanyName,
		OwnerUserID:           ownerUser.UserID,
		SubscriptionTier:      req.SubscriptionTier,
		SubscriptionStatus:    models.SubscriptionStatusActive,
		MaxEmployees:          req.MaxEmployees,
		DataRegion:            req.DataRegion,
		IsActive:              true,
		CreatedAt:             now,
		UpdatedAt:             now,
		SubscriptionStartDate: &now,
		SubscriptionEndDate:   &subscriptionEnd,
	}

	if err := s.companyRepo.CreateCompany(ctx, company, req.Departments); err != nil {
		return nil, fmt.Errorf("failed to create company: %w", err)
	}

	s.logger.Info("Company created successfully with full RBAC setup",
		util.String("company_id", companyID.String()),
		util.String("company_name", req.CompanyName),
		util.String("owner_user_id", ownerUser.UserID.String()),
		util.String("subscription_tier", req.SubscriptionTier),
		util.Int("department_count", len(req.Departments)),
		util.Duration("duration", time.Since(start)))

	return company, nil
}

// ============================================================================
// SYSTEM DEPARTMENT MANAGEMENT
// ============================================================================

func (s *CompanyService) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartments(ctx)
}

func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartmentByModule(ctx, module)
}

// ============================================================================
// DEPARTMENT MANAGEMENT (UPDATED FOR NEW FLOW)
// ============================================================================

type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
	CreatedBy          uuid.UUID  `json:"created_by" validate:"required"`
}

func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
	hasPermission, err := s.CheckUserPermission(ctx, req.CompanyID, req.CreatedBy, "admin.department.create")
	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user lacks permission to create departments")
	}

	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, req.SystemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("system department not found: %w", err)
	}

	if req.DepartmentHead != nil {
		_, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.DepartmentHead)
		if err != nil {
			return nil, fmt.Errorf("department head not found: %w", err)
		}
	}

	department := &models.Department{
		DepartmentID:       uuid.New(),
		CompanyID:          req.CompanyID,
		DepartmentName:     req.DepartmentName,
		SystemDepartmentID: &req.SystemDepartmentID,
		DepartmentHead:     req.DepartmentHead,
		ParentDepartmentID: req.ParentDepartmentID,
		IsActive:           true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}

	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
		return nil, fmt.Errorf("failed to create department: %w", err)
	}

	s.logger.Info("Department created successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", req.DepartmentName),
		util.String("system_module", systemDept.ModuleCode))

	return department, nil
}

// ============================================================================
// ROLE MANAGEMENT (UPDATED FOR NEW FLOW)
// ============================================================================

type CreateRoleRequest struct {
	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
	RoleName      string      `json:"role_name" validate:"required"`
	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
	Description   string      `json:"description"`
	DepartmentIDs []uuid.UUID `json:"department_ids"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
	CreatedBy     uuid.UUID   `json:"created_by" validate:"required"`
}

func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	hasPermission, err := s.CheckUserPermission(ctx, req.CompanyID, req.CreatedBy, "admin.role.create")
	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user lacks permission to create roles")
	}

	for _, deptID := range req.DepartmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
		if err != nil {
			return nil, fmt.Errorf("department not found: %s", deptID)
		}
		if dept.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("department %s does not belong to company", deptID)
		}
	}

	for _, permID := range req.PermissionIDs {
		allPerms, err := s.companyRepo.GetAllPermissions(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to validate permissions: %w", err)
		}
		found := false
		for _, perm := range allPerms {
			if perm.PermissionID == permID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("permission not found: %s", permID)
		}
	}

	role := &models.Role{
		RoleID:       uuid.New(),
		RoleName:     req.RoleName,
		RoleLevel:    req.RoleLevel,
		CompanyID:    req.CompanyID,
		IsSystemRole: false,
		Description:  req.Description,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.companyRepo.CreateRole(ctx, role, req.DepartmentIDs); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	if len(req.PermissionIDs) > 0 {
		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy); err != nil {
			s.logger.Warn("Failed to grant initial permissions to role",
				util.String("role_id", role.RoleID.String()),
				util.ErrorField(err))
		}
	}

	s.logger.Info("Role created successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("role_id", role.RoleID.String()),
		util.String("role_name", req.RoleName),
		util.Int("department_count", len(req.DepartmentIDs)),
		util.Int("permission_count", len(req.PermissionIDs)))

	return role, nil
}

// ============================================================================
// ROLE-DEPARTMENT MAPPING MANAGEMENT
// ============================================================================

type MapRoleToDepartmentRequest struct {
	RoleID       uuid.UUID `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	MappedBy     uuid.UUID `json:"mapped_by" validate:"required"`
}

func (s *CompanyService) MapRoleToDepartment(ctx context.Context, req *MapRoleToDepartmentRequest) error {
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	if role.CompanyID != department.CompanyID {
		return fmt.Errorf("role and department must belong to the same company")
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, req.MappedBy, "admin.role.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to map roles to departments")
	}

	if err := s.companyRepo.CreateRoleDepartment(ctx, req.RoleID, req.DepartmentID); err != nil {
		return fmt.Errorf("failed to map role to department: %w", err)
	}

	s.logger.Info("Role mapped to department successfully",
		util.String("role_id", req.RoleID.String()),
		util.String("department_id", req.DepartmentID.String()),
		util.String("mapped_by", req.MappedBy.String()))

	return nil
}

func (s *CompanyService) RemoveRoleFromDepartment(ctx context.Context, roleID, departmentID, removedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, removedBy, "admin.role.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to remove roles from departments")
	}

	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
	if err != nil {
		return fmt.Errorf("failed to check role assignments: %w", err)
	}

	for _, emp := range employees {
		if emp.DepartmentID != nil && *emp.DepartmentID == departmentID {
			return fmt.Errorf("cannot remove role from department: employees are still assigned to this role-department combination")
		}
	}

	if err := s.companyRepo.RemoveRoleDepartment(ctx, roleID, departmentID); err != nil {
		return fmt.Errorf("failed to remove role from department: %w", err)
	}

	s.logger.Info("Role removed from department successfully",
		util.String("role_id", roleID.String()),
		util.String("department_id", departmentID.String()),
		util.String("removed_by", removedBy.String()))

	return nil
}

// ============================================================================
// PERMISSION MANAGEMENT
// ============================================================================

type GrantRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
	GrantedBy     uuid.UUID   `json:"granted_by" validate:"required"`
}

func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, req.GrantedBy, "admin.permission.assign")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to grant permissions")
	}

	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, req.PermissionIDs, req.GrantedBy); err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	s.logger.Info("Permissions granted to role successfully",
		util.String("role_id", req.RoleID.String()),
		util.Int("permission_count", len(req.PermissionIDs)),
		util.String("granted_by", req.GrantedBy.String()))

	return nil
}

func (s *CompanyService) RevokeRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, revokedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, revokedBy, "admin.permission.revoke")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to revoke permissions")
	}

	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("failed to revoke permissions: %w", err)
	}

	s.logger.Info("Permissions revoked from role successfully",
		util.String("role_id", roleID.String()),
		util.Int("permission_count", len(permissionIDs)),
		util.String("revoked_by", revokedBy.String()))

	return nil
}

// ============================================================================
// COMPANY CONTEXT & USER PERMISSIONS
// ============================================================================

func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*CompanyContext, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user employees: %w", err)
	}

	if len(employees) == 0 {
		return nil, nil
	}

	emp := employees[0]
	if !emp.IsActive {
		return nil, fmt.Errorf("employee is not active")
	}

	company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("company not found: %w", err)
	}

	role, err := s.companyRepo.GetRole(ctx, emp.RoleID)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	var departmentName, systemModule string
	if emp.DepartmentID != nil {
		dept, err := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
		if err == nil {
			departmentName = dept.DepartmentName
			if dept.SystemDepartmentID != nil {
				systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
				if err == nil {
					systemModule = systemDept.ModuleCode
				}
			}
		}
	}

	permissions, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
	if err != nil {
		s.logger.Warn("failed to get employee permissions", util.ErrorField(err))
		permissions = []*models.Permission{}
	}

	permStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permStrings[i] = perm.PermissionName
	}

	return &CompanyContext{
		CompanyID:        company.CompanyID.String(),
		EmployeeID:       emp.EmployeeID,
		RoleID:           emp.RoleID.String(),
		RoleLevel:        role.RoleLevel,
		RoleName:         role.RoleName,
		DepartmentID:     emp.DepartmentID.String(),
		DepartmentName:   departmentName,
		SystemModule:     systemModule,
		Permissions:      permStrings,
		SubscriptionTier: company.SubscriptionTier,
		IsOwner:          company.OwnerUserID == userID,
		IsManager:        role.RoleLevel <= 200,
	}, nil
}

// ============================================================================
// UTILITY METHODS FOR THE NEW FLOW
// ============================================================================

func (s *CompanyService) GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRoleDepartments(ctx, roleID)
}

func (s *CompanyService) GetDepartmentRoles(ctx context.Context, departmentID uuid.UUID) ([]*models.Role, error) {
	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return nil, err
	}

	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0)
	if err != nil {
		return nil, err
	}

	var departmentRoles []*models.Role
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, dept := range roleDepts {
			if dept.DepartmentID == departmentID {
				departmentRoles = append(departmentRoles, role)
				break
			}
		}
	}

	return departmentRoles, nil
}

func (s *CompanyService) ValidateRoleDepartmentCompatibility(ctx context.Context, roleID, departmentID uuid.UUID) (bool, error) {
	permissions, err := s.companyRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		return false, err
	}

	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return false, err
	}

	if department.SystemDepartmentID == nil {
		return false, nil
	}

	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm.Module != systemDept.ModuleCode {
			return false, nil
		}
	}

	return true, nil
}

// ============================================================================
// EXISTING METHODS (UPDATED FOR CONSISTENCY)
// ============================================================================

func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	return s.companyRepo.GetCompany(ctx, companyID)
}

func (s *CompanyService) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesByOwner(ctx, ownerUserID)
}

func (s *CompanyService) UpdateCompany(ctx context.Context, company *models.Company, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, company.CompanyID, updatedBy, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update company")
	}

	return s.companyRepo.UpdateCompany(ctx, company)
}

func (s *CompanyService) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, updatedBy, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update company status")
	}

	return s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive)
}

func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, updatedBy, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update subscription")
	}

	return s.companyRepo.UpdateSubscription(ctx, companyID, tier, status, maxEmployees)
}

func (s *CompanyService) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.ListCompanies(ctx, limit, offset)
}

func (s *CompanyService) ListCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.GetCompaniesByTier(ctx, tier, limit, offset)
}

func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
}

func (s *CompanyService) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string, updatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	if !company.IsActive {
		return fmt.Errorf("company is already inactive")
	}

	if err := s.companyRepo.DeactivateCompany(ctx, companyID, reason); err != nil {
		return fmt.Errorf("failed to deactivate company: %w", err)
	}

	s.logger.Info("Company deactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("reason", reason),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) DeleteCompany(ctx context.Context, companyID uuid.UUID, deletedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	if company.IsActive {
		return fmt.Errorf("cannot delete active company. Deactivate it first")
	}

	if err := s.companyRepo.DeleteCompany(ctx, companyID); err != nil {
		return fmt.Errorf("failed to delete company: %w", err)
	}

	s.logger.Info("Company deleted by admin",
		util.String("company_id", companyID.String()),
		util.String("deleted_by", deletedBy.String()))

	return nil
}

// ============================================================================
// EMPLOYEE MANAGEMENT METHODS
// ============================================================================

func (s *CompanyService) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	return s.companyRepo.GetEmployee(ctx, companyID, userID)
}

func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.GetEmployeesByCompany(ctx, companyID, limit, offset)
}

func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}

func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, updatedBy, "hr.employee.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update employee roles")
	}

	employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("employee not found: %w", err)
	}

	if employee.DepartmentID != nil {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, newRoleID)
		if err != nil {
			return fmt.Errorf("failed to get role departments: %w", err)
		}

		roleInDepartment := false
		for _, dept := range roleDepts {
			if dept.DepartmentID == *employee.DepartmentID {
				roleInDepartment = true
				break
			}
		}
		if !roleInDepartment {
			return fmt.Errorf("new role is not assigned to employee's current department")
		}
	}

	if err := s.companyRepo.UpdateEmployeeRole(ctx, companyID, userID, newRoleID); err != nil {
		return fmt.Errorf("failed to update employee role: %w", err)
	}

	s.logger.Info("Employee role updated successfully",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("new_role_id", newRoleID.String()),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) UpdateEmployeeDepartment(ctx context.Context, companyID, userID, newDepartmentID, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, updatedBy, "hr.employee.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update employee departments")
	}

	if _, err := s.companyRepo.GetDepartment(ctx, newDepartmentID); err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("employee not found: %w", err)
	}

	roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		return fmt.Errorf("failed to get role departments: %w", err)
	}

	roleInNewDepartment := false
	for _, dept := range roleDepts {
		if dept.DepartmentID == newDepartmentID {
			roleInNewDepartment = true
			break
		}
	}
	if !roleInNewDepartment {
		return fmt.Errorf("employee's current role is not assigned to the new department")
	}

	if err := s.companyRepo.UpdateEmployeeDepartment(ctx, companyID, userID, newDepartmentID); err != nil {
		return fmt.Errorf("failed to update employee department: %w", err)
	}

	s.logger.Info("Employee department updated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("new_department_id", newDepartmentID.String()),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, removedBy, "hr.employee.terminate")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to remove employees")
	}

	if userID == removedBy {
		return fmt.Errorf("cannot remove yourself")
	}

	if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("failed to remove employee: %w", err)
	}

	s.logger.Info("Employee removed successfully",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("removed_by", removedBy.String()))

	return nil
}

func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID, reactivatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, reactivatedBy, "hr.employee.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to reactivate employees")
	}

	if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("failed to reactivate employee: %w", err)
	}

	s.logger.Info("Employee reactivated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("reactivated_by", reactivatedBy.String()))

	return nil
}

func (s *CompanyService) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetEmployeeCount(ctx, companyID)
}

func (s *CompanyService) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetActiveEmployeeCount(ctx, companyID)
}

func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
}

// ============================================================================
// ROLE MANAGEMENT METHODS
// ============================================================================

func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	return s.companyRepo.GetRole(ctx, roleID)
}

func (s *CompanyService) UpdateRole(ctx context.Context, roleID uuid.UUID, roleName string, roleLevel int, updatedBy uuid.UUID, description string) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, updatedBy, "admin.role.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update roles")
	}

	if role.IsSystemRole {
		return fmt.Errorf("cannot update system roles")
	}

	role.RoleName = roleName
	role.RoleLevel = roleLevel
	role.Description = description
	role.UpdatedAt = time.Now().UTC()

	if err := s.companyRepo.UpdateRole(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	s.logger.Info("Role updated",
		util.String("role_id", roleID.String()),
		util.String("role_name", roleName),
		util.Int("role_level", roleLevel),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) DeleteRole(ctx context.Context, roleID uuid.UUID, deletedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, deletedBy, "admin.role.delete")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to delete roles")
	}

	if role.IsSystemRole {
		return fmt.Errorf("cannot delete system roles")
	}

	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
	if err != nil {
		return fmt.Errorf("failed to check role assignments: %w", err)
	}
	if len(employees) > 0 {
		return fmt.Errorf("cannot delete role that is assigned to employees")
	}

	if err := s.companyRepo.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	s.logger.Info("Role deleted",
		util.String("role_id", roleID.String()),
		util.String("role_name", role.RoleName),
		util.String("deleted_by", deletedBy.String()))

	return nil
}

// ============================================================================
// DEPARTMENT MANAGEMENT METHODS
// ============================================================================

func (s *CompanyService) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
	return s.companyRepo.GetDepartment(ctx, departmentID)
}

func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, head *uuid.UUID, updatedBy uuid.UUID) error {
	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, department.CompanyID, updatedBy, "admin.department.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update departments")
	}

	if head != nil {
		if _, err := s.companyRepo.GetEmployee(ctx, department.CompanyID, *head); err != nil {
			return fmt.Errorf("department head not found: %w", err)
		}
	}

	department.DepartmentName = name
	department.DepartmentHead = head
	department.UpdatedAt = time.Now().UTC()

	if err := s.companyRepo.UpdateDepartment(ctx, department); err != nil {
		return fmt.Errorf("failed to update department: %w", err)
	}

	s.logger.Info("Department updated",
		util.String("department_id", departmentID.String()),
		util.String("department_name", name),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID uuid.UUID, updatedBy uuid.UUID) error {
	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, department.CompanyID, updatedBy, "admin.department.delete")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to deactivate departments")
	}

	employees, _, err := s.companyRepo.GetEmployeesByDepartment(ctx, departmentID, 1, 0)
	if err != nil {
		return fmt.Errorf("failed to check department employees: %w", err)
	}
	if len(employees) > 0 {
		return fmt.Errorf("cannot deactivate department with active employees")
	}

	if err := s.companyRepo.DeactivateDepartment(ctx, departmentID); err != nil {
		return fmt.Errorf("failed to deactivate department: %w", err)
	}

	s.logger.Info("Department deactivated",
		util.String("department_id", departmentID.String()),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentHierarchy(ctx, companyID)
}

// ============================================================================
// PERMISSION MANAGEMENT METHODS
// ============================================================================

func (s *CompanyService) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	return s.companyRepo.GetPermissionByName(ctx, name)
}

func (s *CompanyService) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

func (s *CompanyService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	return s.companyRepo.GetRolePermissions(ctx, roleID)
}

func (s *CompanyService) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, grantedBy, "admin.permission.assign")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to grant permissions")
	}

	if err := s.companyRepo.GrantRolePermission(ctx, roleID, permissionID, grantedBy); err != nil {
		return fmt.Errorf("failed to grant role permission: %w", err)
	}

	s.logger.Info("Role permission granted",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()),
		util.String("granted_by", grantedBy.String()))

	return nil
}

func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID, revokedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckUserPermission(ctx, role.CompanyID, revokedBy, "admin.permission.revoke")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to revoke permissions")
	}

	if err := s.companyRepo.RevokeRolePermission(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("failed to revoke role permission: %w", err)
	}

	s.logger.Info("Role permission revoked",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()),
		util.String("revoked_by", revokedBy.String()))

	return nil
}

// ============================================================================
// UTILITY & REPORTING METHODS
// ============================================================================

func (s *CompanyService) BulkPermissionCheck(ctx context.Context, companyID, userID uuid.UUID, permissionNames []string) (map[string]bool, error) {
	results := make(map[string]bool)

	for _, permName := range permissionNames {
		hasPerm, err := s.CheckUserPermission(ctx, companyID, userID, permName)
		if err != nil {
			s.logger.Warn("Failed to check permission",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()),
				util.String("permission", permName),
				util.ErrorField(err))
			results[permName] = false
			continue
		}
		results[permName] = hasPerm
	}

	return results, nil
}

func (s *CompanyService) GetModulePermissions(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

func (s *CompanyService) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetDepartmentLoad(ctx, companyID)
}

func (s *CompanyService) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetRoleDistribution(ctx, companyID)
}

func (s *CompanyService) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	return s.companyRepo.GetCompanyStats(ctx, companyID)
}

func (s *CompanyService) HealthCheck(ctx context.Context) error {
	return s.companyRepo.HealthCheck(ctx)
}

func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, additionalMonths, additionalDays int, extendedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	if !company.IsActive {
		return fmt.Errorf("cannot extend subscription for inactive company")
	}

	hasPermission, err := s.CheckUserPermission(ctx, companyID, extendedBy, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to extend subscription")
	}

	var newEndDate time.Time
	if company.SubscriptionEndDate != nil {
		newEndDate = company.SubscriptionEndDate.AddDate(0, additionalMonths, additionalDays)
	} else {
		newEndDate = time.Now().UTC().AddDate(0, additionalMonths, additionalDays)
	}

	company.SubscriptionEndDate = &newEndDate
	company.UpdatedAt = time.Now().UTC()

	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
		return fmt.Errorf("failed to extend subscription: %w", err)
	}

	s.logger.Info("Company subscription extended",
		util.String("company_id", companyID.String()),
		util.Int("additional_months", additionalMonths),
		util.Int("additional_days", additionalDays),
		util.String("new_end_date", newEndDate.Format(time.RFC3339)),
		util.String("extended_by", extendedBy.String()))

	return nil
}

func (s *CompanyService) AuthorizeUserLogin(ctx context.Context, phoneNumber string) (*models.User, error) {
	user, err := s.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user employees: %w", err)
	}

	hasActiveEmployment := false
	for _, emp := range employees {
		if emp.IsActive {
			hasActiveEmployment = true
			break
		}
	}

	if !hasActiveEmployment {
		return nil, fmt.Errorf("user is not an active employee in any company")
	}

	return user, nil
}

func (s *CompanyService) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersWithPermission(ctx, companyID, permissionName, limit)
}

func (s *CompanyService) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersByRoleLevel(ctx, companyID, minLevel, maxLevel)
}

// ============================================================================
// NEW RBAC HANDLER METHODS
// ============================================================================

// CreateRoleWithPermissions creates a role with permissions
func (s *CompanyService) CreateRoleWithPermissions(ctx context.Context, companyID uuid.UUID, roleName string, roleLevel int, createdBy uuid.UUID, description string, isSystemRole bool, permissions []struct {
	PermissionID uuid.UUID `json:"permission_id"`
}) (*models.Role, error) {
	permissionIDs := make([]uuid.UUID, len(permissions))
	for i, perm := range permissions {
		permissionIDs[i] = perm.PermissionID
	}

	req := &CreateRoleRequest{
		CompanyID:     companyID,
		RoleName:      roleName,
		RoleLevel:     roleLevel,
		Description:   description,
		DepartmentIDs: []uuid.UUID{},
		PermissionIDs: permissionIDs,
		CreatedBy:     createdBy,
	}

	return s.CreateRole(ctx, req)
}

func (s *CompanyService) ListRoles(ctx context.Context, companyID uuid.UUID, limit, offset int, includePermissions bool) ([]*models.Role, int, error) {
	roles, total, err := s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	if includePermissions {
		for _, role := range roles {
			permissions, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
			if err == nil {
				s.logger.Debug("Retrieved role permissions",
					util.String("role_id", role.RoleID.String()),
					util.Int("permission_count", len(permissions)))
			}
		}
	}

	return roles, total, nil
}

func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit, offset int, includeEmployees bool) ([]*models.Department, int, error) {
	departments, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	if includeEmployees {
		for _, dept := range departments {
			employees, _, err := s.companyRepo.GetEmployeesByDepartment(ctx, dept.DepartmentID, 5, 0)
			if err == nil {
				s.logger.Debug("Department employee info",
					util.String("department_id", dept.DepartmentID.String()),
					util.Int("sample_employees", len(employees)))
			}
		}
	}

	return departments, total, nil
}

func (s *CompanyService) ListPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

func (s *CompanyService) GetAllPermissions(ctx context.Context, module, category, tier string) ([]*models.Permission, error) {
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, err
	}

	var filtered []*models.Permission
	for _, perm := range allPerms {
		if module != "" && perm.Module != module {
			continue
		}
		if category != "" && perm.Category != category {
			continue
		}
		if tier != "" && perm.RequiresTier != tier {
			continue
		}
		filtered = append(filtered, perm)
	}

	return filtered, nil
}

// CheckUserPermission simplified version - FIXED
func (s *CompanyService) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
	// Use the detailed CheckPermission method instead of recursive call
	req := &PermissionCheckRequest{
		CompanyID:      companyID,
		UserID:         userID,
		PermissionName: permissionName,
	}

	result, err := s.CheckPermission(ctx, req)
	if err != nil {
		return false, err
	}

	return result.HasPermission, nil
}

// GetUserPermissions gets all permissions for a user across companies
func (s *CompanyService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	permissionMap := make(map[uuid.UUID]*models.Permission)

	for _, emp := range employees {
		if emp.IsActive {
			perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
			if err == nil {
				for _, perm := range perms {
					permissionMap[perm.PermissionID] = perm
				}
			}
		}
	}

	var allPermissions []*models.Permission
	for _, perm := range permissionMap {
		allPermissions = append(allPermissions, perm)
	}

	return allPermissions, nil
}

// CreatePermission creates a new permission
func (s *CompanyService) CreatePermission(ctx context.Context, permissionName, description, category, module, requiresTier string) (*models.Permission, error) {
	permission := &models.Permission{
		PermissionID:   uuid.New(),
		PermissionName: permissionName,
		Description:    description,
		Category:       category,
		Module:         module,
		RequiresTier:   requiresTier,
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.companyRepo.CreatePermission(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

func (s *CompanyService) GetUserHierarchy(ctx context.Context, userID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			var deptName string
			if emp.DepartmentID != nil {
				dept, _ := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
				if dept != nil {
					deptName = dept.DepartmentName
				}
			}

			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID:    emp.CompanyID,
				UserID:       emp.UserID,
				EmployeeID:   emp.EmployeeID,
				RoleName:     role.RoleName,
				RoleLevel:    role.RoleLevel,
				DepartmentID: emp.DepartmentID,
				Department:   deptName,
				ReportsTo:    emp.ReportsTo,
				IsActive:     emp.IsActive,
			})
		}
	}

	return hierarchy, nil
}

func (s *CompanyService) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, err
	}

	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			var deptName string
			if emp.DepartmentID != nil {
				dept, _ := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
				if dept != nil {
					deptName = dept.DepartmentName
				}
			}

			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID:    emp.CompanyID,
				UserID:       emp.UserID,
				EmployeeID:   emp.EmployeeID,
				RoleName:     role.RoleName,
				RoleLevel:    role.RoleLevel,
				DepartmentID: emp.DepartmentID,
				Department:   deptName,
				ReportsTo:    emp.ReportsTo,
				IsActive:     emp.IsActive,
			})
		}
	}

	return hierarchy, nil
}

func (s *CompanyService) BulkAssignRoles(ctx context.Context, companyID uuid.UUID, assignments []BulkAssignment, assignedBy uuid.UUID) (map[uuid.UUID]string, error) {
	results := make(map[uuid.UUID]string)

	for _, assignment := range assignments {
		emp, err := s.companyRepo.GetEmployee(ctx, companyID, assignment.UserID)
		if err != nil {
			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
			continue
		}

		emp.RoleID = assignment.RoleID
		if assignment.DepartmentID != uuid.Nil {
			emp.DepartmentID = &assignment.DepartmentID
		}
		if assignment.ReportsTo != uuid.Nil {
			emp.ReportsTo = &assignment.ReportsTo
		}
		emp.UpdatedAt = time.Now().UTC()

		if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
			continue
		}

		results[assignment.UserID] = "Success"
	}

	return results, nil
}

func (s *CompanyService) removeDuplicatePermissions(permissions []*models.Permission) []*models.Permission {
	keys := make(map[uuid.UUID]bool)
	var unique []*models.Permission
	for _, perm := range permissions {
		if _, value := keys[perm.PermissionID]; !value {
			keys[perm.PermissionID] = true
			unique = append(unique, perm)
		}
	}
	return unique
}

func (s *CompanyService) GetCompanyHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	hierarchy, err := s.companyRepo.GetEmployeeHierarchy(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company hierarchy: %w", err)
	}
	return hierarchy, nil
}

func (s *CompanyService) ReactivateCompany(ctx context.Context, companyID uuid.UUID, reactivatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	if company.IsActive {
		return fmt.Errorf("company is already active")
	}

	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
		return fmt.Errorf("failed to reactivate company: %w", err)
	}

	s.logger.Info("Company reactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("reactivated_by", reactivatedBy.String()))

	return nil
}

// Owner request structures
type RenameDepartmentRequest struct {
	DepartmentName string `json:"department_name" validate:"required"`
}

type AddDepartmentRequest struct {
	DepartmentName     string    `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID `json:"system_department_id" validate:"required"`
}

type AddManagerRequest struct {
	CompanyID    uuid.UUID  `json:"company_id" validate:"required"`
	PhoneNumber  string     `json:"phone" validate:"required"`
	RoleName     string     `json:"role_name" validate:"required"`
	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
	Permissions  []string   `json:"permissions" validate:"required"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
}

type AddEmployeeRequest struct {
	CompanyID    uuid.UUID  `json:"company_id" validate:"required"`
	PhoneNumber  string     `json:"phone" validate:"required"`
	EmployeeID   string     `json:"employee_id" validate:"required"`
	RoleID       uuid.UUID  `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
	Permissions  []string   `json:"permissions"`
	AddedBy      uuid.UUID  `json:"added_by" validate:"required"`
}

type PermissionAssignmentRequest struct {
	PermissionNames []string `json:"permissions" validate:"required"`
}

// ============================================================================
// PHASE 2 - OWNER OPERATIONS IMPLEMENTATION
// ============================================================================

func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, updatedBy, "admin.department.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to rename departments")
	}

	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}
	if department.CompanyID != companyID {
		return fmt.Errorf("department does not belong to company")
	}

	if err := s.companyRepo.UpdateDepartmentName(ctx, departmentID, newName); err != nil {
		return fmt.Errorf("failed to rename department: %w", err)
	}

	s.logger.Info("Department renamed successfully",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.String("new_name", newName),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) AddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID, createdBy uuid.UUID) (*models.Department, error) {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, createdBy, "admin.department.create")
	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user lacks permission to add departments")
	}

	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, systemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("system department not found: %w", err)
	}

	department := &models.Department{
		DepartmentID:       uuid.New(),
		CompanyID:          companyID,
		DepartmentName:     departmentName,
		SystemDepartmentID: &systemDepartmentID,
		IsActive:           true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}

	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
		return nil, fmt.Errorf("failed to create department: %w", err)
	}

	_, err = s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company: %w", err)
	}

	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner role: %w", err)
	}

	if err := s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID); err != nil {
		s.logger.Warn("Failed to auto-assign department to owner role",
			util.String("department_id", department.DepartmentID.String()),
			util.ErrorField(err))
	}

	s.logger.Info("Department added successfully with owner auto-access",
		util.String("company_id", companyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", departmentName),
		util.String("system_module", systemDept.ModuleCode),
		util.String("created_by", createdBy.String()))

	return department, nil
}

func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest, addedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, req.CompanyID, addedBy, "hr.employee.create")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to add managers")
	}

	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
		if err != nil {
			return fmt.Errorf("failed to get company: %w", err)
		}

		user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
			PhoneNumber:       req.PhoneNumber,
			DeviceID:          "company-assigned",
			DeviceFingerprint: "company-assigned",
			DataRegion:        company.DataRegion,
			ConsentAgreed:     true,
			ConsentVersion:    "v1.0",
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	managerRole := &models.Role{
		RoleID:       uuid.New(),
		RoleName:     req.RoleName,
		RoleLevel:    500,
		CompanyID:    req.CompanyID,
		IsSystemRole: false,
		Description:  fmt.Sprintf("Manager role for %s", req.RoleName),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	permissionIDs := make([]uuid.UUID, len(permissions))
	for i, perm := range permissions {
		permissionIDs[i] = perm.PermissionID
	}

	if err := s.companyRepo.CreateRoleWithDetails(ctx, managerRole, req.DepartmentID, permissionIDs, addedBy); err != nil {
		return fmt.Errorf("failed to create manager role: %w", err)
	}

	reportsTo := req.ReportsTo
	if reportsTo == nil {
		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
		if err != nil {
			return fmt.Errorf("failed to get company: %w", err)
		}
		reportsTo = &company.OwnerUserID
	}

	emp := &models.CompanyEmployee{
		CompanyID:    req.CompanyID,
		UserID:       user.UserID,
		EmployeeID:   fmt.Sprintf("MGR-%s", uuid.New().String()[:8]),
		RoleID:       managerRole.RoleID,
		DepartmentID: &req.DepartmentID,
		HireDate:     time.Now().UTC(),
		IsActive:     true,
		ReportsTo:    reportsTo,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("failed to add manager as employee: %w", err)
	}

	s.logger.Info("Manager added successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", user.UserID.String()),
		util.String("department_id", req.DepartmentID.String()),
		util.Int("permissions_count", len(req.Permissions)),
		util.String("added_by", addedBy.String()))

	return nil
}

// func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest, addedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckUserPermission(ctx, req.CompanyID, addedBy, "hr.employee.create")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to add employees")
// 	}

// 	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}
// 	if !company.IsActive {
// 		return fmt.Errorf("company is not active")
// 	}

// 	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get active employee count: %w", err)
// 	}
// 	if activeCount >= company.MaxEmployees {
// 		return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
// 	}

// 	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}
// 	if role.CompanyID != req.CompanyID {
// 		return fmt.Errorf("role does not belong to company")
// 	}

// 	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
// 	if err != nil {
// 		return fmt.Errorf("department not found: %w", err)
// 	}
// 	if department.CompanyID != req.CompanyID {
// 		return fmt.Errorf("department does not belong to company")
// 	}

// 	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get role departments: %w", err)
// 	}

// 	roleInDepartment := false
// 	for _, dept := range roleDepartments {
// 		if dept.DepartmentID == req.DepartmentID {
// 			roleInDepartment = true
// 			break
// 		}
// 	}
// 	if !roleInDepartment {
// 		return fmt.Errorf("role %s is not assigned to department %s", req.RoleID, req.DepartmentID)
// 	}

// 	if req.ReportsTo != nil {
// 		_, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
// 		if err != nil {
// 			return fmt.Errorf("reports_to employee not found: %w", err)
// 		}
// 	}

// 	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
// 	if err != nil {
// 		user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
// 			PhoneNumber:       req.PhoneNumber,
// 			DeviceID:          "company-assigned",
// 			DeviceFingerprint: "company-assigned",
// 			DataRegion:        company.DataRegion,
// 			ConsentAgreed:     true,
// 			ConsentVersion:    "v1.0",
// 		})
// 		if err != nil {
// 			return fmt.Errorf("failed to create user: %w", err)
// 		}
// 	}

// 	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
// 	if existingEmp != nil && existingEmp.IsActive {
// 		return fmt.Errorf("user is already an active employee in this company")
// 	}

// 	if len(req.Permissions) > 0 {
// 		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// 		if err != nil {
// 			return fmt.Errorf("failed to get permissions: %w", err)
// 		}

// 		permissionIDs := make([]uuid.UUID, len(permissions))
// 		for i, perm := range permissions {
// 			permissionIDs[i] = perm.PermissionID
// 		}

// 		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, addedBy); err != nil {
// 			return fmt.Errorf("failed to assign permissions to role: %w", err)
// 		}
// 	}

// 	reportsTo := req.ReportsTo
// 	if reportsTo == nil {
// 		reportsTo = &company.OwnerUserID
// 	}

// 	emp := &models.CompanyEmployee{
// 		CompanyID:    req.CompanyID,
// 		UserID:       user.UserID,
// 		EmployeeID:   req.EmployeeID,
// 		RoleID:       req.RoleID,
// 		DepartmentID: &req.DepartmentID,
// 		HireDate:     time.Now().UTC(),
// 		IsActive:     true,
// 		ReportsTo:    reportsTo,
// 		CreatedAt:    time.Now().UTC(),
// 		UpdatedAt:    time.Now().UTC(),
// 	}

// 	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
// 		return fmt.Errorf("failed to add employee: %w", err)
// 	}

// 	s.logger.Info("Employee added successfully",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("user_id", user.UserID.String()),
// 		util.String("employee_id", req.EmployeeID),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Int("permissions_count", len(req.Permissions)),
// 		util.String("added_by", addedBy.String()))

// 	return nil
// }

func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, assignedBy, "admin.permission.assign")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to assign permissions")
	}

	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
	if err != nil {
		return fmt.Errorf("manager not found: %w", err)
	}

	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	permissionIDs := make([]uuid.UUID, len(permissions))
	for i, perm := range permissions {
		permissionIDs[i] = perm.PermissionID
	}

	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, managerEmp.RoleID, permissionIDs, assignedBy); err != nil {
		return fmt.Errorf("failed to assign permissions to manager: %w", err)
	}

	s.logger.Info("Manager permissions assigned successfully",
		util.String("company_id", companyID.String()),
		util.String("manager_id", managerID.String()),
		util.String("role_id", managerEmp.RoleID.String()),
		util.Int("permissions_count", len(permissionNames)),
		util.String("assigned_by", assignedBy.String()))

	return nil
}

func (s *CompanyService) RevokeManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, revokedBy uuid.UUID) error {
	hasPermission, err := s.CheckUserPermission(ctx, companyID, revokedBy, "admin.permission.revoke")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to revoke permissions")
	}

	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
	if err != nil {
		return fmt.Errorf("manager not found: %w", err)
	}

	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	permissionIDs := make([]uuid.UUID, len(permissions))
	for i, perm := range permissions {
		permissionIDs[i] = perm.PermissionID
	}

	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, managerEmp.RoleID, permissionIDs); err != nil {
		return fmt.Errorf("failed to revoke permissions from manager: %w", err)
	}

	s.logger.Info("Manager permissions revoked successfully",
		util.String("company_id", companyID.String()),
		util.String("manager_id", managerID.String()),
		util.String("role_id", managerEmp.RoleID.String()),
		util.Int("permissions_count", len(permissionNames)),
		util.String("revoked_by", revokedBy.String()))

	return nil
}

// ============================================================================
// PHASE 3 - MANAGER OPERATIONS IMPLEMENTATION
// ============================================================================

// func (s *CompanyService) ManagerAddEmployee(ctx context.Context, req *AddEmployeeRequest, managerID uuid.UUID) error {
// 	managerEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, managerID)
// 	if err != nil {
// 		return fmt.Errorf("manager not found: %w", err)
// 	}

// 	if managerEmp.DepartmentID == nil || *managerEmp.DepartmentID != req.DepartmentID {
// 		return fmt.Errorf("manager can only add employees to their own department")
// 	}

// 	managerPermissions, err := s.GetManagerPermissions(ctx, managerID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get manager permissions: %w", err)
// 	}

// 	if !s.ValidatePermissionSubset(ctx, managerPermissions, req.Permissions) {
// 		return fmt.Errorf("manager cannot assign permissions they don't have")
// 	}

// 	req.ReportsTo = &managerID

//		return s.AddEmployee(ctx, req, managerID)
//	}
//
// ManagerAddEmployee handles employee addition by managers with permission validation
func (s *CompanyService) ManagerAddEmployee(ctx context.Context, req *AddEmployeeRequest, managerID uuid.UUID) error {
	start := time.Now()

	// 1. Get manager's employee record
	managerEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, managerID)
	if err != nil {
		return fmt.Errorf("manager not found: %w", err)
	}

	// 2. Verify manager can only add to their own department
	if managerEmp.DepartmentID == nil || *managerEmp.DepartmentID != req.DepartmentID {
		return fmt.Errorf("manager can only add employees to their own department")
	}

	// 3. Get manager's permissions
	managerPermissions, err := s.companyRepo.GetUserPermissions(ctx, req.CompanyID, managerID)
	if err != nil {
		return fmt.Errorf("failed to get manager permissions: %w", err)
	}

	// Convert manager permissions to a map for easy lookup
	managerPermMap := make(map[string]bool)
	for _, perm := range managerPermissions {
		managerPermMap[perm.PermissionName] = true
	}

	// 4. Validate that manager is not assigning permissions they don't have
	if len(req.Permissions) > 0 {
		for _, requestedPerm := range req.Permissions {
			if !managerPermMap[requestedPerm] {
				return fmt.Errorf("manager cannot assign permission '%s' that they don't possess", requestedPerm)
			}
		}
	}

	// 5. Check if role belongs to manager's department
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("failed to get role departments: %w", err)
	}

	roleInDepartment := false
	for _, dept := range roleDepartments {
		if dept.DepartmentID == req.DepartmentID {
			roleInDepartment = true
			break
		}
	}

	if !roleInDepartment {
		return fmt.Errorf("role %s is not assigned to department %s", req.RoleID, req.DepartmentID)
	}

	// 6. If permissions are specified, validate they are compatible with the role and department
	if len(req.Permissions) > 0 {
		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
		if err != nil {
			return fmt.Errorf("failed to validate permissions: %w", err)
		}

		// Check if permissions are compatible with department's module
		department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
		if err != nil {
			return fmt.Errorf("failed to get department: %w", err)
		}

		if department.SystemDepartmentID != nil {
			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
			if err != nil {
				return fmt.Errorf("failed to get system department: %w", err)
			}

			for _, perm := range permissions {
				if perm.Module != systemDept.ModuleCode {
					return fmt.Errorf("permission '%s' (module: %s) is not compatible with department module '%s'",
						perm.PermissionName, perm.Module, systemDept.ModuleCode)
				}
			}
		}
	}

	// 7. Set reports_to to manager for manager-added employees
	req.ReportsTo = &managerID
	req.AddedBy = managerID

	// 8. Call the regular AddEmployee method with validated parameters
	if err := s.AddEmployee(ctx, req, managerID); err != nil {
		return fmt.Errorf("failed to add employee: %w", err)
	}

	s.logger.Info("Manager added employee successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("manager_id", managerID.String()),
		util.String("employee_phone", req.PhoneNumber),
		util.String("role_id", req.RoleID.String()),
		util.String("department_id", req.DepartmentID.String()),
		util.Int("permissions_count", len(req.Permissions)),
		util.Duration("duration", time.Since(start)))

	return nil
}

// Utility methods
func (s *CompanyService) GetManagerPermissions(ctx context.Context, managerID uuid.UUID) ([]string, error) {
	return s.companyRepo.GetUserPermissionNames(ctx, managerID)
}

func (s *CompanyService) ValidatePermissionSubset(ctx context.Context, managerPermissions, requestedPermissions []string) bool {
	managerPermSet := make(map[string]bool)
	for _, perm := range managerPermissions {
		managerPermSet[perm] = true
	}

	for _, reqPerm := range requestedPermissions {
		if !managerPermSet[reqPerm] {
			return false
		}
	}
	return true
}

// Helper to remove duplicate strings
func (s *CompanyService) removeDuplicateStrings(strs []string) []string {
	keys := make(map[string]bool)
	var unique []string
	for _, str := range strs {
		if _, value := keys[str]; !value {
			keys[str] = true
			unique = append(unique, str)
		}
	}
	return unique
}

// internal/service/company_service.go

// CreateRoleWithDepartments creates a role and maps it to departments
func (s *CompanyService) CreateRoleWithDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	roleName string,
	roleLevel int,
	createdBy uuid.UUID,
	description string,
	isSystemRole bool,
	departmentIDs []uuid.UUID,
	permissionIDs []uuid.UUID,
) (*models.Role, error) {

	req := &CreateRoleRequest{
		CompanyID:     companyID,
		RoleName:      roleName,
		RoleLevel:     roleLevel,
		Description:   description,
		DepartmentIDs: departmentIDs,
		PermissionIDs: permissionIDs,
		CreatedBy:     createdBy,
	}

	return s.CreateRole(ctx, req)
}
func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest, addedBy uuid.UUID) error {
	start := time.Now()

	// 1. Check if user has permission to add employees
	hasPermission, err := s.CheckUserPermission(ctx, req.CompanyID, addedBy, "hr.employee.create")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to add employees")
	}

	// 2. Validate company
	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}
	if !company.IsActive {
		return fmt.Errorf("company is not active")
	}

	// 3. Check employee limit
	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to get active employee count: %w", err)
	}
	if activeCount >= company.MaxEmployees {
		return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
	}

	// 4. Validate role
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("role does not belong to company")
	}

	// 5. Validate department
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}
	if department.CompanyID != req.CompanyID {
		return fmt.Errorf("department does not belong to company")
	}

	// 6. Check role-department mapping
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("failed to get role departments: %w", err)
	}

	roleInDepartment := false
	for _, dept := range roleDepartments {
		if dept.DepartmentID == req.DepartmentID {
			roleInDepartment = true
			break
		}
	}
	if !roleInDepartment {
		return fmt.Errorf("role %s is not assigned to department %s", req.RoleID, req.DepartmentID)
	}

	// 7. Validate reports_to
	if req.ReportsTo != nil {
		reportsToEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
		if err != nil {
			return fmt.Errorf("reports_to employee not found: %w", err)
		}
		if !reportsToEmp.IsActive {
			return fmt.Errorf("reports_to employee is not active")
		}
	}

	// 8. Get or create user
	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
			PhoneNumber:       req.PhoneNumber,
			DeviceID:          "company-assigned",
			DeviceFingerprint: "company-assigned",
			DataRegion:        company.DataRegion,
			ConsentAgreed:     true,
			ConsentVersion:    "v1.0",
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	// 9. Check if user is already an active employee
	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
	if existingEmp != nil && existingEmp.IsActive {
		return fmt.Errorf("user is already an active employee in this company")
	}

	// 10. CRITICAL: Validate that addedBy user has the permissions they're trying to assign
	if len(req.Permissions) > 0 {
		// Get the permissions of the user who is adding the employee
		addedByPermissions, err := s.companyRepo.GetUserPermissions(ctx, req.CompanyID, addedBy)
		if err != nil {
			return fmt.Errorf("failed to get user permissions for validation: %w", err)
		}

		// Convert to map for easy lookup
		addedByPermMap := make(map[string]bool)
		for _, perm := range addedByPermissions {
			addedByPermMap[perm.PermissionName] = true
		}

		// Check if addedBy user has all the permissions they're trying to assign
		for _, requestedPerm := range req.Permissions {
			if !addedByPermMap[requestedPerm] {
				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", requestedPerm)
			}
		}

		// 11. Validate permission compatibility with department module
		if department.SystemDepartmentID != nil {
			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
			if err != nil {
				return fmt.Errorf("failed to get system department: %w", err)
			}

			permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
			if err != nil {
				return fmt.Errorf("failed to validate permissions: %w", err)
			}

			for _, perm := range permissions {
				if perm.Module != systemDept.ModuleCode {
					return fmt.Errorf("permission '%s' (module: %s) is not compatible with department module '%s'",
						perm.PermissionName, perm.Module, systemDept.ModuleCode)
				}
			}

			// Grant permissions to the role
			permissionIDs := make([]uuid.UUID, len(permissions))
			for i, perm := range permissions {
				permissionIDs[i] = perm.PermissionID
			}

			if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, addedBy); err != nil {
				return fmt.Errorf("failed to assign permissions to role: %w", err)
			}
		} else {
			// Department doesn't have a system module, get permissions and assign them
			permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
			if err != nil {
				return fmt.Errorf("failed to get permissions: %w", err)
			}

			permissionIDs := make([]uuid.UUID, len(permissions))
			for i, perm := range permissions {
				permissionIDs[i] = perm.PermissionID
			}

			if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, addedBy); err != nil {
				return fmt.Errorf("failed to assign permissions to role: %w", err)
			}
		}
	}

	// 12. Set default reports_to if not provided
	reportsTo := req.ReportsTo
	if reportsTo == nil {
		// For regular employees, default to department head or company owner
		if department.DepartmentHead != nil {
			reportsTo = department.DepartmentHead
		} else {
			reportsTo = &company.OwnerUserID
		}
	}

	// 13. Create employee record
	emp := &models.CompanyEmployee{
		CompanyID:    req.CompanyID,
		UserID:       user.UserID,
		EmployeeID:   req.EmployeeID,
		RoleID:       req.RoleID,
		DepartmentID: &req.DepartmentID,
		HireDate:     time.Now().UTC(),
		IsActive:     true,
		ReportsTo:    reportsTo,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("failed to add employee: %w", err)
	}

	s.logger.Info("Employee added successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", user.UserID.String()),
		util.String("employee_id", req.EmployeeID),
		util.String("role_id", req.RoleID.String()),
		util.String("role_name", role.RoleName),
		util.String("department_id", req.DepartmentID.String()),
		util.String("department_name", department.DepartmentName),
		util.Int("permissions_count", len(req.Permissions)),
		util.String("added_by", addedBy.String()),
		util.Duration("duration", time.Since(start)))

	return nil
}
