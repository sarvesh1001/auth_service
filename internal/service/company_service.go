package service

import (
	"context"
	"fmt"
	"time"
	"strings"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
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

func (s *CompanyService) CheckMultiplePermissionsFromContext(ctx context.Context, permissions []string, checkAll bool) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("session type not found in context")
	}

	if sessionType == "admin" {
		return true, nil
	}

	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return false, fmt.Errorf("permission mask not found in context")
	}

	var hasRequired bool
	if checkAll {
		hasRequired = rbac.HasAllPermissions(permissionMask, permissions...)
	} else {
		hasRequired = rbac.HasAnyPermission(permissionMask, permissions...)
	}

	s.logger.Debug("Multiple bitmask permission check",
		util.Strings("permissions", permissions),
		util.Bool("check_all", checkAll),
		util.Bool("granted", hasRequired))

	return hasRequired, nil
}

func (s *CompanyService) GetPermissionsFromContext(ctx context.Context) ([]string, error) {
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return []string{}, nil
	}

	return rbac.GetPermissionsFromMask(permissionMask), nil
}

type CreateCompanyRequest struct {
    CompanyName        string   `json:"company_name" validate:"required"`
    OwnerPhone         string   `json:"owner_phone" validate:"required"`
    OwnerUsername      string   `json:"owner_username" validate:"required,min=3,max=100,alphanum"`
    OwnerFullName      string   `json:"owner_full_name" validate:"required,max=255"`
    SubscriptionTier   string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
    MaxEmployees       int      `json:"max_employees" validate:"required,min=1,max=2000"`
    DataRegion         string   `json:"data_region" validate:"required"`
    SubscriptionMonths int      `json:"subscription_months" validate:"required,min=1,max=36"`
    SubscriptionDays   int      `json:"subscription_days" validate:"min=0,max=30"`
    Departments        []string `json:"departments"`
}

func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest, createdBy uuid.UUID) (*models.Company, error) {
    start := time.Now()

    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        return nil, fmt.Errorf("only admin users can create companies")
    }

    hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.create")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return nil, fmt.Errorf("insufficient permissions to create companies")
    }

    var ownerUser *models.User
    existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
    if err != nil {
        ownerUser, err = s.createOrFindUserForCompanyOwner(ctx, req)
        if err != nil {
            return nil, fmt.Errorf("failed to create user for company owner: %w", err)
        }
    } else {
        ownerUser = existingUser

        s.logger.Info("Using existing user for company creation",
            util.String("phone", req.OwnerPhone),
            util.String("existing_username", ownerUser.Username),
            util.String("provided_username", req.OwnerUsername),
            util.String("existing_full_name", ownerUser.FullName),
            util.String("provided_full_name", req.OwnerFullName))
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

    s.logger.Info("Company created successfully by admin",
        util.String("company_id", companyID.String()),
        util.String("company_name", req.CompanyName),
        util.String("owner_user_id", ownerUser.UserID.String()),
        util.String("owner_username", ownerUser.Username),
        util.String("owner_phone", req.OwnerPhone),
        util.String("created_by", createdBy.String()),
        util.String("subscription_tier", req.SubscriptionTier),
        util.Int("department_count", len(req.Departments)),
        util.Duration("duration", time.Since(start)))

    return company, nil
}

func (s *CompanyService) createOrFindUserForCompanyOwner(ctx context.Context, req *CreateCompanyRequest) (*models.User, error) {
    user, err := s.userService.CreateUser(ctx, &UserCreateRequest{
        Username:          req.OwnerUsername,
        FullName:          req.OwnerFullName,
        PhoneNumber:       req.OwnerPhone,
        DeviceID:          "company-setup",
        DeviceFingerprint: "company-setup",
        DataRegion:        req.DataRegion,
        ConsentAgreed:     true,
        ConsentVersion:    "v1.0",
        KYCStatus:         models.KYCStatusPending,
        KYCLevel:          models.KYCLevelBasic,
    })

    if err == nil {
        return user, nil
    }

    if strings.Contains(err.Error(), "username already exists") {
        s.logger.Warn("Username already exists, generating unique username",
            util.String("requested_username", req.OwnerUsername),
            util.String("phone", req.OwnerPhone))

        uniqueUsername := fmt.Sprintf("%s_%s", req.OwnerUsername, util.GenerateRandomString(6))

        user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
            Username:          uniqueUsername,
            FullName:          req.OwnerFullName,
            PhoneNumber:       req.OwnerPhone,
            DeviceID:          "company-setup",
            DeviceFingerprint: "company-setup",
            DataRegion:        req.DataRegion,
            ConsentAgreed:     true,
            ConsentVersion:    "v1.0",
            KYCStatus:         models.KYCStatusPending,
            KYCLevel:          models.KYCLevelBasic,
        })

        if err != nil {
            return nil, fmt.Errorf("failed to create user with unique username: %w", err)
        }

        s.logger.Info("Created user with unique username",
            util.String("original_username", req.OwnerUsername),
            util.String("assigned_username", uniqueUsername),
            util.String("user_id", user.UserID.String()))

        return user, nil
    }

    return nil, err
}

type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
}

type AddEmployeeRequest struct {
    CompanyID   uuid.UUID  `json:"company_id" validate:"required"`
    PhoneNumber string     `json:"phone" validate:"required"`
    Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
    FullName    string     `json:"full_name" validate:"required,max=255"`
    EmployeeID  string     `json:"employee_id" validate:"required"`
    RoleID      uuid.UUID  `json:"role_id" validate:"required"`
    ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
}

type AddManagerRequest struct {
    CompanyID   uuid.UUID  `json:"company_id" validate:"required"`
    PhoneNumber string     `json:"phone" validate:"required"`
    Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
    FullName    string     `json:"full_name" validate:"required,max=255"`
    RoleID      uuid.UUID  `json:"role_id" validate:"required"`
    ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
    EmployeeID  string     `json:"employee_id,omitempty"`
}

type GrantRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
}

func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to grant permissions")
	}
	_, err = s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	currentUserID, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("user ID not found in context")
	}
	grantedBy, err := uuid.Parse(currentUserID)
	if err != nil {
		return fmt.Errorf("invalid user ID in context")
	}

	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, req.PermissionIDs, grantedBy); err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	s.logger.Info("Permissions granted to role successfully",
		util.String("role_id", req.RoleID.String()),
		util.Int("permission_count", len(req.PermissionIDs)))

	return nil
}

func (s *CompanyService) RevokeRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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
		util.Int("permission_count", len(permissionIDs)))

	return nil
}

func (s *CompanyService) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
}

func (s *CompanyService) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetRolePermissionBitmask(ctx, roleID)
}

func (s *CompanyService) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
	return s.companyRepo.GetPermissionsWithBitIndex(ctx)
}

func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	return s.companyRepo.GetCompany(ctx, companyID)
}

func (s *CompanyService) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesByOwner(ctx, ownerUserID)
}

func (s *CompanyService) UpdateCompany(ctx context.Context, company *models.Company) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update company")
	}

	return s.companyRepo.UpdateCompany(ctx, company)
}

func (s *CompanyService) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	return s.companyRepo.GetEmployee(ctx, companyID, userID)
}

func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.GetEmployeesByCompany(ctx, companyID, limit, offset)
}

func (s *CompanyService) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartments(ctx)
}

func (s *CompanyService) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
	return s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
}

func (s *CompanyService) HealthCheck(ctx context.Context) error {
	return s.companyRepo.HealthCheck(ctx)
}

func (s *CompanyService) AddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.create")
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

	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err != nil {
		s.logger.Warn("Failed to get owner role for auto-assignment", util.ErrorField(err))
	} else {
		if err := s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID); err != nil {
			s.logger.Warn("Failed to auto-assign department to owner role", util.ErrorField(err))
		}
	}

	s.logger.Info("Department added successfully",
		util.String("company_id", companyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", departmentName),
		util.String("system_module", systemDept.ModuleCode))

	return department, nil
}

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

func (s *CompanyService) CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResult, error) {
	start := time.Now()
	result := &PermissionCheckResult{
		HasPermission: false,
		Checks:        make(map[string]bool),
	}

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

	// Get role departments for this employee's role
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role departments: %w", err)
	}

	if len(roleDepartments) == 0 {
		result.Checks["has_department"] = false
		result.Message = "Employee's role is not assigned to any department"
		return result, nil
	}
	result.Checks["has_department"] = true

	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

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

	// Check if the role has access to a department with the required module
	roleInDepartment := true // Since role has departments, we consider it in department
	result.Checks["role_belongs_to_department"] = roleInDepartment
	if !roleInDepartment {
		result.Message = "Role is not assigned to any department"
		return result, nil
	}

	// Check module access - need to find if any department has the matching module
	moduleMatch := false
	var matchingDept *models.Department
	for _, dept := range roleDepartments {
		if dept.SystemDepartmentID == nil {
			continue
		}

		systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
		if err != nil {
			continue
		}

		if permission.Module == systemDept.ModuleCode {
			moduleMatch = true
			matchingDept = dept
			break
		}
	}
	result.Checks["module_access"] = moduleMatch

	if !moduleMatch {
		result.Message = fmt.Sprintf("Permission module '%s' does not match any department module for this role",
			permission.Module)
		return result, nil
	}

	result.HasPermission = true
	result.Details = &PermissionDetail{
		CompanyID:      req.CompanyID.String(),
		UserID:         req.UserID.String(),
		RoleID:         employee.RoleID.String(),
		RoleName:       role.RoleName,
		DepartmentID:   matchingDept.DepartmentID.String(),
		SystemModule:   matchingDept.ModuleCode,
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

func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*CompanyContext, error) {
    employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user employees: %w", err)
    }

    if len(employees) == 0 {
        return nil, fmt.Errorf("user is not an employee in any company")
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

    // Get role departments
    roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
    if err != nil {
        s.logger.Warn("Failed to get role departments", util.ErrorField(err))
    }

    var departmentID, departmentName, systemModule string
    if len(roleDepartments) > 0 {
        dept := roleDepartments[0]
        departmentID = dept.DepartmentID.String()
        departmentName = dept.DepartmentName
        if dept.SystemDepartmentID != nil {
            systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
            if err == nil {
                systemModule = systemDept.ModuleCode
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
        DepartmentID:     departmentID,
        DepartmentName:   departmentName,
        SystemModule:     systemModule,
        Permissions:      permStrings,
        SubscriptionTier: company.SubscriptionTier,
        IsOwner:          company.OwnerUserID == userID,
        IsManager:        role.RoleLevel <= 200,
    }, nil
}

func (s *CompanyService) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
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

func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartmentByModule(ctx, module)
}

func (s *CompanyService) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to update company status")
	}

	return s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive)
}

func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
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

	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to deactivate company")
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

	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.delete")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to delete company")
	}

	if err := s.companyRepo.DeleteCompany(ctx, companyID); err != nil {
		return fmt.Errorf("failed to delete company: %w", err)
	}

	s.logger.Info("Company deleted by admin",
		util.String("company_id", companyID.String()),
		util.String("deleted_by", deletedBy.String()))

	return nil
}

func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}
func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
    hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
    if err != nil {
        return fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return fmt.Errorf("user lacks permission to update employee roles")
    }

    // Get employee to validate they exist in the company
    emp, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
    if err != nil {
        return fmt.Errorf("employee not found: %w", err)
    }

    newRole, err := s.companyRepo.GetRole(ctx, newRoleID)
    if err != nil {
        return fmt.Errorf("new role not found: %w", err)
    }
    if newRole.CompanyID != companyID {
        return fmt.Errorf("new role does not belong to company")
    }

    // ✅ Get the employee's current reports_to to ensure it's still valid
    if emp.ReportsTo != nil {
        if err := s.validateReportsTo(ctx, companyID, emp.ReportsTo); err != nil {
            s.logger.Warn("Employee's current reports_to is invalid, setting to nil",
                util.String("company_id", companyID.String()),
                util.String("user_id", userID.String()),
                util.String("reports_to", emp.ReportsTo.String()),
                util.ErrorField(err))
            emp.ReportsTo = nil
        }
    }

    emp.RoleID = newRoleID
    emp.UpdatedAt = time.Now().UTC()

    if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
        return fmt.Errorf("failed to update employee role: %w", err)
    }

    s.logger.Info("Employee role updated successfully",
        util.String("company_id", companyID.String()),
        util.String("user_id", userID.String()),
        util.String("new_role_id", newRoleID.String()),
        util.String("updated_by", updatedBy.String()))

    return nil
}
func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.terminate")
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
	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
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

func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
}

func (s *CompanyService) UpdateRole(ctx context.Context, roleID uuid.UUID, roleName string, roleLevel int, updatedBy uuid.UUID, description string) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
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

	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.delete")
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
func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, head *uuid.UUID, updatedBy uuid.UUID) error {
    department, err := s.companyRepo.GetDepartment(ctx, departmentID)
    if err != nil {
        return fmt.Errorf("department not found: %w", err)
    }

    hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
    if err != nil {
        return fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return fmt.Errorf("user lacks permission to update departments")
    }

    // ✅ VALIDATE department_head is an employee of the same company
    if err := s.validateDepartmentHead(ctx, department.CompanyID, head); err != nil {
        return fmt.Errorf("department head validation failed: %w", err)
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
func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentHierarchy(ctx, companyID)
}

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
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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

func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, additionalMonths, additionalDays int, extendedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	if !company.IsActive {
		return fmt.Errorf("cannot extend subscription for inactive company")
	}

	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
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
			// Get role departments
			roleDepartments, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepartments) > 0 {
				deptName = roleDepartments[0].DepartmentName
				deptID = &roleDepartments[0].DepartmentID
			}

			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID:    emp.CompanyID,
				UserID:       emp.UserID,
				EmployeeID:   emp.EmployeeID,
				RoleName:     role.RoleName,
				RoleLevel:    role.RoleLevel,
				DepartmentID: deptID,
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
			// Get role departments
			roleDepartments, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepartments) > 0 {
				deptName = roleDepartments[0].DepartmentName
				deptID = &roleDepartments[0].DepartmentID
			}

			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID:    emp.CompanyID,
				UserID:       emp.UserID,
				EmployeeID:   emp.EmployeeID,
				RoleName:     role.RoleName,
				RoleLevel:    role.RoleLevel,
				DepartmentID: deptID,
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

        // ✅ VALIDATE reports_to user is in the same company
        if assignment.ReportsTo != uuid.Nil {
            if err := s.validateReportsTo(ctx, companyID, &assignment.ReportsTo); err != nil {
                results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
                continue
            }
            emp.ReportsTo = &assignment.ReportsTo
        }

        emp.RoleID = assignment.RoleID
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

	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to reactivate company")
	}

	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
		return fmt.Errorf("failed to reactivate company: %w", err)
	}

	s.logger.Info("Company reactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("reactivated_by", reactivatedBy.String()))

	return nil
}

func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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

type CreateRoleRequest struct {
	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
	RoleName      string      `json:"role_name" validate:"required"`
	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
	Description   string      `json:"description"`
	DepartmentIDs []uuid.UUID `json:"department_ids"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
	CreatedBy     uuid.UUID   `json:"created_by" validate:"required"`
}


// GetPermissionsByDepartmentModules gets permissions filtered by department modules
func (s *CompanyService) GetPermissionsByDepartmentModules(ctx context.Context, departmentIDs []uuid.UUID) ([]*models.Permission, error) {
    if len(departmentIDs) == 0 {
        return []*models.Permission{}, nil
    }

    // Get system department IDs for the departments
    var systemDeptIDs []uuid.UUID
    for _, deptID := range departmentIDs {
        dept, err := s.companyRepo.GetDepartment(ctx, deptID)
        if err != nil {
            continue
        }
        if dept.SystemDepartmentID != nil {
            systemDeptIDs = append(systemDeptIDs, *dept.SystemDepartmentID)
        }
    }

    if len(systemDeptIDs) == 0 {
        return []*models.Permission{}, nil
    }

    // Get permissions for these system departments
    return s.companyRepo.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, "", "", "")
}


// ValidatePermissionDepartmentCompatibility checks if permissions are compatible with departments
func (s *CompanyService) ValidatePermissionDepartmentCompatibility(ctx context.Context, departmentIDs []uuid.UUID, permissionIDs []uuid.UUID) (bool, string, error) {
    if len(departmentIDs) == 0 || len(permissionIDs) == 0 {
        return true, "", nil
    }

    // Get all permissions
    allPerms, err := s.companyRepo.GetAllPermissions(ctx)
    if err != nil {
        return false, "", fmt.Errorf("failed to get permissions: %w", err)
    }

    permMap := make(map[uuid.UUID]*models.Permission)
    for _, perm := range allPerms {
        permMap[perm.PermissionID] = perm
    }

    // Get department modules
    departmentModules := make(map[string]bool)
    for _, deptID := range departmentIDs {
        dept, err := s.companyRepo.GetDepartment(ctx, deptID)
        if err != nil {
            return false, "", fmt.Errorf("department not found: %s", deptID)
        }
        if dept.SystemDepartmentID != nil {
            systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
            if err == nil {
                departmentModules[systemDept.ModuleCode] = true
            }
        }
    }

    // Check each permission
    for _, permID := range permissionIDs {
        perm, exists := permMap[permID]
        if !exists {
            return false, "", fmt.Errorf("permission not found: %s", permID)
        }

        if !departmentModules[perm.Module] {
            // Build error message
            var deptNames []string
            for _, deptID := range departmentIDs {
                dept, _ := s.companyRepo.GetDepartment(ctx, deptID)
                if dept != nil {
                    deptNames = append(deptNames, dept.DepartmentName)
                }
            }

            var moduleNames []string
            for module := range departmentModules {
                if systemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, module); err == nil {
                    moduleNames = append(moduleNames, systemDept.Name)
                }
            }

            errorMsg := fmt.Sprintf(
                "Permission '%s' (module: %s) is incompatible with departments [%s]. "+
                "Allowed modules for these departments: [%s]",
                perm.PermissionName, perm.Module,
                strings.Join(deptNames, ", "),
                strings.Join(moduleNames, ", "))

            return false, errorMsg, nil
        }
    }

    return true, "", nil
}
func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
    hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return nil, fmt.Errorf("user lacks permission to create roles")
    }

    currentUserID, ok := ctx.Value("user_id").(string)
    if !ok {
        return nil, fmt.Errorf("user ID not found in context")
    }
    userID, err := uuid.Parse(currentUserID)
    if err != nil {
        return nil, fmt.Errorf("invalid user ID in context")
    }

    // Validate departments exist and belong to company
    for _, deptID := range req.DepartmentIDs {
        dept, err := s.companyRepo.GetDepartment(ctx, deptID)
        if err != nil {
            return nil, fmt.Errorf("department not found: %s", deptID)
        }
        if dept.CompanyID != req.CompanyID {
            return nil, fmt.Errorf("department %s does not belong to company", deptID)
        }
    }

    // Get all permissions with their details
    allPerms, err := s.companyRepo.GetAllPermissions(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get all permissions: %w", err)
    }

    permMap := make(map[uuid.UUID]*models.Permission)
    for _, perm := range allPerms {
        permMap[perm.PermissionID] = perm
    }

    // Get department modules
    departmentModules := make(map[string]bool)
    for _, deptID := range req.DepartmentIDs {
        dept, _ := s.companyRepo.GetDepartment(ctx, deptID)
        if dept.SystemDepartmentID != nil {
            systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
            if err == nil {
                departmentModules[systemDept.ModuleCode] = true
            }
        }
    }

    // Validate each permission belongs to one of the department's modules
    for _, permID := range req.PermissionIDs {
        perm, exists := permMap[permID]
        if !exists {
            return nil, fmt.Errorf("permission not found: %s", permID)
        }

        // Check if permission's module matches any department's module
        if !departmentModules[perm.Module] {
            // Get department names for error message
            var deptNames []string
            for _, deptID := range req.DepartmentIDs {
                dept, _ := s.companyRepo.GetDepartment(ctx, deptID)
                if dept != nil {
                    deptNames = append(deptNames, dept.DepartmentName)
                }
            }
            
            // Get module names for better error message
            var moduleNames []string
            for module := range departmentModules {
                if systemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, module); err == nil {
                    moduleNames = append(moduleNames, systemDept.Name)
                }
            }
            
            return nil, fmt.Errorf(
                "permission '%s' (module: %s) cannot be assigned to departments [%s]. "+
                "Permissions must match the department modules [%s]",
                perm.PermissionName, perm.Module,
                strings.Join(deptNames, ", "),
                strings.Join(moduleNames, ", "))
        }

        // Check if user has the permission they're trying to assign
        userPermissions, err := s.GetUserPermissions(ctx, userID)
        if err != nil {
            return nil, fmt.Errorf("failed to get user permissions: %w", err)
        }

        userHasPermission := false
        for _, userPerm := range userPermissions {
            if userPerm.PermissionID == permID {
                userHasPermission = true
                break
            }
        }

        if !userHasPermission {
            return nil, fmt.Errorf("user cannot assign permission '%s' that they don't possess", perm.PermissionName)
        }
    }

    if req.RoleLevel < 1 || req.RoleLevel > 1000 {
        return nil, fmt.Errorf("role level must be between 1 and 1000")
    }

    existingRoles, _, err := s.companyRepo.GetRolesByCompany(ctx, req.CompanyID, 1000, 0)
    if err == nil {
        for _, role := range existingRoles {
            if strings.EqualFold(role.RoleName, req.RoleName) {
                return nil, fmt.Errorf("role with name '%s' already exists in this company", req.RoleName)
            }
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
        if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
            return nil, fmt.Errorf("role with name '%s' already exists in this company", req.RoleName)
        }
        return nil, fmt.Errorf("failed to create role: %w", err)
    }

    if len(req.PermissionIDs) > 0 {
        if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy); err != nil {
            s.logger.Warn("Failed to assign permissions to new role",
                util.String("role_id", role.RoleID.String()),
                util.ErrorField(err))
        }
    }

    // Log department modules for debugging
    var moduleNames []string
    for module := range departmentModules {
        if systemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, module); err == nil {
            moduleNames = append(moduleNames, systemDept.Name)
        }
    }

    s.logger.Info("Role created successfully with validated permissions",
        util.String("company_id", req.CompanyID.String()),
        util.String("role_id", role.RoleID.String()),
        util.String("role_name", req.RoleName),
        util.Int("role_level", req.RoleLevel),
        util.Int("department_count", len(req.DepartmentIDs)),
        util.Int("permission_count", len(req.PermissionIDs)),
        util.Strings("department_modules", moduleNames),
        util.String("created_by", req.CreatedBy.String()))

    return role, nil
}
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

	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
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
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
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

	// Check if any employees with this role would be affected
	if len(employees) > 0 {
		s.logger.Warn("Role removal would affect employees",
			util.String("role_id", roleID.String()),
			util.Int("affected_employees", len(employees)))
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

func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	return s.companyRepo.GetRole(ctx, roleID)
}

func (s *CompanyService) CheckPermissionFromContext(ctx context.Context, permissionName string) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		s.logger.Debug("CheckPermissionFromContext: session type not found")
		return false, fmt.Errorf("session type not found in context")
	}

	if sessionType == "admin" {
		s.logger.Debug("CheckPermissionFromContext: admin session - full access granted",
			util.String("permission", permissionName))
		return true, nil
	}

	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		s.logger.Debug("CheckPermissionFromContext: permission mask not found in context",
			util.String("session_type", sessionType))
		return false, fmt.Errorf("permission mask not found in context")
	}

	hasPermission := rbac.HasPermission(permissionMask, permissionName)

	s.logger.Debug("CheckPermissionFromContext: bitmask permission check",
		util.String("permission", permissionName),
		util.String("session_type", sessionType),
		util.Bool("granted", hasPermission),
		util.Any("mask", permissionMask))

	return hasPermission, nil
}

func (s *CompanyService) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
	s.logger.Debug("Fetching departments for company",
		util.String("company_id", companyID.String()),
		util.Int("limit", limit),
		util.Int("offset", offset))

	departments, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		s.logger.Error("Failed to get departments from repository",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, err
	}

	s.logger.Debug("Successfully retrieved departments",
		util.String("company_id", companyID.String()),
		util.Int("count", len(departments)),
		util.Int("total", total))

	return departments, total, nil
}

func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
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
		util.String("new_name", newName))

	return nil
}

func (s *CompanyService) GetPermissionsByCompanyDepartments(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error) {
	departments, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get company departments: %w", err)
	}

	systemDeptIDs := make([]uuid.UUID, 0)
	for _, dept := range departments {
		if dept.SystemDepartmentID != nil {
			systemDeptIDs = append(systemDeptIDs, *dept.SystemDepartmentID)
		}
	}

	adminSystemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, "administration")
	if err == nil {
		systemDeptIDs = append(systemDeptIDs, adminSystemDept.SystemDepartmentID)
	}

	if len(systemDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}

	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, module, category, tier)
}

func (s *CompanyService) ValidatePermissionAssignment(ctx context.Context, assignerID uuid.UUID, permissionsToAssign []string) (bool, error) {
	assignerPermissions, err := s.GetUserPermissions(ctx, assignerID)
	if err != nil {
		return false, err
	}

	assignerPermMap := make(map[string]bool)
	for _, perm := range assignerPermissions {
		assignerPermMap[perm.PermissionName] = true
	}

	for _, permToAssign := range permissionsToAssign {
		if !assignerPermMap[permToAssign] {
			return false, nil
		}
	}

	return true, nil
}

func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
    hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
    if err != nil {
        return fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return fmt.Errorf("user lacks permission to add managers")
    }

    company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }
    if !company.IsActive {
        return fmt.Errorf("company is not active")
    }

    role, err := s.companyRepo.GetRole(ctx, req.RoleID)
    if err != nil {
        return fmt.Errorf("role not found: %w", err)
    }

    if role.RoleLevel < 500 {
        return fmt.Errorf("role level must be 500 or higher for managers")
    }

    roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get role departments: %w", err)
    }
    if len(roleDepartments) == 0 {
        return fmt.Errorf("role is not assigned to any department")
    }

    // ✅ VALIDATE reports_to user is in the same company
    if err := s.validateReportsTo(ctx, req.CompanyID, req.ReportsTo); err != nil {
        return fmt.Errorf("reports_to validation failed: %w", err)
    }

    user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
            Username:          req.Username,
            FullName:          req.FullName,
            PhoneNumber:       req.PhoneNumber,
            DeviceID:          "company-assigned",
            DeviceFingerprint: "company-assigned",
            DataRegion:        company.DataRegion,
            ConsentAgreed:     true,
            ConsentVersion:    "v1.0",
            KYCStatus:         models.KYCStatusPending,
            KYCLevel:          models.KYCLevelBasic,
        })
        if err != nil {
            return fmt.Errorf("failed to create user: %w", err)
        }
    }

    reportsTo := req.ReportsTo
    if reportsTo == nil {
        if len(roleDepartments) > 0 && roleDepartments[0].DepartmentHead != nil {
            reportsTo = roleDepartments[0].DepartmentHead
            // ✅ VALIDATE default reports_to (department head)
            if err := s.validateReportsTo(ctx, req.CompanyID, reportsTo); err != nil {
                s.logger.Warn("Default department head is not a valid employee, falling back to owner",
                    util.String("company_id", req.CompanyID.String()),
                    util.String("department_head", reportsTo.String()),
                    util.ErrorField(err))
                reportsTo = &company.OwnerUserID
            }
        } else {
            reportsTo = &company.OwnerUserID
        }
    }

    existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
    if existingEmp != nil && existingEmp.IsActive {
        return fmt.Errorf("user is already an active employee in this company")
    }

    employeeID := req.EmployeeID
    if employeeID == "" {
        employeeID = fmt.Sprintf("MGR-%s", uuid.New().String()[:8])
    }

    emp := &models.CompanyEmployee{
        CompanyID:  req.CompanyID,
        UserID:     user.UserID,
        EmployeeID: employeeID,
        RoleID:     req.RoleID,
        HireDate:   time.Now().UTC(),
        IsActive:   true,
        ReportsTo:  reportsTo,
        CreatedAt:  time.Now().UTC(),
        UpdatedAt:  time.Now().UTC(),
    }

    if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
        return fmt.Errorf("failed to add manager as employee: %w", err)
    }

    s.logger.Info("Manager added successfully",
        util.String("company_id", req.CompanyID.String()),
        util.String("user_id", user.UserID.String()),
        util.String("role_id", role.RoleID.String()),
        util.String("role_name", role.RoleName),
        util.Int("role_level", role.RoleLevel))

    return nil
}
func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
    start := time.Now()

    hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
    if err != nil {
        return fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return fmt.Errorf("user lacks permission to add employees")
    }

    company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }
    if !company.IsActive {
        return fmt.Errorf("company is not active")
    }

    activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
    if err != nil {
        return fmt.Errorf("failed to get active employee count: %w", err)
    }
    if activeCount >= company.MaxEmployees {
        return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
    }

    role, err := s.companyRepo.GetRole(ctx, req.RoleID)
    if err != nil {
        return fmt.Errorf("role not found: %w", err)
    }
    if role.CompanyID != req.CompanyID {
        return fmt.Errorf("role does not belong to company")
    }

    roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get role departments: %w", err)
    }
    if len(roleDepartments) == 0 {
        return fmt.Errorf("role is not assigned to any department")
    }

    // ✅ VALIDATE reports_to user is in the same company
    if err := s.validateReportsTo(ctx, req.CompanyID, req.ReportsTo); err != nil {
        return fmt.Errorf("reports_to validation failed: %w", err)
    }

    user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
            Username:          req.Username,
            FullName:          req.FullName,
            PhoneNumber:       req.PhoneNumber,
            DeviceID:          "company-assigned",
            DeviceFingerprint: "company-assigned",
            DataRegion:        company.DataRegion,
            ConsentAgreed:     true,
            ConsentVersion:    "v1.0",
            KYCStatus:         models.KYCStatusPending,
            KYCLevel:          models.KYCLevelBasic,
        })
        if err != nil {
            return fmt.Errorf("failed to create user: %w", err)
        }
    }

    existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
    if existingEmp != nil && existingEmp.IsActive {
        return fmt.Errorf("user is already an active employee in this company")
    }

    reportsTo := req.ReportsTo
    if reportsTo == nil {
        if len(roleDepartments) > 0 && roleDepartments[0].DepartmentHead != nil {
            reportsTo = roleDepartments[0].DepartmentHead
            // ✅ VALIDATE default reports_to (department head)
            if err := s.validateReportsTo(ctx, req.CompanyID, reportsTo); err != nil {
                s.logger.Warn("Default department head is not a valid employee, falling back to owner",
                    util.String("company_id", req.CompanyID.String()),
                    util.String("department_head", reportsTo.String()),
                    util.ErrorField(err))
                reportsTo = &company.OwnerUserID
            }
        } else {
            reportsTo = &company.OwnerUserID
        }
    }

    emp := &models.CompanyEmployee{
        CompanyID:  req.CompanyID,
        UserID:     user.UserID,
        EmployeeID: req.EmployeeID,
        RoleID:     req.RoleID,
        HireDate:   time.Now().UTC(),
        IsActive:   true,
        ReportsTo:  reportsTo,
        CreatedAt:  time.Now().UTC(),
        UpdatedAt:  time.Now().UTC(),
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
        util.Duration("duration", time.Since(start)))

    return nil
}
type SearchCompaniesRequest = models.CompanySearchRequest
type SearchCompaniesResponse = models.CompanySearchResponse
type CompanySearchResult = models.CompanySearchResult

func (s *CompanyService) SearchCompanies(
    ctx context.Context,
    req *models.CompanySearchRequest,
) (*models.CompanySearchResponse, error) {

    start := time.Now()

    hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return nil, fmt.Errorf("insufficient permissions to search companies")
    }

    searchType := req.SearchType
    if searchType == "all" {
        if len(req.Query) < 3 {
            searchType = "autocomplete"
        } else {
            searchType = "fulltext"
        }
    }

    companies, total, err := s.companyRepo.SearchCompaniesByName(
        ctx,
        req.Query,
        searchType,
        req.Filters,
        req.Limit,
        req.Offset,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to search companies: %w", err)
    }

	results := make([]*models.CompanySearchResult, len(companies))
	for i, company := range companies {
		results[i] = &models.CompanySearchResult{
			CompanyID:          company.CompanyID,
			CompanyName:        company.CompanyName,
			OwnerUserID:        company.OwnerUserID,
			SubscriptionTier:   company.SubscriptionTier,
			SubscriptionStatus: company.SubscriptionStatus,
			MaxEmployees:       company.MaxEmployees,
			IsActive:           company.IsActive,
			DataRegion:         company.DataRegion,
			CreatedAt:          company.CreatedAt,
			RelevanceScore:     1.0 - (float64(i) * 0.01),
			MatchType:          searchType,
		}
	}
    page := (req.Offset / req.Limit) + 1
    hasMore := req.Offset+req.Limit < total

    resp := &models.CompanySearchResponse{
        Companies: results,
        Total:     total,
        Page:      page,
        PageSize:  req.Limit,
        HasMore:   hasMore,
    }

    s.logger.Info("Company search completed",
        util.String("query", req.Query),
        util.String("search_type", searchType),
        util.Int("results", len(results)),
        util.Int("total", total),
        util.Duration("duration", time.Since(start)),
    )

    return resp, nil
}

func (s *CompanyService) SearchCompaniesByOwner(
    ctx context.Context,
    ownerID uuid.UUID,
    query string,
    isActive *bool,
    limit int,
    offset int,
) (*models.CompanySearchResponse, error) {

    start := time.Now()

    hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }

    if !hasPermission {
        currentUserIDStr, ok := ctx.Value("user_id").(string)
        if !ok {
            return nil, fmt.Errorf("user ID missing in context")
        }
        currentUserID, _ := uuid.Parse(currentUserIDStr)
        if currentUserID != ownerID {
            return nil, fmt.Errorf("can only search your own companies")
        }
    }

    companies, total, err := s.companyRepo.SearchCompaniesByOwnerAndName(
        ctx, ownerID, query, isActive, limit, offset,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to search owner companies: %w", err)
    }

    results := make([]*models.CompanySearchResult, len(companies))
    for i, company := range companies {
        matchType := "owner_search"
        if query != "" {
            if len(query) < 3 {
                matchType = "autocomplete"
            } else {
                matchType = "fulltext"
            }
        }

        results[i] = &models.CompanySearchResult{
            CompanyID:          company.CompanyID,
            CompanyName:        company.CompanyName,
            OwnerUserID:        company.OwnerUserID,
            SubscriptionTier:   company.SubscriptionTier,
            SubscriptionStatus: company.SubscriptionStatus,
            MaxEmployees:       company.MaxEmployees,
            IsActive:           company.IsActive,
            DataRegion:         company.DataRegion,
            CreatedAt:          company.CreatedAt,
            RelevanceScore:     1.0 - (float64(i) * 0.01),
            MatchType:          matchType,
        }
    }

    page := (offset / limit) + 1
    hasMore := offset+limit < total

    resp := &models.CompanySearchResponse{
        Companies: results,
        Total:     total,
        Page:      page,
        PageSize:  limit,
        HasMore:   hasMore,
    }

    s.logger.Info("Owner company search completed",
        util.String("owner_id", ownerID.String()),
        util.String("query", query),
        util.Int("results", len(results)),
        util.Duration("duration", time.Since(start)),
    )

    return resp, nil
}

func (s *CompanyService) GetCompanySuggestions(
    ctx context.Context,
    prefix string,
    limit int,
) ([]string, error) {

    hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return nil, fmt.Errorf("insufficient permissions")
    }

    if len(prefix) < 2 {
        return []string{}, nil
    }

    suggestions, err := s.companyRepo.GetCompanySuggestions(ctx, prefix, limit)
    if err != nil {
        return nil, fmt.Errorf("failed to get suggestions: %w", err)
    }

    return suggestions, nil
}

func (s *CompanyService) GetCompanySearchAnalytics(
    ctx context.Context,
) (map[string]interface{}, error) {

    hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.audit.logs.view")
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !hasPermission {
        return nil, fmt.Errorf("insufficient permissions")
    }

    stats, err := s.companyRepo.GetCompanySearchStats(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get search stats: %w", err)
    }

    companyMetrics, err := s.companyRepo.GetCompanyStats(ctx, uuid.Nil)
    if err == nil {
        stats["company_metrics"] = companyMetrics
    }

    return stats, nil
}

func (s *CompanyService) BenchmarkCompanySearch(
    ctx context.Context,
    testQueries []string,
    iterations int,
) (map[string]interface{}, error) {

    if iterations <= 0 || iterations > 100 {
        iterations = 10
    }

    results := make(map[string]interface{})

    queryTimes := map[string][]time.Duration{}

    for _, q := range testQueries {
        for i := 0; i < iterations; i++ {
            start := time.Now()
            _, _, err := s.companyRepo.SearchCompaniesByName(ctx, q, "fulltext", nil, 10, 0)

            if err == nil {
                queryTimes[q] = append(queryTimes[q], time.Since(start))
            }
        }
    }

    stats := map[string]map[string]interface{}{}
    for query, durations := range queryTimes {
        if len(durations) == 0 {
            continue
        }

        var total time.Duration
        min, max := durations[0], durations[0]

        for _, d := range durations {
            total += d
            if d < min {
                min = d
            }
            if d > max {
                max = d
            }
        }

        avg := total / time.Duration(len(durations))

        stats[query] = map[string]interface{}{
            "iterations": len(durations),
            "avg_ms":     avg.Milliseconds(),
            "min_ms":     min.Milliseconds(),
            "max_ms":     max.Milliseconds(),
            "total_ms":   total.Milliseconds(),
        }
    }

    results["benchmark_results"] = stats
    results["test_queries"] = testQueries
    results["iterations"] = iterations
    results["timestamp"] = time.Now().UTC()

    return results, nil
}
func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
    start := time.Now()

    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        return nil, fmt.Errorf("only admin users can create departments")
    }

    adminID, ok := ctx.Value("user_id").(string)
    if !ok {
        return nil, fmt.Errorf("admin ID not found in context")
    }
    adminIDParsed, err := uuid.Parse(adminID)
    if err != nil {
        return nil, fmt.Errorf("invalid admin ID in context")
    }

    company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
    if err != nil {
        return nil, fmt.Errorf("company not found: %w", err)
    }
    if !company.IsActive {
        return nil, fmt.Errorf("company is not active")
    }

    systemDept, err := s.companyRepo.GetSystemDepartment(ctx, req.SystemDepartmentID)
    if err != nil {
        return nil, fmt.Errorf("system department not found: %w", err)
    }

    departments, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, req.CompanyID, 1000, 0)
    if err != nil {
        return nil, fmt.Errorf("failed to check existing departments: %w", err)
    }

    for _, dept := range departments {
        if strings.EqualFold(dept.DepartmentName, req.DepartmentName) {
            return nil, fmt.Errorf("department with name '%s' already exists in this company", req.DepartmentName)
        }
    }

    for _, dept := range departments {
        if dept.SystemDepartmentID != nil && *dept.SystemDepartmentID == req.SystemDepartmentID {
            return nil, fmt.Errorf("system department '%s' is already assigned to another department in this company", systemDept.Name)
        }
    }

    // ✅ VALIDATE department_head is an employee of the same company
    if err := s.validateDepartmentHead(ctx, req.CompanyID, req.DepartmentHead); err != nil {
        return nil, fmt.Errorf("department head validation failed: %w", err)
    }

    if req.ParentDepartmentID != nil {
        parentDept, err := s.companyRepo.GetDepartment(ctx, *req.ParentDepartmentID)
        if err != nil {
            return nil, fmt.Errorf("parent department not found: %w", err)
        }
        if parentDept.CompanyID != req.CompanyID {
            return nil, fmt.Errorf("parent department does not belong to this company")
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
        if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
            return nil, fmt.Errorf("department with name '%s' already exists in this company", req.DepartmentName)
        }
        return nil, fmt.Errorf("failed to create department: %w", err)
    }

    ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, req.CompanyID, 1000)
    if err == nil && ownerRole != nil {
        if err := s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID); err != nil {
            s.logger.Warn("Failed to auto-assign department to owner role",
                util.ErrorField(err),
                util.String("company_id", req.CompanyID.String()),
                util.String("department_id", department.DepartmentID.String()),
                util.String("owner_role_id", ownerRole.RoleID.String()))
        }
    }

    s.logger.Info("Department created successfully by admin",
        util.String("company_id", req.CompanyID.String()),
        util.String("company_name", company.CompanyName),
        util.String("department_id", department.DepartmentID.String()),
        util.String("department_name", req.DepartmentName),
        util.String("system_department", systemDept.Name),
        util.String("system_module", systemDept.ModuleCode),
        util.String("created_by", adminIDParsed.String()),
        util.Duration("duration", time.Since(start)))

    return department, nil
}
func (s *CompanyService) GetCompanyContextForCompany(ctx context.Context, userID, companyID uuid.UUID) (*CompanyContext, error) {
    employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
    if err != nil {
        return nil, fmt.Errorf("employee not found in company: %w", err)
    }

    if !employee.IsActive {
        return nil, fmt.Errorf("employee is not active in this company")
    }

    company, err := s.companyRepo.GetCompany(ctx, companyID)
    if err != nil {
        return nil, fmt.Errorf("company not found: %w", err)
    }

    if company.SubscriptionEndDate != nil && company.SubscriptionEndDate.Before(time.Now()) {
        return nil, fmt.Errorf("subscription status: company subscription has expired")
    }

    if !company.IsActive {
        return nil, fmt.Errorf("company is not active")
    }

    role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
    if err != nil {
        return nil, fmt.Errorf("role not found: %w", err)
    }

    // Get role departments
    roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
    if err != nil {
        s.logger.Warn("Failed to get role departments", util.ErrorField(err))
    }

    var departmentID, departmentName, systemModule string
    if len(roleDepartments) > 0 {
        dept := roleDepartments[0]
        departmentID = dept.DepartmentID.String()
        departmentName = dept.DepartmentName
        if dept.SystemDepartmentID != nil {
            systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
            if err == nil {
                systemModule = systemDept.ModuleCode
            }
        }
    }

    permissions, err := s.companyRepo.GetUserPermissions(ctx, companyID, userID)
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
        EmployeeID:       employee.EmployeeID,
        RoleID:           employee.RoleID.String(),
        RoleLevel:        role.RoleLevel,
        RoleName:         role.RoleName,
        DepartmentID:     departmentID,
        DepartmentName:   departmentName,
        SystemModule:     systemModule,
        Permissions:      permStrings,
        SubscriptionTier: company.SubscriptionTier,
        IsOwner:          company.OwnerUserID == userID,
        IsManager:        role.RoleLevel <= 200,
    }, nil
}

func (s *CompanyService) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
    return s.companyRepo.GetEmployeesByUser(ctx, userID)
}

func (s *CompanyService) GetCompaniesByEmployeePhone(ctx context.Context, employeePhone string) ([]*models.Company, error) {
    start := time.Now()

    user, err := s.userService.GetUserByPhone(ctx, employeePhone)
    if err != nil {
        return nil, fmt.Errorf("failed to get user by phone: %w", err)
    }

    employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
    if err != nil {
        return nil, fmt.Errorf("failed to get employee records: %w", err)
    }

    var companies []*models.Company
    seenCompanies := make(map[uuid.UUID]bool)

    for _, emp := range employees {
        if !emp.IsActive || seenCompanies[emp.CompanyID] {
            continue
        }

        company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
        if err != nil {
            s.logger.Warn("Failed to get company",
                util.String("company_id", emp.CompanyID.String()),
                util.ErrorField(err))
            continue
        }

        if company.IsActive {
            companies = append(companies, company)
            seenCompanies[emp.CompanyID] = true
        }
    }

    s.logger.Debug("GetCompaniesByEmployeePhone completed",
        util.String("phone", employeePhone),
        util.String("user_id", user.UserID.String()),
        util.Int("total_employee_records", len(employees)),
        util.Int("active_companies", len(companies)),
        util.Duration("duration", time.Since(start)))

    if len(companies) == 0 {
        return nil, fmt.Errorf("no active companies found for employee with phone: %s", employeePhone)
    }

    return companies, nil
}

func (s *CompanyService) ValidateUserAccessToDepartment(ctx context.Context, companyID, userID, departmentID uuid.UUID) (bool, error) {
    departments, _, err := s.ListDepartments(ctx, companyID, 1000, 0, false)
    if err != nil {
        return false, err
    }

    for _, dept := range departments {
        if dept.DepartmentID == departmentID {
            return true, nil
        }
    }
    return false, nil
}

func (s *CompanyService) ValidateUserAccessToPermission(ctx context.Context, userID, permissionID uuid.UUID) (bool, error) {
    userPermissions, err := s.GetUserPermissions(ctx, userID)
    if err != nil {
        return false, err
    }

    for _, perm := range userPermissions {
        if perm.PermissionID == permissionID {
            return true, nil
        }
    }
    return false, nil
}

func (s *CompanyService) ValidatePermissionsExist(ctx context.Context, permissionIDs []uuid.UUID) (bool, error) {
    allPerms, err := s.GetAllPermissions(ctx, "", "", "")
    if err != nil {
        return false, err
    }

    permMap := make(map[uuid.UUID]bool)
    for _, perm := range allPerms {
        permMap[perm.PermissionID] = true
    }

    for _, permID := range permissionIDs {
        if !permMap[permID] {
            return false, fmt.Errorf("permission not found: %s", permID)
        }
    }

    return true, nil
}

func (s *CompanyService) ValidatePermissionIDsExist(ctx context.Context, permissionIDs []uuid.UUID) (bool, map[uuid.UUID]*models.Permission, error) {
    allPerms, err := s.GetAllPermissions(ctx, "", "", "")
    if err != nil {
        return false, nil, err
    }

    permMap := make(map[uuid.UUID]*models.Permission)
    for _, perm := range allPerms {
        permMap[perm.PermissionID] = perm
    }

    missingPerms := make([]uuid.UUID, 0)
    for _, permID := range permissionIDs {
        if _, exists := permMap[permID]; !exists {
            missingPerms = append(missingPerms, permID)
        }
    }

    if len(missingPerms) > 0 {
        return false, nil, fmt.Errorf("permissions not found: %v", missingPerms)
    }

    return true, permMap, nil
}

// DeactivateDepartment deactivates a department (admin only) - SOFT DELETE
func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
    start := time.Now()

    // Check if user is admin (from session_type in context)
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        return fmt.Errorf("only admin users can deactivate departments")
    }

    // Get the department
    department, err := s.companyRepo.GetDepartment(ctx, departmentID)
    if err != nil {
        return fmt.Errorf("department not found: %w", err)
    }

    // Check if department is already inactive
    if !department.IsActive {
        return fmt.Errorf("department is already deactivated")
    }

    // Check if there are active employees in roles assigned to this department
    roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0) // FIXED: Added blank identifier for count
    if err != nil {
        s.logger.Warn("Failed to get roles for department", 
            util.String("department_id", departmentID.String()),
            util.ErrorField(err))
    }

    // Check if any active employees have roles assigned to this department
    for _, role := range roles {
        roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
        if err != nil {
            continue
        }
        
        // Check if this role is assigned to the department we're deactivating
        for _, dept := range roleDepts {
            if dept.DepartmentID == departmentID {
                // Check if any active employees have this role
                employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0) // Also fixed here if needed
                if err == nil && len(employees) > 0 {
                    return fmt.Errorf("cannot deactivate department that has active employees assigned to roles")
                }
                break
            }
        }
    }

    // Soft delete: Only set is_active = false, keep role-department mappings
    department.IsActive = false
    department.UpdatedAt = time.Now().UTC()
    
    if err := s.companyRepo.UpdateDepartment(ctx, department); err != nil {
        return fmt.Errorf("failed to deactivate department: %w", err)
    }

    s.logger.Info("Department deactivated successfully by admin",
        util.String("department_id", departmentID.String()),
        util.String("company_id", department.CompanyID.String()),
        util.String("department_name", department.DepartmentName),
        util.String("admin_id", adminID.String()),
        util.Duration("duration", time.Since(start)))

    return nil
}


// DeleteDepartment permanently deletes a department and its role mappings (admin only)
func (s *CompanyService) DeleteDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
    start := time.Now()

    // Check if user is admin (from session_type in context)
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        return fmt.Errorf("only admin users can delete departments")
    }

    // Get the department
    department, err := s.companyRepo.GetDepartment(ctx, departmentID)
    if err != nil {
        return fmt.Errorf("department not found: %w", err)
    }

    // Check if there are active employees in roles assigned to this department
    roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0) // FIXED: Added blank identifier for count
    if err != nil {
        return fmt.Errorf("failed to get roles for department: %w", err)
    }

    // Check if any active employees have roles assigned to this department
    for _, role := range roles {
        roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
        if err != nil {
            continue
        }
        
        // Check if this role is assigned to the department we're deleting
        for _, dept := range roleDepts {
            if dept.DepartmentID == departmentID {
                // Check if any active employees have this role
                employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0) // Also fixed here
                if err == nil && len(employees) > 0 {
                    return fmt.Errorf("cannot delete department that has active employees assigned to roles")
                }
                break
            }
        }
    }

    // Hard delete: Remove all role-department mappings first
    if err := s.companyRepo.RemoveAllRoleDepartments(ctx, departmentID); err != nil {
        s.logger.Warn("Failed to remove role-department mappings",
            util.String("department_id", departmentID.String()),
            util.ErrorField(err))
        // Continue with deletion even if this fails
    }

    // Delete the department
    if err := s.companyRepo.DeleteDepartment(ctx, departmentID); err != nil {
        return fmt.Errorf("failed to delete department: %w", err)
    }

    s.logger.Info("Department deleted successfully by admin",
        util.String("department_id", departmentID.String()),
        util.String("company_id", department.CompanyID.String()),
        util.String("department_name", department.DepartmentName),
        util.String("admin_id", adminID.String()),
        util.Duration("duration", time.Since(start)))

    return nil
}

// Add to CompanyService
func (s *CompanyService) validateReportsTo(ctx context.Context, companyID uuid.UUID, userID *uuid.UUID) error {
    if userID == nil {
        return nil
    }
    
    _, err := s.companyRepo.GetEmployee(ctx, companyID, *userID)
    if err != nil {
        return fmt.Errorf("reports_to user %s is not an employee of company %s", *userID, companyID)
    }
    
    return nil
}

func (s *CompanyService) validateDepartmentHead(ctx context.Context, companyID uuid.UUID, userID *uuid.UUID) error {
    if userID == nil {
        return nil
    }
    
    _, err := s.companyRepo.GetEmployee(ctx, companyID, *userID)
    if err != nil {
        return fmt.Errorf("department_head %s is not an employee of company %s", *userID, companyID)
    }
    
    return nil
}
// // internal/service/company_service.go
// package service

// import (
// 	"context"
// 	"fmt"
// 	"time"
// 	"strings"
// 	"auth-service/internal/models"
// 	"auth-service/internal/rbac"
// 	"auth-service/internal/repository/postgres"
// 	"auth-service/internal/util"

// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// type CompanyService struct {
// 	companyRepo postgres.CompanyRepository
// 	userService *UserService
// 	logger      *zap.Logger
// }

// type BulkAssignment struct {
// 	UserID       uuid.UUID `json:"user_id"`
// 	RoleID       uuid.UUID `json:"role_id"`
// 	DepartmentID uuid.UUID `json:"department_id,omitempty"`
// 	ReportsTo    uuid.UUID `json:"reports_to,omitempty"`
// }



// func NewCompanyService(
// 	companyRepo postgres.CompanyRepository,
// 	userService *UserService,
// 	logger *zap.Logger,
// ) *CompanyService {
// 	return &CompanyService{
// 		companyRepo: companyRepo,
// 		userService: userService,
// 		logger:      logger,
// 	}
// }

// // ============================================================================
// // PHONE NUMBER BASED COMPANY METHODS
// // ============================================================================

// // // GetCompanyByPhone gets company details by owner's phone number
// // func (s *CompanyService) GetCompanyByPhone(ctx context.Context, ownerPhone string) (*models.Company, error) {
// // 	// Get user by phone number
// // 	user, err := s.userService.GetUserByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to get user by phone: %w", err)
// // 	}

// // 	// Get companies owned by this user
// // 	companies, err := s.companyRepo.GetCompaniesByOwner(ctx, user.UserID)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to get companies by owner: %w", err)
// // 	}

// // 	if len(companies) == 0 {
// // 		return nil, fmt.Errorf("no companies found for phone: %s", ownerPhone)
// // 	}

// // 	// Return the first company (assuming one user owns one company for now)
// // 	// You can modify this to return all companies if needed
// // 	return companies[0], nil
// // }

// // // GetCompanyByEmployeePhone gets company details by employee's phone number
// // func (s *CompanyService) GetCompanyByEmployeePhone(ctx context.Context, employeePhone string) (*models.Company, error) {
// // 	// Get user by phone number
// // 	user, err := s.userService.GetUserByPhone(ctx, employeePhone)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to get user by phone: %w", err)
// // 	}

// // 	// Get employee records for this user
// // 	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to get employee records: %w", err)
// // 	}

// // 	if len(employees) == 0 {
// // 		return nil, fmt.Errorf("user is not an employee in any company")
// // 	}

// // 	// Get the company from the first active employee record
// // 	for _, emp := range employees {
// // 		if emp.IsActive {
// // 			return s.companyRepo.GetCompany(ctx, emp.CompanyID)
// // 		}
// // 	}

// // 	return nil, fmt.Errorf("no active employee found for phone: %s", employeePhone)
// // }

// // // GetCompanyIDByPhone gets company ID by phone number (either owner or employee)
// // func (s *CompanyService) GetCompanyIDByPhone(ctx context.Context, phone string) (uuid.UUID, error) {
// // 	// Try to get company by owner phone first
// // 	company, err := s.GetCompanyByPhone(ctx, phone)
// // 	if err == nil {
// // 		return company.CompanyID, nil
// // 	}

// // 	// If not owner, try to get by employee phone
// // 	company, err = s.GetCompanyByEmployeePhone(ctx, phone)
// // 	if err != nil {
// // 		return uuid.Nil, fmt.Errorf("failed to get company for phone %s: %w", phone, err)
// // 	}

// // 	return company.CompanyID, nil
// // }

// // // GetCompanyEmployeesByPhone gets company employees by owner's phone number
// // func (s *CompanyService) GetCompanyEmployeesByPhone(ctx context.Context, ownerPhone string, limit, offset int) ([]*models.CompanyEmployee, int, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, 0, err
// // 	}

// // 	return s.companyRepo.GetEmployeesByCompany(ctx, company.CompanyID, limit, offset)
// // }

// // // GetCompanyEmployeesByEmployeePhone gets company employees by employee's phone number
// // func (s *CompanyService) GetCompanyEmployeesByEmployeePhone(ctx context.Context, employeePhone string, limit, offset int) ([]*models.CompanyEmployee, int, error) {
// // 	company, err := s.GetCompanyByEmployeePhone(ctx, employeePhone)
// // 	if err != nil {
// // 		return nil, 0, err
// // 	}

// // 	return s.companyRepo.GetEmployeesByCompany(ctx, company.CompanyID, limit, offset)
// // }

// // // UpdateCompanySubscriptionByPhone updates company subscription by owner's phone number
// // func (s *CompanyService) UpdateCompanySubscriptionByPhone(ctx context.Context, ownerPhone, tier, status string, maxEmployees int) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for updated_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	updatedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.UpdateSubscription(ctx, company.CompanyID, tier, status, maxEmployees, updatedBy)
// // }

// // // ExtendSubscriptionByPhone extends subscription by owner's phone number
// // func (s *CompanyService) ExtendSubscriptionByPhone(ctx context.Context, ownerPhone string, additionalMonths, additionalDays int) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for extended_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	extendedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.ExtendSubscription(ctx, company.CompanyID, additionalMonths, additionalDays, extendedBy)
// // }

// // // DeactivateCompanyByPhone deactivates company by owner's phone number
// // func (s *CompanyService) DeactivateCompanyByPhone(ctx context.Context, ownerPhone, reason string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for updated_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	updatedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.DeactivateCompany(ctx, company.CompanyID, reason, updatedBy)
// // }

// // // ReactivateCompanyByPhone reactivates company by owner's phone number
// // func (s *CompanyService) ReactivateCompanyByPhone(ctx context.Context, ownerPhone string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for reactivated_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	reactivatedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.ReactivateCompany(ctx, company.CompanyID, reactivatedBy)
// // }

// // // GetCompanyRolesByPhone gets company roles by owner's phone number
// // func (s *CompanyService) GetCompanyRolesByPhone(ctx context.Context, ownerPhone string, limit, offset int) ([]*models.Role, int, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, 0, err
// // 	}

// // 	return s.companyRepo.GetRolesByCompany(ctx, company.CompanyID, limit, offset)
// // }

// // // GetCompanyDepartmentsByPhone gets company departments by owner's phone number
// // func (s *CompanyService) GetCompanyDepartmentsByPhone(ctx context.Context, ownerPhone string, limit, offset int) ([]*models.Department, int, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, 0, err
// // 	}

// // 	return s.companyRepo.GetDepartmentsByCompany(ctx, company.CompanyID, limit, offset)
// // }

// // // GetCompanyHierarchyByPhone gets company hierarchy by owner's phone number
// // func (s *CompanyService) GetCompanyHierarchyByPhone(ctx context.Context, ownerPhone string) ([]*models.EmployeeHierarchy, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	return s.GetCompanyHierarchy(ctx, company.CompanyID)
// // }

// // // GetCompanyRBACStatsByPhone gets company RBAC stats by owner's phone number
// // func (s *CompanyService) GetCompanyRBACStatsByPhone(ctx context.Context, ownerPhone string) (map[string]interface{}, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	// Get comprehensive stats
// // 	stats := make(map[string]interface{})
	
// // 	// Get employee count
// // 	employeeCount, err := s.companyRepo.GetEmployeeCount(ctx, company.CompanyID)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["employee_count"] = employeeCount
	
// // 	// Get active employee count
// // 	activeEmployeeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, company.CompanyID)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["active_employee_count"] = activeEmployeeCount
	
// // 	// Get role count
// // 	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, company.CompanyID, 1000, 0)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["role_count"] = len(roles)
	
// // 	// Get department count
// // 	depts, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, company.CompanyID, 1000, 0)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["department_count"] = len(depts)
	
// // 	// Get role distribution
// // 	roleDistribution, err := s.companyRepo.GetRoleDistribution(ctx, company.CompanyID)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["role_distribution"] = roleDistribution
	
// // 	// Get department load
// // 	departmentLoad, err := s.companyRepo.GetDepartmentLoad(ctx, company.CompanyID)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	stats["department_load"] = departmentLoad
	
// // 	// Add company info
// // 	stats["company_id"] = company.CompanyID.String()
// // 	stats["company_name"] = company.CompanyName
// // 	stats["subscription_tier"] = company.SubscriptionTier
// // 	stats["max_employees"] = company.MaxEmployees
// // 	stats["employee_utilization"] = float64(activeEmployeeCount) / float64(company.MaxEmployees) * 100
	
// // 	return stats, nil
// // }

// // // BulkAssignRolesByPhone bulk assigns roles by owner's phone number
// // func (s *CompanyService) BulkAssignRolesByPhone(ctx context.Context, ownerPhone string, assignments []BulkAssignment) (map[uuid.UUID]string, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	// Get current user ID for assigned_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return nil, fmt.Errorf("user ID not found in context")
// // 	}
// // 	assignedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.BulkAssignRoles(ctx, company.CompanyID, assignments, assignedBy)
// // }

// // // AddEmployeeByPhone adds employee by owner's phone number
// // func (s *CompanyService) AddEmployeeByPhone(ctx context.Context, req *AddEmployeeRequest, ownerPhone string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Update request with company ID
// // 	req.CompanyID = company.CompanyID
	
// // 	return s.AddEmployee(ctx, req)
// // }

// // // RemoveEmployeeByPhone removes employee by owner's phone number
// // func (s *CompanyService) RemoveEmployeeByPhone(ctx context.Context, ownerPhone string, userID uuid.UUID) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for removed_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	removedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.RemoveEmployee(ctx, company.CompanyID, userID, removedBy)
// // }

// // // UpdateEmployeeRoleByPhone updates employee role by owner's phone number
// // func (s *CompanyService) UpdateEmployeeRoleByPhone(ctx context.Context, ownerPhone string, userID, newRoleID uuid.UUID) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for updated_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	updatedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.UpdateEmployeeRole(ctx, company.CompanyID, userID, newRoleID, updatedBy)
// // }

// // // UpdateEmployeeDepartmentByPhone updates employee department by owner's phone number
// // func (s *CompanyService) UpdateEmployeeDepartmentByPhone(ctx context.Context, ownerPhone string, userID, newDepartmentID uuid.UUID) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for updated_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	updatedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.UpdateEmployeeDepartment(ctx, company.CompanyID, userID, newDepartmentID, updatedBy)
// // }


// // // RenameDepartmentByPhone renames department by owner's phone number
// // func (s *CompanyService) RenameDepartmentByPhone(ctx context.Context, ownerPhone string, departmentID uuid.UUID, newName string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	return s.RenameDepartment(ctx, company.CompanyID, departmentID, newName)
// // }

// // // AddManagerByPhone adds manager by owner's phone number
// // func (s *CompanyService) AddManagerByPhone(ctx context.Context, req *AddManagerRequest, ownerPhone string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Update request with company ID
// // 	req.CompanyID = company.CompanyID
	
// // 	return s.AddManager(ctx, req)
// // }

// // // AssignManagerPermissionsByPhone assigns manager permissions by owner's phone number
// // func (s *CompanyService) AssignManagerPermissionsByPhone(ctx context.Context, ownerPhone string, managerID uuid.UUID, permissionNames []string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for assigned_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	assignedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.AssignManagerPermissions(ctx, company.CompanyID, managerID, permissionNames, assignedBy)
// // }

// // // RevokeManagerPermissionsByPhone revokes manager permissions by owner's phone number
// // func (s *CompanyService) RevokeManagerPermissionsByPhone(ctx context.Context, ownerPhone string, managerID uuid.UUID, permissionNames []string) error {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return err
// // 	}

// // 	// Get current user ID for revoked_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	revokedBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	return s.RevokeManagerPermissions(ctx, company.CompanyID, managerID, permissionNames, revokedBy)
// // }

// // // GetEmployeePermissionsByPhone gets employee permissions by owner's phone number
// // func (s *CompanyService) GetEmployeePermissionsByPhone(ctx context.Context, ownerPhone string, userID uuid.UUID) ([]string, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	permissions, err := s.companyRepo.GetUserPermissions(ctx, company.CompanyID, userID)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	permissionNames := make([]string, len(permissions))
// // 	for i, perm := range permissions {
// // 		permissionNames[i] = perm.PermissionName
// // 	}

// // 	return permissionNames, nil
// // }

// // // CheckEmployeePermissionByPhone checks employee permission by owner's phone number
// // func (s *CompanyService) CheckEmployeePermissionByPhone(ctx context.Context, ownerPhone string, userID uuid.UUID, permissionName string) (bool, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return false, err
// // 	}

// // 	return s.CheckUserPermission(ctx, company.CompanyID, userID, permissionName)
// // }

// // // GetUserHierarchyByPhone gets user hierarchy by owner's phone number
// // func (s *CompanyService) GetUserHierarchyByPhone(ctx context.Context, ownerPhone string, userID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
// // 	company, err := s.GetCompanyByPhone(ctx, ownerPhone)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	// Get employee hierarchy for the specific user
// // 	hierarchy, err := s.companyRepo.GetEmployeeHierarchy(ctx, company.CompanyID)
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	// Filter for the specific user
// // 	var userHierarchy []*models.EmployeeHierarchy
// // 	for _, item := range hierarchy {
// // 		if item.UserID == userID {
// // 			userHierarchy = append(userHierarchy, item)
// // 		}
// // 	}

// // 	return userHierarchy, nil
// // }

// // // GetCompanyContextByPhone gets company context by employee's phone number
// // func (s *CompanyService) GetCompanyContextByPhone(ctx context.Context, employeePhone string) (*CompanyContext, error) {
// // 	user, err := s.userService.GetUserByPhone(ctx, employeePhone)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to get user by phone: %w", err)
// // 	}

// // 	return s.GetCompanyContext(ctx, user.UserID)
// // }

// // ============================================================================
// // BITMASK PERMISSION CHECKING (UPDATED)
// // ============================================================================

// // CheckMultiplePermissionsFromContext checks multiple permissions
// func (s *CompanyService) CheckMultiplePermissionsFromContext(ctx context.Context, permissions []string, checkAll bool) (bool, error) {
// 	sessionType, ok := ctx.Value("session_type").(string)
// 	if !ok {
// 		return false, fmt.Errorf("session type not found in context")
// 	}

// 	// Admin sessions have full access
// 	if sessionType == "admin" {
// 		return true, nil
// 	}

// 	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
// 	if !ok || permissionMask == nil {
// 		return false, fmt.Errorf("permission mask not found in context")
// 	}

// 	var hasRequired bool
// 	if checkAll {
// 		hasRequired = rbac.HasAllPermissions(permissionMask, permissions...)
// 	} else {
// 		hasRequired = rbac.HasAnyPermission(permissionMask, permissions...)
// 	}

// 	s.logger.Debug("Multiple bitmask permission check",
// 		util.Strings("permissions", permissions),
// 		util.Bool("check_all", checkAll),
// 		util.Bool("granted", hasRequired))

// 	return hasRequired, nil
// }

// // GetPermissionsFromContext returns all permission names from the bitmask
// func (s *CompanyService) GetPermissionsFromContext(ctx context.Context) ([]string, error) {
// 	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
// 	if !ok || permissionMask == nil {
// 		return []string{}, nil
// 	}

// 	return rbac.GetPermissionsFromMask(permissionMask), nil
// }

// // ============================================================================
// // COMPANY CREATION (ADMIN ONLY)
// // ============================================================================
// type CreateCompanyRequest struct {
//     CompanyName        string   `json:"company_name" validate:"required"`
//     OwnerPhone         string   `json:"owner_phone" validate:"required"`
//     OwnerUsername      string   `json:"owner_username" validate:"required,min=3,max=100,alphanum"` // NEW
//     OwnerFullName      string   `json:"owner_full_name" validate:"required,max=255"` // NEW
//     SubscriptionTier   string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
//     MaxEmployees       int      `json:"max_employees" validate:"required,min=1,max=2000"`
//     DataRegion         string   `json:"data_region" validate:"required"`
//     SubscriptionMonths int      `json:"subscription_months" validate:"required,min=1,max=36"`
//     SubscriptionDays   int      `json:"subscription_days" validate:"min=0,max=30"`
//     Departments        []string `json:"departments"`
// }
// func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest, createdBy uuid.UUID) (*models.Company, error) {
//     start := time.Now()

//     // Verify admin session
//     sessionType, ok := ctx.Value("session_type").(string)
//     if !ok || sessionType != "admin" {
//         return nil, fmt.Errorf("only admin users can create companies")
//     }

//     // Check if admin has permission to create companies
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.create")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return nil, fmt.Errorf("insufficient permissions to create companies")
//     }

//     // Step 1: Try to get existing user by phone
//     var ownerUser *models.User
//     existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
//     if err != nil {
//         // ✅ NEW: If user doesn't exist, create a new user but handle username gracefully
//         ownerUser, err = s.createOrFindUserForCompanyOwner(ctx, req)
//         if err != nil {
//             return nil, fmt.Errorf("failed to create user for company owner: %w", err)
//         }
//     } else {
//         // ✅ User exists, check if we can use it
//         ownerUser = existingUser
        
//         // Log the difference but don't fail
//         s.logger.Info("Using existing user for company creation",
//             util.String("phone", req.OwnerPhone),
//             util.String("existing_username", ownerUser.Username),
//             util.String("provided_username", req.OwnerUsername),
//             util.String("existing_full_name", ownerUser.FullName),
//             util.String("provided_full_name", req.OwnerFullName))
//     }

//     // Step 2: Check if company with same name already exists for this owner
//     exists, err := s.companyRepo.CheckCompanyExists(ctx, req.CompanyName, ownerUser.UserID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to validate company: %w", err)
//     }
//     if exists {
//         return nil, fmt.Errorf("company with name '%s' already exists for this owner", req.CompanyName)
//     }

//     companyID := uuid.New()
//     now := time.Now().UTC()
//     subscriptionEnd := now.AddDate(0, req.SubscriptionMonths, req.SubscriptionDays)

//     company := &models.Company{
//         CompanyID:             companyID,
//         CompanyName:           req.CompanyName,
//         OwnerUserID:           ownerUser.UserID,
//         SubscriptionTier:      req.SubscriptionTier,
//         SubscriptionStatus:    models.SubscriptionStatusActive,
//         MaxEmployees:          req.MaxEmployees,
//         DataRegion:            req.DataRegion,
//         IsActive:              true,
//         CreatedAt:             now,
//         UpdatedAt:             now,
//         SubscriptionStartDate: &now,
//         SubscriptionEndDate:   &subscriptionEnd,
//     }

//     if err := s.companyRepo.CreateCompany(ctx, company, req.Departments); err != nil {
//         return nil, fmt.Errorf("failed to create company: %w", err)
//     }

//     s.logger.Info("Company created successfully by admin",
//         util.String("company_id", companyID.String()),
//         util.String("company_name", req.CompanyName),
//         util.String("owner_user_id", ownerUser.UserID.String()),
//         util.String("owner_username", ownerUser.Username),
//         util.String("owner_phone", req.OwnerPhone),
//         util.String("created_by", createdBy.String()),
//         util.String("subscription_tier", req.SubscriptionTier),
//         util.Int("department_count", len(req.Departments)),
//         util.Duration("duration", time.Since(start)))

//     return company, nil
// }

// // ✅ NEW: Helper method to create or find user for company owner
// func (s *CompanyService) createOrFindUserForCompanyOwner(ctx context.Context, req *CreateCompanyRequest) (*models.User, error) {
//     // Try to create user with provided username
//     user, err := s.userService.CreateUser(ctx, &UserCreateRequest{
//         Username:          req.OwnerUsername,
//         FullName:          req.OwnerFullName,
//         PhoneNumber:       req.OwnerPhone,
//         DeviceID:          "company-setup",
//         DeviceFingerprint: "company-setup",
//         DataRegion:        req.DataRegion,
//         ConsentAgreed:     true,
//         ConsentVersion:    "v1.0",
//         KYCStatus:         models.KYCStatusPending,
//         KYCLevel:          models.KYCLevelBasic,
//     })
    
//     if err == nil {
//         return user, nil
//     }
    
//     // If username already exists, generate a unique username
//     if strings.Contains(err.Error(), "username already exists") {
//         s.logger.Warn("Username already exists, generating unique username",
//             util.String("requested_username", req.OwnerUsername),
//             util.String("phone", req.OwnerPhone))
        
//         // Generate unique username by appending random string
//         uniqueUsername := fmt.Sprintf("%s_%s", req.OwnerUsername, util.GenerateRandomString(6))
        
//         user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
//             Username:          uniqueUsername,
//             FullName:          req.OwnerFullName,
//             PhoneNumber:       req.OwnerPhone,
//             DeviceID:          "company-setup",
//             DeviceFingerprint: "company-setup",
//             DataRegion:        req.DataRegion,
//             ConsentAgreed:     true,
//             ConsentVersion:    "v1.0",
//             KYCStatus:         models.KYCStatusPending,
//             KYCLevel:          models.KYCLevelBasic,
//         })
        
//         if err != nil {
//             return nil, fmt.Errorf("failed to create user with unique username: %w", err)
//         }
        
//         s.logger.Info("Created user with unique username",
//             util.String("original_username", req.OwnerUsername),
//             util.String("assigned_username", uniqueUsername),
//             util.String("user_id", user.UserID.String()))
        
//         return user, nil
//     }
    
//     // Other errors
//     return nil, err
// }
// // ============================================================================
// // DEPARTMENT MANAGEMENT (BITMASK UPDATED)
// // ============================================================================

// type CreateDepartmentRequest struct {
// 	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
// 	DepartmentName     string     `json:"department_name" validate:"required"`
// 	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
// 	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
// 	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
// }

// // func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
// // 	// Check permission using bitmask
// // 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.create")
// // 	if err != nil {
// // 		return nil, fmt.Errorf("permission check failed: %w", err)
// // 	}
// // 	if !hasPermission {
// // 		return nil, fmt.Errorf("user lacks permission to create departments")
// // 	}

// // 	// Verify user has access to the company
// // 	userID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return nil, fmt.Errorf("user ID not found in context")
// // 	}

// // 	companyID, err := uuid.Parse(userID)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("invalid user ID in context")
// // 	}

// // 	// For non-owners, verify they belong to the company
// // 	sessionType, _ := ctx.Value("session_type").(string)
// // 	if sessionType != "admin" {
// // 		isEmployee, err := s.companyRepo.IsUserActiveEmployee(ctx, req.CompanyID, companyID)
// // 		if err != nil || !isEmployee {
// // 			return nil, fmt.Errorf("user does not belong to this company")
// // 		}
// // 	}

// // 	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, req.SystemDepartmentID)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("system department not found: %w", err)
// // 	}

// // 	if req.DepartmentHead != nil {
// // 		_, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.DepartmentHead)
// // 		if err != nil {
// // 			return nil, fmt.Errorf("department head not found: %w", err)
// // 		}
// // 	}

// // 	department := &models.Department{
// // 		DepartmentID:       uuid.New(),
// // 		CompanyID:          req.CompanyID,
// // 		DepartmentName:     req.DepartmentName,
// // 		SystemDepartmentID: &req.SystemDepartmentID,
// // 		DepartmentHead:     req.DepartmentHead,
// // 		ParentDepartmentID: req.ParentDepartmentID,
// // 		IsActive:           true,
// // 		CreatedAt:          time.Now().UTC(),
// // 		UpdatedAt:          time.Now().UTC(),
// // 	}

// // 	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
// // 		return nil, fmt.Errorf("failed to create department: %w", err)
// // 	}

// // 	s.logger.Info("Department created successfully",
// // 		util.String("company_id", req.CompanyID.String()),
// // 		util.String("department_id", department.DepartmentID.String()),
// // 		util.String("department_name", req.DepartmentName),
// // 		util.String("system_module", systemDept.ModuleCode))

// // 	return department, nil
// // }

// // ============================================================================
// // EMPLOYEE MANAGEMENT (BITMASK UPDATED)
// // ============================================================================
// type AddEmployeeRequest struct {
//     CompanyID   uuid.UUID  `json:"company_id" validate:"required"`
//     PhoneNumber string     `json:"phone" validate:"required"`
//     Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
//     FullName    string     `json:"full_name" validate:"required,max=255"`
//     EmployeeID  string     `json:"employee_id" validate:"required"`
//     RoleID      uuid.UUID  `json:"role_id" validate:"required"`
//     ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
// }

// type AddManagerRequest struct {
//     CompanyID   uuid.UUID  `json:"company_id" validate:"required"`
//     PhoneNumber string     `json:"phone" validate:"required"`
//     Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
//     FullName    string     `json:"full_name" validate:"required,max=255"`
//     RoleID      uuid.UUID  `json:"role_id" validate:"required"`
//     ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
//     EmployeeID  string     `json:"employee_id,omitempty"`
// }
// // ============================================================================
// // PERMISSION MANAGEMENT (BITMASK UPDATED)
// // ============================================================================

// type GrantRolePermissionsRequest struct {
// 	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
// 	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
// }

// func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to grant permissions")
// 	}
// 	_, err = s.companyRepo.GetRole(ctx, req.RoleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}

// 	// Get current user ID for granted_by
// 	currentUserID, ok := ctx.Value("user_id").(string)
// 	if !ok {
// 		return fmt.Errorf("user ID not found in context")
// 	}
// 	grantedBy, err := uuid.Parse(currentUserID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID in context")
// 	}

// 	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, req.PermissionIDs, grantedBy); err != nil {
// 		return fmt.Errorf("failed to grant permissions: %w", err)
// 	}

// 	s.logger.Info("Permissions granted to role successfully",
// 		util.String("role_id", req.RoleID.String()),
// 		util.Int("permission_count", len(req.PermissionIDs)))

// 	return nil
// }

// func (s *CompanyService) RevokeRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to revoke permissions")
// 	}

// 	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, roleID, permissionIDs); err != nil {
// 		return fmt.Errorf("failed to revoke permissions: %w", err)
// 	}

// 	s.logger.Info("Permissions revoked from role successfully",
// 		util.String("role_id", roleID.String()),
// 		util.Int("permission_count", len(permissionIDs)))

// 	return nil
// }

// // ============================================================================
// // UTILITY METHODS
// // ============================================================================

// // GetUserPermissionBitmask retrieves the complete permission bitmask for a user
// func (s *CompanyService) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
// 	return s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
// }

// // GetRolePermissionBitmask retrieves permission bitmask for a role
// func (s *CompanyService) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
// 	return s.companyRepo.GetRolePermissionBitmask(ctx, roleID)
// }

// // GetPermissionsWithBitIndex retrieves all permissions with their bit indexes
// func (s *CompanyService) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
// 	return s.companyRepo.GetPermissionsWithBitIndex(ctx)
// }

// // ============================================================================
// // EXISTING METHODS (MINIMAL CHANGES FOR BITMASK)
// // ============================================================================

// func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
// 	return s.companyRepo.GetCompany(ctx, companyID)
// }

// func (s *CompanyService) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
// 	return s.companyRepo.GetCompaniesByOwner(ctx, ownerUserID)
// }

// func (s *CompanyService) UpdateCompany(ctx context.Context, company *models.Company) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to update company")
// 	}

// 	return s.companyRepo.UpdateCompany(ctx, company)
// }

// func (s *CompanyService) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
// 	return s.companyRepo.GetEmployee(ctx, companyID, userID)
// }

// func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
// 	return s.companyRepo.GetEmployeesByCompany(ctx, companyID, limit, offset)
// }

// func (s *CompanyService) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
// 	return s.companyRepo.GetSystemDepartments(ctx)
// }

// func (s *CompanyService) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
// 	return s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
// }

// func (s *CompanyService) HealthCheck(ctx context.Context) error {
// 	return s.companyRepo.HealthCheck(ctx)
// }

// // AddDepartment adds a new department (simplified version)
// func (s *CompanyService) AddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.create")
// 	if err != nil {
// 		return nil, fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return nil, fmt.Errorf("user lacks permission to add departments")
// 	}

// 	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, systemDepartmentID)
// 	if err != nil {
// 		return nil, fmt.Errorf("system department not found: %w", err)
// 	}

// 	department := &models.Department{
// 		DepartmentID:       uuid.New(),
// 		CompanyID:          companyID,
// 		DepartmentName:     departmentName,
// 		SystemDepartmentID: &systemDepartmentID,
// 		IsActive:           true,
// 		CreatedAt:          time.Now().UTC(),
// 		UpdatedAt:          time.Now().UTC(),
// 	}

// 	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
// 		return nil, fmt.Errorf("failed to create department: %w", err)
// 	}

// 	// Auto-assign to owner role
// 	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
// 	if err != nil {
// 		s.logger.Warn("Failed to get owner role for auto-assignment", util.ErrorField(err))
// 	} else {
// 		if err := s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID); err != nil {
// 			s.logger.Warn("Failed to auto-assign department to owner role", util.ErrorField(err))
// 		}
// 	}

// 	s.logger.Info("Department added successfully",
// 		util.String("company_id", companyID.String()),
// 		util.String("department_id", department.DepartmentID.String()),
// 		util.String("department_name", departmentName),
// 		util.String("system_module", systemDept.ModuleCode))

// 	return department, nil
// }

// // ============================================================================
// // COMPANY CONTEXT & PERMISSION FLOW (FROM YOUR WORKING FILE)
// // ============================================================================

// type CompanyContext struct {
// 	CompanyID        string   `json:"company_id"`
// 	EmployeeID       string   `json:"employee_id"`
// 	RoleID           string   `json:"role_id"`
// 	RoleLevel        int      `json:"role_level"`
// 	RoleName         string   `json:"role_name"`
// 	DepartmentID     string   `json:"department_id"`
// 	DepartmentName   string   `json:"department_name"`
// 	SystemModule     string   `json:"system_module"`
// 	Permissions      []string `json:"permissions"`
// 	SubscriptionTier string   `json:"subscription_tier"`
// 	IsOwner          bool     `json:"is_owner"`
// 	IsManager        bool     `json:"is_manager"`
// }

// type PermissionCheckRequest struct {
// 	CompanyID      uuid.UUID `json:"company_id" validate:"required"`
// 	UserID         uuid.UUID `json:"user_id" validate:"required"`
// 	PermissionName string    `json:"permission_name" validate:"required"`
// 	Module         string    `json:"module,omitempty"`
// }

// type PermissionCheckResult struct {
// 	HasPermission bool              `json:"has_permission"`
// 	IsOwner       bool              `json:"is_owner"`
// 	Checks        map[string]bool   `json:"checks"`
// 	Details       *PermissionDetail `json:"details,omitempty"`
// 	Message       string            `json:"message,omitempty"`
// }

// type PermissionDetail struct {
// 	CompanyID      string `json:"company_id"`
// 	UserID         string `json:"user_id"`
// 	RoleID         string `json:"role_id"`
// 	RoleName       string `json:"role_name"`
// 	DepartmentID   string `json:"department_id"`
// 	SystemModule   string `json:"system_module"`
// 	PermissionName string `json:"permission_name"`
// 	RequiredModule string `json:"required_module"`
// }

// // CheckPermission implements the full RBAC flow: User → Employee → Role → Dept → Module → Permission
// func (s *CompanyService) CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResult, error) {
// 	start := time.Now()
// 	result := &PermissionCheckResult{
// 		HasPermission: false,
// 		Checks:        make(map[string]bool),
// 	}

// 	// 1. Check if user is company owner
// 	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("company not found: %w", err)
// 	}

// 	if company.OwnerUserID == req.UserID {
// 		result.HasPermission = true
// 		result.IsOwner = true
// 		result.Checks["is_owner"] = true
// 		result.Checks["has_employee_record"] = true
// 		result.Checks["role_has_permission"] = true
// 		result.Checks["role_belongs_to_department"] = true
// 		result.Checks["module_access"] = true

// 		s.logger.Debug("Owner permission granted",
// 			util.String("company_id", req.CompanyID.String()),
// 			util.String("user_id", req.UserID.String()),
// 			util.String("permission", req.PermissionName),
// 			util.Duration("duration", time.Since(start)))

// 		return result, nil
// 	}

// 	// 2. Get employee record (USER → EMPLOYEE)
// 	employee, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, req.UserID)
// 	if err != nil {
// 		result.Checks["has_employee_record"] = false
// 		result.Message = "User is not an active employee of this company"
// 		return result, nil
// 	}

// 	if !employee.IsActive {
// 		result.Checks["has_employee_record"] = false
// 		result.Message = "Employee record is not active"
// 		return result, nil
// 	}
// 	result.Checks["has_employee_record"] = true

// 	// 3. Check if employee has department
// 	if employee.DepartmentID == nil {
// 		result.Checks["has_department"] = false
// 		result.Message = "Employee is not assigned to any department"
// 		return result, nil
// 	}
// 	result.Checks["has_department"] = true

// 	// 4. Get role and department details
// 	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get role: %w", err)
// 	}

// 	department, err := s.companyRepo.GetDepartment(ctx, *employee.DepartmentID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get department: %w", err)
// 	}

// 	// 5. Check role has permission (ROLE → PERMISSION)
// 	permission, err := s.companyRepo.GetPermissionByName(ctx, req.PermissionName)
// 	if err != nil {
// 		result.Checks["role_has_permission"] = false
// 		result.Message = fmt.Sprintf("Permission not found: %s", req.PermissionName)
// 		return result, nil
// 	}

// 	hasPermission, err := s.companyRepo.CheckRolePermission(ctx, employee.RoleID, permission.PermissionID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to check role permission: %w", err)
// 	}
// 	result.Checks["role_has_permission"] = hasPermission
// 	if !hasPermission {
// 		result.Message = "Role does not have the required permission"
// 		return result, nil
// 	}

// 	// 6. Check role belongs to department (ROLE ↔ DEPARTMENT)
// 	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get role departments: %w", err)
// 	}

// 	roleInDepartment := false
// 	for _, dept := range roleDepartments {
// 		if dept.DepartmentID == *employee.DepartmentID {
// 			roleInDepartment = true
// 			break
// 		}
// 	}
// 	result.Checks["role_belongs_to_department"] = roleInDepartment
// 	if !roleInDepartment {
// 		result.Message = "Role is not assigned to employee's department"
// 		return result, nil
// 	}

// 	// 7. Check module access (DEPARTMENT → SYSTEM_DEPARTMENT → MODULE)
// 	if department.SystemDepartmentID == nil {
// 		result.Checks["module_access"] = false
// 		result.Message = "Department is not linked to any system module"
// 		return result, nil
// 	}

// 	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get system department: %w", err)
// 	}

// 	moduleMatch := permission.Module == systemDept.ModuleCode
// 	result.Checks["module_access"] = moduleMatch

// 	if !moduleMatch {
// 		result.Message = fmt.Sprintf("Permission module '%s' does not match department module '%s'",
// 			permission.Module, systemDept.ModuleCode)
// 		return result, nil
// 	}

// 	// 8. All checks passed - permission granted
// 	result.HasPermission = true
// 	result.Details = &PermissionDetail{
// 		CompanyID:      req.CompanyID.String(),
// 		UserID:         req.UserID.String(),
// 		RoleID:         employee.RoleID.String(),
// 		RoleName:       role.RoleName,
// 		DepartmentID:   department.DepartmentID.String(),
// 		SystemModule:   systemDept.ModuleCode,
// 		PermissionName: req.PermissionName,
// 		RequiredModule: permission.Module,
// 	}

// 	s.logger.Debug("Permission check completed",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("user_id", req.UserID.String()),
// 		util.String("permission", req.PermissionName),
// 		util.Bool("granted", true),
// 		util.Duration("duration", time.Since(start)))

// 	return result, nil
// }

// func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*CompanyContext, error) {
//     employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get user employees: %w", err)
//     }

//     if len(employees) == 0 {
//         return nil, fmt.Errorf("user is not an employee in any company")
//     }

//     emp := employees[0]
//     if !emp.IsActive {
//         return nil, fmt.Errorf("employee is not active")
//     }

//     company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
//     if err != nil {
//         return nil, fmt.Errorf("company not found: %w", err)
//     }

//     role, err := s.companyRepo.GetRole(ctx, emp.RoleID)
//     if err != nil {
//         return nil, fmt.Errorf("role not found: %w", err)
//     }

//     var departmentName, systemModule string
//     if emp.DepartmentID != nil {
//         dept, err := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
//         if err == nil {
//             departmentName = dept.DepartmentName
//             if dept.SystemDepartmentID != nil {
//                 systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
//                 if err == nil {
//                     systemModule = systemDept.ModuleCode
//                 }
//             }
//         }
//     }

//     permissions, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
//     if err != nil {
//         s.logger.Warn("failed to get employee permissions", util.ErrorField(err))
//         permissions = []*models.Permission{}
//     }

//     permStrings := make([]string, len(permissions))
//     for i, perm := range permissions {
//         permStrings[i] = perm.PermissionName
//     }

//     return &CompanyContext{
//         CompanyID:        company.CompanyID.String(),
//         EmployeeID:       emp.EmployeeID,
//         RoleID:           emp.RoleID.String(),
//         RoleLevel:        role.RoleLevel,
//         RoleName:         role.RoleName,
//         DepartmentID:     emp.DepartmentID.String(),
//         DepartmentName:   departmentName,
//         SystemModule:     systemModule,
//         Permissions:      permStrings,
//         SubscriptionTier: company.SubscriptionTier,
//         IsOwner:          company.OwnerUserID == userID,
//         IsManager:        role.RoleLevel <= 200,
//     }, nil
// }
// // ============================================================================
// // ADDITIONAL METHODS FROM YOUR WORKING FILE
// // ============================================================================

// // CheckUserPermission simplified version - FIXED
// func (s *CompanyService) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
// 	// Use the detailed CheckPermission method instead of recursive call
// 	req := &PermissionCheckRequest{
// 		CompanyID:      companyID,
// 		UserID:         userID,
// 		PermissionName: permissionName,
// 	}

// 	result, err := s.CheckPermission(ctx, req)
// 	if err != nil {
// 		return false, err
// 	}

// 	return result.HasPermission, nil
// }

// // GetUserPermissions gets all permissions for a user across companies
// func (s *CompanyService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
// 	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	permissionMap := make(map[uuid.UUID]*models.Permission)

// 	for _, emp := range employees {
// 		if emp.IsActive {
// 			perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
// 			if err == nil {
// 				for _, perm := range perms {
// 					permissionMap[perm.PermissionID] = perm
// 				}
// 			}
// 		}
// 	}

// 	var allPermissions []*models.Permission
// 	for _, perm := range permissionMap {
// 		allPermissions = append(allPermissions, perm)
// 	}

// 	return allPermissions, nil
// }

// // CreateRoleWithDepartments creates a role and maps it to departments
// func (s *CompanyService) CreateRoleWithDepartments(
// 	ctx context.Context,
// 	companyID uuid.UUID,
// 	roleName string,
// 	roleLevel int,
// 	createdBy uuid.UUID,
// 	description string,
// 	isSystemRole bool,
// 	departmentIDs []uuid.UUID,
// 	permissionIDs []uuid.UUID,
// ) (*models.Role, error) {

// 	req := &CreateRoleRequest{
// 		CompanyID:     companyID,
// 		RoleName:      roleName,
// 		RoleLevel:     roleLevel,
// 		Description:   description,
// 		DepartmentIDs: departmentIDs,
// 		PermissionIDs: permissionIDs,
// 		CreatedBy:     createdBy,
// 	}

// 	return s.CreateRole(ctx, req)
// }

// // ============================================================================
// // ADDITIONAL METHODS FROM SECOND FILE THAT WERE MISSING
// // ============================================================================

// // GetSystemDepartmentByModule retrieves system department by module code
// func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
// 	return s.companyRepo.GetSystemDepartmentByModule(ctx, module)
// }

// // UpdateCompanyStatus updates company active status
// func (s *CompanyService) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool, updatedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to update company status")
// 	}

// 	return s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive)
// }

// // UpdateSubscription updates company subscription
// func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to update subscription")
// 	}

// 	return s.companyRepo.UpdateSubscription(ctx, companyID, tier, status, maxEmployees)
// }

// // ListCompanies lists all companies with pagination
// func (s *CompanyService) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
// 	return s.companyRepo.ListCompanies(ctx, limit, offset)
// }

// // ListCompaniesByTier lists companies by subscription tier
// func (s *CompanyService) ListCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
// 	return s.companyRepo.GetCompaniesByTier(ctx, tier, limit, offset)
// }

// // GetCompaniesWithExpiringSubscription gets companies with expiring subscriptions
// func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
// 	return s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
// }

// // DeactivateCompany deactivates a company
// func (s *CompanyService) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string, updatedBy uuid.UUID) error {
// 	company, err := s.companyRepo.GetCompany(ctx, companyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}

// 	if !company.IsActive {
// 		return fmt.Errorf("company is already inactive")
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to deactivate company")
// 	}

// 	if err := s.companyRepo.DeactivateCompany(ctx, companyID, reason); err != nil {
// 		return fmt.Errorf("failed to deactivate company: %w", err)
// 	}

// 	s.logger.Info("Company deactivated by admin",
// 		util.String("company_id", companyID.String()),
// 		util.String("reason", reason),
// 		util.String("updated_by", updatedBy.String()))

// 	return nil
// }

// // DeleteCompany deletes a company
// func (s *CompanyService) DeleteCompany(ctx context.Context, companyID uuid.UUID, deletedBy uuid.UUID) error {
// 	company, err := s.companyRepo.GetCompany(ctx, companyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}

// 	if company.IsActive {
// 		return fmt.Errorf("cannot delete active company. Deactivate it first")
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.delete")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to delete company")
// 	}

// 	if err := s.companyRepo.DeleteCompany(ctx, companyID); err != nil {
// 		return fmt.Errorf("failed to delete company: %w", err)
// 	}

// 	s.logger.Info("Company deleted by admin",
// 		util.String("company_id", companyID.String()),
// 		util.String("deleted_by", deletedBy.String()))

// 	return nil
// }

// // ListActiveEmployees lists only active employees
// func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
// 	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
// }
// func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
//     if err != nil {
//         return fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return fmt.Errorf("user lacks permission to update employee roles")
//     }

//     _, err = s.companyRepo.GetEmployee(ctx, companyID, userID)
//     if err != nil {
//         return fmt.Errorf("employee not found: %w", err)
//     }

//     // Check if new role exists and belongs to company
//     newRole, err := s.companyRepo.GetRole(ctx, newRoleID)
//     if err != nil {
//         return fmt.Errorf("new role not found: %w", err)
//     }
//     if newRole.CompanyID != companyID {
//         return fmt.Errorf("new role does not belong to company")
//     }

//     if err := s.companyRepo.UpdateEmployeeRole(ctx, companyID, userID, newRoleID); err != nil {
//         return fmt.Errorf("failed to update employee role: %w", err)
//     }

//     s.logger.Info("Employee role updated successfully",
//         util.String("company_id", companyID.String()),
//         util.String("user_id", userID.String()),
//         util.String("new_role_id", newRoleID.String()),
//         util.String("updated_by", updatedBy.String()))

//     return nil
// }


// // RemoveEmployee removes an employee
// func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.terminate")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to remove employees")
// 	}

// 	if userID == removedBy {
// 		return fmt.Errorf("cannot remove yourself")
// 	}

// 	if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
// 		return fmt.Errorf("failed to remove employee: %w", err)
// 	}

// 	s.logger.Info("Employee removed successfully",
// 		util.String("company_id", companyID.String()),
// 		util.String("user_id", userID.String()),
// 		util.String("removed_by", removedBy.String()))

// 	return nil
// }

// // ReactivateEmployee reactivates an employee
// func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID, reactivatedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to reactivate employees")
// 	}

// 	if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
// 		return fmt.Errorf("failed to reactivate employee: %w", err)
// 	}

// 	s.logger.Info("Employee reactivated",
// 		util.String("company_id", companyID.String()),
// 		util.String("user_id", userID.String()),
// 		util.String("reactivated_by", reactivatedBy.String()))

// 	return nil
// }

// // GetEmployeeCount gets total employee count
// func (s *CompanyService) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// 	return s.companyRepo.GetEmployeeCount(ctx, companyID)
// }

// // IsUserActiveEmployee checks if user is active employee
// func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
// 	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
// }

// // UpdateRole updates role details
// func (s *CompanyService) UpdateRole(ctx context.Context, roleID uuid.UUID, roleName string, roleLevel int, updatedBy uuid.UUID, description string) error {
// 	role, err := s.companyRepo.GetRole(ctx, roleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to update roles")
// 	}

// 	if role.IsSystemRole {
// 		return fmt.Errorf("cannot update system roles")
// 	}

// 	role.RoleName = roleName
// 	role.RoleLevel = roleLevel
// 	role.Description = description
// 	role.UpdatedAt = time.Now().UTC()

// 	if err := s.companyRepo.UpdateRole(ctx, role); err != nil {
// 		return fmt.Errorf("failed to update role: %w", err)
// 	}

// 	s.logger.Info("Role updated",
// 		util.String("role_id", roleID.String()),
// 		util.String("role_name", roleName),
// 		util.Int("role_level", roleLevel),
// 		util.String("updated_by", updatedBy.String()))

// 	return nil
// }

// // DeleteRole deletes a role
// func (s *CompanyService) DeleteRole(ctx context.Context, roleID uuid.UUID, deletedBy uuid.UUID) error {
// 	role, err := s.companyRepo.GetRole(ctx, roleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.delete")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to delete roles")
// 	}

// 	if role.IsSystemRole {
// 		return fmt.Errorf("cannot delete system roles")
// 	}

// 	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
// 	if err != nil {
// 		return fmt.Errorf("failed to check role assignments: %w", err)
// 	}
// 	if len(employees) > 0 {
// 		return fmt.Errorf("cannot delete role that is assigned to employees")
// 	}

// 	if err := s.companyRepo.DeleteRole(ctx, roleID); err != nil {
// 		return fmt.Errorf("failed to delete role: %w", err)
// 	}

// 	s.logger.Info("Role deleted",
// 		util.String("role_id", roleID.String()),
// 		util.String("role_name", role.RoleName),
// 		util.String("deleted_by", deletedBy.String()))

// 	return nil
// }

// // UpdateDepartment updates department details
// func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, head *uuid.UUID, updatedBy uuid.UUID) error {
// 	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
// 	if err != nil {
// 		return fmt.Errorf("department not found: %w", err)
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to update departments")
// 	}

// 	if head != nil {
// 		if _, err := s.companyRepo.GetEmployee(ctx, department.CompanyID, *head); err != nil {
// 			return fmt.Errorf("department head not found: %w", err)
// 		}
// 	}

// 	department.DepartmentName = name
// 	department.DepartmentHead = head
// 	department.UpdatedAt = time.Now().UTC()

// 	if err := s.companyRepo.UpdateDepartment(ctx, department); err != nil {
// 		return fmt.Errorf("failed to update department: %w", err)
// 	}

// 	s.logger.Info("Department updated",
// 		util.String("department_id", departmentID.String()),
// 		util.String("department_name", name),
// 		util.String("updated_by", updatedBy.String()))

// 	return nil
// }

// // // DeactivateDepartment deactivates a department
// // func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID uuid.UUID, updatedBy uuid.UUID) error {
// // 	_, err := s.companyRepo.GetDepartment(ctx, departmentID)
// // 	if err != nil {
// // 		return fmt.Errorf("department not found: %w", err)
// // 	}

// // 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.delete")
// // 	if err != nil {
// // 		return fmt.Errorf("permission check failed: %w", err)
// // 	}
// // 	if !hasPermission {
// // 		return fmt.Errorf("user lacks permission to deactivate departments")
// // 	}

// // 	employees, _, err := s.companyRepo.GetEmployeesByDepartment(ctx, departmentID, 1, 0)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to check department employees: %w", err)
// // 	}
// // 	if len(employees) > 0 {
// // 		return fmt.Errorf("cannot deactivate department with active employees")
// // 	}

// // 	if err := s.companyRepo.DeactivateDepartment(ctx, departmentID); err != nil {
// // 		return fmt.Errorf("failed to deactivate department: %w", err)
// // 	}

// // 	s.logger.Info("Department deactivated",
// // 		util.String("department_id", departmentID.String()),
// // 		util.String("updated_by", updatedBy.String()))

// // 	return nil
// // }

// // GetDepartmentHierarchy gets department hierarchy
// func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
// 	return s.companyRepo.GetDepartmentHierarchy(ctx, companyID)
// }

// // GetPermissionByName gets permission by name
// func (s *CompanyService) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
// 	return s.companyRepo.GetPermissionByName(ctx, name)
// }

// // GetPermissionsByModule gets permissions by module
// func (s *CompanyService) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
// 	return s.companyRepo.GetPermissionsByModule(ctx, module)
// }

// // GetRolePermissions gets role permissions
// func (s *CompanyService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
// 	return s.companyRepo.GetRolePermissions(ctx, roleID)
// }

// // GrantRolePermission grants single permission to role
// func (s *CompanyService) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
// 	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to grant permissions")
// 	}

// 	if err := s.companyRepo.GrantRolePermission(ctx, roleID, permissionID, grantedBy); err != nil {
// 		return fmt.Errorf("failed to grant role permission: %w", err)
// 	}

// 	s.logger.Info("Role permission granted",
// 		util.String("role_id", roleID.String()),
// 		util.String("permission_id", permissionID.String()),
// 		util.String("granted_by", grantedBy.String()))

// 	return nil
// }

// // RevokeRolePermission revokes single permission from role
// func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID, revokedBy uuid.UUID) error {
// 	// Remove the unused role variable
// 	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to revoke permissions")
// 	}

// 	if err := s.companyRepo.RevokeRolePermission(ctx, roleID, permissionID); err != nil {
// 		return fmt.Errorf("failed to revoke role permission: %w", err)
// 	}

// 	s.logger.Info("Role permission revoked",
// 		util.String("role_id", roleID.String()),
// 		util.String("permission_id", permissionID.String()),
// 		util.String("revoked_by", revokedBy.String()))

// 	return nil
// }

// // BulkPermissionCheck checks multiple permissions at once
// func (s *CompanyService) BulkPermissionCheck(ctx context.Context, companyID, userID uuid.UUID, permissionNames []string) (map[string]bool, error) {
// 	results := make(map[string]bool)

// 	for _, permName := range permissionNames {
// 		hasPerm, err := s.CheckUserPermission(ctx, companyID, userID, permName)
// 		if err != nil {
// 			s.logger.Warn("Failed to check permission",
// 				util.String("company_id", companyID.String()),
// 				util.String("user_id", userID.String()),
// 				util.String("permission", permName),
// 				util.ErrorField(err))
// 			results[permName] = false
// 			continue
// 		}
// 		results[permName] = hasPerm
// 	}

// 	return results, nil
// }

// // GetModulePermissions gets permissions by module
// func (s *CompanyService) GetModulePermissions(ctx context.Context, module string) ([]*models.Permission, error) {
// 	return s.companyRepo.GetPermissionsByModule(ctx, module)
// }

// // GetDepartmentLoad gets department employee load
// func (s *CompanyService) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
// 	return s.companyRepo.GetDepartmentLoad(ctx, companyID)
// }

// // GetRoleDistribution gets role distribution
// func (s *CompanyService) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
// 	return s.companyRepo.GetRoleDistribution(ctx, companyID)
// }

// // GetCompanyStats gets company statistics
// func (s *CompanyService) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
// 	return s.companyRepo.GetCompanyStats(ctx, companyID)
// }

// // ExtendSubscription extends company subscription
// func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, additionalMonths, additionalDays int, extendedBy uuid.UUID) error {
// 	company, err := s.companyRepo.GetCompany(ctx, companyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}

// 	if !company.IsActive {
// 		return fmt.Errorf("cannot extend subscription for inactive company")
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to extend subscription")
// 	}

// 	var newEndDate time.Time
// 	if company.SubscriptionEndDate != nil {
// 		newEndDate = company.SubscriptionEndDate.AddDate(0, additionalMonths, additionalDays)
// 	} else {
// 		newEndDate = time.Now().UTC().AddDate(0, additionalMonths, additionalDays)
// 	}

// 	company.SubscriptionEndDate = &newEndDate
// 	company.UpdatedAt = time.Now().UTC()

// 	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
// 		return fmt.Errorf("failed to extend subscription: %w", err)
// 	}

// 	s.logger.Info("Company subscription extended",
// 		util.String("company_id", companyID.String()),
// 		util.Int("additional_months", additionalMonths),
// 		util.Int("additional_days", additionalDays),
// 		util.String("new_end_date", newEndDate.Format(time.RFC3339)),
// 		util.String("extended_by", extendedBy.String()))

// 	return nil
// }

// // AuthorizeUserLogin authorizes user login
// func (s *CompanyService) AuthorizeUserLogin(ctx context.Context, phoneNumber string) (*models.User, error) {
// 	user, err := s.userService.GetUserByPhone(ctx, phoneNumber)
// 	if err != nil {
// 		return nil, fmt.Errorf("user not found: %w", err)
// 	}

// 	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get user employees: %w", err)
// 	}

// 	hasActiveEmployment := false
// 	for _, emp := range employees {
// 		if emp.IsActive {
// 			hasActiveEmployment = true
// 			break
// 		}
// 	}

// 	if !hasActiveEmployment {
// 		return nil, fmt.Errorf("user is not an active employee in any company")
// 	}

// 	return user, nil
// }

// // GetUsersWithPermission gets users with specific permission
// func (s *CompanyService) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
// 	return s.companyRepo.GetUsersWithPermission(ctx, companyID, permissionName, limit)
// }

// // GetUsersByRoleLevel gets users by role level range
// func (s *CompanyService) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
// 	return s.companyRepo.GetUsersByRoleLevel(ctx, companyID, minLevel, maxLevel)
// }

// // CreateRoleWithPermissions creates role with permissions
// func (s *CompanyService) CreateRoleWithPermissions(ctx context.Context, companyID uuid.UUID, roleName string, roleLevel int, createdBy uuid.UUID, description string, isSystemRole bool, permissions []struct {
// 	PermissionID uuid.UUID `json:"permission_id"`
// }) (*models.Role, error) {
// 	permissionIDs := make([]uuid.UUID, len(permissions))
// 	for i, perm := range permissions {
// 		permissionIDs[i] = perm.PermissionID
// 	}

// 	req := &CreateRoleRequest{
// 		CompanyID:     companyID,
// 		RoleName:      roleName,
// 		RoleLevel:     roleLevel,
// 		Description:   description,
// 		DepartmentIDs: []uuid.UUID{},
// 		PermissionIDs: permissionIDs,
// 		CreatedBy:     createdBy,
// 	}

// 	return s.CreateRole(ctx, req)
// }

// // ListRoles lists roles with optional permission inclusion
// func (s *CompanyService) ListRoles(ctx context.Context, companyID uuid.UUID, limit, offset int, includePermissions bool) ([]*models.Role, int, error) {
// 	roles, total, err := s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	if includePermissions {
// 		for _, role := range roles {
// 			permissions, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
// 			if err == nil {
// 				s.logger.Debug("Retrieved role permissions",
// 					util.String("role_id", role.RoleID.String()),
// 					util.Int("permission_count", len(permissions)))
// 			}
// 		}
// 	}

// 	return roles, total, nil
// }

// // ListDepartments lists departments with optional employee inclusion
// func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit, offset int, includeEmployees bool) ([]*models.Department, int, error) {
// 	departments, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	if includeEmployees {
// 		for _, dept := range departments {
// 			employees, _, err := s.companyRepo.GetEmployeesByDepartment(ctx, dept.DepartmentID, 5, 0)
// 			if err == nil {
// 				s.logger.Debug("Department employee info",
// 					util.String("department_id", dept.DepartmentID.String()),
// 					util.Int("sample_employees", len(employees)))
// 			}
// 		}
// 	}

// 	return departments, total, nil
// }

// // ListPermissionsByModule lists permissions by module
// func (s *CompanyService) ListPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
// 	return s.companyRepo.GetPermissionsByModule(ctx, module)
// }

// // GetAllPermissions gets all permissions with filtering
// func (s *CompanyService) GetAllPermissions(ctx context.Context, module, category, tier string) ([]*models.Permission, error) {
// 	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var filtered []*models.Permission
// 	for _, perm := range allPerms {
// 		if module != "" && perm.Module != module {
// 			continue
// 		}
// 		if category != "" && perm.Category != category {
// 			continue
// 		}
// 		if tier != "" && perm.RequiresTier != tier {
// 			continue
// 		}
// 		filtered = append(filtered, perm)
// 	}

// 	return filtered, nil
// }

// // CreatePermission creates a new permission
// func (s *CompanyService) CreatePermission(ctx context.Context, permissionName, description, category, module, requiresTier string) (*models.Permission, error) {
// 	permission := &models.Permission{
// 		PermissionID:   uuid.New(),
// 		PermissionName: permissionName,
// 		Description:    description,
// 		Category:       category,
// 		Module:         module,
// 		RequiresTier:   requiresTier,
// 		CreatedAt:      time.Now().UTC(),
// 	}

// 	if err := s.companyRepo.CreatePermission(ctx, permission); err != nil {
// 		return nil, fmt.Errorf("failed to create permission: %w", err)
// 	}

// 	return permission, nil
// }

// // GetUserHierarchy gets user hierarchy
// func (s *CompanyService) GetUserHierarchy(ctx context.Context, userID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
// 	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var hierarchy []*models.EmployeeHierarchy
// 	for _, emp := range employees {
// 		if emp.IsActive {
// 			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
// 			var deptName string
// 			if emp.DepartmentID != nil {
// 				dept, _ := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
// 				if dept != nil {
// 					deptName = dept.DepartmentName
// 				}
// 			}

// 			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
// 				CompanyID:    emp.CompanyID,
// 				UserID:       emp.UserID,
// 				EmployeeID:   emp.EmployeeID,
// 				RoleName:     role.RoleName,
// 				RoleLevel:    role.RoleLevel,
// 				DepartmentID: emp.DepartmentID,
// 				Department:   deptName,
// 				ReportsTo:    emp.ReportsTo,
// 				IsActive:     emp.IsActive,
// 			})
// 		}
// 	}

// 	return hierarchy, nil
// }

// // GetEmployeeHierarchy gets employee hierarchy
// func (s *CompanyService) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
// 	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, companyID, 1000, 0)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var hierarchy []*models.EmployeeHierarchy
// 	for _, emp := range employees {
// 		if emp.IsActive {
// 			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
// 			var deptName string
// 			if emp.DepartmentID != nil {
// 				dept, _ := s.companyRepo.GetDepartment(ctx, *emp.DepartmentID)
// 				if dept != nil {
// 					deptName = dept.DepartmentName
// 				}
// 			}

// 			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
// 				CompanyID:    emp.CompanyID,
// 				UserID:       emp.UserID,
// 				EmployeeID:   emp.EmployeeID,
// 				RoleName:     role.RoleName,
// 				RoleLevel:    role.RoleLevel,
// 				DepartmentID: emp.DepartmentID,
// 				Department:   deptName,
// 				ReportsTo:    emp.ReportsTo,
// 				IsActive:     emp.IsActive,
// 			})
// 		}
// 	}

// 	return hierarchy, nil
// }

// // BulkAssignRoles bulk assigns roles to employees
// func (s *CompanyService) BulkAssignRoles(ctx context.Context, companyID uuid.UUID, assignments []BulkAssignment, assignedBy uuid.UUID) (map[uuid.UUID]string, error) {
// 	results := make(map[uuid.UUID]string)

// 	for _, assignment := range assignments {
// 		emp, err := s.companyRepo.GetEmployee(ctx, companyID, assignment.UserID)
// 		if err != nil {
// 			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
// 			continue
// 		}

// 		emp.RoleID = assignment.RoleID
// 		if assignment.DepartmentID != uuid.Nil {
// 			emp.DepartmentID = &assignment.DepartmentID
// 		}
// 		if assignment.ReportsTo != uuid.Nil {
// 			emp.ReportsTo = &assignment.ReportsTo
// 		}
// 		emp.UpdatedAt = time.Now().UTC()

// 		if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
// 			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
// 			continue
// 		}

// 		results[assignment.UserID] = "Success"
// 	}

// 	return results, nil
// }

// // removeDuplicatePermissions removes duplicate permissions
// func (s *CompanyService) removeDuplicatePermissions(permissions []*models.Permission) []*models.Permission {
// 	keys := make(map[uuid.UUID]bool)
// 	var unique []*models.Permission
// 	for _, perm := range permissions {
// 		if _, value := keys[perm.PermissionID]; !value {
// 			keys[perm.PermissionID] = true
// 			unique = append(unique, perm)
// 		}
// 	}
// 	return unique
// }

// // GetCompanyHierarchy gets company hierarchy
// func (s *CompanyService) GetCompanyHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
// 	hierarchy, err := s.companyRepo.GetEmployeeHierarchy(ctx, companyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get company hierarchy: %w", err)
// 	}
// 	return hierarchy, nil
// }

// // ReactivateCompany reactivates a company
// func (s *CompanyService) ReactivateCompany(ctx context.Context, companyID uuid.UUID, reactivatedBy uuid.UUID) error {
// 	company, err := s.companyRepo.GetCompany(ctx, companyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}

// 	if company.IsActive {
// 		return fmt.Errorf("company is already active")
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to reactivate company")
// 	}

// 	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
// 		return fmt.Errorf("failed to reactivate company: %w", err)
// 	}

// 	s.logger.Info("Company reactivated by admin",
// 		util.String("company_id", companyID.String()),
// 		util.String("reactivated_by", reactivatedBy.String()))

// 	return nil
// }

// // AssignManagerPermissions assigns permissions to manager
// func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to assign permissions")
// 	}

// 	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
// 	if err != nil {
// 		return fmt.Errorf("manager not found: %w", err)
// 	}

// 	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
// 	if err != nil {
// 		return fmt.Errorf("failed to get permissions: %w", err)
// 	}

// 	permissionIDs := make([]uuid.UUID, len(permissions))
// 	for i, perm := range permissions {
// 		permissionIDs[i] = perm.PermissionID
// 	}

// 	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, managerEmp.RoleID, permissionIDs, assignedBy); err != nil {
// 		return fmt.Errorf("failed to assign permissions to manager: %w", err)
// 	}

// 	s.logger.Info("Manager permissions assigned successfully",
// 		util.String("company_id", companyID.String()),
// 		util.String("manager_id", managerID.String()),
// 		util.String("role_id", managerEmp.RoleID.String()),
// 		util.Int("permissions_count", len(permissionNames)),
// 		util.String("assigned_by", assignedBy.String()))

// 	return nil
// }

// // RevokeManagerPermissions revokes permissions from manager
// func (s *CompanyService) RevokeManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, revokedBy uuid.UUID) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to revoke permissions")
// 	}

// 	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
// 	if err != nil {
// 		return fmt.Errorf("manager not found: %w", err)
// 	}

// 	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
// 	if err != nil {
// 		return fmt.Errorf("failed to get permissions: %w", err)
// 	}

// 	permissionIDs := make([]uuid.UUID, len(permissions))
// 	for i, perm := range permissions {
// 		permissionIDs[i] = perm.PermissionID
// 	}

// 	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, managerEmp.RoleID, permissionIDs); err != nil {
// 		return fmt.Errorf("failed to revoke permissions from manager: %w", err)
// 	}

// 	s.logger.Info("Manager permissions revoked successfully",
// 		util.String("company_id", companyID.String()),
// 		util.String("manager_id", managerID.String()),
// 		util.String("role_id", managerEmp.RoleID.String()),
// 		util.Int("permissions_count", len(permissionNames)),
// 		util.String("revoked_by", revokedBy.String()))

// 	return nil
// }

// // GetManagerPermissions gets manager permissions
// func (s *CompanyService) GetManagerPermissions(ctx context.Context, managerID uuid.UUID) ([]string, error) {
// 	return s.companyRepo.GetUserPermissionNames(ctx, managerID)
// }

// // ValidatePermissionSubset validates permission subset
// func (s *CompanyService) ValidatePermissionSubset(ctx context.Context, managerPermissions, requestedPermissions []string) bool {
// 	managerPermSet := make(map[string]bool)
// 	for _, perm := range managerPermissions {
// 		managerPermSet[perm] = true
// 	}

// 	for _, reqPerm := range requestedPermissions {
// 		if !managerPermSet[reqPerm] {
// 			return false
// 		}
// 	}
// 	return true
// }

// // removeDuplicateStrings removes duplicate strings
// func (s *CompanyService) removeDuplicateStrings(strs []string) []string {
// 	keys := make(map[string]bool)
// 	var unique []string
// 	for _, str := range strs {
// 		if _, value := keys[str]; !value {
// 			keys[str] = true
// 			unique = append(unique, str)
// 		}
// 	}
// 	return unique
// }

// // ============================================================================
// // ROLE MANAGEMENT STRUCTURES AND METHODS
// // ============================================================================
// type CreateRoleRequest struct {
// 	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
// 	RoleName      string      `json:"role_name" validate:"required"`
// 	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
// 	Description   string      `json:"description"`
// 	DepartmentIDs []uuid.UUID `json:"department_ids"`
// 	PermissionIDs []uuid.UUID `json:"permission_ids"`  // Direct array, not nested struct
// 	CreatedBy     uuid.UUID   `json:"created_by" validate:"required"`
// }

// // func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
// // 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// // 	if err != nil {
// // 		return nil, fmt.Errorf("permission check failed: %w", err)
// // 	}
// // 	if !hasPermission {
// // 		return nil, fmt.Errorf("user lacks permission to create roles")
// // 	}

// // 	for _, deptID := range req.DepartmentIDs {
// // 		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
// // 		if err != nil {
// // 			return nil, fmt.Errorf("department not found: %s", deptID)
// // 		}
// // 		if dept.CompanyID != req.CompanyID {
// // 			return nil, fmt.Errorf("department %s does not belong to company", deptID)
// // 		}
// // 	}

// // 	for _, permID := range req.PermissionIDs {
// // 		allPerms, err := s.companyRepo.GetAllPermissions(ctx)
// // 		if err != nil {
// // 			return nil, fmt.Errorf("failed to validate permissions: %w", err)
// // 		}
// // 		found := false
// // 		for _, perm := range allPerms {
// // 			if perm.PermissionID == permID {
// // 				found = true
// // 				break
// // 			}
// // 		}
// // 		if !found {
// // 			return nil, fmt.Errorf("permission not found: %s", permID)
// // 		}
// // 	}

// // 	role := &models.Role{
// // 		RoleID:       uuid.New(),
// // 		RoleName:     req.RoleName,
// // 		RoleLevel:    req.RoleLevel,
// // 		CompanyID:    req.CompanyID,
// // 		IsSystemRole: false,
// // 		Description:  req.Description,
// // 		CreatedAt:    time.Now().UTC(),
// // 		UpdatedAt:    time.Now().UTC(),
// // 	}

// // 	if err := s.companyRepo.CreateRole(ctx, role, req.DepartmentIDs); err != nil {
// // 		return nil, fmt.Errorf("failed to create role: %w", err)
// // 	}

// // 	if len(req.PermissionIDs) > 0 {
// // 		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy); err != nil {
// // 			s.logger.Warn("Failed to grant initial permissions to role",
// // 				util.String("role_id", role.RoleID.String()),
// // 				util.ErrorField(err))
// // 		}
// // 	}

// // 	s.logger.Info("Role created successfully",
// // 		util.String("company_id", req.CompanyID.String()),
// // 		util.String("role_id", role.RoleID.String()),
// // 		util.String("role_name", req.RoleName),
// // 		util.Int("department_count", len(req.DepartmentIDs)),
// // 		util.Int("permission_count", len(req.PermissionIDs)))

// // 	return role, nil
// // }
// // CreateRole creates a new role for a company with validation
// func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return nil, fmt.Errorf("user lacks permission to create roles")
//     }

//     // Get current user ID from context for validation
//     currentUserID, ok := ctx.Value("user_id").(string)
//     if !ok {
//         return nil, fmt.Errorf("user ID not found in context")
//     }
//     userID, err := uuid.Parse(currentUserID)
//     if err != nil {
//         return nil, fmt.Errorf("invalid user ID in context")
//     }

//     // 1. Validate that user has access to all departments
//     if len(req.DepartmentIDs) > 0 {
//         // Get user's accessible departments using ListDepartments
//         userDepartments, _, err := s.ListDepartments(ctx, req.CompanyID, 1000, 0, false)
//         if err != nil {
//             return nil, fmt.Errorf("failed to get user departments: %w", err)
//         }

//         // Create a map of accessible department IDs
//         accessibleDepts := make(map[uuid.UUID]bool)
//         for _, dept := range userDepartments {
//             accessibleDepts[dept.DepartmentID] = true
//         }

//         // Check if user has access to all requested departments
//         for _, deptID := range req.DepartmentIDs {
//             if !accessibleDepts[deptID] {
//                 // Try to get department name for better error message
//                 dept, err := s.companyRepo.GetDepartment(ctx, deptID)
//                 if err == nil {
//                     return nil, fmt.Errorf("user does not have access to department '%s' (%s)", dept.DepartmentName, deptID)
//                 }
//                 return nil, fmt.Errorf("user does not have access to department: %s", deptID)
//             }
//         }
//     }

//     // 2. Validate that user has all permissions they're trying to assign
//     if len(req.PermissionIDs) > 0 {
//         // Get user's permissions using GetUserPermissions API
//         userPermissions, err := s.GetUserPermissions(ctx, userID)
//         if err != nil {
//             return nil, fmt.Errorf("failed to get user permissions: %w", err)
//         }

//         // Create a map of user's permission IDs
//         userPermMap := make(map[uuid.UUID]bool)
//         for _, perm := range userPermissions {
//             userPermMap[perm.PermissionID] = true
//         }

//         // Get all available permissions for validation
//         allPerms, err := s.GetAllPermissions(ctx, "", "", "")
//         if err != nil {
//             return nil, fmt.Errorf("failed to get all permissions: %w", err)
//         }

//         // Create a map of all valid permission IDs
//         validPermMap := make(map[uuid.UUID]*models.Permission)
//         for _, perm := range allPerms {
//             validPermMap[perm.PermissionID] = perm
//         }

//         // Check if user has all requested permissions and they're valid
//         for _, permID := range req.PermissionIDs {
//             // Check if permission exists in system
//             perm, exists := validPermMap[permID]
//             if !exists {
//                 return nil, fmt.Errorf("permission not found: %s", permID)
//             }

//             // Check if user has this permission
//             if !userPermMap[permID] {
//                 return nil, fmt.Errorf("user cannot assign permission '%s' that they don't possess", perm.PermissionName)
//             }
//         }
//     }

//     // Validate role level
//     if req.RoleLevel < 1 || req.RoleLevel > 1000 {
//         return nil, fmt.Errorf("role level must be between 1 and 1000")
//     }

//     // Check if role name already exists in company
//     existingRoles, _, err := s.companyRepo.GetRolesByCompany(ctx, req.CompanyID, 1000, 0)
//     if err == nil {
//         for _, role := range existingRoles {
//             if strings.EqualFold(role.RoleName, req.RoleName) {
//                 return nil, fmt.Errorf("role with name '%s' already exists in this company", req.RoleName)
//             }
//         }
//     }

//     // Validate department IDs belong to the company
//     for _, deptID := range req.DepartmentIDs {
//         dept, err := s.companyRepo.GetDepartment(ctx, deptID)
//         if err != nil {
//             return nil, fmt.Errorf("department not found: %s", deptID)
//         }
//         if dept.CompanyID != req.CompanyID {
//             return nil, fmt.Errorf("department %s does not belong to company", deptID)
//         }
//     }

//     // Create the role
//     role := &models.Role{
//         RoleID:       uuid.New(),
//         RoleName:     req.RoleName,
//         RoleLevel:    req.RoleLevel,
//         CompanyID:    req.CompanyID,
//         IsSystemRole: false,
//         Description:  req.Description,
//         CreatedAt:    time.Now().UTC(),
//         UpdatedAt:    time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateRole(ctx, role, req.DepartmentIDs); err != nil {
//         // Check for duplicate role name
//         if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
//             return nil, fmt.Errorf("role with name '%s' already exists in this company", req.RoleName)
//         }
//         return nil, fmt.Errorf("failed to create role: %w", err)
//     }

//     // Assign permissions if specified
//     if len(req.PermissionIDs) > 0 {
//         if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy); err != nil {
//             s.logger.Warn("Failed to assign permissions to new role",
//                 util.String("role_id", role.RoleID.String()),
//                 util.ErrorField(err))
//             // Don't fail the entire operation if permissions fail
//         }
//     }

//     s.logger.Info("Role created successfully",
//         util.String("company_id", req.CompanyID.String()),
//         util.String("role_id", role.RoleID.String()),
//         util.String("role_name", req.RoleName),
//         util.Int("role_level", req.RoleLevel),
//         util.Int("department_count", len(req.DepartmentIDs)),
//         util.Int("permission_count", len(req.PermissionIDs)),
//         util.String("created_by", req.CreatedBy.String()))

//     return role, nil
// }
// // MapRoleToDepartmentRequest role to department mapping request
// type MapRoleToDepartmentRequest struct {
// 	RoleID       uuid.UUID `json:"role_id" validate:"required"`
// 	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
// 	MappedBy     uuid.UUID `json:"mapped_by" validate:"required"`
// }

// // MapRoleToDepartment maps role to department
// func (s *CompanyService) MapRoleToDepartment(ctx context.Context, req *MapRoleToDepartmentRequest) error {
// 	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}

// 	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
// 	if err != nil {
// 		return fmt.Errorf("department not found: %w", err)
// 	}

// 	if role.CompanyID != department.CompanyID {
// 		return fmt.Errorf("role and department must belong to the same company")
// 	}

// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to map roles to departments")
// 	}

// 	if err := s.companyRepo.CreateRoleDepartment(ctx, req.RoleID, req.DepartmentID); err != nil {
// 		return fmt.Errorf("failed to map role to department: %w", err)
// 	}

// 	s.logger.Info("Role mapped to department successfully",
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.String("mapped_by", req.MappedBy.String()))

// 	return nil
// }

// // RemoveRoleFromDepartment removes role from department
// func (s *CompanyService) RemoveRoleFromDepartment(ctx context.Context, roleID, departmentID, removedBy uuid.UUID) error {
// 	// Remove the unused role variable
// 	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to remove roles from departments")
// 	}

// 	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
// 	if err != nil {
// 		return fmt.Errorf("failed to check role assignments: %w", err)
// 	}

// 	for _, emp := range employees {
// 		if emp.DepartmentID != nil && *emp.DepartmentID == departmentID {
// 			return fmt.Errorf("cannot remove role from department: employees are still assigned to this role-department combination")
// 		}
// 	}

// 	if err := s.companyRepo.RemoveRoleDepartment(ctx, roleID, departmentID); err != nil {
// 		return fmt.Errorf("failed to remove role from department: %w", err)
// 	}

// 	s.logger.Info("Role removed from department successfully",
// 		util.String("role_id", roleID.String()),
// 		util.String("department_id", departmentID.String()),
// 		util.String("removed_by", removedBy.String()))

// 	return nil
// }

// // GetRoleDepartments gets role departments
// func (s *CompanyService) GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
// 	return s.companyRepo.GetRoleDepartments(ctx, roleID)
// }

// // GetDepartmentRoles gets department roles
// func (s *CompanyService) GetDepartmentRoles(ctx context.Context, departmentID uuid.UUID) ([]*models.Role, error) {
// 	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var departmentRoles []*models.Role
// 	for _, role := range roles {
// 		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
// 		if err != nil {
// 			continue
// 		}
// 		for _, dept := range roleDepts {
// 			if dept.DepartmentID == departmentID {
// 				departmentRoles = append(departmentRoles, role)
// 				break
// 			}
// 		}
// 	}

// 	return departmentRoles, nil
// }

// // ValidateRoleDepartmentCompatibility validates role-department compatibility
// func (s *CompanyService) ValidateRoleDepartmentCompatibility(ctx context.Context, roleID, departmentID uuid.UUID) (bool, error) {
// 	permissions, err := s.companyRepo.GetRolePermissions(ctx, roleID)
// 	if err != nil {
// 		return false, err
// 	}

// 	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
// 	if err != nil {
// 		return false, err
// 	}

// 	if department.SystemDepartmentID == nil {
// 		return false, nil
// 	}

// 	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
// 	if err != nil {
// 		return false, err
// 	}

// 	for _, perm := range permissions {
// 		if perm.Module != systemDept.ModuleCode {
// 			return false, nil
// 		}
// 	}

// 	return true, nil
// }

// // GetRole retrieves a role by ID
// func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
// 	return s.companyRepo.GetRole(ctx, roleID)
// }

// // IsUserActiveEmployee checks if user is active employee of company
// func (s *CompanyService) CheckPermissionFromContext(ctx context.Context, permissionName string) (bool, error) {
// 	// Get session type from context
// 	sessionType, ok := ctx.Value("session_type").(string)
// 	if !ok {
// 		s.logger.Debug("CheckPermissionFromContext: session type not found")
// 		return false, fmt.Errorf("session type not found in context")
// 	}

// 	// Admin sessions have full access
// 	if sessionType == "admin" {
// 		s.logger.Debug("CheckPermissionFromContext: admin session - full access granted",
// 			util.String("permission", permissionName))
// 		return true, nil
// 	}

// 	// Get permission mask from context
// 	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
// 	if !ok || permissionMask == nil {
// 		s.logger.Debug("CheckPermissionFromContext: permission mask not found in context",
// 			util.String("session_type", sessionType))
// 		return false, fmt.Errorf("permission mask not found in context")
// 	}

// 	// Use RBAC package to check permission
// 	hasPermission := rbac.HasPermission(permissionMask, permissionName)

// 	s.logger.Debug("CheckPermissionFromContext: bitmask permission check",
// 		util.String("permission", permissionName),
// 		util.String("session_type", sessionType),
// 		util.Bool("granted", hasPermission),
// 		util.Any("mask", permissionMask))

// 	return hasPermission, nil
// }

// func (s *CompanyService) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
// 	s.logger.Debug("Fetching departments for company",
// 		util.String("company_id", companyID.String()),
// 		util.Int("limit", limit),
// 		util.Int("offset", offset))

// 	departments, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
// 	if err != nil {
// 		s.logger.Error("Failed to get departments from repository",
// 			util.String("company_id", companyID.String()),
// 			util.ErrorField(err))
// 		return nil, 0, err
// 	}

// 	s.logger.Debug("Successfully retrieved departments",
// 		util.String("company_id", companyID.String()),
// 		util.Int("count", len(departments)),
// 		util.Int("total", total))

// 	return departments, total, nil
// }

// // RenameDepartment updates only the department name
// func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string) error {
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to rename departments")
// 	}

// 	// Verify the department belongs to the company
// 	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
// 	if err != nil {
// 		return fmt.Errorf("department not found: %w", err)
// 	}
// 	if department.CompanyID != companyID {
// 		return fmt.Errorf("department does not belong to company")
// 	}

// 	if err := s.companyRepo.UpdateDepartmentName(ctx, departmentID, newName); err != nil {
// 		return fmt.Errorf("failed to rename department: %w", err)
// 	}

// 	s.logger.Info("Department renamed successfully",
// 		util.String("company_id", companyID.String()),
// 		util.String("department_id", departmentID.String()),
// 		util.String("new_name", newName))

// 	return nil
// }

// // In company_service.go
// func (s *CompanyService) GetPermissionsByCompanyDepartments(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error) {
// 	// Get company departments
// 	departments, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, 1000, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get company departments: %w", err)
// 	}

// 	// Extract system department IDs
// 	systemDeptIDs := make([]uuid.UUID, 0)
// 	for _, dept := range departments {
// 		if dept.SystemDepartmentID != nil {
// 			systemDeptIDs = append(systemDeptIDs, *dept.SystemDepartmentID)
// 		}
// 	}

// 	// Always include administrative department
// 	adminSystemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, "administration")
// 	if err == nil {
// 		systemDeptIDs = append(systemDeptIDs, adminSystemDept.SystemDepartmentID)
// 	}

// 	if len(systemDeptIDs) == 0 {
// 		return []*models.Permission{}, nil
// 	}

// 	// Get permissions by system departments
// 	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, module, category, tier)
// }

// // ValidatePermissionAssignment validates if a user can assign specific permissions
// func (s *CompanyService) ValidatePermissionAssignment(ctx context.Context, assignerID uuid.UUID, permissionsToAssign []string) (bool, error) {
// 	// Get assigner's permissions
// 	assignerPermissions, err := s.GetUserPermissions(ctx, assignerID)
// 	if err != nil {
// 		return false, err
// 	}

// 	// Convert to map for easy lookup
// 	assignerPermMap := make(map[string]bool)
// 	for _, perm := range assignerPermissions {
// 		assignerPermMap[perm.PermissionName] = true
// 	}

// 	// Check if assigner has all permissions they're trying to assign
// 	for _, permToAssign := range permissionsToAssign {
// 		if !assignerPermMap[permToAssign] {
// 			return false, nil
// 		}
// 	}

// 	return true, nil
// }

// // func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
// // 	// ONLY check if user has permission to add managers with administrative access
// // 	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
// // 	if err != nil {
// // 		return fmt.Errorf("permission check failed: %w", err)
// // 	}
// // 	if !hasPermission {
// // 		return fmt.Errorf("user lacks permission to add managers")
// // 	}

// // 	// For non-admin users, validate they're not assigning permissions they don't have
// // 	sessionType, _ := ctx.Value("session_type").(string)
// // 	if sessionType != "admin" && len(req.Permissions) > 0 {
// // 		userPermissions, err := s.GetPermissionsFromContext(ctx)
// // 		if err != nil {
// // 			return fmt.Errorf("failed to get user permissions: %w", err)
// // 		}

// // 		for _, reqPerm := range req.Permissions {
// // 			found := false
// // 			for _, userPerm := range userPermissions {
// // 				if userPerm == reqPerm {
// // 					found = true
// // 					break
// // 				}
// // 			}
// // 			if !found {
// // 				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
// // 			}
// // 		}
// // 	}

// // 	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
// // 	if err != nil {
// // 		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// // 		if err != nil {
// // 			return fmt.Errorf("failed to get company: %w", err)
// // 		}

// // 		user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
// // 			Username:          req.Username,
// // 			FullName:          req.FullName,
// // 			PhoneNumber:       req.PhoneNumber,
// // 			DeviceID:          "company-assigned",
// // 			DeviceFingerprint: "company-assigned",
// // 			DataRegion:        company.DataRegion,
// // 			ConsentAgreed:     true,
// // 			ConsentVersion:    "v1.0",
// // 			KYCStatus:         models.KYCStatusPending,
// // 			KYCLevel:          models.KYCLevelBasic,
// // 		})
// // 		if err != nil {
// // 			return fmt.Errorf("failed to create user: %w", err)
// // 		}
// // 	}

// // 	managerRole := &models.Role{
// // 		RoleID:       uuid.New(),
// // 		RoleName:     req.RoleName,
// // 		RoleLevel:    500, // Manager level
// // 		CompanyID:    req.CompanyID,
// // 		IsSystemRole: false,
// // 		Description:  fmt.Sprintf("Manager role for %s", req.RoleName),
// // 		CreatedAt:    time.Now().UTC(),
// // 		UpdatedAt:    time.Now().UTC(),
// // 	}

// // 	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to get permissions: %w", err)
// // 	}

// // 	permissionIDs := make([]uuid.UUID, len(permissions))
// // 	for i, perm := range permissions {
// // 		permissionIDs[i] = perm.PermissionID
// // 	}

// // 	// Get current user ID for granted_by
// // 	currentUserID, ok := ctx.Value("user_id").(string)
// // 	if !ok {
// // 		return fmt.Errorf("user ID not found in context")
// // 	}
// // 	createdBy, err := uuid.Parse(currentUserID)
// // 	if err != nil {
// // 		return fmt.Errorf("invalid user ID in context")
// // 	}

// // 	if err := s.companyRepo.CreateRoleWithDetails(ctx, managerRole, req.DepartmentID, permissionIDs, createdBy); err != nil {
// // 		return fmt.Errorf("failed to create manager role: %w", err)
// // 	}

// // 	reportsTo := req.ReportsTo
// // 	if reportsTo == nil {
// // 		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// // 		if err != nil {
// // 			return fmt.Errorf("failed to get company: %w", err)
// // 		}
// // 		reportsTo = &company.OwnerUserID
// // 	}

// // 	emp := &models.CompanyEmployee{
// // 		CompanyID:    req.CompanyID,
// // 		UserID:       user.UserID,
// // 		EmployeeID:   fmt.Sprintf("MGR-%s", uuid.New().String()[:8]),
// // 		RoleID:       managerRole.RoleID,
// // 		DepartmentID: &req.DepartmentID,
// // 		HireDate:     time.Now().UTC(),
// // 		IsActive:     true,
// // 		ReportsTo:    reportsTo,
// // 		CreatedAt:    time.Now().UTC(),
// // 		UpdatedAt:    time.Now().UTC(),
// // 	}

// // 	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
// // 		return fmt.Errorf("failed to add manager as employee: %w", err)
// // 	}

// // 	s.logger.Info("Manager added successfully",
// // 		util.String("company_id", req.CompanyID.String()),
// // 		util.String("user_id", user.UserID.String()),
// // 		util.String("department_id", req.DepartmentID.String()),
// // 		util.Int("permissions_count", len(req.Permissions)))

// // 	return nil
// // }
// func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
//     if err != nil {
//         return fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return fmt.Errorf("user lacks permission to add managers")
//     }

//     company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }
//     if !company.IsActive {
//         return fmt.Errorf("company is not active")
//     }

//     role, err := s.companyRepo.GetRole(ctx, req.RoleID)
//     if err != nil {
//         return fmt.Errorf("role not found: %w", err)
//     }

//     // Check role level for manager (500 or higher)
//     if role.RoleLevel < 500 {
//         return fmt.Errorf("role level must be 500 or higher for managers")
//     }

//     // Check role has department assignments
//     roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get role departments: %w", err)
//     }
//     if len(roleDepartments) == 0 {
//         return fmt.Errorf("role is not assigned to any department")
//     }

//     user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
//     if err != nil {
//         user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
//             Username:          req.Username,
//             FullName:          req.FullName,
//             PhoneNumber:       req.PhoneNumber,
//             DeviceID:          "company-assigned",
//             DeviceFingerprint: "company-assigned",
//             DataRegion:        company.DataRegion,
//             ConsentAgreed:     true,
//             ConsentVersion:    "v1.0",
//             KYCStatus:         models.KYCStatusPending,
//             KYCLevel:          models.KYCLevelBasic,
//         })
//         if err != nil {
//             return fmt.Errorf("failed to create user: %w", err)
//         }
//     }

//     reportsTo := req.ReportsTo
//     if reportsTo == nil {
//         // Use the first department's head or company owner
//         if len(roleDepartments) > 0 && roleDepartments[0].DepartmentHead != nil {
//             reportsTo = roleDepartments[0].DepartmentHead
//         } else {
//             reportsTo = &company.OwnerUserID
//         }
//     }

//     existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
//     if existingEmp != nil && existingEmp.IsActive {
//         return fmt.Errorf("user is already an active employee in this company")
//     }

//     employeeID := req.EmployeeID
//     if employeeID == "" {
//         employeeID = fmt.Sprintf("MGR-%s", uuid.New().String()[:8])
//     }

//     emp := &models.CompanyEmployee{
//         CompanyID:  req.CompanyID,
//         UserID:     user.UserID,
//         EmployeeID: employeeID,
//         RoleID:     req.RoleID,
//         // DepartmentID is now removed
//         HireDate:   time.Now().UTC(),
//         IsActive:   true,
//         ReportsTo:  reportsTo,
//         CreatedAt:  time.Now().UTC(),
//         UpdatedAt:  time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
//         return fmt.Errorf("failed to add manager as employee: %w", err)
//     }

//     s.logger.Info("Manager added successfully",
//         util.String("company_id", req.CompanyID.String()),
//         util.String("user_id", user.UserID.String()),
//         util.String("role_id", role.RoleID.String()),
//         util.String("role_name", role.RoleName),
//         util.Int("role_level", role.RoleLevel))

//     return nil
// }
// // func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
// // 	start := time.Now()

// // 	// ONLY check if user has permission to add employees (hr.employee.create)
// // 	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
// // 	if err != nil {
// // 		return fmt.Errorf("permission check failed: %w", err)
// // 	}
// // 	if !hasPermission {
// // 		return fmt.Errorf("user lacks permission to add employees")
// // 	}

// // 	// For non-admin users, validate they're not assigning permissions they don't have
// // 	sessionType, _ := ctx.Value("session_type").(string)
// // 	if sessionType != "admin" && len(req.Permissions) > 0 {
// // 		userPermissions, err := s.GetPermissionsFromContext(ctx)
// // 		if err != nil {
// // 			return fmt.Errorf("failed to get user permissions: %w", err)
// // 		}

// // 		// Check if all requested permissions are in user's permissions
// // 		for _, reqPerm := range req.Permissions {
// // 			found := false
// // 			for _, userPerm := range userPermissions {
// // 				if userPerm == reqPerm {
// // 					found = true
// // 					break
// // 				}
// // 			}
// // 			if !found {
// // 				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
// // 			}
// // 		}
// // 	}

// // 	// Validate company
// // 	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// // 	if err != nil {
// // 		return fmt.Errorf("company not found: %w", err)
// // 	}
// // 	if !company.IsActive {
// // 		return fmt.Errorf("company is not active")
// // 	}

// // 	// Check employee limit
// // 	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to get active employee count: %w", err)
// // 	}
// // 	if activeCount >= company.MaxEmployees {
// // 		return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
// // 	}

// // 	// Validate role
// // 	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
// // 	if err != nil {
// // 		return fmt.Errorf("role not found: %w", err)
// // 	}
// // 	if role.CompanyID != req.CompanyID {
// // 		return fmt.Errorf("role does not belong to company")
// // 	}

// // 	// Validate department
// // 	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
// // 	if err != nil {
// // 		return fmt.Errorf("department not found: %w", err)
// // 	}
// // 	if department.CompanyID != req.CompanyID {
// // 		return fmt.Errorf("department does not belong to company")
// // 	}

// // 	// Check role-department mapping
// // 	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to get role departments: %w", err)
// // 	}

// // 	roleInDepartment := false
// // 	for _, dept := range roleDepartments {
// // 		if dept.DepartmentID == req.DepartmentID {
// // 			roleInDepartment = true
// // 			break
// // 		}
// // 	}
// // 	if !roleInDepartment {
// // 		return fmt.Errorf("role %s is not assigned to department %s", req.RoleID, req.DepartmentID)
// // 	}

// // 	// Validate reports_to
// // 	if req.ReportsTo != nil {
// // 		reportsToEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
// // 		if err != nil {
// // 			return fmt.Errorf("reports_to employee not found: %w", err)
// // 		}
// // 		if !reportsToEmp.IsActive {
// // 			return fmt.Errorf("reports_to employee is not active")
// // 		}
// // 	}

// // 	// Get or create user
// // 	// Get or create user
// // 	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
// // 	if err != nil {
// // 		user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
// // 			Username:          req.Username,
// // 			FullName:          req.FullName,
// // 			PhoneNumber:       req.PhoneNumber,
// // 			DeviceID:          "company-assigned",
// // 			DeviceFingerprint: "company-assigned",
// // 			DataRegion:        company.DataRegion,
// // 			ConsentAgreed:     true,
// // 			ConsentVersion:    "v1.0",
// // 			KYCStatus:         models.KYCStatusPending,
// // 			KYCLevel:          models.KYCLevelBasic,
// // 		})
// // 		if err != nil {
// // 			return fmt.Errorf("failed to create user: %w", err)
// // 		}
// // 	}
// // 	// Check if user is already an active employee
// // 	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
// // 	if existingEmp != nil && existingEmp.IsActive {
// // 		return fmt.Errorf("user is already an active employee in this company")
// // 	}

// // 	// Assign permissions if specified
// // 	if len(req.Permissions) > 0 {
// // 		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// // 		if err != nil {
// // 			return fmt.Errorf("failed to get permissions: %w", err)
// // 		}

// // 		// Validate permission compatibility with department module
// // 		if department.SystemDepartmentID != nil {
// // 			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
// // 			if err != nil {
// // 				return fmt.Errorf("failed to get system department: %w", err)
// // 			}

// // 			for _, perm := range permissions {
// // 				if perm.Module != systemDept.ModuleCode {
// // 					return fmt.Errorf("permission '%s' (module: %s) is not compatible with department module '%s'",
// // 						perm.PermissionName, perm.Module, systemDept.ModuleCode)
// // 				}
// // 			}
// // 		}

// // 		// Grant permissions to the role
// // 		permissionIDs := make([]uuid.UUID, len(permissions))
// // 		for i, perm := range permissions {
// // 			permissionIDs[i] = perm.PermissionID
// // 		}

// // 		// Get current user ID for granted_by
// // 		currentUserID, ok := ctx.Value("user_id").(string)
// // 		if !ok {
// // 			return fmt.Errorf("user ID not found in context")
// // 		}
// // 		grantedBy, err := uuid.Parse(currentUserID)
// // 		if err != nil {
// // 			return fmt.Errorf("invalid user ID in context")
// // 		}

// // 		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, grantedBy); err != nil {
// // 			return fmt.Errorf("failed to assign permissions to role: %w", err)
// // 		}
// // 	}

// // 	// Set default reports_to if not provided
// // 	reportsTo := req.ReportsTo
// // 	if reportsTo == nil {
// // 		if department.DepartmentHead != nil {
// // 			reportsTo = department.DepartmentHead
// // 		} else {
// // 			reportsTo = &company.OwnerUserID
// // 		}
// // 	}

// // 	// Create employee record
// // 	emp := &models.CompanyEmployee{
// // 		CompanyID:    req.CompanyID,
// // 		UserID:       user.UserID,
// // 		EmployeeID:   req.EmployeeID,
// // 		RoleID:       req.RoleID,
// // 		DepartmentID: &req.DepartmentID,
// // 		HireDate:     time.Now().UTC(),
// // 		IsActive:     true,
// // 		ReportsTo:    reportsTo,
// // 		CreatedAt:    time.Now().UTC(),
// // 		UpdatedAt:    time.Now().UTC(),
// // 	}

// // 	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
// // 		return fmt.Errorf("failed to add employee: %w", err)
// // 	}

// // 	s.logger.Info("Employee added successfully",
// // 		util.String("company_id", req.CompanyID.String()),
// // 		util.String("user_id", user.UserID.String()),
// // 		util.String("employee_id", req.EmployeeID),
// // 		util.String("role_id", req.RoleID.String()),
// // 		util.String("role_name", role.RoleName),
// // 		util.String("department_id", req.DepartmentID.String()),
// // 		util.String("department_name", department.DepartmentName),
// // 		util.Int("permissions_count", len(req.Permissions)),
// // 		util.Duration("duration", time.Since(start)))

// // 	return nil
// // }
// func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
//     start := time.Now()

//     hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
//     if err != nil {
//         return fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return fmt.Errorf("user lacks permission to add employees")
//     }

//     company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }
//     if !company.IsActive {
//         return fmt.Errorf("company is not active")
//     }

//     activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
//     if err != nil {
//         return fmt.Errorf("failed to get active employee count: %w", err)
//     }
//     if activeCount >= company.MaxEmployees {
//         return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
//     }

//     role, err := s.companyRepo.GetRole(ctx, req.RoleID)
//     if err != nil {
//         return fmt.Errorf("role not found: %w", err)
//     }
//     if role.CompanyID != req.CompanyID {
//         return fmt.Errorf("role does not belong to company")
//     }

//     // Check if role has department assignments
//     roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get role departments: %w", err)
//     }
//     if len(roleDepartments) == 0 {
//         return fmt.Errorf("role is not assigned to any department")
//     }

//     if req.ReportsTo != nil {
//         reportsToEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
//         if err != nil {
//             return fmt.Errorf("reports_to employee not found: %w", err)
//         }
//         if !reportsToEmp.IsActive {
//             return fmt.Errorf("reports_to employee is not active")
//         }
//     }

//     user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
//     if err != nil {
//         user, err = s.userService.CreateUser(ctx, &UserCreateRequest{
//             Username:          req.Username,
//             FullName:          req.FullName,
//             PhoneNumber:       req.PhoneNumber,
//             DeviceID:          "company-assigned",
//             DeviceFingerprint: "company-assigned",
//             DataRegion:        company.DataRegion,
//             ConsentAgreed:     true,
//             ConsentVersion:    "v1.0",
//             KYCStatus:         models.KYCStatusPending,
//             KYCLevel:          models.KYCLevelBasic,
//         })
//         if err != nil {
//             return fmt.Errorf("failed to create user: %w", err)
//         }
//     }

//     existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
//     if existingEmp != nil && existingEmp.IsActive {
//         return fmt.Errorf("user is already an active employee in this company")
//     }

//     reportsTo := req.ReportsTo
//     if reportsTo == nil {
//         // Use the first department's head or company owner
//         if len(roleDepartments) > 0 && roleDepartments[0].DepartmentHead != nil {
//             reportsTo = roleDepartments[0].DepartmentHead
//         } else {
//             reportsTo = &company.OwnerUserID
//         }
//     }

//     emp := &models.CompanyEmployee{
//         CompanyID:  req.CompanyID,
//         UserID:     user.UserID,
//         EmployeeID: req.EmployeeID,
//         RoleID:     req.RoleID,
//         // DepartmentID is now removed from the model
//         HireDate:   time.Now().UTC(),
//         IsActive:   true,
//         ReportsTo:  reportsTo,
//         CreatedAt:  time.Now().UTC(),
//         UpdatedAt:  time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
//         return fmt.Errorf("failed to add employee: %w", err)
//     }

//     s.logger.Info("Employee added successfully",
//         util.String("company_id", req.CompanyID.String()),
//         util.String("user_id", user.UserID.String()),
//         util.String("employee_id", req.EmployeeID),
//         util.String("role_id", req.RoleID.String()),
//         util.String("role_name", role.RoleName),
//         util.Duration("duration", time.Since(start)))

//     return nil
// }
// // // ============================================================================
// // // ADVANCED COMPANY SEARCH SERVICE METHODS
// // // ============================================================================

// // type SearchCompaniesRequest struct {
// //     Query       string                `json:"query" validate:"required,min=2"`
// //     SearchType  string                `json:"search_type" validate:"oneof=fulltext autocomplete all"`
// //     Filters     *models.CompanySearchFilters `json:"filters,omitempty"` // <-- Use models.CompanySearchFilters
// //     Limit       int                   `json:"limit" validate:"min=1,max=100"`
// //     Offset      int                   `json:"offset" validate:"min=0"`
// //     SortBy      string                `json:"sort_by" validate:"oneof=relevance name created_at"`
// //     SortOrder   string                `json:"sort_order" validate:"oneof=asc desc"`
// // }

// // // SearchCompanies searches companies with advanced text search
// // func (s *CompanyService) SearchCompanies(
// //     ctx context.Context,
// //     req *SearchCompaniesRequest,
// // ) (*models.SearchCompaniesResponse, error) {
    
// //     start := time.Now()

// //     // Check admin permission for global search
// //     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
// //     if err != nil {
// //         return nil, fmt.Errorf("permission check failed: %w", err)
// //     }
// //     if !hasPermission {
// //         return nil, fmt.Errorf("insufficient permissions to search companies")
// //     }

// //     // Auto-detect search type based on query length
// //     searchType := req.SearchType
// //     if searchType == "all" {
// //         if len(req.Query) < 3 {
// //             searchType = "autocomplete"
// //         } else {
// //             searchType = "fulltext"
// //         }
// //     }

// //     // Search in repository
// //     companies, total, err := s.companyRepo.SearchCompaniesByName(
// //         ctx, 
// //         req.Query, 
// //         searchType, 
// //         req.Filters, 
// //         req.Limit, 
// //         req.Offset,
// //     )
    
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to search companies: %w", err)
// //     }

// //     // Convert to search results
// //     searchResults := make([]*CompanySearchResult, len(companies))
// //     for i, company := range companies {
// //         searchResults[i] = &CompanySearchResult{
// //             Company:       company,
// //             MatchType:     searchType,
// //             RelevanceScore: 1.0 - (float64(i) * 0.01), // Simple ranking
// //         }
// //     }

// //     // Calculate pagination info
// //     page := (req.Offset / req.Limit) + 1
// //     hasMore := req.Offset+req.Limit < total

// //     response := &SearchCompaniesResponse{
// //         Companies: searchResults,
// //         Total:     total,
// //         Page:      page,
// //         PageSize:  req.Limit,
// //         HasMore:   hasMore,
// //     }

// //     s.logger.Info("Company search completed",
// //         util.String("query", req.Query),
// //         util.String("search_type", searchType),
// //         util.Int("results", len(companies)),
// //         util.Int("total", total),
// //         util.Duration("duration", time.Since(start)))

// //     return response, nil
// // }

// // // SearchCompaniesByOwner searches companies owned by a specific user
// // func (s *CompanyService) SearchCompaniesByOwner(
// //     ctx context.Context,
// //     ownerID uuid.UUID,
// //     query string,
// //     isActive *bool,
// //     limit, offset int,
// // ) (*SearchCompaniesResponse, error) {
    
// //     start := time.Now()

// //     // Check if requester has permission to view these companies
// //     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
// //     if err != nil {
// //         return nil, fmt.Errorf("permission check failed: %w", err)
// //     }
    
// //     // For non-admins, ensure they can only search their own companies
// //     if !hasPermission {
// //         currentUserID, ok := ctx.Value("user_id").(string)
// //         if !ok {
// //             return nil, fmt.Errorf("user ID not found in context")
// //         }
        
// //         requesterID, err := uuid.Parse(currentUserID)
// //         if err != nil {
// //             return nil, fmt.Errorf("invalid user ID in context")
// //         }
        
// //         if requesterID != ownerID {
// //             return nil, fmt.Errorf("can only search your own companies")
// //         }
// //     }

// //     companies, total, err := s.companyRepo.SearchCompaniesByOwnerAndName(
// //         ctx, ownerID, query, isActive, limit, offset,
// //     )
    
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to search owner companies: %w", err)
// //     }

// //     searchResults := make([]*CompanySearchResult, len(companies))
// //     for i, company := range companies {
// //         searchResults[i] = &CompanySearchResult{
// //             Company:       company,
// //             MatchType:     "owner_search",
// //             RelevanceScore: 1.0,
// //         }
// //     }

// //     page := (offset / limit) + 1
// //     hasMore := offset+limit < total

// //     response := &SearchCompaniesResponse{
// //         Companies: searchResults,
// //         Total:     total,
// //         Page:      page,
// //         PageSize:  limit,
// //         HasMore:   hasMore,
// //     }

// //     s.logger.Info("Owner company search completed",
// //         util.String("owner_id", ownerID.String()),
// //         util.String("query", query),
// //         util.Int("results", len(companies)),
// //         util.Duration("duration", time.Since(start)))

// //     return response, nil
// // }

// // // GetCompanySuggestions provides autocomplete suggestions for company names
// // func (s *CompanyService) GetCompanySuggestions(
// //     ctx context.Context,
// //     prefix string,
// //     limit int,
// // ) ([]string, error) {
    
// //     // Check permission
// //     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
// //     if err != nil {
// //         return nil, fmt.Errorf("permission check failed: %w", err)
// //     }
// //     if !hasPermission {
// //         return nil, fmt.Errorf("insufficient permissions to get suggestions")
// //     }

// //     if len(prefix) < 2 {
// //         return []string{}, nil
// //     }

// //     suggestions, err := s.companyRepo.GetCompanySuggestions(ctx, prefix, limit)
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to get suggestions: %w", err)
// //     }

// //     s.logger.Debug("Company suggestions generated",
// //         util.String("prefix", prefix),
// //         util.Int("suggestions", len(suggestions)))

// //     return suggestions, nil
// // }

// // // GetCompanySearchAnalytics gets analytics about company search performance
// // func (s *CompanyService) GetCompanySearchAnalytics(
// //     ctx context.Context,
// // ) (map[string]interface{}, error) {
    
// //     // Check admin permission
// //     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.audit.logs.view")
// //     if err != nil {
// //         return nil, fmt.Errorf("permission check failed: %w", err)
// //     }
// //     if !hasPermission {
// //         return nil, fmt.Errorf("insufficient permissions to view analytics")
// //     }

// //     stats, err := s.companyRepo.GetCompanySearchStats(ctx)
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to get search stats: %w", err)
// //     }

// //     // Get additional analytics
// //     companyCount, err := s.companyRepo.GetCompanyStats(ctx, uuid.Nil)
// //     if err != nil {
// //         s.logger.Warn("Failed to get company stats", util.ErrorField(err))
// //     } else {
// //         stats["company_metrics"] = companyCount
// //     }

// //     s.logger.Info("Company search analytics retrieved",
// //         util.Any("stats", stats))

// //     return stats, nil
// // }

// // // BenchmarkCompanySearch benchmarks the search performance
// // func (s *CompanyService) BenchmarkCompanySearch(
// //     ctx context.Context,
// //     testQueries []string,
// //     iterations int,
// // ) (map[string]interface{}, error) {
    
// //     if iterations <= 0 || iterations > 100 {
// //         iterations = 10
// //     }

// //     results := make(map[string]interface{})
// //     queryTimes := make(map[string][]time.Duration)

// //     for _, query := range testQueries {
// //         queryTimes[query] = make([]time.Duration, 0, iterations)
        
// //         for i := 0; i < iterations; i++ {
// //             start := time.Now()
            
// //             _, _, err := s.companyRepo.SearchCompaniesByName(
// //                 ctx, query, "fulltext", nil, 10, 0,
// //             )
            
// //             if err != nil {
// //                 s.logger.Warn("Benchmark query failed", 
// //                     util.String("query", query),
// //                     util.ErrorField(err))
// //                 continue
// //             }
            
// //             duration := time.Since(start)
// //             queryTimes[query] = append(queryTimes[query], duration)
// //         }
// //     }

// //     // Calculate statistics
// //     stats := make(map[string]map[string]interface{})
// //     for query, durations := range queryTimes {
// //         if len(durations) == 0 {
// //             continue
// //         }
        
// //         var total time.Duration
// //         var min, max time.Duration = durations[0], durations[0]
        
// //         for _, d := range durations {
// //             total += d
// //             if d < min {
// //                 min = d
// //             }
// //             if d > max {
// //                 max = d
// //             }
// //         }
        
// //         avg := total / time.Duration(len(durations))
        
// //         stats[query] = map[string]interface{}{
// //             "iterations": len(durations),
// //             "avg_ms":     avg.Milliseconds(),
// //             "min_ms":     min.Milliseconds(),
// //             "max_ms":     max.Milliseconds(),
// //             "total_ms":   total.Milliseconds(),
// //         }
// //     }

// //     results["benchmark_results"] = stats
// //     results["test_queries"] = testQueries
// //     results["iterations"] = iterations
// //     results["timestamp"] = time.Now().UTC()

// //     s.logger.Info("Company search benchmark completed",
// //         util.Any("results", results))

// //     return results, nil
// // }


// // ============================================================================
// // ADVANCED COMPANY SEARCH SERVICE METHODS
// // ============================================================================

// type SearchCompaniesRequest = models.CompanySearchRequest
// type SearchCompaniesResponse = models.CompanySearchResponse
// type CompanySearchResult = models.CompanySearchResult

// // SearchCompanies performs advanced search using filters & types
// func (s *CompanyService) SearchCompanies(
//     ctx context.Context,
//     req *models.CompanySearchRequest,
// ) (*models.CompanySearchResponse, error) {

//     start := time.Now()

//     // Permission check
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return nil, fmt.Errorf("insufficient permissions to search companies")
//     }

//     // Auto-select search type if needed
//     searchType := req.SearchType
//     if searchType == "all" {
//         if len(req.Query) < 3 {
//             searchType = "autocomplete"
//         } else {
//             searchType = "fulltext"
//         }
//     }

//     // Repository call
//     companies, total, err := s.companyRepo.SearchCompaniesByName(
//         ctx,
//         req.Query,
//         searchType,
//         req.Filters,
//         req.Limit,
//         req.Offset,
//     )
//     if err != nil {
//         return nil, fmt.Errorf("failed to search companies: %w", err)
//     }

//     // Convert to search result with relevance
//     // Replace lines around 3348 with:
// 	results := make([]*models.CompanySearchResult, len(companies))
// 	for i, company := range companies {
// 		results[i] = &models.CompanySearchResult{
// 			CompanyID:          company.CompanyID,
// 			CompanyName:        company.CompanyName,
// 			OwnerUserID:        company.OwnerUserID,
// 			SubscriptionTier:   company.SubscriptionTier,
// 			SubscriptionStatus: company.SubscriptionStatus,
// 			MaxEmployees:       company.MaxEmployees,
// 			IsActive:           company.IsActive,
// 			DataRegion:         company.DataRegion,
// 			CreatedAt:          company.CreatedAt,
// 			RelevanceScore:     1.0 - (float64(i) * 0.01),
// 			MatchType:          searchType,
// 		}
// 	}    // Pagination
//     page := (req.Offset / req.Limit) + 1
//     hasMore := req.Offset+req.Limit < total

//     resp := &models.CompanySearchResponse{
//         Companies: results,
//         Total:     total,
//         Page:      page,
//         PageSize:  req.Limit,
//         HasMore:   hasMore,
//     }

//     s.logger.Info("Company search completed",
//         util.String("query", req.Query),
//         util.String("search_type", searchType),
//         util.Int("results", len(results)),
//         util.Int("total", total),
//         util.Duration("duration", time.Since(start)),
//     )

//     return resp, nil
// }

// // SearchCompaniesByOwner searches companies by owner with enhanced search
// func (s *CompanyService) SearchCompaniesByOwner(
//     ctx context.Context,
//     ownerID uuid.UUID,
//     query string,
//     isActive *bool,
//     limit int,
//     offset int,
// ) (*models.CompanySearchResponse, error) {

//     start := time.Now()

//     // Permission check
//     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }

//     // Non-admins can only view their own companies
//     if !hasPermission {
//         currentUserIDStr, ok := ctx.Value("user_id").(string)
//         if !ok {
//             return nil, fmt.Errorf("user ID missing in context")
//         }
//         currentUserID, _ := uuid.Parse(currentUserIDStr)
//         if currentUserID != ownerID {
//             return nil, fmt.Errorf("can only search your own companies")
//         }
//     }

//     companies, total, err := s.companyRepo.SearchCompaniesByOwnerAndName(
//         ctx, ownerID, query, isActive, limit, offset,
//     )
//     if err != nil {
//         return nil, fmt.Errorf("failed to search owner companies: %w", err)
//     }

//     // Convert to search result with relevance
//     results := make([]*models.CompanySearchResult, len(companies))
//     for i, company := range companies {
//         // Determine match type based on query
//         matchType := "owner_search"
//         if query != "" {
//             if len(query) < 3 {
//                 matchType = "autocomplete"
//             } else {
//                 matchType = "fulltext"
//             }
//         }
        
//         results[i] = &models.CompanySearchResult{
//             CompanyID:          company.CompanyID,
//             CompanyName:        company.CompanyName,
//             OwnerUserID:        company.OwnerUserID,
//             SubscriptionTier:   company.SubscriptionTier,
//             SubscriptionStatus: company.SubscriptionStatus,
//             MaxEmployees:       company.MaxEmployees,
//             IsActive:           company.IsActive,
//             DataRegion:         company.DataRegion,
//             CreatedAt:          company.CreatedAt,
//             RelevanceScore:     1.0 - (float64(i) * 0.01),
//             MatchType:          matchType,  // Fixed: using matchType instead of undefined searchType
//         }
//     }

//     page := (offset / limit) + 1
//     hasMore := offset+limit < total

//     resp := &models.CompanySearchResponse{
//         Companies: results,
//         Total:     total,
//         Page:      page,
//         PageSize:  limit,
//         HasMore:   hasMore,
//     }

//     s.logger.Info("Owner company search completed",
//         util.String("owner_id", ownerID.String()),
//         util.String("query", query),
//         util.Int("results", len(results)),
//         util.Duration("duration", time.Since(start)),
//     )

//     return resp, nil
// }
// // Autocomplete suggestions
// func (s *CompanyService) GetCompanySuggestions(
//     ctx context.Context,
//     prefix string,
//     limit int,
// ) ([]string, error) {

//     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.view")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return nil, fmt.Errorf("insufficient permissions")
//     }

//     if len(prefix) < 2 {
//         return []string{}, nil
//     }

//     suggestions, err := s.companyRepo.GetCompanySuggestions(ctx, prefix, limit)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get suggestions: %w", err)
//     }

//     return suggestions, nil
// }

// // Search analytics
// func (s *CompanyService) GetCompanySearchAnalytics(
//     ctx context.Context,
// ) (map[string]interface{}, error) {

//     hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.audit.logs.view")
//     if err != nil {
//         return nil, fmt.Errorf("permission check failed: %w", err)
//     }
//     if !hasPermission {
//         return nil, fmt.Errorf("insufficient permissions")
//     }

//     stats, err := s.companyRepo.GetCompanySearchStats(ctx)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get search stats: %w", err)
//     }

//     companyMetrics, err := s.companyRepo.GetCompanyStats(ctx, uuid.Nil)
//     if err == nil {
//         stats["company_metrics"] = companyMetrics
//     }

//     return stats, nil
// }

// // Benchmark search performance
// func (s *CompanyService) BenchmarkCompanySearch(
//     ctx context.Context,
//     testQueries []string,
//     iterations int,
// ) (map[string]interface{}, error) {

//     if iterations <= 0 || iterations > 100 {
//         iterations = 10
//     }

//     results := make(map[string]interface{})

//     queryTimes := map[string][]time.Duration{}

//     for _, q := range testQueries {
//         for i := 0; i < iterations; i++ {
//             start := time.Now()
//             _, _, err := s.companyRepo.SearchCompaniesByName(ctx, q, "fulltext", nil, 10, 0)

//             if err == nil {
//                 queryTimes[q] = append(queryTimes[q], time.Since(start))
//             }
//         }
//     }

//     stats := map[string]map[string]interface{}{}
//     for query, durations := range queryTimes {
//         if len(durations) == 0 {
//             continue
//         }

//         var total time.Duration
//         min, max := durations[0], durations[0]

//         for _, d := range durations {
//             total += d
//             if d < min {
//                 min = d
//             }
//             if d > max {
//                 max = d
//             }
//         }

//         avg := total / time.Duration(len(durations))

//         stats[query] = map[string]interface{}{
//             "iterations": len(durations),
//             "avg_ms":     avg.Milliseconds(),
//             "min_ms":     min.Milliseconds(),
//             "max_ms":     max.Milliseconds(),
//             "total_ms":   total.Milliseconds(),
//         }
//     }

//     results["benchmark_results"] = stats
//     results["test_queries"] = testQueries
//     results["iterations"] = iterations
//     results["timestamp"] = time.Now().UTC()

//     return results, nil
// }
// // CreateDepartment creates a new department (admin only)
// func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
// 	start := time.Now()

// 	// 1. Only admin sessions can create departments
// 	sessionType, ok := ctx.Value("session_type").(string)
// 	if !ok || sessionType != "admin" {
// 		return nil, fmt.Errorf("only admin users can create departments")
// 	}

// 	// Get admin ID from context for audit logging
// 	adminID, ok := ctx.Value("user_id").(string)
// 	if !ok {
// 		return nil, fmt.Errorf("admin ID not found in context")
// 	}
// 	adminIDParsed, err := uuid.Parse(adminID)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid admin ID in context")
// 	}

// 	// 2. Validate company exists and is active
// 	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("company not found: %w", err)
// 	}
// 	if !company.IsActive {
// 		return nil, fmt.Errorf("company is not active")
// 	}

// 	// 3. Validate system department exists
// 	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, req.SystemDepartmentID)
// 	if err != nil {
// 		return nil, fmt.Errorf("system department not found: %w", err)
// 	}

// 	// 4. Check for duplicate department name in the same company
// 	// Get all departments for this company
// 	departments, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, req.CompanyID, 1000, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to check existing departments: %w", err)
// 	}

// 	// Check for duplicate department name (case-insensitive)
// 	for _, dept := range departments {
// 		if strings.EqualFold(dept.DepartmentName, req.DepartmentName) {
// 			return nil, fmt.Errorf("department with name '%s' already exists in this company", req.DepartmentName)
// 		}
// 	}

// 	// 5. Check for duplicate system department in the same company
// 	// First, let's check if any department is already linked to this system department
// 	// We need to get all departments and check their system_department_id
// 	for _, dept := range departments {
// 		if dept.SystemDepartmentID != nil && *dept.SystemDepartmentID == req.SystemDepartmentID {
// 			return nil, fmt.Errorf("system department '%s' is already assigned to another department in this company", systemDept.Name)
// 		}
// 	}

// 	// 6. Validate department head if provided
// 	if req.DepartmentHead != nil {
// 		// Check if department head exists and is active in the company
// 		employee, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.DepartmentHead)
// 		if err != nil {
// 			return nil, fmt.Errorf("department head not found: %w", err)
// 		}
// 		if !employee.IsActive {
// 			return nil, fmt.Errorf("department head is not an active employee")
// 		}
// 	}

// 	// 7. Validate parent department if provided
// 	if req.ParentDepartmentID != nil {
// 		parentDept, err := s.companyRepo.GetDepartment(ctx, *req.ParentDepartmentID)
// 		if err != nil {
// 			return nil, fmt.Errorf("parent department not found: %w", err)
// 		}
// 		if parentDept.CompanyID != req.CompanyID {
// 			return nil, fmt.Errorf("parent department does not belong to this company")
// 		}
// 	}

// 	// Create the department
// 	department := &models.Department{
// 		DepartmentID:       uuid.New(),
// 		CompanyID:          req.CompanyID,
// 		DepartmentName:     req.DepartmentName,
// 		SystemDepartmentID: &req.SystemDepartmentID,
// 		DepartmentHead:     req.DepartmentHead,
// 		ParentDepartmentID: req.ParentDepartmentID,
// 		IsActive:           true,
// 		CreatedAt:          time.Now().UTC(),
// 		UpdatedAt:          time.Now().UTC(),
// 	}

// 	// 8. Create the department
// 	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
// 		// Check if error is due to duplicate constraint
// 		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
// 			return nil, fmt.Errorf("department with name '%s' already exists in this company", req.DepartmentName)
// 		}
// 		return nil, fmt.Errorf("failed to create department: %w", err)
// 	}

// 	// Auto-assign the department to the owner role for admin access
// 	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, req.CompanyID, 1000)
// 	if err == nil && ownerRole != nil {
// 		// Create role-department mapping for the owner
// 		if err := s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID); err != nil {
// 			s.logger.Warn("Failed to auto-assign department to owner role",
// 				util.ErrorField(err),
// 				util.String("company_id", req.CompanyID.String()),
// 				util.String("department_id", department.DepartmentID.String()),
// 				util.String("owner_role_id", ownerRole.RoleID.String()))
// 		}
// 	}

// 	s.logger.Info("Department created successfully by admin",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("company_name", company.CompanyName),
// 		util.String("department_id", department.DepartmentID.String()),
// 		util.String("department_name", req.DepartmentName),
// 		util.String("system_department", systemDept.Name),
// 		util.String("system_module", systemDept.ModuleCode),
// 		util.String("created_by", adminIDParsed.String()),
// 		util.Duration("duration", time.Since(start)))

// 	return department, nil
// }



// // Add this to company_service.go
// func (s *CompanyService) GetCompanyContextForCompany(ctx context.Context, userID, companyID uuid.UUID) (*CompanyContext, error) {
//     // Get employee record for THIS specific company
//     employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
//     if err != nil {
//         return nil, fmt.Errorf("employee not found in company: %w", err)
//     }

//     if !employee.IsActive {
//         return nil, fmt.Errorf("employee is not active in this company")
//     }

//     company, err := s.companyRepo.GetCompany(ctx, companyID)
//     if err != nil {
//         return nil, fmt.Errorf("company not found: %w", err)
//     }

//     // Check company subscription status
//     if company.SubscriptionEndDate != nil && company.SubscriptionEndDate.Before(time.Now()) {
//         return nil, fmt.Errorf("subscription status: company subscription has expired")
//     }

//     if !company.IsActive {
//         return nil, fmt.Errorf("company is not active")
//     }

//     role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
//     if err != nil {
//         return nil, fmt.Errorf("role not found: %w", err)
//     }

//     var departmentName, systemModule string
//     if employee.DepartmentID != nil {
//         dept, err := s.companyRepo.GetDepartment(ctx, *employee.DepartmentID)
//         if err == nil {
//             departmentName = dept.DepartmentName
//             if dept.SystemDepartmentID != nil {
//                 systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
//                 if err == nil {
//                     systemModule = systemDept.ModuleCode
//                 }
//             }
//         }
//     }

//     permissions, err := s.companyRepo.GetUserPermissions(ctx, companyID, userID)
//     if err != nil {
//         s.logger.Warn("failed to get employee permissions", util.ErrorField(err))
//         permissions = []*models.Permission{}
//     }

//     permStrings := make([]string, len(permissions))
//     for i, perm := range permissions {
//         permStrings[i] = perm.PermissionName
//     }

//     return &CompanyContext{
//         CompanyID:        company.CompanyID.String(),
//         EmployeeID:       employee.EmployeeID,
//         RoleID:           employee.RoleID.String(),
//         RoleLevel:        role.RoleLevel,
//         RoleName:         role.RoleName,
//         DepartmentID:     employee.DepartmentID.String(),
//         DepartmentName:   departmentName,
//         SystemModule:     systemModule,
//         Permissions:      permStrings,
//         SubscriptionTier: company.SubscriptionTier,
//         IsOwner:          company.OwnerUserID == userID,
//         IsManager:        role.RoleLevel <= 200,
//     }, nil
// }


// // GetEmployeesByUser retrieves all company employees for a user
// func (s *CompanyService) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
//     return s.companyRepo.GetEmployeesByUser(ctx, userID)
// }

// // // GetCompaniesByEmployeePhone gets all companies where a user is an active employee by phone number
// // func (s *CompanyService) GetCompaniesByEmployeePhone(ctx context.Context, employeePhone string) ([]*models.Company, error) {
// //     start := time.Now()
    
// //     // 1. Get user by phone number
// //     user, err := s.userService.GetUserByPhone(ctx, employeePhone)
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to get user by phone: %w", err)
// //     }
    
// //     // 2. Get all employee records for this user
// //     employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
// //     if err != nil {
// //         return nil, fmt.Errorf("failed to get employee records: %w", err)
// //     }
    
// //     // 3. Filter for active employees and collect unique companies
// //     var companies []*models.Company
// //     seenCompanies := make(map[uuid.UUID]bool)
    
// //     for _, emp := range employees {
// //         // Skip if not active or already processed this company
// //         if !emp.IsActive || seenCompanies[emp.CompanyID] {
// //             continue
// //         }
        
// //         // Get company details
// //         company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
// //         if err != nil {
// //             s.logger.Warn("Failed to get company",
// //                 util.String("company_id", emp.CompanyID.String()),
// //                 util.ErrorField(err))
// //             continue
// //         }
        
// //         // Only include active companies
// //         if company.IsActive {
// //             companies = append(companies, company)
// //             seenCompanies[emp.CompanyID] = true
// //         }
// //     }
    
// //     s.logger.Debug("GetCompaniesByEmployeePhone completed",
// //         util.String("phone", employeePhone),
// //         util.String("user_id", user.UserID.String()),
// //         util.Int("total_companies", len(companies)),
// //         util.Duration("duration", time.Since(start)))
    
// //     if len(companies) == 0 {
// //         return nil, fmt.Errorf("no active companies found for employee with phone: %s", employeePhone)
// //     }
    
// //     return companies, nil
// // }


// // internal/service/company_service.go
// // Add this new method to the CompanyService struct

// // GetCompaniesByEmployeePhone gets ALL companies where a user is an active employee by phone number
// func (s *CompanyService) GetCompaniesByEmployeePhone(ctx context.Context, employeePhone string) ([]*models.Company, error) {
//     start := time.Now()
    
//     // 1. Get user by phone number
//     user, err := s.userService.GetUserByPhone(ctx, employeePhone)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get user by phone: %w", err)
//     }
    
//     // 2. Get all employee records for this user
//     employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get employee records: %w", err)
//     }
    
//     // 3. Filter for active employees and collect unique companies
//     var companies []*models.Company
//     seenCompanies := make(map[uuid.UUID]bool)
    
//     for _, emp := range employees {
//         // Skip if not active or already processed this company
//         if !emp.IsActive || seenCompanies[emp.CompanyID] {
//             continue
//         }
        
//         // Get company details
//         company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
//         if err != nil {
//             s.logger.Warn("Failed to get company",
//                 util.String("company_id", emp.CompanyID.String()),
//                 util.ErrorField(err))
//             continue
//         }
        
//         // Only include active companies
//         if company.IsActive {
//             companies = append(companies, company)
//             seenCompanies[emp.CompanyID] = true
//         }
//     }
    
//     s.logger.Debug("GetCompaniesByEmployeePhone completed",
//         util.String("phone", employeePhone),
//         util.String("user_id", user.UserID.String()),
//         util.Int("total_employee_records", len(employees)),
//         util.Int("active_companies", len(companies)),
//         util.Duration("duration", time.Since(start)))
    
//     if len(companies) == 0 {
//         return nil, fmt.Errorf("no active companies found for employee with phone: %s", employeePhone)
//     }
    
//     return companies, nil
// }


// // ValidateUserAccessToDepartment checks if user has access to a department
// func (s *CompanyService) ValidateUserAccessToDepartment(ctx context.Context, companyID, userID, departmentID uuid.UUID) (bool, error) {
//     // Get user's accessible departments
//     departments, _, err := s.ListDepartments(ctx, companyID, 1000, 0, false)
//     if err != nil {
//         return false, err
//     }

//     for _, dept := range departments {
//         if dept.DepartmentID == departmentID {
//             return true, nil
//         }
//     }
//     return false, nil
// }

// // ValidateUserAccessToPermission checks if user has a specific permission
// func (s *CompanyService) ValidateUserAccessToPermission(ctx context.Context, userID, permissionID uuid.UUID) (bool, error) {
//     userPermissions, err := s.GetUserPermissions(ctx, userID)
//     if err != nil {
//         return false, err
//     }

//     for _, perm := range userPermissions {
//         if perm.PermissionID == permissionID {
//             return true, nil
//         }
//     }
//     return false, nil
// }

// // ValidatePermissionsExist checks if all permission IDs exist in the system
// func (s *CompanyService) ValidatePermissionsExist(ctx context.Context, permissionIDs []uuid.UUID) (bool, error) {
//     allPerms, err := s.GetAllPermissions(ctx, "", "", "")
//     if err != nil {
//         return false, err
//     }

//     permMap := make(map[uuid.UUID]bool)
//     for _, perm := range allPerms {
//         permMap[perm.PermissionID] = true
//     }

//     for _, permID := range permissionIDs {
//         if !permMap[permID] {
//             return false, fmt.Errorf("permission not found: %s", permID)
//         }
//     }

//     return true, nil
// }

// // ValidatePermissionIDsExist checks if all permission IDs exist in the system
// func (s *CompanyService) ValidatePermissionIDsExist(ctx context.Context, permissionIDs []uuid.UUID) (bool, map[uuid.UUID]*models.Permission, error) {
//     allPerms, err := s.GetAllPermissions(ctx, "", "", "")
//     if err != nil {
//         return false, nil, err
//     }

//     permMap := make(map[uuid.UUID]*models.Permission)
//     for _, perm := range allPerms {
//         permMap[perm.PermissionID] = perm
//     }

//     missingPerms := make([]uuid.UUID, 0)
//     for _, permID := range permissionIDs {
//         if _, exists := permMap[permID]; !exists {
//             missingPerms = append(missingPerms, permID)
//         }
//     }

//     if len(missingPerms) > 0 {
//         return false, nil, fmt.Errorf("permissions not found: %v", missingPerms)
//     }

//     return true, permMap, nil
// }