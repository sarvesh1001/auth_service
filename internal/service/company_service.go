package service

import (
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/util"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CompanyService struct {
	companyRepo postgres.CompanyRepository
	userService *UserService
	logger      *zap.Logger
}

type BulkAssignment struct {
	UserID    uuid.UUID `json:"user_id"`
	RoleID    uuid.UUID `json:"role_id"`
	ReportsTo uuid.UUID `json:"reports_to,omitempty"`
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
	CompanyName        string   `json:"company_name"`
	OwnerPhone         string   `json:"owner_phone"`
	OwnerUsername      string   `json:"owner_username"`
	OwnerFullName      string   `json:"owner_full_name"`
	OwnerPositionTitle string   `json:"owner_position_title"`
	SubscriptionTier   string   `json:"subscription_tier"`
	MaxEmployees       int      `json:"max_employees"`
	MaxDepartments     int      `json:"max_departments"`
	DataRegion         string   `json:"data_region"`
	SubscriptionMonths int      `json:"subscription_months"`
	SubscriptionDays   int      `json:"subscription_days"`
	Departments        []string `json:"departments"`
}

func (s *CompanyService) CreateCompany(
	ctx context.Context,
	req *CreateCompanyRequest,
	createdBy uuid.UUID,
) (*models.Company, error) {
	start := time.Now()

	if req.MaxDepartments < 1 || req.MaxDepartments > 100 {
		return nil, fmt.Errorf("max_departments must be between 1 and 100")
	}

	totalDepartments := len(req.Departments) + 1
	if totalDepartments > req.MaxDepartments {
		return nil, fmt.Errorf(
			"cannot create company: requested %d departments exceeds max_departments limit of %d",
			totalDepartments,
			req.MaxDepartments,
		)
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
			util.String("provided_full_name", req.OwnerFullName),
		)
	}

	exists, err := s.companyRepo.CheckCompanyExists(ctx, req.CompanyName, ownerUser.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate company: %w", err)
	}
	if exists {
		return nil, fmt.Errorf(
			"company with name '%s' already exists for this owner",
			req.CompanyName,
		)
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
		MaxDepartments:        req.MaxDepartments,
		DataRegion:            req.DataRegion,
		IsActive:              true,
		CreatedAt:             now,
		UpdatedAt:             now,
		SubscriptionStartDate: &now,
		SubscriptionEndDate:   &subscriptionEnd,
	}

	if err := s.companyRepo.CreateCompany(
		ctx,
		company,
		req.Departments,
		req.OwnerPositionTitle,
	); err != nil {
		return nil, fmt.Errorf("failed to create company: %w", err)
	}

	s.logger.Info("Company created successfully by admin",
		util.String("company_id", companyID.String()),
		util.String("company_name", req.CompanyName),
		util.String("owner_user_id", ownerUser.UserID.String()),
		util.String("owner_username", ownerUser.Username),
		util.String("owner_phone", req.OwnerPhone),
		util.String("owner_position_title", req.OwnerPositionTitle),
		util.String("created_by", createdBy.String()),
		util.String("subscription_tier", req.SubscriptionTier),
		util.Int("max_departments", req.MaxDepartments),
		util.Int("initial_departments", totalDepartments),
		util.Duration("duration", time.Since(start)),
	)

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
	PositionID  *uuid.UUID `json:"position_id,omitempty"`
}

type AddManagerRequest struct {
	CompanyID   uuid.UUID  `json:"company_id" validate:"required"`
	PhoneNumber string     `json:"phone" validate:"required"`
	Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
	FullName    string     `json:"full_name" validate:"required,max=255"`
	RoleID      uuid.UUID  `json:"role_id" validate:"required"`
	ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
	EmployeeID  string     `json:"employee_id,omitempty"`
	PositionID  *uuid.UUID `json:"position_id,omitempty"`
}

type GrantRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
}

func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
	_, err := s.companyRepo.GetRole(ctx, req.RoleID)
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

	roleInDepartment := true
	result.Checks["role_belongs_to_department"] = roleInDepartment

	if !roleInDepartment {
		result.Message = "Role is not assigned to any department"
		return result, nil
	}

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
	return s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive)
}

func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
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

func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}

func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
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

func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, updatedBy uuid.UUID) error {
	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	department.DepartmentName = name
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

func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID, revokedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
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

	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
		return fmt.Errorf("failed to reactivate company: %w", err)
	}

	s.logger.Info("Company reactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("reactivated_by", reactivatedBy.String()))
	return nil
}

func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
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

func (s *CompanyService) GetPermissionsByDepartmentModules(ctx context.Context, departmentIDs []uuid.UUID) ([]*models.Permission, error) {
	if len(departmentIDs) == 0 {
		return []*models.Permission{}, nil
	}

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

	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, "", "", "")
}

func (s *CompanyService) ValidatePermissionDepartmentCompatibility(ctx context.Context, departmentIDs []uuid.UUID, permissionIDs []uuid.UUID) (bool, string, error) {
	if len(departmentIDs) == 0 || len(permissionIDs) == 0 {
		return true, "", nil
	}

	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return false, "", fmt.Errorf("failed to get permissions: %w", err)
	}

	permMap := make(map[uuid.UUID]*models.Permission)
	for _, perm := range allPerms {
		permMap[perm.PermissionID] = perm
	}

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

	for _, permID := range permissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return false, "", fmt.Errorf("permission not found: %s", permID)
		}

		if !departmentModules[perm.Module] {
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

	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
	if err != nil {
		return fmt.Errorf("failed to check role assignments: %w", err)
	}

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

func (s *CompanyService) CreateRoleAdmin(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	for _, deptID := range req.DepartmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
		if err != nil {
			return nil, fmt.Errorf("department not found: %s", deptID)
		}
		if dept.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("department %s does not belong to company", deptID)
		}
	}

	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all permissions: %w", err)
	}

	permMap := make(map[uuid.UUID]*models.Permission)
	for _, perm := range allPerms {
		permMap[perm.PermissionID] = perm
	}

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

	for _, permID := range req.PermissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return nil, fmt.Errorf("permission not found: %s", permID)
		}

		if !departmentModules[perm.Module] {
			var deptNames []string
			for _, deptID := range req.DepartmentIDs {
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

			return nil, fmt.Errorf(
				"permission '%s' (module: %s) cannot be assigned to departments [%s]. "+
					"Permissions must match the department modules [%s]",
				perm.PermissionName, perm.Module,
				strings.Join(deptNames, ", "),
				strings.Join(moduleNames, ", "))
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

	var moduleNames []string
	for module := range departmentModules {
		if systemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, module); err == nil {
			moduleNames = append(moduleNames, systemDept.Name)
		}
	}

	s.logger.Info("Role created successfully by admin",
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

func (s *CompanyService) GrantRolePermissionAdmin(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate permission: %w", err)
	}

	permissionExists := false
	for _, perm := range allPerms {
		if perm.PermissionID == permissionID {
			permissionExists = true
			break
		}
	}

	if !permissionExists {
		return fmt.Errorf("permission not found: %s", permissionID)
	}

	if err := s.companyRepo.GrantRolePermission(ctx, roleID, permissionID, grantedBy); err != nil {
		return fmt.Errorf("failed to grant role permission: %w", err)
	}

	s.logger.Info("Role permission granted by admin",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()),
		util.String("granted_by", grantedBy.String()))
	return nil
}

func (s *CompanyService) RevokeRolePermissionAdmin(ctx context.Context, roleID, permissionID, revokedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	if err := s.companyRepo.RevokeRolePermission(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("failed to revoke role permission: %w", err)
	}

	s.logger.Info("Role permission revoked by admin",
		util.String("role_id", roleID.String()),
		util.String("permission_id", permissionID.String()),
		util.String("revoked_by", revokedBy.String()))
	return nil
}

func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	currentUserID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in context")
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

	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all permissions: %w", err)
	}

	permMap := make(map[uuid.UUID]*models.Permission)
	for _, perm := range allPerms {
		permMap[perm.PermissionID] = perm
	}

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

	userPermissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	for _, permID := range req.PermissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return nil, fmt.Errorf("permission not found: %s", permID)
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

		if !departmentModules[perm.Module] {
			var deptNames []string
			for _, deptID := range req.DepartmentIDs {
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

			return nil, fmt.Errorf(
				"permission '%s' (module: %s) cannot be assigned to departments [%s]. "+
					"Permissions must match the department modules [%s]",
				perm.PermissionName, perm.Module,
				strings.Join(deptNames, ", "),
				strings.Join(moduleNames, ", "))
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

	var moduleNames []string
	for module := range departmentModules {
		if systemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, module); err == nil {
			moduleNames = append(moduleNames, systemDept.Name)
		}
	}

	s.logger.Info("Role created successfully",
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

func (s *CompanyService) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	currentUserID, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		return fmt.Errorf("invalid user ID in context")
	}

	userPermissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user permissions: %w", err)
	}

	userHasSpecificPermission := false
	for _, userPerm := range userPermissions {
		if userPerm.PermissionID == permissionID {
			userHasSpecificPermission = true
			break
		}
	}

	if !userHasSpecificPermission {
		allPerms, err := s.companyRepo.GetAllPermissions(ctx)
		if err != nil {
			return fmt.Errorf("permission not found: %s", permissionID)
		}

		var permissionName string
		for _, perm := range allPerms {
			if perm.PermissionID == permissionID {
				permissionName = perm.PermissionName
				break
			}
		}

		if permissionName == "" {
			return fmt.Errorf("permission not found: %s", permissionID)
		}

		return fmt.Errorf("user cannot assign permission '%s' that they don't possess", permissionName)
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

func (s *CompanyService) ValidatePermissionAssignment(ctx context.Context, assignerID uuid.UUID, permissionsToAssign []string) (bool, error) {
	assignerPermissions, err := s.GetUserPermissions(ctx, assignerID)
	if err != nil {
		return false, err
	}

	for _, perm := range assignerPermissions {
		if perm.PermissionName == "admin.permission.assign" {
			return true, nil
		}
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
		reportsTo = &company.OwnerUserID
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

	// Validate position if provided
	if req.PositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, *req.PositionID)
		if err != nil {
			return fmt.Errorf("position not found: %w", err)
		}

		if position.CompanyID != req.CompanyID {
			return fmt.Errorf("position does not belong to company")
		}

		if !position.IsOpen {
			return fmt.Errorf("position is not open for assignment")
		}

		// Check if position's department is in role's departments
		positionInRoleDept := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				positionInRoleDept = true
				break
			}
		}

		if !positionInRoleDept {
			return fmt.Errorf("position's department is not assigned to the role")
		}
	}

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
		reportsTo = &company.OwnerUserID
	}

	emp := &models.CompanyEmployee{
		CompanyID:  req.CompanyID,
		UserID:     user.UserID,
		EmployeeID: req.EmployeeID,
		RoleID:     req.RoleID,
		PositionID: req.PositionID, // NEW FIELD
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
		util.String("position_id", func() string {
			if req.PositionID != nil {
				return req.PositionID.String()
			}
			return "none"
		}()),
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

	currentUserIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, fmt.Errorf("user ID missing in context")
	}

	currentUserID, _ := uuid.Parse(currentUserIDStr)
	if currentUserID != ownerID {
		return nil, fmt.Errorf("can only search your own companies")
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

func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	start := time.Now()

	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	if !department.IsActive {
		return fmt.Errorf("department is already deactivated")
	}

	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0)
	if err != nil {
		s.logger.Warn("Failed to get roles for department",
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
	}

	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, dept := range roleDepts {
			if dept.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("cannot deactivate department that has active employees assigned to roles")
				}
				break
			}
		}
	}

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

func (s *CompanyService) DeleteDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	start := time.Now()

	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0)
	if err != nil {
		return fmt.Errorf("failed to get roles for department: %w", err)
	}

	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, dept := range roleDepts {
			if dept.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("cannot delete department that has active employees assigned to roles")
				}
				break
			}
		}
	}

	if err := s.companyRepo.RemoveAllRoleDepartments(ctx, departmentID); err != nil {
		s.logger.Warn("Failed to remove role-department mappings",
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
	}

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

type CreatePositionRequest struct {
	CompanyID    uuid.UUID `json:"company_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	Title        string    `json:"title" validate:"required,min=1,max=255"`
	IsOpen       bool      `json:"is_open" default:"true"`
}

type UpdatePositionRequest struct {
	PositionID   uuid.UUID `json:"position_id" validate:"required"`
	Title        string    `json:"title" validate:"required,min=1,max=255"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	IsOpen       bool      `json:"is_open"`
}

func (s *CompanyService) CreatePosition(
	ctx context.Context,
	req *CreatePositionRequest,
	createdBy uuid.UUID,
) (*models.Position, error) {
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return nil, fmt.Errorf("department not found: %w", err)
	}

	if department.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("department does not belong to company")
	}

	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, fmt.Errorf("user ID not found in context")
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in context")
	}

	hasAccess, err := s.ValidateUserAccessToDepartment(
		ctx,
		req.CompanyID,
		parsedUserID,
		req.DepartmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate department access: %w", err)
	}

	if !hasAccess {
		return nil, fmt.Errorf("user lacks access to this department")
	}

	exists, err := s.companyRepo.PositionExists(
		ctx,
		req.CompanyID,
		req.DepartmentID,
		req.Title,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to check position uniqueness: %w", err)
	}

	if exists {
		return nil, fmt.Errorf("position with this title already exists in the department")
	}

	now := time.Now().UTC()
	position := &models.Position{
		PositionID:   uuid.New(),
		CompanyID:    req.CompanyID,
		DepartmentID: req.DepartmentID,
		Title:        req.Title,
		IsOpen:       req.IsOpen,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.companyRepo.CreatePosition(ctx, position); err != nil {
		return nil, fmt.Errorf("failed to create position: %w", err)
	}

	s.logger.Info("Position created successfully",
		util.String("company_id", req.CompanyID.String()),
		util.String("department_id", req.DepartmentID.String()),
		util.String("position_id", position.PositionID.String()),
		util.String("title", req.Title),
		util.String("created_by", createdBy.String()),
	)

	return position, nil
}

func (s *CompanyService) GetPosition(ctx context.Context, positionID uuid.UUID) (*models.Position, error) {
	position, err := s.companyRepo.GetPosition(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}

	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, fmt.Errorf("user ID not found in context")
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in context")
	}

	isEmployee, err := s.companyRepo.IsUserActiveEmployee(ctx, position.CompanyID, parsedUserID)
	if err != nil || !isEmployee {
		return nil, fmt.Errorf("user is not an employee of this company")
	}

	return position, nil
}

func (s *CompanyService) UpdatePosition(ctx context.Context, req *UpdatePositionRequest, updatedBy uuid.UUID) error {
	existingPosition, err := s.companyRepo.GetPosition(ctx, req.PositionID)
	if err != nil {
		return fmt.Errorf("position not found: %w", err)
	}

	if req.DepartmentID != existingPosition.DepartmentID {
		newDepartment, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
		if err != nil {
			return fmt.Errorf("new department not found: %w", err)
		}
		if newDepartment.CompanyID != existingPosition.CompanyID {
			return fmt.Errorf("new department does not belong to same company")
		}

		userID, ok := ctx.Value("user_id").(string)
		if !ok {
			return fmt.Errorf("user ID not found in context")
		}

		parsedUserID, err := uuid.Parse(userID)
		if err != nil {
			return fmt.Errorf("invalid user ID in context")
		}

		hasAccess, err := s.ValidateUserAccessToDepartment(ctx, existingPosition.CompanyID, parsedUserID, req.DepartmentID)
		if err != nil || !hasAccess {
			return fmt.Errorf("user lacks access to the new department")
		}
	}

	existingPosition.Title = req.Title
	existingPosition.DepartmentID = req.DepartmentID
	existingPosition.IsOpen = req.IsOpen
	existingPosition.UpdatedAt = time.Now().UTC()

	if err := s.companyRepo.UpdatePosition(ctx, existingPosition); err != nil {
		return fmt.Errorf("failed to update position: %w", err)
	}

	s.logger.Info("Position updated successfully",
		util.String("position_id", req.PositionID.String()),
		util.String("title", req.Title),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *CompanyService) ListPositions(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID *uuid.UUID,
	onlyOpen bool,
	limit, offset int,
) ([]*models.Position, int, error) {
	var positions []*models.Position
	var total int
	var err error

	if departmentID != nil {
		positions, total, err = s.companyRepo.GetPositionsByDepartment(ctx, *departmentID, limit, offset, onlyOpen)
	} else {
		positions, total, err = s.companyRepo.GetPositionsByCompany(ctx, companyID, limit, offset, onlyOpen)
	}

	if err != nil {
		return nil, 0, fmt.Errorf("failed to list positions: %w", err)
	}

	return positions, total, nil
}

func (s *CompanyService) DeletePosition(ctx context.Context, positionID, deletedBy uuid.UUID) error {
	position, err := s.companyRepo.GetPosition(ctx, positionID)
	if err != nil {
		return fmt.Errorf("position not found: %w", err)
	}

	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, position.CompanyID, 1, 0)
	if err == nil {
		for _, emp := range employees {
			if emp.PositionID != nil && *emp.PositionID == positionID {
				return fmt.Errorf("cannot delete position that has employees assigned")
			}
		}
	}

	if err := s.companyRepo.DeletePosition(ctx, positionID); err != nil {
		return fmt.Errorf("failed to delete position: %w", err)
	}

	s.logger.Info("Position deleted successfully",
		util.String("position_id", positionID.String()),
		util.String("company_id", position.CompanyID.String()),
		util.String("deleted_by", deletedBy.String()))

	return nil
}

func (s *CompanyService) GetDepartment(
	ctx context.Context,
	departmentID uuid.UUID,
) (*models.Department, error) {
	department, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department: %w", err)
	}
	return department, nil
}

func (s *CompanyService) UpdatePositionStatus(ctx context.Context, positionID uuid.UUID, isOpen bool, updatedBy uuid.UUID) error {
	if err := s.companyRepo.UpdatePositionStatus(ctx, positionID, isOpen); err != nil {
		return fmt.Errorf("failed to update position status: %w", err)
	}

	s.logger.Info("Position status updated",
		util.String("position_id", positionID.String()),
		util.Bool("is_open", isOpen),
		util.String("updated_by", updatedBy.String()))
	return nil
}

type UpdateDepartmentParentRequest struct {
	DepartmentID       uuid.UUID  `json:"department_id" validate:"required"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id"`
}

func (s *CompanyService) UpdateDepartmentParent(
	ctx context.Context,
	req *UpdateDepartmentParentRequest,
	updatedBy uuid.UUID,
) error {
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return fmt.Errorf("invalid user ID")
	}

	isEmployee, err := s.companyRepo.IsUserActiveEmployee(ctx, department.CompanyID, userID)
	if err != nil || !isEmployee {
		return fmt.Errorf("user is not an employee of this company")
	}

	if err := s.companyRepo.UpdateDepartmentParent(
		ctx,
		req.DepartmentID,
		req.ParentDepartmentID,
	); err != nil {
		return fmt.Errorf("failed to update department parent: %w", err)
	}

	s.logger.Info("Department parent updated",
		util.String("department_id", req.DepartmentID.String()),
		util.String("updated_by", updatedBy.String()),
	)
	return nil
}

func (s *CompanyService) GetDepartmentChildren(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentChildren(ctx, departmentID)
}

func (s *CompanyService) GetDepartmentTree(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.DepartmentTree, error) {
	return s.companyRepo.GetDepartmentTree(ctx, departmentID)
}

func (s *CompanyService) GetDepartmentParents(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentParents(ctx, departmentID)
}

func (s *CompanyService) MoveDepartmentWithEmployees(
	ctx context.Context,
	departmentID uuid.UUID,
	newParentDepartmentID *uuid.UUID,
	movedBy uuid.UUID,
) error {
	if err := s.companyRepo.MoveDepartmentWithEmployees(
		ctx,
		departmentID,
		newParentDepartmentID,
	); err != nil {
		return fmt.Errorf("failed to move department: %w", err)
	}

	s.logger.Info("Department moved",
		util.String("department_id", departmentID.String()),
		util.String("moved_by", movedBy.String()),
	)
	return nil
}

func (s *CompanyService) GetRootDepartments(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*models.Department, error) {
	return s.companyRepo.GetRootDepartments(ctx, companyID)
}

func (s *CompanyService) ValidateDepartmentHierarchy(
	ctx context.Context,
	departmentID uuid.UUID,
	newParentDepartmentID *uuid.UUID,
) (bool, error) {
	if newParentDepartmentID == nil {
		return true, nil
	}

	parent, err := s.companyRepo.GetDepartment(ctx, *newParentDepartmentID)
	if err != nil {
		return false, err
	}

	current, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return false, err
	}

	if parent.CompanyID != current.CompanyID {
		return false, fmt.Errorf("departments must belong to same company")
	}

	return true, nil
}

func (s *CompanyService) GetCompanyByID(
	ctx context.Context,
	companyID uuid.UUID,
) (*models.Company, error) {
	company, err := s.companyRepo.GetCompanyByID(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company by id: %w", err)
	}
	return company, nil
}

func (s *CompanyService) GetActiveDepartmentCount(
	ctx context.Context,
	companyID uuid.UUID,
) (int, error) {
	count, err := s.companyRepo.GetActiveDepartmentCount(ctx, companyID)
	if err != nil {
		return 0, fmt.Errorf("failed to get active department count: %w", err)
	}
	return count, nil
}

func (s *CompanyService) GetCompanyDepartmentInfo(
	ctx context.Context,
	companyID uuid.UUID,
) (*postgres.CompanyDepartmentInfo, error) {
	info, err := s.companyRepo.GetCompanyDepartmentInfo(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company department info: %w", err)
	}
	return info, nil
}

func (s *CompanyService) CheckDepartmentLimit(
	ctx context.Context,
	companyID uuid.UUID,
) error {
	return s.companyRepo.CheckDepartmentLimit(ctx, companyID)
}

func (s *CompanyService) UpdateMaxDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	newMaxDepartments int,
) error {
	start := time.Now()

	if newMaxDepartments < 1 || newMaxDepartments > 100 {
		return fmt.Errorf("max_departments must be between 1 and 100")
	}

	if err := s.companyRepo.UpdateMaxDepartments(ctx, companyID, newMaxDepartments); err != nil {
		return fmt.Errorf("failed to update max departments: %w", err)
	}

	s.logger.Info("Company max_departments updated",
		util.String("company_id", companyID.String()),
		util.Int("new_max_departments", newMaxDepartments),
		util.Duration("duration", time.Since(start)),
	)
	return nil
}

func (s *CompanyService) SoftDeleteDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID uuid.UUID,
) error {
	return s.companyRepo.SoftDeleteDepartment(ctx, companyID, departmentID)
}

func (s *CompanyService) CreateSubDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	parentDepartmentID uuid.UUID,
	departmentName string,
) (*models.Department, error) {
	parent, err := s.companyRepo.GetDepartmentByID(ctx, parentDepartmentID)
	if err != nil {
		return nil, err
	}

	if parent.CompanyID != companyID {
		return nil, fmt.Errorf("parent department does not belong to this company")
	}

	if parent.SystemDepartmentID == nil {
		return nil, fmt.Errorf("parent department missing system department mapping")
	}

	return s.companyRepo.CreateSubDepartment(
		ctx,
		companyID,
		parentDepartmentID,
		departmentName,
		*parent.SystemDepartmentID,
	)
}

func (s *CompanyService) ActivateDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID uuid.UUID,
) error {
	return s.companyRepo.ActivateDepartment(ctx, companyID, departmentID)
}

type CreateSubDepartmentRequest struct {
	DepartmentName string `json:"department_name" validate:"required"`
}

func (s *CompanyService) AdminAddDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentName string,
	systemDepartmentID uuid.UUID,
) (*models.Department, error) {
	start := time.Now()

	if err := s.companyRepo.CheckDepartmentLimit(ctx, companyID); err != nil {
		return nil, err
	}

	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, systemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("system department not found: %w", err)
	}

	department, err := s.companyRepo.CreateCompanyDepartment(
		ctx,
		companyID,
		departmentName,
		systemDepartmentID,
	)
	if err != nil {
		return nil, err
	}

	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err == nil {
		_ = s.companyRepo.CreateRoleDepartment(
			ctx,
			ownerRole.RoleID,
			department.DepartmentID,
		)
	}

	s.logger.Info("Admin added company department",
		util.String("company_id", companyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", departmentName),
		util.String("system_module", systemDept.ModuleCode),
		util.Duration("duration", time.Since(start)),
	)

	return department, nil
}

type AdminAddDepartmentRequest struct {
	DepartmentName     string    `json:"department_name"`
	SystemDepartmentID uuid.UUID `json:"system_department_id"`
}

func (s *CompanyService) requireAnyPermission(
	ctx context.Context,
	perms ...string,
) error {
	for _, p := range perms {
		ok, err := s.CheckPermissionFromContext(ctx, p)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("user lacks required permission")
}

type SearchDepartmentsRequest struct {
	Query           string `json:"q"`
	Limit           int    `json:"limit,omitempty"`
	Offset          int    `json:"offset,omitempty"`
	IncludeInactive bool   `json:"include_inactive,omitempty"`
}

type DepartmentSearchResponse struct {
	Departments []*models.DepartmentSearchResult `json:"departments"`
	Total       int                              `json:"total"`
	Page        int                              `json:"page"`
	Limit       int                              `json:"limit"`
	HasMore     bool                             `json:"has_more"`
}

func (s *CompanyService) SearchDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	req *SearchDepartmentsRequest,
) (*DepartmentSearchResponse, error) {
	start := time.Now()

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	departments, total, err := s.companyRepo.SearchDepartments(
		ctx,
		companyID,
		req.Query,
		req.Limit,
		req.Offset,
		req.IncludeInactive,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search departments: %w", err)
	}

	page := 1
	if req.Limit > 0 {
		page = (req.Offset / req.Limit) + 1
	}
	hasMore := (req.Offset + len(departments)) < total

	resp := &DepartmentSearchResponse{
		Departments: departments,
		Total:       total,
		Page:        page,
		Limit:       req.Limit,
		HasMore:     hasMore,
	}

	s.logger.Info("Department search completed",
		util.String("company_id", companyID.String()),
		util.String("query", req.Query),
		util.Int("results", len(departments)),
		util.Int("total", total),
		util.Duration("duration", time.Since(start)),
	)

	return resp, nil
}

func (s *CompanyService) GetDepartmentSuggestions(
	ctx context.Context,
	companyID uuid.UUID,
	prefix string,
	limit int,
) ([]*models.Department, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}

	suggestions, err := s.companyRepo.GetDepartmentSuggestions(ctx, companyID, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get department suggestions: %w", err)
	}
	return suggestions, nil
}

func (s *CompanyService) UpdateEmployeePosition(ctx context.Context, companyID, userID uuid.UUID, positionID *uuid.UUID) error {
	// Get employee
	employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("employee not found: %w", err)
	}

	if !employee.IsActive {
		return fmt.Errorf("employee is not active")
	}

	// Validate position if provided
	if positionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, *positionID)
		if err != nil {
			return fmt.Errorf("position not found: %w", err)
		}

		if position.CompanyID != companyID {
			return fmt.Errorf("position does not belong to company")
		}

		if !position.IsOpen {
			return fmt.Errorf("position is not open for assignment")
		}

		// Get role departments to validate position department
		roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
		if err != nil {
			return fmt.Errorf("failed to get role departments: %w", err)
		}

		// Check if position's department is in role's departments
		positionInRoleDept := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				positionInRoleDept = true
				break
			}
		}

		if !positionInRoleDept {
			return fmt.Errorf("position's department is not assigned to the employee's role")
		}
	}

	// Update employee position
	if err := s.companyRepo.UpdateEmployeePosition(ctx, companyID, userID, positionID); err != nil {
		return fmt.Errorf("failed to update employee position: %w", err)
	}

	s.logger.Info("Employee position updated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("position_id", func() string {
			if positionID != nil {
				return positionID.String()
			}
			return "none"
		}()))

	return nil
}

// service/company_service.go
// Add these methods to the CompanyService struct

func (s *CompanyService) GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error) {
	start := time.Now()

	// Check permission
	hasPerm, err := s.CheckPermissionFromContext(ctx, "hr.position.view")
	if err != nil || !hasPerm {
		return nil, 0, fmt.Errorf("permission denied for hr.position.view")
	}

	// Get positions
	positions, total, err := s.companyRepo.GetOpenPositions(ctx, companyID, isOpen, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get open positions: %w", err)
	}

	s.logger.Info("Open positions retrieved",
		util.String("company_id", companyID.String()),
		util.Int("total", total),
		util.Int("returned", len(positions)),
		util.Duration("duration", time.Since(start)),
	)

	return positions, total, nil
}
func (s *CompanyService) GetPositionsByDepartment(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
	isOpen *bool,
	limit, offset int,
) ([]*models.Position, int, error) {

	start := time.Now()

	// Permission check
	hasPerm, err := s.CheckPermissionFromContext(ctx, "hr.position.view")
	if err != nil || !hasPerm {
		return nil, 0, fmt.Errorf("permission denied for hr.position.view")
	}

	// Repo supports only bool, so normalize
	onlyOpen := false
	if isOpen != nil {
		onlyOpen = *isOpen
	}

	positions, total, err := s.companyRepo.GetPositionsByDepartment(
		ctx,
		departmentID,
		limit,
		offset,
		onlyOpen,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get positions by department: %w", err)
	}

	s.logger.Info(
		"Positions by department retrieved",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.Int("total", total),
		util.Int("returned", len(positions)),
		util.Bool("only_open", onlyOpen),
		util.Duration("duration", time.Since(start)),
	)

	return positions, total, nil
}
func (s *CompanyService) GetEmployeeWithPosition(
	ctx context.Context,
	companyID, userID uuid.UUID,
) (*models.CompanyEmployeeWithPosition, error) {

	start := time.Now()

	// Permission check
	hasPerm, err := s.CheckPermissionFromContext(ctx, "hr.employee.view")
	if err != nil || !hasPerm {
		return nil, fmt.Errorf("permission denied for hr.employee.view")
	}

	employee, position, err := s.companyRepo.GetEmployeeWithPosition(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee with position: %w", err)
	}

	result := &models.CompanyEmployeeWithPosition{
		CompanyEmployee: *employee,
	}

	// Map position fields if present
	if position != nil {
		result.PositionID = &position.PositionID
		result.PositionTitle = position.Title
		result.IsOpen = &position.IsOpen
	}

	s.logger.Info(
		"Employee with position retrieved",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Bool("has_position", position != nil),
		util.Duration("duration", time.Since(start)),
	)

	return result, nil
}
