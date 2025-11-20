// internal/service/company_service.go
package service

import (
	"context"
	"fmt"
	"time"

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
// BITMASK PERMISSION CHECKING (UPDATED)
// ============================================================================

// CheckMultiplePermissionsFromContext checks multiple permissions
func (s *CompanyService) CheckMultiplePermissionsFromContext(ctx context.Context, permissions []string, checkAll bool) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("session type not found in context")
	}

	// Admin sessions have full access
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

// GetPermissionsFromContext returns all permission names from the bitmask
func (s *CompanyService) GetPermissionsFromContext(ctx context.Context) ([]string, error) {
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return []string{}, nil
	}

	return rbac.GetPermissionsFromMask(permissionMask), nil
}

// ============================================================================
// COMPANY CREATION (ADMIN ONLY)
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

func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest, createdBy uuid.UUID) (*models.Company, error) {
	start := time.Now()

	// Verify admin session
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType != "admin" {
		return nil, fmt.Errorf("only admin users can create companies")
	}

	// Check if admin has permission to create companies
	hasPermission, err := s.CheckPermissionFromContext(ctx, "admin.company.create")
	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("insufficient permissions to create companies")
	}

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

	s.logger.Info("Company created successfully by admin",
		util.String("company_id", companyID.String()),
		util.String("company_name", req.CompanyName),
		util.String("owner_user_id", ownerUser.UserID.String()),
		util.String("created_by", createdBy.String()),
		util.String("subscription_tier", req.SubscriptionTier),
		util.Int("department_count", len(req.Departments)),
		util.Duration("duration", time.Since(start)))

	return company, nil
}

// ============================================================================
// DEPARTMENT MANAGEMENT (BITMASK UPDATED)
// ============================================================================

type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
}

func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
	// Check permission using bitmask
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.create")
	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user lacks permission to create departments")
	}

	// Verify user has access to the company
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, fmt.Errorf("user ID not found in context")
	}

	companyID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in context")
	}

	// For non-owners, verify they belong to the company
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType != "admin" {
		isEmployee, err := s.companyRepo.IsUserActiveEmployee(ctx, req.CompanyID, companyID)
		if err != nil || !isEmployee {
			return nil, fmt.Errorf("user does not belong to this company")
		}
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
// EMPLOYEE MANAGEMENT (BITMASK UPDATED)
// ============================================================================

type AddEmployeeRequest struct {
	CompanyID    uuid.UUID  `json:"company_id" validate:"required"`
	PhoneNumber  string     `json:"phone" validate:"required"`
	EmployeeID   string     `json:"employee_id" validate:"required"`
	RoleID       uuid.UUID  `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
	Permissions  []string   `json:"permissions"`
}

// func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
// 	start := time.Now()

// 	// Check if user has permission to add employees
// 	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}
// 	if !hasPermission {
// 		return fmt.Errorf("user lacks permission to add employees")
// 	}

// 	// For non-admin users, validate they're not assigning permissions they don't have
// 	sessionType, _ := ctx.Value("session_type").(string)
// 	if sessionType != "admin" && len(req.Permissions) > 0 {
// 		userPermissions, err := s.GetPermissionsFromContext(ctx)
// 		if err != nil {
// 			return fmt.Errorf("failed to get user permissions: %w", err)
// 		}

// 		// Check if all requested permissions are in user's permissions
// 		for _, reqPerm := range req.Permissions {
// 			found := false
// 			for _, userPerm := range userPermissions {
// 				if userPerm == reqPerm {
// 					found = true
// 					break
// 				}
// 			}
// 			if !found {
// 				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
// 			}
// 		}
// 	}

// 	// Validate company
// 	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 	if err != nil {
// 		return fmt.Errorf("company not found: %w", err)
// 	}
// 	if !company.IsActive {
// 		return fmt.Errorf("company is not active")
// 	}

// 	// Check employee limit
// 	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get active employee count: %w", err)
// 	}
// 	if activeCount >= company.MaxEmployees {
// 		return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
// 	}

// 	// Validate role
// 	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
// 	if err != nil {
// 		return fmt.Errorf("role not found: %w", err)
// 	}
// 	if role.CompanyID != req.CompanyID {
// 		return fmt.Errorf("role does not belong to company")
// 	}

// 	// Validate department
// 	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
// 	if err != nil {
// 		return fmt.Errorf("department not found: %w", err)
// 	}
// 	if department.CompanyID != req.CompanyID {
// 		return fmt.Errorf("department does not belong to company")
// 	}

// 	// Check role-department mapping
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

// 	// Validate reports_to
// 	if req.ReportsTo != nil {
// 		reportsToEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
// 		if err != nil {
// 			return fmt.Errorf("reports_to employee not found: %w", err)
// 		}
// 		if !reportsToEmp.IsActive {
// 			return fmt.Errorf("reports_to employee is not active")
// 		}
// 	}

// 	// Get or create user
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

// 	// Check if user is already an active employee
// 	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
// 	if existingEmp != nil && existingEmp.IsActive {
// 		return fmt.Errorf("user is already an active employee in this company")
// 	}

// 	// Assign permissions if specified
// 	if len(req.Permissions) > 0 {
// 		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// 		if err != nil {
// 			return fmt.Errorf("failed to get permissions: %w", err)
// 		}

// 		// Validate permission compatibility with department module
// 		if department.SystemDepartmentID != nil {
// 			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
// 			if err != nil {
// 				return fmt.Errorf("failed to get system department: %w", err)
// 			}

// 			for _, perm := range permissions {
// 				if perm.Module != systemDept.ModuleCode {
// 					return fmt.Errorf("permission '%s' (module: %s) is not compatible with department module '%s'",
// 						perm.PermissionName, perm.Module, systemDept.ModuleCode)
// 				}
// 			}
// 		}

// 		// Grant permissions to the role
// 		permissionIDs := make([]uuid.UUID, len(permissions))
// 		for i, perm := range permissions {
// 			permissionIDs[i] = perm.PermissionID
// 		}

// 		// Get current user ID for granted_by
// 		currentUserID, ok := ctx.Value("user_id").(string)
// 		if !ok {
// 			return fmt.Errorf("user ID not found in context")
// 		}
// 		grantedBy, err := uuid.Parse(currentUserID)
// 		if err != nil {
// 			return fmt.Errorf("invalid user ID in context")
// 		}

// 		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, grantedBy); err != nil {
// 			return fmt.Errorf("failed to assign permissions to role: %w", err)
// 		}
// 	}

// 	// Set default reports_to if not provided
// 	reportsTo := req.ReportsTo
// 	if reportsTo == nil {
// 		if department.DepartmentHead != nil {
// 			reportsTo = department.DepartmentHead
// 		} else {
// 			reportsTo = &company.OwnerUserID
// 		}
// 	}

// 	// Create employee record
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
// 		util.String("role_name", role.RoleName),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.String("department_name", department.DepartmentName),
// 		util.Int("permissions_count", len(req.Permissions)),
// 		util.Duration("duration", time.Since(start)))

// 	return nil
// }

// ============================================================================
// MANAGER OPERATIONS (BITMASK UPDATED)
// ============================================================================

type AddManagerRequest struct {
	CompanyID    uuid.UUID  `json:"company_id" validate:"required"`
	PhoneNumber  string     `json:"phone" validate:"required"`
	RoleName     string     `json:"role_name" validate:"required"`
	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
	Permissions  []string   `json:"permissions" validate:"required"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
}

// func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
// 	// Check if user has permission to add managers and administrative access
// 	hasCreatePermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
// 	if err != nil {
// 		return fmt.Errorf("permission check failed: %w", err)
// 	}

// 	hasAdminAccess, err := s.CheckPermissionFromContext(ctx, "administrative.department.create")
// 	if err != nil {
// 		return fmt.Errorf("administrative access check failed: %w", err)
// 	}

// 	if !hasCreatePermission || !hasAdminAccess {
// 		return fmt.Errorf("user lacks permission to add managers or administrative access")
// 	}

// 	// For non-admin users, validate they're not assigning permissions they don't have
// 	sessionType, _ := ctx.Value("session_type").(string)
// 	if sessionType != "admin" {
// 		userPermissions, err := s.GetPermissionsFromContext(ctx)
// 		if err != nil {
// 			return fmt.Errorf("failed to get user permissions: %w", err)
// 		}

// 		for _, reqPerm := range req.Permissions {
// 			found := false
// 			for _, userPerm := range userPermissions {
// 				if userPerm == reqPerm {
// 					found = true
// 					break
// 				}
// 			}
// 			if !found {
// 				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
// 			}
// 		}
// 	}

// 	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
// 	if err != nil {
// 		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 		if err != nil {
// 			return fmt.Errorf("failed to get company: %w", err)
// 		}

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

// 	managerRole := &models.Role{
// 		RoleID:       uuid.New(),
// 		RoleName:     req.RoleName,
// 		RoleLevel:    500, // Manager level
// 		CompanyID:    req.CompanyID,
// 		IsSystemRole: false,
// 		Description:  fmt.Sprintf("Manager role for %s", req.RoleName),
// 		CreatedAt:    time.Now().UTC(),
// 		UpdatedAt:    time.Now().UTC(),
// 	}

// 	permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// 	if err != nil {
// 		return fmt.Errorf("failed to get permissions: %w", err)
// 	}

// 	permissionIDs := make([]uuid.UUID, len(permissions))
// 	for i, perm := range permissions {
// 		permissionIDs[i] = perm.PermissionID
// 	}

// 	// Get current user ID for granted_by
// 	currentUserID, ok := ctx.Value("user_id").(string)
// 	if !ok {
// 		return fmt.Errorf("user ID not found in context")
// 	}
// 	createdBy, err := uuid.Parse(currentUserID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID in context")
// 	}

// 	if err := s.companyRepo.CreateRoleWithDetails(ctx, managerRole, req.DepartmentID, permissionIDs, createdBy); err != nil {
// 		return fmt.Errorf("failed to create manager role: %w", err)
// 	}

// 	reportsTo := req.ReportsTo
// 	if reportsTo == nil {
// 		company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
// 		if err != nil {
// 			return fmt.Errorf("failed to get company: %w", err)
// 		}
// 		reportsTo = &company.OwnerUserID
// 	}

// 	emp := &models.CompanyEmployee{
// 		CompanyID:    req.CompanyID,
// 		UserID:       user.UserID,
// 		EmployeeID:   fmt.Sprintf("MGR-%s", uuid.New().String()[:8]),
// 		RoleID:       managerRole.RoleID,
// 		DepartmentID: &req.DepartmentID,
// 		HireDate:     time.Now().UTC(),
// 		IsActive:     true,
// 		ReportsTo:    reportsTo,
// 		CreatedAt:    time.Now().UTC(),
// 		UpdatedAt:    time.Now().UTC(),
// 	}

// 	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
// 		return fmt.Errorf("failed to add manager as employee: %w", err)
// 	}

// 	s.logger.Info("Manager added successfully",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("user_id", user.UserID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Int("permissions_count", len(req.Permissions)))

// 	return nil
// }

// ============================================================================
// PERMISSION MANAGEMENT (BITMASK UPDATED)
// ============================================================================

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

	// Get current user ID for granted_by
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

// ============================================================================
// UTILITY METHODS
// ============================================================================

// GetUserPermissionBitmask retrieves the complete permission bitmask for a user
func (s *CompanyService) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
}

// GetRolePermissionBitmask retrieves permission bitmask for a role
func (s *CompanyService) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetRolePermissionBitmask(ctx, roleID)
}

// GetPermissionsWithBitIndex retrieves all permissions with their bit indexes
func (s *CompanyService) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
	return s.companyRepo.GetPermissionsWithBitIndex(ctx)
}

// ============================================================================
// EXISTING METHODS (MINIMAL CHANGES FOR BITMASK)
// ============================================================================

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

// AddDepartment adds a new department (simplified version)
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

	// Auto-assign to owner role
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

// ============================================================================
// COMPANY CONTEXT & PERMISSION FLOW (FROM YOUR WORKING FILE)
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
// ADDITIONAL METHODS FROM YOUR WORKING FILE
// ============================================================================

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

// // ManagerAddEmployee handles employee addition by managers with permission validation
// func (s *CompanyService) ManagerAddEmployee(ctx context.Context, req *AddEmployeeRequest, managerID uuid.UUID) error {
// 	start := time.Now()

// 	// 1. Get manager's employee record
// 	managerEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, managerID)
// 	if err != nil {
// 		return fmt.Errorf("manager not found: %w", err)
// 	}

// 	// 2. Verify manager can only add to their own department
// 	if managerEmp.DepartmentID == nil || *managerEmp.DepartmentID != req.DepartmentID {
// 		return fmt.Errorf("manager can only add employees to their own department")
// 	}

// 	// 3. Get manager's permissions
// 	managerPermissions, err := s.companyRepo.GetUserPermissions(ctx, req.CompanyID, managerID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get manager permissions: %w", err)
// 	}

// 	// Convert manager permissions to a map for easy lookup
// 	managerPermMap := make(map[string]bool)
// 	for _, perm := range managerPermissions {
// 		managerPermMap[perm.PermissionName] = true
// 	}

// 	// 4. Validate that manager is not assigning permissions they don't have
// 	if len(req.Permissions) > 0 {
// 		for _, requestedPerm := range req.Permissions {
// 			if !managerPermMap[requestedPerm] {
// 				return fmt.Errorf("manager cannot assign permission '%s' that they don't possess", requestedPerm)
// 			}
// 		}
// 	}

// 	// 5. Check if role belongs to manager's department
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

// 	// 6. If permissions are specified, validate they are compatible with the role and department
// 	if len(req.Permissions) > 0 {
// 		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
// 		if err != nil {
// 			return fmt.Errorf("failed to validate permissions: %w", err)
// 		}

// 		// Check if permissions are compatible with department's module
// 		department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
// 		if err != nil {
// 			return fmt.Errorf("failed to get department: %w", err)
// 		}

// 		if department.SystemDepartmentID != nil {
// 			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, *department.SystemDepartmentID)
// 			if err != nil {
// 				return fmt.Errorf("failed to get system department: %w", err)
// 			}

// 			for _, perm := range permissions {
// 				if perm.Module != systemDept.ModuleCode {
// 					return fmt.Errorf("permission '%s' (module: %s) is not compatible with department module '%s'",
// 						perm.PermissionName, perm.Module, systemDept.ModuleCode)
// 				}
// 			}
// 		}
// 	}

// 	// 7. Set reports_to to manager for manager-added employees
// 	req.ReportsTo = &managerID

// 	// 8. Call the regular AddEmployee method with validated parameters
// 	if err := s.AddEmployee(ctx, req); err != nil {
// 		return fmt.Errorf("failed to add employee: %w", err)
// 	}

// 	s.logger.Info("Manager added employee successfully",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("manager_id", managerID.String()),
// 		util.String("employee_phone", req.PhoneNumber),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Int("permissions_count", len(req.Permissions)),
// 		util.Duration("duration", time.Since(start)))

// 	return nil
// }

// ============================================================================
// ADDITIONAL METHODS FROM SECOND FILE THAT WERE MISSING
// ============================================================================

// GetSystemDepartmentByModule retrieves system department by module code
func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartmentByModule(ctx, module)
}

// UpdateCompanyStatus updates company active status
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

// UpdateSubscription updates company subscription
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

// ListCompanies lists all companies with pagination
func (s *CompanyService) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.ListCompanies(ctx, limit, offset)
}

// ListCompaniesByTier lists companies by subscription tier
func (s *CompanyService) ListCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.GetCompaniesByTier(ctx, tier, limit, offset)
}

// GetCompaniesWithExpiringSubscription gets companies with expiring subscriptions
func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
}

// DeactivateCompany deactivates a company
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

// DeleteCompany deletes a company
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

// ListActiveEmployees lists only active employees
func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}

// UpdateEmployeeRole updates employee role
func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
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

// UpdateEmployeeDepartment updates employee department
func (s *CompanyService) UpdateEmployeeDepartment(ctx context.Context, companyID, userID, newDepartmentID, updatedBy uuid.UUID) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.update")
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

// RemoveEmployee removes an employee
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

// ReactivateEmployee reactivates an employee
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

// GetEmployeeCount gets total employee count
func (s *CompanyService) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetEmployeeCount(ctx, companyID)
}

// IsUserActiveEmployee checks if user is active employee
func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
}

// UpdateRole updates role details
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

// DeleteRole deletes a role
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

// UpdateDepartment updates department details
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

// DeactivateDepartment deactivates a department
func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID uuid.UUID, updatedBy uuid.UUID) error {
	_, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}

	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.delete")
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

// GetDepartmentHierarchy gets department hierarchy
func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentHierarchy(ctx, companyID)
}

// GetPermissionByName gets permission by name
func (s *CompanyService) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	return s.companyRepo.GetPermissionByName(ctx, name)
}

// GetPermissionsByModule gets permissions by module
func (s *CompanyService) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

// GetRolePermissions gets role permissions
func (s *CompanyService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	return s.companyRepo.GetRolePermissions(ctx, roleID)
}

// GrantRolePermission grants single permission to role
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

// RevokeRolePermission revokes single permission from role
func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID, revokedBy uuid.UUID) error {
	// Remove the unused role variable
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

// BulkPermissionCheck checks multiple permissions at once
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

// GetModulePermissions gets permissions by module
func (s *CompanyService) GetModulePermissions(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

// GetDepartmentLoad gets department employee load
func (s *CompanyService) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetDepartmentLoad(ctx, companyID)
}

// GetRoleDistribution gets role distribution
func (s *CompanyService) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetRoleDistribution(ctx, companyID)
}

// GetCompanyStats gets company statistics
func (s *CompanyService) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	return s.companyRepo.GetCompanyStats(ctx, companyID)
}

// ExtendSubscription extends company subscription
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

// AuthorizeUserLogin authorizes user login
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

// GetUsersWithPermission gets users with specific permission
func (s *CompanyService) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersWithPermission(ctx, companyID, permissionName, limit)
}

// GetUsersByRoleLevel gets users by role level range
func (s *CompanyService) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersByRoleLevel(ctx, companyID, minLevel, maxLevel)
}

// CreateRoleWithPermissions creates role with permissions
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

// ListRoles lists roles with optional permission inclusion
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

// ListDepartments lists departments with optional employee inclusion
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

// ListPermissionsByModule lists permissions by module
func (s *CompanyService) ListPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

// GetAllPermissions gets all permissions with filtering
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

// GetUserHierarchy gets user hierarchy
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

// GetEmployeeHierarchy gets employee hierarchy
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

// BulkAssignRoles bulk assigns roles to employees
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

// removeDuplicatePermissions removes duplicate permissions
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

// GetCompanyHierarchy gets company hierarchy
func (s *CompanyService) GetCompanyHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	hierarchy, err := s.companyRepo.GetEmployeeHierarchy(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company hierarchy: %w", err)
	}
	return hierarchy, nil
}

// ReactivateCompany reactivates a company
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

// AssignManagerPermissions assigns permissions to manager
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

// RevokeManagerPermissions revokes permissions from manager
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

// GetManagerPermissions gets manager permissions
func (s *CompanyService) GetManagerPermissions(ctx context.Context, managerID uuid.UUID) ([]string, error) {
	return s.companyRepo.GetUserPermissionNames(ctx, managerID)
}

// ValidatePermissionSubset validates permission subset
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

// removeDuplicateStrings removes duplicate strings
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

// ============================================================================
// ROLE MANAGEMENT STRUCTURES AND METHODS
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
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
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

// MapRoleToDepartmentRequest role to department mapping request
type MapRoleToDepartmentRequest struct {
	RoleID       uuid.UUID `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	MappedBy     uuid.UUID `json:"mapped_by" validate:"required"`
}

// MapRoleToDepartment maps role to department
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

// RemoveRoleFromDepartment removes role from department
func (s *CompanyService) RemoveRoleFromDepartment(ctx context.Context, roleID, departmentID, removedBy uuid.UUID) error {
	// Remove the unused role variable
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

// GetRoleDepartments gets role departments
func (s *CompanyService) GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRoleDepartments(ctx, roleID)
}

// GetDepartmentRoles gets department roles
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

// ValidateRoleDepartmentCompatibility validates role-department compatibility
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

// GetRole retrieves a role by ID
func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	return s.companyRepo.GetRole(ctx, roleID)
}

// IsUserActiveEmployee checks if user is active employee of company
func (s *CompanyService) CheckPermissionFromContext(ctx context.Context, permissionName string) (bool, error) {
	// Get session type from context
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		s.logger.Debug("CheckPermissionFromContext: session type not found")
		return false, fmt.Errorf("session type not found in context")
	}

	// Admin sessions have full access
	if sessionType == "admin" {
		s.logger.Debug("CheckPermissionFromContext: admin session - full access granted",
			util.String("permission", permissionName))
		return true, nil
	}

	// Get permission mask from context
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		s.logger.Debug("CheckPermissionFromContext: permission mask not found in context",
			util.String("session_type", sessionType))
		return false, fmt.Errorf("permission mask not found in context")
	}

	// Use RBAC package to check permission
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

// RenameDepartment updates only the department name
func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string) error {
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.department.update")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to rename departments")
	}

	// Verify the department belongs to the company
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

// In company_service.go
func (s *CompanyService) GetPermissionsByCompanyDepartments(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error) {
	// Get company departments
	departments, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get company departments: %w", err)
	}

	// Extract system department IDs
	systemDeptIDs := make([]uuid.UUID, 0)
	for _, dept := range departments {
		if dept.SystemDepartmentID != nil {
			systemDeptIDs = append(systemDeptIDs, *dept.SystemDepartmentID)
		}
	}

	// Always include administrative department
	adminSystemDept, err := s.companyRepo.GetSystemDepartmentByModule(ctx, "administration")
	if err == nil {
		systemDeptIDs = append(systemDeptIDs, adminSystemDept.SystemDepartmentID)
	}

	if len(systemDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}

	// Get permissions by system departments
	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, module, category, tier)
}

// ValidatePermissionAssignment validates if a user can assign specific permissions
func (s *CompanyService) ValidatePermissionAssignment(ctx context.Context, assignerID uuid.UUID, permissionsToAssign []string) (bool, error) {
	// Get assigner's permissions
	assignerPermissions, err := s.GetUserPermissions(ctx, assignerID)
	if err != nil {
		return false, err
	}

	// Convert to map for easy lookup
	assignerPermMap := make(map[string]bool)
	for _, perm := range assignerPermissions {
		assignerPermMap[perm.PermissionName] = true
	}

	// Check if assigner has all permissions they're trying to assign
	for _, permToAssign := range permissionsToAssign {
		if !assignerPermMap[permToAssign] {
			return false, nil
		}
	}

	return true, nil
}
func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
	// ONLY check if user has permission to add managers with administrative access
	hasPermission, err := s.CheckPermissionFromContext(ctx, "administrative.employee.manage")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to add managers")
	}

	// For non-admin users, validate they're not assigning permissions they don't have
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType != "admin" && len(req.Permissions) > 0 {
		userPermissions, err := s.GetPermissionsFromContext(ctx)
		if err != nil {
			return fmt.Errorf("failed to get user permissions: %w", err)
		}

		for _, reqPerm := range req.Permissions {
			found := false
			for _, userPerm := range userPermissions {
				if userPerm == reqPerm {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
			}
		}
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
		RoleLevel:    500, // Manager level
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

	// Get current user ID for granted_by
	currentUserID, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("user ID not found in context")
	}
	createdBy, err := uuid.Parse(currentUserID)
	if err != nil {
		return fmt.Errorf("invalid user ID in context")
	}

	if err := s.companyRepo.CreateRoleWithDetails(ctx, managerRole, req.DepartmentID, permissionIDs, createdBy); err != nil {
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
		util.Int("permissions_count", len(req.Permissions)))

	return nil
}

func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
	start := time.Now()

	// ONLY check if user has permission to add employees (hr.employee.create)
	hasPermission, err := s.CheckPermissionFromContext(ctx, "hr.employee.create")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user lacks permission to add employees")
	}

	// For non-admin users, validate they're not assigning permissions they don't have
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType != "admin" && len(req.Permissions) > 0 {
		userPermissions, err := s.GetPermissionsFromContext(ctx)
		if err != nil {
			return fmt.Errorf("failed to get user permissions: %w", err)
		}

		// Check if all requested permissions are in user's permissions
		for _, reqPerm := range req.Permissions {
			found := false
			for _, userPerm := range userPermissions {
				if userPerm == reqPerm {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("user cannot assign permission '%s' that they don't possess", reqPerm)
			}
		}
	}

	// Validate company
	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}
	if !company.IsActive {
		return fmt.Errorf("company is not active")
	}

	// Check employee limit
	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to get active employee count: %w", err)
	}
	if activeCount >= company.MaxEmployees {
		return fmt.Errorf("max employee limit reached: %d/%d", activeCount, company.MaxEmployees)
	}

	// Validate role
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("role does not belong to company")
	}

	// Validate department
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("department not found: %w", err)
	}
	if department.CompanyID != req.CompanyID {
		return fmt.Errorf("department does not belong to company")
	}

	// Check role-department mapping
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

	// Validate reports_to
	if req.ReportsTo != nil {
		reportsToEmp, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, *req.ReportsTo)
		if err != nil {
			return fmt.Errorf("reports_to employee not found: %w", err)
		}
		if !reportsToEmp.IsActive {
			return fmt.Errorf("reports_to employee is not active")
		}
	}

	// Get or create user
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

	// Check if user is already an active employee
	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
	if existingEmp != nil && existingEmp.IsActive {
		return fmt.Errorf("user is already an active employee in this company")
	}

	// Assign permissions if specified
	if len(req.Permissions) > 0 {
		permissions, err := s.companyRepo.GetPermissionsByNames(ctx, req.Permissions)
		if err != nil {
			return fmt.Errorf("failed to get permissions: %w", err)
		}

		// Validate permission compatibility with department module
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

		// Grant permissions to the role
		permissionIDs := make([]uuid.UUID, len(permissions))
		for i, perm := range permissions {
			permissionIDs[i] = perm.PermissionID
		}

		// Get current user ID for granted_by
		currentUserID, ok := ctx.Value("user_id").(string)
		if !ok {
			return fmt.Errorf("user ID not found in context")
		}
		grantedBy, err := uuid.Parse(currentUserID)
		if err != nil {
			return fmt.Errorf("invalid user ID in context")
		}

		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, permissionIDs, grantedBy); err != nil {
			return fmt.Errorf("failed to assign permissions to role: %w", err)
		}
	}

	// Set default reports_to if not provided
	reportsTo := req.ReportsTo
	if reportsTo == nil {
		if department.DepartmentHead != nil {
			reportsTo = department.DepartmentHead
		} else {
			reportsTo = &company.OwnerUserID
		}
	}

	// Create employee record
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
		util.Duration("duration", time.Since(start)))

	return nil
}
