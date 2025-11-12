// service/company_service.go
package service

import (
    "context"
    "fmt"
    "time"

    "auth-service/internal/models"
    "auth-service/internal/repository/scylla"
    "auth-service/internal/util"

    "github.com/google/uuid"
    "go.uber.org/zap"
)

type CompanyService struct {
    companyRepo scylla.CompanyRepository
    userService *UserService
    adminRepo   scylla.AdminRepository
    logger      *zap.Logger
}

func NewCompanyService(
    companyRepo scylla.CompanyRepository,
    userService *UserService,
    adminRepo   scylla.AdminRepository,
    logger      *zap.Logger,
) *CompanyService {
    return &CompanyService{
        companyRepo: companyRepo,
        userService: userService,
        adminRepo:   adminRepo,
        logger:      logger,
    }
}

// CreateCompanyRequest with enhanced validation
type CreateCompanyRequest struct {
    CompanyName      string    `json:"company_name" validate:"required"`
    OwnerPhone       string    `json:"owner_phone" validate:"required"`
    SubscriptionTier string    `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
    MonthlyPremium   float64   `json:"monthly_premium" validate:"required,min=0"`
    MaxEmployees     int       `json:"max_employees" validate:"required,min=1,max=2000"`
    DataRegion       string    `json:"data_region" validate:"required"`
    CreatedByAdmin   uuid.UUID `json:"-"`
}

// ✅ FIXED: CreateCompany with proper error handling
func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest) (*models.Company, error) {
    // ✅ CHECK: Check if phone number already exists as user
    existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
    if err == nil && existingUser != nil {
        // Check if user already owns a company
        existingCompanies, err := s.companyRepo.GetCompaniesByOwner(ctx, existingUser.UserID)
        if err == nil && len(existingCompanies) > 0 {
            return nil, fmt.Errorf("user already owns a company")
        }
        
        // Use existing user as owner
        ownerUser := existingUser
        s.logger.Info("Using existing user as company owner",
            util.String("user_id", ownerUser.UserID.String()),
            util.String("phone", req.OwnerPhone))
        
        return s.createCompanyWithOwner(ctx, req, ownerUser)
    }

    // ✅ FIXED: Auto-create user for company owner if not exists
    s.logger.Info("Creating new user for company owner", util.String("phone", req.OwnerPhone))
    
    ownerUser, err := s.userService.CreateUserForCompanyOwner(ctx, req.OwnerPhone, req.DataRegion)
    if err != nil {
        return nil, fmt.Errorf("failed to create user for company owner: %w", err)
    }

    s.logger.Info("Created new user for company owner",
        util.String("user_id", ownerUser.UserID.String()),
        util.String("phone", req.OwnerPhone))

    return s.createCompanyWithOwner(ctx, req, ownerUser)
}

// ✅ FIXED: Single createCompanyWithOwner method without role level
func (s *CompanyService) createCompanyWithOwner(ctx context.Context, req *CreateCompanyRequest, ownerUser *models.User) (*models.Company, error) {
    start := time.Now()
    companyID := uuid.New()
    now := time.Now().UTC()
    subscriptionEnd := now.AddDate(0, 1, 0)

    company := &models.Company{
        CompanyID:             companyID,
        CompanyName:           req.CompanyName,
        OwnerPhone:            req.OwnerPhone,
        OwnerUserID:           ownerUser.UserID,
        SubscriptionTier:      req.SubscriptionTier,
        SubscriptionStartDate: now,
        SubscriptionEndDate:   subscriptionEnd,
        MonthlyPremium:        req.MonthlyPremium,
        MaxEmployees:          req.MaxEmployees,
        IsActive:              true,
        IsBlocked:             false,
        CreatedAt:             now,
        UpdatedAt:             now,
        DataRegion:            req.DataRegion,
    }

    if err := s.companyRepo.CreateCompany(ctx, company); err != nil {
        return nil, fmt.Errorf("failed to create company: %w", err)
    }

    // ✅ FIXED: Only update user's company ID, not role level
    if err := s.userService.UpdateUserCompany(ctx, ownerUser.UserID, companyID); err != nil {
        s.logger.Warn("failed to update user company",
            util.String("user_id", ownerUser.UserID.String()),
            util.ErrorField(err))
        // Don't return error here as company is already created
    }

    // Create owner role and employee record
    if err := s.createCompanyOwnerSetup(ctx, companyID, ownerUser.UserID); err != nil {
        // Rollback company creation if setup fails
        _ = s.companyRepo.UpdateCompanyStatus(ctx, companyID, false)
        return nil, fmt.Errorf("failed to setup company owner: %w", err)
    }

    s.logger.Info("Company created successfully",
        util.String("company_id", companyID.String()),
        util.String("company_name", req.CompanyName),
        util.String("owner_user_id", ownerUser.UserID.String()),
        util.Duration("duration", time.Since(start)),
    )

    return company, nil
}

// ✅ FIXED: Enhanced company owner setup with proper role creation
func (s *CompanyService) createCompanyOwnerSetup(ctx context.Context, companyID, ownerUserID uuid.UUID) error {
    // Create owner role in employee_roles table
    ownerRole := &models.EmployeeRole{
        CompanyID:    companyID,
        RoleID:       uuid.New(),
        RoleName:     "Company Owner",
        RoleLevel:    models.CompanyRoleLevelOwner,
        Permissions:  s.getAllPermissions(),
        DepartmentID: uuid.Nil, // Owner has no department
        IsSystemRole: true,
        CreatedAt:    time.Now().UTC(),
        UpdatedAt:    time.Now().UTC(),
    }

    if err := s.companyRepo.CreateEmployeeRole(ctx, ownerRole); err != nil {
        return fmt.Errorf("failed to create owner role: %w", err)
    }

    // Create owner employee record in company_employees table
    ownerEmployee := &models.CompanyEmployee{
        CompanyID:    companyID,
        UserID:       ownerUserID,
        EmployeeID:   "OWNER-001",
        RoleID:       ownerRole.RoleID,
        DepartmentID: uuid.Nil, // Owner has no department
        HireDate:     time.Now().UTC(),
        IsActive:     true,
        ReportsTo:    uuid.Nil, // Owner doesn't report to anyone
        CreatedAt:    time.Now().UTC(),
        UpdatedAt:    time.Now().UTC(),
    }

    if err := s.companyRepo.CreateCompanyEmployee(ctx, ownerEmployee); err != nil {
        return fmt.Errorf("failed to add owner as employee: %w", err)
    }

    s.logger.Info("Company owner setup completed",
        util.String("company_id", companyID.String()),
        util.String("user_id", ownerUserID.String()),
        util.String("role_id", ownerRole.RoleID.String()),
    )

    return nil
}

// AddEmployeeRequest with enhanced fields
type AddEmployeeRequest struct {
    CompanyID     uuid.UUID `json:"company_id" validate:"required"`
    PhoneNumber   string    `json:"phone_number" validate:"required"`
    EmployeeID    string    `json:"employee_id" validate:"required"`
    RoleID        uuid.UUID `json:"role_id" validate:"required"`
    DepartmentID  uuid.UUID `json:"department_id" validate:"required"`
    ReportsTo     uuid.UUID `json:"reports_to"`
    AddedBy       uuid.UUID `json:"added_by" validate:"required"` // User adding this employee
}

// ✅ FIXED: AddEmployee with proper method calls
func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
    // Validate company
    company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }
    
    if !company.IsActive || company.IsBlocked {
        return fmt.Errorf("company is not active")
    }

    // ✅ CHECK: Subscription active
    if !company.IsSubscriptionActive() {
        return fmt.Errorf("company subscription is not active")
    }

    // ✅ CHECK: Employee limit
    activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
    if err != nil {
        return fmt.Errorf("failed to get active employee count: %w", err)
    }
    if activeCount >= company.MaxEmployees {
        return fmt.Errorf("max active employee limit reached: %d/%d", activeCount, company.MaxEmployees)
    }

    // ✅ CHECK: Permissions of the user adding the employee
    if err := s.validateAddEmployeePermission(ctx, req.CompanyID, req.AddedBy, req.RoleID, req.DepartmentID); err != nil {
        return err
    }

    // ✅ STRICT: User must exist
    user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        return fmt.Errorf("user not found with phone: %s. User must be registered first", req.PhoneNumber)
    }

    // ✅ CHECK: Not already an active employee
    if existing, _ := s.companyRepo.GetCompanyEmployee(ctx, req.CompanyID, user.UserID); existing != nil && existing.IsActive {
        return fmt.Errorf("user is already an active employee in this company")
    }

    // ✅ VALIDATE: Role exists and is valid
    role, err := s.companyRepo.GetEmployeeRole(ctx, req.CompanyID, req.RoleID)
    if err != nil {
        return fmt.Errorf("role not found: %w", err)
    }

    // ✅ VALIDATE: Department exists if specified
    if req.DepartmentID != uuid.Nil {
        if _, err := s.companyRepo.GetDepartment(ctx, req.CompanyID, req.DepartmentID); err != nil {
            return fmt.Errorf("department not found: %w", err)
        }
    }

    // ✅ CHECK: Role level hierarchy
    if err := s.validateRoleAssignment(ctx, req.CompanyID, req.AddedBy, role.RoleLevel); err != nil {
        return err
    }

    // Create employee record
    emp := &models.CompanyEmployee{
        CompanyID:    req.CompanyID,
        UserID:       user.UserID,
        EmployeeID:   req.EmployeeID,
        RoleID:       req.RoleID,
        DepartmentID: req.DepartmentID,
        HireDate:     time.Now().UTC(),
        IsActive:     true,
        ReportsTo:    req.ReportsTo,
        CreatedAt:    time.Now().UTC(),
        UpdatedAt:    time.Now().UTC(),
    }

    if err := s.companyRepo.CreateCompanyEmployee(ctx, emp); err != nil {
        return fmt.Errorf("failed to add employee: %w", err)
    }

    // ✅ FIXED: Only update user's company ID, not role level
    if err := s.userService.UpdateUserCompany(ctx, user.UserID, req.CompanyID); err != nil {
        s.logger.Warn("failed to update user company",
            util.String("user_id", user.UserID.String()),
            util.ErrorField(err))
    }

    s.logger.Info("Employee added successfully",
        util.String("company_id", req.CompanyID.String()),
        util.String("user_id", user.UserID.String()),
        util.String("employee_id", req.EmployeeID),
        util.String("role_level", role.RoleLevel),
        util.String("department_id", req.DepartmentID.String()),
        util.String("added_by", req.AddedBy.String()),
    )

    return nil
}

// ✅ FIXED: Validate add employee permissions
func (s *CompanyService) validateAddEmployeePermission(ctx context.Context, companyID, addedBy, roleID, departmentID uuid.UUID) error {
    // Get the employee record of the user adding
    adderEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, addedBy)
    if err != nil || adderEmp == nil || !adderEmp.IsActive {
        return fmt.Errorf("user is not an active employee of this company")
    }

    // Get the role of the user adding
    adderRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, adderEmp.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get adder role: %w", err)
    }

    // Get the target role being assigned
    targetRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, roleID)
    if err != nil {
        return fmt.Errorf("failed to get target role: %w", err)
    }

    // Role hierarchy validation
    if !s.canAssignRole(adderRole.RoleLevel, targetRole.RoleLevel) {
        return fmt.Errorf("user with role %s cannot assign role %s", adderRole.RoleLevel, targetRole.RoleLevel)
    }

    // Department validation for managers
    if adderRole.RoleLevel == models.CompanyRoleLevelManager {
        if adderEmp.DepartmentID != departmentID {
            return fmt.Errorf("manager can only add employees to their own department")
        }
    }

    return nil
}

// ✅ FIXED: Role assignment validation
func (s *CompanyService) validateRoleAssignment(ctx context.Context, companyID, addedBy uuid.UUID, targetRoleLevel string) error {
    adderEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, addedBy)
    if err != nil {
        return err
    }

    adderRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, adderEmp.RoleID)
    if err != nil {
        return err
    }

    if !s.canAssignRole(adderRole.RoleLevel, targetRoleLevel) {
        return fmt.Errorf("insufficient permissions to assign role %s", targetRoleLevel)
    }

    return nil
}

// ✅ FIXED: Role assignment rules
func (s *CompanyService) canAssignRole(assignerRole, targetRole string) bool {
    roleHierarchy := map[string]bool{
        models.CompanyRoleLevelOwner:   true,
        models.CompanyRoleLevelManager: true,
        models.CompanyRoleLevelEmployee: true,
        models.CompanyRoleLevelViewer:  true,
    }

    if !roleHierarchy[assignerRole] || !roleHierarchy[targetRole] {
        return false
    }

    // Owners can assign any role except owner (single owner)
    if assignerRole == models.CompanyRoleLevelOwner {
        return targetRole != models.CompanyRoleLevelOwner
    }

    // Managers can only assign employee and viewer roles
    if assignerRole == models.CompanyRoleLevelManager {
        return targetRole == models.CompanyRoleLevelEmployee || targetRole == models.CompanyRoleLevelViewer
    }

    // Employees and viewers cannot assign any roles
    return false
}

// RemoveEmployee with permission checks
func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
    // Validate permissions
    if err := s.validateRemovePermission(ctx, companyID, userID, removedBy); err != nil {
        return err
    }

    // Deactivate employee
    if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
        return fmt.Errorf("failed to remove employee: %w", err)
    }

    // ✅ FIXED: Remove role level update since we're not storing it in user table
    // Just update user's company ID to Nil
    if err := s.userService.UpdateUserCompany(ctx, userID, uuid.Nil); err != nil {
        s.logger.Warn("Failed to update user company after removal", util.ErrorField(err))
    }

    s.logger.Info("Employee removed successfully",
        util.String("company_id", companyID.String()),
        util.String("user_id", userID.String()),
        util.String("removed_by", removedBy.String()),
    )

    return nil
}

// ✅ FIXED: Validate remove permissions
func (s *CompanyService) validateRemovePermission(ctx context.Context, companyID, targetUserID, removedBy uuid.UUID) error {
    // Cannot remove yourself
    if targetUserID == removedBy {
        return fmt.Errorf("cannot remove yourself")
    }

    // Get remover's employee record and role
    removerEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, removedBy)
    if err != nil || removerEmp == nil || !removerEmp.IsActive {
        return fmt.Errorf("user is not an active employee")
    }

    removerRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, removerEmp.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get remover role: %w", err)
    }

    // Get target user's employee record and role
    targetEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, targetUserID)
    if err != nil || targetEmp == nil {
        return fmt.Errorf("target employee not found")
    }

    targetRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, targetEmp.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get target role: %w", err)
    }

    // Check if remover can remove target based on role hierarchy
    if !s.canRemoveRole(removerRole.RoleLevel, targetRole.RoleLevel) {
        return fmt.Errorf("user with role %s cannot remove user with role %s", removerRole.RoleLevel, targetRole.RoleLevel)
    }

    // Department check for managers
    if removerRole.RoleLevel == models.CompanyRoleLevelManager {
        if removerEmp.DepartmentID != targetEmp.DepartmentID {
            return fmt.Errorf("manager can only remove employees from their own department")
        }
    }

    return nil
}

// ✅ FIXED: Remove role rules
func (s *CompanyService) canRemoveRole(removerRole, targetRole string) bool {
    roleHierarchy := map[string]bool{
        models.CompanyRoleLevelOwner:   true,
        models.CompanyRoleLevelManager: true,
        models.CompanyRoleLevelEmployee: true,
        models.CompanyRoleLevelViewer:  true,
    }

    if !roleHierarchy[removerRole] || !roleHierarchy[targetRole] {
        return false
    }

    // Owners can remove anyone except themselves
    if removerRole == models.CompanyRoleLevelOwner {
        return targetRole != models.CompanyRoleLevelOwner
    }

    // Managers can only remove employees and viewers
    if removerRole == models.CompanyRoleLevelManager {
        return targetRole == models.CompanyRoleLevelEmployee || targetRole == models.CompanyRoleLevelViewer
    }

    return false
}

// ✅ FIXED: GetCompanyContext with proper role handling
func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*models.CompanyContext, error) {
    user, err := s.userService.GetUserByID(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }

    if user.CompanyID == uuid.Nil {
        return nil, nil
    }

    company, err := s.companyRepo.GetCompany(ctx, user.CompanyID)
    if err != nil {
        return nil, fmt.Errorf("company not found: %w", err)
    }

    // ✅ CHECK: Subscription status
    subscriptionStatus := company.GetSubscriptionStatus()
    if subscriptionStatus != models.SubscriptionStatusActive {
        return nil, fmt.Errorf("subscription status: %s", subscriptionStatus)
    }

    employee, err := s.companyRepo.GetCompanyEmployee(ctx, user.CompanyID, userID)
    if err != nil || employee == nil || !employee.IsActive {
        return nil, fmt.Errorf("user is not an active employee")
    }

    role, err := s.companyRepo.GetEmployeeRole(ctx, user.CompanyID, employee.RoleID)
    if err != nil {
        return nil, fmt.Errorf("role not found: %w", err)
    }

    perms, err := s.companyRepo.GetEmployeePermissions(ctx, user.CompanyID, userID)
    if err != nil {
        s.logger.Warn("failed to get employee permissions", util.ErrorField(err))
    }

    allPerms := append(role.Permissions, perms...)
    
    return &models.CompanyContext{
        CompanyID:        company.CompanyID.String(),
        EmployeeID:       employee.EmployeeID,
        RoleID:           employee.RoleID.String(),
        RoleLevel:        role.RoleLevel, // Now from employee_roles table
        DepartmentID:     employee.DepartmentID.String(),
        Permissions:      allPerms,
        SubscriptionTier: company.SubscriptionTier,
    }, nil
}

// ============================================================
// EXISTING METHODS FROM OLD SERVICE (UPDATED AS NEEDED)
// ============================================================

func (s *CompanyService) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID) error {
    company, err := s.companyRepo.GetCompany(ctx, companyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }
    if company.IsBlocked {
        return fmt.Errorf("company already blocked")
    }

    now := time.Now().UTC()
    if err := s.companyRepo.BlockCompany(ctx, companyID, reason, blockedBy, now); err != nil {
        return fmt.Errorf("failed to block company: %w", err)
    }

    s.logger.Info("company blocked",
        util.String("company_id", companyID.String()),
        util.String("reason", reason),
    )
    return nil
}

func (s *CompanyService) UnblockCompany(ctx context.Context, companyID uuid.UUID, unblockedBy uuid.UUID) error {
    company, err := s.companyRepo.GetCompany(ctx, companyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }
    if !company.IsBlocked {
        return fmt.Errorf("company not blocked")
    }

    if err := s.companyRepo.UnblockCompany(ctx, companyID); err != nil {
        return fmt.Errorf("failed to unblock company: %w", err)
    }

    s.logger.Info("company unblocked",
        util.String("company_id", companyID.String()),
        util.String("unblocked_by", unblockedBy.String()),
    )
    return nil
}

func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedBy uuid.UUID) error {
    if _, err := s.companyRepo.GetCompany(ctx, companyID); err != nil {
        return fmt.Errorf("company not found: %w", err)
    }

    now := time.Now().UTC()
    if err := s.companyRepo.UpdateSubscription(ctx, companyID, tier, premium, maxEmployees, now); err != nil {
        return fmt.Errorf("failed to update subscription: %w", err)
    }

    s.logger.Info("subscription updated",
        util.String("company_id", companyID.String()),
        util.String("tier", tier),
        zap.Float64("premium", premium),
        util.Int("max_employees", maxEmployees),
    )

    return nil
}

func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, months int, updatedBy uuid.UUID) error {
    company, err := s.companyRepo.GetCompany(ctx, companyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }

    newEnd := company.SubscriptionEndDate.AddDate(0, months, 0)
    if err := s.companyRepo.UpdateSubscriptionEndDate(ctx, companyID, newEnd); err != nil {
        return fmt.Errorf("failed to extend subscription: %w", err)
    }

    s.logger.Info("subscription extended",
        util.String("company_id", companyID.String()),
        util.Int("months", months),
        util.String("new_end_date", newEnd.Format(time.RFC3339)),
    )
    return nil
}

func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
    return s.companyRepo.GetCompany(ctx, companyID)
}

func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
    return s.companyRepo.ListEmployees(ctx, companyID, page, limit)
}

// ✅ FIXED: Reactivate employee (for subscription renewal, etc.)
func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID, reactivatedBy uuid.UUID) error {
    company, err := s.companyRepo.GetCompany(ctx, companyID)
    if err != nil {
        return fmt.Errorf("company not found: %w", err)
    }

    // Check subscription limit
    activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, companyID)
    if err != nil {
        return fmt.Errorf("failed to get active employee count: %w", err)
    }
    if activeCount >= company.MaxEmployees {
        return fmt.Errorf("max active employee limit reached: %d/%d", activeCount, company.MaxEmployees)
    }

    // Reactivate employee
    if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
        return fmt.Errorf("failed to reactivate employee: %w", err)
    }

    s.logger.Info("Employee reactivated",
        util.String("company_id", companyID.String()),
        util.String("user_id", userID.String()),
        util.String("reactivated_by", reactivatedBy.String()),
    )
    return nil
}

// ✅ FIXED: List only active employees
func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
    return s.companyRepo.ListActiveEmployees(ctx, companyID, page, limit)
}

// ✅ FIXED: Check if user is active employee
func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
    emp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, userID)
    if err != nil {
        return false, err
    }
    return emp != nil && emp.IsActive, nil
}

// ============================================================
// ❌ REMOVED: Complex multi-filter ListCompanies methods
// ============================================================

// ============================================================
// NEW: Department Management Methods
// ============================================================

type CreateDepartmentRequest struct {
    CompanyID       uuid.UUID `json:"company_id" validate:"required"`
    DepartmentName  string    `json:"department_name" validate:"required"`
    DepartmentHead  uuid.UUID `json:"department_head"`
    Permissions     []string  `json:"permissions"`
    CreatedBy       uuid.UUID `json:"created_by" validate:"required"`
}

func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.CompanyDepartment, error) {
    // Validate company exists and user has permission
    _, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
    if err != nil {
        return nil, fmt.Errorf("company not found: %w", err)
    }

    // Validate user has permission to create department
    if err := s.validateDepartmentManagementPermission(ctx, req.CompanyID, req.CreatedBy); err != nil {
        return nil, err
    }

    // Validate department head exists if provided
    if req.DepartmentHead != uuid.Nil {
        if _, err := s.companyRepo.GetCompanyEmployee(ctx, req.CompanyID, req.DepartmentHead); err != nil {
            return nil, fmt.Errorf("department head not found: %w", err)
        }
    }

    department := &models.CompanyDepartment{
        CompanyID:      req.CompanyID,
        DepartmentID:   uuid.New(),
        DepartmentName: req.DepartmentName,
        DepartmentHead: req.DepartmentHead,
        Permissions:    req.Permissions,
        IsActive:       true,
        CreatedAt:      time.Now().UTC(),
        UpdatedAt:      time.Now().UTC(),
    }

    if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
        return nil, fmt.Errorf("failed to create department: %w", err)
    }

    s.logger.Info("Department created successfully",
        util.String("company_id", req.CompanyID.String()),
        util.String("department_id", department.DepartmentID.String()),
        util.String("department_name", req.DepartmentName),
    )

    return department, nil
}

func (s *CompanyService) validateDepartmentManagementPermission(ctx context.Context, companyID, userID uuid.UUID) error {
    emp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, userID)
    if err != nil || emp == nil || !emp.IsActive {
        return fmt.Errorf("user is not an active employee")
    }

    role, err := s.companyRepo.GetEmployeeRole(ctx, companyID, emp.RoleID)
    if err != nil {
        return fmt.Errorf("failed to get user role: %w", err)
    }

    // Only owners and managers can manage departments
    if role.RoleLevel != models.CompanyRoleLevelOwner && role.RoleLevel != models.CompanyRoleLevelManager {
        return fmt.Errorf("insufficient permissions to manage departments")
    }

    return nil
}

func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    return s.companyRepo.ListDepartmentsByCompany(ctx, companyID, limit)
}

func (s *CompanyService) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
    return s.companyRepo.GetDepartment(ctx, companyID, departmentID)
}

// ============================================================
// Role and Permission Methods
// ============================================================

func (s *CompanyService) getAllPermissions() []string {
    return []string{
        models.PermissionCompanyRead,
        models.PermissionCompanyWrite,
        models.PermissionCompanyManage,
        models.PermissionEmployeeRead,
        models.PermissionEmployeeWrite,
        models.PermissionEmployeeManage,
        models.PermissionDepartmentRead,
        models.PermissionDepartmentWrite,
        models.PermissionDepartmentManage,
        models.PermissionHRAttendanceRead,
        models.PermissionHRAttendanceWrite,
        models.PermissionHRLeaveRead,
        models.PermissionHRLeaveWrite,
        models.PermissionHRPayrollRead,
        models.PermissionHRPayrollWrite,
        models.PermissionFinanceExpenseRead,
        models.PermissionFinanceExpenseWrite,
        models.PermissionFinanceInvoiceRead,
        models.PermissionFinanceInvoiceWrite,
        models.PermissionInventoryRead,
        models.PermissionInventoryWrite,
        models.PermissionSalesRead,
        models.PermissionSalesWrite,
        models.PermissionReportsRead,
        models.PermissionReportsWrite,
    }
}

// ============================================================
// Health Check
// ============================================================

func (s *CompanyService) HealthCheck(ctx context.Context) error {
    return s.companyRepo.HealthCheck(ctx)
}

// ============================================================
// Utility Methods
// ============================================================

func (s *CompanyService) LogCompanyStatus(company *models.Company) {
    status := company.GetSubscriptionStatus()
    s.logger.Info("Company status check",
        zap.String("company_id", company.CompanyID.String()),
        zap.String("status", status),
        zap.Time("subscription_end_date", company.SubscriptionEndDate),
    )
}


func (s *CompanyService) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
    return s.companyRepo.GetActiveEmployeeCount(ctx, companyID)
}
// Add these methods to CompanyService

// GetCompaniesByBlockedStatus returns companies by blocked status
func (s *CompanyService) GetCompaniesByBlockedStatus(ctx context.Context, isBlocked bool, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    return s.companyRepo.GetCompaniesByBlockedStatus(ctx, isBlocked, limit)
}

// GetRecentCompanies returns recently created companies
func (s *CompanyService) GetRecentCompanies(ctx context.Context, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    return s.companyRepo.GetCompaniesByCreatedDate(ctx, limit)
}

// ============================================================
// NEW: Optimized Company Queries with Materialized Views
// ============================================================

// // GetCompaniesByTier retrieves companies by subscription tier using materialized view
// func (s *CompanyService) GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTier(ctx, tier, limit)
// }

// // GetCompaniesByTierAndActive retrieves companies by tier and active status using materialized view
// func (s *CompanyService) GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTierAndActive(ctx, tier, isActive, limit)
// }

// // GetCompaniesByTierAndBlocked retrieves companies by tier and blocked status using materialized view
// func (s *CompanyService) GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTierAndBlocked(ctx, tier, isBlocked, limit)
// }

// // GetCompaniesBySubscriptionDateRange retrieves companies by subscription date range using materialized view
// func (s *CompanyService) GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesBySubscriptionDateRange(ctx, startDate, endDate, limit)
// }


// // ✅ ADD these service methods
// func (s *CompanyService) GetCompaniesByBlockedStatus(ctx context.Context, isBlocked bool, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByBlockedStatus(ctx, isBlocked, limit)
// }

// func (s *CompanyService) GetRecentCompanies(ctx context.Context, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByCreatedDate(ctx, limit)
// }
// GetCompaniesByActiveStatus returns companies by active status
func (s *CompanyService) GetCompaniesByActiveStatus(ctx context.Context, isActive bool, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    return s.companyRepo.GetCompaniesByActiveStatus(ctx, isActive, limit)
}
// // GetCompaniesWithExpiringSubscription returns companies whose subscription ends within specified days
// func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
//     if days <= 0 || days > 365 {
//         days = 7 // Default to 1 week
//     }
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
    
//     companies, err := s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
//     if err != nil {
//         return nil, fmt.Errorf("failed to get companies with expiring subscriptions: %w", err)
//     }
    
//     s.logger.Info("Retrieved companies with expiring subscriptions",
//         zap.Int("days", days),
//         zap.Int("count", len(companies)),
//     )
    
//     return companies, nil
// }


func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
    // Get all active companies first
    companies, err := s.companyRepo.GetCompaniesByActiveStatus(ctx, true, 1000)
    if err != nil {
        return nil, err
    }
    
    // Filter in memory
    var expiring []*models.Company
    cutoff := time.Now().AddDate(0, 0, days)
    
    for _, company := range companies {
        if company.SubscriptionEndDate.Before(cutoff) && company.SubscriptionEndDate.After(time.Now()) {
            expiring = append(expiring, company)
        }
        if len(expiring) >= limit {
            break
        }
    }
    
    return expiring, nil
}
// // service/company_service.go
// package service

// import (
//     "context"
//     "fmt"
//     "time"

//     "auth-service/internal/models"
//     "auth-service/internal/repository/scylla"
//     "auth-service/internal/util"

//     "github.com/google/uuid"
//     "go.uber.org/zap"
// )

// type CompanyService struct {
//     companyRepo scylla.CompanyRepository
//     userService *UserService
//     adminRepo   scylla.AdminRepository
//     logger      *zap.Logger
// }

// func NewCompanyService(
//     companyRepo scylla.CompanyRepository,
//     userService *UserService,
//     adminRepo   scylla.AdminRepository,
//     logger      *zap.Logger,
// ) *CompanyService {
//     return &CompanyService{
//         companyRepo: companyRepo,
//         userService: userService,
//         adminRepo:   adminRepo,
//         logger:      logger,
//     }
// }

// // CreateCompanyRequest with enhanced validation
// type CreateCompanyRequest struct {
//     CompanyName      string    `json:"company_name" validate:"required"`
//     OwnerPhone       string    `json:"owner_phone" validate:"required"`
//     SubscriptionTier string    `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
//     MonthlyPremium   float64   `json:"monthly_premium" validate:"required,min=0"`
//     MaxEmployees     int       `json:"max_employees" validate:"required,min=1,max=2000"`
//     DataRegion       string    `json:"data_region" validate:"required"`
//     CreatedByAdmin   uuid.UUID `json:"-"`
// }

// // ✅ FIXED: CreateCompany with proper error handling
// func (s *CompanyService) CreateCompany(ctx context.Context, req *CreateCompanyRequest) (*models.Company, error) {
//     // ✅ CHECK: Check if phone number already exists as user
//     existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
//     if err == nil && existingUser != nil {
//         // Check if user already owns a company
//         existingCompanies, err := s.companyRepo.GetCompaniesByOwner(ctx, existingUser.UserID)
//         if err == nil && len(existingCompanies) > 0 {
//             return nil, fmt.Errorf("user already owns a company")
//         }
        
//         // Use existing user as owner
//         ownerUser := existingUser
//         s.logger.Info("Using existing user as company owner",
//             util.String("user_id", ownerUser.UserID.String()),
//             util.String("phone", req.OwnerPhone))
        
//         return s.createCompanyWithOwner(ctx, req, ownerUser)
//     }

//     // ✅ FIXED: Auto-create user for company owner if not exists
//     s.logger.Info("Creating new user for company owner", util.String("phone", req.OwnerPhone))
    
//     ownerUser, err := s.userService.CreateUserForCompanyOwner(ctx, req.OwnerPhone, req.DataRegion)
//     if err != nil {
//         return nil, fmt.Errorf("failed to create user for company owner: %w", err)
//     }

//     s.logger.Info("Created new user for company owner",
//         util.String("user_id", ownerUser.UserID.String()),
//         util.String("phone", req.OwnerPhone))

//     return s.createCompanyWithOwner(ctx, req, ownerUser)
// }

// // ✅ FIXED: Single createCompanyWithOwner method without role level
// func (s *CompanyService) createCompanyWithOwner(ctx context.Context, req *CreateCompanyRequest, ownerUser *models.User) (*models.Company, error) {
//     start := time.Now()
//     companyID := uuid.New()
//     now := time.Now().UTC()
//     subscriptionEnd := now.AddDate(0, 1, 0)

//     company := &models.Company{
//         CompanyID:             companyID,
//         CompanyName:           req.CompanyName,
//         OwnerPhone:            req.OwnerPhone,
//         OwnerUserID:           ownerUser.UserID,
//         SubscriptionTier:      req.SubscriptionTier,
//         SubscriptionStartDate: now,
//         SubscriptionEndDate:   subscriptionEnd,
//         MonthlyPremium:        req.MonthlyPremium,
//         MaxEmployees:          req.MaxEmployees,
//         IsActive:              true,
//         IsBlocked:             false,
//         CreatedAt:             now,
//         UpdatedAt:             now,
//         DataRegion:            req.DataRegion,
//     }

//     if err := s.companyRepo.CreateCompany(ctx, company); err != nil {
//         return nil, fmt.Errorf("failed to create company: %w", err)
//     }

//     // ✅ FIXED: Only update user's company ID, not role level
//     if err := s.userService.UpdateUserCompany(ctx, ownerUser.UserID, companyID); err != nil {
//         s.logger.Warn("failed to update user company",
//             util.String("user_id", ownerUser.UserID.String()),
//             util.ErrorField(err))
//         // Don't return error here as company is already created
//     }

//     // Create owner role and employee record
//     if err := s.createCompanyOwnerSetup(ctx, companyID, ownerUser.UserID); err != nil {
//         // Rollback company creation if setup fails
//         _ = s.companyRepo.UpdateCompanyStatus(ctx, companyID, false)
//         return nil, fmt.Errorf("failed to setup company owner: %w", err)
//     }

//     s.logger.Info("Company created successfully",
//         util.String("company_id", companyID.String()),
//         util.String("company_name", req.CompanyName),
//         util.String("owner_user_id", ownerUser.UserID.String()),
//         util.Duration("duration", time.Since(start)),
//     )

//     return company, nil
// }

// // ✅ FIXED: Enhanced company owner setup with proper role creation
// func (s *CompanyService) createCompanyOwnerSetup(ctx context.Context, companyID, ownerUserID uuid.UUID) error {
//     // Create owner role in employee_roles table
//     ownerRole := &models.EmployeeRole{
//         CompanyID:    companyID,
//         RoleID:       uuid.New(),
//         RoleName:     "Company Owner",
//         RoleLevel:    models.CompanyRoleLevelOwner,
//         Permissions:  s.getAllPermissions(),
//         DepartmentID: uuid.Nil, // Owner has no department
//         IsSystemRole: true,
//         CreatedAt:    time.Now().UTC(),
//         UpdatedAt:    time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateEmployeeRole(ctx, ownerRole); err != nil {
//         return fmt.Errorf("failed to create owner role: %w", err)
//     }

//     // Create owner employee record in company_employees table
//     ownerEmployee := &models.CompanyEmployee{
//         CompanyID:    companyID,
//         UserID:       ownerUserID,
//         EmployeeID:   "OWNER-001",
//         RoleID:       ownerRole.RoleID,
//         DepartmentID: uuid.Nil, // Owner has no department
//         HireDate:     time.Now().UTC(),
//         IsActive:     true,
//         ReportsTo:    uuid.Nil, // Owner doesn't report to anyone
//         CreatedAt:    time.Now().UTC(),
//         UpdatedAt:    time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateCompanyEmployee(ctx, ownerEmployee); err != nil {
//         return fmt.Errorf("failed to add owner as employee: %w", err)
//     }

//     s.logger.Info("Company owner setup completed",
//         util.String("company_id", companyID.String()),
//         util.String("user_id", ownerUserID.String()),
//         util.String("role_id", ownerRole.RoleID.String()),
//     )

//     return nil
// }

// // AddEmployeeRequest with enhanced fields
// type AddEmployeeRequest struct {
//     CompanyID     uuid.UUID `json:"company_id" validate:"required"`
//     PhoneNumber   string    `json:"phone_number" validate:"required"`
//     EmployeeID    string    `json:"employee_id" validate:"required"`
//     RoleID        uuid.UUID `json:"role_id" validate:"required"`
//     DepartmentID  uuid.UUID `json:"department_id" validate:"required"`
//     ReportsTo     uuid.UUID `json:"reports_to"`
//     AddedBy       uuid.UUID `json:"added_by" validate:"required"` // User adding this employee
// }

// // ✅ FIXED: AddEmployee with proper method calls
// func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
//     // Validate company
//     company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }
    
//     if !company.IsActive || company.IsBlocked {
//         return fmt.Errorf("company is not active")
//     }

//     // ✅ CHECK: Subscription active
//     if !company.IsSubscriptionActive() {
//         return fmt.Errorf("company subscription is not active")
//     }

//     // ✅ CHECK: Employee limit
//     activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
//     if err != nil {
//         return fmt.Errorf("failed to get active employee count: %w", err)
//     }
//     if activeCount >= company.MaxEmployees {
//         return fmt.Errorf("max active employee limit reached: %d/%d", activeCount, company.MaxEmployees)
//     }

//     // ✅ CHECK: Permissions of the user adding the employee
//     if err := s.validateAddEmployeePermission(ctx, req.CompanyID, req.AddedBy, req.RoleID, req.DepartmentID); err != nil {
//         return err
//     }

//     // ✅ STRICT: User must exist
//     user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
//     if err != nil {
//         return fmt.Errorf("user not found with phone: %s. User must be registered first", req.PhoneNumber)
//     }

//     // ✅ CHECK: Not already an active employee
//     if existing, _ := s.companyRepo.GetCompanyEmployee(ctx, req.CompanyID, user.UserID); existing != nil && existing.IsActive {
//         return fmt.Errorf("user is already an active employee in this company")
//     }

//     // ✅ VALIDATE: Role exists and is valid
//     role, err := s.companyRepo.GetEmployeeRole(ctx, req.CompanyID, req.RoleID)
//     if err != nil {
//         return fmt.Errorf("role not found: %w", err)
//     }

//     // ✅ VALIDATE: Department exists if specified
//     if req.DepartmentID != uuid.Nil {
//         if _, err := s.companyRepo.GetDepartment(ctx, req.CompanyID, req.DepartmentID); err != nil {
//             return fmt.Errorf("department not found: %w", err)
//         }
//     }

//     // ✅ CHECK: Role level hierarchy
//     if err := s.validateRoleAssignment(ctx, req.CompanyID, req.AddedBy, role.RoleLevel); err != nil {
//         return err
//     }

//     // Create employee record
//     emp := &models.CompanyEmployee{
//         CompanyID:    req.CompanyID,
//         UserID:       user.UserID,
//         EmployeeID:   req.EmployeeID,
//         RoleID:       req.RoleID,
//         DepartmentID: req.DepartmentID,
//         HireDate:     time.Now().UTC(),
//         IsActive:     true,
//         ReportsTo:    req.ReportsTo,
//         CreatedAt:    time.Now().UTC(),
//         UpdatedAt:    time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateCompanyEmployee(ctx, emp); err != nil {
//         return fmt.Errorf("failed to add employee: %w", err)
//     }

//     // ✅ FIXED: Only update user's company ID, not role level
//     if err := s.userService.UpdateUserCompany(ctx, user.UserID, req.CompanyID); err != nil {
//         s.logger.Warn("failed to update user company",
//             util.String("user_id", user.UserID.String()),
//             util.ErrorField(err))
//     }

//     s.logger.Info("Employee added successfully",
//         util.String("company_id", req.CompanyID.String()),
//         util.String("user_id", user.UserID.String()),
//         util.String("employee_id", req.EmployeeID),
//         util.String("role_level", role.RoleLevel),
//         util.String("department_id", req.DepartmentID.String()),
//         util.String("added_by", req.AddedBy.String()),
//     )

//     return nil
// }

// // ✅ FIXED: Validate add employee permissions
// func (s *CompanyService) validateAddEmployeePermission(ctx context.Context, companyID, addedBy, roleID, departmentID uuid.UUID) error {
//     // Get the employee record of the user adding
//     adderEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, addedBy)
//     if err != nil || adderEmp == nil || !adderEmp.IsActive {
//         return fmt.Errorf("user is not an active employee of this company")
//     }

//     // Get the role of the user adding
//     adderRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, adderEmp.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get adder role: %w", err)
//     }

//     // Get the target role being assigned
//     targetRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, roleID)
//     if err != nil {
//         return fmt.Errorf("failed to get target role: %w", err)
//     }

//     // Role hierarchy validation
//     if !s.canAssignRole(adderRole.RoleLevel, targetRole.RoleLevel) {
//         return fmt.Errorf("user with role %s cannot assign role %s", adderRole.RoleLevel, targetRole.RoleLevel)
//     }

//     // Department validation for managers
//     if adderRole.RoleLevel == models.CompanyRoleLevelManager {
//         if adderEmp.DepartmentID != departmentID {
//             return fmt.Errorf("manager can only add employees to their own department")
//         }
//     }

//     return nil
// }

// // ✅ FIXED: Role assignment validation
// func (s *CompanyService) validateRoleAssignment(ctx context.Context, companyID, addedBy uuid.UUID, targetRoleLevel string) error {
//     adderEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, addedBy)
//     if err != nil {
//         return err
//     }

//     adderRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, adderEmp.RoleID)
//     if err != nil {
//         return err
//     }

//     if !s.canAssignRole(adderRole.RoleLevel, targetRoleLevel) {
//         return fmt.Errorf("insufficient permissions to assign role %s", targetRoleLevel)
//     }

//     return nil
// }

// // ✅ FIXED: Role assignment rules
// func (s *CompanyService) canAssignRole(assignerRole, targetRole string) bool {
//     roleHierarchy := map[string]bool{
//         models.CompanyRoleLevelOwner:   true,
//         models.CompanyRoleLevelManager: true,
//         models.CompanyRoleLevelEmployee: true,
//         models.CompanyRoleLevelViewer:  true,
//     }

//     if !roleHierarchy[assignerRole] || !roleHierarchy[targetRole] {
//         return false
//     }

//     // Owners can assign any role except owner (single owner)
//     if assignerRole == models.CompanyRoleLevelOwner {
//         return targetRole != models.CompanyRoleLevelOwner
//     }

//     // Managers can only assign employee and viewer roles
//     if assignerRole == models.CompanyRoleLevelManager {
//         return targetRole == models.CompanyRoleLevelEmployee || targetRole == models.CompanyRoleLevelViewer
//     }

//     // Employees and viewers cannot assign any roles
//     return false
// }

// // RemoveEmployee with permission checks
// func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
//     // Validate permissions
//     if err := s.validateRemovePermission(ctx, companyID, userID, removedBy); err != nil {
//         return err
//     }

//     // Deactivate employee
//     if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
//         return fmt.Errorf("failed to remove employee: %w", err)
//     }

//     // ✅ FIXED: Remove role level update since we're not storing it in user table
//     // Just update user's company ID to Nil
//     if err := s.userService.UpdateUserCompany(ctx, userID, uuid.Nil); err != nil {
//         s.logger.Warn("Failed to update user company after removal", util.ErrorField(err))
//     }

//     s.logger.Info("Employee removed successfully",
//         util.String("company_id", companyID.String()),
//         util.String("user_id", userID.String()),
//         util.String("removed_by", removedBy.String()),
//     )

//     return nil
// }

// // ✅ FIXED: Validate remove permissions
// func (s *CompanyService) validateRemovePermission(ctx context.Context, companyID, targetUserID, removedBy uuid.UUID) error {
//     // Cannot remove yourself
//     if targetUserID == removedBy {
//         return fmt.Errorf("cannot remove yourself")
//     }

//     // Get remover's employee record and role
//     removerEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, removedBy)
//     if err != nil || removerEmp == nil || !removerEmp.IsActive {
//         return fmt.Errorf("user is not an active employee")
//     }

//     removerRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, removerEmp.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get remover role: %w", err)
//     }

//     // Get target user's employee record and role
//     targetEmp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, targetUserID)
//     if err != nil || targetEmp == nil {
//         return fmt.Errorf("target employee not found")
//     }

//     targetRole, err := s.companyRepo.GetEmployeeRole(ctx, companyID, targetEmp.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get target role: %w", err)
//     }

//     // Check if remover can remove target based on role hierarchy
//     if !s.canRemoveRole(removerRole.RoleLevel, targetRole.RoleLevel) {
//         return fmt.Errorf("user with role %s cannot remove user with role %s", removerRole.RoleLevel, targetRole.RoleLevel)
//     }

//     // Department check for managers
//     if removerRole.RoleLevel == models.CompanyRoleLevelManager {
//         if removerEmp.DepartmentID != targetEmp.DepartmentID {
//             return fmt.Errorf("manager can only remove employees from their own department")
//         }
//     }

//     return nil
// }

// // ✅ FIXED: Remove role rules
// func (s *CompanyService) canRemoveRole(removerRole, targetRole string) bool {
//     roleHierarchy := map[string]bool{
//         models.CompanyRoleLevelOwner:   true,
//         models.CompanyRoleLevelManager: true,
//         models.CompanyRoleLevelEmployee: true,
//         models.CompanyRoleLevelViewer:  true,
//     }

//     if !roleHierarchy[removerRole] || !roleHierarchy[targetRole] {
//         return false
//     }

//     // Owners can remove anyone except themselves
//     if removerRole == models.CompanyRoleLevelOwner {
//         return targetRole != models.CompanyRoleLevelOwner
//     }

//     // Managers can only remove employees and viewers
//     if removerRole == models.CompanyRoleLevelManager {
//         return targetRole == models.CompanyRoleLevelEmployee || targetRole == models.CompanyRoleLevelViewer
//     }

//     return false
// }

// // ✅ FIXED: GetCompanyContext with proper role handling
// func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*models.CompanyContext, error) {
//     user, err := s.userService.GetUserByID(ctx, userID)
//     if err != nil {
//         return nil, fmt.Errorf("user not found: %w", err)
//     }

//     if user.CompanyID == uuid.Nil {
//         return nil, nil
//     }

//     company, err := s.companyRepo.GetCompany(ctx, user.CompanyID)
//     if err != nil {
//         return nil, fmt.Errorf("company not found: %w", err)
//     }

//     // ✅ CHECK: Subscription status
//     subscriptionStatus := company.GetSubscriptionStatus()
//     if subscriptionStatus != models.SubscriptionStatusActive {
//         return nil, fmt.Errorf("subscription status: %s", subscriptionStatus)
//     }

//     employee, err := s.companyRepo.GetCompanyEmployee(ctx, user.CompanyID, userID)
//     if err != nil || employee == nil || !employee.IsActive {
//         return nil, fmt.Errorf("user is not an active employee")
//     }

//     role, err := s.companyRepo.GetEmployeeRole(ctx, user.CompanyID, employee.RoleID)
//     if err != nil {
//         return nil, fmt.Errorf("role not found: %w", err)
//     }

//     perms, err := s.companyRepo.GetEmployeePermissions(ctx, user.CompanyID, userID)
//     if err != nil {
//         s.logger.Warn("failed to get employee permissions", util.ErrorField(err))
//     }

//     allPerms := append(role.Permissions, perms...)
    
//     return &models.CompanyContext{
//         CompanyID:        company.CompanyID.String(),
//         EmployeeID:       employee.EmployeeID,
//         RoleID:           employee.RoleID.String(),
//         RoleLevel:        role.RoleLevel, // Now from employee_roles table
//         DepartmentID:     employee.DepartmentID.String(),
//         Permissions:      allPerms,
//         SubscriptionTier: company.SubscriptionTier,
//     }, nil
// }

// // ============================================================
// // EXISTING METHODS FROM OLD SERVICE (UPDATED AS NEEDED)
// // ============================================================

// func (s *CompanyService) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID) error {
//     company, err := s.companyRepo.GetCompany(ctx, companyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }
//     if company.IsBlocked {
//         return fmt.Errorf("company already blocked")
//     }

//     now := time.Now().UTC()
//     if err := s.companyRepo.BlockCompany(ctx, companyID, reason, blockedBy, now); err != nil {
//         return fmt.Errorf("failed to block company: %w", err)
//     }

//     s.logger.Info("company blocked",
//         util.String("company_id", companyID.String()),
//         util.String("reason", reason),
//     )
//     return nil
// }

// func (s *CompanyService) UnblockCompany(ctx context.Context, companyID uuid.UUID, unblockedBy uuid.UUID) error {
//     company, err := s.companyRepo.GetCompany(ctx, companyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }
//     if !company.IsBlocked {
//         return fmt.Errorf("company not blocked")
//     }

//     if err := s.companyRepo.UnblockCompany(ctx, companyID); err != nil {
//         return fmt.Errorf("failed to unblock company: %w", err)
//     }

//     s.logger.Info("company unblocked",
//         util.String("company_id", companyID.String()),
//         util.String("unblocked_by", unblockedBy.String()),
//     )
//     return nil
// }

// func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedBy uuid.UUID) error {
//     if _, err := s.companyRepo.GetCompany(ctx, companyID); err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }

//     now := time.Now().UTC()
//     if err := s.companyRepo.UpdateSubscription(ctx, companyID, tier, premium, maxEmployees, now); err != nil {
//         return fmt.Errorf("failed to update subscription: %w", err)
//     }

//     s.logger.Info("subscription updated",
//         util.String("company_id", companyID.String()),
//         util.String("tier", tier),
//         zap.Float64("premium", premium),
//         util.Int("max_employees", maxEmployees),
//     )

//     return nil
// }

// func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, months int, updatedBy uuid.UUID) error {
//     company, err := s.companyRepo.GetCompany(ctx, companyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }

//     newEnd := company.SubscriptionEndDate.AddDate(0, months, 0)
//     if err := s.companyRepo.UpdateSubscriptionEndDate(ctx, companyID, newEnd); err != nil {
//         return fmt.Errorf("failed to extend subscription: %w", err)
//     }

//     s.logger.Info("subscription extended",
//         util.String("company_id", companyID.String()),
//         util.Int("months", months),
//         util.String("new_end_date", newEnd.Format(time.RFC3339)),
//     )
//     return nil
// }

// func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
//     return s.companyRepo.GetCompany(ctx, companyID)
// }

// func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
//     return s.companyRepo.ListEmployees(ctx, companyID, page, limit)
// }

// // ✅ FIXED: Reactivate employee (for subscription renewal, etc.)
// func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID, reactivatedBy uuid.UUID) error {
//     company, err := s.companyRepo.GetCompany(ctx, companyID)
//     if err != nil {
//         return fmt.Errorf("company not found: %w", err)
//     }

//     // Check subscription limit
//     activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, companyID)
//     if err != nil {
//         return fmt.Errorf("failed to get active employee count: %w", err)
//     }
//     if activeCount >= company.MaxEmployees {
//         return fmt.Errorf("max active employee limit reached: %d/%d", activeCount, company.MaxEmployees)
//     }

//     // Reactivate employee
//     if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
//         return fmt.Errorf("failed to reactivate employee: %w", err)
//     }

//     s.logger.Info("Employee reactivated",
//         util.String("company_id", companyID.String()),
//         util.String("user_id", userID.String()),
//         util.String("reactivated_by", reactivatedBy.String()),
//     )
//     return nil
// }

// // ✅ FIXED: List only active employees
// func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
//     return s.companyRepo.ListActiveEmployees(ctx, companyID, page, limit)
// }

// // ✅ FIXED: Check if user is active employee
// func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
//     emp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, userID)
//     if err != nil {
//         return false, err
//     }
//     return emp != nil && emp.IsActive, nil
// }

// // ============================================================
// // NEW: Company List with Materialized Views
// // ============================================================

// // ListCompanies retrieves companies with pagination and filters using materialized views
// func (s *CompanyService) ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error) {
//     companies, total, err := s.companyRepo.ListCompanies(ctx, filter, page, limit)
//     if err != nil {
//         return nil, 0, fmt.Errorf("failed to list companies: %w", err)
//     }
//     return companies, total, nil
// }

// // ListCompaniesWithPaging retrieves companies with pagination state
// func (s *CompanyService) ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error) {
//     return s.companyRepo.ListCompaniesWithPaging(ctx, filter, pageSize, pageState)
// }

// // GetCompaniesByStatus retrieves companies by subscription status
// func (s *CompanyService) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
//     return s.companyRepo.GetCompaniesByStatus(ctx, status, limit)
// }

// // ============================================================
// // NEW: Department Management Methods
// // ============================================================

// type CreateDepartmentRequest struct {
//     CompanyID       uuid.UUID `json:"company_id" validate:"required"`
//     DepartmentName  string    `json:"department_name" validate:"required"`
//     DepartmentHead  uuid.UUID `json:"department_head"`
//     Permissions     []string  `json:"permissions"`
//     CreatedBy       uuid.UUID `json:"created_by" validate:"required"`
// }

// func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.CompanyDepartment, error) {
//     // Validate company exists and user has permission
//     _, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
//     if err != nil {
//         return nil, fmt.Errorf("company not found: %w", err)
//     }

//     // Validate user has permission to create department
//     if err := s.validateDepartmentManagementPermission(ctx, req.CompanyID, req.CreatedBy); err != nil {
//         return nil, err
//     }

//     // Validate department head exists if provided
//     if req.DepartmentHead != uuid.Nil {
//         if _, err := s.companyRepo.GetCompanyEmployee(ctx, req.CompanyID, req.DepartmentHead); err != nil {
//             return nil, fmt.Errorf("department head not found: %w", err)
//         }
//     }

//     department := &models.CompanyDepartment{
//         CompanyID:      req.CompanyID,
//         DepartmentID:   uuid.New(),
//         DepartmentName: req.DepartmentName,
//         DepartmentHead: req.DepartmentHead,
//         Permissions:    req.Permissions,
//         IsActive:       true,
//         CreatedAt:      time.Now().UTC(),
//         UpdatedAt:      time.Now().UTC(),
//     }

//     if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
//         return nil, fmt.Errorf("failed to create department: %w", err)
//     }

//     s.logger.Info("Department created successfully",
//         util.String("company_id", req.CompanyID.String()),
//         util.String("department_id", department.DepartmentID.String()),
//         util.String("department_name", req.DepartmentName),
//     )

//     return department, nil
// }

// func (s *CompanyService) validateDepartmentManagementPermission(ctx context.Context, companyID, userID uuid.UUID) error {
//     emp, err := s.companyRepo.GetCompanyEmployee(ctx, companyID, userID)
//     if err != nil || emp == nil || !emp.IsActive {
//         return fmt.Errorf("user is not an active employee")
//     }

//     role, err := s.companyRepo.GetEmployeeRole(ctx, companyID, emp.RoleID)
//     if err != nil {
//         return fmt.Errorf("failed to get user role: %w", err)
//     }

//     // Only owners and managers can manage departments
//     if role.RoleLevel != models.CompanyRoleLevelOwner && role.RoleLevel != models.CompanyRoleLevelManager {
//         return fmt.Errorf("insufficient permissions to manage departments")
//     }

//     return nil
// }

// func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.ListDepartmentsByCompany(ctx, companyID, limit)
// }

// func (s *CompanyService) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
//     return s.companyRepo.GetDepartment(ctx, companyID, departmentID)
// }

// // ============================================================
// // Role and Permission Methods
// // ============================================================

// func (s *CompanyService) getAllPermissions() []string {
//     return []string{
//         models.PermissionCompanyRead,
//         models.PermissionCompanyWrite,
//         models.PermissionCompanyManage,
//         models.PermissionEmployeeRead,
//         models.PermissionEmployeeWrite,
//         models.PermissionEmployeeManage,
//         models.PermissionDepartmentRead,
//         models.PermissionDepartmentWrite,
//         models.PermissionDepartmentManage,
//         models.PermissionHRAttendanceRead,
//         models.PermissionHRAttendanceWrite,
//         models.PermissionHRLeaveRead,
//         models.PermissionHRLeaveWrite,
//         models.PermissionHRPayrollRead,
//         models.PermissionHRPayrollWrite,
//         models.PermissionFinanceExpenseRead,
//         models.PermissionFinanceExpenseWrite,
//         models.PermissionFinanceInvoiceRead,
//         models.PermissionFinanceInvoiceWrite,
//         models.PermissionInventoryRead,
//         models.PermissionInventoryWrite,
//         models.PermissionSalesRead,
//         models.PermissionSalesWrite,
//         models.PermissionReportsRead,
//         models.PermissionReportsWrite,
//     }
// }

// // ============================================================
// // Health Check
// // ============================================================

// func (s *CompanyService) HealthCheck(ctx context.Context) error {
//     return s.companyRepo.HealthCheck(ctx)
// }

// // ============================================================
// // Utility Methods
// // ============================================================

// func (s *CompanyService) LogCompanyStatus(company *models.Company) {
//     status := company.GetSubscriptionStatus()
//     s.logger.Info("Company status check",
//         zap.String("company_id", company.CompanyID.String()),
//         zap.String("status", status),
//         zap.Time("subscription_end_date", company.SubscriptionEndDate),
//     )
// }


// func (s *CompanyService) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
//     return s.companyRepo.GetActiveEmployeeCount(ctx, companyID)
// }

// // ============================================================
// // NEW: Optimized Company Queries with Materialized Views
// // ============================================================

// // GetCompaniesByTier retrieves companies by subscription tier using materialized view
// func (s *CompanyService) GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTier(ctx, tier, limit)
// }

// // GetCompaniesByTierAndActive retrieves companies by tier and active status using materialized view
// func (s *CompanyService) GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTierAndActive(ctx, tier, isActive, limit)
// }

// // GetCompaniesByTierAndBlocked retrieves companies by tier and blocked status using materialized view
// func (s *CompanyService) GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesByTierAndBlocked(ctx, tier, isBlocked, limit)
// }

// // GetCompaniesBySubscriptionDateRange retrieves companies by subscription date range using materialized view
// func (s *CompanyService) GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error) {
//     if limit <= 0 || limit > 1000 {
//         limit = 100
//     }
//     return s.companyRepo.GetCompaniesBySubscriptionDateRange(ctx, startDate, endDate, limit)
// }

// // ============================================================
// // UPDATED: ListCompanies with Optimized Simple Filters
// // ============================================================

// // ListCompanies retrieves companies with pagination and filters using materialized views
// func (s *CompanyService) ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error) {
//     companies, total, err := s.companyRepo.ListCompanies(ctx, filter, page, limit)
//     if err != nil {
//         return nil, 0, fmt.Errorf("failed to list companies: %w", err)
//     }
//     return companies, total, nil
// }

// // ListCompaniesWithPaging retrieves companies with pagination state
// func (s *CompanyService) ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error) {
//     return s.companyRepo.ListCompaniesWithPaging(ctx, filter, pageSize, pageState)
// }

// // GetCompaniesByStatus retrieves companies by subscription status
// func (s *CompanyService) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
//     return s.companyRepo.GetCompaniesByStatus(ctx, status, limit)
// }

