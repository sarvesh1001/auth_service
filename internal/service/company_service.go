// Package service defines the company service layer with audit, idempotency, and application-specific errors.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
)

// CompanyService handles company, employee, role, department, and position management.
type CompanyService struct {
	companyRepo      postgres.CompanyRepository
	userService      *UserService
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	config           config.Config
}

// NewCompanyService creates a new CompanyService.
func NewCompanyService(
	companyRepo postgres.CompanyRepository,
	userService *UserService,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	config config.Config,
) *CompanyService {
	return &CompanyService{
		companyRepo:      companyRepo,
		userService:      userService,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		config:           config,
	}
}

// ---- Permission helpers ----

// CheckMultiplePermissionsFromContext checks multiple permissions from context using bitmask.
func (s *CompanyService) CheckMultiplePermissionsFromContext(ctx context.Context, permissions []string, checkAll bool) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("%w: session type not found", appErrors.ErrUnauthorized)
	}
	if sessionType == "admin" {
		return true, nil
	}
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return false, fmt.Errorf("%w: permission mask not found", appErrors.ErrPermissionDenied)
	}
	if checkAll {
		return rbac.HasAllPermissions(permissionMask, permissions...), nil
	}
	return rbac.HasAnyPermission(permissionMask, permissions...), nil
}

// GetPermissionsFromContext returns the list of permission names from context.
func (s *CompanyService) GetPermissionsFromContext(ctx context.Context) ([]string, error) {
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return []string{}, nil
	}
	return rbac.GetPermissionsFromMask(permissionMask), nil
}

// CheckPermissionFromContext checks a single permission from context.
func (s *CompanyService) CheckPermissionFromContext(ctx context.Context, permissionName string) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("%w: session type not found", appErrors.ErrUnauthorized)
	}
	if sessionType == "admin" {
		return true, nil
	}
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return false, fmt.Errorf("%w: permission mask not found", appErrors.ErrPermissionDenied)
	}
	return rbac.HasPermission(permissionMask, permissionName), nil
}

// ---- Company creation ----

// CreateCompanyRequest defines the request for creating a new company.
type CreateCompanyRequest struct {
	CompanyName             string
	OwnerPhone              string
	OwnerUsername           string
	OwnerFullName           string
	OwnerPositionTitle      string
	SubscriptionTier        string
	MaxEmployees            int
	MaxDepartments          int
	DataRegion              string
	SubscriptionMonths      int
	SubscriptionDays        int
	Departments             []string
	FinancialYearStartMonth int
	WorkCenterCode          string
	WorkCenterName          string
	WorkCenterDesc          *string
	WorkCenterTZ            string
	WorkCenterActive        bool
	PositionWorkCenterCode  *string
}

// CreateCompany creates a new company with owner, departments, work center, and position.
func (s *CompanyService) CreateCompany(
	ctx context.Context,
	req *CreateCompanyRequest,
	createdBy uuid.UUID,
) (*models.Company, error) {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_company:%s:%s", req.CompanyName, req.OwnerPhone)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedCompany models.Company
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedCompany); err == nil {
		return &cachedCompany, nil
	}

	// Validation
	if req.MaxDepartments < 1 || req.MaxDepartments > 100 {
		return nil, fmt.Errorf("%w: max_departments must be between 1 and 100", appErrors.ErrInvalidInput)
	}
	if req.FinancialYearStartMonth < 1 || req.FinancialYearStartMonth > 12 {
		return nil, fmt.Errorf("%w: financial_year_start_month must be between 1 and 12", appErrors.ErrInvalidInput)
	}
	totalDepartments := len(req.Departments) + 1
	if totalDepartments > req.MaxDepartments {
		return nil, fmt.Errorf("%w: requested %d departments exceeds max_departments limit %d", appErrors.ErrInvalidInput, totalDepartments, req.MaxDepartments)
	}

	// Owner user
	var ownerUser *models.User
	existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			ownerUser, err = s.createOrFindUserForCompanyOwner(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to create owner user", appErrors.ErrInternal)
			}
		} else {
			return nil, fmt.Errorf("%w: failed to get user", appErrors.ErrInternal)
		}
	} else {
		ownerUser = existingUser
	}

	// Check existing company
	exists, err := s.companyRepo.CheckCompanyExists(ctx, req.CompanyName, ownerUser.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to validate company", appErrors.ErrInternal)
	}
	if exists {
		return nil, fmt.Errorf("%w: company with name '%s' already exists for this owner", appErrors.ErrDuplicate, req.CompanyName)
	}

	now := time.Now().UTC()
	subscriptionEnd := now.AddDate(0, req.SubscriptionMonths, req.SubscriptionDays)

	positionWorkCenter := req.PositionWorkCenterCode
	if positionWorkCenter == nil {
		positionWorkCenter = &req.WorkCenterCode
	}

	workCenter := &models.WorkCenter{
		WorkCenterCode: req.WorkCenterCode,
		CompanyID:      uuid.Nil, // Will be set after company creation
		Name:           req.WorkCenterName,
		Description:    req.WorkCenterDesc,
		Timezone:       req.WorkCenterTZ,
		IsActive:       req.WorkCenterActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	position := &models.Position{
		PositionID:         uuid.New(),
		CompanyID:          uuid.Nil,
		DepartmentID:       uuid.Nil,
		DepartmentName:     "Administration",
		Title:              req.OwnerPositionTitle,
		IsOpen:             false,
		IsSchedulable:      true,
		AttendanceRequired: true,
		OvertimeAllowed:    true,
		WorkCenterCode:     positionWorkCenter,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	company := &models.Company{
		CompanyID:               uuid.New(),
		CompanyName:             req.CompanyName,
		OwnerUserID:             ownerUser.UserID,
		SubscriptionTier:        req.SubscriptionTier,
		SubscriptionStatus:      models.SubscriptionStatusActive,
		MaxEmployees:            req.MaxEmployees,
		MaxDepartments:          req.MaxDepartments,
		DataRegion:              req.DataRegion,
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
		SubscriptionStartDate:   &now,
		SubscriptionEndDate:     &subscriptionEnd,
		FinancialYearStartMonth: req.FinancialYearStartMonth,
	}

	if err := s.companyRepo.CreateCompany(ctx, company, req.Departments, req.OwnerPositionTitle, position, workCenter); err != nil {
		return nil, fmt.Errorf("%w: failed to create company", appErrors.ErrInternal)
	}

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, company)

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "company", "create_company", "admin",
			&createdBy, "admin", &createdBy, nil, nil, map[string]interface{}{
				"company_id":        company.CompanyID.String(),
				"company_name":      req.CompanyName,
				"owner_user_id":     ownerUser.UserID.String(),
				"subscription_tier": req.SubscriptionTier,
				"max_departments":   req.MaxDepartments,
				"ip_address":        ip,
			})
	}

	return company, nil
}

// createOrFindUserForCompanyOwner creates a user for the owner, handling username conflicts.
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
		uniqueUsername := fmt.Sprintf("%s_%s", req.OwnerUsername, generateRandomString(6))
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
			return nil, fmt.Errorf("%w: failed to create user with unique username", appErrors.ErrInternal)
		}
		return user, nil
	}
	return nil, err
}

// ---- Company read methods ----

// GetCompany retrieves a company by ID.
func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return company, nil
}

// GetCompanyByID is an alias for GetCompany.
func (s *CompanyService) GetCompanyByID(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	return s.GetCompany(ctx, companyID)
}

// GetCompaniesByOwner returns companies owned by a user.
func (s *CompanyService) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	companies, err := s.companyRepo.GetCompaniesByOwner(ctx, ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return companies, nil
}

// UpdateCompany updates company details.
func (s *CompanyService) UpdateCompany(ctx context.Context, company *models.Company) error {
	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// UpdateCompanyStatus updates company active status.
func (s *CompanyService) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool, updatedBy uuid.UUID) error {
	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// UpdateSubscription updates subscription details.
func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
	if err := s.companyRepo.UpdateSubscription(ctx, companyID, tier, status, maxEmployees); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// ListCompanies lists companies with pagination.
func (s *CompanyService) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.ListCompanies(ctx, limit, offset)
}

// ListCompaniesByTier lists companies by subscription tier.
func (s *CompanyService) ListCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.GetCompaniesByTier(ctx, tier, limit, offset)
}

// GetCompaniesWithExpiringSubscription returns companies whose subscription ends within days.
func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
}

// DeactivateCompany deactivates a company.
func (s *CompanyService) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string, updatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is already inactive", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.DeactivateCompany(ctx, companyID, reason); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// ReactivateCompany reactivates a company.
func (s *CompanyService) ReactivateCompany(ctx context.Context, companyID uuid.UUID, reactivatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if company.IsActive {
		return fmt.Errorf("%w: company is already active", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// DeleteCompany deletes a company (must be inactive).
func (s *CompanyService) DeleteCompany(ctx context.Context, companyID uuid.UUID, deletedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if company.IsActive {
		return fmt.Errorf("%w: cannot delete active company; deactivate first", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.DeleteCompany(ctx, companyID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// ExtendSubscription extends company subscription.
func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, additionalMonths, additionalDays int, extendedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: cannot extend subscription for inactive company", appErrors.ErrInvalidState)
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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// ---- Employee management ----

// AddEmployeeRequest defines the request to add an employee.
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

// AddEmployee adds a new employee to a company.
func (s *CompanyService) AddEmployee(ctx context.Context, req *AddEmployeeRequest) error {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_employee:%s:%s", req.CompanyID.String(), req.PhoneNumber)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// Validate company
	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}

	// Check employee limit
	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("%w: failed to get active employee count", appErrors.ErrInternal)
	}
	if activeCount >= company.MaxEmployees {
		return fmt.Errorf("%w: max employee limit reached (%d/%d)", appErrors.ErrConflict, activeCount, company.MaxEmployees)
	}

	// Validate role
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("%w: role does not belong to company", appErrors.ErrInvalidInput)
	}
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
	}

	// Validate position if provided
	if req.PositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, *req.PositionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open", appErrors.ErrInvalidState)
		}
		// Check if position department matches role departments
		found := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to role", appErrors.ErrInvalidInput)
		}
	}

	// Validate reports_to
	if err := s.validateReportsTo(ctx, req.CompanyID, req.ReportsTo); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}

	// Get or create user
	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
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
				return fmt.Errorf("%w: failed to create user", appErrors.ErrInternal)
			}
		} else {
			return fmt.Errorf("%w: failed to get user", appErrors.ErrInternal)
		}
	}

	// Check existing active employee
	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
	if existingEmp != nil && existingEmp.IsActive {
		return fmt.Errorf("%w: user is already an active employee", appErrors.ErrDuplicate)
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
		PositionID: req.PositionID,
		HireDate:   time.Now().UTC(),
		IsActive:   true,
		ReportsTo:  reportsTo,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("%w: failed to add employee", appErrors.ErrInternal)
	}

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "add_employee", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(),
				"user_id":    user.UserID.String(),
				"role_id":    req.RoleID.String(),
				"ip_address": ip,
			})
	}

	return nil
}

// AddManagerRequest defines adding a manager.
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

// AddManager adds a manager (role level >= 500).
func (s *CompanyService) AddManager(ctx context.Context, req *AddManagerRequest) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_manager:%s:%s", req.CompanyID.String(), req.PhoneNumber)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}

	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.RoleLevel < 500 {
		return fmt.Errorf("%w: role level must be 500 or higher for managers", appErrors.ErrInvalidInput)
	}
	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
	}
	if err := s.validateReportsTo(ctx, req.CompanyID, req.ReportsTo); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}

	user, err := s.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
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
				return fmt.Errorf("%w: failed to create user", appErrors.ErrInternal)
			}
		} else {
			return fmt.Errorf("%w: failed to get user", appErrors.ErrInternal)
		}
	}

	existingEmp, _ := s.companyRepo.GetEmployee(ctx, req.CompanyID, user.UserID)
	if existingEmp != nil && existingEmp.IsActive {
		return fmt.Errorf("%w: user is already an active employee", appErrors.ErrDuplicate)
	}

	reportsTo := req.ReportsTo
	if reportsTo == nil {
		reportsTo = &company.OwnerUserID
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
		PositionID: req.PositionID,
		HireDate:   time.Now().UTC(),
		IsActive:   true,
		ReportsTo:  reportsTo,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := s.companyRepo.CreateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("%w: failed to add manager", appErrors.ErrInternal)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "add_manager", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(),
				"user_id":    user.UserID.String(),
				"role_id":    req.RoleID.String(),
				"ip_address": ip,
			})
	}

	return nil
}

// GetEmployee retrieves an employee by company and user.
func (s *CompanyService) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	emp, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return emp, nil
}

// ListEmployees lists employees of a company.
// ListEmployees returns a paginated list of employee summaries (minimal fields)
// and the total count of employees in the company.
// ListEmployees returns a paginated list of employee summaries (minimal fields)
// and the total count of employees in the company.
func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]models.EmployeeSummary, int, error) {
	return s.companyRepo.GetEmployeeSummariesByCompany(ctx, companyID, limit, offset)
}

// ListActiveEmployees lists active employees only.
func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}

// UpdateEmployeeRole updates employee's role.
func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_employee_role:%s:%s", companyID.String(), userID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	emp, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	newRole, err := s.companyRepo.GetRole(ctx, newRoleID)
	if err != nil {
		return fmt.Errorf("%w: new role not found", appErrors.ErrNotFound)
	}
	if newRole.CompanyID != companyID {
		return fmt.Errorf("%w: new role does not belong to company", appErrors.ErrInvalidInput)
	}
	// Validate reports_to if set
	if emp.ReportsTo != nil {
		if err := s.validateReportsTo(ctx, companyID, emp.ReportsTo); err != nil {
			// If invalid, set to nil
			emp.ReportsTo = nil
		}
	}
	emp.RoleID = newRoleID
	emp.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("%w: failed to update employee role", appErrors.ErrInternal)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_role", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"company_id":  companyID.String(),
				"user_id":     userID.String(),
				"new_role_id": newRoleID.String(),
				"ip_address":  ip,
			})
	}

	return nil
}

// RemoveEmployee deactivates an employee.
func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
	if userID == removedBy {
		return fmt.Errorf("%w: cannot remove yourself", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "remove_employee", "admin",
			&removedBy, "admin", &removedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(),
				"user_id":    userID.String(),
			})
	}
	return nil
}

// ReactivateEmployee reactivates an employee.
func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID, reactivatedBy uuid.UUID) error {
	if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "reactivate_employee", "admin",
			&reactivatedBy, "admin", &reactivatedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(),
				"user_id":    userID.String(),
			})
	}
	return nil
}

// GetEmployeeCount returns active employee count.
func (s *CompanyService) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetEmployeeCount(ctx, companyID)
}

// IsUserActiveEmployee checks if user is active employee.
func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
}

// GetEmployeesByUser returns all employee records for a user.
func (s *CompanyService) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetEmployeesByUser(ctx, userID)
}

// GetCompaniesByEmployeePhone returns active companies for an employee by phone.
func (s *CompanyService) GetCompaniesByEmployeePhone(ctx context.Context, employeePhone string) ([]*models.Company, error) {
	user, err := s.userService.GetUserByPhone(ctx, employeePhone)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get user", appErrors.ErrNotFound)
	}
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var companies []*models.Company
	seen := make(map[uuid.UUID]bool)
	for _, emp := range employees {
		if !emp.IsActive || seen[emp.CompanyID] {
			continue
		}
		company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
		if err != nil {
			continue
		}
		if company.IsActive {
			companies = append(companies, company)
			seen[emp.CompanyID] = true
		}
	}
	if len(companies) == 0 {
		return nil, fmt.Errorf("%w: no active companies found", appErrors.ErrNotFound)
	}
	return companies, nil
}

// UpdateEmployeePosition updates employee's position.
func (s *CompanyService) UpdateEmployeePosition(ctx context.Context, companyID, userID uuid.UUID, positionID *uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_employee_position:%s:%s", companyID.String(), userID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	if !employee.IsActive {
		return fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}
	if positionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, *positionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != companyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open", appErrors.ErrInvalidState)
		}
		roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
		if err != nil {
			return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
		}
		found := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to role", appErrors.ErrInvalidInput)
		}
	}
	if err := s.companyRepo.UpdateEmployeePosition(ctx, companyID, userID, positionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_position", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id":  companyID.String(),
				"user_id":     userID.String(),
				"position_id": positionID,
				"ip_address":  ip,
			})
	}
	return nil
}

// GetEmployeeWithPosition retrieves employee with position details.
// GetEmployeeWithPosition retrieves a company employee with enriched details:
// role, position, work center, department, username, and full name.
func (s *CompanyService) GetEmployeeWithPosition(ctx context.Context, companyID, userID uuid.UUID) (*models.EmployeeWithPositionDetails, error) {
	employee, err := s.companyRepo.GetEmployeeWithPosition(ctx, companyID, userID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) { // appErrors, not apperrors
			return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return employee, nil
}

// ---- Role management ----

// CreateRoleRequest defines role creation.
type CreateRoleRequest struct {
	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
	RoleName      string      `json:"role_name" validate:"required"`
	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
	Description   string      `json:"description"`
	DepartmentIDs []uuid.UUID `json:"department_ids"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
	CreatedBy     uuid.UUID   `json:"created_by" validate:"required"`
}

// CreateRole creates a new role with departments and permissions.
func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_role:%s:%s", req.CompanyID.String(), req.RoleName)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedRole models.Role
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedRole); err == nil {
		return &cachedRole, nil
	}

	// Validate departments
	for _, deptID := range req.DepartmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
		if err != nil {
			return nil, fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptID)
		}
		if dept.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: department %s does not belong to company", appErrors.ErrInvalidInput, deptID)
		}
	}

	// Validate permissions
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
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
			return nil, fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, permID)
		}
		if !departmentModules[perm.Module] {
			return nil, fmt.Errorf("%w: permission '%s' module '%s' not compatible with departments", appErrors.ErrInvalidInput, perm.PermissionName, perm.Module)
		}
	}

	// Check duplicate role name
	existingRoles, _, err := s.companyRepo.GetRolesByCompany(ctx, req.CompanyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check existing roles", appErrors.ErrInternal)
	}
	for _, role := range existingRoles {
		if strings.EqualFold(role.RoleName, req.RoleName) {
			return nil, fmt.Errorf("%w: role with name '%s' already exists", appErrors.ErrDuplicate, req.RoleName)
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
		return nil, fmt.Errorf("%w: failed to create role", appErrors.ErrInternal)
	}
	if len(req.PermissionIDs) > 0 {
		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy); err != nil {
			// non-critical
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, role)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "create_role", "admin",
			&req.CreatedBy, "admin", &req.CreatedBy, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(),
				"role_id":    role.RoleID.String(),
				"role_name":  req.RoleName,
				"role_level": req.RoleLevel,
				"ip_address": ip,
			})
	}

	return role, nil
}

// CreateRoleAdmin is an admin version of CreateRole.
func (s *CompanyService) CreateRoleAdmin(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	return s.CreateRole(ctx, req)
}

// GetRole retrieves a role by ID.
func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return role, nil
}

// GetRolesByCompany lists roles.
func (s *CompanyService) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
	return s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
}

// ListRoles lists roles with optional permission inclusion.
func (s *CompanyService) ListRoles(ctx context.Context, companyID uuid.UUID, limit, offset int, includePermissions bool) ([]*models.Role, int, error) {
	roles, total, err := s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if includePermissions {
		for _, role := range roles {
			perms, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
			if err == nil {
				_ = perms
			}
		}
	}
	return roles, total, nil
}

// DeleteRole deletes a custom role.
func (s *CompanyService) DeleteRole(ctx context.Context, roleID uuid.UUID, deletedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.IsSystemRole {
		return fmt.Errorf("%w: cannot delete system roles", appErrors.ErrSystemRole)
	}
	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, roleID, 1, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to check assignments", appErrors.ErrInternal)
	}
	if len(employees) > 0 {
		return fmt.Errorf("%w: role is in use and cannot be deleted", appErrors.ErrRoleInUse)
	}
	if err := s.companyRepo.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "delete_role", "admin",
			&deletedBy, "admin", &deletedBy, nil, nil, map[string]interface{}{
				"role_id":   roleID.String(),
				"role_name": role.RoleName,
			})
	}
	return nil
}

// UpdateRoleRequest defines role update.
type UpdateRoleRequest struct {
	CompanyID          uuid.UUID
	RoleID             uuid.UUID
	RoleName           string
	Description        string
	AddDepartments     []string
	RemoveDepartments  []string
	AddPermissions     []string
	RemovePermissions  []string
	ReplacePermissions []string
	UpdatedBy          uuid.UUID
}

// UpdateRole updates a role's name, description, departments, and permissions.
func (s *CompanyService) UpdateRole(ctx context.Context, req UpdateRoleRequest) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_role:%s", req.RoleID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.IsSystemRole {
		return fmt.Errorf("%w: cannot update system roles", appErrors.ErrSystemRole)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("%w: role does not belong to specified company", appErrors.ErrInvalidInput)
	}

	role.RoleName = req.RoleName
	role.Description = req.Description
	role.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateRole(ctx, role); err != nil {
		return fmt.Errorf("%w: failed to update role", appErrors.ErrInternal)
	}

	// Update departments
	if len(req.AddDepartments) > 0 || len(req.RemoveDepartments) > 0 {
		if err := s.updateRoleDepartments(ctx, req, role); err != nil {
			return err
		}
	}

	// Update permissions
	if len(req.ReplacePermissions) > 0 {
		if err := s.replaceRolePermissions(ctx, req, role); err != nil {
			return err
		}
	} else {
		if err := s.updateRolePermissions(ctx, req, role); err != nil {
			return err
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "update_role", "admin",
			&req.UpdatedBy, "admin", &req.UpdatedBy, nil, nil, map[string]interface{}{
				"role_id":    req.RoleID.String(),
				"role_name":  req.RoleName,
				"ip_address": ip,
			})
	}

	return nil
}

// Helper functions for UpdateRole
func (s *CompanyService) updateRoleDepartments(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get current departments", appErrors.ErrInternal)
	}
	currentDeptMap := make(map[string]uuid.UUID)
	for _, dept := range currentDepts {
		currentDeptMap[dept.DepartmentName] = dept.DepartmentID
	}
	for _, deptName := range req.AddDepartments {
		if _, exists := currentDeptMap[deptName]; exists {
			continue
		}
		dept, err := s.companyRepo.GetDepartmentByName(ctx, role.CompanyID, deptName)
		if err != nil {
			return fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptName)
		}
		if err := s.validatePermissionDepartmentCompatibilityForUpdate(ctx, []uuid.UUID{dept.DepartmentID}, req); err != nil {
			return err
		}
		if err := s.companyRepo.CreateRoleDepartment(ctx, role.RoleID, dept.DepartmentID); err != nil {
			return fmt.Errorf("%w: failed to add department", appErrors.ErrInternal)
		}
	}
	for _, deptName := range req.RemoveDepartments {
		deptID, exists := currentDeptMap[deptName]
		if !exists {
			continue
		}
		if err := s.companyRepo.RemoveRoleDepartment(ctx, role.RoleID, deptID); err != nil {
			return fmt.Errorf("%w: failed to remove department", appErrors.ErrInternal)
		}
	}
	return nil
}

func (s *CompanyService) replaceRolePermissions(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, perm := range allPerms {
		permMap[perm.PermissionName] = perm.PermissionID
	}
	var permIDs []uuid.UUID
	for _, name := range req.ReplacePermissions {
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		permIDs = append(permIDs, id)
	}
	// Validate compatibility with current departments
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var deptIDs []uuid.UUID
	for _, dept := range currentDepts {
		deptIDs = append(deptIDs, dept.DepartmentID)
	}
	if len(deptIDs) > 0 && len(permIDs) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, deptIDs, permIDs)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	if err := s.companyRepo.ReplaceRolePermissions(ctx, role.RoleID, permIDs, req.UpdatedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) updateRolePermissions(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	currentPerms, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	currentMap := make(map[string]bool)
	for _, p := range currentPerms {
		currentMap[p.PermissionName] = true
	}
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, p := range allPerms {
		permMap[p.PermissionName] = p.PermissionID
	}
	var toAdd []uuid.UUID
	for _, name := range req.AddPermissions {
		if currentMap[name] {
			continue
		}
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		toAdd = append(toAdd, id)
	}
	var toRemove []uuid.UUID
	for _, name := range req.RemovePermissions {
		if !currentMap[name] {
			continue
		}
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		toRemove = append(toRemove, id)
	}
	// Validate compatibility
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var deptIDs []uuid.UUID
	for _, dept := range currentDepts {
		deptIDs = append(deptIDs, dept.DepartmentID)
	}
	if len(deptIDs) > 0 && len(toAdd) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, deptIDs, toAdd)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	if len(toAdd) > 0 {
		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, toAdd, req.UpdatedBy); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	if len(toRemove) > 0 {
		if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, role.RoleID, toRemove); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	return nil
}

// ---- Role-Department mapping ----

// MapRoleToDepartmentRequest defines mapping.
type MapRoleToDepartmentRequest struct {
	RoleID       uuid.UUID `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	MappedBy     uuid.UUID `json:"mapped_by" validate:"required"`
}

// MapRoleToDepartment maps a role to a department.
func (s *CompanyService) MapRoleToDepartment(ctx context.Context, req *MapRoleToDepartmentRequest) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("map_role_dept:%s:%s", req.RoleID.String(), req.DepartmentID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if role.CompanyID != department.CompanyID {
		return fmt.Errorf("%w: role and department must belong to same company", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.CreateRoleDepartment(ctx, req.RoleID, req.DepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "map_role_department", "admin",
			&req.MappedBy, "admin", &req.MappedBy, nil, nil, map[string]interface{}{
				"role_id":       req.RoleID.String(),
				"department_id": req.DepartmentID.String(),
				"ip_address":    ip,
			})
	}
	return nil
}

// RemoveRoleFromDepartment removes a role from a department.
func (s *CompanyService) RemoveRoleFromDepartment(ctx context.Context, roleID, departmentID, removedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RemoveRoleDepartment(ctx, roleID, departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "unmap_role_department", "admin",
			&removedBy, "admin", &removedBy, nil, nil, map[string]interface{}{
				"role_id":       roleID.String(),
				"department_id": departmentID.String(),
			})
	}
	return nil
}

// GetRoleDepartments returns departments for a role.
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

// ---- Permission management ----

// GrantRolePermission grants a permission to a role.
func (s *CompanyService) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	// Check if user has the permission to grant (optional)
	if err := s.companyRepo.GrantRolePermission(ctx, roleID, permissionID, grantedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "grant", "admin",
			&grantedBy, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"role_id":       roleID.String(),
				"permission_id": permissionID.String(),
			})
	}
	return nil
}

// GrantRolePermissionAdmin is admin version.
func (s *CompanyService) GrantRolePermissionAdmin(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	return s.GrantRolePermission(ctx, roleID, permissionID, grantedBy)
}

// RevokeRolePermission revokes a permission from a role.
func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID, revokedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RevokeRolePermission(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "revoke", "admin",
			&revokedBy, "admin", &revokedBy, nil, nil, map[string]interface{}{
				"role_id":       roleID.String(),
				"permission_id": permissionID.String(),
			})
	}
	return nil
}

// RevokeRolePermissionAdmin is admin version.
func (s *CompanyService) RevokeRolePermissionAdmin(ctx context.Context, roleID, permissionID, revokedBy uuid.UUID) error {
	return s.RevokeRolePermission(ctx, roleID, permissionID, revokedBy)
}

// GrantRolePermissions grants multiple permissions.
type GrantRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
}

// GrantRolePermissions grants multiple permissions.
func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
	if _, err := s.companyRepo.GetRole(ctx, req.RoleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("%w: user ID not found", appErrors.ErrUnauthorized)
	}
	grantedBy, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user ID", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, req.PermissionIDs, grantedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "grant_multiple", "admin",
			&grantedBy, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"role_id":          req.RoleID.String(),
				"permission_count": len(req.PermissionIDs),
			})
	}
	return nil
}

// RevokeRolePermissions revokes multiple permissions.
func (s *CompanyService) RevokeRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetRolePermissions returns permissions for a role.
func (s *CompanyService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	return s.companyRepo.GetRolePermissions(ctx, roleID)
}

// GetPermissionByName returns a permission by name.
func (s *CompanyService) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	perm, err := s.companyRepo.GetPermissionByName(ctx, name)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: permission not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return perm, nil
}

// GetPermissionsByModule returns permissions for a module.
func (s *CompanyService) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

// GetAllPermissions returns all permissions with filters.
func (s *CompanyService) GetAllPermissions(ctx context.Context, module, category, tier string) ([]*models.Permission, error) {
	all, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var filtered []*models.Permission
	for _, p := range all {
		if module != "" && p.Module != module {
			continue
		}
		if category != "" && p.Category != category {
			continue
		}
		if tier != "" && p.RequiresTier != tier {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, nil
}

// CreatePermission creates a new permission.
func (s *CompanyService) CreatePermission(ctx context.Context, permissionName, description, category, module, requiresTier string) (*models.Permission, error) {
	perm := &models.Permission{
		PermissionID:   uuid.New(),
		PermissionName: permissionName,
		Description:    description,
		Category:       category,
		Module:         module,
		RequiresTier:   requiresTier,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.companyRepo.CreatePermission(ctx, perm); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return perm, nil
}

// GetUserPermissions returns permissions for a user across companies.
func (s *CompanyService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[uuid.UUID]*models.Permission)
	for _, emp := range employees {
		if emp.IsActive {
			perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
			if err == nil {
				for _, p := range perms {
					permMap[p.PermissionID] = p
				}
			}
		}
	}
	result := make([]*models.Permission, 0, len(permMap))
	for _, p := range permMap {
		result = append(result, p)
	}
	return result, nil
}

// GetUserPermissionBitmask returns permission bitmask for a user in a company.
func (s *CompanyService) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
}

// GetRolePermissionBitmask returns permission bitmask for a role.
func (s *CompanyService) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetRolePermissionBitmask(ctx, roleID)
}

// GetPermissionsWithBitIndex returns permissions with bit index.
func (s *CompanyService) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
	return s.companyRepo.GetPermissionsWithBitIndex(ctx)
}

// ---- Department management ----

// CreateDepartmentRequest defines department creation.
type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
}

// CreateDepartment creates a new department.
func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_dept:%s:%s", req.CompanyID.String(), req.DepartmentName)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedDept models.Department
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedDept); err == nil {
		return &cachedDept, nil
	}

	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return nil, fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}
	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, req.SystemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: system department not found", appErrors.ErrNotFound)
	}
	// Check duplicate name
	existing, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, req.CompanyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check existing", appErrors.ErrInternal)
	}
	for _, d := range existing {
		if strings.EqualFold(d.DepartmentName, req.DepartmentName) {
			return nil, fmt.Errorf("%w: department name already exists", appErrors.ErrDuplicate)
		}
		if d.SystemDepartmentID != nil && *d.SystemDepartmentID == req.SystemDepartmentID {
			return nil, fmt.Errorf("%w: system department already assigned", appErrors.ErrDuplicate)
		}
	}
	if req.ParentDepartmentID != nil {
		parent, err := s.companyRepo.GetDepartment(ctx, *req.ParentDepartmentID)
		if err != nil {
			return nil, fmt.Errorf("%w: parent department not found", appErrors.ErrNotFound)
		}
		if parent.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: parent department does not belong to company", appErrors.ErrInvalidInput)
		}
	}

	dept := &models.Department{
		DepartmentID:       uuid.New(),
		CompanyID:          req.CompanyID,
		DepartmentName:     req.DepartmentName,
		SystemDepartmentID: &req.SystemDepartmentID,
		ParentDepartmentID: req.ParentDepartmentID,
		IsActive:           true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if err := s.companyRepo.CreateDepartment(ctx, dept); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Auto-assign to owner role
	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, req.CompanyID, 1000)
	if err == nil && ownerRole != nil {
		_ = s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, dept.DepartmentID)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, dept)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "create", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id":        req.CompanyID.String(),
				"department_id":     dept.DepartmentID.String(),
				"department_name":   req.DepartmentName,
				"system_department": systemDept.Name,
				"ip_address":        ip,
			})
	}
	return dept, nil
}

// GetDepartment retrieves a department by ID.
func (s *CompanyService) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
	dept, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return dept, nil
}

// ListDepartments lists departments with pagination.
func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit, offset int, includeEmployees bool) ([]*models.Department, int, error) {
	depts, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return depts, total, nil
}

// GetDepartmentsByCompany lists departments.
func (s *CompanyService) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
	return s.companyRepo.GetDepartmentsByCompany(ctx, companyID, limit, offset)
}

// UpdateDepartment updates department name.
func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, updatedBy uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	dept.DepartmentName = name
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "update", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
				"new_name":      name,
			})
	}
	return nil
}

// RenameDepartment is an alias.
func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string) error {
	return s.UpdateDepartment(ctx, departmentID, newName, uuid.Nil)
}

// DeactivateDepartment deactivates a department.
func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if !dept.IsActive {
		return fmt.Errorf("%w: department already deactivated", appErrors.ErrInvalidState)
	}
	// Check if any employees in roles that belong to this department
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, dept.CompanyID, 1000, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to get roles", appErrors.ErrInternal)
	}
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, rd := range roleDepts {
			if rd.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("%w: department has active employees", appErrors.ErrConflict)
				}
				break
			}
		}
	}
	dept.IsActive = false
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "deactivate", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
			})
	}
	return nil
}

// ActivateDepartment activates a department.
func (s *CompanyService) ActivateDepartment(ctx context.Context, companyID uuid.UUID, departmentID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if dept.IsActive {
		return fmt.Errorf("%w: department already active", appErrors.ErrInvalidState)
	}
	dept.IsActive = true
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// DeleteDepartment deletes a department (must be inactive and no employees).
func (s *CompanyService) DeleteDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	// Check employees
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, dept.CompanyID, 1000, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to get roles", appErrors.ErrInternal)
	}
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, rd := range roleDepts {
			if rd.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("%w: department has employees", appErrors.ErrConflict)
				}
				break
			}
		}
	}
	// Remove role-department mappings
	if err := s.companyRepo.RemoveAllRoleDepartments(ctx, departmentID); err != nil {
		// non-critical
	}
	if err := s.companyRepo.DeleteDepartment(ctx, departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "delete", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"department_id":   departmentID.String(),
				"department_name": dept.DepartmentName,
			})
	}
	return nil
}

// SoftDeleteDepartment soft-deletes a department.
func (s *CompanyService) SoftDeleteDepartment(ctx context.Context, companyID uuid.UUID, departmentID uuid.UUID) error {
	return s.companyRepo.SoftDeleteDepartment(ctx, companyID, departmentID)
}

// GetDepartmentHierarchy returns hierarchy.
func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentHierarchy(ctx, companyID)
}

// UpdateDepartmentParent updates parent.
type UpdateDepartmentParentRequest struct {
	DepartmentID       uuid.UUID  `json:"department_id" validate:"required"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id"`
}

// UpdateDepartmentParent updates the parent of a department.
func (s *CompanyService) UpdateDepartmentParent(ctx context.Context, req *UpdateDepartmentParentRequest, updatedBy uuid.UUID) error {
	_, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.UpdateDepartmentParent(ctx, req.DepartmentID, req.ParentDepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetDepartmentChildren returns children.
func (s *CompanyService) GetDepartmentChildren(ctx context.Context, departmentID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentChildren(ctx, departmentID)
}

// GetDepartmentTree returns tree.
func (s *CompanyService) GetDepartmentTree(ctx context.Context, departmentID uuid.UUID) ([]*models.DepartmentTree, error) {
	return s.companyRepo.GetDepartmentTree(ctx, departmentID)
}

// GetDepartmentParents returns parents.
func (s *CompanyService) GetDepartmentParents(ctx context.Context, departmentID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentParents(ctx, departmentID)
}

// MoveDepartmentWithEmployees moves a department.
func (s *CompanyService) MoveDepartmentWithEmployees(ctx context.Context, departmentID uuid.UUID, newParentDepartmentID *uuid.UUID, movedBy uuid.UUID) error {
	if err := s.companyRepo.MoveDepartmentWithEmployees(ctx, departmentID, newParentDepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetRootDepartments returns root departments.
func (s *CompanyService) GetRootDepartments(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRootDepartments(ctx, companyID)
}

// ValidateDepartmentHierarchy validates hierarchy.
func (s *CompanyService) ValidateDepartmentHierarchy(ctx context.Context, departmentID uuid.UUID, newParentDepartmentID *uuid.UUID) (bool, error) {
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
	return parent.CompanyID == current.CompanyID, nil
}

// GetActiveDepartmentCount returns count.
func (s *CompanyService) GetActiveDepartmentCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetActiveDepartmentCount(ctx, companyID)
}

// GetCompanyDepartmentInfo returns info.
func (s *CompanyService) GetCompanyDepartmentInfo(ctx context.Context, companyID uuid.UUID) (*postgres.CompanyDepartmentInfo, error) {
	return s.companyRepo.GetCompanyDepartmentInfo(ctx, companyID)
}

// CheckDepartmentLimit checks limit.
func (s *CompanyService) CheckDepartmentLimit(ctx context.Context, companyID uuid.UUID) error {
	return s.companyRepo.CheckDepartmentLimit(ctx, companyID)
}

// GetDeactivatedDepartments retrieves all deactivated departments for a company.
func (s *CompanyService) GetDeactivatedDepartments(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDeactivatedDepartments(ctx, companyID)
}

// UpdateMaxDepartments updates max departments.
func (s *CompanyService) UpdateMaxDepartments(ctx context.Context, companyID uuid.UUID, newMaxDepartments int) error {
	if newMaxDepartments < 1 || newMaxDepartments > 100 {
		return fmt.Errorf("%w: max_departments must be between 1 and 100", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.UpdateMaxDepartments(ctx, companyID, newMaxDepartments); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// CreateSubDepartment creates a sub-department.
func (s *CompanyService) CreateSubDepartment(ctx context.Context, companyID uuid.UUID, parentDepartmentID uuid.UUID, departmentName string) (*models.Department, error) {
	parent, err := s.companyRepo.GetDepartmentByID(ctx, parentDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: parent not found", appErrors.ErrNotFound)
	}
	if parent.CompanyID != companyID {
		return nil, fmt.Errorf("%w: parent does not belong to company", appErrors.ErrInvalidInput)
	}
	if parent.SystemDepartmentID == nil {
		return nil, fmt.Errorf("%w: parent missing system mapping", appErrors.ErrInvalidState)
	}
	return s.companyRepo.CreateSubDepartment(ctx, companyID, parentDepartmentID, departmentName, *parent.SystemDepartmentID)
}

// AdminAddDepartment is admin version.
func (s *CompanyService) AdminAddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
	return s.CreateDepartment(ctx, &CreateDepartmentRequest{
		CompanyID:          companyID,
		DepartmentName:     departmentName,
		SystemDepartmentID: systemDepartmentID,
	})
}

// ---- System departments ----

// GetSystemDepartments returns all system departments.
func (s *CompanyService) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartments(ctx)
}

// GetSystemDepartmentByModule returns system department by module.
func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartmentByModule(ctx, module)
}

// ---- Positions ----

// CreatePositionRequest defines position creation.
type CreatePositionRequest struct {
	CompanyID          uuid.UUID `json:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id"`
	Title              string    `json:"title"`
	IsOpen             *bool     `json:"is_open"`
	IsSchedulable      *bool     `json:"is_schedulable"`
	AttendanceRequired *bool     `json:"attendance_required"`
	OvertimeAllowed    *bool     `json:"overtime_allowed"`
	WorkCenterCode     *string   `json:"work_center_code"`
}

// CreatePosition creates a position.
func (s *CompanyService) CreatePosition(ctx context.Context, req *CreatePositionRequest, createdBy uuid.UUID) (*models.Position, error) {
	if req.IsOpen == nil || req.IsSchedulable == nil || req.AttendanceRequired == nil || req.OvertimeAllowed == nil {
		return nil, fmt.Errorf("%w: boolean defaults not initialized", appErrors.ErrInvalidInput)
	}
	department, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if department.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("%w: department does not belong to company", appErrors.ErrInvalidInput)
	}
	// Validate work center if provided
	if req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		exists, err := s.companyRepo.WorkCenterExists(ctx, req.CompanyID, *req.WorkCenterCode)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to validate work center", appErrors.ErrInternal)
		}
		if !exists {
			return nil, fmt.Errorf("%w: work center does not exist", appErrors.ErrNotFound)
		}
	}
	exists, err := s.companyRepo.PositionExists(ctx, req.CompanyID, req.DepartmentID, req.Title)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check uniqueness", appErrors.ErrInternal)
	}
	if exists {
		return nil, fmt.Errorf("%w: position with this title already exists", appErrors.ErrDuplicate)
	}
	now := time.Now().UTC()
	position := &models.Position{
		PositionID:         uuid.New(),
		CompanyID:          req.CompanyID,
		DepartmentID:       req.DepartmentID,
		Title:              req.Title,
		IsOpen:             *req.IsOpen,
		IsSchedulable:      *req.IsSchedulable,
		AttendanceRequired: *req.AttendanceRequired,
		OvertimeAllowed:    *req.OvertimeAllowed,
		WorkCenterCode:     req.WorkCenterCode,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.companyRepo.CreatePosition(ctx, position); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "create", "admin",
			&createdBy, "admin", &createdBy, nil, nil, map[string]interface{}{
				"company_id":    req.CompanyID.String(),
				"department_id": req.DepartmentID.String(),
				"position_id":   position.PositionID.String(),
				"title":         req.Title,
			})
	}
	return position, nil
}

// UpdatePositionRequest defines position update.
type UpdatePositionRequest struct {
	PositionID         uuid.UUID `json:"position_id" validate:"required"`
	Title              string    `json:"title" validate:"required,min=1,max=255"`
	DepartmentID       uuid.UUID `json:"department_id" validate:"required"`
	IsOpen             bool      `json:"is_open"`
	IsSchedulable      *bool     `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool     `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool     `json:"overtime_allowed,omitempty"`
	WorkCenterCode     *string   `json:"work_center_code,omitempty" validate:"omitempty,max=100"`
}

// UpdatePosition updates a position.
func (s *CompanyService) UpdatePosition(ctx context.Context, req *UpdatePositionRequest, updatedBy uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_position:%s", req.PositionID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	existing, err := s.companyRepo.GetPosition(ctx, req.PositionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}
	if req.DepartmentID != existing.DepartmentID {
		newDept, err := s.companyRepo.GetDepartment(ctx, req.DepartmentID)
		if err != nil {
			return fmt.Errorf("%w: new department not found", appErrors.ErrNotFound)
		}
		if newDept.CompanyID != existing.CompanyID {
			return fmt.Errorf("%w: new department does not belong to same company", appErrors.ErrInvalidInput)
		}
	}
	if req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		exists, err := s.companyRepo.WorkCenterExists(ctx, existing.CompanyID, *req.WorkCenterCode)
		if err != nil {
			return fmt.Errorf("%w: failed to validate work center", appErrors.ErrInternal)
		}
		if !exists {
			return fmt.Errorf("%w: work center does not exist", appErrors.ErrNotFound)
		}
		existing.WorkCenterCode = req.WorkCenterCode
	}
	existing.Title = req.Title
	existing.DepartmentID = req.DepartmentID
	existing.IsOpen = req.IsOpen
	if req.IsSchedulable != nil {
		existing.IsSchedulable = *req.IsSchedulable
	}
	if req.AttendanceRequired != nil {
		existing.AttendanceRequired = *req.AttendanceRequired
	}
	if req.OvertimeAllowed != nil {
		existing.OvertimeAllowed = *req.OvertimeAllowed
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdatePosition(ctx, existing); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "update", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"position_id": req.PositionID.String(),
				"title":       req.Title,
				"ip_address":  ip,
			})
	}
	return nil
}

// UpdatePositionStatus updates open status.
func (s *CompanyService) UpdatePositionStatus(ctx context.Context, positionID uuid.UUID, isOpen bool, updatedBy uuid.UUID) error {
	pos, err := s.companyRepo.GetPosition(ctx, positionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}
	pos.IsOpen = isOpen
	pos.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdatePosition(ctx, pos); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetPosition retrieves a position.
func (s *CompanyService) GetPosition(ctx context.Context, positionID uuid.UUID) (*models.Position, error) {
	pos, err := s.companyRepo.GetPosition(ctx, positionID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return pos, nil
}

// ListPositions lists positions.
func (s *CompanyService) ListPositions(ctx context.Context, companyID uuid.UUID, departmentID *uuid.UUID, onlyOpen bool, limit, offset int) ([]*models.Position, int, error) {
	var positions []*models.Position
	var total int
	var err error
	if departmentID != nil {
		positions, total, err = s.companyRepo.GetPositionsByDepartment(ctx, *departmentID, limit, offset, onlyOpen)
	} else {
		positions, total, err = s.companyRepo.GetPositionsByCompany(ctx, companyID, limit, offset, onlyOpen)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return positions, total, nil
}

// DeletePosition deletes a position.
func (s *CompanyService) DeletePosition(ctx context.Context, positionID, deletedBy uuid.UUID) error {
	pos, err := s.companyRepo.GetPosition(ctx, positionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}
	// Check if any employee assigned
	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, pos.CompanyID, 1, 0)
	if err == nil {
		for _, emp := range employees {
			if emp.PositionID != nil && *emp.PositionID == positionID {
				return fmt.Errorf("%w: position has employees assigned", appErrors.ErrConflict)
			}
		}
	}
	if err := s.companyRepo.DeletePosition(ctx, positionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "delete", "admin",
			&deletedBy, "admin", &deletedBy, nil, nil, map[string]interface{}{
				"position_id": positionID.String(),
				"title":       pos.Title,
			})
	}
	return nil
}

// GetOpenPositions returns open positions.
func (s *CompanyService) GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error) {
	return s.companyRepo.GetOpenPositions(ctx, companyID, isOpen, limit, offset)
}

// GetPositionsByDepartment returns positions by department.
func (s *CompanyService) GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error) {
	onlyOpen := false
	if isOpen != nil {
		onlyOpen = *isOpen
	}
	return s.companyRepo.GetPositionsByDepartment(ctx, departmentID, limit, offset, onlyOpen)
}

// ---- Permission checks ----

// PermissionCheckRequest defines permission check.
type PermissionCheckRequest struct {
	CompanyID      uuid.UUID `json:"company_id" validate:"required"`
	UserID         uuid.UUID `json:"user_id" validate:"required"`
	PermissionName string    `json:"permission_name" validate:"required"`
	Module         string    `json:"module,omitempty"`
}

// PermissionCheckResult contains result.
type PermissionCheckResult struct {
	HasPermission bool              `json:"has_permission"`
	IsOwner       bool              `json:"is_owner"`
	Checks        map[string]bool   `json:"checks"`
	Details       *PermissionDetail `json:"details,omitempty"`
	Message       string            `json:"message,omitempty"`
}

// PermissionDetail provides details.
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

// CheckPermission checks if a user has a permission in a company.
func (s *CompanyService) CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResult, error) {
	result := &PermissionCheckResult{
		HasPermission: false,
		Checks:        make(map[string]bool),
	}
	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if company.OwnerUserID == req.UserID {
		result.HasPermission = true
		result.IsOwner = true
		result.Checks["is_owner"] = true
		result.Checks["has_employee_record"] = true
		result.Checks["role_has_permission"] = true
		result.Checks["role_belongs_to_department"] = true
		result.Checks["module_access"] = true
		return result, nil
	}
	employee, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, req.UserID)
	if err != nil {
		result.Checks["has_employee_record"] = false
		result.Message = "User is not an active employee"
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
		return nil, fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		result.Checks["has_department"] = false
		result.Message = "Role has no department"
		return result, nil
	}
	result.Checks["has_department"] = true

	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrInternal)
	}
	permission, err := s.companyRepo.GetPermissionByName(ctx, req.PermissionName)
	if err != nil {
		result.Checks["role_has_permission"] = false
		result.Message = "Permission not found"
		return result, nil
	}
	hasPerm, err := s.companyRepo.CheckRolePermission(ctx, employee.RoleID, permission.PermissionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check permission", appErrors.ErrInternal)
	}
	result.Checks["role_has_permission"] = hasPerm
	if !hasPerm {
		result.Message = "Role does not have permission"
		return result, nil
	}
	// Module match
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
		result.Message = fmt.Sprintf("Permission module '%s' not in department modules", permission.Module)
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
	return result, nil
}

// CheckUserPermission is a simpler version.
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

// BulkPermissionCheck checks multiple permissions.
func (s *CompanyService) BulkPermissionCheck(ctx context.Context, companyID, userID uuid.UUID, permissionNames []string) (map[string]bool, error) {
	results := make(map[string]bool)
	for _, name := range permissionNames {
		has, err := s.CheckUserPermission(ctx, companyID, userID, name)
		if err != nil {
			results[name] = false
			continue
		}
		results[name] = has
	}
	return results, nil
}

// ---- Company context ----

// CompanyContext holds context data for a user in a company.
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

// GetCompanyContext returns context for a user's first active company.
func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*CompanyContext, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if len(employees) == 0 {
		return nil, fmt.Errorf("%w: user is not an employee", appErrors.ErrNotFound)
	}
	emp := employees[0]
	if !emp.IsActive {
		return nil, fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}
	company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	role, err := s.companyRepo.GetRole(ctx, emp.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
	if err != nil {
		roleDepts = []*models.Department{}
	}
	var deptID, deptName, sysModule string
	if len(roleDepts) > 0 {
		dept := roleDepts[0]
		deptID = dept.DepartmentID.String()
		deptName = dept.DepartmentName
		if dept.SystemDepartmentID != nil {
			sys, _ := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
			if sys != nil {
				sysModule = sys.ModuleCode
			}
		}
	}
	perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
	if err != nil {
		perms = []*models.Permission{}
	}
	permStrs := make([]string, len(perms))
	for i, p := range perms {
		permStrs[i] = p.PermissionName
	}
	return &CompanyContext{
		CompanyID:        company.CompanyID.String(),
		EmployeeID:       emp.EmployeeID,
		RoleID:           emp.RoleID.String(),
		RoleLevel:        role.RoleLevel,
		RoleName:         role.RoleName,
		DepartmentID:     deptID,
		DepartmentName:   deptName,
		SystemModule:     sysModule,
		Permissions:      permStrs,
		SubscriptionTier: company.SubscriptionTier,
		IsOwner:          company.OwnerUserID == userID,
		IsManager:        role.RoleLevel <= 200,
	}, nil
}

// GetCompanyContextForCompany returns context for a specific company.
func (s *CompanyService) GetCompanyContextForCompany(ctx context.Context, userID, companyID uuid.UUID) (*CompanyContext, error) {
	employee, err := s.companyRepo.GetEmployee(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	if !employee.IsActive {
		return nil, fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if company.SubscriptionEndDate != nil && company.SubscriptionEndDate.Before(time.Now()) {
		return nil, fmt.Errorf("%w: subscription expired", appErrors.ErrInvalidState)
	}
	if !company.IsActive {
		return nil, fmt.Errorf("%w: company not active", appErrors.ErrInvalidState)
	}
	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		roleDepts = []*models.Department{}
	}
	var deptID, deptName, sysModule string
	if len(roleDepts) > 0 {
		dept := roleDepts[0]
		deptID = dept.DepartmentID.String()
		deptName = dept.DepartmentName
		if dept.SystemDepartmentID != nil {
			sys, _ := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
			if sys != nil {
				sysModule = sys.ModuleCode
			}
		}
	}
	perms, err := s.companyRepo.GetUserPermissions(ctx, companyID, userID)
	if err != nil {
		perms = []*models.Permission{}
	}
	permStrs := make([]string, len(perms))
	for i, p := range perms {
		permStrs[i] = p.PermissionName
	}
	return &CompanyContext{
		CompanyID:        company.CompanyID.String(),
		EmployeeID:       employee.EmployeeID,
		RoleID:           employee.RoleID.String(),
		RoleLevel:        role.RoleLevel,
		RoleName:         role.RoleName,
		DepartmentID:     deptID,
		DepartmentName:   deptName,
		SystemModule:     sysModule,
		Permissions:      permStrs,
		SubscriptionTier: company.SubscriptionTier,
		IsOwner:          company.OwnerUserID == userID,
		IsManager:        role.RoleLevel <= 200,
	}, nil
}

// ---- Authorization ----

// AuthorizeUserLogin checks if a user is active in any company.
func (s *CompanyService) AuthorizeUserLogin(ctx context.Context, phoneNumber string) (*models.User, error) {
	user, err := s.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		return nil, fmt.Errorf("%w: user not found", appErrors.ErrNotFound)
	}
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get employees", appErrors.ErrInternal)
	}
	for _, emp := range employees {
		if emp.IsActive {
			return user, nil
		}
	}
	return nil, fmt.Errorf("%w: user is not an active employee", appErrors.ErrPermissionDenied)
}

// ---- Bulk operations ----

// BulkAssignment defines bulk role assignment.
type BulkAssignment struct {
	UserID    uuid.UUID `json:"user_id"`
	RoleID    uuid.UUID `json:"role_id"`
	ReportsTo uuid.UUID `json:"reports_to,omitempty"`
}

// BulkAssignRoles assigns roles to multiple employees.
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

// ---- Manager permissions ----

// AssignManagerPermissions assigns permissions to a manager's role.
func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
	if err != nil {
		return fmt.Errorf("%w: manager not found", appErrors.ErrNotFound)
	}
	perms, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
	}
	permIDs := make([]uuid.UUID, len(perms))
	for i, p := range perms {
		permIDs[i] = p.PermissionID
	}
	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, managerEmp.RoleID, permIDs, assignedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// RevokeManagerPermissions revokes permissions from a manager's role.
func (s *CompanyService) RevokeManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, revokedBy uuid.UUID) error {
	managerEmp, err := s.companyRepo.GetEmployee(ctx, companyID, managerID)
	if err != nil {
		return fmt.Errorf("%w: manager not found", appErrors.ErrNotFound)
	}
	perms, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
	}
	permIDs := make([]uuid.UUID, len(perms))
	for i, p := range perms {
		permIDs[i] = p.PermissionID
	}
	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, managerEmp.RoleID, permIDs); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetManagerPermissions returns permission names for a manager.
func (s *CompanyService) GetManagerPermissions(ctx context.Context, managerID uuid.UUID) ([]string, error) {
	return s.companyRepo.GetUserPermissionNames(ctx, managerID)
}

// ValidatePermissionSubset checks if requested permissions are subset of manager's.
func (s *CompanyService) ValidatePermissionSubset(ctx context.Context, managerPermissions, requestedPermissions []string) bool {
	managerSet := make(map[string]bool)
	for _, p := range managerPermissions {
		managerSet[p] = true
	}
	for _, p := range requestedPermissions {
		if !managerSet[p] {
			return false
		}
	}
	return true
}

// ---- Permission department compatibility ----

// ValidatePermissionDepartmentCompatibility checks if permissions match department modules.
func (s *CompanyService) ValidatePermissionDepartmentCompatibility(ctx context.Context, departmentIDs []uuid.UUID, permissionIDs []uuid.UUID) (bool, string, error) {
	if len(departmentIDs) == 0 || len(permissionIDs) == 0 {
		return true, "", nil
	}
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[uuid.UUID]*models.Permission)
	for _, p := range allPerms {
		permMap[p.PermissionID] = p
	}
	departmentModules := make(map[string]bool)
	for _, deptID := range departmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
		if err != nil {
			return false, "", fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptID)
		}
		if dept.SystemDepartmentID != nil {
			sys, err := s.companyRepo.GetSystemDepartment(ctx, *dept.SystemDepartmentID)
			if err == nil {
				departmentModules[sys.ModuleCode] = true
			}
		}
	}
	for _, permID := range permissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return false, "", fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, permID)
		}
		if !departmentModules[perm.Module] {
			return false, fmt.Sprintf("Permission '%s' module '%s' not compatible with departments", perm.PermissionName, perm.Module), nil
		}
	}
	return true, "", nil
}

func (s *CompanyService) validatePermissionDepartmentCompatibilityForUpdate(ctx context.Context, departmentIDs []uuid.UUID, req UpdateRoleRequest) error {
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, p := range allPerms {
		permMap[p.PermissionName] = p.PermissionID
	}
	var permIDs []uuid.UUID
	for _, name := range req.AddPermissions {
		if id, exists := permMap[name]; exists {
			permIDs = append(permIDs, id)
		}
	}
	if len(req.ReplacePermissions) > 0 {
		permIDs = nil
		for _, name := range req.ReplacePermissions {
			if id, exists := permMap[name]; exists {
				permIDs = append(permIDs, id)
			}
		}
	}
	if len(departmentIDs) > 0 && len(permIDs) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, departmentIDs, permIDs)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	return nil
}

// GetPermissionsByDepartmentModules returns permissions for departments.
func (s *CompanyService) GetPermissionsByDepartmentModules(ctx context.Context, departmentIDs []uuid.UUID) ([]*models.Permission, error) {
	if len(departmentIDs) == 0 {
		return []*models.Permission{}, nil
	}
	var sysDeptIDs []uuid.UUID
	for _, deptID := range departmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, deptID)
		if err != nil {
			continue
		}
		if dept.SystemDepartmentID != nil {
			sysDeptIDs = append(sysDeptIDs, *dept.SystemDepartmentID)
		}
	}
	if len(sysDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}
	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, sysDeptIDs, "", "", "")
}

// GetPermissionsByCompanyDepartments returns permissions for company departments.
func (s *CompanyService) GetPermissionsByCompanyDepartments(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error) {
	depts, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var sysDeptIDs []uuid.UUID
	for _, d := range depts {
		if d.SystemDepartmentID != nil {
			sysDeptIDs = append(sysDeptIDs, *d.SystemDepartmentID)
		}
	}
	adminSys, err := s.companyRepo.GetSystemDepartmentByModule(ctx, "administration")
	if err == nil {
		sysDeptIDs = append(sysDeptIDs, adminSys.SystemDepartmentID)
	}
	if len(sysDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}
	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, sysDeptIDs, module, category, tier)
}

// ---- Validation helpers ----

func (s *CompanyService) validateReportsTo(ctx context.Context, companyID uuid.UUID, userID *uuid.UUID) error {
	if userID == nil {
		return nil
	}
	_, err := s.companyRepo.GetEmployee(ctx, companyID, *userID)
	if err != nil {
		return fmt.Errorf("%w: reports_to user not employee", appErrors.ErrInvalidInput)
	}
	return nil
}

// ---- Statistics and health ----

// GetCompanyStats returns company statistics.
func (s *CompanyService) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	return s.companyRepo.GetCompanyStats(ctx, companyID)
}

// HealthCheck performs health check.
func (s *CompanyService) HealthCheck(ctx context.Context) error {
	return s.companyRepo.HealthCheck(ctx)
}

// ---- Search ----

// SearchCompaniesRequest is alias.
type SearchCompaniesRequest = models.CompanySearchRequest

// SearchCompaniesResponse is alias.
type SearchCompaniesResponse = models.CompanySearchResponse

// CompanySearchResult is alias.
type CompanySearchResult = models.CompanySearchResult

// SearchCompanies searches companies.
func (s *CompanyService) SearchCompanies(ctx context.Context, req *models.CompanySearchRequest) (*models.CompanySearchResponse, error) {
	searchType := req.SearchType
	if searchType == "all" {
		if len(req.Query) < 3 {
			searchType = "autocomplete"
		} else {
			searchType = "fulltext"
		}
	}
	companies, total, err := s.companyRepo.SearchCompaniesByName(ctx, req.Query, searchType, req.Filters, req.Limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	results := make([]*models.CompanySearchResult, len(companies))
	for i, c := range companies {
		results[i] = &models.CompanySearchResult{
			CompanyID:          c.CompanyID,
			CompanyName:        c.CompanyName,
			OwnerUserID:        c.OwnerUserID,
			SubscriptionTier:   c.SubscriptionTier,
			SubscriptionStatus: c.SubscriptionStatus,
			MaxEmployees:       c.MaxEmployees,
			IsActive:           c.IsActive,
			DataRegion:         c.DataRegion,
			CreatedAt:          c.CreatedAt,
			RelevanceScore:     1.0 - float64(i)*0.01,
			MatchType:          searchType,
		}
	}
	page := (req.Offset / req.Limit) + 1
	hasMore := req.Offset+req.Limit < total
	return &models.CompanySearchResponse{
		Companies: results,
		Total:     total,
		Page:      page,
		PageSize:  req.Limit,
		HasMore:   hasMore,
	}, nil
}

// SearchCompaniesByOwner searches companies owned by a user.
func (s *CompanyService) SearchCompaniesByOwner(ctx context.Context, ownerID uuid.UUID, query string, isActive *bool, limit int, offset int) (*models.CompanySearchResponse, error) {
	companies, total, err := s.companyRepo.SearchCompaniesByOwnerAndName(ctx, ownerID, query, isActive, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	results := make([]*models.CompanySearchResult, len(companies))
	for i, c := range companies {
		matchType := "owner_search"
		if query != "" {
			if len(query) < 3 {
				matchType = "autocomplete"
			} else {
				matchType = "fulltext"
			}
		}
		results[i] = &models.CompanySearchResult{
			CompanyID:          c.CompanyID,
			CompanyName:        c.CompanyName,
			OwnerUserID:        c.OwnerUserID,
			SubscriptionTier:   c.SubscriptionTier,
			SubscriptionStatus: c.SubscriptionStatus,
			MaxEmployees:       c.MaxEmployees,
			IsActive:           c.IsActive,
			DataRegion:         c.DataRegion,
			CreatedAt:          c.CreatedAt,
			RelevanceScore:     1.0 - float64(i)*0.01,
			MatchType:          matchType,
		}
	}
	page := (offset / limit) + 1
	hasMore := offset+limit < total
	return &models.CompanySearchResponse{
		Companies: results,
		Total:     total,
		Page:      page,
		PageSize:  limit,
		HasMore:   hasMore,
	}, nil
}

// GetCompanySuggestions returns company name suggestions.
func (s *CompanyService) GetCompanySuggestions(ctx context.Context, prefix string, limit int) ([]string, error) {
	if len(prefix) < 2 {
		return []string{}, nil
	}
	return s.companyRepo.GetCompanySuggestions(ctx, prefix, limit)
}

// GetCompanySearchAnalytics returns search stats.
func (s *CompanyService) GetCompanySearchAnalytics(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.companyRepo.GetCompanySearchStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	companyMetrics, err := s.companyRepo.GetCompanyStats(ctx, uuid.Nil)
	if err == nil {
		stats["company_metrics"] = companyMetrics
	}
	return stats, nil
}

// BenchmarkCompanySearch benchmarks search.
func (s *CompanyService) BenchmarkCompanySearch(ctx context.Context, testQueries []string, iterations int) (map[string]interface{}, error) {
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
	for q, durations := range queryTimes {
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
		stats[q] = map[string]interface{}{
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

// ---- Department search ----

// SearchDepartmentsRequest defines department search.
type SearchDepartmentsRequest struct {
	Query           string `json:"q"`
	Limit           int    `json:"limit,omitempty"`
	Offset          int    `json:"offset,omitempty"`
	IncludeInactive bool   `json:"include_inactive,omitempty"`
}

// DepartmentSearchResponse is response.
type DepartmentSearchResponse struct {
	Departments []*models.DepartmentSearchResult `json:"departments"`
	Total       int                              `json:"total"`
	Page        int                              `json:"page"`
	Limit       int                              `json:"limit"`
	HasMore     bool                             `json:"has_more"`
}

// SearchDepartments searches departments in a company.
func (s *CompanyService) SearchDepartments(ctx context.Context, companyID uuid.UUID, req *SearchDepartmentsRequest) (*DepartmentSearchResponse, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	depts, total, err := s.companyRepo.SearchDepartments(ctx, companyID, req.Query, req.Limit, req.Offset, req.IncludeInactive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	page := 1
	if req.Limit > 0 {
		page = (req.Offset / req.Limit) + 1
	}
	hasMore := (req.Offset + len(depts)) < total
	return &DepartmentSearchResponse{
		Departments: depts,
		Total:       total,
		Page:        page,
		Limit:       req.Limit,
		HasMore:     hasMore,
	}, nil
}

// GetDepartmentSuggestions returns department suggestions.
func (s *CompanyService) GetDepartmentSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.Department, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return s.companyRepo.GetDepartmentSuggestions(ctx, companyID, prefix, limit)
}

// ---- Employee hierarchy ----

// GetUserHierarchy returns hierarchy for a user.
func (s *CompanyService) GetUserHierarchy(ctx context.Context, userID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			roleDepts, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepts) > 0 {
				deptName = roleDepts[0].DepartmentName
				deptID = &roleDepts[0].DepartmentID
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

// GetEmployeeHierarchy returns hierarchy for a company.
func (s *CompanyService) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			roleDepts, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepts) > 0 {
				deptName = roleDepts[0].DepartmentName
				deptID = &roleDepts[0].DepartmentID
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

// GetCompanyHierarchy returns company hierarchy.
func (s *CompanyService) GetCompanyHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	return s.companyRepo.GetEmployeeHierarchy(ctx, companyID)
}

// ---- Role-level queries ----

// GetUsersWithPermission returns users with a permission.
func (s *CompanyService) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersWithPermission(ctx, companyID, permissionName, limit)
}

// GetUsersByRoleLevel returns users by role level.
func (s *CompanyService) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersByRoleLevel(ctx, companyID, minLevel, maxLevel)
}

// ---- Utility ----

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// ListPermissionsByModule retrieves all permissions for a given module.
func (s *CompanyService) ListPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

// GetDepartmentLoad returns the number of employees per department.
func (s *CompanyService) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetDepartmentLoad(ctx, companyID)
}

// GetRoleDistribution returns the count of employees per role.
func (s *CompanyService) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetRoleDistribution(ctx, companyID)
}

// AddDepartment creates a new department in a company and auto‑assigns it to the owner role.
func (s *CompanyService) AddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_dept:%s:%s", companyID.String(), departmentName)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedDept models.Department
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedDept); err == nil {
		return &cachedDept, nil
	}

	// Validate system department
	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, systemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: system department not found", appErrors.ErrNotFound)
	}

	// Check duplicate name (optional, repository may enforce unique)
	existing, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, companyID, 1, 0)
	if err == nil {
		for _, d := range existing {
			if strings.EqualFold(d.DepartmentName, departmentName) {
				return nil, fmt.Errorf("%w: department name already exists", appErrors.ErrDuplicate)
			}
		}
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
		return nil, fmt.Errorf("%w: failed to create department", appErrors.ErrInternal)
	}

	// Auto-assign to owner role (non-critical)
	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err == nil {
		_ = s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID)
	}

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, department)

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "add_department", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id":        companyID.String(),
				"department_id":     department.DepartmentID.String(),
				"department_name":   departmentName,
				"system_department": systemDept.Name,
				"ip_address":        ip,
			})
	}

	return department, nil
}

// GetRoleDepartments returns departments for a role.
func (s *CompanyService) GetRoleDepartmentsForPermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRoleDepartmentsForPermission(ctx, roleID)
}

// UpdateEmployee updates an existing employee's details.
// It validates role, position, reports_to, and active status against company rules.
func (s *CompanyService) UpdateEmployee(ctx context.Context, req *UpdateEmployeeRequest) error {
	// 1. Fetch existing employee to verify existence and get current values
	existing, err := s.companyRepo.GetEmployee(ctx, req.CompanyID, req.UserID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return fmt.Errorf("%w: failed to get employee", appErrors.ErrInternal)
	}

	// 2. Prepare update map
	updates := make(map[string]interface{})
	if req.EmployeeID != nil {
		updates["employee_id"] = *req.EmployeeID
	}
	if req.RoleID != nil {
		updates["role_id"] = *req.RoleID
	}
	if req.PositionID != nil {
		updates["position_id"] = *req.PositionID
	}
	if req.ReportsTo != nil {
		updates["reports_to"] = *req.ReportsTo
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}
	// No fields to update
	if len(updates) == 0 {
		return fmt.Errorf("%w: no fields to update", appErrors.ErrInvalidInput)
	}

	// 3. Validate role if provided
	if req.RoleID != nil {
		role, err := s.companyRepo.GetRole(ctx, *req.RoleID)
		if err != nil {
			return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
		}
		if role.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: role does not belong to company", appErrors.ErrInvalidInput)
		}
		// Check if role has departments (optional but recommended)
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, *req.RoleID)
		if err != nil || len(roleDepts) == 0 {
			return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
		}
	}

	// 4. Validate position if provided
	if req.PositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, *req.PositionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open for assignment", appErrors.ErrInvalidState)
		}

		// Determine which role to check for department compatibility
		var roleID uuid.UUID
		if req.RoleID != nil {
			roleID = *req.RoleID
		} else {
			roleID = existing.RoleID // use current role
		}

		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, roleID)
		if err != nil {
			return err
		}
		found := false
		for _, rd := range roleDepts {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to the role", appErrors.ErrInvalidInput)
		}
	}

	// 5. Validate reports_to if provided
	if req.ReportsTo != nil {
		if *req.ReportsTo == req.UserID {
			return fmt.Errorf("%w: employee cannot report to themselves", appErrors.ErrInvalidInput)
		}
		// Check if the reports-to user is an active employee of the same company
		isActive, err := s.companyRepo.IsUserActiveEmployee(ctx, req.CompanyID, *req.ReportsTo)
		if err != nil || !isActive {
			return fmt.Errorf("%w: reports-to employee not found or not active", appErrors.ErrInvalidInput)
		}
	}

	// 6. If deactivating, prevent deactivation if they are a manager of active employees? (optional)
	// This is a business rule you may or may not want to enforce.
	// For now, we allow deactivation.

	// 7. Perform update
	if err := s.companyRepo.UpdateEmployeeOfCompany(ctx, req.CompanyID, req.UserID, updates); err != nil {
		return fmt.Errorf("%w: failed to update employee", appErrors.ErrInternal)
	}

	// 8. Audit logging
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_employee", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(),
				"user_id":    req.UserID.String(),
				"updates":    updates,
				"ip_address": ip,
			})
	}

	return nil
}

// UpdateEmployeeRequest defines the fields that can be updated.
type UpdateEmployeeRequest struct {
	CompanyID  uuid.UUID
	UserID     uuid.UUID
	EmployeeID *string
	RoleID     *uuid.UUID
	PositionID *uuid.UUID
	ReportsTo  *uuid.UUID
	IsActive   *bool
}
