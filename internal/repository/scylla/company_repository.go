// repository/scylla/company_repository.go
package scylla

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/models"
	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================
// CompanyRepository Interface (OPTIMIZED FOR FIXED MATERIALIZED VIEWS)
// ============================================================

type CompanyRepository interface {
	// ============================================================
	// Company operations (OPTIMIZED WITH MATERIALIZED VIEWS)
	// ============================================================
	CreateCompany(ctx context.Context, company *models.Company) error
	GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error)
	GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error)
	GetCompaniesByBlockedStatus(ctx context.Context, isBlocked bool, limit int) ([]*models.Company, error) 
	GetCompaniesByCreatedDate(ctx context.Context, limit int) ([]*models.Company, error) 

	// ❌ REMOVED: Complex multi-filter ListCompanies
	// ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error)
	
	ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error)
	BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error
	UnblockCompany(ctx context.Context, companyID uuid.UUID) error
	UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error
	UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error
	UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error
	GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error)
	
	// NEW: Direct materialized view queries
	GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error)
	// GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error)
	// GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error)
	GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error)

	// ============================================================
	// Department operations
	// ============================================================
	CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error
	GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error)
	UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error
	ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error)
	DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error

	// ============================================================
	// Employee operations (OPTIMIZED WITH MATERIALIZED VIEWS)
	// ============================================================
	CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
	GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
	GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error)
	UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)
	ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)
	ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)
	GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) 

	// Employee Activation/Status Functions
	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)

	// ============================================================
	// Role operations
	// ============================================================
	CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
	GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error)
	GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error)
	UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
	ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
	ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
	DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error

	// ============================================================
	// Permission operations
	// ============================================================
	GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error)
	GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error
	RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error
	GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error)
    GetCompaniesByActiveStatus(ctx context.Context, isActive bool, limit int) ([]*models.Company, error) 

	// ============================================================
	// Utility
	// ============================================================
	HealthCheck(ctx context.Context) error
}

// ============================================================
// Implementation
// ============================================================

type CompanyRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger
}

func NewCompanyRepository(client *ScyllaClient, logger *zap.Logger) CompanyRepository {
	return &CompanyRepositoryImpl{
		client: client,
		logger: logger,
	}
}

// ============================================================
// Company CRUD
// ============================================================
// GetCompaniesByActiveStatus retrieves companies by active status
func (r *CompanyRepositoryImpl) GetCompaniesByActiveStatus(ctx context.Context, isActive bool, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    query := r.client.Session.Query(`
        SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
               subscription_start_date, subscription_end_date, created_at
        FROM companies_by_active_status 
        WHERE is_active = ? 
        LIMIT ?`,
        isActive, limit,
    )
    
    return r.fetchCompaniesFromViewIter(ctx, query, 0)
}
func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company) error {
	query := r.client.Session.Query(`
		INSERT INTO companies (
			company_id, company_name, owner_phone, owner_user_id, 
			subscription_tier, subscription_start_date, subscription_end_date,
			monthly_premium, max_employees, is_active, is_blocked,
			created_at, updated_at, data_region
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(company.CompanyID),
		company.CompanyName,
		company.OwnerPhone,
		gocql.UUID(company.OwnerUserID),
		company.SubscriptionTier,
		company.SubscriptionStartDate,
		company.SubscriptionEndDate,
		company.MonthlyPremium,
		company.MaxEmployees,
		company.IsActive,
		company.IsBlocked,
		company.CreatedAt,
		company.UpdatedAt,
		company.DataRegion,
	)

	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	query := r.client.Session.Query(`
		SELECT company_id, company_name, owner_phone, owner_user_id,
		       subscription_tier, subscription_start_date, subscription_end_date,
		       monthly_premium, max_employees, is_active, is_blocked,
		       blocked_reason, blocked_by, blocked_at,
		       created_at, updated_at, data_region
		FROM companies WHERE company_id = ?`,
		gocql.UUID(companyID),
	)

	var (
		scannedID        gocql.UUID
		scannedOwnerID   gocql.UUID
		scannedBlockedBy gocql.UUID
		company          models.Company
	)

	err := query.WithContext(ctx).Scan(
		&scannedID, &company.CompanyName, &company.OwnerPhone, &scannedOwnerID,
		&company.SubscriptionTier, &company.SubscriptionStartDate, &company.SubscriptionEndDate,
		&company.MonthlyPremium, &company.MaxEmployees, &company.IsActive, &company.IsBlocked,
		&company.BlockedReason, &scannedBlockedBy, &company.BlockedAt,
		&company.CreatedAt, &company.UpdatedAt, &company.DataRegion,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("company not found: %s", companyID.String())
		}
		return nil, fmt.Errorf("failed to get company: %w", err)
	}

	company.CompanyID = uuid.UUID(scannedID)
	company.OwnerUserID = uuid.UUID(scannedOwnerID)
	if scannedBlockedBy != (gocql.UUID{}) {
		company.BlockedBy = uuid.UUID(scannedBlockedBy)
	}

	return &company, nil
}

// GetCompaniesByOwner - DIRECT MATERIALIZED VIEW QUERY
func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	query := r.client.Session.Query(`
		SELECT company_id, company_name, owner_phone, owner_user_id,
		       subscription_tier, is_active, created_at
		FROM companies_by_owner WHERE owner_user_id = ?`,
		gocql.UUID(ownerUserID),
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var companies []*models.Company
	var (
		companyID       gocql.UUID
		companyName     string
		ownerPhone      string
		scannedOwnerID  gocql.UUID
		subscriptionTier string
		isActive        bool
		createdAt       time.Time
	)

	for iter.Scan(&companyID, &companyName, &ownerPhone, &scannedOwnerID, 
		&subscriptionTier, &isActive, &createdAt) {
		
		company := &models.Company{
			CompanyID:        uuid.UUID(companyID),
			CompanyName:      companyName,
			OwnerPhone:       ownerPhone,
			OwnerUserID:      uuid.UUID(scannedOwnerID),
			SubscriptionTier: subscriptionTier,
			IsActive:         isActive,
			CreatedAt:        createdAt,
		}
		companies = append(companies, company)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate companies_by_owner: %w", err)
	}

	return companies, nil
}

// ❌ REMOVED: Complex multi-filter ListCompanies method

// ============================================================
// NEW DIRECT MATERIALIZED VIEW QUERIES
// ============================================================

// DIRECT QUERY: Get companies by tier using companies_by_tier
func (r *CompanyRepositoryImpl) GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error) {
	query := r.client.Session.Query(`
		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
		       subscription_start_date, subscription_end_date, created_at
		FROM companies_by_tier 
		WHERE subscription_tier = ? 
		LIMIT ?`,
		tier, limit,
	)

	return r.fetchCompaniesFromViewIter(ctx, query, 0)
}

// // DIRECT QUERY: Get companies by tier and active status using companies_by_tier_active
// func (r *CompanyRepositoryImpl) GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, subscription_tier, is_active, company_name
// 		FROM companies_by_tier_active 
// 		WHERE subscription_tier = ? AND is_active = ? 
// 		LIMIT ?`,
// 		tier, isActive, limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID      gocql.UUID
// 		subscriptionTier string
// 		isActiveFlag   bool
// 		companyName    string
// 	)

// 	for iter.Scan(&companyID, &subscriptionTier, &isActiveFlag, &companyName) {
// 		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// 		if err == nil && company != nil {
// 			companies = append(companies, company)
// 		}
		
// 		if len(companies) >= limit {
// 			break
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies_by_tier_active: %w", err)
// 	}

// 	return companies, nil
// }

// DIRECT QUERY: Get companies by tier and blocked status using companies_by_tier_blocked
func (r *CompanyRepositoryImpl) GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error) {
	query := r.client.Session.Query(`
		SELECT company_id, subscription_tier, is_blocked, company_name
		FROM companies_by_tier_blocked 
		WHERE subscription_tier = ? AND is_blocked = ? 
		LIMIT ?`,
		tier, isBlocked, limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var companies []*models.Company
	var (
		companyID      gocql.UUID
		subscriptionTier string
		isBlockedFlag  bool
		companyName    string
	)

	for iter.Scan(&companyID, &subscriptionTier, &isBlockedFlag, &companyName) {
		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
		if err == nil && company != nil {
			companies = append(companies, company)
		}
		
		if len(companies) >= limit {
			break
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate companies_by_tier_blocked: %w", err)
	}

	return companies, nil
}

// Get companies by subscription date range
func (r *CompanyRepositoryImpl) GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error) {
	query := r.client.Session.Query(`
		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
		       subscription_start_date, subscription_end_date, created_at
		FROM companies_by_subscription_date 
		WHERE subscription_end_date >= ? AND subscription_end_date <= ?
		LIMIT ?`,
		startDate, endDate, limit,
	)

	return r.fetchCompaniesFromViewIter(ctx, query, 0)
}

// Helper function to fetch companies from view iterations
func (r *CompanyRepositoryImpl) fetchCompaniesFromViewIter(ctx context.Context, query *gocql.Query, offset int) ([]*models.Company, error) {
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var companies []*models.Company
	var (
		companyID              gocql.UUID
		companyName            string
		subscriptionTier       string
		isActive               bool
		isBlocked              bool
		subscriptionStartDate  time.Time
		subscriptionEndDate    time.Time
		createdAt              time.Time
	)

	currentOffset := 0
	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActive, &isBlocked,
		&subscriptionStartDate, &subscriptionEndDate, &createdAt) {
		
		if currentOffset < offset {
			currentOffset++
			continue
		}
		
		company := &models.Company{
			CompanyID:             uuid.UUID(companyID),
			CompanyName:           companyName,
			SubscriptionTier:      subscriptionTier,
			IsActive:              isActive,
			IsBlocked:             isBlocked,
			SubscriptionStartDate: subscriptionStartDate,
			SubscriptionEndDate:   subscriptionEndDate,
			CreatedAt:             createdAt,
		}
		companies = append(companies, company)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate materialized view: %w", err)
	}

	return companies, nil
}

// ============================================================
// OPTIMIZED EMPLOYEE QUERIES WITH MATERIALIZED VIEWS
// ============================================================

// GetCompanyEmployeeByUser - DIRECT MATERIALIZED VIEW QUERY
func (r *CompanyRepositoryImpl) GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	query := r.client.Session.Query(`
		SELECT company_id, user_id, employee_id, role_id, department_id, is_active
		FROM employees_by_user 
		WHERE user_id = ?`,
		gocql.UUID(userID),
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var employees []*models.CompanyEmployee
	var (
		scCompanyID gocql.UUID
		scUserID    gocql.UUID
		employeeID  string
		scRoleID    gocql.UUID
		scDeptID    gocql.UUID
		isActive    bool
	)

	for iter.Scan(&scCompanyID, &scUserID, &employeeID, &scRoleID, &scDeptID, &isActive) {
		emp := &models.CompanyEmployee{
			CompanyID:    uuid.UUID(scCompanyID),
			UserID:       uuid.UUID(scUserID),
			EmployeeID:   employeeID,
			RoleID:       uuid.UUID(scRoleID),
			DepartmentID: uuid.UUID(scDeptID),
			IsActive:     isActive,
		}
		employees = append(employees, emp)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate employees_by_user: %w", err)
	}

	return employees, nil
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

func (r *CompanyRepositoryImpl) statusToIsActive(status string) bool {
	switch status {
	case models.SubscriptionStatusActive:
		return true
	case models.SubscriptionStatusCompanyInactive:
		return false
	case models.SubscriptionStatusCompanyBlocked:
		return true // blocked companies are technically active but blocked
	default:
		return true
	}
}

func (r *CompanyRepositoryImpl) matchesStatus(status string, isActive, isBlocked bool) bool {
	switch status {
	case models.SubscriptionStatusActive:
		return isActive && !isBlocked
	case models.SubscriptionStatusCompanyBlocked:
		return isBlocked
	case models.SubscriptionStatusCompanyInactive:
		return !isActive && !isBlocked
	default:
		return true
	}
}

func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
	isActive := r.statusToIsActive(status)
	
	query := r.client.Session.Query(`
		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
		       subscription_start_date, subscription_end_date, created_at
		FROM companies_by_active_status 
		WHERE is_active = ? 
		LIMIT ?`,
		isActive, limit,
	)

	return r.fetchCompaniesFromViewIter(ctx, query, 0)
}

func (r *CompanyRepositoryImpl) ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error) {
	// Implementation for cursor-based pagination
	query := r.client.Session.Query(`
		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
		       subscription_start_date, subscription_end_date, created_at
		FROM companies 
		LIMIT ?`,
		pageSize,
	).PageState(pageState)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var companies []*models.Company
	var (
		companyID              gocql.UUID
		companyName            string
		subscriptionTier       string
		isActive               bool
		isBlocked              bool
		subscriptionStartDate  time.Time
		subscriptionEndDate    time.Time
		createdAt              time.Time
	)

	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActive, &isBlocked,
		&subscriptionStartDate, &subscriptionEndDate, &createdAt) {
		
		company := &models.Company{
			CompanyID:             uuid.UUID(companyID),
			CompanyName:           companyName,
			SubscriptionTier:      subscriptionTier,
			IsActive:              isActive,
			IsBlocked:             isBlocked,
			SubscriptionStartDate: subscriptionStartDate,
			SubscriptionEndDate:   subscriptionEndDate,
			CreatedAt:             createdAt,
		}
		companies = append(companies, company)
	}

	nextPageState := iter.PageState()
	if err := iter.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate companies with paging: %w", err)
	}

	return companies, nextPageState, nil
}

func (r *CompanyRepositoryImpl) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error {
	query := r.client.Session.Query(`
		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
		true, reason, gocql.UUID(blockedBy), blockedAt, time.Now().UTC(), gocql.UUID(companyID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) UnblockCompany(ctx context.Context, companyID uuid.UUID) error {
	now := time.Now().UTC()
	query := r.client.Session.Query(`
		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
		false, nil, nil, nil, now, gocql.UUID(companyID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error {
	query := r.client.Session.Query(`
		UPDATE companies SET subscription_tier = ?, monthly_premium = ?, max_employees = ?, updated_at = ? 
		WHERE company_id = ?`,
		tier, premium, maxEmployees, updatedAt, gocql.UUID(companyID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error {
	query := r.client.Session.Query(`
		UPDATE companies SET subscription_end_date = ?, updated_at = ? WHERE company_id = ?`,
		endDate, time.Now().UTC(), gocql.UUID(companyID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error {
	query := r.client.Session.Query(`
		UPDATE companies SET is_active = ?, updated_at = ? WHERE company_id = ?`,
		isActive, time.Now().UTC(), gocql.UUID(companyID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
	query := r.client.Session.Query(`
		INSERT INTO company_departments (
			company_id, department_id, department_name, department_head, 
			permissions, is_active, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(department.CompanyID),
		gocql.UUID(department.DepartmentID),
		department.DepartmentName,
		gocql.UUID(department.DepartmentHead),
		department.Permissions,
		department.IsActive,
		department.CreatedAt,
		department.UpdatedAt,
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
	query := r.client.Session.Query(`
		SELECT company_id, department_id, department_name, department_head, 
		       permissions, is_active, created_at, updated_at
		FROM company_departments WHERE company_id = ? AND department_id = ?`,
		gocql.UUID(companyID), gocql.UUID(departmentID),
	)

	var (
		scCompanyID    gocql.UUID
		scDepartmentID gocql.UUID
		scDeptHead     gocql.UUID
		department     models.CompanyDepartment
	)

	err := query.WithContext(ctx).Scan(
		&scCompanyID, &scDepartmentID, &department.DepartmentName, &scDeptHead,
		&department.Permissions, &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("department not found")
		}
		return nil, fmt.Errorf("failed to get department: %w", err)
	}

	department.CompanyID = uuid.UUID(scCompanyID)
	department.DepartmentID = uuid.UUID(scDepartmentID)
	department.DepartmentHead = uuid.UUID(scDeptHead)
	return &department, nil
}

func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
	query := r.client.Session.Query(`
		UPDATE company_departments SET 
			department_name = ?, department_head = ?, permissions = ?, 
			is_active = ?, updated_at = ?
		WHERE company_id = ? AND department_id = ?`,
		department.DepartmentName,
		gocql.UUID(department.DepartmentHead),
		department.Permissions,
		department.IsActive,
		department.UpdatedAt,
		gocql.UUID(department.CompanyID),
		gocql.UUID(department.DepartmentID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT department_id FROM company_departments 
		WHERE company_id = ? AND is_active = true LIMIT ?`,
		gocql.UUID(companyID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var deptID gocql.UUID
	var departments []*models.CompanyDepartment

	for iter.Scan(&deptID) {
		dept, err := r.GetDepartment(ctx, companyID, uuid.UUID(deptID))
		if err == nil && dept != nil {
			departments = append(departments, dept)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate departments: %w", err)
	}

	return departments, nil
}

func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error {
	query := r.client.Session.Query(`
		UPDATE company_departments SET is_active = false, updated_at = ?
		WHERE company_id = ? AND department_id = ?`,
		time.Now().UTC(), gocql.UUID(companyID), gocql.UUID(departmentID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	query := r.client.Session.Query(`
		INSERT INTO company_employees (
			company_id, user_id, employee_id, role_id, department_id,
			hire_date, is_active, reports_to, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(employee.CompanyID),
		gocql.UUID(employee.UserID),
		employee.EmployeeID,
		gocql.UUID(employee.RoleID),
		gocql.UUID(employee.DepartmentID),
		employee.HireDate,
		employee.IsActive,
		gocql.UUID(employee.ReportsTo),
		employee.CreatedAt,
		employee.UpdatedAt,
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	query := r.client.Session.Query(`
		SELECT company_id, user_id, employee_id, role_id, department_id, hire_date, is_active, reports_to, created_at, updated_at
		FROM company_employees WHERE company_id = ? AND user_id = ?`,
		gocql.UUID(companyID), gocql.UUID(userID),
	)
	var (
		scCompanyID gocql.UUID
		scUserID    gocql.UUID
		emp         models.CompanyEmployee
		scRoleID    gocql.UUID
		scDeptID    gocql.UUID
		scReportsTo gocql.UUID
	)
	err := query.WithContext(ctx).Scan(
		&scCompanyID, &scUserID, &emp.EmployeeID, &scRoleID, &scDeptID, &emp.HireDate, &emp.IsActive, &scReportsTo, &emp.CreatedAt, &emp.UpdatedAt,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get company employee: %w", err)
	}

	emp.CompanyID = uuid.UUID(scCompanyID)
	emp.UserID = uuid.UUID(scUserID)
	emp.RoleID = uuid.UUID(scRoleID)
	emp.DepartmentID = uuid.UUID(scDeptID)
	if scReportsTo != (gocql.UUID{}) {
		emp.ReportsTo = uuid.UUID(scReportsTo)
	}
	return &emp, nil
}

func (r *CompanyRepositoryImpl) UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	query := r.client.Session.Query(`
		UPDATE company_employees SET 
			employee_id = ?, role_id = ?, department_id = ?, 
			reports_to = ?, is_active = ?, updated_at = ?
		WHERE company_id = ? AND user_id = ?`,
		employee.EmployeeID,
		gocql.UUID(employee.RoleID),
		gocql.UUID(employee.DepartmentID),
		gocql.UUID(employee.ReportsTo),
		employee.IsActive,
		employee.UpdatedAt,
		gocql.UUID(employee.CompanyID),
		gocql.UUID(employee.UserID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT user_id FROM company_employees WHERE company_id = ? LIMIT ?`,
		gocql.UUID(companyID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var uid gocql.UUID
	var employees []*models.CompanyEmployee

	for iter.Scan(&uid) {
		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
		if err == nil && e != nil {
			employees = append(employees, e)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to list employees: %w", err)
	}

	return employees, len(employees), nil
}

func (r *CompanyRepositoryImpl) ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT user_id FROM company_employees 
		WHERE company_id = ? AND department_id = ? AND is_active = true LIMIT ?`,
		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var uid gocql.UUID
	var employees []*models.CompanyEmployee

	for iter.Scan(&uid) {
		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
		if err == nil && e != nil && e.IsActive {
			employees = append(employees, e)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to list employees by department: %w", err)
	}

	return employees, nil
}

func (r *CompanyRepositoryImpl) ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT user_id FROM company_employees 
		WHERE company_id = ? AND role_id = ? AND is_active = true LIMIT ?`,
		gocql.UUID(companyID), gocql.UUID(roleID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var uid gocql.UUID
	var employees []*models.CompanyEmployee

	for iter.Scan(&uid) {
		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
		if err == nil && e != nil && e.IsActive {
			employees = append(employees, e)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to list employees by role: %w", err)
	}

	return employees, nil
}

func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := r.client.Session.Query(`SELECT COUNT(*) FROM company_employees WHERE company_id = ?`, gocql.UUID(companyID))
	var cnt int64
	if err := query.WithContext(ctx).Scan(&cnt); err != nil {
		return 0, fmt.Errorf("failed to count employees: %w", err)
	}
	return int(cnt), nil
}

func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := r.client.Session.Query(`
		UPDATE company_employees SET is_active = false, updated_at = ?
		WHERE company_id = ? AND user_id = ?`,
		time.Now().UTC(),
		gocql.UUID(companyID),
		gocql.UUID(userID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := r.client.Session.Query(`
		UPDATE company_employees SET is_active = true, updated_at = ?
		WHERE company_id = ? AND user_id = ?`,
		time.Now().UTC(),
		gocql.UUID(companyID),
		gocql.UUID(userID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := r.client.Session.Query(`
		SELECT COUNT(*) FROM company_employees 
		WHERE company_id = ? AND is_active = true`,
		gocql.UUID(companyID),
	)
	var count int64
	if err := query.WithContext(ctx).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count active employees: %w", err)
	}
	return int(count), nil
}

func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT user_id FROM company_employees 
		WHERE company_id = ? AND is_active = true 
		LIMIT ?`,
		gocql.UUID(companyID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var uid gocql.UUID
	var employeeIDs []uuid.UUID

	for iter.Scan(&uid) {
		employeeIDs = append(employeeIDs, uuid.UUID(uid))
	}

	if err := iter.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to list active employees: %w", err)
	}

	// Get employee details
	var employees []*models.CompanyEmployee
	for _, userID := range employeeIDs {
		emp, err := r.GetCompanyEmployee(ctx, companyID, userID)
		if err == nil && emp != nil && emp.IsActive {
			employees = append(employees, emp)
		}
	}

	return employees, len(employees), nil
}

func (r *CompanyRepositoryImpl) CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
	query := r.client.Session.Query(`
		INSERT INTO employee_roles (
			company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gocql.UUID(role.CompanyID),
		gocql.UUID(role.RoleID),
		role.RoleName,
		role.RoleLevel,
		role.Permissions,
		gocql.UUID(role.DepartmentID),
		role.IsSystemRole,
		role.CreatedAt,
		role.UpdatedAt,
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error) {
	query := r.client.Session.Query(`
		SELECT company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
		FROM employee_roles WHERE company_id = ? AND role_id = ?`,
		gocql.UUID(companyID), gocql.UUID(roleID),
	)
	var (
		scCompanyID gocql.UUID
		scRoleID    gocql.UUID
		role        models.EmployeeRole
		scDeptID    gocql.UUID
	)
	err := query.WithContext(ctx).Scan(&scCompanyID, &scRoleID, &role.RoleName, &role.RoleLevel, &role.Permissions, &scDeptID, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("role not found")
		}
		return nil, fmt.Errorf("failed to get employee role: %w", err)
	}
	role.CompanyID = uuid.UUID(scCompanyID)
	role.RoleID = uuid.UUID(scRoleID)
	role.DepartmentID = uuid.UUID(scDeptID)
	return &role, nil
}

func (r *CompanyRepositoryImpl) GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error) {
	query := r.client.Session.Query(`
		SELECT role_id FROM employee_roles 
		WHERE company_id = ? AND role_level = ? LIMIT 1`,
		gocql.UUID(companyID), roleLevel,
	)

	var roleID gocql.UUID
	if err := query.WithContext(ctx).Scan(&roleID); err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("role level not found: %s", roleLevel)
		}
		return nil, fmt.Errorf("failed to get role by level: %w", err)
	}

	return r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
}

func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
	query := r.client.Session.Query(`
		UPDATE employee_roles SET 
			role_name = ?, role_level = ?, permissions = ?, department_id = ?,
			is_system_role = ?, updated_at = ?
		WHERE company_id = ? AND role_id = ?`,
		role.RoleName,
		role.RoleLevel,
		role.Permissions,
		gocql.UUID(role.DepartmentID),
		role.IsSystemRole,
		role.UpdatedAt,
		gocql.UUID(role.CompanyID),
		gocql.UUID(role.RoleID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT role_id FROM employee_roles WHERE company_id = ? LIMIT ?`,
		gocql.UUID(companyID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var roleID gocql.UUID
	var roles []*models.EmployeeRole

	for iter.Scan(&roleID) {
		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
		if err == nil && role != nil {
			roles = append(roles, role)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to list employee roles: %w", err)
	}

	return roles, nil
}

func (r *CompanyRepositoryImpl) ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := r.client.Session.Query(`
		SELECT role_id FROM employee_roles 
		WHERE company_id = ? AND department_id = ? LIMIT ?`,
		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
	)

	iter := query.WithContext(ctx).Iter()
	var roleID gocql.UUID
	var roles []*models.EmployeeRole

	for iter.Scan(&roleID) {
		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
		if err == nil && role != nil {
			roles = append(roles, role)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to list employee roles by department: %w", err)
	}

	return roles, nil
}

func (r *CompanyRepositoryImpl) DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error {
	query := r.client.Session.Query(`
		DELETE FROM employee_roles WHERE company_id = ? AND role_id = ?`,
		gocql.UUID(companyID), gocql.UUID(roleID),
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

// ============================================================
// Permission Operations (ENHANCED)
// ============================================================

func (r *CompanyRepositoryImpl) GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error) {
	query := r.client.Session.Query(`
		SELECT permission FROM employee_permissions WHERE company_id = ? AND user_id = ?`,
		gocql.UUID(companyID), gocql.UUID(userID),
	)
	iter := query.WithContext(ctx).Iter()
	var perm string
	perms := make([]string, 0)
	for iter.Scan(&perm) {
		perms = append(perms, perm)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate permissions: %w", err)
	}
	return perms, nil
}

func (r *CompanyRepositoryImpl) GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error {
	query := r.client.Session.Query(`
		INSERT INTO employee_permissions (
			company_id, user_id, permission, granted_by, granted_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		gocql.UUID(permission.CompanyID),
		gocql.UUID(permission.UserID),
		permission.Permission,
		gocql.UUID(permission.GrantedBy),
		permission.GrantedAt,
		permission.ExpiresAt,
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error {
	query := r.client.Session.Query(`
		DELETE FROM employee_permissions 
		WHERE company_id = ? AND user_id = ? AND permission = ?`,
		gocql.UUID(companyID), gocql.UUID(userID), permission,
	)
	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
}

func (r *CompanyRepositoryImpl) GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// First get user IDs with the permission
	query := r.client.Session.Query(`
		SELECT user_id FROM employee_permissions 
		WHERE company_id = ? AND permission = ? LIMIT ?`,
		gocql.UUID(companyID), permission, limit,
	)

	iter := query.WithContext(ctx).Iter()
	var uid gocql.UUID
	var employees []*models.CompanyEmployee

	for iter.Scan(&uid) {
		emp, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
		if err == nil && emp != nil && emp.IsActive {
			employees = append(employees, emp)
		}
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to get employees with permission: %w", err)
	}

	return employees, nil
}

// ============================================================
// Health Check
// ============================================================

func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
	var release string
	q := r.client.Session.Query(`SELECT release_version FROM system.local`)
	if err := q.WithContext(ctx).Scan(&release); err != nil {
		return fmt.Errorf("scylla health check failed: %w", err)
	}
	r.logger.Debug("scylla release_version", zap.String("version", release))
	return nil
}

// ✅ ADD these methods
func (r *CompanyRepositoryImpl) GetCompaniesByBlockedStatus(ctx context.Context, isBlocked bool, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    query := r.client.Session.Query(`
        SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
               subscription_start_date, subscription_end_date, created_at
        FROM companies_by_blocked_status 
        WHERE is_blocked = ? 
        LIMIT ?`,
        isBlocked, limit,
    )
    
    return r.fetchCompaniesFromViewIter(ctx, query, 0)
}

func (r *CompanyRepositoryImpl) GetCompaniesByCreatedDate(ctx context.Context, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    query := r.client.Session.Query(`
        SELECT company_id, company_name, subscription_tier, is_active, created_at
        FROM companies_by_created_date 
        LIMIT ?`,
        limit,
    )
    
    return r.fetchCompaniesFromViewIter(ctx, query, 0)
}

// GetCompaniesWithExpiringSubscription gets companies whose subscription ends within X days
func (r *CompanyRepositoryImpl) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    
    // Calculate the date range
    startDate := time.Now().UTC()
    endDate := startDate.AddDate(0, 0, days)
    
    query := r.client.Session.Query(`
        SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
               subscription_start_date, subscription_end_date, created_at
        FROM companies 
        WHERE subscription_end_date >= ? AND subscription_end_date <= ?
        LIMIT ?`,
        startDate, endDate, limit,
    )
    
    return r.fetchCompaniesFromViewIter(ctx, query, 0)
}
// package scylla

// import (
// 	"context"
// 	"fmt"
// 	"strings"
// 	"time"

// 	"auth-service/internal/models"
// 	"github.com/gocql/gocql"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// // ============================================================
// // CompanyRepository Interface (OPTIMIZED FOR FIXED MATERIALIZED VIEWS)
// // ============================================================

// type CompanyRepository interface {
// 	// ============================================================
// 	// Company operations (OPTIMIZED WITH MATERIALIZED VIEWS)
// 	// ============================================================
// 	CreateCompany(ctx context.Context, company *models.Company) error
// 	GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error)
// 	GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error)
// 	ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error)
// 	ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error)
// 	BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error
// 	UnblockCompany(ctx context.Context, companyID uuid.UUID) error
// 	UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error
// 	UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error
// 	UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error
// 	GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error)
	
// 	// NEW: Direct materialized view queries
// 	GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error)
// 	GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error)
// 	GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error)
// 	GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error)

// 	// ============================================================
// 	// Department operations
// 	// ============================================================
// 	CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// 	GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error)
// 	UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// 	ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error)
// 	DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error

// 	// ============================================================
// 	// Employee operations (OPTIMIZED WITH MATERIALIZED VIEWS)
// 	// ============================================================
// 	CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// 	GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
// 	GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error)
// 	UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// 	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// 	ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)
// 	ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)
// 	ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)

// 	// Employee Activation/Status Functions
// 	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// 	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// 	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// 	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)

// 	// ============================================================
// 	// Role operations
// 	// ============================================================
// 	CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// 	GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error)
// 	GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error)
// 	UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// 	ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// 	ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// 	DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error

// 	// ============================================================
// 	// Permission operations
// 	// ============================================================
// 	GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error)
// 	GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error
// 	RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error
// 	GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error)

// 	// ============================================================
// 	// Utility
// 	// ============================================================
// 	HealthCheck(ctx context.Context) error
// }

// // ============================================================
// // Implementation
// // ============================================================

// type CompanyRepositoryImpl struct {
// 	client *ScyllaClient
// 	logger *zap.Logger
// }

// func NewCompanyRepository(client *ScyllaClient, logger *zap.Logger) CompanyRepository {
// 	return &CompanyRepositoryImpl{
// 		client: client,
// 		logger: logger,
// 	}
// }

// // ============================================================
// // Company CRUD
// // ============================================================

// func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company) error {
// 	query := r.client.Session.Query(`
// 		INSERT INTO companies (
// 			company_id, company_name, owner_phone, owner_user_id, 
// 			subscription_tier, subscription_start_date, subscription_end_date,
// 			monthly_premium, max_employees, is_active, is_blocked,
// 			created_at, updated_at, data_region
// 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(company.CompanyID),
// 		company.CompanyName,
// 		company.OwnerPhone,
// 		gocql.UUID(company.OwnerUserID),
// 		company.SubscriptionTier,
// 		company.SubscriptionStartDate,
// 		company.SubscriptionEndDate,
// 		company.MonthlyPremium,
// 		company.MaxEmployees,
// 		company.IsActive,
// 		company.IsBlocked,
// 		company.CreatedAt,
// 		company.UpdatedAt,
// 		company.DataRegion,
// 	)

// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, owner_phone, owner_user_id,
// 		       subscription_tier, subscription_start_date, subscription_end_date,
// 		       monthly_premium, max_employees, is_active, is_blocked,
// 		       blocked_reason, blocked_by, blocked_at,
// 		       created_at, updated_at, data_region
// 		FROM companies WHERE company_id = ?`,
// 		gocql.UUID(companyID),
// 	)

// 	var (
// 		scannedID        gocql.UUID
// 		scannedOwnerID   gocql.UUID
// 		scannedBlockedBy gocql.UUID
// 		company          models.Company
// 	)

// 	err := query.WithContext(ctx).Scan(
// 		&scannedID, &company.CompanyName, &company.OwnerPhone, &scannedOwnerID,
// 		&company.SubscriptionTier, &company.SubscriptionStartDate, &company.SubscriptionEndDate,
// 		&company.MonthlyPremium, &company.MaxEmployees, &company.IsActive, &company.IsBlocked,
// 		&company.BlockedReason, &scannedBlockedBy, &company.BlockedAt,
// 		&company.CreatedAt, &company.UpdatedAt, &company.DataRegion,
// 	)

// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, fmt.Errorf("company not found: %s", companyID.String())
// 		}
// 		return nil, fmt.Errorf("failed to get company: %w", err)
// 	}

// 	company.CompanyID = uuid.UUID(scannedID)
// 	company.OwnerUserID = uuid.UUID(scannedOwnerID)
// 	if scannedBlockedBy != (gocql.UUID{}) {
// 		company.BlockedBy = uuid.UUID(scannedBlockedBy)
// 	}

// 	return &company, nil
// }

// // GetCompaniesByOwner - DIRECT MATERIALIZED VIEW QUERY
// func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, owner_phone, owner_user_id,
// 		       subscription_tier, is_active, created_at
// 		FROM companies_by_owner WHERE owner_user_id = ?`,
// 		gocql.UUID(ownerUserID),
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID       gocql.UUID
// 		companyName     string
// 		ownerPhone      string
// 		scannedOwnerID  gocql.UUID
// 		subscriptionTier string
// 		isActive        bool
// 		createdAt       time.Time
// 	)

// 	for iter.Scan(&companyID, &companyName, &ownerPhone, &scannedOwnerID, 
// 		&subscriptionTier, &isActive, &createdAt) {
		
// 		company := &models.Company{
// 			CompanyID:        uuid.UUID(companyID),
// 			CompanyName:      companyName,
// 			OwnerPhone:       ownerPhone,
// 			OwnerUserID:      uuid.UUID(scannedOwnerID),
// 			SubscriptionTier: subscriptionTier,
// 			IsActive:         isActive,
// 			CreatedAt:        createdAt,
// 		}
// 		companies = append(companies, company)
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies_by_owner: %w", err)
// 	}

// 	return companies, nil
// }

// // ============================================================
// // OPTIMIZED LIST COMPANIES WITH FIXED MATERIALIZED VIEWS
// // ============================================================

// func (r *CompanyRepositoryImpl) ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 25
// 	}
// 	if page <= 0 {
// 		page = 1
// 	}

// 	offset := (page - 1) * limit
// 	var companies []*models.Company
// 	var err error

// 	switch {
// 	// Use companies_by_tier for tier-only queries
// 	case filter.SubscriptionTier != "" && filter.NameContains == "" && filter.Status == "":
// 		companies, err = r.getCompaniesByTierDirect(ctx, filter.SubscriptionTier, limit, offset)
	
// 	// Use companies_by_active_status for status-only queries  
// 	case filter.Status != "" && filter.NameContains == "" && filter.SubscriptionTier == "":
// 		companies, err = r.getCompaniesByStatusDirect(ctx, filter.Status, limit, offset)
	
// 	// Use companies_by_tier_active for tier + active status
// 	case filter.SubscriptionTier != "" && filter.Status == "active" && filter.NameContains == "":
// 		companies, err = r.getCompaniesByTierAndActiveDirect(ctx, filter.SubscriptionTier, true, limit, offset)
	
// 	// Use companies_by_tier_blocked for tier + blocked status
// 	case filter.SubscriptionTier != "" && filter.Status == "blocked" && filter.NameContains == "":
// 		companies, err = r.getCompaniesByTierAndBlockedDirect(ctx, filter.SubscriptionTier, true, limit, offset)
	
// 	// Use companies_by_tier_name for tier + name search
// 	case filter.SubscriptionTier != "" && filter.NameContains != "":
// 		companies, err = r.getCompaniesByTierAndNameDirect(ctx, filter.SubscriptionTier, filter.NameContains, limit, offset)
	
// 	// Complex filters - fallback to optimized base query
// 	default:
// 		companies, err = r.listCompaniesComplexFilter(ctx, filter, limit, offset)
// 	}

// 	if err != nil {
// 		return nil, 0, fmt.Errorf("failed to list companies: %w", err)
// 	}

// 	total, err := r.getCompaniesCountOptimized(ctx, filter)
// 	if err != nil {
// 		r.logger.Warn("failed to get companies count", zap.Error(err))
// 		total = len(companies)
// 	}

// 	return companies, total, nil
// }

// // DIRECT QUERY: Get companies by tier using companies_by_tier
// func (r *CompanyRepositoryImpl) getCompaniesByTierDirect(ctx context.Context, tier string, limit, offset int) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// 		       subscription_start_date, subscription_end_date, created_at
// 		FROM companies_by_tier 
// 		WHERE subscription_tier = ? 
// 		LIMIT ?`,
// 		tier, limit,
// 	)

// 	return r.fetchCompaniesFromViewIter(ctx, query, offset)
// }

// // DIRECT QUERY: Get companies by status using companies_by_active_status
// func (r *CompanyRepositoryImpl) getCompaniesByStatusDirect(ctx context.Context, status string, limit, offset int) ([]*models.Company, error) {
// 	isActive := r.statusToIsActive(status)
	
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// 		       subscription_start_date, subscription_end_date, created_at
// 		FROM companies_by_active_status 
// 		WHERE is_active = ? 
// 		LIMIT ?`,
// 		isActive, limit,
// 	)

// 	return r.fetchCompaniesFromViewIter(ctx, query, offset)
// }

// // NEW: Get companies by tier and active status using companies_by_tier_active
// func (r *CompanyRepositoryImpl) getCompaniesByTierAndActiveDirect(ctx context.Context, tier string, isActive bool, limit, offset int) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, subscription_tier, is_active, company_name
// 		FROM companies_by_tier_active 
// 		WHERE subscription_tier = ? AND is_active = ? 
// 		LIMIT ?`,
// 		tier, isActive, limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID      gocql.UUID
// 		subscriptionTier string
// 		isActiveFlag   bool
// 		companyName    string
// 	)

// 	currentOffset := 0
// 	for iter.Scan(&companyID, &subscriptionTier, &isActiveFlag, &companyName) {
// 		if currentOffset < offset {
// 			currentOffset++
// 			continue
// 		}
		
// 		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// 		if err == nil && company != nil {
// 			companies = append(companies, company)
// 		}
		
// 		if len(companies) >= limit {
// 			break
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies_by_tier_active: %w", err)
// 	}

// 	return companies, nil
// }

// // NEW: Get companies by tier and blocked status using companies_by_tier_blocked
// func (r *CompanyRepositoryImpl) getCompaniesByTierAndBlockedDirect(ctx context.Context, tier string, isBlocked bool, limit, offset int) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, subscription_tier, is_blocked, company_name
// 		FROM companies_by_tier_blocked 
// 		WHERE subscription_tier = ? AND is_blocked = ? 
// 		LIMIT ?`,
// 		tier, isBlocked, limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID      gocql.UUID
// 		subscriptionTier string
// 		isBlockedFlag  bool
// 		companyName    string
// 	)

// 	currentOffset := 0
// 	for iter.Scan(&companyID, &subscriptionTier, &isBlockedFlag, &companyName) {
// 		if currentOffset < offset {
// 			currentOffset++
// 			continue
// 		}
		
// 		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// 		if err == nil && company != nil {
// 			companies = append(companies, company)
// 		}
		
// 		if len(companies) >= limit {
// 			break
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies_by_tier_blocked: %w", err)
// 	}

// 	return companies, nil
// }

// // Get companies by tier and name using companies_by_tier_name
// func (r *CompanyRepositoryImpl) getCompaniesByTierAndNameDirect(ctx context.Context, tier, nameContains string, limit, offset int) ([]*models.Company, error) {
// 	searchPattern := strings.ToLower(nameContains) + "%"
	
// 	query := r.client.Session.Query(`
// 		SELECT company_id, subscription_tier, company_name
// 		FROM companies_by_tier_name 
// 		WHERE subscription_tier = ? AND company_name >= ? 
// 		LIMIT ?`,
// 		tier, searchPattern, limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID      gocql.UUID
// 		subscriptionTier string
// 		companyName    string
// 	)

// 	currentOffset := 0
// 	for iter.Scan(&companyID, &subscriptionTier, &companyName) {
// 		if currentOffset < offset {
// 			currentOffset++
// 			continue
// 		}
		
// 		// Additional client-side filtering for contains (since we only have prefix)
// 		if strings.Contains(strings.ToLower(companyName), strings.ToLower(nameContains)) {
// 			company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// 			if err == nil && company != nil {
// 				companies = append(companies, company)
// 			}
// 		}
		
// 		if len(companies) >= limit {
// 			break
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies_by_tier_name: %w", err)
// 	}

// 	return companies, nil
// }

// // Helper function to fetch companies from view iterations
// func (r *CompanyRepositoryImpl) fetchCompaniesFromViewIter(ctx context.Context, query *gocql.Query, offset int) ([]*models.Company, error) {
// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID              gocql.UUID
// 		companyName            string
// 		subscriptionTier       string
// 		isActive               bool
// 		isBlocked              bool
// 		subscriptionStartDate  time.Time
// 		subscriptionEndDate    time.Time
// 		createdAt              time.Time
// 	)

// 	currentOffset := 0
// 	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActive, &isBlocked,
// 		&subscriptionStartDate, &subscriptionEndDate, &createdAt) {
		
// 		if currentOffset < offset {
// 			currentOffset++
// 			continue
// 		}
		
// 		company := &models.Company{
// 			CompanyID:             uuid.UUID(companyID),
// 			CompanyName:           companyName,
// 			SubscriptionTier:      subscriptionTier,
// 			IsActive:              isActive,
// 			IsBlocked:             isBlocked,
// 			SubscriptionStartDate: subscriptionStartDate,
// 			SubscriptionEndDate:   subscriptionEndDate,
// 			CreatedAt:             createdAt,
// 		}
// 		companies = append(companies, company)
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate materialized view: %w", err)
// 	}

// 	return companies, nil
// }

// // Fallback for complex filters
// func (r *CompanyRepositoryImpl) listCompaniesComplexFilter(ctx context.Context, filter models.CompanyFilter, limit, offset int) ([]*models.Company, error) {
// 	// Use base companies table with minimal filtering
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, owner_phone, owner_user_id,
// 		       subscription_tier, subscription_start_date, subscription_end_date,
// 		       monthly_premium, max_employees, is_active, is_blocked,
// 		       created_at, updated_at, data_region
// 		FROM companies 
// 		LIMIT ?`,
// 		limit + offset, // Fetch extra to handle offset
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		scannedID        gocql.UUID
// 		companyName      string
// 		ownerPhone       string
// 		scannedOwnerID   gocql.UUID
// 		subscriptionTier string
// 		startDate        time.Time
// 		endDate          time.Time
// 		monthlyPremium   float64
// 		maxEmployees     int
// 		isActive         bool
// 		isBlocked        bool
// 		createdAt        time.Time
// 		updatedAt        time.Time
// 		dataRegion       string
// 	)

// 	currentOffset := 0
// 	for iter.Scan(&scannedID, &companyName, &ownerPhone, &scannedOwnerID,
// 		&subscriptionTier, &startDate, &endDate, &monthlyPremium, &maxEmployees,
// 		&isActive, &isBlocked, &createdAt, &updatedAt, &dataRegion) {
		
// 		// Apply offset
// 		if currentOffset < offset {
// 			currentOffset++
// 			continue
// 		}
		
// 		// Apply filters
// 		if filter.SubscriptionTier != "" && filter.SubscriptionTier != subscriptionTier {
// 			continue
// 		}
// 		if filter.Status != "" && !r.matchesStatus(filter.Status, isActive, isBlocked) {
// 			continue
// 		}
// 		if filter.NameContains != "" && !strings.Contains(strings.ToLower(companyName), strings.ToLower(filter.NameContains)) {
// 			continue
// 		}
		
// 		company := &models.Company{
// 			CompanyID:            uuid.UUID(scannedID),
// 			CompanyName:          companyName,
// 			OwnerPhone:           ownerPhone,
// 			OwnerUserID:          uuid.UUID(scannedOwnerID),
// 			SubscriptionTier:     subscriptionTier,
// 			SubscriptionStartDate: startDate,
// 			SubscriptionEndDate:  endDate,
// 			MonthlyPremium:       monthlyPremium,
// 			MaxEmployees:         maxEmployees,
// 			IsActive:             isActive,
// 			IsBlocked:            isBlocked,
// 			CreatedAt:            createdAt,
// 			UpdatedAt:            updatedAt,
// 			DataRegion:           dataRegion,
// 		}
// 		companies = append(companies, company)
		
// 		if len(companies) >= limit {
// 			break
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate companies: %w", err)
// 	}

// 	return companies, nil
// }

// // Optimized count using materialized views when possible
// func (r *CompanyRepositoryImpl) getCompaniesCountOptimized(ctx context.Context, filter models.CompanyFilter) (int, error) {
// 	var count int64
// 	var err error

// 	switch {
// 	case filter.SubscriptionTier != "" && filter.Status == "" && filter.NameContains == "":
// 		// Use companies_by_tier for counting
// 		query := r.client.Session.Query(`
// 			SELECT COUNT(*) FROM companies_by_tier WHERE subscription_tier = ?`,
// 			filter.SubscriptionTier,
// 		)
// 		err = query.WithContext(ctx).Scan(&count)
	
// 	case filter.Status != "" && filter.SubscriptionTier == "" && filter.NameContains == "":
// 		// Use companies_by_active_status for counting
// 		isActive := r.statusToIsActive(filter.Status)
// 		query := r.client.Session.Query(`
// 			SELECT COUNT(*) FROM companies_by_active_status WHERE is_active = ?`,
// 			isActive,
// 		)
// 		err = query.WithContext(ctx).Scan(&count)
	
// 	default:
// 		// Fallback to base table count
// 		query := r.client.Session.Query("SELECT COUNT(*) FROM companies")
// 		err = query.WithContext(ctx).Scan(&count)
// 	}

// 	if err != nil {
// 		return 0, fmt.Errorf("failed to count companies: %w", err)
// 	}
	
// 	return int(count), nil
// }

// // ============================================================
// // NEW DIRECT MATERIALIZED VIEW QUERIES
// // ============================================================

// func (r *CompanyRepositoryImpl) GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error) {
// 	return r.getCompaniesByTierDirect(ctx, tier, limit, 0)
// }

// func (r *CompanyRepositoryImpl) GetCompaniesByTierAndActive(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error) {
// 	return r.getCompaniesByTierAndActiveDirect(ctx, tier, isActive, limit, 0)
// }

// func (r *CompanyRepositoryImpl) GetCompaniesByTierAndBlocked(ctx context.Context, tier string, isBlocked bool, limit int) ([]*models.Company, error) {
// 	return r.getCompaniesByTierAndBlockedDirect(ctx, tier, isBlocked, limit, 0)
// }

// func (r *CompanyRepositoryImpl) GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// 		       subscription_start_date, subscription_end_date, created_at
// 		FROM companies_by_subscription_date 
// 		WHERE subscription_end_date >= ? AND subscription_end_date <= ?
// 		LIMIT ?`,
// 		startDate, endDate, limit,
// 	)

// 	return r.fetchCompaniesFromViewIter(ctx, query, 0)
// }

// // ============================================================
// // OPTIMIZED EMPLOYEE QUERIES WITH MATERIALIZED VIEWS
// // ============================================================

// // GetCompanyEmployeeByUser - DIRECT MATERIALIZED VIEW QUERY
// func (r *CompanyRepositoryImpl) GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, user_id, employee_id, role_id, department_id, is_active
// 		FROM employees_by_user 
// 		WHERE user_id = ?`,
// 		gocql.UUID(userID),
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var employees []*models.CompanyEmployee
// 	var (
// 		scCompanyID gocql.UUID
// 		scUserID    gocql.UUID
// 		employeeID  string
// 		scRoleID    gocql.UUID
// 		scDeptID    gocql.UUID
// 		isActive    bool
// 	)

// 	for iter.Scan(&scCompanyID, &scUserID, &employeeID, &scRoleID, &scDeptID, &isActive) {
// 		emp := &models.CompanyEmployee{
// 			CompanyID:    uuid.UUID(scCompanyID),
// 			UserID:       uuid.UUID(scUserID),
// 			EmployeeID:   employeeID,
// 			RoleID:       uuid.UUID(scRoleID),
// 			DepartmentID: uuid.UUID(scDeptID),
// 			IsActive:     isActive,
// 		}
// 		employees = append(employees, emp)
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate employees_by_user: %w", err)
// 	}

// 	return employees, nil
// }

// // ============================================================
// // HELPER FUNCTIONS
// // ============================================================

// func (r *CompanyRepositoryImpl) statusToIsActive(status string) bool {
// 	switch status {
// 	case models.SubscriptionStatusActive:
// 		return true
// 	case models.SubscriptionStatusCompanyInactive:
// 		return false
// 	case models.SubscriptionStatusCompanyBlocked:
// 		return true // blocked companies are technically active but blocked
// 	default:
// 		return true
// 	}
// }

// func (r *CompanyRepositoryImpl) matchesStatus(status string, isActive, isBlocked bool) bool {
// 	switch status {
// 	case models.SubscriptionStatusActive:
// 		return isActive && !isBlocked
// 	case models.SubscriptionStatusCompanyBlocked:
// 		return isBlocked
// 	case models.SubscriptionStatusCompanyInactive:
// 		return !isActive && !isBlocked
// 	default:
// 		return true
// 	}
// }

// func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
// 	filter := models.CompanyFilter{Status: status}
// 	companies, _, err := r.ListCompanies(ctx, filter, 1, limit)
// 	return companies, err
// }

// func (r *CompanyRepositoryImpl) ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error) {
// 	// Implementation for cursor-based pagination
// 	query := r.client.Session.Query(`
// 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// 		       subscription_start_date, subscription_end_date, created_at
// 		FROM companies 
// 		LIMIT ?`,
// 		pageSize,
// 	).PageState(pageState)

// 	iter := query.WithContext(ctx).Iter()
// 	defer iter.Close()

// 	var companies []*models.Company
// 	var (
// 		companyID              gocql.UUID
// 		companyName            string
// 		subscriptionTier       string
// 		isActive               bool
// 		isBlocked              bool
// 		subscriptionStartDate  time.Time
// 		subscriptionEndDate    time.Time
// 		createdAt              time.Time
// 	)

// 	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActive, &isBlocked,
// 		&subscriptionStartDate, &subscriptionEndDate, &createdAt) {
		
// 		company := &models.Company{
// 			CompanyID:             uuid.UUID(companyID),
// 			CompanyName:           companyName,
// 			SubscriptionTier:      subscriptionTier,
// 			IsActive:              isActive,
// 			IsBlocked:             isBlocked,
// 			SubscriptionStartDate: subscriptionStartDate,
// 			SubscriptionEndDate:   subscriptionEndDate,
// 			CreatedAt:             createdAt,
// 		}
// 		companies = append(companies, company)
// 	}

// 	nextPageState := iter.PageState()
// 	if err := iter.Close(); err != nil {
// 		return nil, nil, fmt.Errorf("failed to iterate companies with paging: %w", err)
// 	}

// 	return companies, nextPageState, nil
// }

// func (r *CompanyRepositoryImpl) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error {
// 	query := r.client.Session.Query(`
// 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// 		true, reason, gocql.UUID(blockedBy), blockedAt, time.Now().UTC(), gocql.UUID(companyID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) UnblockCompany(ctx context.Context, companyID uuid.UUID) error {
// 	now := time.Now().UTC()
// 	query := r.client.Session.Query(`
// 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// 		false, nil, nil, nil, now, gocql.UUID(companyID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error {
// 	query := r.client.Session.Query(`
// 		UPDATE companies SET subscription_tier = ?, monthly_premium = ?, max_employees = ?, updated_at = ? 
// 		WHERE company_id = ?`,
// 		tier, premium, maxEmployees, updatedAt, gocql.UUID(companyID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error {
// 	query := r.client.Session.Query(`
// 		UPDATE companies SET subscription_end_date = ?, updated_at = ? WHERE company_id = ?`,
// 		endDate, time.Now().UTC(), gocql.UUID(companyID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error {
// 	query := r.client.Session.Query(`
// 		UPDATE companies SET is_active = ?, updated_at = ? WHERE company_id = ?`,
// 		isActive, time.Now().UTC(), gocql.UUID(companyID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// 	query := r.client.Session.Query(`
// 		INSERT INTO company_departments (
// 			company_id, department_id, department_name, department_head, 
// 			permissions, is_active, created_at, updated_at
// 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(department.CompanyID),
// 		gocql.UUID(department.DepartmentID),
// 		department.DepartmentName,
// 		gocql.UUID(department.DepartmentHead),
// 		department.Permissions,
// 		department.IsActive,
// 		department.CreatedAt,
// 		department.UpdatedAt,
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, department_id, department_name, department_head, 
// 		       permissions, is_active, created_at, updated_at
// 		FROM company_departments WHERE company_id = ? AND department_id = ?`,
// 		gocql.UUID(companyID), gocql.UUID(departmentID),
// 	)

// 	var (
// 		scCompanyID    gocql.UUID
// 		scDepartmentID gocql.UUID
// 		scDeptHead     gocql.UUID
// 		department     models.CompanyDepartment
// 	)

// 	err := query.WithContext(ctx).Scan(
// 		&scCompanyID, &scDepartmentID, &department.DepartmentName, &scDeptHead,
// 		&department.Permissions, &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
// 	)

// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, fmt.Errorf("department not found")
// 		}
// 		return nil, fmt.Errorf("failed to get department: %w", err)
// 	}

// 	department.CompanyID = uuid.UUID(scCompanyID)
// 	department.DepartmentID = uuid.UUID(scDepartmentID)
// 	department.DepartmentHead = uuid.UUID(scDeptHead)
// 	return &department, nil
// }

// func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// 	query := r.client.Session.Query(`
// 		UPDATE company_departments SET 
// 			department_name = ?, department_head = ?, permissions = ?, 
// 			is_active = ?, updated_at = ?
// 		WHERE company_id = ? AND department_id = ?`,
// 		department.DepartmentName,
// 		gocql.UUID(department.DepartmentHead),
// 		department.Permissions,
// 		department.IsActive,
// 		department.UpdatedAt,
// 		gocql.UUID(department.CompanyID),
// 		gocql.UUID(department.DepartmentID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT department_id FROM company_departments 
// 		WHERE company_id = ? AND is_active = true LIMIT ?`,
// 		gocql.UUID(companyID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var deptID gocql.UUID
// 	var departments []*models.CompanyDepartment

// 	for iter.Scan(&deptID) {
// 		dept, err := r.GetDepartment(ctx, companyID, uuid.UUID(deptID))
// 		if err == nil && dept != nil {
// 			departments = append(departments, dept)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate departments: %w", err)
// 	}

// 	return departments, nil
// }

// func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error {
// 	query := r.client.Session.Query(`
// 		UPDATE company_departments SET is_active = false, updated_at = ?
// 		WHERE company_id = ? AND department_id = ?`,
// 		time.Now().UTC(), gocql.UUID(companyID), gocql.UUID(departmentID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// 	query := r.client.Session.Query(`
// 		INSERT INTO company_employees (
// 			company_id, user_id, employee_id, role_id, department_id,
// 			hire_date, is_active, reports_to, created_at, updated_at
// 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(employee.CompanyID),
// 		gocql.UUID(employee.UserID),
// 		employee.EmployeeID,
// 		gocql.UUID(employee.RoleID),
// 		gocql.UUID(employee.DepartmentID),
// 		employee.HireDate,
// 		employee.IsActive,
// 		gocql.UUID(employee.ReportsTo),
// 		employee.CreatedAt,
// 		employee.UpdatedAt,
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, user_id, employee_id, role_id, department_id, hire_date, is_active, reports_to, created_at, updated_at
// 		FROM company_employees WHERE company_id = ? AND user_id = ?`,
// 		gocql.UUID(companyID), gocql.UUID(userID),
// 	)
// 	var (
// 		scCompanyID gocql.UUID
// 		scUserID    gocql.UUID
// 		emp         models.CompanyEmployee
// 		scRoleID    gocql.UUID
// 		scDeptID    gocql.UUID
// 		scReportsTo gocql.UUID
// 	)
// 	err := query.WithContext(ctx).Scan(
// 		&scCompanyID, &scUserID, &emp.EmployeeID, &scRoleID, &scDeptID, &emp.HireDate, &emp.IsActive, &scReportsTo, &emp.CreatedAt, &emp.UpdatedAt,
// 	)
// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, nil
// 		}
// 		return nil, fmt.Errorf("failed to get company employee: %w", err)
// 	}

// 	emp.CompanyID = uuid.UUID(scCompanyID)
// 	emp.UserID = uuid.UUID(scUserID)
// 	emp.RoleID = uuid.UUID(scRoleID)
// 	emp.DepartmentID = uuid.UUID(scDeptID)
// 	if scReportsTo != (gocql.UUID{}) {
// 		emp.ReportsTo = uuid.UUID(scReportsTo)
// 	}
// 	return &emp, nil
// }

// func (r *CompanyRepositoryImpl) UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// 	query := r.client.Session.Query(`
// 		UPDATE company_employees SET 
// 			employee_id = ?, role_id = ?, department_id = ?, 
// 			reports_to = ?, is_active = ?, updated_at = ?
// 		WHERE company_id = ? AND user_id = ?`,
// 		employee.EmployeeID,
// 		gocql.UUID(employee.RoleID),
// 		gocql.UUID(employee.DepartmentID),
// 		gocql.UUID(employee.ReportsTo),
// 		employee.IsActive,
// 		employee.UpdatedAt,
// 		gocql.UUID(employee.CompanyID),
// 		gocql.UUID(employee.UserID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT user_id FROM company_employees WHERE company_id = ? LIMIT ?`,
// 		gocql.UUID(companyID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var uid gocql.UUID
// 	var employees []*models.CompanyEmployee

// 	for iter.Scan(&uid) {
// 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// 		if err == nil && e != nil {
// 			employees = append(employees, e)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, 0, fmt.Errorf("failed to list employees: %w", err)
// 	}

// 	return employees, len(employees), nil
// }

// func (r *CompanyRepositoryImpl) ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT user_id FROM company_employees 
// 		WHERE company_id = ? AND department_id = ? AND is_active = true LIMIT ?`,
// 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var uid gocql.UUID
// 	var employees []*models.CompanyEmployee

// 	for iter.Scan(&uid) {
// 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// 		if err == nil && e != nil && e.IsActive {
// 			employees = append(employees, e)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to list employees by department: %w", err)
// 	}

// 	return employees, nil
// }

// func (r *CompanyRepositoryImpl) ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT user_id FROM company_employees 
// 		WHERE company_id = ? AND role_id = ? AND is_active = true LIMIT ?`,
// 		gocql.UUID(companyID), gocql.UUID(roleID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var uid gocql.UUID
// 	var employees []*models.CompanyEmployee

// 	for iter.Scan(&uid) {
// 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// 		if err == nil && e != nil && e.IsActive {
// 			employees = append(employees, e)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to list employees by role: %w", err)
// 	}

// 	return employees, nil
// }

// func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// 	query := r.client.Session.Query(`SELECT COUNT(*) FROM company_employees WHERE company_id = ?`, gocql.UUID(companyID))
// 	var cnt int64
// 	if err := query.WithContext(ctx).Scan(&cnt); err != nil {
// 		return 0, fmt.Errorf("failed to count employees: %w", err)
// 	}
// 	return int(cnt), nil
// }

// func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// 	query := r.client.Session.Query(`
// 		UPDATE company_employees SET is_active = false, updated_at = ?
// 		WHERE company_id = ? AND user_id = ?`,
// 		time.Now().UTC(),
// 		gocql.UUID(companyID),
// 		gocql.UUID(userID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// 	query := r.client.Session.Query(`
// 		UPDATE company_employees SET is_active = true, updated_at = ?
// 		WHERE company_id = ? AND user_id = ?`,
// 		time.Now().UTC(),
// 		gocql.UUID(companyID),
// 		gocql.UUID(userID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// 	query := r.client.Session.Query(`
// 		SELECT COUNT(*) FROM company_employees 
// 		WHERE company_id = ? AND is_active = true`,
// 		gocql.UUID(companyID),
// 	)
// 	var count int64
// 	if err := query.WithContext(ctx).Scan(&count); err != nil {
// 		return 0, fmt.Errorf("failed to count active employees: %w", err)
// 	}
// 	return int(count), nil
// }

// func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT user_id FROM company_employees 
// 		WHERE company_id = ? AND is_active = true 
// 		LIMIT ?`,
// 		gocql.UUID(companyID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var uid gocql.UUID
// 	var employeeIDs []uuid.UUID

// 	for iter.Scan(&uid) {
// 		employeeIDs = append(employeeIDs, uuid.UUID(uid))
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, 0, fmt.Errorf("failed to list active employees: %w", err)
// 	}

// 	// Get employee details
// 	var employees []*models.CompanyEmployee
// 	for _, userID := range employeeIDs {
// 		emp, err := r.GetCompanyEmployee(ctx, companyID, userID)
// 		if err == nil && emp != nil && emp.IsActive {
// 			employees = append(employees, emp)
// 		}
// 	}

// 	return employees, len(employees), nil
// }

// func (r *CompanyRepositoryImpl) CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// 	query := r.client.Session.Query(`
// 		INSERT INTO employee_roles (
// 			company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(role.CompanyID),
// 		gocql.UUID(role.RoleID),
// 		role.RoleName,
// 		role.RoleLevel,
// 		role.Permissions,
// 		gocql.UUID(role.DepartmentID),
// 		role.IsSystemRole,
// 		role.CreatedAt,
// 		role.UpdatedAt,
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error) {
// 	query := r.client.Session.Query(`
// 		SELECT company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// 		FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// 		gocql.UUID(companyID), gocql.UUID(roleID),
// 	)
// 	var (
// 		scCompanyID gocql.UUID
// 		scRoleID    gocql.UUID
// 		role        models.EmployeeRole
// 		scDeptID    gocql.UUID
// 	)
// 	err := query.WithContext(ctx).Scan(&scCompanyID, &scRoleID, &role.RoleName, &role.RoleLevel, &role.Permissions, &scDeptID, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt)
// 	if err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, fmt.Errorf("role not found")
// 		}
// 		return nil, fmt.Errorf("failed to get employee role: %w", err)
// 	}
// 	role.CompanyID = uuid.UUID(scCompanyID)
// 	role.RoleID = uuid.UUID(scRoleID)
// 	role.DepartmentID = uuid.UUID(scDeptID)
// 	return &role, nil
// }

// func (r *CompanyRepositoryImpl) GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error) {
// 	query := r.client.Session.Query(`
// 		SELECT role_id FROM employee_roles 
// 		WHERE company_id = ? AND role_level = ? LIMIT 1`,
// 		gocql.UUID(companyID), roleLevel,
// 	)

// 	var roleID gocql.UUID
// 	if err := query.WithContext(ctx).Scan(&roleID); err != nil {
// 		if err == gocql.ErrNotFound {
// 			return nil, fmt.Errorf("role level not found: %s", roleLevel)
// 		}
// 		return nil, fmt.Errorf("failed to get role by level: %w", err)
// 	}

// 	return r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// }

// func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// 	query := r.client.Session.Query(`
// 		UPDATE employee_roles SET 
// 			role_name = ?, role_level = ?, permissions = ?, department_id = ?,
// 			is_system_role = ?, updated_at = ?
// 		WHERE company_id = ? AND role_id = ?`,
// 		role.RoleName,
// 		role.RoleLevel,
// 		role.Permissions,
// 		gocql.UUID(role.DepartmentID),
// 		role.IsSystemRole,
// 		role.UpdatedAt,
// 		gocql.UUID(role.CompanyID),
// 		gocql.UUID(role.RoleID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT role_id FROM employee_roles WHERE company_id = ? LIMIT ?`,
// 		gocql.UUID(companyID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var roleID gocql.UUID
// 	var roles []*models.EmployeeRole

// 	for iter.Scan(&roleID) {
// 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// 		if err == nil && role != nil {
// 			roles = append(roles, role)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to list employee roles: %w", err)
// 	}

// 	return roles, nil
// }

// func (r *CompanyRepositoryImpl) ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	query := r.client.Session.Query(`
// 		SELECT role_id FROM employee_roles 
// 		WHERE company_id = ? AND department_id = ? LIMIT ?`,
// 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var roleID gocql.UUID
// 	var roles []*models.EmployeeRole

// 	for iter.Scan(&roleID) {
// 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// 		if err == nil && role != nil {
// 			roles = append(roles, role)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to list employee roles by department: %w", err)
// 	}

// 	return roles, nil
// }

// func (r *CompanyRepositoryImpl) DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error {
// 	query := r.client.Session.Query(`
// 		DELETE FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// 		gocql.UUID(companyID), gocql.UUID(roleID),
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// // ============================================================
// // Permission Operations (ENHANCED)
// // ============================================================

// func (r *CompanyRepositoryImpl) GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error) {
// 	query := r.client.Session.Query(`
// 		SELECT permission FROM employee_permissions WHERE company_id = ? AND user_id = ?`,
// 		gocql.UUID(companyID), gocql.UUID(userID),
// 	)
// 	iter := query.WithContext(ctx).Iter()
// 	var perm string
// 	perms := make([]string, 0)
// 	for iter.Scan(&perm) {
// 		perms = append(perms, perm)
// 	}
// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to iterate permissions: %w", err)
// 	}
// 	return perms, nil
// }

// func (r *CompanyRepositoryImpl) GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error {
// 	query := r.client.Session.Query(`
// 		INSERT INTO employee_permissions (
// 			company_id, user_id, permission, granted_by, granted_at, expires_at
// 		) VALUES (?, ?, ?, ?, ?, ?)`,
// 		gocql.UUID(permission.CompanyID),
// 		gocql.UUID(permission.UserID),
// 		permission.Permission,
// 		gocql.UUID(permission.GrantedBy),
// 		permission.GrantedAt,
// 		permission.ExpiresAt,
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error {
// 	query := r.client.Session.Query(`
// 		DELETE FROM employee_permissions 
// 		WHERE company_id = ? AND user_id = ? AND permission = ?`,
// 		gocql.UUID(companyID), gocql.UUID(userID), permission,
// 	)
// 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// }

// func (r *CompanyRepositoryImpl) GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error) {
// 	if limit <= 0 || limit > 1000 {
// 		limit = 100
// 	}

// 	// First get user IDs with the permission
// 	query := r.client.Session.Query(`
// 		SELECT user_id FROM employee_permissions 
// 		WHERE company_id = ? AND permission = ? LIMIT ?`,
// 		gocql.UUID(companyID), permission, limit,
// 	)

// 	iter := query.WithContext(ctx).Iter()
// 	var uid gocql.UUID
// 	var employees []*models.CompanyEmployee

// 	for iter.Scan(&uid) {
// 		emp, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// 		if err == nil && emp != nil && emp.IsActive {
// 			employees = append(employees, emp)
// 		}
// 	}

// 	if err := iter.Close(); err != nil {
// 		return nil, fmt.Errorf("failed to get employees with permission: %w", err)
// 	}

// 	return employees, nil
// }

// // ============================================================
// // Health Check
// // ============================================================

// func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
// 	var release string
// 	q := r.client.Session.Query(`SELECT release_version FROM system.local`)
// 	if err := q.WithContext(ctx).Scan(&release); err != nil {
// 		return fmt.Errorf("scylla health check failed: %w", err)
// 	}
// 	r.logger.Debug("scylla release_version", zap.String("version", release))
// 	return nil
// }
// // package scylla

// // import (
// // 	"context"
// // 	"fmt"
// // 	"strings"
// // 	"time"

// // 	"auth-service/internal/models"
// // 	"github.com/gocql/gocql"
// // 	"github.com/google/uuid"
// // 	"go.uber.org/zap"
// // )

// // // ============================================================
// // // CompanyRepository Interface (ENHANCED WITH MATERIALIZED VIEWS)
// // // ============================================================

// // type CompanyRepository interface {
// // 	// ============================================================
// // 	// Company operations (OPTIMIZED WITH MATERIALIZED VIEWS)
// // 	// ============================================================
// // 	CreateCompany(ctx context.Context, company *models.Company) error
// // 	GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error)
// // 	GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error)
// // 	ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error)
// // 	ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error)
// // 	BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error
// // 	UnblockCompany(ctx context.Context, companyID uuid.UUID) error
// // 	UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error
// // 	UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error
// // 	UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error
// // 	GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error)
	
// // 	// NEW: Direct materialized view queries
// // 	GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error)
// // 	GetCompaniesByTierAndStatus(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error)
// // 	GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error)

// // 	// ============================================================
// // 	// Department operations
// // 	// ============================================================
// // 	CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// // 	GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error)
// // 	UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// // 	ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error)
// // 	DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error

// // 	// ============================================================
// // 	// Employee operations (OPTIMIZED WITH MATERIALIZED VIEWS)
// // 	// ============================================================
// // 	CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// // 	GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
// // 	GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) // NEW: Using employees_by_user view
// // 	UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// // 	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// // 	ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)
// // 	ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)
// // 	ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)

// // 	// Employee Activation/Status Functions
// // 	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// // 	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// // 	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// // 	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)

// // 	// ============================================================
// // 	// Role operations
// // 	// ============================================================
// // 	CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// // 	GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error)
// // 	GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error)
// // 	UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// // 	ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// // 	ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// // 	DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error

// // 	// ============================================================
// // 	// Permission operations
// // 	// ============================================================
// // 	GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error)
// // 	GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error
// // 	RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error
// // 	GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error)

// // 	// ============================================================
// // 	// Utility
// // 	// ============================================================
// // 	HealthCheck(ctx context.Context) error
// // }

// // // ============================================================
// // // Implementation
// // // ============================================================

// // type CompanyRepositoryImpl struct {
// // 	client *ScyllaClient
// // 	logger *zap.Logger
// // }

// // func NewCompanyRepository(client *ScyllaClient, logger *zap.Logger) CompanyRepository {
// // 	return &CompanyRepositoryImpl{
// // 		client: client,
// // 		logger: logger,
// // 	}
// // }

// // // ============================================================
// // // Company CRUD (OPTIMIZED WITH MATERIALIZED VIEWS)
// // // ============================================================

// // func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company) error {
// // 	query := r.client.Session.Query(`
// // 		INSERT INTO companies (
// // 			company_id, company_name, owner_phone, owner_user_id, 
// // 			subscription_tier, subscription_start_date, subscription_end_date,
// // 			monthly_premium, max_employees, is_active, is_blocked,
// // 			created_at, updated_at, data_region
// // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // 		gocql.UUID(company.CompanyID),
// // 		company.CompanyName,
// // 		company.OwnerPhone,
// // 		gocql.UUID(company.OwnerUserID),
// // 		company.SubscriptionTier,
// // 		company.SubscriptionStartDate,
// // 		company.SubscriptionEndDate,
// // 		company.MonthlyPremium,
// // 		company.MaxEmployees,
// // 		company.IsActive,
// // 		company.IsBlocked,
// // 		company.CreatedAt,
// // 		company.UpdatedAt,
// // 		company.DataRegion,
// // 	)

// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, owner_phone, owner_user_id,
// // 		       subscription_tier, subscription_start_date, subscription_end_date,
// // 		       monthly_premium, max_employees, is_active, is_blocked,
// // 		       blocked_reason, blocked_by, blocked_at,
// // 		       created_at, updated_at, data_region
// // 		FROM companies WHERE company_id = ?`,
// // 		gocql.UUID(companyID),
// // 	)

// // 	var (
// // 		scannedID        gocql.UUID
// // 		scannedOwnerID   gocql.UUID
// // 		scannedBlockedBy gocql.UUID
// // 		company          models.Company
// // 	)

// // 	err := query.WithContext(ctx).Scan(
// // 		&scannedID, &company.CompanyName, &company.OwnerPhone, &scannedOwnerID,
// // 		&company.SubscriptionTier, &company.SubscriptionStartDate, &company.SubscriptionEndDate,
// // 		&company.MonthlyPremium, &company.MaxEmployees, &company.IsActive, &company.IsBlocked,
// // 		&company.BlockedReason, &scannedBlockedBy, &company.BlockedAt,
// // 		&company.CreatedAt, &company.UpdatedAt, &company.DataRegion,
// // 	)

// // 	if err != nil {
// // 		if err == gocql.ErrNotFound {
// // 			return nil, fmt.Errorf("company not found: %s", companyID.String())
// // 		}
// // 		return nil, fmt.Errorf("failed to get company: %w", err)
// // 	}

// // 	company.CompanyID = uuid.UUID(scannedID)
// // 	company.OwnerUserID = uuid.UUID(scannedOwnerID)
// // 	if scannedBlockedBy != (gocql.UUID{}) {
// // 		company.BlockedBy = uuid.UUID(scannedBlockedBy)
// // 	}

// // 	return &company, nil
// // }

// // // GetCompaniesByOwner - DIRECT MATERIALIZED VIEW QUERY (NO FILTERING NEEDED)
// // func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, owner_phone, owner_user_id,
// // 		       subscription_tier, is_active, created_at
// // 		FROM companies_by_owner WHERE owner_user_id = ?`,
// // 		gocql.UUID(ownerUserID),
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		companyID      gocql.UUID
// // 		companyName    string
// // 		ownerPhone     string
// // 		scannedOwnerID gocql.UUID
// // 		subscriptionTier string
// // 		isActive       bool
// // 		createdAt      time.Time
// // 	)

// // 	for iter.Scan(&companyID, &companyName, &ownerPhone, &scannedOwnerID, 
// // 		&subscriptionTier, &isActive, &createdAt) {
		
// // 		company := &models.Company{
// // 			CompanyID:       uuid.UUID(companyID),
// // 			CompanyName:     companyName,
// // 			OwnerPhone:      ownerPhone,
// // 			OwnerUserID:     uuid.UUID(scannedOwnerID),
// // 			SubscriptionTier: subscriptionTier,
// // 			IsActive:        isActive,
// // 			CreatedAt:       createdAt,
// // 		}
// // 		companies = append(companies, company)
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate companies_by_owner: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // // ============================================================
// // // OPTIMIZED LIST COMPANIES WITH DIRECT MATERIALIZED VIEW QUERIES
// // // ============================================================

// // func (r *CompanyRepositoryImpl) ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error) {
// // 	// Validate and normalize limit
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 25
// // 	}
// // 	if page <= 0 {
// // 		page = 1
// // 	}

// // 	// Calculate offset for pagination
// // 	offset := (page - 1) * limit

// // 	// Choose the optimal materialized view based on filters
// // 	var companies []*models.Company
// // 	var err error

// // 	switch {
// // 	// Case 1: Only tier filter - use companies_by_tier
// // 	case filter.SubscriptionTier != "" && filter.NameContains == "" && filter.Status == "":
// // 		companies, err = r.getCompaniesByTierDirect(ctx, filter.SubscriptionTier, limit, offset)
	
// // 	// Case 2: Only status filter - use companies_by_active_status  
// // 	case filter.Status != "" && filter.NameContains == "" && filter.SubscriptionTier == "":
// // 		companies, err = r.getCompaniesByStatusDirect(ctx, filter.Status, limit, offset)
	
// // 	// Case 3: Tier and status - use companies_by_tier_active or companies_by_tier_blocked
// // 	case filter.SubscriptionTier != "" && filter.Status != "" && filter.NameContains == "":
// // 		companies, err = r.getCompaniesByTierAndStatusDirect(ctx, filter.SubscriptionTier, filter.Status, limit, offset)
	
// // 	// Case 4: Name search with tier - use companies_by_tier_name
// // 	case filter.NameContains != "" && filter.SubscriptionTier != "":
// // 		companies, err = r.getCompaniesByTierAndNameDirect(ctx, filter.SubscriptionTier, filter.NameContains, limit, offset)
	
// // 	// Case 5: Complex filters - fallback to optimized base query
// // 	default:
// // 		companies, err = r.listCompaniesComplexFilter(ctx, filter, limit, offset)
// // 	}

// // 	if err != nil {
// // 		return nil, 0, fmt.Errorf("failed to list companies: %w", err)
// // 	}

// // 	// Get total count using appropriate materialized view
// // 	total, err := r.getCompaniesCountOptimized(ctx, filter)
// // 	if err != nil {
// // 		r.logger.Warn("failed to get companies count", zap.Error(err))
// // 		total = len(companies)
// // 	}

// // 	return companies, total, nil
// // }

// // // DIRECT MATERIALIZED VIEW QUERY: Get companies by tier
// // func (r *CompanyRepositoryImpl) getCompaniesByTierDirect(ctx context.Context, tier string, limit, offset int) ([]*models.Company, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// // 		       subscription_start_date, subscription_end_date, created_at
// // 		FROM companies_by_tier 
// // 		WHERE subscription_tier = ? 
// // 		LIMIT ?`,
// // 		tier, limit,
// // 	)

// // 	return r.fetchCompaniesFromViewIter(ctx, query, offset)
// // }

// // // DIRECT MATERIALIZED VIEW QUERY: Get companies by status
// // func (r *CompanyRepositoryImpl) getCompaniesByStatusDirect(ctx context.Context, status string, limit, offset int) ([]*models.Company, error) {
// // 	isActive := r.statusToIsActive(status)
	
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// // 		       subscription_start_date, subscription_end_date, created_at
// // 		FROM companies_by_active_status 
// // 		WHERE is_active = ? 
// // 		LIMIT ?`,
// // 		isActive, limit,
// // 	)

// // 	return r.fetchCompaniesFromViewIter(ctx, query, offset)
// // }

// // // DIRECT MATERIALIZED VIEW QUERY: Get companies by tier and status
// // func (r *CompanyRepositoryImpl) getCompaniesByTierAndStatusDirect(ctx context.Context, tier, status string, limit, offset int) ([]*models.Company, error) {
// // 	isActive := r.statusToIsActive(status)
	
// // 	// Use the appropriate composite view
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier, is_active
// // 		FROM companies_by_tier_active 
// // 		WHERE subscription_tier = ? AND is_active = ? 
// // 		LIMIT ?`,
// // 		tier, isActive, limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		companyID      gocql.UUID
// // 		companyName    string
// // 		subscriptionTier string
// // 		isActiveFlag   bool
// // 	)

// // 	// Apply offset manually
// // 	currentOffset := 0
// // 	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActiveFlag) {
// // 		if currentOffset < offset {
// // 			currentOffset++
// // 			continue
// // 		}
		
// // 		// Get full company details
// // 		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // 		if err == nil && company != nil {
// // 			companies = append(companies, company)
// // 		}
		
// // 		if len(companies) >= limit {
// // 			break
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate companies_by_tier_active: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // // DIRECT MATERIALIZED VIEW QUERY: Get companies by tier and name
// // func (r *CompanyRepositoryImpl) getCompaniesByTierAndNameDirect(ctx context.Context, tier, nameContains string, limit, offset int) ([]*models.Company, error) {
// // 	searchPattern := strings.ToLower(nameContains) + "%"
	
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier
// // 		FROM companies_by_tier_name 
// // 		WHERE subscription_tier = ? AND company_name >= ? 
// // 		LIMIT ?`,
// // 		tier, searchPattern, limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		companyID      gocql.UUID
// // 		companyName    string
// // 		subscriptionTier string
// // 	)

// // 	// Apply offset manually and filter by name contains
// // 	currentOffset := 0
// // 	for iter.Scan(&companyID, &companyName, &subscriptionTier) {
// // 		if currentOffset < offset {
// // 			currentOffset++
// // 			continue
// // 		}
		
// // 		// Additional client-side filtering for contains (since we only have prefix)
// // 		if strings.Contains(strings.ToLower(companyName), strings.ToLower(nameContains)) {
// // 			company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // 			if err == nil && company != nil {
// // 				companies = append(companies, company)
// // 			}
// // 		}
		
// // 		if len(companies) >= limit {
// // 			break
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate companies_by_tier_name: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // // Helper function to fetch companies from view iterations
// // func (r *CompanyRepositoryImpl) fetchCompaniesFromViewIter(ctx context.Context, query *gocql.Query, offset int) ([]*models.Company, error) {
// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		companyID              gocql.UUID
// // 		companyName            string
// // 		subscriptionTier       string
// // 		isActive               bool
// // 		isBlocked              bool
// // 		subscriptionStartDate  time.Time
// // 		subscriptionEndDate    time.Time
// // 		createdAt              time.Time
// // 	)

// // 	currentOffset := 0
// // 	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActive, &isBlocked,
// // 		&subscriptionStartDate, &subscriptionEndDate, &createdAt) {
		
// // 		if currentOffset < offset {
// // 			currentOffset++
// // 			continue
// // 		}
		
// // 		company := &models.Company{
// // 			CompanyID:            uuid.UUID(companyID),
// // 			CompanyName:          companyName,
// // 			SubscriptionTier:     subscriptionTier,
// // 			IsActive:             isActive,
// // 			IsBlocked:            isBlocked,
// // 			SubscriptionStartDate: subscriptionStartDate,
// // 			SubscriptionEndDate:  subscriptionEndDate,
// // 			CreatedAt:            createdAt,
// // 		}
// // 		companies = append(companies, company)
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate materialized view: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // // Fallback for complex filters
// // func (r *CompanyRepositoryImpl) listCompaniesComplexFilter(ctx context.Context, filter models.CompanyFilter, limit, offset int) ([]*models.Company, error) {
// // 	// Use base companies table with minimal filtering
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, owner_phone, owner_user_id,
// // 		       subscription_tier, subscription_start_date, subscription_end_date,
// // 		       monthly_premium, max_employees, is_active, is_blocked,
// // 		       created_at, updated_at, data_region
// // 		FROM companies 
// // 		LIMIT ?`,
// // 		limit + offset, // Fetch extra to handle offset
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		scannedID        gocql.UUID
// // 		companyName      string
// // 		ownerPhone       string
// // 		scannedOwnerID   gocql.UUID
// // 		subscriptionTier string
// // 		startDate        time.Time
// // 		endDate          time.Time
// // 		monthlyPremium   float64
// // 		maxEmployees     int
// // 		isActive         bool
// // 		isBlocked        bool
// // 		createdAt        time.Time
// // 		updatedAt        time.Time
// // 		dataRegion       string
// // 	)

// // 	currentOffset := 0
// // 	for iter.Scan(&scannedID, &companyName, &ownerPhone, &scannedOwnerID,
// // 		&subscriptionTier, &startDate, &endDate, &monthlyPremium, &maxEmployees,
// // 		&isActive, &isBlocked, &createdAt, &updatedAt, &dataRegion) {
		
// // 		// Apply offset
// // 		if currentOffset < offset {
// // 			currentOffset++
// // 			continue
// // 		}
		
// // 		// Apply filters
// // 		if filter.SubscriptionTier != "" && filter.SubscriptionTier != subscriptionTier {
// // 			continue
// // 		}
// // 		if filter.Status != "" && !r.matchesStatus(filter.Status, isActive, isBlocked) {
// // 			continue
// // 		}
// // 		if filter.NameContains != "" && !strings.Contains(strings.ToLower(companyName), strings.ToLower(filter.NameContains)) {
// // 			continue
// // 		}
		
// // 		company := &models.Company{
// // 			CompanyID:            uuid.UUID(scannedID),
// // 			CompanyName:          companyName,
// // 			OwnerPhone:           ownerPhone,
// // 			OwnerUserID:          uuid.UUID(scannedOwnerID),
// // 			SubscriptionTier:     subscriptionTier,
// // 			SubscriptionStartDate: startDate,
// // 			SubscriptionEndDate:  endDate,
// // 			MonthlyPremium:       monthlyPremium,
// // 			MaxEmployees:         maxEmployees,
// // 			IsActive:             isActive,
// // 			IsBlocked:            isBlocked,
// // 			CreatedAt:            createdAt,
// // 			UpdatedAt:            updatedAt,
// // 			DataRegion:           dataRegion,
// // 		}
// // 		companies = append(companies, company)
		
// // 		if len(companies) >= limit {
// // 			break
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate companies: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // // Optimized count using materialized views when possible
// // func (r *CompanyRepositoryImpl) getCompaniesCountOptimized(ctx context.Context, filter models.CompanyFilter) (int, error) {
// // 	var count int64
// // 	var err error

// // 	switch {
// // 	case filter.SubscriptionTier != "" && filter.Status == "" && filter.NameContains == "":
// // 		// Use companies_by_tier for counting
// // 		query := r.client.Session.Query(`
// // 			SELECT COUNT(*) FROM companies_by_tier WHERE subscription_tier = ?`,
// // 			filter.SubscriptionTier,
// // 		)
// // 		err = query.WithContext(ctx).Scan(&count)
	
// // 	case filter.Status != "" && filter.SubscriptionTier == "" && filter.NameContains == "":
// // 		// Use companies_by_active_status for counting
// // 		isActive := r.statusToIsActive(filter.Status)
// // 		query := r.client.Session.Query(`
// // 			SELECT COUNT(*) FROM companies_by_active_status WHERE is_active = ?`,
// // 			isActive,
// // 		)
// // 		err = query.WithContext(ctx).Scan(&count)
	
// // 	default:
// // 		// Fallback to base table count
// // 		query := r.client.Session.Query("SELECT COUNT(*) FROM companies")
// // 		err = query.WithContext(ctx).Scan(&count)
// // 	}

// // 	if err != nil {
// // 		return 0, fmt.Errorf("failed to count companies: %w", err)
// // 	}
	
// // 	return int(count), nil
// // }

// // // ============================================================
// // // NEW DIRECT MATERIALIZED VIEW QUERIES
// // // ============================================================

// // func (r *CompanyRepositoryImpl) GetCompaniesByTier(ctx context.Context, tier string, limit int) ([]*models.Company, error) {
// // 	return r.getCompaniesByTierDirect(ctx, tier, limit, 0)
// // }

// // func (r *CompanyRepositoryImpl) GetCompaniesByTierAndStatus(ctx context.Context, tier string, isActive bool, limit int) ([]*models.Company, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier, is_active
// // 		FROM companies_by_tier_active 
// // 		WHERE subscription_tier = ? AND is_active = ? 
// // 		LIMIT ?`,
// // 		tier, isActive, limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var companies []*models.Company
// // 	var (
// // 		companyID      gocql.UUID
// // 		companyName    string
// // 		subscriptionTier string
// // 		isActiveFlag   bool
// // 	)

// // 	for iter.Scan(&companyID, &companyName, &subscriptionTier, &isActiveFlag) {
// // 		company, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // 		if err == nil && company != nil {
// // 			companies = append(companies, company)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate companies_by_tier_active: %w", err)
// // 	}

// // 	return companies, nil
// // }

// // func (r *CompanyRepositoryImpl) GetCompaniesBySubscriptionDateRange(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.Company, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
// // 		       subscription_start_date, subscription_end_date, created_at
// // 		FROM companies_by_subscription_date 
// // 		WHERE subscription_end_date >= ? AND subscription_end_date <= ?
// // 		LIMIT ?`,
// // 		startDate, endDate, limit,
// // 	)

// // 	return r.fetchCompaniesFromViewIter(ctx, query, 0)
// // }

// // // ============================================================
// // // OPTIMIZED EMPLOYEE QUERIES WITH MATERIALIZED VIEWS
// // // ============================================================

// // // GetCompanyEmployeeByUser - DIRECT MATERIALIZED VIEW QUERY
// // func (r *CompanyRepositoryImpl) GetCompanyEmployeeByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, user_id, employee_id, role_id, department_id, is_active
// // 		FROM employees_by_user 
// // 		WHERE user_id = ?`,
// // 		gocql.UUID(userID),
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	defer iter.Close()

// // 	var employees []*models.CompanyEmployee
// // 	var (
// // 		scCompanyID gocql.UUID
// // 		scUserID    gocql.UUID
// // 		employeeID  string
// // 		scRoleID    gocql.UUID
// // 		scDeptID    gocql.UUID
// // 		isActive    bool
// // 	)

// // 	for iter.Scan(&scCompanyID, &scUserID, &employeeID, &scRoleID, &scDeptID, &isActive) {
// // 		emp := &models.CompanyEmployee{
// // 			CompanyID:    uuid.UUID(scCompanyID),
// // 			UserID:       uuid.UUID(scUserID),
// // 			EmployeeID:   employeeID,
// // 			RoleID:       uuid.UUID(scRoleID),
// // 			DepartmentID: uuid.UUID(scDeptID),
// // 			IsActive:     isActive,
// // 		}
// // 		employees = append(employees, emp)
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate employees_by_user: %w", err)
// // 	}

// // 	return employees, nil
// // }

// // // ============================================================
// // // HELPER FUNCTIONS
// // // ============================================================

// // func (r *CompanyRepositoryImpl) statusToIsActive(status string) bool {
// // 	switch status {
// // 	case models.SubscriptionStatusActive:
// // 		return true
// // 	case models.SubscriptionStatusCompanyInactive:
// // 		return false
// // 	case models.SubscriptionStatusCompanyBlocked:
// // 		return true // blocked companies are technically active but blocked
// // 	default:
// // 		return true
// // 	}
// // }

// // func (r *CompanyRepositoryImpl) matchesStatus(status string, isActive, isBlocked bool) bool {
// // 	switch status {
// // 	case models.SubscriptionStatusActive:
// // 		return isActive && !isBlocked
// // 	case models.SubscriptionStatusCompanyBlocked:
// // 		return isBlocked
// // 	case models.SubscriptionStatusCompanyInactive:
// // 		return !isActive && !isBlocked
// // 	default:
// // 		return true
// // 	}
// // }
// // ]

// // func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
// // 	filter := models.CompanyFilter{Status: status}
// // 	companies, _, err := r.ListCompanies(ctx, filter, 1, limit)
// // 	return companies, err
// // }



// // func (r *CompanyRepositoryImpl) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// // 		true, reason, gocql.UUID(blockedBy), blockedAt, time.Now().UTC(), gocql.UUID(companyID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) UnblockCompany(ctx context.Context, companyID uuid.UUID) error {
// // 	now := time.Now().UTC()
// // 	query := r.client.Session.Query(`
// // 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// // 		false, nil, nil, nil, now, gocql.UUID(companyID),



// // func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// // 	query := r.client.Session.Query(`
// // 		INSERT INTO company_departments (
// // 			company_id, department_id, department_name, department_head, 
// // 			permissions, is_active, created_at, updated_at
// // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
// // 		gocql.UUID(department.CompanyID),
// // 		gocql.UUID(department.DepartmentID),
// // 		department.DepartmentName,
// // 		gocql.UUID(department.DepartmentHead),
// // 		department.Permissions,
// // 		department.IsActive,
// // 		department.CreatedAt,
// // 		department.UpdatedAt,
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, department_id, department_name, department_head, 
// // 		       permissions, is_active, created_at, updated_at
// // 		FROM company_departments WHERE company_id = ? AND department_id = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(departmentID),
// // 	)

// // 	var (
// // 		scCompanyID    gocql.UUID
// // 		scDepartmentID gocql.UUID
// // 		scDeptHead     gocql.UUID
// // 		department     models.CompanyDepartment
// // 	)

// // 	err := query.WithContext(ctx).Scan(
// // 		&scCompanyID, &scDepartmentID, &department.DepartmentName, &scDeptHead,
// // 		&department.Permissions, &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
// // 	)

// // 	if err != nil {
// // 		if err == gocql.ErrNotFound {
// // 			return nil, fmt.Errorf("department not found")
// // 		}
// // 		return nil, fmt.Errorf("failed to get department: %w", err)
// // 	}

// // 	department.CompanyID = uuid.UUID(scCompanyID)
// // 	department.DepartmentID = uuid.UUID(scDepartmentID)
// // 	department.DepartmentHead = uuid.UUID(scDeptHead)
// // 	return &department, nil
// // }

// // func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE company_departments SET 
// // 			department_name = ?, department_head = ?, permissions = ?, 
// // 			is_active = ?, updated_at = ?
// // 		WHERE company_id = ? AND department_id = ?`,
// // 		department.DepartmentName,
// // 		gocql.UUID(department.DepartmentHead),
// // 		department.Permissions,
// // 		department.IsActive,
// // 		department.UpdatedAt,
// // 		gocql.UUID(department.CompanyID),
// // 		gocql.UUID(department.DepartmentID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT department_id FROM company_departments 
// // 		WHERE company_id = ? AND is_active = true LIMIT ?`,
// // 		gocql.UUID(companyID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var deptID gocql.UUID
// // 	var departments []*models.CompanyDepartment

// // 	for iter.Scan(&deptID) {
// // 		dept, err := r.GetDepartment(ctx, companyID, uuid.UUID(deptID))
// // 		if err == nil && dept != nil {
// // 			departments = append(departments, dept)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate departments: %w", err)
// // 	}

// // 	return departments, nil
// // }

// // func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE company_departments SET is_active = false, updated_at = ?
// // 		WHERE company_id = ? AND department_id = ?`,
// // 		time.Now().UTC(), gocql.UUID(companyID), gocql.UUID(departmentID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// // 	query := r.client.Session.Query(`
// // 		INSERT INTO company_employees (
// // 			company_id, user_id, employee_id, role_id, department_id,
// // 			hire_date, is_active, reports_to, created_at, updated_at
// // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // 		gocql.UUID(employee.CompanyID),
// // 		gocql.UUID(employee.UserID),
// // 		employee.EmployeeID,
// // 		gocql.UUID(employee.RoleID),
// // 		gocql.UUID(employee.DepartmentID),
// // 		employee.HireDate,
// // 		employee.IsActive,
// // 		gocql.UUID(employee.ReportsTo),
// // 		employee.CreatedAt,
// // 		employee.UpdatedAt,
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, user_id, employee_id, role_id, department_id, hire_date, is_active, reports_to, created_at, updated_at
// // 		FROM company_employees WHERE company_id = ? AND user_id = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(userID),
// // 	)
// // 	var (
// // 		scCompanyID gocql.UUID
// // 		scUserID    gocql.UUID
// // 		emp         models.CompanyEmployee
// // 		scRoleID    gocql.UUID
// // 		scDeptID    gocql.UUID
// // 		scReportsTo gocql.UUID
// // 	)
// // 	err := query.WithContext(ctx).Scan(
// // 		&scCompanyID, &scUserID, &emp.EmployeeID, &scRoleID, &scDeptID, &emp.HireDate, &emp.IsActive, &scReportsTo, &emp.CreatedAt, &emp.UpdatedAt,
// // 	)
// // 	if err != nil {
// // 		if err == gocql.ErrNotFound {
// // 			return nil, nil
// // 		}
// // 		return nil, fmt.Errorf("failed to get company employee: %w", err)
// // 	}

// // 	emp.CompanyID = uuid.UUID(scCompanyID)
// // 	emp.UserID = uuid.UUID(scUserID)
// // 	emp.RoleID = uuid.UUID(scRoleID)
// // 	emp.DepartmentID = uuid.UUID(scDeptID)
// // 	if scReportsTo != (gocql.UUID{}) {
// // 		emp.ReportsTo = uuid.UUID(scReportsTo)
// // 	}
// // 	return &emp, nil
// // }

// // func (r *CompanyRepositoryImpl) UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE company_employees SET 
// // 			employee_id = ?, role_id = ?, department_id = ?, 
// // 			reports_to = ?, is_active = ?, updated_at = ?
// // 		WHERE company_id = ? AND user_id = ?`,
// // 		employee.EmployeeID,
// // 		gocql.UUID(employee.RoleID),
// // 		gocql.UUID(employee.DepartmentID),
// // 		gocql.UUID(employee.ReportsTo),
// // 		employee.IsActive,
// // 		employee.UpdatedAt,
// // 		gocql.UUID(employee.CompanyID),
// // 		gocql.UUID(employee.UserID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT user_id FROM company_employees WHERE company_id = ? LIMIT ?`,
// // 		gocql.UUID(companyID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var uid gocql.UUID
// // 	var employees []*models.CompanyEmployee

// // 	for iter.Scan(&uid) {
// // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // 		if err == nil && e != nil {
// // 			employees = append(employees, e)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, 0, fmt.Errorf("failed to list employees: %w", err)
// // 	}

// // 	return employees, len(employees), nil
// // }

// // func (r *CompanyRepositoryImpl) ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT user_id FROM company_employees 
// // 		WHERE company_id = ? AND department_id = ? AND is_active = true LIMIT ?`,
// // 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var uid gocql.UUID
// // 	var employees []*models.CompanyEmployee

// // 	for iter.Scan(&uid) {
// // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // 		if err == nil && e != nil && e.IsActive {
// // 			employees = append(employees, e)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to list employees by department: %w", err)
// // 	}

// // 	return employees, nil
// // }

// // func (r *CompanyRepositoryImpl) ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT user_id FROM company_employees 
// // 		WHERE company_id = ? AND role_id = ? AND is_active = true LIMIT ?`,
// // 		gocql.UUID(companyID), gocql.UUID(roleID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var uid gocql.UUID
// // 	var employees []*models.CompanyEmployee

// // 	for iter.Scan(&uid) {
// // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // 		if err == nil && e != nil && e.IsActive {
// // 			employees = append(employees, e)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to list employees by role: %w", err)
// // 	}

// // 	return employees, nil
// // }

// // func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// // 	query := r.client.Session.Query(`SELECT COUNT(*) FROM company_employees WHERE company_id = ?`, gocql.UUID(companyID))
// // 	var cnt int64
// // 	if err := query.WithContext(ctx).Scan(&cnt); err != nil {
// // 		return 0, fmt.Errorf("failed to count employees: %w", err)
// // 	}
// // 	return int(cnt), nil
// // }

// // func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE company_employees SET is_active = false, updated_at = ?
// // 		WHERE company_id = ? AND user_id = ?`,
// // 		time.Now().UTC(),
// // 		gocql.UUID(companyID),
// // 		gocql.UUID(userID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE company_employees SET is_active = true, updated_at = ?
// // 		WHERE company_id = ? AND user_id = ?`,
// // 		time.Now().UTC(),
// // 		gocql.UUID(companyID),
// // 		gocql.UUID(userID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT COUNT(*) FROM company_employees 
// // 		WHERE company_id = ? AND is_active = true`,
// // 		gocql.UUID(companyID),
// // 	)
// // 	var count int64
// // 	if err := query.WithContext(ctx).Scan(&count); err != nil {
// // 		return 0, fmt.Errorf("failed to count active employees: %w", err)
// // 	}
// // 	return int(count), nil
// // }

// // func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT user_id FROM company_employees 
// // 		WHERE company_id = ? AND is_active = true 
// // 		LIMIT ?`,
// // 		gocql.UUID(companyID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var uid gocql.UUID
// // 	var employeeIDs []uuid.UUID

// // 	for iter.Scan(&uid) {
// // 		employeeIDs = append(employeeIDs, uuid.UUID(uid))
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, 0, fmt.Errorf("failed to list active employees: %w", err)
// // 	}

// // 	// Get employee details
// // 	var employees []*models.CompanyEmployee
// // 	for _, userID := range employeeIDs {
// // 		emp, err := r.GetCompanyEmployee(ctx, companyID, userID)
// // 		if err == nil && emp != nil && emp.IsActive {
// // 			employees = append(employees, emp)
// // 		}
// // 	}

// // 	return employees, len(employees), nil
// // }

// // func (r *CompanyRepositoryImpl) CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// // 	query := r.client.Session.Query(`
// // 		INSERT INTO employee_roles (
// // 			company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // 		gocql.UUID(role.CompanyID),
// // 		gocql.UUID(role.RoleID),
// // 		role.RoleName,
// // 		role.RoleLevel,
// // 		role.Permissions,
// // 		gocql.UUID(role.DepartmentID),
// // 		role.IsSystemRole,
// // 		role.CreatedAt,
// // 		role.UpdatedAt,
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// // 		FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(roleID),
// // 	)
// // 	var (
// // 		scCompanyID gocql.UUID
// // 		scRoleID    gocql.UUID
// // 		role        models.EmployeeRole
// // 		scDeptID    gocql.UUID
// // 	)
// // 	err := query.WithContext(ctx).Scan(&scCompanyID, &scRoleID, &role.RoleName, &role.RoleLevel, &role.Permissions, &scDeptID, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt)
// // 	if err != nil {
// // 		if err == gocql.ErrNotFound {
// // 			return nil, fmt.Errorf("role not found")
// // 		}
// // 		return nil, fmt.Errorf("failed to get employee role: %w", err)
// // 	}
// // 	role.CompanyID = uuid.UUID(scCompanyID)
// // 	role.RoleID = uuid.UUID(scRoleID)
// // 	role.DepartmentID = uuid.UUID(scDeptID)
// // 	return &role, nil
// // }

// // func (r *CompanyRepositoryImpl) GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT role_id FROM employee_roles 
// // 		WHERE company_id = ? AND role_level = ? LIMIT 1`,
// // 		gocql.UUID(companyID), roleLevel,
// // 	)

// // 	var roleID gocql.UUID
// // 	if err := query.WithContext(ctx).Scan(&roleID); err != nil {
// // 		if err == gocql.ErrNotFound {
// // 			return nil, fmt.Errorf("role level not found: %s", roleLevel)
// // 		}
// // 		return nil, fmt.Errorf("failed to get role by level: %w", err)
// // 	}

// // 	return r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // }

// // func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// // 	query := r.client.Session.Query(`
// // 		UPDATE employee_roles SET 
// // 			role_name = ?, role_level = ?, permissions = ?, department_id = ?,
// // 			is_system_role = ?, updated_at = ?
// // 		WHERE company_id = ? AND role_id = ?`,
// // 		role.RoleName,
// // 		role.RoleLevel,
// // 		role.Permissions,
// // 		gocql.UUID(role.DepartmentID),
// // 		role.IsSystemRole,
// // 		role.UpdatedAt,
// // 		gocql.UUID(role.CompanyID),
// // 		gocql.UUID(role.RoleID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT role_id FROM employee_roles WHERE company_id = ? LIMIT ?`,
// // 		gocql.UUID(companyID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var roleID gocql.UUID
// // 	var roles []*models.EmployeeRole

// // 	for iter.Scan(&roleID) {
// // 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // 		if err == nil && role != nil {
// // 			roles = append(roles, role)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to list employee roles: %w", err)
// // 	}

// // 	return roles, nil
// // }

// // func (r *CompanyRepositoryImpl) ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	query := r.client.Session.Query(`
// // 		SELECT role_id FROM employee_roles 
// // 		WHERE company_id = ? AND department_id = ? LIMIT ?`,
// // 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var roleID gocql.UUID
// // 	var roles []*models.EmployeeRole

// // 	for iter.Scan(&roleID) {
// // 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // 		if err == nil && role != nil {
// // 			roles = append(roles, role)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to list employee roles by department: %w", err)
// // 	}

// // 	return roles, nil
// // }

// // func (r *CompanyRepositoryImpl) DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error {
// // 	query := r.client.Session.Query(`
// // 		DELETE FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(roleID),
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // // ============================================================
// // // Permission Operations (ENHANCED)
// // // ============================================================

// // func (r *CompanyRepositoryImpl) GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error) {
// // 	query := r.client.Session.Query(`
// // 		SELECT permission FROM employee_permissions WHERE company_id = ? AND user_id = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(userID),
// // 	)
// // 	iter := query.WithContext(ctx).Iter()
// // 	var perm string
// // 	perms := make([]string, 0)
// // 	for iter.Scan(&perm) {
// // 		perms = append(perms, perm)
// // 	}
// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to iterate permissions: %w", err)
// // 	}
// // 	return perms, nil
// // }

// // func (r *CompanyRepositoryImpl) GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error {
// // 	query := r.client.Session.Query(`
// // 		INSERT INTO employee_permissions (
// // 			company_id, user_id, permission, granted_by, granted_at, expires_at
// // 		) VALUES (?, ?, ?, ?, ?, ?)`,
// // 		gocql.UUID(permission.CompanyID),
// // 		gocql.UUID(permission.UserID),
// // 		permission.Permission,
// // 		gocql.UUID(permission.GrantedBy),
// // 		permission.GrantedAt,
// // 		permission.ExpiresAt,
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error {
// // 	query := r.client.Session.Query(`
// // 		DELETE FROM employee_permissions 
// // 		WHERE company_id = ? AND user_id = ? AND permission = ?`,
// // 		gocql.UUID(companyID), gocql.UUID(userID), permission,
// // 	)
// // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // }

// // func (r *CompanyRepositoryImpl) GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error) {
// // 	if limit <= 0 || limit > 1000 {
// // 		limit = 100
// // 	}

// // 	// First get user IDs with the permission
// // 	query := r.client.Session.Query(`
// // 		SELECT user_id FROM employee_permissions 
// // 		WHERE company_id = ? AND permission = ? LIMIT ?`,
// // 		gocql.UUID(companyID), permission, limit,
// // 	)

// // 	iter := query.WithContext(ctx).Iter()
// // 	var uid gocql.UUID
// // 	var employees []*models.CompanyEmployee

// // 	for iter.Scan(&uid) {
// // 		emp, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // 		if err == nil && emp != nil && emp.IsActive {
// // 			employees = append(employees, emp)
// // 		}
// // 	}

// // 	if err := iter.Close(); err != nil {
// // 		return nil, fmt.Errorf("failed to get employees with permission: %w", err)
// // 	}

// // 	return employees, nil
// // }

// // // ============================================================
// // // Health Check
// // // ============================================================

// // func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
// // 	var release string
// // 	q := r.client.Session.Query(`SELECT release_version FROM system.local`)
// // 	if err := q.WithContext(ctx).Scan(&release); err != nil {
// // 		return fmt.Errorf("scylla health check failed: %w", err)
// // 	}
// // 	r.logger.Debug("scylla release_version", zap.String("version", release))
// // 	return nil
// // }

// // // func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
// // //     filter := models.CompanyFilter{Status: status}
// // //     companies, _, err := r.ListCompanies(ctx, filter, 1, limit)
// // //     return companies, err
// // // }

// // // ============================================================
// // // EXISTING METHODS (minimal changes)
// // // ============================================================

// // // ... (Keep all the existing methods like BlockCompany, UnblockCompany, Department operations, 
// // // Employee operations, Role operations, Permission operations, HealthCheck exactly as they were)

// // // The rest of your existing methods remain unchanged...
// // // [Include all the existing methods from your original code here without modification
// // // package scylla

// // // import (
// // // 	"context"
// // // 	"fmt"
// // // 	"strings"
// // // 	"time"

// // // 	"auth-service/internal/models"
// // // 	"github.com/gocql/gocql"
// // // 	"github.com/google/uuid"
// // // 	"go.uber.org/zap"
// // // )

// // // // ============================================================
// // // // CompanyRepository Interface (ENHANCED)
// // // // ============================================================

// // // type CompanyRepository interface {
// // // 	// ============================================================
// // // 	// Company operations
// // // 	// ============================================================
// // // 	CreateCompany(ctx context.Context, company *models.Company) error
// // // 	GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error)
// // // 	GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error)
// // // 	ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error)
// // // 	ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error)
// // // 	BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error
// // // 	UnblockCompany(ctx context.Context, companyID uuid.UUID) error
// // // 	UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error
// // // 	UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error
// // // 	UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error
// // // 	GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error)

// // // 	// ============================================================
// // // 	// Department operations (NEW)
// // // 	// ============================================================
// // // 	CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// // // 	GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error)
// // // 	UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error
// // // 	ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error)
// // // 	DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error

// // // 	// ============================================================
// // // 	// Employee operations
// // // 	// ============================================================
// // // 	CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// // // 	GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error)
// // // 	UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error
// // // 	GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// // // 	ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)
// // // 	ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)
// // // 	ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error)

// // // 	// Employee Activation/Status Functions
// // // 	DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// // // 	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error
// // // 	GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error)
// // // 	ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error)

// // // 	// ============================================================
// // // 	// Role operations (ENHANCED)
// // // 	// ============================================================
// // // 	CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// // // 	GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error)
// // // 	GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error)
// // // 	UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error
// // // 	ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// // // 	ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error)
// // // 	DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error

// // // 	// ============================================================
// // // 	// Permission operations (ENHANCED)
// // // 	// ============================================================
// // // 	GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error)
// // // 	GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error
// // // 	RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error
// // // 	GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error)

// // // 	// ============================================================
// // // 	// Utility
// // // 	// ============================================================
// // // 	HealthCheck(ctx context.Context) error
// // // }

// // // // ============================================================
// // // // Implementation
// // // // ============================================================

// // // type CompanyRepositoryImpl struct {
// // // 	client *ScyllaClient
// // // 	logger *zap.Logger
// // // }

// // // func NewCompanyRepository(client *ScyllaClient, logger *zap.Logger) CompanyRepository {
// // // 	return &CompanyRepositoryImpl{
// // // 		client: client,
// // // 		logger: logger,
// // // 	}
// // // }

// // // // ============================================================
// // // // Company CRUD
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company) error {
// // // 	query := r.client.Session.Query(`
// // // 		INSERT INTO companies (
// // // 			company_id, company_name, owner_phone, owner_user_id, 
// // // 			subscription_tier, subscription_start_date, subscription_end_date,
// // // 			monthly_premium, max_employees, is_active, is_blocked,
// // // 			created_at, updated_at, data_region
// // // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // // 		gocql.UUID(company.CompanyID),
// // // 		company.CompanyName,
// // // 		company.OwnerPhone,
// // // 		gocql.UUID(company.OwnerUserID),
// // // 		company.SubscriptionTier,
// // // 		company.SubscriptionStartDate,
// // // 		company.SubscriptionEndDate,
// // // 		company.MonthlyPremium,
// // // 		company.MaxEmployees,
// // // 		company.IsActive,
// // // 		company.IsBlocked,
// // // 		company.CreatedAt,
// // // 		company.UpdatedAt,
// // // 		company.DataRegion,
// // // 	)

// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT company_id, company_name, owner_phone, owner_user_id,
// // // 		       subscription_tier, subscription_start_date, subscription_end_date,
// // // 		       monthly_premium, max_employees, is_active, is_blocked,
// // // 		       blocked_reason, blocked_by, blocked_at,
// // // 		       created_at, updated_at, data_region
// // // 		FROM companies WHERE company_id = ?`,
// // // 		gocql.UUID(companyID),
// // // 	)

// // // 	var (
// // // 		scannedID        gocql.UUID
// // // 		scannedOwnerID   gocql.UUID
// // // 		scannedBlockedBy gocql.UUID
// // // 		company          models.Company
// // // 	)

// // // 	err := query.WithContext(ctx).Scan(
// // // 		&scannedID, &company.CompanyName, &company.OwnerPhone, &scannedOwnerID,
// // // 		&company.SubscriptionTier, &company.SubscriptionStartDate, &company.SubscriptionEndDate,
// // // 		&company.MonthlyPremium, &company.MaxEmployees, &company.IsActive, &company.IsBlocked,
// // // 		&company.BlockedReason, &scannedBlockedBy, &company.BlockedAt,
// // // 		&company.CreatedAt, &company.UpdatedAt, &company.DataRegion,
// // // 	)

// // // 	if err != nil {
// // // 		if err == gocql.ErrNotFound {
// // // 			return nil, fmt.Errorf("company not found: %s", companyID.String())
// // // 		}
// // // 		return nil, fmt.Errorf("failed to get company: %w", err)
// // // 	}

// // // 	company.CompanyID = uuid.UUID(scannedID)
// // // 	company.OwnerUserID = uuid.UUID(scannedOwnerID)
// // // 	if scannedBlockedBy != (gocql.UUID{}) {
// // // 		company.BlockedBy = uuid.UUID(scannedBlockedBy)
// // // 	}

// // // 	return &company, nil
// // // }

// // // func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT company_id FROM companies_by_owner WHERE owner_user_id = ?`,
// // // 		gocql.UUID(ownerUserID),
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var cid gocql.UUID
// // // 	var results []*models.Company

// // // 	for iter.Scan(&cid) {
// // // 		c, err := r.GetCompany(ctx, uuid.UUID(cid))
// // // 		if err != nil {
// // // 			r.logger.Warn("failed to fetch company details from companies_by_owner", zap.Error(err))
// // // 			continue
// // // 		}
// // // 		results = append(results, c)
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to iterate companies_by_owner: %w", err)
// // // 	}

// // // 	return results, nil
// // // }

// // // // ============================================================
// // // // OPTIMIZED LIST COMPANIES WITH MATERIALIZED VIEWS
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) ListCompanies(ctx context.Context, filter models.CompanyFilter, page, limit int) ([]*models.Company, int, error) {
// // //     // Validate and normalize limit
// // //     if limit <= 0 || limit > 1000 {
// // //         limit = 25
// // //     }
// // //     if page <= 0 {
// // //         page = 1
// // //     }

// // //     // Calculate offset for pagination
// // //     offset := (page - 1) * limit

// // //     // Choose the optimal query strategy based on filters
// // //     var companies []*models.Company
// // //     var err error

// // //     // Strategy 1: Use tier view when only tier is filtered
// // //     if filter.SubscriptionTier != "" && filter.NameContains == "" && filter.Status == "" {
// // //         companies, err = r.listCompaniesByTierOptimized(ctx, filter.SubscriptionTier, limit, offset)
// // //     } else if filter.Status != "" && r.canUseStatusView(filter.Status) && filter.NameContains == "" && filter.SubscriptionTier == "" {
// // //         // Strategy 2: Use status view when only status is filtered
// // //         companies, err = r.listCompaniesByStatusOptimized(ctx, filter.Status, limit, offset)
// // //     } else if filter.NameContains != "" {
// // //         // Strategy 3: Use name search with efficient filtering
// // //         companies, err = r.listCompaniesByNameOptimized(ctx, filter, limit, offset)
// // //     } else {
// // //         // Strategy 4: Fallback to efficient base query with careful filtering
// // //         companies, err = r.listCompaniesEfficientFallback(ctx, filter, limit, offset)
// // //     }

// // //     if err != nil {
// // //         return nil, 0, fmt.Errorf("failed to list companies: %w", err)
// // //     }

// // //     // Get total count separately for pagination
// // //     total, err := r.getCompaniesCount(ctx, filter)
// // //     if err != nil {
// // //         r.logger.Warn("failed to get companies count", zap.Error(err))
// // //         total = len(companies) // Fallback to current result count
// // //     }

// // //     return companies, total, nil
// // // }

// // // // New optimized method for tier-based filtering
// // // func (r *CompanyRepositoryImpl) listCompaniesByTierOptimized(ctx context.Context, tier string, limit, offset int) ([]*models.Company, error) {
// // //     query := r.client.Session.Query(`
// // //         SELECT company_id FROM companies_by_tier 
// // //         WHERE subscription_tier = ? 
// // //         LIMIT ?`,
// // //         tier, limit,
// // //     )

// // //     iter := query.WithContext(ctx).Iter()
// // //     defer iter.Close()

// // //     var companies []*models.Company
// // //     var companyID gocql.UUID
    
// // //     for iter.Scan(&companyID) {
// // //         // Apply offset manually in application logic
// // //         if offset > 0 {
// // //             offset--
// // //             continue
// // //         }
        
// // //         c, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // //         if err == nil {
// // //             companies = append(companies, c)
// // //         }
        
// // //         if len(companies) >= limit {
// // //             break
// // //         }
// // //     }

// // //     if err := iter.Close(); err != nil {
// // //         return nil, fmt.Errorf("failed to iterate companies by tier: %w", err)
// // //     }

// // //     return companies, nil
// // // }

// // // // New optimized method for status-based filtering
// // // func (r *CompanyRepositoryImpl) listCompaniesByStatusOptimized(ctx context.Context, status string, limit, offset int) ([]*models.Company, error) {
// // //     isActive, isBlocked := r.getStatusFlags(status)
    
// // //     query := r.client.Session.Query(`
// // //         SELECT company_id FROM companies_by_active_status 
// // //         WHERE is_active = ? AND is_blocked = ? 
// // //         LIMIT ?`,
// // //         isActive, isBlocked, limit,
// // //     )

// // //     iter := query.WithContext(ctx).Iter()
// // //     defer iter.Close()

// // //     var companies []*models.Company
// // //     var companyID gocql.UUID
    
// // //     for iter.Scan(&companyID) {
// // //         // Apply offset manually
// // //         if offset > 0 {
// // //             offset--
// // //             continue
// // //         }
        
// // //         c, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // //         if err == nil {
// // //             companies = append(companies, c)
// // //         }
        
// // //         if len(companies) >= limit {
// // //             break
// // //         }
// // //     }

// // //     if err := iter.Close(); err != nil {
// // //         return nil, fmt.Errorf("failed to iterate companies by status: %w", err)
// // //     }

// // //     return companies, nil
// // // }

// // // // New optimized method for name-based search
// // // func (r *CompanyRepositoryImpl) listCompaniesByNameOptimized(ctx context.Context, filter models.CompanyFilter, limit, offset int) ([]*models.Company, error) {
// // //     // Use the most efficient approach for name search
// // //     var baseQuery string
// // //     var params []interface{}

// // //     // Try to use the most specific materialized view first
// // //     if filter.SubscriptionTier != "" {
// // //         baseQuery = "SELECT company_id FROM companies_by_tier WHERE subscription_tier = ? AND company_name LIKE ? LIMIT ?"
// // //         params = []interface{}{filter.SubscriptionTier, "%" + strings.ToLower(filter.NameContains) + "%", limit}
// // //     } else if filter.Status != "" && r.canUseStatusView(filter.Status) {
// // //         isActive, isBlocked := r.getStatusFlags(filter.Status)
// // //         baseQuery = "SELECT company_id FROM companies_by_active_status WHERE is_active = ? AND is_blocked = ? AND company_name LIKE ? LIMIT ?"
// // //         params = []interface{}{isActive, isBlocked, "%" + strings.ToLower(filter.NameContains) + "%", limit}
// // //     } else {
// // //         // Fallback to base table with ALLOW FILTERING for complex cases
// // //         baseQuery = "SELECT company_id FROM companies WHERE company_name LIKE ? LIMIT ? ALLOW FILTERING"
// // //         params = []interface{}{"%" + strings.ToLower(filter.NameContains) + "%", limit}
// // //     }

// // //     query := r.client.Session.Query(baseQuery, params...)
// // //     iter := query.WithContext(ctx).Iter()
// // //     defer iter.Close()

// // //     var companies []*models.Company
// // //     var companyID gocql.UUID
    
// // //     for iter.Scan(&companyID) {
// // //         // Apply offset manually
// // //         if offset > 0 {
// // //             offset--
// // //             continue
// // //         }
        
// // //         c, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // //         if err == nil {
// // //             companies = append(companies, c)
// // //         }
        
// // //         if len(companies) >= limit {
// // //             break
// // //         }
// // //     }

// // //     if err := iter.Close(); err != nil {
// // //         return nil, fmt.Errorf("failed to iterate companies by name: %w", err)
// // //     }

// // //     return companies, nil
// // // }

// // // // Efficient fallback for complex filters
// // // func (r *CompanyRepositoryImpl) listCompaniesEfficientFallback(ctx context.Context, filter models.CompanyFilter, limit, offset int) ([]*models.Company, error) {
// // //     // Build query carefully to avoid performance issues
// // //     var clauses []string
// // //     var params []interface{}

// // //     baseQuery := "SELECT company_id FROM companies"

// // //     // Add filters selectively - only use filters that are truly needed
// // //     if filter.SubscriptionTier != "" {
// // //         clauses = append(clauses, "subscription_tier = ?")
// // //         params = append(params, filter.SubscriptionTier)
// // //     }

// // //     if filter.Status != "" {
// // //         switch filter.Status {
// // //         case models.SubscriptionStatusActive:
// // //             clauses = append(clauses, "is_active = true AND is_blocked = false")
// // //         case models.SubscriptionStatusCompanyBlocked:
// // //             clauses = append(clauses, "is_blocked = true")
// // //         case models.SubscriptionStatusCompanyInactive:
// // //             clauses = append(clauses, "is_active = false")
// // //         }
// // //     }

// // //     // Only use ALLOW FILTERING if absolutely necessary
// // //     if len(clauses) > 0 {
// // //         baseQuery += " WHERE " + strings.Join(clauses, " AND ")
// // //         // Add ALLOW FILTERING only for complex multi-column filters
// // //         if len(clauses) > 1 {
// // //             baseQuery += " ALLOW FILTERING"
// // //         }
// // //     }

// // //     baseQuery += " LIMIT ?"
// // //     params = append(params, limit)

// // //     query := r.client.Session.Query(baseQuery, params...)
// // //     iter := query.WithContext(ctx).Iter()
// // //     defer iter.Close()

// // //     var companies []*models.Company
// // //     var companyID gocql.UUID
    
// // //     for iter.Scan(&companyID) {
// // //         // Apply offset manually
// // //         if offset > 0 {
// // //             offset--
// // //             continue
// // //         }
        
// // //         c, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // //         if err == nil {
// // //             companies = append(companies, c)
// // //         }
        
// // //         if len(companies) >= limit {
// // //             break
// // //         }
// // //     }

// // //     if err := iter.Close(); err != nil {
// // //         return nil, fmt.Errorf("failed to iterate companies in fallback: %w", err)
// // //     }

// // //     return companies, nil
// // // }

// // // // Helper method to get total count
// // // func (r *CompanyRepositoryImpl) getCompaniesCount(ctx context.Context, filter models.CompanyFilter) (int, error) {
// // //     // For complex filters, we might need to use a different counting strategy
// // //     // For now, use a simple count that works for most cases
// // //     query := r.client.Session.Query("SELECT COUNT(*) FROM companies")
    
// // //     var count int64
// // //     if err := query.WithContext(ctx).Scan(&count); err != nil {
// // //         return 0, fmt.Errorf("failed to count companies: %w", err)
// // //     }
    
// // //     return int(count), nil
// // // }

// // // func (r *CompanyRepositoryImpl) ListCompaniesWithPaging(ctx context.Context, filter models.CompanyFilter, pageSize int, pageState []byte) ([]*models.Company, []byte, error) {
// // // 	// Choose the best view based on filters
// // // 	var query *gocql.Query
	
// // // 	if filter.SubscriptionTier != "" && filter.Status == "" {
// // // 		if filter.NameContains != "" {
// // // 			query = r.client.Session.Query(`
// // // 				SELECT company_id FROM companies_by_tier 
// // // 				WHERE subscription_tier = ? AND company_name LIKE ?`,
// // // 				filter.SubscriptionTier, "%"+strings.ToLower(filter.NameContains)+"%",
// // // 			)
// // // 		} else {
// // // 			query = r.client.Session.Query(`
// // // 				SELECT company_id FROM companies_by_tier 
// // // 				WHERE subscription_tier = ?`,
// // // 				filter.SubscriptionTier,
// // // 			)
// // // 		}
// // // 	} else if filter.Status != "" && r.canUseStatusView(filter.Status) {
// // // 		isActive, isBlocked := r.getStatusFlags(filter.Status)
// // // 		if filter.NameContains != "" {
// // // 			query = r.client.Session.Query(`
// // // 				SELECT company_id FROM companies_by_active_status 
// // // 				WHERE is_active = ? AND is_blocked = ? AND company_name LIKE ?`,
// // // 				isActive, isBlocked, "%"+strings.ToLower(filter.NameContains)+"%",
// // // 			)
// // // 		} else if filter.SubscriptionTier != "" {
// // // 			query = r.client.Session.Query(`
// // // 				SELECT company_id FROM companies_by_active_status 
// // // 				WHERE is_active = ? AND is_blocked = ? AND subscription_tier = ?`,
// // // 				isActive, isBlocked, filter.SubscriptionTier,
// // // 			)
// // // 		} else {
// // // 			query = r.client.Session.Query(`
// // // 				SELECT company_id FROM companies_by_active_status 
// // // 				WHERE is_active = ? AND is_blocked = ?`,
// // // 				isActive, isBlocked,
// // // 			)
// // // 		}
// // // 	} else {
// // // 		// Use base table with filtering for complex queries
// // // 		var clauses []string
// // // 		var params []interface{}

// // // 		baseQuery := "SELECT company_id FROM companies"

// // // 		if filter.NameContains != "" {
// // // 			clauses = append(clauses, "company_name LIKE ?")
// // // 			params = append(params, "%"+strings.ToLower(filter.NameContains)+"%")
// // // 		}
// // // 		if filter.SubscriptionTier != "" {
// // // 			clauses = append(clauses, "subscription_tier = ?")
// // // 			params = append(params, filter.SubscriptionTier)
// // // 		}
		
// // // 		if len(clauses) > 0 {
// // // 			baseQuery += " WHERE " + strings.Join(clauses, " AND ")
// // // 		}
// // // 		baseQuery += " ALLOW FILTERING"
		
// // // 		query = r.client.Session.Query(baseQuery, params...)
// // // 	}

// // // 	// Apply pagination
// // // 	if pageSize > 0 {
// // // 		query = query.PageSize(pageSize)
// // // 	}
// // // 	if pageState != nil {
// // // 		query = query.PageState(pageState)
// // // 	}

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	defer iter.Close()

// // // 	var companies []*models.Company
// // // 	var companyID gocql.UUID
	
// // // 	for iter.Scan(&companyID) {
// // // 		c, err := r.GetCompany(ctx, uuid.UUID(companyID))
// // // 		if err == nil {
// // // 			companies = append(companies, c)
// // // 		}
// // // 	}

// // // 	nextPageState := iter.PageState()
// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, nil, fmt.Errorf("failed to iterate companies: %w", err)
// // // 	}

// // // 	return companies, nextPageState, nil
// // // }

// // // func (r *CompanyRepositoryImpl) canUseStatusView(status string) bool {
// // // 	switch status {
// // // 	case models.SubscriptionStatusActive, models.SubscriptionStatusCompanyBlocked, models.SubscriptionStatusCompanyInactive:
// // // 		return true
// // // 	default:
// // // 		return false
// // // 	}
// // // }

// // // func (r *CompanyRepositoryImpl) getStatusFlags(status string) (bool, bool) {
// // // 	switch status {
// // // 	case models.SubscriptionStatusActive:
// // // 		return true, false
// // // 	case models.SubscriptionStatusCompanyBlocked:
// // // 		return true, true
// // // 	case models.SubscriptionStatusCompanyInactive:
// // // 		return false, false
// // // 	default:
// // // 		return true, false
// // // 	}
// // // }

// // // func (r *CompanyRepositoryImpl) BlockCompany(ctx context.Context, companyID uuid.UUID, reason string, blockedBy uuid.UUID, blockedAt time.Time) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// // // 		true, reason, gocql.UUID(blockedBy), blockedAt, time.Now().UTC(), gocql.UUID(companyID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) UnblockCompany(ctx context.Context, companyID uuid.UUID) error {
// // // 	now := time.Now().UTC()
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE companies SET is_blocked = ?, blocked_reason = ?, blocked_by = ?, blocked_at = ?, updated_at = ? WHERE company_id = ?`,
// // // 		false, nil, nil, nil, now, gocql.UUID(companyID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier string, premium float64, maxEmployees int, updatedAt time.Time) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE companies SET subscription_tier = ?, monthly_premium = ?, max_employees = ?, updated_at = ? WHERE company_id = ?`,
// // // 		tier, premium, maxEmployees, updatedAt, gocql.UUID(companyID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateSubscriptionEndDate(ctx context.Context, companyID uuid.UUID, endDate time.Time) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE companies SET subscription_end_date = ?, updated_at = ? WHERE company_id = ?`,
// // // 		endDate, time.Now().UTC(), gocql.UUID(companyID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE companies SET is_active = ?, updated_at = ? WHERE company_id = ?`,
// // // 		isActive, time.Now().UTC(), gocql.UUID(companyID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // // ============================================================
// // // // Department Operations (NEW)
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// // // 	query := r.client.Session.Query(`
// // // 		INSERT INTO company_departments (
// // // 			company_id, department_id, department_name, department_head, 
// // // 			permissions, is_active, created_at, updated_at
// // // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
// // // 		gocql.UUID(department.CompanyID),
// // // 		gocql.UUID(department.DepartmentID),
// // // 		department.DepartmentName,
// // // 		gocql.UUID(department.DepartmentHead),
// // // 		department.Permissions,
// // // 		department.IsActive,
// // // 		department.CreatedAt,
// // // 		department.UpdatedAt,
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, companyID, departmentID uuid.UUID) (*models.CompanyDepartment, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT company_id, department_id, department_name, department_head, 
// // // 		       permissions, is_active, created_at, updated_at
// // // 		FROM company_departments WHERE company_id = ? AND department_id = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(departmentID),
// // // 	)

// // // 	var (
// // // 		scCompanyID    gocql.UUID
// // // 		scDepartmentID gocql.UUID
// // // 		scDeptHead     gocql.UUID
// // // 		department     models.CompanyDepartment
// // // 	)

// // // 	err := query.WithContext(ctx).Scan(
// // // 		&scCompanyID, &scDepartmentID, &department.DepartmentName, &scDeptHead,
// // // 		&department.Permissions, &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
// // // 	)

// // // 	if err != nil {
// // // 		if err == gocql.ErrNotFound {
// // // 			return nil, fmt.Errorf("department not found")
// // // 		}
// // // 		return nil, fmt.Errorf("failed to get department: %w", err)
// // // 	}

// // // 	department.CompanyID = uuid.UUID(scCompanyID)
// // // 	department.DepartmentID = uuid.UUID(scDepartmentID)
// // // 	department.DepartmentHead = uuid.UUID(scDeptHead)
// // // 	return &department, nil
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.CompanyDepartment) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE company_departments SET 
// // // 			department_name = ?, department_head = ?, permissions = ?, 
// // // 			is_active = ?, updated_at = ?
// // // 		WHERE company_id = ? AND department_id = ?`,
// // // 		department.DepartmentName,
// // // 		gocql.UUID(department.DepartmentHead),
// // // 		department.Permissions,
// // // 		department.IsActive,
// // // 		department.UpdatedAt,
// // // 		gocql.UUID(department.CompanyID),
// // // 		gocql.UUID(department.DepartmentID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) ListDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.CompanyDepartment, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT department_id FROM company_departments 
// // // 		WHERE company_id = ? AND is_active = true LIMIT ?`,
// // // 		gocql.UUID(companyID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var deptID gocql.UUID
// // // 	var departments []*models.CompanyDepartment

// // // 	for iter.Scan(&deptID) {
// // // 		dept, err := r.GetDepartment(ctx, companyID, uuid.UUID(deptID))
// // // 		if err == nil && dept != nil {
// // // 			departments = append(departments, dept)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to iterate departments: %w", err)
// // // 	}

// // // 	return departments, nil
// // // }

// // // func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, companyID, departmentID uuid.UUID) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE company_departments SET is_active = false, updated_at = ?
// // // 		WHERE company_id = ? AND department_id = ?`,
// // // 		time.Now().UTC(), gocql.UUID(companyID), gocql.UUID(departmentID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // // ============================================================
// // // // Employee Operations
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) CreateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// // // 	query := r.client.Session.Query(`
// // // 		INSERT INTO company_employees (
// // // 			company_id, user_id, employee_id, role_id, department_id,
// // // 			hire_date, is_active, reports_to, created_at, updated_at
// // // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // // 		gocql.UUID(employee.CompanyID),
// // // 		gocql.UUID(employee.UserID),
// // // 		employee.EmployeeID,
// // // 		gocql.UUID(employee.RoleID),
// // // 		gocql.UUID(employee.DepartmentID),
// // // 		employee.HireDate,
// // // 		employee.IsActive,
// // // 		gocql.UUID(employee.ReportsTo),
// // // 		employee.CreatedAt,
// // // 		employee.UpdatedAt,
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetCompanyEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT company_id, user_id, employee_id, role_id, department_id, hire_date, is_active, reports_to, created_at, updated_at
// // // 		FROM company_employees WHERE company_id = ? AND user_id = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(userID),
// // // 	)
// // // 	var (
// // // 		scCompanyID gocql.UUID
// // // 		scUserID    gocql.UUID
// // // 		emp         models.CompanyEmployee
// // // 		scRoleID    gocql.UUID
// // // 		scDeptID    gocql.UUID
// // // 		scReportsTo gocql.UUID
// // // 	)
// // // 	err := query.WithContext(ctx).Scan(
// // // 		&scCompanyID, &scUserID, &emp.EmployeeID, &scRoleID, &scDeptID, &emp.HireDate, &emp.IsActive, &scReportsTo, &emp.CreatedAt, &emp.UpdatedAt,
// // // 	)
// // // 	if err != nil {
// // // 		if err == gocql.ErrNotFound {
// // // 			return nil, nil
// // // 		}
// // // 		return nil, fmt.Errorf("failed to get company employee: %w", err)
// // // 	}

// // // 	emp.CompanyID = uuid.UUID(scCompanyID)
// // // 	emp.UserID = uuid.UUID(scUserID)
// // // 	emp.RoleID = uuid.UUID(scRoleID)
// // // 	emp.DepartmentID = uuid.UUID(scDeptID)
// // // 	if scReportsTo != (gocql.UUID{}) {
// // // 		emp.ReportsTo = uuid.UUID(scReportsTo)
// // // 	}
// // // 	return &emp, nil
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateCompanyEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE company_employees SET 
// // // 			employee_id = ?, role_id = ?, department_id = ?, 
// // // 			reports_to = ?, is_active = ?, updated_at = ?
// // // 		WHERE company_id = ? AND user_id = ?`,
// // // 		employee.EmployeeID,
// // // 		gocql.UUID(employee.RoleID),
// // // 		gocql.UUID(employee.DepartmentID),
// // // 		gocql.UUID(employee.ReportsTo),
// // // 		employee.IsActive,
// // // 		employee.UpdatedAt,
// // // 		gocql.UUID(employee.CompanyID),
// // // 		gocql.UUID(employee.UserID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) ListEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT user_id FROM company_employees WHERE company_id = ? LIMIT ?`,
// // // 		gocql.UUID(companyID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var uid gocql.UUID
// // // 	var employees []*models.CompanyEmployee

// // // 	for iter.Scan(&uid) {
// // // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // // 		if err == nil && e != nil {
// // // 			employees = append(employees, e)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, 0, fmt.Errorf("failed to list employees: %w", err)
// // // 	}

// // // 	return employees, len(employees), nil
// // // }

// // // func (r *CompanyRepositoryImpl) ListEmployeesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT user_id FROM company_employees 
// // // 		WHERE company_id = ? AND department_id = ? AND is_active = true LIMIT ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var uid gocql.UUID
// // // 	var employees []*models.CompanyEmployee

// // // 	for iter.Scan(&uid) {
// // // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // // 		if err == nil && e != nil && e.IsActive {
// // // 			employees = append(employees, e)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to list employees by department: %w", err)
// // // 	}

// // // 	return employees, nil
// // // }

// // // func (r *CompanyRepositoryImpl) ListEmployeesByRole(ctx context.Context, companyID, roleID uuid.UUID, limit int) ([]*models.CompanyEmployee, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT user_id FROM company_employees 
// // // 		WHERE company_id = ? AND role_id = ? AND is_active = true LIMIT ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(roleID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var uid gocql.UUID
// // // 	var employees []*models.CompanyEmployee

// // // 	for iter.Scan(&uid) {
// // // 		e, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // // 		if err == nil && e != nil && e.IsActive {
// // // 			employees = append(employees, e)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to list employees by role: %w", err)
// // // 	}

// // // 	return employees, nil
// // // }

// // // func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// // // 	query := r.client.Session.Query(`SELECT COUNT(*) FROM company_employees WHERE company_id = ?`, gocql.UUID(companyID))
// // // 	var cnt int64
// // // 	if err := query.WithContext(ctx).Scan(&cnt); err != nil {
// // // 		return 0, fmt.Errorf("failed to count employees: %w", err)
// // // 	}
// // // 	return int(cnt), nil
// // // }

// // // func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE company_employees SET is_active = false, updated_at = ?
// // // 		WHERE company_id = ? AND user_id = ?`,
// // // 		time.Now().UTC(),
// // // 		gocql.UUID(companyID),
// // // 		gocql.UUID(userID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE company_employees SET is_active = true, updated_at = ?
// // // 		WHERE company_id = ? AND user_id = ?`,
// // // 		time.Now().UTC(),
// // // 		gocql.UUID(companyID),
// // // 		gocql.UUID(userID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT COUNT(*) FROM company_employees 
// // // 		WHERE company_id = ? AND is_active = true`,
// // // 		gocql.UUID(companyID),
// // // 	)
// // // 	var count int64
// // // 	if err := query.WithContext(ctx).Scan(&count); err != nil {
// // // 		return 0, fmt.Errorf("failed to count active employees: %w", err)
// // // 	}
// // // 	return int(count), nil
// // // }

// // // func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, page, limit int) ([]*models.CompanyEmployee, int, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT user_id FROM company_employees 
// // // 		WHERE company_id = ? AND is_active = true 
// // // 		LIMIT ?`,
// // // 		gocql.UUID(companyID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var uid gocql.UUID
// // // 	var employeeIDs []uuid.UUID

// // // 	for iter.Scan(&uid) {
// // // 		employeeIDs = append(employeeIDs, uuid.UUID(uid))
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, 0, fmt.Errorf("failed to list active employees: %w", err)
// // // 	}

// // // 	// Get employee details
// // // 	var employees []*models.CompanyEmployee
// // // 	for _, userID := range employeeIDs {
// // // 		emp, err := r.GetCompanyEmployee(ctx, companyID, userID)
// // // 		if err == nil && emp != nil && emp.IsActive {
// // // 			employees = append(employees, emp)
// // // 		}
// // // 	}

// // // 	return employees, len(employees), nil
// // // }

// // // // ============================================================
// // // // Role Operations (ENHANCED)
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) CreateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// // // 	query := r.client.Session.Query(`
// // // 		INSERT INTO employee_roles (
// // // 			company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// // // 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
// // // 		gocql.UUID(role.CompanyID),
// // // 		gocql.UUID(role.RoleID),
// // // 		role.RoleName,
// // // 		role.RoleLevel,
// // // 		role.Permissions,
// // // 		gocql.UUID(role.DepartmentID),
// // // 		role.IsSystemRole,
// // // 		role.CreatedAt,
// // // 		role.UpdatedAt,
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) (*models.EmployeeRole, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT company_id, role_id, role_name, role_level, permissions, department_id, is_system_role, created_at, updated_at
// // // 		FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(roleID),
// // // 	)
// // // 	var (
// // // 		scCompanyID gocql.UUID
// // // 		scRoleID    gocql.UUID
// // // 		role        models.EmployeeRole
// // // 		scDeptID    gocql.UUID
// // // 	)
// // // 	err := query.WithContext(ctx).Scan(&scCompanyID, &scRoleID, &role.RoleName, &role.RoleLevel, &role.Permissions, &scDeptID, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt)
// // // 	if err != nil {
// // // 		if err == gocql.ErrNotFound {
// // // 			return nil, fmt.Errorf("role not found")
// // // 		}
// // // 		return nil, fmt.Errorf("failed to get employee role: %w", err)
// // // 	}
// // // 	role.CompanyID = uuid.UUID(scCompanyID)
// // // 	role.RoleID = uuid.UUID(scRoleID)
// // // 	role.DepartmentID = uuid.UUID(scDeptID)
// // // 	return &role, nil
// // // }

// // // func (r *CompanyRepositoryImpl) GetEmployeeRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel string) (*models.EmployeeRole, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT role_id FROM employee_roles 
// // // 		WHERE company_id = ? AND role_level = ? LIMIT 1`,
// // // 		gocql.UUID(companyID), roleLevel,
// // // 	)

// // // 	var roleID gocql.UUID
// // // 	if err := query.WithContext(ctx).Scan(&roleID); err != nil {
// // // 		if err == gocql.ErrNotFound {
// // // 			return nil, fmt.Errorf("role level not found: %s", roleLevel)
// // // 		}
// // // 		return nil, fmt.Errorf("failed to get role by level: %w", err)
// // // 	}

// // // 	return r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // // }

// // // func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, role *models.EmployeeRole) error {
// // // 	query := r.client.Session.Query(`
// // // 		UPDATE employee_roles SET 
// // // 			role_name = ?, role_level = ?, permissions = ?, department_id = ?,
// // // 			is_system_role = ?, updated_at = ?
// // // 		WHERE company_id = ? AND role_id = ?`,
// // // 		role.RoleName,
// // // 		role.RoleLevel,
// // // 		role.Permissions,
// // // 		gocql.UUID(role.DepartmentID),
// // // 		role.IsSystemRole,
// // // 		role.UpdatedAt,
// // // 		gocql.UUID(role.CompanyID),
// // // 		gocql.UUID(role.RoleID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) ListEmployeeRoles(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT role_id FROM employee_roles WHERE company_id = ? LIMIT ?`,
// // // 		gocql.UUID(companyID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var roleID gocql.UUID
// // // 	var roles []*models.EmployeeRole

// // // 	for iter.Scan(&roleID) {
// // // 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // // 		if err == nil && role != nil {
// // // 			roles = append(roles, role)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to list employee roles: %w", err)
// // // 	}

// // // 	return roles, nil
// // // }

// // // func (r *CompanyRepositoryImpl) ListEmployeeRolesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, limit int) ([]*models.EmployeeRole, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	query := r.client.Session.Query(`
// // // 		SELECT role_id FROM employee_roles 
// // // 		WHERE company_id = ? AND department_id = ? LIMIT ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(departmentID), limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var roleID gocql.UUID
// // // 	var roles []*models.EmployeeRole

// // // 	for iter.Scan(&roleID) {
// // // 		role, err := r.GetEmployeeRole(ctx, companyID, uuid.UUID(roleID))
// // // 		if err == nil && role != nil {
// // // 			roles = append(roles, role)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to list employee roles by department: %w", err)
// // // 	}

// // // 	return roles, nil
// // // }

// // // func (r *CompanyRepositoryImpl) DeleteEmployeeRole(ctx context.Context, companyID, roleID uuid.UUID) error {
// // // 	query := r.client.Session.Query(`
// // // 		DELETE FROM employee_roles WHERE company_id = ? AND role_id = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(roleID),
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // // ============================================================
// // // // Permission Operations (ENHANCED)
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) GetEmployeePermissions(ctx context.Context, companyID, userID uuid.UUID) ([]string, error) {
// // // 	query := r.client.Session.Query(`
// // // 		SELECT permission FROM employee_permissions WHERE company_id = ? AND user_id = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(userID),
// // // 	)
// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var perm string
// // // 	perms := make([]string, 0)
// // // 	for iter.Scan(&perm) {
// // // 		perms = append(perms, perm)
// // // 	}
// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to iterate permissions: %w", err)
// // // 	}
// // // 	return perms, nil
// // // }

// // // func (r *CompanyRepositoryImpl) GrantEmployeePermission(ctx context.Context, permission *models.EmployeePermission) error {
// // // 	query := r.client.Session.Query(`
// // // 		INSERT INTO employee_permissions (
// // // 			company_id, user_id, permission, granted_by, granted_at, expires_at
// // // 		) VALUES (?, ?, ?, ?, ?, ?)`,
// // // 		gocql.UUID(permission.CompanyID),
// // // 		gocql.UUID(permission.UserID),
// // // 		permission.Permission,
// // // 		gocql.UUID(permission.GrantedBy),
// // // 		permission.GrantedAt,
// // // 		permission.ExpiresAt,
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) RevokeEmployeePermission(ctx context.Context, companyID, userID uuid.UUID, permission string) error {
// // // 	query := r.client.Session.Query(`
// // // 		DELETE FROM employee_permissions 
// // // 		WHERE company_id = ? AND user_id = ? AND permission = ?`,
// // // 		gocql.UUID(companyID), gocql.UUID(userID), permission,
// // // 	)
// // // 	return r.client.ExecuteWithRetry(query.WithContext(ctx), 3)
// // // }

// // // func (r *CompanyRepositoryImpl) GetEmployeesWithPermission(ctx context.Context, companyID uuid.UUID, permission string, limit int) ([]*models.CompanyEmployee, error) {
// // // 	if limit <= 0 || limit > 1000 {
// // // 		limit = 100
// // // 	}

// // // 	// First get user IDs with the permission
// // // 	query := r.client.Session.Query(`
// // // 		SELECT user_id FROM employee_permissions 
// // // 		WHERE company_id = ? AND permission = ? LIMIT ?`,
// // // 		gocql.UUID(companyID), permission, limit,
// // // 	)

// // // 	iter := query.WithContext(ctx).Iter()
// // // 	var uid gocql.UUID
// // // 	var employees []*models.CompanyEmployee

// // // 	for iter.Scan(&uid) {
// // // 		emp, err := r.GetCompanyEmployee(ctx, companyID, uuid.UUID(uid))
// // // 		if err == nil && emp != nil && emp.IsActive {
// // // 			employees = append(employees, emp)
// // // 		}
// // // 	}

// // // 	if err := iter.Close(); err != nil {
// // // 		return nil, fmt.Errorf("failed to get employees with permission: %w", err)
// // // 	}

// // // 	return employees, nil
// // // }

// // // // ============================================================
// // // // Health Check
// // // // ============================================================

// // // func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
// // // 	var release string
// // // 	q := r.client.Session.Query(`SELECT release_version FROM system.local`)
// // // 	if err := q.WithContext(ctx).Scan(&release); err != nil {
// // // 		return fmt.Errorf("scylla health check failed: %w", err)
// // // 	}
// // // 	r.logger.Debug("scylla release_version", zap.String("version", release))
// // // 	return nil
// // // }

// // // func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit int) ([]*models.Company, error) {
// // //     filter := models.CompanyFilter{Status: status}
// // //     companies, _, err := r.ListCompanies(ctx, filter, 1, limit)
// // //     return companies, err
// // // }// ❌ REMOVE - Complex filtering logic
// // getCompaniesByTierAndStatusDirect
// // listCompaniesComplexFilter
// // getCompaniesCountOptimized
// // matchesStatus