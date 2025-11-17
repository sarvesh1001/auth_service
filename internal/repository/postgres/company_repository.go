package postgres

import (
	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgtype"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Constants for optimization
const (
	MaxCompanyBatchSize    = 100
	MaxConcurrentCompany   = 50
	DefaultCompanyPageSize = 100
	CompanyStmtCacheSize   = 30
)

// CompanyRepositoryImpl handles PostgreSQL company and RBAC operations
type CompanyRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
	metrics   struct {
		queryCount int64
		batchCount int64
		errorCount int64
		lastReset  time.Time
		sync.RWMutex
	}
}

// NewCompanyRepository creates a new PostgreSQL company repository
func NewCompanyRepository(postgresClient *client.PostgresClient, logger *zap.Logger) CompanyRepository {
	repo := &CompanyRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt, CompanyStmtCacheSize),
	}

	repo.metrics.lastReset = time.Now()
	go repo.initializePreparedStatements(context.Background())

	return repo
}

// ============================================================================
// COMPANY OPERATIONS - UPDATED FOR NEW FLOW
// ============================================================================

// // CreateCompany creates a new company and automatically creates owner role
// func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company) error {
// 	tx, err := r.client.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("failed to begin transaction: %w", err)
// 	}
// 	defer tx.Rollback()

// 	// 1. Insert company
// 	companyQuery := `
// 		INSERT INTO companies (
// 			company_id, company_name, owner_user_id, subscription_tier,
// 			subscription_status, max_employees, data_region, is_active,
// 			created_at, updated_at, subscription_start_date, subscription_end_date
// 		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

// 	_, err = tx.ExecContext(ctx, companyQuery,
// 		company.CompanyID, company.CompanyName, company.OwnerUserID, company.SubscriptionTier,
// 		company.SubscriptionStatus, company.MaxEmployees, company.DataRegion, company.IsActive,
// 		company.CreatedAt, company.UpdatedAt, company.SubscriptionStartDate, company.SubscriptionEndDate,
// 	)

// 	if err != nil {
// 		r.recordError()
// 		if strings.Contains(err.Error(), "idx_companies_name_owner_unique") ||
// 			strings.Contains(err.Error(), "unique constraint") {
// 			return fmt.Errorf("company with name '%s' already exists for this owner", company.CompanyName)
// 		}
// 		return fmt.Errorf("failed to create company: %w", err)
// 	}

// 	// 2. Create OWNER role for this company
// 	ownerRoleID := uuid.New()
// 	ownerRoleQuery := `
// 		INSERT INTO roles (
// 			role_id, role_name, role_level, company_id, is_system_role,
// 			description, created_at, updated_at
// 		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// 	_, err = tx.ExecContext(ctx, ownerRoleQuery,
// 		ownerRoleID, "Owner", 1000, company.CompanyID, true,
// 		"Company owner with full permissions", company.CreatedAt, company.UpdatedAt,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to create owner role: %w", err)
// 	}

// 	// 3. Grant all permissions to owner role
// 	grantPermissionsQuery := `
// 		INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
// 		SELECT $1, permission_id, $2, $3 FROM permissions
// 		WHERE requires_tier <= $4` // Assuming requires_tier indicates permission level

// 	_, err = tx.ExecContext(ctx, grantPermissionsQuery,
// 		ownerRoleID, company.OwnerUserID, company.CreatedAt, 1000)
// 	if err != nil {
// 		return fmt.Errorf("failed to grant permissions to owner role: %w", err)
// 	}

// 	// 4. Add owner as employee in company_employees
// 	employeeQuery := `
// 		INSERT INTO company_employees (
// 			company_id, user_id, employee_id, role_id,
// 			hire_date, is_active, created_at, updated_at
// 		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// 	_, err = tx.ExecContext(ctx, employeeQuery,
// 		company.CompanyID, company.OwnerUserID, uuid.New().String(), ownerRoleID,
// 		company.CreatedAt, true, company.CreatedAt, company.UpdatedAt,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to add owner as employee: %w", err)
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("failed to commit transaction: %w", err)
// 	}

// 	r.recordQuery()
// 	r.logger.Debug("Company created successfully with owner setup",
// 		util.String("company_id", company.CompanyID.String()),
// 		util.String("company_name", company.CompanyName))
// 	return nil
// }

// GetCompany retrieves a company by ID
func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	query := `
		SELECT company_id, company_name, owner_user_id, subscription_tier,
			   subscription_status, max_employees, data_region, is_active,
			   created_at, updated_at, subscription_start_date, subscription_end_date
		FROM companies WHERE company_id = $1`

	var company models.Company
	var subStartDate, subEndDate sql.NullTime

	err := r.client.QueryRow(ctx, query, companyID).Scan(
		&company.CompanyID, &company.CompanyName, &company.OwnerUserID, &company.SubscriptionTier,
		&company.SubscriptionStatus, &company.MaxEmployees, &company.DataRegion, &company.IsActive,
		&company.CreatedAt, &company.UpdatedAt, &subStartDate, &subEndDate,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("company not found: %s", companyID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get company: %w", err)
	}

	// Handle nullable dates
	if subStartDate.Valid {
		company.SubscriptionStartDate = &subStartDate.Time
	}
	if subEndDate.Valid {
		company.SubscriptionEndDate = &subEndDate.Time
	}

	r.recordQuery()
	return &company, nil
}

// GetCompaniesByOwner retrieves companies owned by a user
func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	query := `
		SELECT company_id, company_name, subscription_tier, subscription_status,
			   max_employees, is_active, created_at
		FROM companies 
		WHERE owner_user_id = $1 AND is_active = true
		ORDER BY created_at DESC`

	rows, err := r.client.Query(ctx, query, ownerUserID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query companies by owner: %w", err)
	}
	defer rows.Close()

	var companies []*models.Company
	for rows.Next() {
		var company models.Company
		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.SubscriptionTier,
			&company.SubscriptionStatus, &company.MaxEmployees, &company.IsActive,
			&company.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company row", util.ErrorField(err))
			continue
		}
		company.OwnerUserID = ownerUserID
		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating company rows: %w", err)
	}

	r.recordQuery()
	return companies, nil
}

// UpdateCompany updates company information
func (r *CompanyRepositoryImpl) UpdateCompany(ctx context.Context, company *models.Company) error {
	company.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE companies SET 
			company_name = $1, subscription_tier = $2, subscription_status = $3,
			max_employees = $4, data_region = $5, is_active = $6, updated_at = $7,
			subscription_start_date = $8, subscription_end_date = $9
		WHERE company_id = $10`

	result, err := r.client.Exec(ctx, query,
		company.CompanyName, company.SubscriptionTier, company.SubscriptionStatus,
		company.MaxEmployees, company.DataRegion, company.IsActive, company.UpdatedAt,
		company.SubscriptionStartDate, company.SubscriptionEndDate, company.CompanyID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update company: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("company not found: %s", company.CompanyID)
	}

	r.recordQuery()
	return nil
}

// UpdateCompanyStatus updates company active status
func (r *CompanyRepositoryImpl) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error {
	query := `UPDATE companies SET is_active = $1, updated_at = $2 WHERE company_id = $3`

	result, err := r.client.Exec(ctx, query, isActive, time.Now().UTC(), companyID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update company status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("company not found: %s", companyID)
	}

	r.recordQuery()
	return nil
}

// UpdateSubscription updates company subscription
func (r *CompanyRepositoryImpl) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int) error {
	query := `
		UPDATE companies SET 
			subscription_tier = $1, subscription_status = $2, 
			max_employees = $3, updated_at = $4
		WHERE company_id = $5`

	result, err := r.client.Exec(ctx, query, tier, status, maxEmployees, time.Now().UTC(), companyID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("company not found: %s", companyID)
	}

	r.recordQuery()
	return nil
}

// GetCompaniesByStatus retrieves companies by status with pagination
func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies WHERE subscription_status = $1`
	err := r.client.QueryRow(ctx, countQuery, status).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count companies by status: %w", err)
	}

	// Get paginated results
	query := `
		SELECT company_id, company_name, owner_user_id, subscription_tier,
			   subscription_status, max_employees, data_region, is_active,
			   created_at, updated_at
		FROM companies 
		WHERE subscription_status = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, status, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query companies by status: %w", err)
	}
	defer rows.Close()

	companies := make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID, &company.SubscriptionTier,
			&company.SubscriptionStatus, &company.MaxEmployees, &company.DataRegion, &company.IsActive,
			&company.CreatedAt, &company.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company row", util.ErrorField(err))
			continue
		}
		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}

	r.recordQuery()
	return companies, totalCount, nil
}

// GetCompaniesByTier retrieves companies by subscription tier
func (r *CompanyRepositoryImpl) GetCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies WHERE subscription_tier = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, tier).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count companies by tier: %w", err)
	}

	// Get paginated results
	query := `
		SELECT company_id, company_name, owner_user_id, subscription_tier,
			   subscription_status, max_employees, data_region, is_active,
			   created_at, updated_at
		FROM companies 
		WHERE subscription_tier = $1 AND is_active = true
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, tier, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query companies by tier: %w", err)
	}
	defer rows.Close()

	companies := make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID, &company.SubscriptionTier,
			&company.SubscriptionStatus, &company.MaxEmployees, &company.DataRegion, &company.IsActive,
			&company.CreatedAt, &company.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company row", util.ErrorField(err))
			continue
		}
		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}

	r.recordQuery()
	return companies, totalCount, nil
}

// GetCompaniesWithExpiringSubscription gets companies with subscriptions expiring soon
func (r *CompanyRepositoryImpl) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}

	expiryDate := time.Now().UTC().AddDate(0, 0, days)

	query := `
		SELECT company_id, company_name, subscription_tier, subscription_status,
			   max_employees, subscription_end_date, created_at
		FROM companies 
		WHERE subscription_end_date <= $1 AND subscription_status = 'active'
		ORDER BY subscription_end_date ASC 
		LIMIT $2`

	rows, err := r.client.Query(ctx, query, expiryDate, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query companies with expiring subscriptions: %w", err)
	}
	defer rows.Close()

	var companies []*models.Company
	for rows.Next() {
		var company models.Company
		var subEndDate sql.NullTime

		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.SubscriptionTier,
			&company.SubscriptionStatus, &company.MaxEmployees, &subEndDate,
			&company.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company row", util.ErrorField(err))
			continue
		}

		if subEndDate.Valid {
			company.SubscriptionEndDate = &subEndDate.Time
		}
		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating company rows: %w", err)
	}

	r.recordQuery()
	return companies, nil
}

// DeactivateCompany deactivates a company with reason
func (r *CompanyRepositoryImpl) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string) error {
	query := `UPDATE companies SET is_active = false, updated_at = $1 WHERE company_id = $2`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to deactivate company: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("company not found: %s", companyID)
	}

	r.recordQuery()
	return nil
}

// DeleteCompany permanently deletes a company (use with caution)
func (r *CompanyRepositoryImpl) DeleteCompany(ctx context.Context, companyID uuid.UUID) error {
	// Note: In production, you might want to soft delete instead
	query := `DELETE FROM companies WHERE company_id = $1`

	result, err := r.client.Exec(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete company: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("company not found: %s", companyID)
	}

	r.recordQuery()
	return nil
}

// ListCompanies lists all companies with pagination
func (r *CompanyRepositoryImpl) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies`
	err := r.client.QueryRow(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count companies: %w", err)
	}

	// Get paginated results
	query := `
        SELECT company_id, company_name, owner_user_id, subscription_tier,
               subscription_status, max_employees, data_region, is_active,
               created_at, updated_at
        FROM companies 
        ORDER BY created_at DESC 
        LIMIT $1 OFFSET $2`

	rows, err := r.client.Query(ctx, query, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query companies: %w", err)
	}
	defer rows.Close()

	companies := make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID, &company.SubscriptionTier,
			&company.SubscriptionStatus, &company.MaxEmployees, &company.DataRegion, &company.IsActive,
			&company.CreatedAt, &company.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan company row", util.ErrorField(err))
			continue
		}
		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}

	r.recordQuery()
	return companies, totalCount, nil
}

// CheckCompanyExists checks if a company with the same name and owner already exists
func (r *CompanyRepositoryImpl) CheckCompanyExists(ctx context.Context, companyName string, ownerUserID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM companies WHERE company_name = $1 AND owner_user_id = $2 AND is_active = true`

	var exists bool
	err := r.client.QueryRow(ctx, query, companyName, ownerUserID).Scan(&exists)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to check company existence: %w", err)
	}

	r.recordQuery()
	return exists, nil
}

// ============================================================================
// SYSTEM DEPARTMENT OPERATIONS - NEW
// ============================================================================

// GetSystemDepartments retrieves all global system departments
func (r *CompanyRepositoryImpl) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	query := `
		SELECT system_department_id, name, module_code, description
		FROM system_departments 
		ORDER BY name`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query system departments: %w", err)
	}
	defer rows.Close()

	var systemDepartments []*models.SystemDepartment
	for rows.Next() {
		var dept models.SystemDepartment
		err := rows.Scan(
			&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
		)
		if err != nil {
			r.logger.Warn("Failed to scan system department row", util.ErrorField(err))
			continue
		}
		systemDepartments = append(systemDepartments, &dept)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}

	r.recordQuery()
	return systemDepartments, nil
}

// GetSystemDepartmentByModule retrieves system department by module
func (r *CompanyRepositoryImpl) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	query := `
		SELECT system_department_id, name, module_code, description
		FROM system_departments 
		WHERE module_code = $1
		LIMIT 1`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, module).Scan(
		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("system department not found for module: %s", module)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get system department: %w", err)
	}

	r.recordQuery()
	return &dept, nil
}

// ============================================================================
// DEPARTMENT OPERATIONS - UPDATED FOR NEW FLOW
// ============================================================================

// CreateDepartment creates a new department linked to a system department
func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.Department) error {
	query := `
		INSERT INTO departments (
			department_id, company_id, department_name, system_department_id,
			department_head, parent_department_id, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.client.Exec(ctx, query,
		department.DepartmentID, department.CompanyID, department.DepartmentName,
		department.SystemDepartmentID, department.DepartmentHead, department.ParentDepartmentID,
		department.IsActive, department.CreatedAt, department.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create department: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetDepartment retrieves a department by ID with system department info
func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
	query := `
		SELECT d.department_id, d.company_id, d.department_name, d.system_department_id,
			   sd.name as system_department_name, sd.module_code,
			   d.department_head, d.parent_department_id, d.is_active, 
			   d.created_at, d.updated_at
		FROM departments d
		LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		WHERE d.department_id = $1`

	var department models.Department
	var deptHead, parentDeptID sql.NullString
	var systemDeptID sql.NullString
	var systemDeptName, moduleCode sql.NullString

	err := r.client.QueryRow(ctx, query, departmentID).Scan(
		&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
		&systemDeptID, &systemDeptName, &moduleCode,
		&deptHead, &parentDeptID, &department.IsActive,
		&department.CreatedAt, &department.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("department not found: %s", departmentID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get department: %w", err)
	}

	// Handle nullable fields
	if deptHead.Valid {
		headID, _ := uuid.Parse(deptHead.String)
		department.DepartmentHead = &headID
	}
	if parentDeptID.Valid {
		parentID, _ := uuid.Parse(parentDeptID.String)
		department.ParentDepartmentID = &parentID
	}
	if systemDeptID.Valid {
		systemID, _ := uuid.Parse(systemDeptID.String)
		department.SystemDepartmentID = &systemID
	}
	if systemDeptName.Valid {
		department.SystemDepartmentName = systemDeptName.String
	}
	if moduleCode.Valid {
		department.ModuleCode = moduleCode.String
	}

	r.recordQuery()
	return &department, nil
}

// GetDepartmentsByCompany retrieves departments for a company
func (r *CompanyRepositoryImpl) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM departments WHERE company_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count departments: %w", err)
	}

	// Get paginated results
	query := `
		SELECT department_id, department_name, department_head,
			   parent_department_id, created_at, updated_at
		FROM departments 
		WHERE company_id = $1 AND is_active = true
		ORDER BY department_name ASC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query departments: %w", err)
	}
	defer rows.Close()

	departments := make([]*models.Department, 0, limit)
	for rows.Next() {
		var department models.Department
		var deptHead, parentDeptID sql.NullString

		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName,
			&deptHead, &parentDeptID, &department.CreatedAt, &department.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}

		department.CompanyID = companyID
		department.IsActive = true

		// Handle nullable UUIDs
		if deptHead.Valid {
			headID, _ := uuid.Parse(deptHead.String)
			department.DepartmentHead = &headID
		}
		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			department.ParentDepartmentID = &parentID
		}

		departments = append(departments, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating department rows: %w", err)
	}

	r.recordQuery()
	return departments, totalCount, nil
}

// UpdateDepartment updates department information
func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.Department) error {
	department.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE departments SET 
			department_name = $1, department_head = $2, 
			parent_department_id = $3, is_active = $4, updated_at = $5
		WHERE department_id = $6`

	result, err := r.client.Exec(ctx, query,
		department.DepartmentName, department.DepartmentHead, department.ParentDepartmentID,
		department.IsActive, department.UpdatedAt, department.DepartmentID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update department: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found: %s", department.DepartmentID)
	}

	r.recordQuery()
	return nil
}

// DeactivateDepartment deactivates a department
func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, departmentID uuid.UUID) error {
	query := `UPDATE departments SET is_active = false, updated_at = $1 WHERE department_id = $2`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to deactivate department: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found: %s", departmentID)
	}

	r.recordQuery()
	return nil
}

// GetDepartmentHierarchy retrieves department hierarchy for a company
func (r *CompanyRepositoryImpl) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	query := `
        WITH RECURSIVE dept_tree AS (
            SELECT department_id, department_name, department_head, 
                   parent_department_id, is_active, created_at, updated_at,
                   1 as level
            FROM departments 
            WHERE company_id = $1 AND parent_department_id IS NULL AND is_active = true
            
            UNION ALL
            
            SELECT d.department_id, d.department_name, d.department_head,
                   d.parent_department_id, d.is_active, d.created_at, d.updated_at,
                   dt.level + 1
            FROM departments d
            INNER JOIN dept_tree dt ON d.parent_department_id = dt.department_id
            WHERE d.company_id = $1 AND d.is_active = true
        )
        SELECT department_id, department_name, department_head,
               parent_department_id, is_active, level
        FROM dept_tree
        ORDER BY level, department_name`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query department hierarchy: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var department models.Department
		var deptHead, parentDeptID sql.NullString
		var level int

		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName,
			&deptHead, &parentDeptID, &department.IsActive, &level,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}

		department.CompanyID = companyID

		// Handle nullable UUIDs
		if deptHead.Valid {
			headID, _ := uuid.Parse(deptHead.String)
			department.DepartmentHead = &headID
		}
		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			department.ParentDepartmentID = &parentID
		}

		departments = append(departments, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}

	r.recordQuery()
	return departments, nil
}

// GetDepartmentLoad gets employee count per department
func (r *CompanyRepositoryImpl) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	query := `
        SELECT d.department_name, COUNT(ce.user_id) as employee_count
        FROM departments d
        LEFT JOIN company_employees ce ON d.department_id = ce.department_id AND ce.is_active = true
        WHERE d.company_id = $1 AND d.is_active = true
        GROUP BY d.department_id, d.department_name
        ORDER BY employee_count DESC`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query department load: %w", err)
	}
	defer rows.Close()

	departmentLoad := make(map[string]int)
	for rows.Next() {
		var departmentName string
		var count int
		err := rows.Scan(&departmentName, &count)
		if err != nil {
			continue
		}
		departmentLoad[departmentName] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department load rows: %w", err)
	}

	r.recordQuery()
	return departmentLoad, nil
}

// ============================================================================
// ROLE-DEPARTMENT MAPPING OPERATIONS - NEW
// ============================================================================

// CreateRoleDepartment maps a role to a department
func (r *CompanyRepositoryImpl) CreateRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `
		INSERT INTO role_departments (role_id, department_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, department_id) DO NOTHING`

	_, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to map role to department: %w", err)
	}

	r.recordQuery()
	return nil
}

// RemoveRoleDepartment removes a role from a department
func (r *CompanyRepositoryImpl) RemoveRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `DELETE FROM role_departments WHERE role_id = $1 AND department_id = $2`

	result, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to remove role from department: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("role department mapping not found")
	}

	r.recordQuery()
	return nil
}

// GetRoleDepartments gets all departments for a role
func (r *CompanyRepositoryImpl) GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	query := `
		SELECT d.department_id, d.department_name, d.system_department_id,
			   sd.name as system_department_name, sd.module_code
		FROM role_departments rd
		INNER JOIN departments d ON rd.department_id = d.department_id
		LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		WHERE rd.role_id = $1 AND d.is_active = true`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query role departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var department models.Department
		var systemDeptID sql.NullString
		var systemDeptName, moduleCode sql.NullString

		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName, &systemDeptID,
			&systemDeptName, &moduleCode,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}

		if systemDeptID.Valid {
			systemID, _ := uuid.Parse(systemDeptID.String)
			department.SystemDepartmentID = &systemID
		}
		if systemDeptName.Valid {
			department.SystemDepartmentName = systemDeptName.String
		}
		if moduleCode.Valid {
			department.ModuleCode = moduleCode.String
		}

		departments = append(departments, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}

	r.recordQuery()
	return departments, nil
}

// ============================================================================
// ROLE & PERMISSION OPERATIONS - UPDATED
// ============================================================================

// CreateRole creates a new role and optionally maps to departments
func (r *CompanyRepositoryImpl) CreateRole(ctx context.Context, role *models.Role, departmentIDs []uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Create role
	roleQuery := `
		INSERT INTO roles (
			role_id, role_name, role_level, company_id, is_system_role,
			description, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = tx.ExecContext(ctx, roleQuery,
		role.RoleID, role.RoleName, role.RoleLevel, role.CompanyID,
		role.IsSystemRole, role.Description, role.CreatedAt, role.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create role: %w", err)
	}

	// 2. Map role to departments
	if len(departmentIDs) > 0 {
		for _, deptID := range departmentIDs {
			_, err = tx.ExecContext(ctx,
				"INSERT INTO role_departments (role_id, department_id) VALUES ($1, $2)",
				role.RoleID, deptID,
			)
			if err != nil {
				return fmt.Errorf("failed to map role to department %s: %w", deptID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetRole retrieves a role by ID
func (r *CompanyRepositoryImpl) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	query := `
		SELECT role_id, role_name, role_level, company_id, is_system_role,
			   description, created_at, updated_at
		FROM roles WHERE role_id = $1`

	var role models.Role
	err := r.client.QueryRow(ctx, query, roleID).Scan(
		&role.RoleID, &role.RoleName, &role.RoleLevel, &role.CompanyID,
		&role.IsSystemRole, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found: %s", roleID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	r.recordQuery()
	return &role, nil
}

// GetRolesByCompany retrieves roles for a company
func (r *CompanyRepositoryImpl) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM roles WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	// Get paginated results
	query := `
		SELECT role_id, role_name, role_level, is_system_role,
			   description, created_at, updated_at
		FROM roles 
		WHERE company_id = $1
		ORDER BY role_level ASC, created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close()

	roles := make([]*models.Role, 0, limit)
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.RoleID, &role.RoleName, &role.RoleLevel, &role.IsSystemRole,
			&role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan role row", util.ErrorField(err))
			continue
		}
		role.CompanyID = companyID
		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating role rows: %w", err)
	}

	r.recordQuery()
	return roles, totalCount, nil
}

// GetSystemRoleByLevel retrieves system role by level
func (r *CompanyRepositoryImpl) GetSystemRoleByLevel(ctx context.Context, companyID uuid.UUID, roleLevel int) (*models.Role, error) {
	query := `
		SELECT role_id, role_name, role_level, description
		FROM roles 
		WHERE company_id = $1 AND role_level = $2 AND is_system_role = true
		LIMIT 1`

	var role models.Role
	err := r.client.QueryRow(ctx, query, companyID, roleLevel).Scan(
		&role.RoleID, &role.RoleName, &role.RoleLevel, &role.Description,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("system role not found for level %d", roleLevel)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get system role: %w", err)
	}

	role.CompanyID = companyID
	role.IsSystemRole = true

	r.recordQuery()
	return &role, nil
}

// UpdateRole updates role information
func (r *CompanyRepositoryImpl) UpdateRole(ctx context.Context, role *models.Role) error {
	role.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE roles SET 
			role_name = $1, role_level = $2, description = $3, updated_at = $4
		WHERE role_id = $5`

	result, err := r.client.Exec(ctx, query,
		role.RoleName, role.RoleLevel, role.Description, role.UpdatedAt, role.RoleID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("role not found: %s", role.RoleID)
	}

	r.recordQuery()
	return nil
}

// DeleteRole deletes a role (only non-system roles)
func (r *CompanyRepositoryImpl) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	query := `DELETE FROM roles WHERE role_id = $1 AND is_system_role = false`

	result, err := r.client.Exec(ctx, query, roleID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("role not found or is system role: %s", roleID)
	}

	r.recordQuery()
	return nil
}

// GrantRolePermission grants a permission to a role
func (r *CompanyRepositoryImpl) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, permission_id) DO UPDATE SET
			granted_by = EXCLUDED.granted_by,
			granted_at = EXCLUDED.granted_at`

	_, err := r.client.Exec(ctx, query, roleID, permissionID, grantedBy, time.Now().UTC())
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to grant role permission: %w", err)
	}

	r.recordQuery()
	return nil
}

// RevokeRolePermission revokes a permission from a role
func (r *CompanyRepositoryImpl) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`

	result, err := r.client.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to revoke role permission: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("role permission not found")
	}

	r.recordQuery()
	return nil
}

// GetRolePermissions retrieves all permissions for a role
func (r *CompanyRepositoryImpl) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	query := `
		SELECT p.permission_id, p.permission_name, p.description, 
			   p.category, p.module, p.requires_tier, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.category, p.permission_name`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GrantMultipleRolePermissions grants multiple permissions to a role in batch
func (r *CompanyRepositoryImpl) GrantMultipleRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	query := `
        INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
        VALUES `

	values := []interface{}{}
	valuePlaceholders := []string{}
	grantedAt := time.Now().UTC()

	for i, permID := range permissionIDs {
		baseIndex := i * 4 // 4 fields per association
		valuePlaceholders = append(valuePlaceholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d)",
				baseIndex+1, baseIndex+2, baseIndex+3, baseIndex+4))

		values = append(values, roleID, permID, grantedBy, grantedAt)
	}

	query += strings.Join(valuePlaceholders, ", ")
	query += ` ON CONFLICT (role_id, permission_id) DO UPDATE SET
        granted_by = EXCLUDED.granted_by,
        granted_at = EXCLUDED.granted_at`

	_, err := r.client.Exec(ctx, query, values...)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to grant multiple role permissions: %w", err)
	}

	r.recordBatch(int64(len(permissionIDs)))
	r.logger.Debug("Multiple role permissions granted successfully",
		util.String("role_id", roleID.String()),
		util.Int("permissions_count", len(permissionIDs)))
	return nil
}

// RevokeMultipleRolePermissions revokes multiple permissions from a role
func (r *CompanyRepositoryImpl) RevokeMultipleRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(permissionIDs))
	values := []interface{}{roleID}

	for i, permID := range permissionIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		values = append(values, permID)
	}

	query := fmt.Sprintf(
		`DELETE FROM role_permissions 
         WHERE role_id = $1 AND permission_id IN (%s)`,
		strings.Join(placeholders, ", "))

	result, err := r.client.Exec(ctx, query, values...)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to revoke multiple role permissions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.recordBatch(int64(len(permissionIDs)))
	r.logger.Debug("Multiple role permissions revoked successfully",
		util.String("role_id", roleID.String()),
		util.Int64("permissions_revoked", rowsAffected))
	return nil
}

// ReplaceRolePermissions replaces all permissions for a role with new ones
func (r *CompanyRepositoryImpl) ReplaceRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error {
	// Start a transaction using BeginTx with nil options for default behavior
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// First, remove all existing permissions for this role
	deleteQuery := `DELETE FROM role_permissions WHERE role_id = $1`
	_, err = tx.ExecContext(ctx, deleteQuery, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove existing role permissions: %w", err)
	}

	// Then grant the new permissions
	if len(permissionIDs) > 0 {
		grantQuery := `
            INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
            VALUES `

		values := []interface{}{}
		valuePlaceholders := []string{}
		grantedAt := time.Now().UTC()

		for i, permID := range permissionIDs {
			baseIndex := i * 4
			valuePlaceholders = append(valuePlaceholders,
				fmt.Sprintf("($%d, $%d, $%d, $%d)",
					baseIndex+1, baseIndex+2, baseIndex+3, baseIndex+4))

			values = append(values, roleID, permID, grantedBy, grantedAt)
		}

		grantQuery += strings.Join(valuePlaceholders, ", ")
		_, err = tx.ExecContext(ctx, grantQuery, values...)
		if err != nil {
			return fmt.Errorf("failed to grant new role permissions: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordBatch(int64(len(permissionIDs) + 1)) // +1 for the delete operation
	r.logger.Debug("Role permissions replaced successfully",
		util.String("role_id", roleID.String()),
		util.Int("new_permissions_count", len(permissionIDs)))
	return nil
}

// CheckRolePermission checks if a role has a specific permission
func (r *CompanyRepositoryImpl) CheckRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM role_permissions WHERE role_id = $1 AND permission_id = $2`

	var hasPermission bool
	err := r.client.QueryRow(ctx, query, roleID, permissionID).Scan(&hasPermission)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to check role permission: %w", err)
	}

	r.recordQuery()
	return hasPermission, nil
}

// CopyRolePermissions copies permissions from one role to another
func (r *CompanyRepositoryImpl) CopyRolePermissions(ctx context.Context, sourceRoleID, targetRoleID, grantedBy uuid.UUID) error {
	query := `
        INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, $3
        FROM role_permissions 
        WHERE role_id = $4
        ON CONFLICT (role_id, permission_id) DO NOTHING`

	result, err := r.client.Exec(ctx, query, targetRoleID, grantedBy, time.Now().UTC(), sourceRoleID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to copy role permissions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.recordQuery()
	r.logger.Debug("Role permissions copied successfully",
		util.String("source_role_id", sourceRoleID.String()),
		util.String("target_role_id", targetRoleID.String()),
		util.Int64("permissions_copied", rowsAffected))
	return nil
}

// InitializeDefaultPermissions creates a set of default permissions for a new company
func (r *CompanyRepositoryImpl) InitializeDefaultPermissions(ctx context.Context, companyID uuid.UUID, createdBy uuid.UUID) error {
	// Get all basic permissions
	permissions, err := r.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	// Get owner role
	ownerRole, err := r.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err != nil {
		return fmt.Errorf("failed to get owner role: %w", err)
	}

	// Grant all basic permissions to owner
	permissionIDs := make([]uuid.UUID, 0, len(permissions))
	for _, perm := range permissions {
		if perm.RequiresTier == "basic" || perm.RequiresTier == "admin" {
			permissionIDs = append(permissionIDs, perm.PermissionID)
		}
	}

	if len(permissionIDs) > 0 {
		err = r.GrantMultipleRolePermissions(ctx, ownerRole.RoleID, permissionIDs, createdBy)
		if err != nil {
			return fmt.Errorf("failed to grant default permissions: %w", err)
		}
	}

	r.logger.Debug("Default permissions initialized successfully",
		util.String("company_id", companyID.String()),
		util.Int("permissions_granted", len(permissionIDs)))
	return nil
}

// ============================================================================
// EMPLOYEE OPERATIONS - UPDATED
// ============================================================================

// CreateEmployee creates a new company employee with role and department validation
func (r *CompanyRepositoryImpl) CreateEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Check if role belongs to the department (if department is specified)
	if employee.DepartmentID != nil {
		var roleDeptExists bool
		checkQuery := `SELECT COUNT(*) > 0 FROM role_departments WHERE role_id = $1 AND department_id = $2`
		err = tx.QueryRowContext(ctx, checkQuery, employee.RoleID, *employee.DepartmentID).Scan(&roleDeptExists)
		if err != nil {
			return fmt.Errorf("failed to check role-department mapping: %w", err)
		}

		if !roleDeptExists {
			return fmt.Errorf("role %s is not assigned to department %s", employee.RoleID, *employee.DepartmentID)
		}
	}

	// 2. Insert employee
	query := `
		INSERT INTO company_employees (
			company_id, user_id, employee_id, role_id, department_id,
			hire_date, is_active, reports_to, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err = tx.ExecContext(ctx, query,
		employee.CompanyID, employee.UserID, employee.EmployeeID, employee.RoleID,
		employee.DepartmentID, employee.HireDate, employee.IsActive, employee.ReportsTo,
		employee.CreatedAt, employee.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create employee: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetEmployee retrieves an employee by company and user ID
func (r *CompanyRepositoryImpl) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	query := `
		SELECT company_id, user_id, employee_id, role_id, department_id,
			   hire_date, is_active, reports_to, created_at, updated_at
		FROM company_employees 
		WHERE company_id = $1 AND user_id = $2`

	var employee models.CompanyEmployee
	var deptID, reportsTo sql.NullString

	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
		&employee.CompanyID, &employee.UserID, &employee.EmployeeID, &employee.RoleID,
		&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
		&employee.CreatedAt, &employee.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("employee not found")
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get employee: %w", err)
	}

	// Handle nullable UUIDs
	if deptID.Valid {
		departmentID, _ := uuid.Parse(deptID.String)
		employee.DepartmentID = &departmentID
	}
	if reportsTo.Valid {
		reportsToID, _ := uuid.Parse(reportsTo.String)
		employee.ReportsTo = &reportsToID
	}

	r.recordQuery()
	return &employee, nil
}

// // GetEmployeesByUser retrieves all company employees for a user
// func (r *CompanyRepositoryImpl) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
// 	query := `
// 		SELECT company_id, employee_id, role_id, department_id,
// 			   hire_date, is_active, reports_to, created_at, updated_at
// 		FROM company_employees
// 		WHERE user_id = $1 AND is_active = true
// 		ORDER BY hire_date DESC`

// 	rows, err := r.client.Query(ctx, query, userID)
// 	if err != nil {
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to query employees by user: %w", err)
// 	}
// 	defer rows.Close()

// 	var employees []*models.CompanyEmployee
// 	for rows.Next() {
// 		var employee models.CompanyEmployee
// 		var deptID, reportsTo sql.NullString

// 		err := rows.Scan(
// 			&employee.CompanyID, &employee.EmployeeID, &employee.RoleID,
// 			&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
// 			&employee.CreatedAt, &employee.UpdatedAt,
// 		)
// 		if err != nil {
// 			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
// 			continue
// 		}

// 		employee.UserID = userID

// 		// Handle nullable UUIDs
// 		if deptID.Valid {
// 			departmentID, _ := uuid.Parse(deptID.String)
// 			employee.DepartmentID = &departmentID
// 		}
// 		if reportsTo.Valid {
// 			reportsToID, _ := uuid.Parse(reportsTo.String)
// 			employee.ReportsTo = &reportsToID
// 		}

// 		employees = append(employees, &employee)
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, fmt.Errorf("error iterating employee rows: %w", err)
// 	}

// 	r.recordQuery()
// 	return employees, nil
// }

// UpdateEmployee updates employee information
func (r *CompanyRepositoryImpl) UpdateEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	employee.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE company_employees SET 
			employee_id = $1, role_id = $2, department_id = $3,
			is_active = $4, reports_to = $5, updated_at = $6
		WHERE company_id = $7 AND user_id = $8`

	result, err := r.client.Exec(ctx, query,
		employee.EmployeeID, employee.RoleID, employee.DepartmentID,
		employee.IsActive, employee.ReportsTo, employee.UpdatedAt,
		employee.CompanyID, employee.UserID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update employee: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// UpdateEmployeeRole updates an employee's role
func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	query := `UPDATE company_employees SET role_id = $1, updated_at = $2 WHERE company_id = $3 AND user_id = $4`

	result, err := r.client.Exec(ctx, query, roleID, time.Now().UTC(), companyID, userID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update employee role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// UpdateEmployeeDepartment updates an employee's department
func (r *CompanyRepositoryImpl) UpdateEmployeeDepartment(ctx context.Context, companyID, userID, departmentID uuid.UUID) error {
	query := `UPDATE company_employees SET department_id = $1, updated_at = $2 WHERE company_id = $3 AND user_id = $4`

	result, err := r.client.Exec(ctx, query, departmentID, time.Now().UTC(), companyID, userID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update employee department: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// DeactivateEmployee deactivates an employee
func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `UPDATE company_employees SET is_active = false, updated_at = $1 WHERE company_id = $2 AND user_id = $3`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID, userID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to deactivate employee: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// ReactivateEmployee reactivates an employee
func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `UPDATE company_employees SET is_active = true, updated_at = $1 WHERE company_id = $2 AND user_id = $3`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID, userID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to reactivate employee: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// GetEmployeeCount gets total employee count for a company
func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1`

	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to get employee count: %w", err)
	}

	r.recordQuery()
	return count, nil
}

// GetActiveEmployeeCount gets active employee count for a company
func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1 AND is_active = true`

	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to get active employee count: %w", err)
	}

	r.recordQuery()
	return count, nil
}

// GetEmployeesByCompany retrieves employees for a company with pagination
func (r *CompanyRepositoryImpl) GetEmployeesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count employees: %w", err)
	}

	// Get paginated results
	query := `
		SELECT user_id, employee_id, role_id, department_id,
			   hire_date, is_active, reports_to, created_at, updated_at
		FROM company_employees 
		WHERE company_id = $1
		ORDER BY hire_date DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query employees: %w", err)
	}
	defer rows.Close()

	employees := make([]*models.CompanyEmployee, 0, limit)
	for rows.Next() {
		var employee models.CompanyEmployee
		var deptID, reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

		// Handle nullable UUIDs
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			employee.DepartmentID = &departmentID
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, totalCount, nil
}

// GetEmployeesByDepartment retrieves employees by department
func (r *CompanyRepositoryImpl) GetEmployeesByDepartment(ctx context.Context, departmentID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE department_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, departmentID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count department employees: %w", err)
	}

	// Get paginated results
	query := `
		SELECT company_id, user_id, employee_id, role_id,
			   hire_date, is_active, reports_to, created_at, updated_at
		FROM company_employees 
		WHERE department_id = $1 AND is_active = true
		ORDER BY hire_date DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, departmentID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query department employees: %w", err)
	}
	defer rows.Close()

	employees := make([]*models.CompanyEmployee, 0, limit)
	for rows.Next() {
		var employee models.CompanyEmployee
		var reportsTo sql.NullString

		err := rows.Scan(
			&employee.CompanyID, &employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&employee.HireDate, &employee.IsActive, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.DepartmentID = &departmentID

		// Handle nullable UUIDs
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, totalCount, nil
}

// GetEmployeesByRole retrieves employees by role
func (r *CompanyRepositoryImpl) GetEmployeesByRole(ctx context.Context, roleID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE role_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, roleID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count role employees: %w", err)
	}

	// Get paginated results
	query := `
		SELECT company_id, user_id, employee_id, department_id,
			   hire_date, is_active, reports_to, created_at, updated_at
		FROM company_employees 
		WHERE role_id = $1 AND is_active = true
		ORDER BY hire_date DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, roleID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query role employees: %w", err)
	}
	defer rows.Close()

	employees := make([]*models.CompanyEmployee, 0, limit)
	for rows.Next() {
		var employee models.CompanyEmployee
		var deptID, reportsTo sql.NullString

		err := rows.Scan(
			&employee.CompanyID, &employee.UserID, &employee.EmployeeID,
			&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.RoleID = roleID

		// Handle nullable UUIDs
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			employee.DepartmentID = &departmentID
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, totalCount, nil
}

// ListActiveEmployees lists only active employees
func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count active employees: %w", err)
	}

	// Get paginated results
	query := `
        SELECT user_id, employee_id, role_id, department_id,
               hire_date, reports_to, created_at, updated_at
        FROM company_employees 
        WHERE company_id = $1 AND is_active = true
        ORDER BY hire_date DESC 
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query active employees: %w", err)
	}
	defer rows.Close()

	employees := make([]*models.CompanyEmployee, 0, limit)
	for rows.Next() {
		var employee models.CompanyEmployee
		var deptID, reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&deptID, &employee.HireDate, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID
		employee.IsActive = true

		// Handle nullable UUIDs
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			employee.DepartmentID = &departmentID
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, totalCount, nil
}

// IsUserActiveEmployee checks if a user is an active employee
func (r *CompanyRepositoryImpl) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM company_employees WHERE company_id = $1 AND user_id = $2 AND is_active = true`

	var isActive bool
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(&isActive)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to check employee status: %w", err)
	}

	r.recordQuery()
	return isActive, nil
}

// GetUsersByRoleLevel retrieves users by role level range
func (r *CompanyRepositoryImpl) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	query := `
        SELECT ce.user_id, ce.employee_id, ce.role_id, ce.department_id,
               ce.hire_date, ce.is_active, ce.reports_to, r.role_name, r.role_level
        FROM company_employees ce
        INNER JOIN roles r ON ce.role_id = r.role_id
        WHERE ce.company_id = $1 AND ce.is_active = true 
          AND r.role_level BETWEEN $2 AND $3
        ORDER BY r.role_level DESC, ce.hire_date ASC`

	rows, err := r.client.Query(ctx, query, companyID, minLevel, maxLevel)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query users by role level: %w", err)
	}
	defer rows.Close()

	var employees []*models.CompanyEmployee
	for rows.Next() {
		var employee models.CompanyEmployee
		var deptID, reportsTo sql.NullString
		var roleName string
		var roleLevel int

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
			&roleName, &roleLevel,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

		// Handle nullable UUIDs
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			employee.DepartmentID = &departmentID
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, nil
}

// ============================================================================
// PERMISSION & RBAC QUERIES - UPDATED
// ============================================================================

// GetAllPermissions retrieves all permissions
func (r *CompanyRepositoryImpl) GetAllPermissions(ctx context.Context) ([]*models.Permission, error) {
	query := `
		SELECT permission_id, permission_name, description, 
			   category, module, requires_tier, created_at
		FROM permissions 
		ORDER BY category, permission_name`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetPermissionsByCategory retrieves permissions by category
func (r *CompanyRepositoryImpl) GetPermissionsByCategory(ctx context.Context, category string) ([]*models.Permission, error) {
	query := `
		SELECT permission_id, permission_name, description, 
			   module, requires_tier, created_at
		FROM permissions 
		WHERE category = $1
		ORDER BY permission_name`

	rows, err := r.client.Query(ctx, query, category)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions by category: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Module, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		perm.Category = category
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetPermissionsByModule retrieves permissions by module
func (r *CompanyRepositoryImpl) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	query := `
		SELECT permission_id, permission_name, description, 
			   category, requires_tier, created_at
		FROM permissions 
		WHERE module = $1
		ORDER BY category, permission_name`

	rows, err := r.client.Query(ctx, query, module)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions by module: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		perm.Module = module
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// CheckUserPermission checks if a user has a specific permission with module validation
func (r *CompanyRepositoryImpl) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
	// First check if user is company owner
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to get company owner: %w", err)
	}

	// Owner has all permissions
	if ownerUserID == userID {
		return true, nil
	}

	// For non-owner, check the full permission flow
	query := `
		SELECT COUNT(*) > 0
		FROM company_employees ce
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id AND ce.department_id = rd.department_id
		INNER JOIN departments d ON ce.department_id = d.department_id
		INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		INNER JOIN role_permissions rp ON r.role_id = rp.role_id
		INNER JOIN permissions p ON rp.permission_id = p.permission_id
		WHERE ce.company_id = $1 AND ce.user_id = $2 
		  AND ce.is_active = true AND p.permission_name = $3
		  AND p.module = sd.module_code` // Critical: module must match

	var hasPermission bool
	err = r.client.QueryRow(ctx, query, companyID, userID, permissionName).Scan(&hasPermission)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to check user permission: %w", err)
	}

	r.recordQuery()
	return hasPermission, nil
}

// CheckUserPermissionDetailed performs comprehensive permission check with all validations
func (r *CompanyRepositoryImpl) CheckUserPermissionDetailed(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (*models.PermissionCheckResult, error) {
	result := &models.PermissionCheckResult{
		HasPermission: false,
		Checks:        make(map[string]bool),
	}

	// 1. Check if user is company owner
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}

	if ownerUserID == userID {
		result.HasPermission = true
		result.Checks["is_owner"] = true
		result.Checks["has_employee_record"] = true
		result.Checks["role_has_permission"] = true
		result.Checks["role_belongs_to_department"] = true
		result.Checks["module_access"] = true
		return result, nil
	}

	// 2. Get employee record
	var roleID, departmentID uuid.UUID
	var deptID sql.NullString
	employeeQuery := `
		SELECT role_id, department_id 
		FROM company_employees 
		WHERE company_id = $1 AND user_id = $2 AND is_active = true`

	err = r.client.QueryRow(ctx, employeeQuery, companyID, userID).Scan(&roleID, &deptID)
	if err != nil {
		if err == sql.ErrNoRows {
			result.Checks["has_employee_record"] = false
			return result, nil
		}
		return nil, fmt.Errorf("failed to get employee record: %w", err)
	}
	result.Checks["has_employee_record"] = true

	// Handle nullable department
	if !deptID.Valid {
		result.Checks["has_department"] = false
		return result, nil
	}
	departmentID, _ = uuid.Parse(deptID.String)
	result.Checks["has_department"] = true

	// 3. Check role has permission
	var permissionExists bool
	permissionQuery := `
		SELECT COUNT(*) > 0 
		FROM role_permissions rp
		INNER JOIN permissions p ON rp.permission_id = p.permission_id
		WHERE rp.role_id = $1 AND p.permission_name = $2`

	err = r.client.QueryRow(ctx, permissionQuery, roleID, permissionName).Scan(&permissionExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check role permission: %w", err)
	}
	result.Checks["role_has_permission"] = permissionExists
	if !permissionExists {
		return result, nil
	}

	// 4. Check role belongs to department
	var roleDeptExists bool
	roleDeptQuery := `SELECT COUNT(*) > 0 FROM role_departments WHERE role_id = $1 AND department_id = $2`
	err = r.client.QueryRow(ctx, roleDeptQuery, roleID, departmentID).Scan(&roleDeptExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check role department: %w", err)
	}
	result.Checks["role_belongs_to_department"] = roleDeptExists
	if !roleDeptExists {
		return result, nil
	}

	// 5. Check module access
	var moduleMatch bool
	moduleQuery := `
		SELECT COUNT(*) > 0
		FROM departments d
		INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		INNER JOIN permissions p ON p.module = sd.module_code
		WHERE d.department_id = $1 AND p.permission_name = $2`

	err = r.client.QueryRow(ctx, moduleQuery, departmentID, permissionName).Scan(&moduleMatch)
	if err != nil {
		return nil, fmt.Errorf("failed to check module access: %w", err)
	}
	result.Checks["module_access"] = moduleMatch

	result.HasPermission = permissionExists && roleDeptExists && moduleMatch
	return result, nil
}

// GetUserPermissions retrieves all permissions for a user with module validation
func (r *CompanyRepositoryImpl) GetUserPermissions(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Permission, error) {
	// First check if user is company owner
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}

	// Owner gets all permissions
	if ownerUserID == userID {
		return r.GetAllPermissions(ctx)
	}

	// For non-owner, check permissions with module validation
	query := `
		SELECT DISTINCT p.permission_id, p.permission_name, p.description, 
			   p.category, p.module, p.requires_tier, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.role_id
		INNER JOIN company_employees ce ON r.role_id = ce.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id AND ce.department_id = rd.department_id
		INNER JOIN departments d ON ce.department_id = d.department_id
		INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
		  AND p.module = sd.module_code  -- Module must match
		ORDER BY p.category, p.permission_name`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetUsersWithPermission retrieves users with a specific permission
func (r *CompanyRepositoryImpl) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}

	query := `
		SELECT ce.user_id, ce.employee_id, ce.role_id, ce.department_id,
			   ce.hire_date, ce.is_active, ce.reports_to
		FROM company_employees ce
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_permissions rp ON r.role_id = rp.role_id
		INNER JOIN permissions p ON rp.permission_id = p.permission_id
		WHERE ce.company_id = $1 AND ce.is_active = true 
		  AND p.permission_name = $2
		LIMIT $3`

	rows, err := r.client.Query(ctx, query, companyID, permissionName, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query users with permission: %w", err)
	}
	defer rows.Close()

	var employees []*models.CompanyEmployee
	for rows.Next() {
		var employee models.CompanyEmployee
		var deptID, reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&deptID, &employee.HireDate, &employee.IsActive, &reportsTo,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

		// Handle nullable UUIDs
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			employee.DepartmentID = &departmentID
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, nil
}

// ============================================================================
// PERMISSION MANAGEMENT OPERATIONS
// ============================================================================

// CreatePermission creates a new permission
func (r *CompanyRepositoryImpl) CreatePermission(ctx context.Context, permission *models.Permission) error {
	query := `
        INSERT INTO permissions (
            permission_id, permission_name, description, category, 
            module, requires_tier, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.client.Exec(ctx, query,
		permission.PermissionID, permission.PermissionName, permission.Description,
		permission.Category, permission.Module, permission.RequiresTier, permission.CreatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create permission: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Permission created successfully",
		util.String("permission_id", permission.PermissionID.String()),
		util.String("permission_name", permission.PermissionName))
	return nil
}

// CreateMultiplePermissions creates multiple permissions in batch
func (r *CompanyRepositoryImpl) CreateMultiplePermissions(ctx context.Context, permissions []*models.Permission) error {
	if len(permissions) == 0 {
		return nil
	}

	query := `
        INSERT INTO permissions (
            permission_id, permission_name, description, category, 
            module, requires_tier, created_at
        ) VALUES `

	values := []interface{}{}
	valuePlaceholders := []string{}

	for i, perm := range permissions {
		baseIndex := i * 7 // 7 fields per permission
		valuePlaceholders = append(valuePlaceholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				baseIndex+1, baseIndex+2, baseIndex+3, baseIndex+4,
				baseIndex+5, baseIndex+6, baseIndex+7))

		values = append(values,
			perm.PermissionID, perm.PermissionName, perm.Description,
			perm.Category, perm.Module, perm.RequiresTier, perm.CreatedAt)
	}

	query += strings.Join(valuePlaceholders, ", ")

	_, err := r.client.Exec(ctx, query, values...)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create multiple permissions: %w", err)
	}

	r.recordBatch(int64(len(permissions)))
	r.logger.Debug("Multiple permissions created successfully",
		util.Int("count", len(permissions)))
	return nil
}

// GetPermissionByName retrieves a permission by name
func (r *CompanyRepositoryImpl) GetPermissionByName(ctx context.Context, permissionName string) (*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description, 
               category, module, requires_tier, created_at
        FROM permissions WHERE permission_name = $1`

	var permission models.Permission
	err := r.client.QueryRow(ctx, query, permissionName).Scan(
		&permission.PermissionID, &permission.PermissionName, &permission.Description,
		&permission.Category, &permission.Module, &permission.RequiresTier, &permission.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("permission not found: %s", permissionName)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	r.recordQuery()
	return &permission, nil
}

// UpdatePermission updates permission information
func (r *CompanyRepositoryImpl) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	query := `
        UPDATE permissions SET 
            permission_name = $1, description = $2, category = $3,
            module = $4, requires_tier = $5
        WHERE permission_id = $6`

	result, err := r.client.Exec(ctx, query,
		permission.PermissionName, permission.Description, permission.Category,
		permission.Module, permission.RequiresTier, permission.PermissionID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update permission: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("permission not found: %s", permission.PermissionID)
	}

	r.recordQuery()
	return nil
}

// DeletePermission deletes a permission
func (r *CompanyRepositoryImpl) DeletePermission(ctx context.Context, permissionID uuid.UUID) error {
	// First, delete any role_permissions associations
	deleteAssocQuery := `DELETE FROM role_permissions WHERE permission_id = $1`
	_, err := r.client.Exec(ctx, deleteAssocQuery, permissionID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete permission associations: %w", err)
	}

	// Then delete the permission
	query := `DELETE FROM permissions WHERE permission_id = $1`
	result, err := r.client.Exec(ctx, query, permissionID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("permission not found: %s", permissionID)
	}

	r.recordQuery()
	return nil
}

// ============================================================================
// ANALYTICS & REPORTING
// ============================================================================

// GetCompanyStats retrieves comprehensive company statistics
func (r *CompanyRepositoryImpl) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get basic company info
	var companyName, subscriptionTier string
	var maxEmployees int
	companyQuery := `SELECT company_name, subscription_tier, max_employees FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, companyQuery, companyID).Scan(&companyName, &subscriptionTier, &maxEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get company info: %w", err)
	}

	stats["company_name"] = companyName
	stats["subscription_tier"] = subscriptionTier
	stats["max_employees"] = maxEmployees

	// Get employee counts
	totalEmployees, err := r.GetEmployeeCount(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get total employees: %w", err)
	}
	activeEmployees, err := r.GetActiveEmployeeCount(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees: %w", err)
	}

	stats["total_employees"] = totalEmployees
	stats["active_employees"] = activeEmployees
	if maxEmployees > 0 {
		stats["employee_utilization"] = float64(activeEmployees) / float64(maxEmployees) * 100
	} else {
		stats["employee_utilization"] = 0
	}

	// Get department count
	var departmentCount int
	deptQuery := `SELECT COUNT(*) FROM departments WHERE company_id = $1 AND is_active = true`
	err = r.client.QueryRow(ctx, deptQuery, companyID).Scan(&departmentCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get department count: %w", err)
	}
	stats["department_count"] = departmentCount

	// Get role distribution
	roleDistribution, err := r.GetRoleDistribution(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role distribution: %w", err)
	}
	stats["role_distribution"] = roleDistribution

	r.recordQuery()
	return stats, nil
}

// GetEmployeeRoleHierarchy retrieves employee role hierarchy
func (r *CompanyRepositoryImpl) GetEmployeeRoleHierarchy(ctx context.Context, companyID uuid.UUID) ([]*EmployeeRoleHierarchy, error) {
	query := `
		SELECT ce.employee_id, ce.user_id, r.role_name, r.role_level,
			   d.department_id, d.department_name, ce.reports_to, ce.is_active
		FROM company_employees ce
		INNER JOIN roles r ON ce.role_id = r.role_id
		LEFT JOIN departments d ON ce.department_id = d.department_id
		WHERE ce.company_id = $1 AND ce.is_active = true
		ORDER BY r.role_level ASC, d.department_name, ce.employee_id`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query employee hierarchy: %w", err)
	}
	defer rows.Close()

	var hierarchy []*EmployeeRoleHierarchy
	for rows.Next() {
		var item EmployeeRoleHierarchy
		var deptID, deptName, reportsTo sql.NullString

		err := rows.Scan(
			&item.EmployeeID, &item.UserID, &item.RoleName, &item.RoleLevel,
			&deptID, &deptName, &reportsTo, &item.IsActive,
		)
		if err != nil {
			r.logger.Warn("Failed to scan hierarchy row", util.ErrorField(err))
			continue
		}

		// Handle nullable fields
		if deptID.Valid {
			item.DepartmentID, _ = uuid.Parse(deptID.String)
		}
		if deptName.Valid {
			item.Department = deptName.String
		}
		if reportsTo.Valid {
			item.ReportsTo, _ = uuid.Parse(reportsTo.String)
		}

		hierarchy = append(hierarchy, &item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating hierarchy rows: %w", err)
	}

	r.recordQuery()
	return hierarchy, nil
}

// GetRoleDistribution gets employee count per role
func (r *CompanyRepositoryImpl) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	query := `
        SELECT r.role_name, COUNT(ce.user_id) as employee_count
        FROM roles r
        LEFT JOIN company_employees ce ON r.role_id = ce.role_id AND ce.is_active = true
        WHERE r.company_id = $1
        GROUP BY r.role_id, r.role_name
        ORDER BY employee_count DESC`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query role distribution: %w", err)
	}
	defer rows.Close()

	roleDistribution := make(map[string]int)
	for rows.Next() {
		var roleName string
		var count int
		err := rows.Scan(&roleName, &count)
		if err != nil {
			continue
		}
		roleDistribution[roleName] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role distribution rows: %w", err)
	}

	r.recordQuery()
	return roleDistribution, nil
}

// ============================================================================
// UTILITY METHODS
// ============================================================================

// HealthCheck verifies database connectivity
func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
	var result int
	err := r.client.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		r.recordError()
		return fmt.Errorf("postgreSQL health check failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("postgreSQL health check returned unexpected result: %d", result)
	}

	return nil
}

// GetRepositoryStats returns performance and usage statistics
func (r *CompanyRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get database connection stats
	dbStats := r.client.GetStats()
	stats["db_connections"] = map[string]interface{}{
		"open_connections": dbStats.OpenConnections,
		"in_use":           dbStats.InUse,
		"idle":             dbStats.Idle,
		"wait_count":       dbStats.WaitCount,
		"wait_duration":    dbStats.WaitDuration.String(),
	}

	// Get repository metrics
	r.metrics.RLock()
	stats["repository_metrics"] = map[string]interface{}{
		"query_count": r.metrics.queryCount,
		"batch_count": r.metrics.batchCount,
		"error_count": r.metrics.errorCount,
		"uptime":      time.Since(r.metrics.lastReset).String(),
	}
	r.metrics.RUnlock()

	// Get prepared statements count
	r.stmtMutex.RLock()
	stats["prepared_statements"] = len(r.stmtCache)
	r.stmtMutex.RUnlock()

	// Get table statistics
	var companyCount, employeeCount, roleCount int
	r.client.QueryRow(ctx, "SELECT COUNT(*) FROM companies").Scan(&companyCount)
	r.client.QueryRow(ctx, "SELECT COUNT(*) FROM company_employees").Scan(&employeeCount)
	r.client.QueryRow(ctx, "SELECT COUNT(*) FROM roles").Scan(&roleCount)

	stats["table_counts"] = map[string]interface{}{
		"companies": companyCount,
		"employees": employeeCount,
		"roles":     roleCount,
	}

	return stats, nil
}

// Close cleans up prepared statements
func (r *CompanyRepositoryImpl) Close() error {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	var lastErr error
	for name, stmt := range r.stmtCache {
		if err := stmt.Close(); err != nil {
			r.logger.Warn("Failed to close prepared statement",
				util.String("statement", name),
				util.ErrorField(err))
			lastErr = err
		}
	}

	r.stmtCache = make(map[string]*sql.Stmt)
	return lastErr
}

// ============================================================================
// PRIVATE HELPER METHODS
// ============================================================================

// initializePreparedStatements initializes frequently used prepared statements
func (r *CompanyRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		// Existing statements
		"get_company": `
			SELECT company_id, company_name, owner_user_id, subscription_tier,
				   subscription_status, max_employees, data_region, is_active,
				   created_at, updated_at, subscription_start_date, subscription_end_date
			FROM companies WHERE company_id = $1`,

		"get_employee": `
			SELECT company_id, user_id, employee_id, role_id, department_id,
				   hire_date, is_active, reports_to, created_at, updated_at
			FROM company_employees WHERE company_id = $1 AND user_id = $2`,

		// New statements for the flow
		"check_user_permission_full": `
			SELECT COUNT(*) > 0
			FROM company_employees ce
			INNER JOIN roles r ON ce.role_id = r.role_id
			INNER JOIN role_departments rd ON r.role_id = rd.role_id AND ce.department_id = rd.department_id
			INNER JOIN departments d ON ce.department_id = d.department_id
			INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
			INNER JOIN role_permissions rp ON r.role_id = rp.role_id
			INNER JOIN permissions p ON rp.permission_id = p.permission_id
			WHERE ce.company_id = $1 AND ce.user_id = $2 
			  AND ce.is_active = true AND p.permission_name = $3
			  AND p.module = sd.module_code`,

		"get_user_permissions_full": `
			SELECT DISTINCT p.permission_id, p.permission_name, p.description, 
				   p.category, p.module, p.requires_tier, p.created_at
			FROM permissions p
			INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
			INNER JOIN roles r ON rp.role_id = r.role_id
			INNER JOIN company_employees ce ON r.role_id = ce.role_id
			INNER JOIN role_departments rd ON r.role_id = rd.role_id AND ce.department_id = rd.department_id
			INNER JOIN departments d ON ce.department_id = d.department_id
			INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
			WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
			  AND p.module = sd.module_code
			ORDER BY p.category, p.permission_name`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Company prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

// // getStmt retrieves a prepared statement from cache
// func (r *CompanyRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
// 	r.stmtMutex.RLock()
// 	defer r.stmtMutex.RUnlock()

// 	stmt, exists := r.stmtCache[name]
// 	return stmt, exists
// }

func (r *CompanyRepositoryImpl) recordQuery() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.queryCount++
}

func (r *CompanyRepositoryImpl) recordBatch(count int64) {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.batchCount += count
}

func (r *CompanyRepositoryImpl) recordError() {
	r.metrics.Lock()
	defer r.metrics.Unlock()
	r.metrics.errorCount++
}

// Add to CompanyRepository interface

// Implementation in postgres/company_repository.go
func (r *CompanyRepositoryImpl) GetSystemDepartment(ctx context.Context, systemDeptID uuid.UUID) (*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description
        FROM system_departments 
        WHERE system_department_id = $1`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, systemDeptID).Scan(
		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("system department not found: %s", systemDeptID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get system department: %w", err)
	}

	r.recordQuery()
	return &dept, nil
}

// GetEmployeeHierarchy retrieves employee hierarchy for a company
func (r *CompanyRepositoryImpl) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	query := `
        SELECT ce.user_id, ce.employee_id, r.role_name, r.role_level,
               d.department_id, d.department_name, ce.reports_to, ce.is_active
        FROM company_employees ce
        INNER JOIN roles r ON ce.role_id = r.role_id
        LEFT JOIN departments d ON ce.department_id = d.department_id
        WHERE ce.company_id = $1 AND ce.is_active = true
        ORDER BY r.role_level ASC, d.department_name, ce.employee_id`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query employee hierarchy: %w", err)
	}
	defer rows.Close()

	var hierarchy []*models.EmployeeHierarchy
	for rows.Next() {
		var item models.EmployeeHierarchy
		var deptID, deptName, reportsTo sql.NullString

		err := rows.Scan(
			&item.UserID, &item.EmployeeID, &item.RoleName, &item.RoleLevel,
			&deptID, &deptName, &reportsTo, &item.IsActive,
		)
		if err != nil {
			r.logger.Warn("Failed to scan hierarchy row", util.ErrorField(err))
			continue
		}

		item.CompanyID = companyID

		// Handle nullable fields
		if deptID.Valid {
			departmentID, _ := uuid.Parse(deptID.String)
			item.DepartmentID = &departmentID
		}
		if deptName.Valid {
			item.Department = deptName.String
		}
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			item.ReportsTo = &reportsToID
		}

		hierarchy = append(hierarchy, &item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating hierarchy rows: %w", err)
	}

	r.recordQuery()
	return hierarchy, nil
}
func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company, additionalDepartments []string) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Insert company
	companyQuery := `
        INSERT INTO companies (
            company_id, company_name, owner_user_id, subscription_tier, 
            subscription_status, max_employees, data_region, is_active,
            created_at, updated_at, subscription_start_date, subscription_end_date
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err = tx.ExecContext(ctx, companyQuery,
		company.CompanyID, company.CompanyName, company.OwnerUserID, company.SubscriptionTier,
		company.SubscriptionStatus, company.MaxEmployees, company.DataRegion, company.IsActive,
		company.CreatedAt, company.UpdatedAt, company.SubscriptionStartDate, company.SubscriptionEndDate,
	)
	if err != nil {
		r.recordError()
		if strings.Contains(err.Error(), "idx_companies_name_owner_unique") {
			return fmt.Errorf("company with name '%s' already exists for this owner", company.CompanyName)
		}
		return fmt.Errorf("failed to create company: %w", err)
	}

	// 2. Create OWNER role for this company
	ownerRoleID := uuid.New()
	ownerRoleQuery := `
        INSERT INTO roles (
            role_id, role_name, role_level, company_id, is_system_role,
            description, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = tx.ExecContext(ctx, ownerRoleQuery,
		ownerRoleID, "Owner", 1000, company.CompanyID, true,
		"Company owner with full permissions", company.CreatedAt, company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create owner role: %w", err)
	}

	// 🔵 STEP 3 — Create Default Department: ADMINISTRATION
	adminDeptID := uuid.New()
	adminDeptQuery := `
        INSERT INTO departments (
            department_id, company_id, department_name, system_department_id,
            is_active, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = tx.ExecContext(ctx, adminDeptQuery,
		adminDeptID, company.CompanyID, "Administration", nil,
		true, company.CreatedAt, company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create administration department: %w", err)
	}

	// 🔵 STEP 4 — Create Additional Department Rows from user input
	systemDepts, err := r.GetSystemDepartments(ctx)
	if err != nil {
		return fmt.Errorf("failed to get system departments: %w", err)
	}

	// Map department names to system departments
	systemDeptMap := make(map[string]uuid.UUID)
	for _, dept := range systemDepts {
		systemDeptMap[strings.ToLower(dept.ModuleCode)] = dept.SystemDepartmentID
	}

	createdDeptIDs := []uuid.UUID{adminDeptID} // Start with admin department

	for _, deptName := range additionalDepartments {
		deptID := uuid.New()
		var systemDeptID uuid.UUID

		// Map department name to system module
		switch strings.ToLower(deptName) {
		case "hr", "human resources":
			systemDeptID = systemDeptMap["hr"]
		case "inventory", "warehouse":
			systemDeptID = systemDeptMap["inventory"]
		case "sales":
			systemDeptID = systemDeptMap["sales"]
		case "production", "manufacturing":
			systemDeptID = systemDeptMap["production"]
		case "finance", "accounting":
			systemDeptID = systemDeptMap["finance"]
		case "logistics", "shipping":
			systemDeptID = systemDeptMap["logistics"]
		case "it", "technology":
			systemDeptID = systemDeptMap["it"]
		case "customer support", "support":
			systemDeptID = systemDeptMap["support"]
		case "quality control", "qc":
			systemDeptID = systemDeptMap["qc"]
		case "quality assurance", "qa":
			systemDeptID = systemDeptMap["qa"]
		case "research", "r&d":
			systemDeptID = systemDeptMap["rnd"]
		case "operations":
			systemDeptID = systemDeptMap["operations"]
		case "marketing":
			systemDeptID = systemDeptMap["marketing"]
		case "procurement", "purchasing":
			systemDeptID = systemDeptMap["procurement"]
		default:
			// Use operations as default for unknown departments
			systemDeptID = systemDeptMap["operations"]
		}

		deptQuery := `
            INSERT INTO departments (
                department_id, company_id, department_name, system_department_id,
                is_active, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)`

		_, err = tx.ExecContext(ctx, deptQuery,
			deptID, company.CompanyID, deptName, systemDeptID,
			true, company.CreatedAt, company.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to create department",
				util.String("department", deptName),
				util.ErrorField(err))
			continue // Continue with other departments even if one fails
		}

		createdDeptIDs = append(createdDeptIDs, deptID)
	}

	// 🔵 STEP 6 — Assign EVERY department to the Owner role
	roleDeptQuery := `INSERT INTO role_departments (role_id, department_id) VALUES ($1, $2)`
	for _, deptID := range createdDeptIDs {
		_, err = tx.ExecContext(ctx, roleDeptQuery, ownerRoleID, deptID)
		if err != nil {
			r.logger.Warn("Failed to assign department to owner role",
				util.String("department_id", deptID.String()),
				util.ErrorField(err))
			// Continue even if some assignments fail
		}
	}

	// 🔵 STEP 7 — Assign ALL permissions to Owner Role
	grantPermissionsQuery := `
        INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, $3 FROM permissions`

	_, err = tx.ExecContext(ctx, grantPermissionsQuery,
		ownerRoleID, company.OwnerUserID, company.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to grant permissions to owner role: %w", err)
	}

	// 🔵 STEP 8 — Insert the Owner as Employee with Administration department
	employeeQuery := `
        INSERT INTO company_employees (
            company_id, user_id, employee_id, role_id, department_id,
            hire_date, is_active, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = tx.ExecContext(ctx, employeeQuery,
		company.CompanyID, company.OwnerUserID, "OWNER-"+company.CompanyID.String()[:8], ownerRoleID, adminDeptID,
		company.CreatedAt, true, company.CreatedAt, company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add owner as employee: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Company created successfully with full RBAC setup",
		util.String("company_id", company.CompanyID.String()),
		util.String("company_name", company.CompanyName),
		util.Int("department_count", len(createdDeptIDs)),
		util.Int("additional_departments", len(additionalDepartments)))

	return nil
}

// Department operations
func (r *CompanyRepositoryImpl) UpdateDepartmentName(ctx context.Context, departmentID uuid.UUID, newName string) error {
	query := `UPDATE departments SET department_name = $1, updated_at = $2 WHERE department_id = $3`

	result, err := r.client.Exec(ctx, query, newName, time.Now().UTC(), departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update department name: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found: %s", departmentID)
	}

	r.recordQuery()
	return nil
}

func (r *CompanyRepositoryImpl) GetDepartmentBySystemID(ctx context.Context, companyID, systemDepartmentID uuid.UUID) (*models.Department, error) {
	query := `
        SELECT department_id, company_id, department_name, system_department_id,
               is_active, created_at, updated_at
        FROM departments 
        WHERE company_id = $1 AND system_department_id = $2 AND is_active = true`

	var department models.Department
	var systemDeptID sql.NullString

	err := r.client.QueryRow(ctx, query, companyID, systemDepartmentID).Scan(
		&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
		&systemDeptID, &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("department not found for system department: %s", systemDepartmentID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get department by system ID: %w", err)
	}

	if systemDeptID.Valid {
		systemID, _ := uuid.Parse(systemDeptID.String)
		department.SystemDepartmentID = &systemID
	}

	r.recordQuery()
	return &department, nil
}

// Permission operations
func (r *CompanyRepositoryImpl) GetPermissionsByNames(ctx context.Context, permissionNames []string) ([]*models.Permission, error) {
	if len(permissionNames) == 0 {
		return []*models.Permission{}, nil
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(permissionNames))
	values := []interface{}{}

	for i, name := range permissionNames {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		values = append(values, name)
	}

	query := fmt.Sprintf(`
        SELECT permission_id, permission_name, description, category, module, requires_tier, created_at
        FROM permissions 
        WHERE permission_name IN (%s)`,
		strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, values...)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions by names: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

func (r *CompanyRepositoryImpl) GetUserPermissionNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
        SELECT DISTINCT p.permission_name
        FROM permissions p
        INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
        INNER JOIN roles r ON rp.role_id = r.role_id
        INNER JOIN company_employees ce ON r.role_id = ce.role_id
        WHERE ce.user_id = $1 AND ce.is_active = true
        ORDER BY p.permission_name`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query user permission names: %w", err)
	}
	defer rows.Close()

	var permissionNames []string
	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		if err != nil {
			r.logger.Warn("Failed to scan permission name", util.ErrorField(err))
			continue
		}
		permissionNames = append(permissionNames, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission name rows: %w", err)
	}

	r.recordQuery()
	return permissionNames, nil
}

// Role operations
func (r *CompanyRepositoryImpl) CreateRoleWithDetails(ctx context.Context, role *models.Role, departmentID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Create role
	roleQuery := `
        INSERT INTO roles (
            role_id, role_name, role_level, company_id, is_system_role,
            description, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = tx.ExecContext(ctx, roleQuery,
		role.RoleID, role.RoleName, role.RoleLevel, role.CompanyID,
		role.IsSystemRole, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create role: %w", err)
	}

	// 2. Map role to department
	roleDeptQuery := `INSERT INTO role_departments (role_id, department_id) VALUES ($1, $2)`
	_, err = tx.ExecContext(ctx, roleDeptQuery, role.RoleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to map role to department: %w", err)
	}

	// 3. Grant permissions if provided
	if len(permissionIDs) > 0 {
		grantQuery := `
            INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
            VALUES `

		values := []interface{}{}
		valuePlaceholders := []string{}
		grantedAt := time.Now().UTC()

		for i, permID := range permissionIDs {
			baseIndex := i * 4
			valuePlaceholders = append(valuePlaceholders,
				fmt.Sprintf("($%d, $%d, $%d, $%d)",
					baseIndex+1, baseIndex+2, baseIndex+3, baseIndex+4))

			values = append(values, role.RoleID, permID, createdBy, grantedAt)
		}

		grantQuery += strings.Join(valuePlaceholders, ", ")
		_, err = tx.ExecContext(ctx, grantQuery, values...)
		if err != nil {
			return fmt.Errorf("failed to grant permissions to role: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	return nil
}
func (r *CompanyRepositoryImpl) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	query := `
        SELECT company_id, employee_id, role_id, department_id,
               hire_date, is_active, reports_to, created_at, updated_at
        FROM company_employees 
        WHERE user_id = $1 AND is_active = true
        ORDER BY hire_date DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query employees by user: %w", err)
	}
	defer rows.Close()

	var employees []*models.CompanyEmployee

	for rows.Next() {
		var employee models.CompanyEmployee

		// pgx v4 UUID type
		var deptID pgtype.UUID
		var reportsTo pgtype.UUID

		err := rows.Scan(
			&employee.CompanyID,
			&employee.EmployeeID,
			&employee.RoleID,
			&deptID,
			&employee.HireDate,
			&employee.IsActive,
			&reportsTo,
			&employee.CreatedAt,
			&employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.UserID = userID

		// Convert department_id if present
		if deptID.Status == pgtype.Present {
			u, _ := uuid.FromBytes(deptID.Bytes[:])
			employee.DepartmentID = &u
		}

		// Convert reports_to if present
		if reportsTo.Status == pgtype.Present {
			u, _ := uuid.FromBytes(reportsTo.Bytes[:])
			employee.ReportsTo = &u
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}

	r.recordQuery()
	return employees, nil
}
