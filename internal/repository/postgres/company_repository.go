// internal/repository/postgres/company_repository_impl.go
package postgres

import (
	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/util"
	"strconv"

	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// Constants for optimization
const (
	MaxCompanyBatchSize    = 100
	MaxConcurrentCompany   = 50
	DefaultCompanyPageSize = 100
	CompanyStmtCacheSize   = 30
)

// // EmployeeRoleHierarchy represents employee role hierarchy for reporting
// type EmployeeRoleHierarchy struct {
// 	EmployeeID   string    `json:"employee_id"`
// 	UserID       uuid.UUID `json:"user_id"`
// 	RoleName     string    `json:"role_name"`
// 	RoleLevel    int       `json:"role_level"`
// 	DepartmentID uuid.UUID `json:"department_id"`
// 	Department   string    `json:"department"`
// 	ReportsTo    uuid.UUID `json:"reports_to"`
// 	IsActive     bool      `json:"is_active"`
// }

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
// SYSTEM DEPARTMENT OPERATIONS
// ============================================================================

// // GetSystemDepartments retrieves all global system departments
// func (r *CompanyRepositoryImpl) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
// 	query := `
// 		SELECT system_department_id, name, module_code, description
// 		FROM system_departments
// 		ORDER BY name`

// 	rows, err := r.client.Query(ctx, query)
// 	if err != nil {
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to query system departments: %w", err)
// 	}
// 	defer rows.Close()

// 	var systemDepartments []*models.SystemDepartment
// 	for rows.Next() {
// 		var dept models.SystemDepartment
// 		err := rows.Scan(
// 			&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
// 		)
// 		if err != nil {
// 			r.logger.Warn("Failed to scan system department row", util.ErrorField(err))
// 			continue
// 		}
// 		systemDepartments = append(systemDepartments, &dept)
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, fmt.Errorf("error iterating system department rows: %w", err)
// 	}

// 	r.recordQuery()
// 	return systemDepartments, nil
// }

// // GetSystemDepartmentByModule retrieves system department by module
// func (r *CompanyRepositoryImpl) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
// 	query := `
// 		SELECT system_department_id, name, module_code, description
// 		FROM system_departments
// 		WHERE module_code = $1
// 		LIMIT 1`

// 	var dept models.SystemDepartment
// 	err := r.client.QueryRow(ctx, query, module).Scan(
// 		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
// 	)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			return nil, fmt.Errorf("system department not found for module: %s", module)
// 		}
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to get system department: %w", err)
// 	}

// 	r.recordQuery()
// 	return &dept, nil
// }

// // GetSystemDepartment retrieves a specific system department by ID
// func (r *CompanyRepositoryImpl) GetSystemDepartment(ctx context.Context, systemDeptID uuid.UUID) (*models.SystemDepartment, error) {
// 	query := `
//         SELECT system_department_id, name, module_code, description
//         FROM system_departments
//         WHERE system_department_id = $1`

// 	var dept models.SystemDepartment
// 	err := r.client.QueryRow(ctx, query, systemDeptID).Scan(
// 		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
// 	)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			return nil, fmt.Errorf("system department not found: %s", systemDeptID)
// 		}
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to get system department: %w", err)
// 	}

// 	r.recordQuery()
// 	return &dept, nil
// }

// ============================================================================
// DEPARTMENT OPERATIONS
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
		department.SystemDepartmentID, department.ParentDepartmentID,
		department.IsActive, department.CreatedAt, department.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create department: %w", err)
	}

	r.recordQuery()
	return nil
}

// // GetDepartment retrieves a department by ID with system department info
// func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
// 	query := `
// 		SELECT d.department_id, d.company_id, d.department_name, d.system_department_id,
// 			   sd.name as system_department_name, sd.module_code,
// 			   d.department_head, d.parent_department_id, d.is_active,
// 			   d.created_at, d.updated_at
// 		FROM departments d
// 		LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
// 		WHERE d.department_id = $1`

// 	var department models.Department
// 	var deptHead, parentDeptID sql.NullString
// 	var systemDeptID sql.NullString
// 	var systemDeptName, moduleCode sql.NullString

// 	err := r.client.QueryRow(ctx, query, departmentID).Scan(
// 		&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
// 		&systemDeptID, &systemDeptName, &moduleCode,
// 		&deptHead, &parentDeptID, &department.IsActive,
// 		&department.CreatedAt, &department.UpdatedAt,
// 	)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			return nil, fmt.Errorf("department not found: %s", departmentID)
// 		}
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to get department: %w", err)
// 	}

// 	if parentDeptID.Valid {
// 		parentID, _ := uuid.Parse(parentDeptID.String)
// 		department.ParentDepartmentID = &parentID
// 	}
// 	if systemDeptID.Valid {
// 		systemID, _ := uuid.Parse(systemDeptID.String)
// 		department.SystemDepartmentID = &systemID
// 	}
// 	if systemDeptName.Valid {
// 		department.SystemDepartmentName = systemDeptName.String
// 	}
// 	if moduleCode.Valid {
// 		department.ModuleCode = moduleCode.String
// 	}

// 	r.recordQuery()
// 	return &department, nil
// }

// // GetDepartmentsByCompany retrieves departments for a company
// func (r *CompanyRepositoryImpl) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
// 	if limit <= 0 || limit > DefaultCompanyPageSize {
// 		limit = DefaultCompanyPageSize
// 	}
// 	if offset < 0 {
// 		offset = 0
// 	}

// 	// Get total count
// 	var totalCount int
// 	countQuery := `SELECT COUNT(*) FROM departments WHERE company_id = $1 AND is_active = true`
// 	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
// 	if err != nil {
// 		r.recordError()
// 		return nil, 0, fmt.Errorf("failed to count departments: %w", err)
// 	}

// 	// Get paginated results
// 	query := `
// 		SELECT department_id, department_name, department_head,
// 			   parent_department_id, created_at, updated_at
// 		FROM departments
// 		WHERE company_id = $1 AND is_active = true
// 		ORDER BY department_name ASC
// 		LIMIT $2 OFFSET $3`

// 	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
// 	if err != nil {
// 		r.recordError()
// 		return nil, 0, fmt.Errorf("failed to query departments: %w", err)
// 	}
// 	defer rows.Close()

// 	departments := make([]*models.Department, 0, limit)
// 	for rows.Next() {
// 		var department models.Department
// 		var deptHead, parentDeptID sql.NullString

// 		err := rows.Scan(
// 			&department.DepartmentID, &department.DepartmentName,
// 			&deptHead, &parentDeptID, &department.CreatedAt, &department.UpdatedAt,
// 		)
// 		if err != nil {
// 			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
// 			continue
// 		}

// 		department.CompanyID = companyID
// 		department.IsActive = true
// 		if parentDeptID.Valid {
// 			parentID, _ := uuid.Parse(parentDeptID.String)
// 			department.ParentDepartmentID = &parentID
// 		}

// 		departments = append(departments, &department)
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, 0, fmt.Errorf("error iterating department rows: %w", err)
// 	}

// 	r.recordQuery()
// 	return departments, totalCount, nil
// }

// UpdateDepartment updates department information
func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.Department) error {
	department.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE departments SET 
			department_name = $1, department_head = $2, 
			parent_department_id = $3, is_active = $4, updated_at = $5
		WHERE department_id = $6`

	result, err := r.client.Exec(ctx, query,
		department.DepartmentName, department.ParentDepartmentID,
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

// UpdateDepartmentName updates a department's name
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

// // GetDepartmentHierarchy retrieves department hierarchy for a company
// func (r *CompanyRepositoryImpl) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
// 	query := `
//         WITH RECURSIVE dept_tree AS (
//             SELECT department_id, department_name, department_head,
//                    parent_department_id, is_active, created_at, updated_at,
//                    1 as level
//             FROM departments
//             WHERE company_id = $1 AND parent_department_id IS NULL AND is_active = true

//             UNION ALL

//             SELECT d.department_id, d.department_name, d.department_head,
//                    d.parent_department_id, d.is_active, d.created_at, d.updated_at,
//                    dt.level + 1
//             FROM departments d
//             INNER JOIN dept_tree dt ON d.parent_department_id = dt.department_id
//             WHERE d.company_id = $1 AND d.is_active = true
//         )
//         SELECT department_id, department_name, department_head,
//                parent_department_id, is_active, level
//         FROM dept_tree
//         ORDER BY level, department_name`

// 	rows, err := r.client.Query(ctx, query, companyID)
// 	if err != nil {
// 		r.recordError()
// 		return nil, fmt.Errorf("failed to query department hierarchy: %w", err)
// 	}
// 	defer rows.Close()

// 	var departments []*models.Department
// 	for rows.Next() {
// 		var department models.Department
// 		var deptHead, parentDeptID sql.NullString
// 		var level int

// 		err := rows.Scan(
// 			&department.DepartmentID, &department.DepartmentName,
// 			&deptHead, &parentDeptID, &department.IsActive, &level,
// 		)
// 		if err != nil {
// 			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
// 			continue
// 		}

// 		department.CompanyID = companyID
// 		if parentDeptID.Valid {
// 			parentID, _ := uuid.Parse(parentDeptID.String)
// 			department.ParentDepartmentID = &parentID
// 		}

// 		departments = append(departments, &department)
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, fmt.Errorf("error iterating department rows: %w", err)
// 	}

// 	r.recordQuery()
// 	return departments, nil
// }

func (r *CompanyRepositoryImpl) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	query := `
        SELECT d.department_name, COUNT(DISTINCT ce.user_id) as employee_count
        FROM departments d
        LEFT JOIN role_departments rd ON d.department_id = rd.department_id
        LEFT JOIN company_employees ce ON rd.role_id = ce.role_id AND ce.is_active = true
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

// GetDepartmentBySystemID retrieves a department by company and system department ID
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

// ============================================================================
// ROLE-DEPARTMENT MAPPING OPERATIONS
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
// ROLE & PERMISSION OPERATIONS
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

// CreateRoleWithDetails creates a role with department and permissions in one transaction
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
// EMPLOYEE OPERATIONS
// ============================================================================
func (r *CompanyRepositoryImpl) CreateEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	query := `
        INSERT INTO company_employees (
            company_id, user_id, employee_id, role_id, position_id,
            hire_date, is_active, reports_to, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.client.Exec(ctx, query,
		employee.CompanyID,
		employee.UserID,
		employee.EmployeeID,
		employee.RoleID,
		employee.PositionID, // NEW: Include position_id
		employee.HireDate,
		employee.IsActive,
		employee.ReportsTo,
		employee.CreatedAt,
		employee.UpdatedAt,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to create employee: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetEmployeesByUser retrieves all company employees for a user
func (r *CompanyRepositoryImpl) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	query := `
        SELECT company_id, employee_id, role_id,
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
		var reportsTo pgtype.UUID

		err := rows.Scan(
			&employee.CompanyID,
			&employee.EmployeeID,
			&employee.RoleID,
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
	r.logger.Debug("Employees by user retrieved",
		util.String("user_id", userID.String()),
		util.Int("employee_count", len(employees)))

	return employees, nil
}

func (r *CompanyRepositoryImpl) UpdateEmployee(ctx context.Context, employee *models.CompanyEmployee) error {
	employee.UpdatedAt = time.Now().UTC()

	query := `
        UPDATE company_employees SET
            employee_id = $1, role_id = $2,
            is_active = $3, reports_to = $4, updated_at = $5
        WHERE company_id = $6 AND user_id = $7`

	result, err := r.client.Exec(ctx, query,
		employee.EmployeeID, employee.RoleID,
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

func (r *CompanyRepositoryImpl) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count active employees: %w", err)
	}

	query := `
        SELECT user_id, employee_id, role_id,
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
		var reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&employee.HireDate, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID
		employee.IsActive = true

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

// GetEmployeeHierarchy retrieves employee hierarchy for a company
func (r *CompanyRepositoryImpl) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	query := `
    SELECT
        ce.user_id,
        ce.employee_id,
        r.role_name,
        r.role_level,
        d.department_id,
        d.department_name,
        ce.reports_to,
        ce.is_active
    FROM company_employees ce
    INNER JOIN roles r
        ON ce.role_id = r.role_id
    LEFT JOIN role_departments rd
        ON ce.role_id = rd.role_id
    LEFT JOIN departments d
        ON rd.department_id = d.department_id
    WHERE ce.company_id = $1
      AND ce.is_active = true
    ORDER BY
        r.role_level ASC,
        d.department_name NULLS LAST,
        ce.employee_id
`
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

// ============================================================================
// PERMISSION & RBAC QUERIES
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
               category, module, requires_tier, bit_index, created_at
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
		var bitIndex sql.NullInt32

		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &bitIndex, &perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}

		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}

		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetPermissionsByNames retrieves permissions by their names
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

// GetUserPermissionNames retrieves permission names for a user
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
func (r *CompanyRepositoryImpl) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		r.recordError()
		return false, fmt.Errorf("failed to get company owner: %w", err)
	}

	if ownerUserID == userID {
		return true, nil
	}

	query := `
        SELECT COUNT(*) > 0
        FROM company_employees ce
        INNER JOIN roles r ON ce.role_id = r.role_id
        INNER JOIN role_departments rd ON r.role_id = rd.role_id
        INNER JOIN departments d ON rd.department_id = d.department_id
        INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        INNER JOIN role_permissions rp ON r.role_id = rp.role_id
        INNER JOIN permissions p ON rp.permission_id = p.permission_id
        WHERE ce.company_id = $1 AND ce.user_id = $2
          AND ce.is_active = true AND p.permission_name = $3
          AND p.module = sd.module_code`

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

	// Get employee role
	var roleID uuid.UUID
	employeeQuery := `
		SELECT role_id
		FROM company_employees
		WHERE company_id = $1 AND user_id = $2 AND is_active = true`
	err = r.client.QueryRow(ctx, employeeQuery, companyID, userID).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			result.Checks["has_employee_record"] = false
			return result, nil
		}
		return nil, fmt.Errorf("failed to get employee record: %w", err)
	}
	result.Checks["has_employee_record"] = true

	// Check if role has permission
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

	// Check if role belongs to at least one department
	var roleDeptExists bool
	roleDeptQuery := `SELECT COUNT(*) > 0 FROM role_departments WHERE role_id = $1`
	err = r.client.QueryRow(ctx, roleDeptQuery, roleID).Scan(&roleDeptExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check role departments: %w", err)
	}
	result.Checks["role_belongs_to_department"] = roleDeptExists

	if !roleDeptExists {
		return result, nil
	}

	// Check module access through role departments
	var moduleMatch bool
	moduleQuery := `
		SELECT COUNT(*) > 0
		FROM role_departments rd
		INNER JOIN departments d ON rd.department_id = d.department_id
		INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		INNER JOIN permissions p ON p.module = sd.module_code
		WHERE rd.role_id = $1 AND p.permission_name = $2`
	err = r.client.QueryRow(ctx, moduleQuery, roleID, permissionName).Scan(&moduleMatch)
	if err != nil {
		return nil, fmt.Errorf("failed to check module access: %w", err)
	}
	result.Checks["module_access"] = moduleMatch

	result.HasPermission = permissionExists && roleDeptExists && moduleMatch
	return result, nil
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

// GetRolePermissionBitmask retrieves permission bitmask for a role
func (r *CompanyRepositoryImpl) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
	query := `
        SELECT p.bit_index
        FROM permissions p
        INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
        WHERE rp.role_id = $1 AND p.bit_index IS NOT NULL`

	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query role permission bitmask: %w", err)
	}
	defer rows.Close()

	var bitPositions []uint64
	for rows.Next() {
		var bitIndex int
		err := rows.Scan(&bitIndex)
		if err != nil {
			r.logger.Warn("Failed to scan bit index", util.ErrorField(err))
			continue
		}
		bitPositions = append(bitPositions, uint64(bitIndex))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role bitmask rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Role permission bitmask retrieved",
		util.String("role_id", roleID.String()),
		util.Int("bit_count", len(bitPositions)))

	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

// GetPermissionsWithBitIndex retrieves all permissions with their bit indexes
func (r *CompanyRepositoryImpl) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
	query := `
        SELECT permission_id, permission_name, bit_index, module, category
        FROM permissions 
        WHERE bit_index IS NOT NULL
        ORDER BY bit_index`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query permissions with bit index: %w", err)
	}
	defer rows.Close()

	var permissions []*models.PermissionWithBitIndex
	for rows.Next() {
		var perm models.PermissionWithBitIndex
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.BitIndex, &perm.Module, &perm.Category,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission with bit index", util.ErrorField(err))
			continue
		}
		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Permissions with bit index retrieved",
		util.Int("permission_count", len(permissions)))

	return permissions, nil
}

// GetPermissionsByBitPositions gets permissions by their bit positions
func (r *CompanyRepositoryImpl) GetPermissionsByBitPositions(ctx context.Context, bitPositions []uint64) ([]*models.Permission, error) {
	if len(bitPositions) == 0 {
		return []*models.Permission{}, nil
	}

	// Convert bit positions to interface slice for query
	args := make([]interface{}, len(bitPositions))
	placeholders := make([]string, len(bitPositions))

	for i, pos := range bitPositions {
		args[i] = int(pos)
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
        SELECT permission_id, permission_name, description, category, module, requires_tier, bit_index
        FROM permissions 
        WHERE bit_index IN (%s)
        ORDER BY bit_index`, strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query permissions by bit positions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32

		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &bitIndex,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission by bit position", util.ErrorField(err))
			continue
		}

		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}

		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetPermissionBitIndexes returns a map of permission names to bit indexes
func (r *CompanyRepositoryImpl) GetPermissionBitIndexes(ctx context.Context, permissionNames []string) (map[string]uint64, error) {
	if len(permissionNames) == 0 {
		return map[string]uint64{}, nil
	}

	args := make([]interface{}, len(permissionNames))
	placeholders := make([]string, len(permissionNames))

	for i, name := range permissionNames {
		args[i] = name
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
        SELECT permission_name, bit_index
        FROM permissions 
        WHERE permission_name IN (%s) AND bit_index IS NOT NULL`,
		strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query permission bit indexes: %w", err)
	}
	defer rows.Close()

	result := make(map[string]uint64)
	for rows.Next() {
		var name string
		var bitIndex int
		err := rows.Scan(&name, &bitIndex)
		if err != nil {
			r.logger.Warn("Failed to scan permission bit index", util.ErrorField(err))
			continue
		}
		result[name] = uint64(bitIndex)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission bit index rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Permission bit indexes retrieved",
		util.Int("permission_count", len(result)))

	return result, nil
}

// Helper method to build full access mask (all bits = 1)
func (r *CompanyRepositoryImpl) buildFullAccessMask() []uint64 {
	// We have 229 permissions, so we need 4 uint64s (229/64 = 3.57 -> 4)
	mask := make([]uint64, 4)
	for i := range mask {
		mask[i] = ^uint64(0) // Set all bits to 1
	}
	return mask
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
func (r *CompanyRepositoryImpl) GetEmployeeRoleHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	query := `
        SELECT 
            ce.company_id, ce.user_id, ce.employee_id, 
            r.role_name, r.role_level,
            d.department_id, d.department_name, 
            ce.reports_to, ce.is_active
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
			&item.CompanyID, &item.UserID, &item.EmployeeID,
			&item.RoleName, &item.RoleLevel,
			&deptID, &deptName, &reportsTo,
			&item.IsActive,
		)
		if err != nil {
			r.logger.Warn("Failed to scan hierarchy row", util.ErrorField(err))
			continue
		}

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
	r.logger.Debug("Employee role hierarchy retrieved",
		util.String("company_id", companyID.String()),
		util.Int("employee_count", len(hierarchy)))

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
func (r *CompanyRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_company": `
			SELECT company_id, company_name, owner_user_id, subscription_tier,
				   subscription_status, max_employees, data_region, is_active,
				   created_at, updated_at, subscription_start_date, subscription_end_date
			FROM companies WHERE company_id = $1`,
		"get_employee": `
			SELECT company_id, user_id, employee_id, role_id,
				   hire_date, is_active, reports_to, created_at, updated_at
			FROM company_employees WHERE company_id = $1 AND user_id = $2`,
		"get_user_permission_bitmask": `
			SELECT DISTINCT p.bit_index
			FROM permissions p
			INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
			INNER JOIN roles r ON rp.role_id = r.role_id
			INNER JOIN company_employees ce ON r.role_id = ce.role_id
			INNER JOIN role_departments rd ON r.role_id = rd.role_id
			INNER JOIN departments d ON rd.department_id = d.department_id
			INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
			WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
			  AND p.module = sd.module_code
			  AND p.bit_index IS NOT NULL`,
		"get_role_permission_bitmask": `
			SELECT p.bit_index
			FROM permissions p
			INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
			WHERE rp.role_id = $1 AND p.bit_index IS NOT NULL`,
		"get_permissions_with_bit_index": `
			SELECT permission_id, permission_name, bit_index, module, category
			FROM permissions
			WHERE bit_index IS NOT NULL
			ORDER BY bit_index`,
		"check_user_permission_full": `
			SELECT COUNT(*) > 0
			FROM company_employees ce
			INNER JOIN roles r ON ce.role_id = r.role_id
			INNER JOIN role_departments rd ON r.role_id = rd.role_id
			INNER JOIN departments d ON rd.department_id = d.department_id
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
			INNER JOIN role_departments rd ON r.role_id = rd.role_id
			INNER JOIN departments d ON rd.department_id = d.department_id
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

// CreateCompany creates a new company with full RBAC setup
// func (r *CompanyRepositoryImpl) CreateCompany(ctx context.Context, company *models.Company, additionalDepartments []string) error {
// 	tx, err := r.client.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("failed to begin transaction: %w", err)
// 	}
// 	defer tx.Rollback()

// 	// 1. Insert company
// 	companyQuery := `
//         INSERT INTO companies (
//             company_id, company_name, owner_user_id, subscription_tier,
//             subscription_status, max_employees, data_region, is_active,
//             created_at, updated_at, subscription_start_date, subscription_end_date
//         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

// 	_, err = tx.ExecContext(ctx, companyQuery,
// 		company.CompanyID, company.CompanyName, company.OwnerUserID, company.SubscriptionTier,
// 		company.SubscriptionStatus, company.MaxEmployees, company.DataRegion, company.IsActive,
// 		company.CreatedAt, company.UpdatedAt, company.SubscriptionStartDate, company.SubscriptionEndDate,
// 	)
// 	if err != nil {
// 		r.recordError()
// 		if strings.Contains(err.Error(), "idx_companies_name_owner_unique") {
// 			return fmt.Errorf("company with name '%s' already exists for this owner", company.CompanyName)
// 		}
// 		return fmt.Errorf("failed to create company: %w", err)
// 	}

// 	// 2. Create OWNER role for this company
// 	ownerRoleID := uuid.New()
// 	ownerRoleQuery := `
//         INSERT INTO roles (
//             role_id, role_name, role_level, company_id, is_system_role,
//             description, created_at, updated_at
//         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// 	_, err = tx.ExecContext(ctx, ownerRoleQuery,
// 		ownerRoleID, "Owner", 1000, company.CompanyID, true,
// 		"Company owner with full permissions", company.CreatedAt, company.UpdatedAt,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to create owner role: %w", err)
// 	}

// 	// 3. Create Default Department: ADMINISTRATION
// 	adminDeptID := uuid.New()
// 	adminDeptQuery := `
//         INSERT INTO departments (
//             department_id, company_id, department_name, system_department_id,
//             is_active, created_at, updated_at
//         ) VALUES ($1, $2, $3, $4, $5, $6, $7)`

// 	_, err = tx.ExecContext(ctx, adminDeptQuery,
// 		adminDeptID, company.CompanyID, "Administration", nil,
// 		true, company.CreatedAt, company.UpdatedAt,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to create administration department: %w", err)
// 	}

// 	// 4. Create Additional Department Rows from user input
// 	systemDepts, err := r.GetSystemDepartments(ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to get system departments: %w", err)
// 	}

// 	// Map department names to system departments
// 	systemDeptMap := make(map[string]uuid.UUID)
// 	for _, dept := range systemDepts {
// 		systemDeptMap[strings.ToLower(dept.ModuleCode)] = dept.SystemDepartmentID
// 	}

// 	// Store created department IDs - ONLY the ones the owner should have access to
// 	ownerAccessDeptIDs := []uuid.UUID{adminDeptID} // Owner always has access to Administration

// 	for _, deptName := range additionalDepartments {
// 		deptID := uuid.New()
// 		var systemDeptID uuid.UUID

// 		// Map department name to system module
// 		switch strings.ToLower(deptName) {
// 		case "hr", "human resources":
// 			systemDeptID = systemDeptMap["hr"]
// 		case "inventory", "warehouse":
// 			systemDeptID = systemDeptMap["inventory"]
// 		case "sales":
// 			systemDeptID = systemDeptMap["sales"]
// 		case "production", "manufacturing":
// 			systemDeptID = systemDeptMap["production"]
// 		case "finance", "accounting":
// 			systemDeptID = systemDeptMap["finance"]
// 		case "logistics", "shipping":
// 			systemDeptID = systemDeptMap["logistics"]
// 		case "it", "technology":
// 			systemDeptID = systemDeptMap["it"]
// 		case "customer support", "support":
// 			systemDeptID = systemDeptMap["support"]
// 		case "quality control", "qc":
// 			systemDeptID = systemDeptMap["qc"]
// 		case "quality assurance", "qa":
// 			systemDeptID = systemDeptMap["qa"]
// 		case "research", "r&d":
// 			systemDeptID = systemDeptMap["rnd"]
// 		case "operations":
// 			systemDeptID = systemDeptMap["operations"]
// 		case "marketing":
// 			systemDeptID = systemDeptMap["marketing"]
// 		case "procurement", "purchasing":
// 			systemDeptID = systemDeptMap["procurement"]
// 		default:
// 			// Use operations as default for unknown departments
// 			systemDeptID = systemDeptMap["operations"]
// 		}

// 		deptQuery := `
//             INSERT INTO departments (
//                 department_id, company_id, department_name, system_department_id,
//                 is_active, created_at, updated_at
//             ) VALUES ($1, $2, $3, $4, $5, $6, $7)`

// 		_, err = tx.ExecContext(ctx, deptQuery,
// 			deptID, company.CompanyID, deptName, systemDeptID,
// 			true, company.CreatedAt, company.UpdatedAt,
// 		)
// 		if err != nil {
// 			r.logger.Warn("Failed to create department",
// 				util.String("department", deptName),
// 				util.ErrorField(err))
// 			continue // Continue with other departments even if one fails
// 		}

// 		// Add this department to owner's accessible departments
// 		ownerAccessDeptIDs = append(ownerAccessDeptIDs, deptID)
// 	}

// 	// 5. Assign ONLY the specified departments to the Owner role (not all departments)
// 	roleDeptQuery := `INSERT INTO role_departments (role_id, department_id) VALUES ($1, $2)`
// 	for _, deptID := range ownerAccessDeptIDs {
// 		_, err = tx.ExecContext(ctx, roleDeptQuery, ownerRoleID, deptID)
// 		if err != nil {
// 			r.logger.Warn("Failed to assign department to owner role",
// 				util.String("department_id", deptID.String()),
// 				util.ErrorField(err))
// 			// Continue even if some assignments fail
// 		}
// 	}

// 	// 6. Grant permissions ONLY for the modules that the owner has access to
// 	// This is the key change: instead of granting ALL permissions, we grant only permissions
// 	// for the modules that the owner's departments belong to
// 	grantPermissionsQuery := `
//         INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
//         SELECT $1, p.permission_id, $2, $3
//         FROM permissions p
//         WHERE p.module IN (
//             SELECT DISTINCT sd.module_code
//             FROM system_departments sd
//             INNER JOIN departments d ON sd.system_department_id = d.system_department_id
//             WHERE d.department_id = ANY($4)
//         )`

// 	// Convert ownerAccessDeptIDs to PostgreSQL UUID array
// 	deptIDStrings := make([]string, len(ownerAccessDeptIDs))
// 	for i, id := range ownerAccessDeptIDs {
// 		deptIDStrings[i] = id.String()
// 	}

// 	_, err = tx.ExecContext(ctx, grantPermissionsQuery,
// 		ownerRoleID, company.OwnerUserID, company.CreatedAt, pq.Array(deptIDStrings))
// 	if err != nil {
// 		return fmt.Errorf("failed to grant permissions to owner role: %w", err)
// 	}

// 	// 7. Insert the Owner as Employee with Administration department
// 	employeeQuery := `
//         INSERT INTO company_employees (
//             company_id, user_id, employee_id, role_id, department_id,
//             hire_date, is_active, created_at, updated_at
//         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

// 	_, err = tx.ExecContext(ctx, employeeQuery,
// 		company.CompanyID, company.OwnerUserID, "OWNER-"+company.CompanyID.String()[:8], ownerRoleID, adminDeptID,
// 		company.CreatedAt, true, company.CreatedAt, company.UpdatedAt,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to add owner as employee: %w", err)
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("failed to commit transaction: %w", err)
// 	}

// 	r.recordQuery()
// 	r.logger.Info("Company created successfully with restricted RBAC setup",
// 		util.String("company_id", company.CompanyID.String()),
// 		util.String("company_name", company.CompanyName),
// 		util.Int("owner_department_count", len(ownerAccessDeptIDs)),
// 		util.Int("additional_departments", len(additionalDepartments)))

// 	return nil
// }

// GetUserPermissions retrieves all permissions for a user with module validation
func (r *CompanyRepositoryImpl) GetUserPermissions(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Permission, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}

	if ownerUserID == userID {
		// Owner gets permissions from all their departments
		query := `
			SELECT DISTINCT p.permission_id, p.permission_name, p.description,
				   p.category, p.module, p.requires_tier, p.created_at
			FROM permissions p
			WHERE p.module IN (
				SELECT DISTINCT sd.module_code
				FROM company_employees ce
				INNER JOIN roles r ON ce.role_id = r.role_id
				INNER JOIN role_departments rd ON r.role_id = rd.role_id
				INNER JOIN departments d ON rd.department_id = d.department_id
				INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
				WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
			)
			ORDER BY p.category, p.permission_name`

		rows, err := r.client.Query(ctx, query, companyID, userID)
		if err != nil {
			r.recordError()
			return nil, fmt.Errorf("failed to query owner permissions: %w", err)
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

	// Regular employee - get permissions through role and role_departments
	query := `
		SELECT DISTINCT p.permission_id, p.permission_name, p.description,
			   p.category, p.module, p.requires_tier, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.role_id
		INNER JOIN company_employees ce ON r.role_id = ce.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id
		INNER JOIN departments d ON rd.department_id = d.department_id
		INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
		  AND p.module = sd.module_code
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

// // GetUserPermissionBitmask retrieves the complete permission bitmask for a user
// func (r *CompanyRepositoryImpl) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
// 	// Check if user is company owner
// 	var ownerUserID uuid.UUID
// 	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
// 	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get company owner: %w", err)
// 	}

// 	// For owners, use a simpler query
// 	if ownerUserID == userID {
// 		query := `
// 			SELECT DISTINCT p.bit_index
// 			FROM permissions p
// 			INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
// 			INNER JOIN roles r ON rp.role_id = r.role_id
// 			INNER JOIN company_employees ce ON r.role_id = ce.role_id
// 			WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
// 			  AND p.bit_index IS NOT NULL`

// 		rows, err := r.client.Query(ctx, query, companyID, userID)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to query owner permission bitmask: %w", err)
// 		}
// 		defer rows.Close()

// 		var bitPositions []uint64
// 		for rows.Next() {
// 			var bitIndex int
// 			err := rows.Scan(&bitIndex)
// 			if err != nil {
// 				r.logger.Warn("Failed to scan bit index", util.ErrorField(err))
// 				continue
// 			}
// 			bitPositions = append(bitPositions, uint64(bitIndex))
// 		}

// 		if err := rows.Err(); err != nil {
// 			return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
// 		}

// 		r.recordQuery()
// 		r.logger.Debug("Owner permission bitmask retrieved",
// 			util.String("user_id", userID.String()),
// 			util.String("company_id", companyID.String()),
// 			util.Int("bit_count", len(bitPositions)))

// 		return rbac.BuildMaskFromBitPositions(bitPositions), nil
// 	}

// 	// For non-owner, get permissions via RBAC flow with module validation
// 	query := `
//         SELECT DISTINCT p.bit_index
//         FROM permissions p
//         INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
//         INNER JOIN roles r ON rp.role_id = r.role_id
//         INNER JOIN company_employees ce ON r.role_id = ce.role_id
//         INNER JOIN role_departments rd ON r.role_id = rd.role_id AND ce.department_id = rd.department_id
//         INNER JOIN departments d ON ce.department_id = d.department_id
//         LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
//         WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
//           AND (sd.system_department_id IS NULL OR p.module = sd.module_code)
//           AND p.bit_index IS NOT NULL`

// 	rows, err := r.client.Query(ctx, query, companyID, userID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to query user permission bitmask: %w", err)
// 	}
// 	defer rows.Close()

// 	var bitPositions []uint64
// 	for rows.Next() {
// 		var bitIndex int
// 		err := rows.Scan(&bitIndex)
// 		if err != nil {
// 			r.logger.Warn("Failed to scan bit index", util.ErrorField(err))
// 			continue
// 		}
// 		bitPositions = append(bitPositions, uint64(bitIndex))
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
// 	}

// 	r.recordQuery()
// 	r.logger.Debug("User permission bitmask retrieved",
// 		util.String("user_id", userID.String()),
// 		util.String("company_id", companyID.String()),
// 		util.Bool("is_owner", false),
// 		util.Int("bit_count", len(bitPositions)))

//		return rbac.BuildMaskFromBitPositions(bitPositions), nil
//	}
//
// CreateCompany creates a new company with full RBAC setup

func (r *CompanyRepositoryImpl) CreateCompany(
	ctx context.Context,
	company *models.Company,
	additionalDepartments []string,
	ownerPositionTitle string,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// ------------------------------------------------------------------
	// 1. Insert company (WITH max_departments)
	// ------------------------------------------------------------------
	companyQuery := `
		INSERT INTO companies (
			company_id,
			company_name,
			owner_user_id,
			subscription_tier,
			subscription_status,
			max_employees,
			max_departments,
			data_region,
			is_active,
			created_at,
			updated_at,
			subscription_start_date,
			subscription_end_date
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`

	_, err = tx.ExecContext(ctx, companyQuery,
		company.CompanyID,
		company.CompanyName,
		company.OwnerUserID,
		company.SubscriptionTier,
		company.SubscriptionStatus,
		company.MaxEmployees,
		company.MaxDepartments,
		company.DataRegion,
		company.IsActive,
		company.CreatedAt,
		company.UpdatedAt,
		company.SubscriptionStartDate,
		company.SubscriptionEndDate,
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_companies_name_owner_unique") {
			return fmt.Errorf("company with name '%s' already exists for this owner", company.CompanyName)
		}
		return fmt.Errorf("failed to create company: %w", err)
	}

	// ------------------------------------------------------------------
	// 2. Create OWNER role
	// ------------------------------------------------------------------
	ownerRoleID := uuid.New()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO roles (
			role_id, role_name, role_level, company_id,
			is_system_role, description, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`,
		ownerRoleID,
		"Owner",
		1000,
		company.CompanyID,
		true,
		"Company owner with full permissions",
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create owner role: %w", err)
	}

	// ------------------------------------------------------------------
	// 3. Load system departments
	// ------------------------------------------------------------------
	systemDepts, err := r.GetSystemDepartments(ctx)
	if err != nil {
		return fmt.Errorf("failed to get system departments: %w", err)
	}

	systemDeptMap := make(map[string]uuid.UUID)
	for _, d := range systemDepts {
		systemDeptMap[strings.ToLower(d.ModuleCode)] = d.SystemDepartmentID
	}

	// ------------------------------------------------------------------
	// 4. Create ADMINISTRATION department (always 1)
	// ------------------------------------------------------------------
	adminSystemDeptID, ok := systemDeptMap["administration"]
	if !ok {
		return fmt.Errorf("administration system department not found")
	}

	adminDeptID := uuid.New()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO departments (
			department_id, company_id, department_name,
			system_department_id, is_active, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`,
		adminDeptID,
		company.CompanyID,
		"Administration",
		adminSystemDeptID,
		true,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create administration department: %w", err)
	}

	// ------------------------------------------------------------------
	// 5. Create OWNER position (Administration)
	// ------------------------------------------------------------------
	adminPositionID := uuid.New()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO positions (
			position_id, company_id, department_id,
			title, is_open, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`,
		adminPositionID,
		company.CompanyID,
		adminDeptID,
		ownerPositionTitle,
		false,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create owner position: %w", err)
	}

	// ------------------------------------------------------------------
	// 6. Create additional departments (LIMITED by max_departments)
	// ------------------------------------------------------------------
	remainingSlots := company.MaxDepartments - 1 // 1 = Administration
	if remainingSlots < 0 {
		remainingSlots = 0
	}

	if len(additionalDepartments) > remainingSlots {
		additionalDepartments = additionalDepartments[:remainingSlots]
	}

	ownerAccessDeptIDs := []uuid.UUID{adminDeptID}
	ownerAccessModules := []string{"administration"}
	positionsByDept := map[uuid.UUID]uuid.UUID{
		adminDeptID: adminPositionID,
	}

	for _, deptName := range additionalDepartments {
		deptID := uuid.New()

		module := strings.ToLower(strings.TrimSpace(deptName))
		systemDeptID, ok := systemDeptMap[module]
		if !ok {
			systemDeptID = systemDeptMap["operations"]
			module = "operations"
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO departments (
				department_id, company_id, department_name,
				system_department_id, is_active, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7)
		`,
			deptID,
			company.CompanyID,
			deptName,
			systemDeptID,
			true,
			company.CreatedAt,
			company.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("department creation failed",
				util.String("department", deptName),
				util.ErrorField(err))
			continue
		}

		positionID := uuid.New()
		_, _ = tx.ExecContext(ctx, `
			INSERT INTO positions (
				position_id, company_id, department_id,
				title, is_open, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7)
		`,
			positionID,
			company.CompanyID,
			deptID,
			fmt.Sprintf("%s Head", deptName),
			true,
			company.CreatedAt,
			company.UpdatedAt,
		)

		positionsByDept[deptID] = positionID
		ownerAccessDeptIDs = append(ownerAccessDeptIDs, deptID)
		ownerAccessModules = append(ownerAccessModules, module)
	}

	// ------------------------------------------------------------------
	// 7. Assign departments to OWNER role
	// ------------------------------------------------------------------
	for _, deptID := range ownerAccessDeptIDs {
		_, _ = tx.ExecContext(ctx,
			`INSERT INTO role_departments (role_id, department_id) VALUES ($1,$2)`,
			ownerRoleID,
			deptID,
		)
	}

	// ------------------------------------------------------------------
	// 8. Grant permissions ONLY for allowed modules
	// ------------------------------------------------------------------
	_, err = tx.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
		SELECT $1, p.permission_id, $2, $3
		FROM permissions p
		WHERE p.module = ANY($4)
	`,
		ownerRoleID,
		company.OwnerUserID,
		company.CreatedAt,
		pq.Array(ownerAccessModules),
	)
	if err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	// ------------------------------------------------------------------
	// 9. Insert OWNER as employee
	// ------------------------------------------------------------------
	_, err = tx.ExecContext(ctx, `
		INSERT INTO company_employees (
			company_id, user_id, employee_id,
			role_id, position_id,
			hire_date, is_active, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		company.CompanyID,
		company.OwnerUserID,
		"OWNER-"+company.CompanyID.String()[:8],
		ownerRoleID,
		adminPositionID,
		company.CreatedAt,
		true,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert owner employee: %w", err)
	}

	// ------------------------------------------------------------------
	// COMMIT
	// ------------------------------------------------------------------
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Company created successfully",
		util.String("company_id", company.CompanyID.String()),
		util.Int("max_departments", company.MaxDepartments),
		util.Int("departments_created", len(ownerAccessDeptIDs)),
	)

	return nil
}

// GetUserPermissionBitmask retrieves the complete permission bitmask for a user
func (r *CompanyRepositoryImpl) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}

	if ownerUserID == userID {
		// Owner gets all permissions from their assigned departments
		query := `
            SELECT DISTINCT p.bit_index
            FROM permissions p
            WHERE p.bit_index IS NOT NULL
            AND p.module IN (
                -- Get modules from the owner's departments through their role
                SELECT DISTINCT sd.module_code
                FROM company_employees ce
                INNER JOIN roles r ON ce.role_id = r.role_id
                INNER JOIN role_departments rd ON r.role_id = rd.role_id
                INNER JOIN departments d ON rd.department_id = d.department_id
                INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
                WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
            )
            ORDER BY p.bit_index`

		rows, err := r.client.Query(ctx, query, companyID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to query owner permission bitmask: %w", err)
		}
		defer rows.Close()

		var bitPositions []uint64
		for rows.Next() {
			var bitIndex int
			err := rows.Scan(&bitIndex)
			if err != nil {
				r.logger.Warn("Failed to scan bit index", util.ErrorField(err))
				continue
			}
			bitPositions = append(bitPositions, uint64(bitIndex))
		}

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
		}

		r.recordQuery()
		return rbac.BuildMaskFromBitPositions(bitPositions), nil
	}

	// Regular employee - get permissions through role and role_departments
	query := `
        SELECT DISTINCT p.bit_index
        FROM permissions p
        INNER JOIN role_permissions rp ON p.permission_id = rp.permission_id
        INNER JOIN roles r ON rp.role_id = r.role_id
        INNER JOIN company_employees ce ON r.role_id = ce.role_id
        INNER JOIN role_departments rd ON r.role_id = rd.role_id
        INNER JOIN departments d ON rd.department_id = d.department_id
        INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
          AND p.module = sd.module_code
          AND p.bit_index IS NOT NULL`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user permission bitmask: %w", err)
	}
	defer rows.Close()

	var bitPositions []uint64
	for rows.Next() {
		var bitIndex int
		err := rows.Scan(&bitIndex)
		if err != nil {
			r.logger.Warn("Failed to scan bit index", util.ErrorField(err))
			continue
		}
		bitPositions = append(bitPositions, uint64(bitIndex))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
	}

	r.recordQuery()
	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

// ============================================================================
// PERMISSION QUERY OPERATIONS
// ============================================================================

// GetPermissionsBySystemDepartments retrieves permissions filtered by system departments and optional filters
func (r *CompanyRepositoryImpl) GetPermissionsBySystemDepartments(
	ctx context.Context,
	systemDeptIDs []uuid.UUID,
	module, category, tier string,
) ([]*models.Permission, error) {

	if len(systemDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}

	// Convert UUIDs to string array for PostgreSQL
	deptIDStrings := make([]string, len(systemDeptIDs))
	for i, id := range systemDeptIDs {
		deptIDStrings[i] = id.String()
	}

	// Build the base query with JOIN on system_departments
	query := `
        SELECT DISTINCT 
            p.permission_id, 
            p.permission_name, 
            p.description, 
            p.category, 
            p.module, 
            p.requires_tier, 
            p.bit_index,
            p.created_at
        FROM permissions p
        INNER JOIN system_departments sd ON p.module = sd.module_code
        WHERE sd.system_department_id = ANY($1)`

	args := []interface{}{pq.Array(deptIDStrings)}
	argCount := 1

	// Add optional filters
	if module != "" {
		argCount++
		query += fmt.Sprintf(" AND p.module = $%d", argCount)
		args = append(args, module)
	}

	if category != "" {
		argCount++
		query += fmt.Sprintf(" AND p.category = $%d", argCount)
		args = append(args, category)
	}

	if tier != "" {
		argCount++
		query += fmt.Sprintf(" AND p.requires_tier = $%d", argCount)
		args = append(args, tier)
	}

	// Add ordering
	query += " ORDER BY p.module, p.category, p.permission_name"

	// Execute query
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions by system departments: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32

		err := rows.Scan(
			&perm.PermissionID,
			&perm.PermissionName,
			&perm.Description,
			&perm.Category,
			&perm.Module,
			&perm.RequiresTier,
			&bitIndex,
			&perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row",
				util.ErrorField(err),
				util.String("method", "GetPermissionsBySystemDepartments"))
			continue
		}

		// Handle nullable bit_index
		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}

		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Permissions retrieved by system departments",
		util.Int("system_dept_count", len(systemDeptIDs)),
		util.Int("permission_count", len(permissions)),
		util.String("module_filter", module),
		util.String("category_filter", category),
		util.String("tier_filter", tier))

	return permissions, nil
}

// GetPermissionsByCompanyModules retrieves permissions for a company's active modules
func (r *CompanyRepositoryImpl) GetPermissionsByCompanyModules(
	ctx context.Context,
	companyID uuid.UUID,
	module, category, tier string,
) ([]*models.Permission, error) {

	// Get company's active system departments through their departments
	query := `
        SELECT DISTINCT sd.system_department_id
        FROM departments d
        INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        WHERE d.company_id = $1 AND d.is_active = true`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query company system departments: %w", err)
	}
	defer rows.Close()

	var systemDeptIDs []uuid.UUID
	for rows.Next() {
		var deptID uuid.UUID
		err := rows.Scan(&deptID)
		if err != nil {
			r.logger.Warn("Failed to scan system department ID", util.ErrorField(err))
			continue
		}
		systemDeptIDs = append(systemDeptIDs, deptID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}

	// Use the main method to get permissions
	return r.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, module, category, tier)
}

// GetModulePermissions retrieves all permissions for specific modules
func (r *CompanyRepositoryImpl) GetModulePermissions(
	ctx context.Context,
	modules []string,
	category, tier string,
) ([]*models.Permission, error) {

	if len(modules) == 0 {
		return []*models.Permission{}, nil
	}

	query := `
        SELECT 
            permission_id, 
            permission_name, 
            description, 
            category, 
            module, 
            requires_tier, 
            bit_index,
            created_at
        FROM permissions 
        WHERE module = ANY($1)`

	args := []interface{}{pq.Array(modules)}
	argCount := 1

	if category != "" {
		argCount++
		query += fmt.Sprintf(" AND category = $%d", argCount)
		args = append(args, category)
	}

	if tier != "" {
		argCount++
		query += fmt.Sprintf(" AND requires_tier = $%d", argCount)
		args = append(args, tier)
	}

	query += " ORDER BY module, category, permission_name"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query module permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32

		err := rows.Scan(
			&perm.PermissionID,
			&perm.PermissionName,
			&perm.Description,
			&perm.Category,
			&perm.Module,
			&perm.RequiresTier,
			&bitIndex,
			&perm.CreatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}

		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}

		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// ============================================================================
// ADVANCED COMPANY SEARCH METHODS
// ============================================================================

// SearchCompaniesByName searches companies by name with advanced text search
// SearchCompaniesByName searches companies by name with advanced text search
func (r *CompanyRepositoryImpl) SearchCompaniesByName(
	ctx context.Context,
	searchQuery string,
	searchType string,
	filters *models.CompanySearchFilters,
	limit, offset int,
) ([]*models.Company, int, error) {

	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	var companies []*models.Company
	var err error

	// Build base conditions
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1

	// Add search condition based on type
	if searchType == "autocomplete" || len(searchQuery) < 3 {
		// Use trigram similarity for partial matches
		conditions = append(conditions,
			fmt.Sprintf("company_name ILIKE $%d", argCounter))
		args = append(args, "%"+searchQuery+"%")
		argCounter++
	} else {
		// Use full-text search for complete words
		conditions = append(conditions,
			fmt.Sprintf("company_name_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
		args = append(args, searchQuery)
		argCounter++
	}

	// Add filters
	if filters != nil {
		if filters.OwnerID != uuid.Nil {
			conditions = append(conditions,
				fmt.Sprintf("owner_user_id = $%d", argCounter))
			args = append(args, filters.OwnerID)
			argCounter++
		}
		if filters.IsActive != nil {
			conditions = append(conditions,
				fmt.Sprintf("is_active = $%d", argCounter))
			args = append(args, *filters.IsActive)
			argCounter++
		}
		if filters.SubscriptionTier != "" {
			conditions = append(conditions,
				fmt.Sprintf("subscription_tier = $%d", argCounter))
			args = append(args, filters.SubscriptionTier)
			argCounter++
		}
		if filters.DataRegion != "" {
			conditions = append(conditions,
				fmt.Sprintf("data_region = $%d", argCounter))
			args = append(args, filters.DataRegion)
			argCounter++
		}
		if filters.SubscriptionStatus != "" {
			conditions = append(conditions,
				fmt.Sprintf("subscription_status = $%d", argCounter))
			args = append(args, filters.SubscriptionStatus)
			argCounter++
		}
	}

	// Build WHERE clause
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf(`
        SELECT COUNT(*) 
        FROM companies 
        %s`, whereClause)

	err = r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Build search query with ordering
	var searchQueryStr string
	if searchType == "autocomplete" || len(searchQuery) < 3 {
		// Use trigram similarity ordering
		searchQueryStr = fmt.Sprintf(`
            SELECT 
                company_id, company_name, owner_user_id, 
                subscription_tier, subscription_status, max_employees,
                data_region, is_active, created_at, updated_at,
                subscription_start_date, subscription_end_date,
                similarity(company_name, $1) as relevance_score
            FROM companies 
            %s
            ORDER BY relevance_score DESC, company_name ASC
            LIMIT $%d OFFSET $%d`,
			whereClause, argCounter, argCounter+1)

		args = append(args, searchQuery, limit, offset)
	} else {
		// Use full-text search ordering
		searchQueryStr = fmt.Sprintf(`
            SELECT 
                company_id, company_name, owner_user_id, 
                subscription_tier, subscription_status, max_employees,
                data_region, is_active, created_at, updated_at,
                subscription_start_date, subscription_end_date,
                ts_rank(company_name_tsv, plainto_tsquery('simple', $1)) as relevance_score
            FROM companies 
            %s
            ORDER BY relevance_score DESC, company_name ASC
            LIMIT $%d OFFSET $%d`,
			whereClause, argCounter, argCounter+1)

		args = append(args, limit, offset)
	}

	// Execute search
	rows, err := r.client.Query(ctx, searchQueryStr, args...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search companies: %w", err)
	}
	defer rows.Close()

	companies = make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		var subStartDate, subEndDate sql.NullTime
		var relevanceScore float64 // We'll read but not use directly

		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID,
			&company.SubscriptionTier, &company.SubscriptionStatus, &company.MaxEmployees,
			&company.DataRegion, &company.IsActive, &company.CreatedAt, &company.UpdatedAt,
			&subStartDate, &subEndDate,
			&relevanceScore,
		)

		if err != nil {
			r.logger.Warn("Failed to scan company search row", util.ErrorField(err))
			continue
		}

		// Handle nullable dates
		if subStartDate.Valid {
			company.SubscriptionStartDate = &subStartDate.Time
		}
		if subEndDate.Valid {
			company.SubscriptionEndDate = &subEndDate.Time
		}

		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Company search completed",
		util.String("query", searchQuery),
		util.String("type", searchType),
		util.Int("results", len(companies)),
		util.Int("total", totalCount))

	return companies, totalCount, nil
}

// OPTION 1: DIRECT SQL APPROACH (RECOMMENDED FOR PROD)
func (r *CompanyRepositoryImpl) SearchCompaniesByOwnerAndName(
	ctx context.Context,
	ownerID uuid.UUID,
	searchQuery string,
	isActive *bool,
	limit, offset int,
) ([]*models.Company, int, error) {

	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// =========================================================
	// STEP 1: Build dynamic WHERE clause with bind parameters
	// =========================================================
	conditions := []string{"owner_user_id = $1"}
	args := []interface{}{ownerID}
	paramCount := 1

	// Text search condition (use trigram for short, full-text for long)
	if searchQuery != "" {
		paramCount++
		if len(searchQuery) < 3 {
			// Use ILIKE with trigram optimization for autocomplete
			conditions = append(conditions,
				fmt.Sprintf("company_name ILIKE $%d", paramCount))
			args = append(args, "%"+searchQuery+"%")
		} else {
			// Use full-text search for complete words
			conditions = append(conditions,
				fmt.Sprintf("company_name_tsv @@ plainto_tsquery('simple', $%d)", paramCount))
			args = append(args, searchQuery)
		}
	}

	// Active status filter
	if isActive != nil {
		paramCount++
		conditions = append(conditions,
			fmt.Sprintf("is_active = $%d", paramCount))
		args = append(args, *isActive)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// =========================================================
	// STEP 2: Get total count (fast with COUNT(*))
	// =========================================================
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM companies %s", whereClause)

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Early return if no results
	if totalCount == 0 || offset >= totalCount {
		return []*models.Company{}, totalCount, nil
	}

	// =========================================================
	// STEP 3: Execute paginated search with optimal ordering
	// =========================================================
	paramCount++ // For limit
	paramCount++ // For offset

	// Add relevance-based ordering
	orderBy := ""
	if searchQuery != "" && len(searchQuery) >= 3 {
		// Full-text: order by relevance score
		orderBy = fmt.Sprintf(`
            ORDER BY 
                ts_rank(company_name_tsv, plainto_tsquery('simple', $%d)) DESC,
                company_name ASC`, 2) // $2 is the searchQuery param position
	} else if searchQuery != "" {
		// Trigram: order by similarity
		orderBy = fmt.Sprintf(`
            ORDER BY 
                similarity(company_name, $%d) DESC,
                company_name ASC`, 2)
	} else {
		// No search query: order by creation date
		orderBy = "ORDER BY created_at DESC"
	}

	// Main search query
	searchQueryStr := fmt.Sprintf(`
        SELECT 
            company_id, company_name, owner_user_id,
            subscription_tier, subscription_status, max_employees,
            data_region, is_active, created_at, updated_at,
            subscription_start_date, subscription_end_date
        FROM companies 
        %s
        %s
        LIMIT $%d OFFSET $%d`,
		whereClause, orderBy, paramCount-1, paramCount)

	// Add pagination parameters
	args = append(args, limit, offset)

	rows, err := r.client.Query(ctx, searchQueryStr, args...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search companies: %w", err)
	}
	defer rows.Close()

	companies := make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		var subStartDate, subEndDate sql.NullTime

		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID,
			&company.SubscriptionTier, &company.SubscriptionStatus, &company.MaxEmployees,
			&company.DataRegion, &company.IsActive, &company.CreatedAt, &company.UpdatedAt,
			&subStartDate, &subEndDate,
		)

		if err != nil {
			r.logger.Warn("Failed to scan company search row",
				util.String("owner_id", ownerID.String()),
				util.ErrorField(err))
			continue
		}

		// Handle nullable dates
		if subStartDate.Valid {
			company.SubscriptionStartDate = &subStartDate.Time
		}
		if subEndDate.Valid {
			company.SubscriptionEndDate = &subEndDate.Time
		}

		companies = append(companies, &company)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Company search by owner completed",
		util.String("owner_id", ownerID.String()),
		util.String("query", searchQuery),
		util.Int("results", len(companies)),
		util.Int("total", totalCount),
		util.Int("limit", limit),
		util.Int("offset", offset))

	return companies, totalCount, nil
}

// GetCompanySuggestions provides autocomplete suggestions
func (r *CompanyRepositoryImpl) GetCompanySuggestions(
	ctx context.Context,
	prefix string,
	limit int,
) ([]string, error) {

	if limit <= 0 || limit > 20 {
		limit = 10
	}

	query := `
        SELECT DISTINCT company_name
        FROM companies 
        WHERE company_name ILIKE $1
        ORDER BY company_name ASC
        LIMIT $2`

	rows, err := r.client.Query(ctx, query, prefix+"%", limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get company suggestions: %w", err)
	}
	defer rows.Close()

	suggestions := make([]string, 0, limit)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		suggestions = append(suggestions, name)
	}

	r.recordQuery()
	return suggestions, nil
}

// ============================================================================
// ANALYTICS METHODS
// ============================================================================

// GetCompanySearchStats gets statistics about company search performance
func (r *CompanyRepositoryImpl) GetCompanySearchStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get total company count
	var totalCompanies int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM companies").Scan(&totalCompanies)
	if err != nil {
		return nil, fmt.Errorf("failed to get company count: %w", err)
	}
	stats["total_companies"] = totalCompanies

	// Get index usage statistics
	indexQuery := `
        SELECT 
            schemaname,
            relname as tablename,
            indexrelname as indexname,
            idx_scan as index_scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched
        FROM pg_stat_user_indexes 
        WHERE relname = 'companies'
        ORDER BY idx_scan DESC`

	rows, err := r.client.Query(ctx, indexQuery)
	if err != nil {
		r.logger.Warn("Failed to get index stats", util.ErrorField(err))
		stats["index_usage_error"] = err.Error()
	} else {
		defer rows.Close()

		var indexStats []map[string]interface{}
		for rows.Next() {
			var schema, table, index string
			var scans, read, fetched int64
			err := rows.Scan(&schema, &table, &index, &scans, &read, &fetched)
			if err != nil {
				continue
			}
			indexStats = append(indexStats, map[string]interface{}{
				"index_name":     index,
				"schema":         schema,
				"table":          table,
				"scans":          scans,
				"tuples_read":    read,
				"tuples_fetched": fetched,
				"efficiency":     calculateEfficiency(read, fetched),
			})
		}
		stats["index_usage"] = indexStats

		// Add summary stats
		if len(indexStats) > 0 {
			var totalScans, totalReads int64
			for _, idx := range indexStats {
				if scans, ok := idx["scans"].(int64); ok {
					totalScans += scans
				}
				if reads, ok := idx["tuples_read"].(int64); ok {
					totalReads += reads
				}
			}
			stats["index_summary"] = map[string]interface{}{
				"total_indexes":       len(indexStats),
				"total_scans":         totalScans,
				"total_tuples_read":   totalReads,
				"avg_scans_per_index": float64(totalScans) / float64(len(indexStats)),
			}
		}
	}

	// Get search pattern statistics
	patternQuery := `
        SELECT 
            LENGTH(company_name) as name_length,
            COUNT(*) as count,
            AVG(LENGTH(company_name)) as avg_length,
            MIN(company_name) as example_name
        FROM companies 
        GROUP BY LENGTH(company_name)
        ORDER BY count DESC
        LIMIT 10`

	rows2, err := r.client.Query(ctx, patternQuery)
	if err != nil {
		r.logger.Warn("Failed to get search patterns", util.ErrorField(err))
		stats["patterns_error"] = err.Error()
	} else {
		defer rows2.Close()

		var patterns []map[string]interface{}
		for rows2.Next() {
			var length int
			var count int
			var avgLength float64
			var exampleName string
			err := rows2.Scan(&length, &count, &avgLength, &exampleName)
			if err != nil {
				continue
			}
			patterns = append(patterns, map[string]interface{}{
				"name_length":  length,
				"count":        count,
				"avg_length":   avgLength,
				"example_name": exampleName,
				"percentage":   float64(count) / float64(totalCompanies) * 100,
			})
		}
		stats["name_patterns"] = patterns
	}

	// Get text search statistics
	searchStatsQuery := `
        SELECT 
            COUNT(*) as total_with_search,
            SUM(CASE WHEN company_name_tsv IS NOT NULL THEN 1 ELSE 0 END) as with_tsvector,
            AVG(LENGTH(company_name)) as avg_name_length,
            MIN(LENGTH(company_name)) as min_name_length,
            MAX(LENGTH(company_name)) as max_name_length
        FROM companies`

	var totalWithSearch, withTsvector int
	var avgLength, minLength, maxLength float64
	err = r.client.QueryRow(ctx, searchStatsQuery).Scan(
		&totalWithSearch, &withTsvector, &avgLength, &minLength, &maxLength,
	)
	if err == nil {
		stats["search_stats"] = map[string]interface{}{
			"total_companies":   totalWithSearch,
			"with_tsvector":     withTsvector,
			"tsvector_coverage": float64(withTsvector) / float64(totalWithSearch) * 100,
			"avg_name_length":   avgLength,
			"min_name_length":   minLength,
			"max_name_length":   maxLength,
		}
	}

	// Get common prefixes for autocomplete
	prefixQuery := `
        SELECT 
            LEFT(company_name, 3) as prefix,
            COUNT(*) as count,
            AVG(LENGTH(company_name)) as avg_length
        FROM companies 
        GROUP BY LEFT(company_name, 3)
        HAVING COUNT(*) > 1
        ORDER BY count DESC
        LIMIT 10`

	rows3, err := r.client.Query(ctx, prefixQuery)
	if err == nil {
		defer rows3.Close()

		var prefixes []map[string]interface{}
		for rows3.Next() {
			var prefix string
			var count int
			var avgLength float64
			err := rows3.Scan(&prefix, &count, &avgLength)
			if err != nil {
				continue
			}
			prefixes = append(prefixes, map[string]interface{}{
				"prefix":               prefix,
				"count":                count,
				"avg_length":           avgLength,
				"suggestion_potential": "high",
			})
		}
		if len(prefixes) > 0 {
			stats["common_prefixes"] = prefixes
		}
	}

	r.recordQuery()
	return stats, nil
}

// Helper function to calculate index efficiency
func calculateEfficiency(tuplesRead, tuplesFetched int64) float64 {
	if tuplesRead == 0 {
		return 0
	}
	return float64(tuplesFetched) / float64(tuplesRead) * 100
}

// internal/repository/postgres/company_repository_impl.go

// Update GetEmployee method
func (r *CompanyRepositoryImpl) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	query := `
        SELECT 
            company_id, user_id, employee_id, role_id, position_id,
            hire_date, is_active, reports_to, created_at, updated_at
        FROM company_employees 
        WHERE company_id = $1 AND user_id = $2`

	var employee models.CompanyEmployee
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
		&employee.CompanyID,
		&employee.UserID,
		&employee.EmployeeID,
		&employee.RoleID,
		&employee.PositionID, // NEW: Scan position_id
		&employee.HireDate,
		&employee.IsActive,
		&employee.ReportsTo,
		&employee.CreatedAt,
		&employee.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("employee not found")
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get employee: %w", err)
	}

	r.recordQuery()
	return &employee, nil
}

// Update GetEmployeesByRole method
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
        SELECT company_id, user_id, employee_id,
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
		var reportsTo sql.NullString

		err := rows.Scan(
			&employee.CompanyID, &employee.UserID, &employee.EmployeeID,
			&employee.HireDate, &employee.IsActive, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.RoleID = roleID

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

// Update GetUsersByRoleLevel method
func (r *CompanyRepositoryImpl) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	query := `
        SELECT ce.user_id, ce.employee_id, ce.role_id,
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
		var reportsTo sql.NullString
		var roleName string
		var roleLevel int

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&employee.HireDate, &employee.IsActive, &reportsTo,
			&roleName, &roleLevel,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

		// Handle nullable UUIDs
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

// Update GetUsersWithPermission method
func (r *CompanyRepositoryImpl) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}

	query := `
        SELECT ce.user_id, ce.employee_id, ce.role_id,
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
		var reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&employee.HireDate, &employee.IsActive, &reportsTo,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

		// Handle nullable UUIDs
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

// Update GetEmployeesByCompany method
func (r *CompanyRepositoryImpl) GetEmployeesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count employees: %w", err)
	}

	query := `
        SELECT user_id, employee_id, role_id,
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
		var reportsTo sql.NullString

		err := rows.Scan(
			&employee.UserID, &employee.EmployeeID, &employee.RoleID,
			&employee.HireDate, &employee.IsActive, &reportsTo,
			&employee.CreatedAt, &employee.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan employee row", util.ErrorField(err))
			continue
		}

		employee.CompanyID = companyID

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

// Add GetEmployeesByDepartment method implementation
func (r *CompanyRepositoryImpl) GetEmployeesByDepartment(ctx context.Context, departmentID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `
        SELECT COUNT(DISTINCT ce.user_id)
        FROM company_employees ce
        INNER JOIN role_departments rd ON ce.role_id = rd.role_id
        WHERE rd.department_id = $1 AND ce.is_active = true`

	err := r.client.QueryRow(ctx, countQuery, departmentID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to get employees count for department: %w", err)
	}

	// Get paginated results
	query := `
        SELECT DISTINCT 
            ce.company_id, ce.user_id, ce.employee_id, ce.role_id,
            ce.hire_date, ce.is_active, ce.reports_to, 
            ce.created_at, ce.updated_at
        FROM company_employees ce
        INNER JOIN role_departments rd ON ce.role_id = rd.role_id
        WHERE rd.department_id = $1 AND ce.is_active = true
        ORDER BY ce.hire_date DESC
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, departmentID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to get employees by department: %w", err)
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
			return nil, 0, fmt.Errorf("failed to scan employee: %w", err)
		}

		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}

		employees = append(employees, &employee)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	return employees, totalCount, nil
}

// // GetEmployeeDepartment gets the department for an employee through role → role_departments → department relationship
// func (r *CompanyRepositoryImpl) GetEmployeeDepartment(ctx context.Context, companyID, userID uuid.UUID) (*models.Department, error) {
//     query := `
//         SELECT DISTINCT d.department_id, d.company_id, d.department_name,
//                d.system_department_id, d.department_head, d.parent_department_id,
//                d.is_active, d.created_at, d.updated_at,
//                sd.name as system_department_name, sd.module_code
//         FROM company_employees ce
//         INNER JOIN roles r ON ce.role_id = r.role_id
//         INNER JOIN role_departments rd ON r.role_id = rd.role_id
//         INNER JOIN departments d ON rd.department_id = d.department_id
//         LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
//         WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
//         LIMIT 1`

//     var department models.Department
//     var deptHead, parentDeptID, systemDeptID sql.NullString
//     var systemDeptName, moduleCode sql.NullString

//     err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
//         &department.DepartmentID, &department.CompanyID, &department.DepartmentName,
//         &systemDeptID, &deptHead, &parentDeptID,
//         &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
//         &systemDeptName, &moduleCode,
//     )

//     if err != nil {
//         if err == sql.ErrNoRows {
//             return nil, fmt.Errorf("employee has no department assigned or not found")
//         }
//         r.recordError()
//         return nil, fmt.Errorf("failed to get employee department: %w", err)
//     }

//     if parentDeptID.Valid {
//         parentID, _ := uuid.Parse(parentDeptID.String)
//         department.ParentDepartmentID = &parentID
//     }
//     if systemDeptID.Valid {
//         systemID, _ := uuid.Parse(systemDeptID.String)
//         department.SystemDepartmentID = &systemID
//     }
//     if systemDeptName.Valid {
//         department.SystemDepartmentName = systemDeptName.String
//     }
//     if moduleCode.Valid {
//         department.ModuleCode = moduleCode.String
//     }

//     r.recordQuery()
//     return &department, nil
// }

// // GetEmployeeDepartments gets all departments for an employee (if multiple roles/departments)
// func (r *CompanyRepositoryImpl) GetEmployeeDepartments(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Department, error) {
//     query := `
//         SELECT DISTINCT d.department_id, d.company_id, d.department_name,
//                d.system_department_id, d.department_head, d.parent_department_id,
//                d.is_active, d.created_at, d.updated_at,
//                sd.name as system_department_name, sd.module_code
//         FROM company_employees ce
//         INNER JOIN roles r ON ce.role_id = r.role_id
//         INNER JOIN role_departments rd ON r.role_id = rd.role_id
//         INNER JOIN departments d ON rd.department_id = d.department_id
//         LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
//         WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
//         ORDER BY d.department_name`

//     rows, err := r.client.Query(ctx, query, companyID, userID)
//     if err != nil {
//         r.recordError()
//         return nil, fmt.Errorf("failed to get employee departments: %w", err)
//     }
//     defer rows.Close()

//     var departments []*models.Department
//     for rows.Next() {
//         var department models.Department
//         var deptHead, parentDeptID, systemDeptID sql.NullString
//         var systemDeptName, moduleCode sql.NullString

//         err := rows.Scan(
//             &department.DepartmentID, &department.CompanyID, &department.DepartmentName,
//             &systemDeptID, &deptHead, &parentDeptID,
//             &department.IsActive, &department.CreatedAt, &department.UpdatedAt,
//             &systemDeptName, &moduleCode,
//         )

//         if err != nil {
//             r.logger.Warn("Failed to scan department row", util.ErrorField(err))
//             continue
//         }

//         if parentDeptID.Valid {
//             parentID, _ := uuid.Parse(parentDeptID.String)
//             department.ParentDepartmentID = &parentID
//         }
//         if systemDeptID.Valid {
//             systemID, _ := uuid.Parse(systemDeptID.String)
//             department.SystemDepartmentID = &systemID
//         }
//         if systemDeptName.Valid {
//             department.SystemDepartmentName = systemDeptName.String
//         }
//         if moduleCode.Valid {
//             department.ModuleCode = moduleCode.String
//         }

//         departments = append(departments, &department)
//     }

//     if err := rows.Err(); err != nil {
//         return nil, fmt.Errorf("error iterating department rows: %w", err)
//     }

//     r.recordQuery()
//     return departments, nil
// }

// DeleteDepartment permanently deletes a department
func (r *CompanyRepositoryImpl) DeleteDepartment(ctx context.Context, departmentID uuid.UUID) error {
	query := `DELETE FROM departments WHERE department_id = $1`

	result, err := r.client.Exec(ctx, query, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete department: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found: %s", departmentID)
	}

	r.recordQuery()
	r.logger.Debug("Department deleted",
		util.String("department_id", departmentID.String()),
		util.Int64("rows_affected", rowsAffected))

	return nil
}

// RemoveAllRoleDepartments removes all role-department mappings for a department
func (r *CompanyRepositoryImpl) RemoveAllRoleDepartments(ctx context.Context, departmentID uuid.UUID) error {
	query := `DELETE FROM role_departments WHERE department_id = $1`

	result, err := r.client.Exec(ctx, query, departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to remove role-department mappings: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.recordQuery()
	r.logger.Debug("Role-department mappings removed",
		util.String("department_id", departmentID.String()),
		util.Int64("rows_affected", rowsAffected))

	return nil
}

// GetSystemDepartmentsWithBitmask returns all system departments with their bitmasks
func (r *CompanyRepositoryImpl) GetSystemDepartmentsWithBitmask(ctx context.Context) ([]*models.SystemDepartment, error) {
	query := `
		SELECT system_department_id, name, module_code, description, bitmask
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
		var bitmask sql.NullInt64

		err := rows.Scan(
			&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description, &bitmask,
		)
		if err != nil {
			r.logger.Warn("Failed to scan system department row", util.ErrorField(err))
			continue
		}

		if bitmask.Valid {
			dept.Bitmask = uint64(bitmask.Int64)
		}

		systemDepartments = append(systemDepartments, &dept)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}

	r.recordQuery()
	return systemDepartments, nil
}

// GetDepartmentBitmask returns bitmask for a specific department
func (r *CompanyRepositoryImpl) GetDepartmentBitmask(ctx context.Context, departmentName string) (uint64, error) {
	query := `
		SELECT bitmask
		FROM system_departments
		WHERE name = $1`

	var bitmask sql.NullInt64
	err := r.client.QueryRow(ctx, query, departmentName).Scan(&bitmask)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("department not found: %s", departmentName)
		}
		r.recordError()
		return 0, fmt.Errorf("failed to get department bitmask: %w", err)
	}

	if !bitmask.Valid {
		return 0, nil
	}

	r.recordQuery()
	return uint64(bitmask.Int64), nil
}

// GetPermissionsByModule returns permissions for specific modules
func (r *CompanyRepositoryImpl) GetPermissionsByModules(ctx context.Context, modules []string) ([]*models.Permission, error) {
	if len(modules) == 0 {
		return []*models.Permission{}, nil
	}

	placeholders := make([]string, len(modules))
	values := make([]interface{}, len(modules))

	for i, module := range modules {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		values[i] = module
	}

	query := fmt.Sprintf(`
		SELECT permission_id, permission_name, description, category, module, requires_tier, bit_index
		FROM permissions
		WHERE module IN (%s)
		ORDER BY module, bit_index`,
		strings.Join(placeholders, ", "))

	rows, err := r.client.Query(ctx, query, values...)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query permissions by module: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		var perm models.Permission
		var bitIndex sql.NullInt32

		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Description,
			&perm.Category, &perm.Module, &perm.RequiresTier, &bitIndex,
		)
		if err != nil {
			r.logger.Warn("Failed to scan permission row", util.ErrorField(err))
			continue
		}

		if bitIndex.Valid {
			perm.BitIndex = int(bitIndex.Int32)
		}

		permissions = append(permissions, &perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	r.recordQuery()
	return permissions, nil
}

// GetSystemDepartments retrieves all global system departments
func (r *CompanyRepositoryImpl) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
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
			&dept.Bitmask,
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
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments 
        WHERE module_code = $1
        LIMIT 1`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, module).Scan(
		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
		&dept.Bitmask,
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

// GetSystemDepartment retrieves a specific system department by ID
func (r *CompanyRepositoryImpl) GetSystemDepartment(ctx context.Context, systemDeptID uuid.UUID) (*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments 
        WHERE system_department_id = $1`

	var dept models.SystemDepartment
	err := r.client.QueryRow(ctx, query, systemDeptID).Scan(
		&dept.SystemDepartmentID, &dept.Name, &dept.ModuleCode, &dept.Description,
		&dept.Bitmask,
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

func (r *CompanyRepositoryImpl) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM departments WHERE company_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count departments: %w", err)
	}

	query := `
		SELECT department_id, department_name, 
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
		var parentDeptID sql.NullString
		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName,
			&parentDeptID, &department.CreatedAt, &department.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}
		department.CompanyID = companyID
		department.IsActive = true
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

func (r *CompanyRepositoryImpl) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
	query := `
		SELECT d.department_id, d.company_id, d.department_name, d.system_department_id,
			   sd.name as system_department_name, sd.module_code,
			   d.parent_department_id, d.is_active,
			   d.created_at, d.updated_at
		FROM departments d
		LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
		WHERE d.department_id = $1`
	var department models.Department
	var parentDeptID sql.NullString
	var systemDeptID sql.NullString
	var systemDeptName, moduleCode sql.NullString
	err := r.client.QueryRow(ctx, query, departmentID).Scan(
		&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
		&systemDeptID, &systemDeptName, &moduleCode,
		&parentDeptID, &department.IsActive,
		&department.CreatedAt, &department.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("department not found: %s", departmentID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get department: %w", err)
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

func (r *CompanyRepositoryImpl) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	query := `
        WITH RECURSIVE dept_tree AS (
            SELECT department_id, department_name,
                   parent_department_id, is_active, created_at, updated_at,
                   1 as level
            FROM departments
            WHERE company_id = $1 AND parent_department_id IS NULL AND is_active = true
            UNION ALL
            SELECT d.department_id, d.department_name,
                   d.parent_department_id, d.is_active, d.created_at, d.updated_at,
                   dt.level + 1
            FROM departments d
            INNER JOIN dept_tree dt ON d.parent_department_id = dt.department_id
            WHERE d.company_id = $1 AND d.is_active = true
        )
        SELECT department_id, department_name,
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
		var parentDeptID sql.NullString
		var level int
		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName,
			&parentDeptID, &department.IsActive, &level,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}
		department.CompanyID = companyID
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

func (r *CompanyRepositoryImpl) GetEmployeeDepartment(ctx context.Context, companyID, userID uuid.UUID) (*models.Department, error) {
	query := `
        SELECT DISTINCT d.department_id, d.company_id, d.department_name,
               d.system_department_id, d.parent_department_id,
               d.is_active, d.created_at, d.updated_at,
               sd.name as system_department_name, sd.module_code
        FROM company_employees ce
        INNER JOIN roles r ON ce.role_id = r.role_id
        INNER JOIN role_departments rd ON r.role_id = rd.role_id
        INNER JOIN departments d ON rd.department_id = d.department_id
        LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
        LIMIT 1`
	var department models.Department
	var parentDeptID, systemDeptID sql.NullString
	var systemDeptName, moduleCode sql.NullString
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
		&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
		&systemDeptID, &parentDeptID,
		&department.IsActive, &department.CreatedAt, &department.UpdatedAt,
		&systemDeptName, &moduleCode,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("employee has no department assigned or not found")
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get employee department: %w", err)
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

func (r *CompanyRepositoryImpl) GetEmployeeDepartments(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Department, error) {
	query := `
        SELECT DISTINCT d.department_id, d.company_id, d.department_name,
               d.system_department_id, d.parent_department_id,
               d.is_active, d.created_at, d.updated_at,
               sd.name as system_department_name, sd.module_code
        FROM company_employees ce
        INNER JOIN roles r ON ce.role_id = r.role_id
        INNER JOIN role_departments rd ON r.role_id = rd.role_id
        INNER JOIN departments d ON rd.department_id = d.department_id
        LEFT JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        WHERE ce.company_id = $1 AND ce.user_id = $2 AND ce.is_active = true
        ORDER BY d.department_name`
	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get employee departments: %w", err)
	}
	defer rows.Close()
	var departments []*models.Department
	for rows.Next() {
		var department models.Department
		var parentDeptID, systemDeptID sql.NullString
		var systemDeptName, moduleCode sql.NullString
		err := rows.Scan(
			&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
			&systemDeptID, &parentDeptID,
			&department.IsActive, &department.CreatedAt, &department.UpdatedAt,
			&systemDeptName, &moduleCode,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
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
		departments = append(departments, &department)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}
	r.recordQuery()
	return departments, nil
}

// CreatePosition creates a new position in the database
func (r *CompanyRepositoryImpl) CreatePosition(ctx context.Context, position *models.Position) error {
	query := `
		INSERT INTO positions (
			position_id, company_id, department_id, title,
			is_open, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.client.Exec(ctx, query,
		position.PositionID,
		position.CompanyID,
		position.DepartmentID,
		position.Title,
		position.IsOpen,
		position.CreatedAt,
		position.UpdatedAt,
	)

	if err != nil {
		r.recordError()

		// Handle duplicate title
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return fmt.Errorf("position with same title already exists in this department")
		}

		return fmt.Errorf("failed to create position: %w", err)
	}

	r.recordQuery()
	return nil
}

// GetPosition retrieves a position by ID
func (r *CompanyRepositoryImpl) GetPosition(ctx context.Context, positionID uuid.UUID) (*models.Position, error) {
	query := `
        SELECT position_id, company_id, department_id, title,
               is_open, created_at, updated_at
        FROM positions
        WHERE position_id = $1`

	var position models.Position
	err := r.client.QueryRow(ctx, query, positionID).Scan(
		&position.PositionID, &position.CompanyID, &position.DepartmentID,
		&position.Title, &position.IsOpen, &position.CreatedAt, &position.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("position not found: %s", positionID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get position: %w", err)
	}

	r.recordQuery()
	return &position, nil
}

// GetPositionsByCompany retrieves all positions for a company
func (r *CompanyRepositoryImpl) GetPositionsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	limit, offset int,
	onlyOpen bool,
) ([]*models.Position, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM positions WHERE company_id = $1`
	if onlyOpen {
		countQuery += ` AND is_open = true`
	}

	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count positions: %w", err)
	}

	query := `
        SELECT position_id, department_id, title, is_open, created_at, updated_at
        FROM positions
        WHERE company_id = $1`

	if onlyOpen {
		query += ` AND is_open = true`
	}

	query += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query positions: %w", err)
	}
	defer rows.Close()

	positions := make([]*models.Position, 0, limit)
	for rows.Next() {
		var position models.Position
		err := rows.Scan(
			&position.PositionID, &position.DepartmentID, &position.Title,
			&position.IsOpen, &position.CreatedAt, &position.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan position row", util.ErrorField(err))
			continue
		}
		position.CompanyID = companyID
		positions = append(positions, &position)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating position rows: %w", err)
	}

	r.recordQuery()
	return positions, totalCount, nil
}

// GetPositionsByDepartment retrieves all positions for a department
func (r *CompanyRepositoryImpl) GetPositionsByDepartment(
	ctx context.Context,
	departmentID uuid.UUID,
	limit, offset int,
	onlyOpen bool,
) ([]*models.Position, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM positions WHERE department_id = $1`
	if onlyOpen {
		countQuery += ` AND is_open = true`
	}

	err := r.client.QueryRow(ctx, countQuery, departmentID).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count department positions: %w", err)
	}

	query := `
        SELECT p.position_id, p.company_id, p.title, p.is_open,
               p.created_at, p.updated_at, d.department_name
        FROM positions p
        INNER JOIN departments d ON p.department_id = d.department_id
        WHERE p.department_id = $1`

	if onlyOpen {
		query += ` AND p.is_open = true`
	}

	query += ` ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, departmentID, limit, offset)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query department positions: %w", err)
	}
	defer rows.Close()

	positions := make([]*models.Position, 0, limit)
	for rows.Next() {
		var position models.Position
		var departmentName string
		err := rows.Scan(
			&position.PositionID, &position.CompanyID, &position.Title,
			&position.IsOpen, &position.CreatedAt, &position.UpdatedAt,
			&departmentName,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department position row", util.ErrorField(err))
			continue
		}
		position.DepartmentID = departmentID
		position.DepartmentName = departmentName
		positions = append(positions, &position)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating department position rows: %w", err)
	}

	r.recordQuery()
	return positions, totalCount, nil
}

// UpdatePosition updates position details
func (r *CompanyRepositoryImpl) UpdatePosition(ctx context.Context, position *models.Position) error {
	position.UpdatedAt = time.Now().UTC()
	query := `
        UPDATE positions SET
            title = $1, department_id = $2, is_open = $3, updated_at = $4
        WHERE position_id = $5`

	result, err := r.client.Exec(ctx, query,
		position.Title, position.DepartmentID, position.IsOpen,
		position.UpdatedAt, position.PositionID,
	)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("position not found: %s", position.PositionID)
	}

	r.recordQuery()
	return nil
}

// DeletePosition deletes a position
func (r *CompanyRepositoryImpl) DeletePosition(ctx context.Context, positionID uuid.UUID) error {
	query := `DELETE FROM positions WHERE position_id = $1`

	result, err := r.client.Exec(ctx, query, positionID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to delete position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("position not found: %s", positionID)
	}

	r.recordQuery()
	return nil
}

// UpdatePositionStatus updates the open/closed status of a position
func (r *CompanyRepositoryImpl) UpdatePositionStatus(ctx context.Context, positionID uuid.UUID, isOpen bool) error {
	query := `UPDATE positions SET is_open = $1, updated_at = $2 WHERE position_id = $3`

	result, err := r.client.Exec(ctx, query, isOpen, time.Now().UTC(), positionID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update position status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("position not found: %s", positionID)
	}

	r.recordQuery()
	return nil
}

// UpdateDepartmentParent updates a department's parent department
func (r *CompanyRepositoryImpl) UpdateDepartmentParent(
	ctx context.Context,
	departmentID uuid.UUID,
	parentDepartmentID *uuid.UUID,
) error {
	// Check for circular references
	if parentDepartmentID != nil {
		if departmentID == *parentDepartmentID {
			return fmt.Errorf("department cannot be its own parent")
		}

		// Check if the parent exists and belongs to the same company
		parentDept, err := r.GetDepartment(ctx, *parentDepartmentID)
		if err != nil {
			return fmt.Errorf("parent department not found: %w", err)
		}

		// Get current department to check company
		currentDept, err := r.GetDepartment(ctx, departmentID)
		if err != nil {
			return fmt.Errorf("department not found: %w", err)
		}

		if parentDept.CompanyID != currentDept.CompanyID {
			return fmt.Errorf("parent department belongs to a different company")
		}

		// Check for circular reference in the hierarchy
		if r.isCircularReference(ctx, departmentID, parentDepartmentID) {
			return fmt.Errorf("circular reference detected in department hierarchy")
		}
	}

	query := `UPDATE departments SET parent_department_id = $1, updated_at = $2 WHERE department_id = $3`

	result, err := r.client.Exec(ctx, query, parentDepartmentID, time.Now().UTC(), departmentID)
	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update department parent: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department not found: %s", departmentID)
	}

	r.recordQuery()
	return nil
}

// isCircularReference checks if setting parent would create a circular reference
func (r *CompanyRepositoryImpl) isCircularReference(
	ctx context.Context,
	departmentID uuid.UUID,
	parentDepartmentID *uuid.UUID,
) bool {
	if parentDepartmentID == nil {
		return false
	}

	// Follow the parent chain to see if we loop back to the original department
	visited := make(map[uuid.UUID]bool)
	current := *parentDepartmentID

	for current != uuid.Nil {
		if current == departmentID {
			return true
		}

		if visited[current] {
			return true // Loop detected
		}

		visited[current] = true

		query := `SELECT parent_department_id FROM departments WHERE department_id = $1`
		var parentID *uuid.UUID
		err := r.client.QueryRow(ctx, query, current).Scan(&parentID)
		if err != nil {
			break
		}

		if parentID == nil {
			break
		}

		current = *parentID
	}

	return false
}

// GetDepartmentChildren retrieves immediate children of a department
func (r *CompanyRepositoryImpl) GetDepartmentChildren(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.Department, error) {
	query := `
        SELECT department_id, company_id, department_name,
               system_department_id, parent_department_id,
               is_active, created_at, updated_at
        FROM departments
        WHERE parent_department_id = $1 AND is_active = true
        ORDER BY department_name ASC`

	rows, err := r.client.Query(ctx, query, departmentID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query department children: %w", err)
	}
	defer rows.Close()

	var children []*models.Department
	for rows.Next() {
		var department models.Department
		var parentDeptID sql.NullString
		var systemDeptID sql.NullString

		err := rows.Scan(
			&department.DepartmentID, &department.CompanyID, &department.DepartmentName,
			&systemDeptID, &parentDeptID,
			&department.IsActive, &department.CreatedAt, &department.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department child row", util.ErrorField(err))
			continue
		}

		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			department.ParentDepartmentID = &parentID
		}

		if systemDeptID.Valid {
			systemID, _ := uuid.Parse(systemDeptID.String)
			department.SystemDepartmentID = &systemID
		}

		children = append(children, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department children rows: %w", err)
	}

	r.recordQuery()
	return children, nil
}

// GetDepartmentTree retrieves entire subtree of a department
func (r *CompanyRepositoryImpl) GetDepartmentTree(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.DepartmentTree, error) {
	query := `
        WITH RECURSIVE dept_tree AS (
            -- Base case: the starting department
            SELECT 
                d.department_id, d.department_name, d.parent_department_id,
                d.is_active, 1 as level,
                ARRAY[d.department_id] as path,
                d.created_at, d.updated_at
            FROM departments d
            WHERE d.department_id = $1 AND d.is_active = true
            
            UNION ALL
            
            -- Recursive case: children of departments in the tree
            SELECT 
                d.department_id, d.department_name, d.parent_department_id,
                d.is_active, dt.level + 1 as level,
                dt.path || d.department_id as path,
                d.created_at, d.updated_at
            FROM departments d
            INNER JOIN dept_tree dt ON d.parent_department_id = dt.department_id
            WHERE d.is_active = true
        )
        SELECT 
            department_id, department_name, parent_department_id,
            level, path
        FROM dept_tree
        ORDER BY level, department_name`

	rows, err := r.client.Query(ctx, query, departmentID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query department tree: %w", err)
	}
	defer rows.Close()

	var tree []*models.DepartmentTree
	for rows.Next() {
		var item models.DepartmentTree
		var parentDeptID sql.NullString
		var pathStr string

		err := rows.Scan(
			&item.DepartmentID, &item.DepartmentName, &parentDeptID,
			&item.Level, &pathStr,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department tree row", util.ErrorField(err))
			continue
		}

		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			item.ParentDepartmentID = &parentID
		}

		// Parse path array
		if pathStr != "" {
			pathStr = strings.Trim(pathStr, "{}")
			if pathStr != "" {
				parts := strings.Split(pathStr, ",")
				for _, part := range parts {
					id, err := uuid.Parse(strings.TrimSpace(part))
					if err == nil {
						item.Path = append(item.Path, id)
					}
				}
			}
		}

		tree = append(tree, &item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department tree rows: %w", err)
	}

	r.recordQuery()
	return tree, nil
}

// GetDepartmentParents gets all parent departments up to root
func (r *CompanyRepositoryImpl) GetDepartmentParents(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.Department, error) {
	query := `
        WITH RECURSIVE dept_parents AS (
            -- Start with the current department
            SELECT 
                d.department_id, d.department_name, d.parent_department_id,
                d.company_id, d.is_active,
                0 as level
            FROM departments d
            WHERE d.department_id = $1 AND d.is_active = true
            
            UNION ALL
            
            -- Recursively get parents
            SELECT 
                d.department_id, d.department_name, d.parent_department_id,
                d.company_id, d.is_active,
                dp.level - 1 as level
            FROM departments d
            INNER JOIN dept_parents dp ON d.department_id = dp.parent_department_id
            WHERE d.is_active = true
        )
        SELECT 
            department_id, department_name, parent_department_id,
            company_id, is_active, level
        FROM dept_parents
        WHERE department_id != $1
        ORDER BY level ASC`

	rows, err := r.client.Query(ctx, query, departmentID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query department parents: %w", err)
	}
	defer rows.Close()

	var parents []*models.Department
	for rows.Next() {
		var department models.Department
		var parentDeptID sql.NullString
		var level int

		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName, &parentDeptID,
			&department.CompanyID, &department.IsActive, &level,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department parent row", util.ErrorField(err))
			continue
		}

		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			department.ParentDepartmentID = &parentID
		}

		parents = append(parents, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department parent rows: %w", err)
	}

	r.recordQuery()
	return parents, nil
}

// MoveDepartmentWithEmployees moves a department and its employees to a new parent
func (r *CompanyRepositoryImpl) MoveDepartmentWithEmployees(
	ctx context.Context,
	departmentID uuid.UUID,
	newParentDepartmentID *uuid.UUID,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update department parent
	updateQuery := `UPDATE departments SET parent_department_id = $1, updated_at = $2 WHERE department_id = $3`
	_, err = tx.ExecContext(ctx, updateQuery, newParentDepartmentID, time.Now().UTC(), departmentID)
	if err != nil {
		return fmt.Errorf("failed to update department parent: %w", err)
	}

	r.recordQuery()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetRootDepartments gets all root departments (no parent) for a company
func (r *CompanyRepositoryImpl) GetRootDepartments(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*models.Department, error) {
	query := `
        SELECT department_id, department_name,
               system_department_id, is_active, created_at, updated_at
        FROM departments
        WHERE company_id = $1 AND parent_department_id IS NULL AND is_active = true
        ORDER BY department_name ASC`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to query root departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var department models.Department
		var systemDeptID sql.NullString

		err := rows.Scan(
			&department.DepartmentID, &department.DepartmentName,
			&systemDeptID, &department.IsActive,
			&department.CreatedAt, &department.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan root department row", util.ErrorField(err))
			continue
		}

		department.CompanyID = companyID
		if systemDeptID.Valid {
			systemID, _ := uuid.Parse(systemDeptID.String)
			department.SystemDepartmentID = &systemID
		}

		departments = append(departments, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating root department rows: %w", err)
	}

	r.recordQuery()
	return departments, nil
}
func (r *CompanyRepositoryImpl) CreateSubDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	parentDepartmentID uuid.UUID,
	departmentName string,
	systemDepartmentID uuid.UUID,
) (*models.Department, error) {

	departmentName = strings.TrimSpace(departmentName)
	if departmentName == "" {
		return nil, fmt.Errorf("department name cannot be empty")
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1️⃣ Validate parent department exists, active, and belongs to company
	var parentCompanyID uuid.UUID
	err = tx.QueryRowContext(
		ctx,
		`
		SELECT company_id
		FROM departments
		WHERE department_id = $1
		  AND is_active = true
		`,
		parentDepartmentID,
	).Scan(&parentCompanyID)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("parent department not found or inactive")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate parent department: %w", err)
	}

	if parentCompanyID != companyID {
		return nil, fmt.Errorf("parent department does not belong to this company")
	}

	// 2️⃣ Insert sub-department (DB enforces limits & uniqueness)
	departmentID := uuid.New()
	now := time.Now().UTC()

	_, err = tx.ExecContext(
		ctx,
		`
		INSERT INTO departments (
			department_id,
			company_id,
			department_name,
			system_department_id,
			parent_department_id,
			is_active,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, true, $6, $7)
		`,
		departmentID,
		companyID,
		departmentName,
		systemDepartmentID,
		parentDepartmentID,
		now,
		now,
	)

	if err != nil {
		// Let DB constraints speak (name conflict, limit exceeded, etc.)
		return nil, fmt.Errorf("failed to create sub-department: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()

	department := &models.Department{
		DepartmentID:       departmentID,
		CompanyID:          companyID,
		DepartmentName:     departmentName,
		SystemDepartmentID: &systemDepartmentID,
		ParentDepartmentID: &parentDepartmentID,
		IsActive:           true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	r.logger.Info(
		"Sub-department created",
		util.String("department_id", departmentID.String()),
		util.String("department_name", departmentName),
		util.String("company_id", companyID.String()),
		util.String("parent_department_id", parentDepartmentID.String()),
	)

	return department, nil
}

func (r *CompanyRepositoryImpl) GetSubDepartments(
	ctx context.Context,
	parentDepartmentID uuid.UUID,
) ([]*models.Department, error) {

	query := `
		SELECT
			department_id,
			company_id,
			department_name,
			system_department_id,
			parent_department_id,
			is_active,
			created_at,
			updated_at
		FROM departments
		WHERE parent_department_id = $1
		ORDER BY department_name ASC
	`

	rows, err := r.client.DB.QueryContext(ctx, query, parentDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sub-departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department

	for rows.Next() {
		var dept models.Department
		var systemDeptID *uuid.UUID
		var parentDeptID *uuid.UUID

		if err := rows.Scan(
			&dept.DepartmentID,
			&dept.CompanyID,
			&dept.DepartmentName,
			&systemDeptID,
			&parentDeptID,
			&dept.IsActive,
			&dept.CreatedAt,
			&dept.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan sub-department: %w", err)
		}

		dept.SystemDepartmentID = systemDeptID
		dept.ParentDepartmentID = parentDeptID

		departments = append(departments, &dept)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sub-departments: %w", err)
	}

	r.recordQuery()
	return departments, nil
}
func (r *CompanyRepositoryImpl) GetCompanyByID(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	query := `
		SELECT company_id, company_name, owner_user_id,
			   subscription_tier, subscription_status,
			   max_employees, max_departments,
			   data_region, is_active,
			   created_at, updated_at,
			   subscription_start_date, subscription_end_date
		FROM companies
		WHERE company_id = $1`

	var company models.Company
	var subStart, subEnd sql.NullTime

	err := r.client.QueryRow(ctx, query, companyID).Scan(
		&company.CompanyID,
		&company.CompanyName,
		&company.OwnerUserID,
		&company.SubscriptionTier,
		&company.SubscriptionStatus,
		&company.MaxEmployees,
		&company.MaxDepartments,
		&company.DataRegion,
		&company.IsActive,
		&company.CreatedAt,
		&company.UpdatedAt,
		&subStart,
		&subEnd,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("company not found: %s", companyID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get company by id: %w", err)
	}

	if subStart.Valid {
		company.SubscriptionStartDate = &subStart.Time
	}
	if subEnd.Valid {
		company.SubscriptionEndDate = &subEnd.Time
	}

	r.recordQuery()
	return &company, nil
}
func (r *CompanyRepositoryImpl) GetActiveDepartmentCount(
	ctx context.Context,
	companyID uuid.UUID,
) (int, error) {

	query := `
		SELECT COUNT(*)
		FROM departments
		WHERE company_id = $1
		  AND is_active = true`

	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		r.recordError()
		return 0, fmt.Errorf("failed to get active department count: %w", err)
	}

	r.recordQuery()
	return count, nil
}
func (r *CompanyRepositoryImpl) UpdateMaxDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	newMaxDepartments int,
) error {

	if newMaxDepartments <= 0 {
		return fmt.Errorf("max_departments must be greater than zero")
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Lock company row
	var currentMax int
	err = tx.QueryRowContext(ctx, `
		SELECT max_departments
		FROM companies
		WHERE company_id = $1
		FOR UPDATE
	`, companyID).Scan(&currentMax)
	if err != nil {
		return fmt.Errorf("company not found: %w", err)
	}

	// Count active departments
	var activeCount int
	err = tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM departments
		WHERE company_id = $1 AND is_active = true
	`, companyID).Scan(&activeCount)
	if err != nil {
		return fmt.Errorf("failed to count active departments: %w", err)
	}

	if newMaxDepartments < activeCount {
		return fmt.Errorf(
			"cannot reduce max_departments below active departments (%d)",
			activeCount,
		)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE companies
		SET max_departments = $1,
		    updated_at = $2
		WHERE company_id = $3
	`, newMaxDepartments, time.Now().UTC(), companyID)
	if err != nil {
		return fmt.Errorf("failed to update max_departments: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Max departments updated",
		util.String("company_id", companyID.String()),
		util.Int("old_max_departments", currentMax),
		util.Int("new_max_departments", newMaxDepartments),
		util.Int("active_departments", activeCount),
	)

	return nil
}
func (r *CompanyRepositoryImpl) CheckDepartmentLimit(
	ctx context.Context,
	companyID uuid.UUID,
) error {

	info, err := r.GetCompanyDepartmentInfo(ctx, companyID)
	if err != nil {
		return err
	}

	if info.ActiveDepartments >= info.MaxDepartments {
		return fmt.Errorf(
			"department limit reached (%d/%d)",
			info.ActiveDepartments,
			info.MaxDepartments,
		)
	}

	return nil
}

type CompanyDepartmentInfo struct {
	CompanyID            uuid.UUID
	MaxDepartments       int
	ActiveDepartments    int
	RemainingDepartments int
}

func (r *CompanyRepositoryImpl) GetCompanyDepartmentInfo(
	ctx context.Context,
	companyID uuid.UUID,
) (*CompanyDepartmentInfo, error) {

	query := `
		SELECT
			c.company_id,
			c.max_departments,
			COUNT(d.department_id) FILTER (WHERE d.is_active = true)
		FROM companies c
		LEFT JOIN departments d ON d.company_id = c.company_id
		WHERE c.company_id = $1
		GROUP BY c.company_id, c.max_departments`

	var info CompanyDepartmentInfo

	err := r.client.QueryRow(ctx, query, companyID).Scan(
		&info.CompanyID,
		&info.MaxDepartments,
		&info.ActiveDepartments,
	)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get company department info: %w", err)
	}

	info.RemainingDepartments = info.MaxDepartments - info.ActiveDepartments
	if info.RemainingDepartments < 0 {
		info.RemainingDepartments = 0
	}

	r.recordQuery()
	return &info, nil
}

func (r *CompanyRepositoryImpl) CreateCompanyDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentName string,
	systemDepartmentID uuid.UUID,
) (*models.Department, error) {

	departmentName = strings.TrimSpace(departmentName)
	if departmentName == "" {
		return nil, fmt.Errorf("department name cannot be empty")
	}

	now := time.Now().UTC()
	departmentID := uuid.New()

	query := `
		INSERT INTO departments (
			department_id,
			company_id,
			department_name,
			system_department_id,
			parent_department_id,
			is_active,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, NULL, true, $5, $6)
	`

	_, err := r.client.Exec(ctx, query,
		departmentID,
		companyID,
		departmentName,
		systemDepartmentID,
		now,
		now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "departments_company_id_department_name_key") {
			return nil, fmt.Errorf("department '%s' already exists in this company", departmentName)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to create department: %w", err)
	}

	r.recordQuery()

	department := &models.Department{
		DepartmentID:       departmentID,
		CompanyID:          companyID,
		DepartmentName:     departmentName,
		SystemDepartmentID: &systemDepartmentID,
		IsActive:           true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	r.logger.Info("Company department created by admin",
		util.String("department_id", departmentID.String()),
		util.String("company_id", companyID.String()),
		util.String("department_name", departmentName),
	)

	return department, nil
}

// GetDepartmentByID retrieves a department by ID with system department info
func (r *CompanyRepositoryImpl) GetDepartmentByID(
	ctx context.Context,
	departmentID uuid.UUID,
) (*models.Department, error) {

	query := `
		SELECT
			d.department_id,
			d.company_id,
			d.department_name,
			d.system_department_id,
			sd.name AS system_department_name,
			sd.module_code,
			d.parent_department_id,
			d.is_active,
			d.created_at,
			d.updated_at
		FROM departments d
		LEFT JOIN system_departments sd
			ON d.system_department_id = sd.system_department_id
		WHERE d.department_id = $1
	`

	var dept models.Department

	var systemDeptID sql.NullString
	var systemDeptName sql.NullString
	var moduleCode sql.NullString
	var parentDeptID sql.NullString

	err := r.client.QueryRow(ctx, query, departmentID).Scan(
		&dept.DepartmentID,
		&dept.CompanyID,
		&dept.DepartmentName,
		&systemDeptID,
		&systemDeptName,
		&moduleCode,
		&parentDeptID,
		&dept.IsActive,
		&dept.CreatedAt,
		&dept.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("department not found: %s", departmentID)
		}
		r.recordError()
		return nil, fmt.Errorf("failed to get department: %w", err)
	}

	// Nullable system department
	if systemDeptID.Valid {
		id, _ := uuid.Parse(systemDeptID.String)
		dept.SystemDepartmentID = &id
	}
	if systemDeptName.Valid {
		dept.SystemDepartmentName = systemDeptName.String
	}
	if moduleCode.Valid {
		dept.ModuleCode = moduleCode.String
	}

	// Nullable parent department
	if parentDeptID.Valid {
		id, _ := uuid.Parse(parentDeptID.String)
		dept.ParentDepartmentID = &id
	}

	r.recordQuery()
	return &dept, nil
}

func (r *CompanyRepositoryImpl) PositionExists(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
	title string,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM positions
			WHERE company_id = $1
			  AND department_id = $2
			  AND LOWER(title) = LOWER($3)
		)`

	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, departmentID, title).Scan(&exists)
	return exists, err
}

// Add this to your CompanyRepository interface (postgres/company_repository.go)
func (r *CompanyRepositoryImpl) SearchDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	searchQuery string,
	limit int,
	offset int,
	includeInactive bool,
) ([]*models.DepartmentSearchResult, int, error) {

	start := time.Now()

	// Base select query
	baseQuery := `
		SELECT 
			d.department_id, 
			d.company_id, 
			d.department_name,
			d.system_department_id,
			d.parent_department_id,
			d.is_active,
			d.created_at,
			d.updated_at,
			sd.name AS system_department_name,
			sd.module_code AS system_module_code,
			parent.department_name AS parent_department_name
		FROM departments d
		LEFT JOIN system_departments sd 
			ON d.system_department_id = sd.system_department_id
		LEFT JOIN departments parent 
			ON d.parent_department_id = parent.department_id
		WHERE d.company_id = $1
	`

	// Count query
	countQuery := `
		SELECT COUNT(*)
		FROM departments d
		WHERE d.company_id = $1
	`

	var (
		whereClause string
		queryParams []interface{}
	)

	queryParams = append(queryParams, companyID)

	// Active filter
	if !includeInactive {
		whereClause += " AND d.is_active = true"
	}

	// Search filter
	if searchQuery != "" {
		whereClause += " AND d.department_name ILIKE $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, "%"+searchQuery+"%")
	}

	// Execute count query
	var totalCount int
	err := r.client.QueryRow(
		ctx,
		countQuery+whereClause,
		queryParams...,
	).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count departments: %w", err)
	}

	// Pagination
	searchSQL := baseQuery + whereClause +
		` ORDER BY d.department_name ASC
		  LIMIT $` + strconv.Itoa(len(queryParams)+1) +
		` OFFSET $` + strconv.Itoa(len(queryParams)+2)

	queryParams = append(queryParams, limit, offset)

	rows, err := r.client.Query(ctx, searchSQL, queryParams...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to search departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.DepartmentSearchResult

	for rows.Next() {
		var d models.DepartmentSearchResult

		var (
			systemDeptID, parentDeptID sql.NullString
			systemDeptName, moduleCode sql.NullString
			parentDeptName             sql.NullString
		)

		err := rows.Scan(
			&d.DepartmentID,
			&d.CompanyID,
			&d.DepartmentName,
			&systemDeptID,
			&parentDeptID,
			&d.IsActive,
			&d.CreatedAt,
			&d.UpdatedAt,
			&systemDeptName,
			&moduleCode,
			&parentDeptName,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department row", util.ErrorField(err))
			continue
		}

		if systemDeptID.Valid {
			if id, err := uuid.Parse(systemDeptID.String); err == nil {
				d.SystemDepartmentID = &id
			}
		}
		if parentDeptID.Valid {
			if id, err := uuid.Parse(parentDeptID.String); err == nil {
				d.ParentDepartmentID = &id
			}
		}
		if systemDeptName.Valid {
			d.SystemDepartmentName = systemDeptName.String
		}
		if moduleCode.Valid {
			d.ModuleCode = moduleCode.String
		}
		if parentDeptName.Valid {
			d.ParentDepartmentName = parentDeptName.String
		}

		departments = append(departments, &d)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating department rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("Department search completed",
		util.String("company_id", companyID.String()),
		util.String("query", searchQuery),
		util.Int("results", len(departments)),
		util.Duration("duration", time.Since(start)),
	)

	return departments, totalCount, nil
}

// Also add this function to get department suggestions
func (r *CompanyRepositoryImpl) GetDepartmentSuggestions(
	ctx context.Context,
	companyID uuid.UUID,
	prefix string,
	limit int,
) ([]*models.Department, error) {
	query := `
        SELECT 
            department_id,
            department_name,
            system_department_id,
            is_active
        FROM departments
        WHERE company_id = $1 
          AND department_name ILIKE $2 || '%'
          AND is_active = true
        ORDER BY department_name
        LIMIT $3`

	rows, err := r.client.Query(ctx, query, companyID, prefix, limit)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("failed to get department suggestions: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var department models.Department
		var systemDeptID sql.NullString

		err := rows.Scan(
			&department.DepartmentID,
			&department.DepartmentName,
			&systemDeptID,
			&department.IsActive,
		)
		if err != nil {
			r.logger.Warn("Failed to scan department suggestion row", util.ErrorField(err))
			continue
		}

		department.CompanyID = companyID
		if systemDeptID.Valid {
			systemID, _ := uuid.Parse(systemDeptID.String)
			department.SystemDepartmentID = &systemID
		}

		departments = append(departments, &department)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department suggestion rows: %w", err)
	}

	r.recordQuery()
	return departments, nil
}
func (r *CompanyRepositoryImpl) SoftDeleteDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Fetch current department name
	var deptName string
	err = tx.QueryRowContext(ctx, `
		SELECT department_name
		FROM departments
		WHERE department_id = $1
		  AND company_id = $2
		  AND is_active = true
	`, departmentID, companyID).Scan(&deptName)

	if err == sql.ErrNoRows {
		return fmt.Errorf("department not found or already inactive")
	}
	if err != nil {
		return fmt.Errorf("failed to fetch department name: %w", err)
	}

	// 2. Create archived name
	archivedName := fmt.Sprintf(
		"%s__archived_%d",
		deptName,
		time.Now().UnixNano()%10000,
	)

	// 3. Soft delete (DB trigger handles children + positions)
	res, err := tx.ExecContext(ctx, `
		UPDATE departments
		SET is_active = false,
		    department_name = $3,
		    updated_at = $4
		WHERE department_id = $1
		  AND company_id = $2
	`, departmentID, companyID, archivedName, time.Now().UTC())

	if err != nil {
		return fmt.Errorf("failed to soft delete department: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("department not found")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Department soft deleted",
		util.String("department_id", departmentID.String()),
		util.String("company_id", companyID.String()),
		util.String("archived_name", archivedName),
	)

	return nil
}
func (r *CompanyRepositoryImpl) ActivateDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var deptName string
	err = tx.QueryRowContext(ctx, `
		SELECT department_name
		FROM departments
		WHERE department_id = $1
		  AND company_id = $2
		  AND is_active = false
	`, departmentID, companyID).Scan(&deptName)

	if err == sql.ErrNoRows {
		return fmt.Errorf("department not found or already active")
	}
	if err != nil {
		return fmt.Errorf("failed to fetch department: %w", err)
	}

	finalName := deptName

	// Check name conflict
	var exists bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM departments
			WHERE company_id = $1
			  AND department_name = $2
			  AND is_active = true
		)
	`, companyID, deptName).Scan(&exists)

	if err != nil {
		return fmt.Errorf("failed to check department name conflict: %w", err)
	}

	if exists {
		finalName = fmt.Sprintf(
			"%s_%d",
			deptName,
			time.Now().UnixNano()%1000,
		)
	}

	// Activate department
	_, err = tx.ExecContext(ctx, `
		UPDATE departments
		SET is_active = true,
		    department_name = $3,
		    updated_at = $4
		WHERE department_id = $1
		  AND company_id = $2
	`, departmentID, companyID, finalName, time.Now().UTC())

	if err != nil {
		return fmt.Errorf("failed to activate department: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.recordQuery()
	r.logger.Info("Department activated",
		util.String("department_id", departmentID.String()),
		util.String("company_id", companyID.String()),
		util.String("final_name", finalName),
	)

	return nil
}

// UpdateEmployeePosition updates an employee's position
func (r *CompanyRepositoryImpl) UpdateEmployeePosition(ctx context.Context, companyID, userID uuid.UUID, positionID *uuid.UUID) error {
	query := `
		UPDATE company_employees 
		SET position_id = $1, updated_at = $2
		WHERE company_id = $3 AND user_id = $4
	`

	result, err := r.client.Exec(ctx, query,
		positionID,
		time.Now().UTC(),
		companyID,
		userID,
	)

	if err != nil {
		r.recordError()
		return fmt.Errorf("failed to update employee position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee not found")
	}

	r.recordQuery()
	return nil
}

// GetEmployeeWithPosition gets employee details including position
func (r *CompanyRepositoryImpl) GetEmployeeWithPosition(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, *models.Position, error) {
	query := `
		SELECT 
			ce.company_id, ce.user_id, ce.employee_id, ce.role_id, 
			ce.position_id, ce.hire_date, ce.is_active, ce.reports_to,
			ce.created_at, ce.updated_at,
			p.position_id, p.company_id as pos_company_id, p.department_id,
			p.title, p.is_open, p.created_at as pos_created_at, p.updated_at as pos_updated_at
		FROM company_employees ce
		LEFT JOIN positions p ON ce.position_id = p.position_id
		WHERE ce.company_id = $1 AND ce.user_id = $2
	`

	var (
		emp      models.CompanyEmployee
		position *models.Position
	)

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query employee: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		var (
			posPositionID, posCompanyID, posDepartmentID *uuid.UUID
			posTitle                                     *string
			posIsOpen                                    *bool
			posCreatedAt, posUpdatedAt                   *time.Time
		)

		err := rows.Scan(
			&emp.CompanyID,
			&emp.UserID,
			&emp.EmployeeID,
			&emp.RoleID,
			&emp.PositionID,
			&emp.HireDate,
			&emp.IsActive,
			&emp.ReportsTo,
			&emp.CreatedAt,
			&emp.UpdatedAt,
			&posPositionID,
			&posCompanyID,
			&posDepartmentID,
			&posTitle,
			&posIsOpen,
			&posCreatedAt,
			&posUpdatedAt,
		)

		if err != nil {
			return nil, nil, fmt.Errorf("failed to scan employee: %w", err)
		}

		// If position data exists
		if posPositionID != nil {
			position = &models.Position{
				PositionID:   *posPositionID,
				CompanyID:    *posCompanyID,
				DepartmentID: *posDepartmentID,
				Title:        *posTitle,
				IsOpen:       *posIsOpen,
				CreatedAt:    *posCreatedAt,
				UpdatedAt:    *posUpdatedAt,
			}
		}
	} else {
		return nil, nil, fmt.Errorf("employee not found")
	}

	return &emp, position, nil
}
func (r *CompanyRepositoryImpl) GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error) {
	start := time.Now()

	if limit <= 0 {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Count total
	var countQuery string
	var countArgs []interface{}
	countArgs = append(countArgs, companyID)

	if isOpen != nil {
		countQuery = `SELECT COUNT(*) FROM positions WHERE company_id = $1 AND is_open = $2`
		countArgs = append(countArgs, *isOpen)
	} else {
		countQuery = `SELECT COUNT(*) FROM positions WHERE company_id = $1`
	}

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, countArgs...).Scan(&totalCount)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to count positions: %w", err)
	}

	// Query positions
	query := `
		SELECT 
			p.position_id, 
			p.company_id, 
			p.department_id, 
			p.title, 
			p.is_open, 
			p.created_at, 
			p.updated_at
		FROM positions p
		INNER JOIN departments d ON p.department_id = d.department_id
		WHERE p.company_id = $1 AND d.is_active = true
	`

	var queryArgs []interface{}
	queryArgs = append(queryArgs, companyID)
	argCounter := 2

	if isOpen != nil {
		query += fmt.Sprintf(" AND p.is_open = $%d", argCounter)
		queryArgs = append(queryArgs, *isOpen)
		argCounter++
	}

	query += fmt.Sprintf(" ORDER BY p.created_at DESC LIMIT $%d OFFSET $%d", argCounter, argCounter+1)
	queryArgs = append(queryArgs, limit, offset)

	rows, err := r.client.Query(ctx, query, queryArgs...)
	if err != nil {
		r.recordError()
		return nil, 0, fmt.Errorf("failed to query open positions: %w", err)
	}
	defer rows.Close()

	var positions []*models.Position
	for rows.Next() {
		var position models.Position
		err := rows.Scan(
			&position.PositionID,
			&position.CompanyID,
			&position.DepartmentID,
			&position.Title,
			&position.IsOpen,
			&position.CreatedAt,
			&position.UpdatedAt,
		)
		if err != nil {
			r.logger.Warn("Failed to scan position row", util.ErrorField(err))
			continue
		}
		positions = append(positions, &position)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating position rows: %w", err)
	}

	r.recordQuery()
	r.logger.Debug("GetOpenPositions completed",
		util.String("company_id", companyID.String()),
		util.Int("total", totalCount),
		util.Int("returned", len(positions)),
		util.Duration("duration", time.Since(start)),
	)

	return positions, totalCount, nil
}
