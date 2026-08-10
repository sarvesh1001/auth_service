package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/lib/pq"
)

const (
	MaxCompanyBatchSize    = 100
	MaxConcurrentCompany   = 50
	DefaultCompanyPageSize = 100
)

type CompanyRepositoryImpl struct {
	client *client.PostgresClient
}

// NewCompanyRepository creates a new CompanyRepository instance.
func NewCompanyRepository(postgresClient *client.PostgresClient) CompanyRepository {
	return &CompanyRepositoryImpl{
		client: postgresClient,
	}
}

// Close implements the CompanyRepository interface.
// No resources to clean up in this version.
func (r *CompanyRepositoryImpl) Close() error {
	return nil
}

// ---- Company CRUD ----

// GetCompany retrieves a company by ID.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	query := `
		SELECT company_id, company_name, owner_user_id, subscription_tier,
			   subscription_status, max_employees, max_departments, data_region, is_active,
			   created_at, updated_at, subscription_start_date, subscription_end_date,
			   financial_year_start_month
		FROM companies WHERE company_id = $1`

	var company models.Company
	var subStartDate, subEndDate sql.NullTime

	err := r.client.QueryRow(ctx, query, companyID).Scan(
		&company.CompanyID,
		&company.CompanyName,
		&company.OwnerUserID,
		&company.SubscriptionTier,
		&company.SubscriptionStatus,
		&company.MaxEmployees,
		&company.MaxDepartments, // ✅ added
		&company.DataRegion,
		&company.IsActive,
		&company.CreatedAt,
		&company.UpdatedAt,
		&subStartDate,
		&subEndDate,
		&company.FinancialYearStartMonth, // ✅ added
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get company: %w", err)
	}

	if subStartDate.Valid {
		company.SubscriptionStartDate = &subStartDate.Time
	}
	if subEndDate.Valid {
		company.SubscriptionEndDate = &subEndDate.Time
	}

	return &company, nil
}

// GetCompaniesByOwner returns active companies owned by a user.
func (r *CompanyRepositoryImpl) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	query := `
		SELECT company_id, company_name, subscription_tier, subscription_status,
			   max_employees, is_active, created_at
		FROM companies
		WHERE owner_user_id = $1 AND is_active = true
		ORDER BY created_at DESC`
	rows, err := r.client.Query(ctx, query, ownerUserID)
	if err != nil {
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
			continue
		}
		company.OwnerUserID = ownerUserID
		companies = append(companies, &company)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating company rows: %w", err)
	}
	return companies, nil
}

// UpdateCompany updates an existing company.
// Returns apperrors.ErrNotFound if company not found.
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
		return fmt.Errorf("failed to update company: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateCompanyStatus updates the is_active flag.
// Returns apperrors.ErrNotFound if company not found.
func (r *CompanyRepositoryImpl) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool) error {
	query := `UPDATE companies SET is_active = $1, updated_at = $2 WHERE company_id = $3`
	result, err := r.client.Exec(ctx, query, isActive, time.Now().UTC(), companyID)
	if err != nil {
		return fmt.Errorf("failed to update company status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateSubscription updates subscription details.
// Returns apperrors.ErrNotFound if company not found.
func (r *CompanyRepositoryImpl) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int) error {
	query := `
		UPDATE companies SET
			subscription_tier = $1, subscription_status = $2,
			max_employees = $3, updated_at = $4
		WHERE company_id = $5`
	result, err := r.client.Exec(ctx, query, tier, status, maxEmployees, time.Now().UTC(), companyID)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetCompaniesByStatus returns companies with a given subscription status.
func (r *CompanyRepositoryImpl) GetCompaniesByStatus(ctx context.Context, status string, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies WHERE subscription_status = $1`
	err := r.client.QueryRow(ctx, countQuery, status).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count companies by status: %w", err)
	}
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
			continue
		}
		companies = append(companies, &company)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}
	return companies, totalCount, nil
}

// GetCompaniesByTier returns active companies with a given subscription tier.
func (r *CompanyRepositoryImpl) GetCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies WHERE subscription_tier = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, tier).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count companies by tier: %w", err)
	}
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
			continue
		}
		companies = append(companies, &company)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}
	return companies, totalCount, nil
}

// GetCompaniesWithExpiringSubscription returns companies whose subscription ends within the given days.
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
	return companies, nil
}

// DeactivateCompany sets is_active to false.
// Returns apperrors.ErrNotFound if company not found.
func (r *CompanyRepositoryImpl) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string) error {
	query := `UPDATE companies SET is_active = false, updated_at = $1 WHERE company_id = $2`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID)
	if err != nil {
		return fmt.Errorf("failed to deactivate company: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeleteCompany permanently deletes a company.
// Returns apperrors.ErrNotFound if company not found.
func (r *CompanyRepositoryImpl) DeleteCompany(ctx context.Context, companyID uuid.UUID) error {
	query := `DELETE FROM companies WHERE company_id = $1`
	result, err := r.client.Exec(ctx, query, companyID)
	if err != nil {
		return fmt.Errorf("failed to delete company: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ListCompanies returns paginated companies.
func (r *CompanyRepositoryImpl) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM companies`
	err := r.client.QueryRow(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count companies: %w", err)
	}
	query := `
        SELECT company_id, company_name, owner_user_id, subscription_tier,
               subscription_status, max_employees, data_region, is_active,
               created_at, updated_at
        FROM companies
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2`
	rows, err := r.client.Query(ctx, query, limit, offset)
	if err != nil {
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
			continue
		}
		companies = append(companies, &company)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating company rows: %w", err)
	}
	return companies, totalCount, nil
}

// CheckCompanyExists checks if a company with given name and owner exists.
func (r *CompanyRepositoryImpl) CheckCompanyExists(ctx context.Context, companyName string, ownerUserID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM companies WHERE company_name = $1 AND owner_user_id = $2 AND is_active = true`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyName, ownerUserID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check company existence: %w", err)
	}
	return exists, nil
}

// ---- Departments ----

// CreateDepartment creates a new department.
func (r *CompanyRepositoryImpl) CreateDepartment(ctx context.Context, department *models.Department) error {
	query := `
        INSERT INTO departments (
            department_id, company_id, department_name, system_department_id,
            parent_department_id, is_active, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.client.Exec(ctx, query,
		department.DepartmentID, department.CompanyID, department.DepartmentName,
		department.SystemDepartmentID, department.ParentDepartmentID,
		department.IsActive, department.CreatedAt, department.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create department: %w", err)
	}
	return nil
}

// UpdateDepartment updates an existing department.
// Returns apperrors.ErrNotFound if department not found.
func (r *CompanyRepositoryImpl) UpdateDepartment(ctx context.Context, department *models.Department) error {
	department.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE departments SET
			department_name = $1,
			parent_department_id = $2,
			is_active = $3,
			updated_at = $4
		WHERE department_id = $5`
	result, err := r.client.Exec(ctx, query,
		department.DepartmentName,
		department.ParentDepartmentID,
		department.IsActive,
		department.UpdatedAt,
		department.DepartmentID,
	)
	if err != nil {
		return fmt.Errorf("failed to update department: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateDepartmentName updates the department name.
// Returns apperrors.ErrNotFound if department not found.
func (r *CompanyRepositoryImpl) UpdateDepartmentName(ctx context.Context, departmentID uuid.UUID, newName string) error {
	query := `UPDATE departments SET department_name = $1, updated_at = $2 WHERE department_id = $3`
	result, err := r.client.Exec(ctx, query, newName, time.Now().UTC(), departmentID)
	if err != nil {
		return fmt.Errorf("failed to update department name: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeactivateDepartment sets is_active to false.
// Returns apperrors.ErrNotFound if department not found.
func (r *CompanyRepositoryImpl) DeactivateDepartment(ctx context.Context, departmentID uuid.UUID) error {
	query := `UPDATE departments SET is_active = false, updated_at = $1 WHERE department_id = $2`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), departmentID)
	if err != nil {
		return fmt.Errorf("failed to deactivate department: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetDepartmentLoad returns a map of department name to employee count.
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
	return departmentLoad, nil
}

// GetDepartmentBySystemID returns an active department by system department ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get department by system ID: %w", err)
	}
	if systemDeptID.Valid {
		systemID, _ := uuid.Parse(systemDeptID.String)
		department.SystemDepartmentID = &systemID
	}
	return &department, nil
}

// CreateRoleDepartment maps a role to a department.
func (r *CompanyRepositoryImpl) CreateRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `
		INSERT INTO role_departments (role_id, department_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, department_id) DO NOTHING`
	_, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to map role to department: %w", err)
	}
	return nil
}

// RemoveRoleDepartment removes a role-department mapping.
// Returns apperrors.ErrNotFound if mapping not found.
func (r *CompanyRepositoryImpl) RemoveRoleDepartment(ctx context.Context, roleID, departmentID uuid.UUID) error {
	query := `DELETE FROM role_departments WHERE role_id = $1 AND department_id = $2`
	result, err := r.client.Exec(ctx, query, roleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to remove role from department: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetRoleDepartments returns departments assigned to a role.
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
	return departments, nil
}

// ---- Roles ----

// CreateRole creates a new role with optional department assignments.
func (r *CompanyRepositoryImpl) CreateRole(ctx context.Context, role *models.Role, departmentIDs []uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
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
		return fmt.Errorf("failed to create role: %w", err)
	}
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
	return nil
}

// CreateRoleWithDetails creates a role with department and permissions.
func (r *CompanyRepositoryImpl) CreateRoleWithDetails(ctx context.Context, role *models.Role, departmentID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
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
		return fmt.Errorf("failed to create role: %w", err)
	}
	roleDeptQuery := `INSERT INTO role_departments (role_id, department_id) VALUES ($1, $2)`
	_, err = tx.ExecContext(ctx, roleDeptQuery, role.RoleID, departmentID)
	if err != nil {
		return fmt.Errorf("failed to map role to department: %w", err)
	}
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
	return nil
}

// GetRole retrieves a role by ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	return &role, nil
}

// GetRolesByCompany returns roles for a company.
func (r *CompanyRepositoryImpl) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM roles WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}
	query := `
		SELECT role_id, role_name, role_level, is_system_role,
			   description, created_at, updated_at
		FROM roles
		WHERE company_id = $1
		ORDER BY role_level ASC, created_at DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
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
			continue
		}
		role.CompanyID = companyID
		roles = append(roles, &role)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating role rows: %w", err)
	}
	return roles, totalCount, nil
}

// GetSystemRoleByLevel returns a system role by level.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get system role: %w", err)
	}
	role.CompanyID = companyID
	role.IsSystemRole = true
	return &role, nil
}

// UpdateRole updates a role.
// Returns apperrors.ErrNotFound if role not found.
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
		return fmt.Errorf("failed to update role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeleteRole deletes a non-system role.
// Returns apperrors.ErrNotFound if role not found or is system.
func (r *CompanyRepositoryImpl) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	query := `DELETE FROM roles WHERE role_id = $1 AND is_system_role = false`
	result, err := r.client.Exec(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---- Role Permissions ----

// GrantRolePermission grants a permission to a role.
func (r *CompanyRepositoryImpl) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, permission_id) DO UPDATE SET
			granted_by = EXCLUDED.granted_by,
			granted_at = EXCLUDED.granted_at`
	_, err := r.client.Exec(ctx, query, roleID, permissionID, grantedBy, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to grant role permission: %w", err)
	}
	return nil
}

// RevokeRolePermission revokes a permission from a role.
// Returns apperrors.ErrNotFound if mapping not found.
func (r *CompanyRepositoryImpl) RevokeRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	result, err := r.client.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke role permission: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetRolePermissions returns permissions granted to a role.
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GrantMultipleRolePermissions grants multiple permissions to a role.
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
		baseIndex := i * 4
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
		return fmt.Errorf("failed to grant multiple role permissions: %w", err)
	}
	return nil
}

// RevokeMultipleRolePermissions revokes multiple permissions from a role.
func (r *CompanyRepositoryImpl) RevokeMultipleRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}
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
	_, err := r.client.Exec(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("failed to revoke multiple role permissions: %w", err)
	}
	return nil
}

// ReplaceRolePermissions replaces all permissions for a role with a new set.
func (r *CompanyRepositoryImpl) ReplaceRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	deleteQuery := `DELETE FROM role_permissions WHERE role_id = $1`
	_, err = tx.ExecContext(ctx, deleteQuery, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove existing role permissions: %w", err)
	}
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
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// CheckRolePermission checks if a role has a specific permission.
func (r *CompanyRepositoryImpl) CheckRolePermission(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	var hasPermission bool
	err := r.client.QueryRow(ctx, query, roleID, permissionID).Scan(&hasPermission)
	if err != nil {
		return false, fmt.Errorf("failed to check role permission: %w", err)
	}
	return hasPermission, nil
}

// CopyRolePermissions copies permissions from source role to target role.
func (r *CompanyRepositoryImpl) CopyRolePermissions(ctx context.Context, sourceRoleID, targetRoleID, grantedBy uuid.UUID) error {
	query := `
        INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at)
        SELECT $1, permission_id, $2, $3
        FROM role_permissions
        WHERE role_id = $4
        ON CONFLICT (role_id, permission_id) DO NOTHING`
	_, err := r.client.Exec(ctx, query, targetRoleID, grantedBy, time.Now().UTC(), sourceRoleID)
	if err != nil {
		return fmt.Errorf("failed to copy role permissions: %w", err)
	}
	return nil
}

// InitializeDefaultPermissions grants basic permissions to the owner role.
func (r *CompanyRepositoryImpl) InitializeDefaultPermissions(ctx context.Context, companyID uuid.UUID, createdBy uuid.UUID) error {
	permissions, err := r.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}
	ownerRole, err := r.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err != nil {
		return fmt.Errorf("failed to get owner role: %w", err)
	}
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
	return nil
}

// ---- Employees ----

// CreateEmployee creates a new company employee record.
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
		employee.PositionID,
		employee.HireDate,
		employee.IsActive,
		employee.ReportsTo,
		employee.CreatedAt,
		employee.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create employee: %w", err)
	}
	return nil
}

// GetEmployeesByUser returns active employees for a user.
func (r *CompanyRepositoryImpl) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	query := `
        SELECT company_id, employee_id, role_id,
               hire_date, is_active, reports_to, created_at, updated_at
        FROM company_employees
        WHERE user_id = $1 AND is_active = true
        ORDER BY hire_date DESC`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query employees by user: %w", err)
	}
	defer rows.Close()
	var employees []*models.CompanyEmployee
	for rows.Next() {
		var employee models.CompanyEmployee
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
			continue
		}
		employee.UserID = userID
		if reportsTo.Status == pgtype.Present {
			u, _ := uuid.FromBytes(reportsTo.Bytes[:])
			employee.ReportsTo = &u
		}
		employees = append(employees, &employee)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}
	return employees, nil
}

// UpdateEmployee updates employee details.
// Returns apperrors.ErrNotFound if employee not found.
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
		return fmt.Errorf("failed to update employee: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateEmployeeRole updates the role of an employee.
// Returns apperrors.ErrNotFound if employee not found.
func (r *CompanyRepositoryImpl) UpdateEmployeeRole(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	query := `UPDATE company_employees SET role_id = $1, updated_at = $2 WHERE company_id = $3 AND user_id = $4`
	result, err := r.client.Exec(ctx, query, roleID, time.Now().UTC(), companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to update employee role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeactivateEmployee sets is_active to false.
// Returns apperrors.ErrNotFound if employee not found.
func (r *CompanyRepositoryImpl) DeactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `UPDATE company_employees SET is_active = false, updated_at = $1 WHERE company_id = $2 AND user_id = $3`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to deactivate employee: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ReactivateEmployee sets is_active to true.
// Returns apperrors.ErrNotFound if employee not found.
func (r *CompanyRepositoryImpl) ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `UPDATE company_employees SET is_active = true, updated_at = $1 WHERE company_id = $2 AND user_id = $3`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to reactivate employee: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetEmployeeCount returns total employees for a company.
func (r *CompanyRepositoryImpl) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1`
	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get employee count: %w", err)
	}
	return count, nil
}

// GetActiveEmployeeCount returns active employees for a company.
func (r *CompanyRepositoryImpl) GetActiveEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1 AND is_active = true`
	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get active employee count: %w", err)
	}
	return count, nil
}

// ListActiveEmployees returns active employees with pagination.
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
	return employees, totalCount, nil
}

// IsUserActiveEmployee checks if a user is an active employee in a company.
func (r *CompanyRepositoryImpl) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) > 0 FROM company_employees WHERE company_id = $1 AND user_id = $2 AND is_active = true`
	var isActive bool
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(&isActive)
	if err != nil {
		return false, fmt.Errorf("failed to check employee status: %w", err)
	}
	return isActive, nil
}

// GetEmployeeHierarchy returns the employee hierarchy for a company.
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
			continue
		}
		item.CompanyID = companyID
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
	return hierarchy, nil
}

// ---- Permissions (global) ----

// GetAllPermissions returns all permissions.
func (r *CompanyRepositoryImpl) GetAllPermissions(ctx context.Context) ([]*models.Permission, error) {
	query := `
		SELECT permission_id, permission_name, description,
			   category, module, requires_tier, created_at
		FROM permissions
		ORDER BY category, permission_name`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetPermissionsByCategory returns permissions by category.
func (r *CompanyRepositoryImpl) GetPermissionsByCategory(ctx context.Context, category string) ([]*models.Permission, error) {
	query := `
		SELECT permission_id, permission_name, description,
			   module, requires_tier, created_at
		FROM permissions
		WHERE category = $1
		ORDER BY permission_name`
	rows, err := r.client.Query(ctx, query, category)
	if err != nil {
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
			continue
		}
		perm.Category = category
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetPermissionsByModule returns permissions by module.
func (r *CompanyRepositoryImpl) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	query := `
        SELECT permission_id, permission_name, description,
               category, module, requires_tier, bit_index, created_at
        FROM permissions
        WHERE module = $1
        ORDER BY category, permission_name`
	rows, err := r.client.Query(ctx, query, module)
	if err != nil {
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
	return permissions, nil
}

// GetPermissionsByNames returns permissions by their names.
func (r *CompanyRepositoryImpl) GetPermissionsByNames(ctx context.Context, permissionNames []string) ([]*models.Permission, error) {
	if len(permissionNames) == 0 {
		return []*models.Permission{}, nil
	}
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetUserPermissionNames returns distinct permission names for a user.
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
		return nil, fmt.Errorf("failed to query user permission names: %w", err)
	}
	defer rows.Close()
	var permissionNames []string
	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		if err != nil {
			continue
		}
		permissionNames = append(permissionNames, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission name rows: %w", err)
	}
	return permissionNames, nil
}

// CheckUserPermission checks if a user has a permission in a company.
func (r *CompanyRepositoryImpl) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
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
		return false, fmt.Errorf("failed to check user permission: %w", err)
	}
	return hasPermission, nil
}

// CheckUserPermissionDetailed provides detailed permission check.
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

// CreatePermission creates a new permission.
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
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

// CreateMultiplePermissions creates multiple permissions.
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
		baseIndex := i * 7
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
		return fmt.Errorf("failed to create multiple permissions: %w", err)
	}
	return nil
}

// GetPermissionByName returns a permission by name.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	return &permission, nil
}

// UpdatePermission updates a permission.
// Returns apperrors.ErrNotFound if permission not found.
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
		return fmt.Errorf("failed to update permission: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// DeletePermission deletes a permission and its associations.
// Returns apperrors.ErrNotFound if permission not found.
func (r *CompanyRepositoryImpl) DeletePermission(ctx context.Context, permissionID uuid.UUID) error {
	deleteAssocQuery := `DELETE FROM role_permissions WHERE permission_id = $1`
	_, err := r.client.Exec(ctx, deleteAssocQuery, permissionID)
	if err != nil {
		return fmt.Errorf("failed to delete permission associations: %w", err)
	}
	query := `DELETE FROM permissions WHERE permission_id = $1`
	result, err := r.client.Exec(ctx, query, permissionID)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---- Bitmask helpers ----

// GetRolePermissionBitmask returns the bitmask for a role.
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
			continue
		}
		bitPositions = append(bitPositions, uint64(bitIndex))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role bitmask rows: %w", err)
	}
	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

// GetPermissionsWithBitIndex returns all permissions with non-null bit_index.
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetPermissionsByBitPositions returns permissions for given bit positions.
func (r *CompanyRepositoryImpl) GetPermissionsByBitPositions(ctx context.Context, bitPositions []uint64) ([]*models.Permission, error) {
	if len(bitPositions) == 0 {
		return []*models.Permission{}, nil
	}
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
	return permissions, nil
}

// GetPermissionBitIndexes returns a map of permission name to bit index.
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
			continue
		}
		result[name] = uint64(bitIndex)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission bit index rows: %w", err)
	}
	return result, nil
}

// ---- Statistics ----

// GetCompanyStats returns statistics for a company.
func (r *CompanyRepositoryImpl) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
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
	var departmentCount int
	deptQuery := `SELECT COUNT(*) FROM departments WHERE company_id = $1 AND is_active = true`
	err = r.client.QueryRow(ctx, deptQuery, companyID).Scan(&departmentCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get department count: %w", err)
	}
	stats["department_count"] = departmentCount
	roleDistribution, err := r.GetRoleDistribution(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role distribution: %w", err)
	}
	stats["role_distribution"] = roleDistribution
	return stats, nil
}

// GetEmployeeRoleHierarchy returns employee hierarchy with role details.
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
			continue
		}
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
	return hierarchy, nil
}

// GetRoleDistribution returns a map of role name to employee count.
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
	return roleDistribution, nil
}

// HealthCheck performs a simple health check.
func (r *CompanyRepositoryImpl) HealthCheck(ctx context.Context) error {
	var result int
	err := r.client.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("postgreSQL health check failed: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("postgreSQL health check returned unexpected result: %d", result)
	}
	return nil
}

// GetRepositoryStats returns statistics about the repository.
func (r *CompanyRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	dbStats := r.client.GetStats()
	stats["db_connections"] = map[string]interface{}{
		"open_connections": dbStats.OpenConnections,
		"in_use":           dbStats.InUse,
		"idle":             dbStats.Idle,
		"wait_count":       dbStats.WaitCount,
		"wait_duration":    dbStats.WaitDuration.String(),
	}
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

// ---- User Permissions (custom) ----

// GetUserPermissions returns all permissions for a user within a company.
func (r *CompanyRepositoryImpl) GetUserPermissions(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Permission, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}
	if ownerUserID == userID {
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
				continue
			}
			permissions = append(permissions, &perm)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating permission rows: %w", err)
		}
		return permissions, nil
	}
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
			continue
		}
		permissions = append(permissions, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}
	return permissions, nil
}

// GetUserPermissionBitmask returns the bitmask for a user.
func (r *CompanyRepositoryImpl) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	var ownerUserID uuid.UUID
	ownerQuery := `SELECT owner_user_id FROM companies WHERE company_id = $1`
	err := r.client.QueryRow(ctx, ownerQuery, companyID).Scan(&ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company owner: %w", err)
	}
	if ownerUserID == userID {
		query := `
            SELECT DISTINCT p.bit_index
            FROM permissions p
            WHERE p.bit_index IS NOT NULL
            AND p.module IN (
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
				continue
			}
			bitPositions = append(bitPositions, uint64(bitIndex))
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
		}
		return rbac.BuildMaskFromBitPositions(bitPositions), nil
	}
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
			continue
		}
		bitPositions = append(bitPositions, uint64(bitIndex))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bitmask rows: %w", err)
	}
	return rbac.BuildMaskFromBitPositions(bitPositions), nil
}

// ---- System Departments ----

// GetPermissionsBySystemDepartments returns permissions by system department IDs.
func (r *CompanyRepositoryImpl) GetPermissionsBySystemDepartments(
	ctx context.Context,
	systemDeptIDs []uuid.UUID,
	module, category, tier string,
) ([]*models.Permission, error) {
	if len(systemDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}
	deptIDStrings := make([]string, len(systemDeptIDs))
	for i, id := range systemDeptIDs {
		deptIDStrings[i] = id.String()
	}
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
	query += " ORDER BY p.module, p.category, p.permission_name"
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
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
	return permissions, nil
}

// GetPermissionsByCompanyModules returns permissions for modules used by a company.
func (r *CompanyRepositoryImpl) GetPermissionsByCompanyModules(
	ctx context.Context,
	companyID uuid.UUID,
	module, category, tier string,
) ([]*models.Permission, error) {
	query := `
        SELECT DISTINCT sd.system_department_id
        FROM departments d
        INNER JOIN system_departments sd ON d.system_department_id = sd.system_department_id
        WHERE d.company_id = $1 AND d.is_active = true`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to query company system departments: %w", err)
	}
	defer rows.Close()
	var systemDeptIDs []uuid.UUID
	for rows.Next() {
		var deptID uuid.UUID
		err := rows.Scan(&deptID)
		if err != nil {
			continue
		}
		systemDeptIDs = append(systemDeptIDs, deptID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}
	return r.GetPermissionsBySystemDepartments(ctx, systemDeptIDs, module, category, tier)
}

// GetModulePermissions returns permissions for given modules.
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
	return permissions, nil
}

// ---- Search ----

// SearchCompaniesByName searches companies by name with filters.
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
	conditions := []string{}
	args := []interface{}{}
	argCounter := 1
	if searchType == "autocomplete" || len(searchQuery) < 3 {
		conditions = append(conditions,
			fmt.Sprintf("company_name ILIKE $%d", argCounter))
		args = append(args, "%"+searchQuery+"%")
		argCounter++
	} else {
		conditions = append(conditions,
			fmt.Sprintf("company_name_tsv @@ plainto_tsquery('simple', $%d)", argCounter))
		args = append(args, searchQuery)
		argCounter++
	}
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
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	countQuery := fmt.Sprintf(`
        SELECT COUNT(*)
        FROM companies
        %s`, whereClause)
	err = r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}
	var searchQueryStr string
	if searchType == "autocomplete" || len(searchQuery) < 3 {
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
	rows, err := r.client.Query(ctx, searchQueryStr, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search companies: %w", err)
	}
	defer rows.Close()
	companies = make([]*models.Company, 0, limit)
	for rows.Next() {
		var company models.Company
		var subStartDate, subEndDate sql.NullTime
		var relevanceScore float64
		err := rows.Scan(
			&company.CompanyID, &company.CompanyName, &company.OwnerUserID,
			&company.SubscriptionTier, &company.SubscriptionStatus, &company.MaxEmployees,
			&company.DataRegion, &company.IsActive, &company.CreatedAt, &company.UpdatedAt,
			&subStartDate, &subEndDate,
			&relevanceScore,
		)
		if err != nil {
			continue
		}
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
	return companies, totalCount, nil
}

// SearchCompaniesByOwnerAndName searches companies by owner and name.
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
	conditions := []string{"owner_user_id = $1"}
	args := []interface{}{ownerID}
	paramCount := 1
	if searchQuery != "" {
		paramCount++
		if len(searchQuery) < 3 {
			conditions = append(conditions,
				fmt.Sprintf("company_name ILIKE $%d", paramCount))
			args = append(args, "%"+searchQuery+"%")
		} else {
			conditions = append(conditions,
				fmt.Sprintf("company_name_tsv @@ plainto_tsquery('simple', $%d)", paramCount))
			args = append(args, searchQuery)
		}
	}
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM companies %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}
	if totalCount == 0 || offset >= totalCount {
		return []*models.Company{}, totalCount, nil
	}
	paramCount++
	paramCount++
	orderBy := ""
	if searchQuery != "" && len(searchQuery) >= 3 {
		orderBy = fmt.Sprintf(`
            ORDER BY
                ts_rank(company_name_tsv, plainto_tsquery('simple', $%d)) DESC,
                company_name ASC`, 2)
	} else if searchQuery != "" {
		orderBy = fmt.Sprintf(`
            ORDER BY
                similarity(company_name, $%d) DESC,
                company_name ASC`, 2)
	} else {
		orderBy = "ORDER BY created_at DESC"
	}
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
	args = append(args, limit, offset)
	rows, err := r.client.Query(ctx, searchQueryStr, args...)
	if err != nil {
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
			continue
		}
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
	return companies, totalCount, nil
}

// GetCompanySuggestions returns company name suggestions for autocomplete.
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
	return suggestions, nil
}

// GetCompanySearchStats returns statistics about company search indexes.
func (r *CompanyRepositoryImpl) GetCompanySearchStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	var totalCompanies int
	err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM companies").Scan(&totalCompanies)
	if err != nil {
		return nil, fmt.Errorf("failed to get company count: %w", err)
	}
	stats["total_companies"] = totalCompanies
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
	if err == nil {
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
	if err == nil {
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
	return stats, nil
}

func calculateEfficiency(tuplesRead, tuplesFetched int64) float64 {
	if tuplesRead == 0 {
		return 0
	}
	return float64(tuplesFetched) / float64(tuplesRead) * 100
}

// ---- Additional Employee methods ----

// GetEmployee returns a specific employee by company and user.
// Returns apperrors.ErrNotFound if not found.
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
		&employee.PositionID,
		&employee.HireDate,
		&employee.IsActive,
		&employee.ReportsTo,
		&employee.CreatedAt,
		&employee.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get employee: %w", err)
	}
	return &employee, nil
}

// GetEmployeesByRole returns employees with a given role.
func (r *CompanyRepositoryImpl) GetEmployeesByRole(ctx context.Context, roleID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE role_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, roleID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count role employees: %w", err)
	}
	query := `
        SELECT company_id, user_id, employee_id,
               hire_date, is_active, reports_to, created_at, updated_at
        FROM company_employees
        WHERE role_id = $1 AND is_active = true
        ORDER BY hire_date DESC
        LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, roleID, limit, offset)
	if err != nil {
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
			continue
		}
		employee.RoleID = roleID
		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}
		employees = append(employees, &employee)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}
	return employees, totalCount, nil
}

// GetUsersByRoleLevel returns users by role level range.
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
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}
	return employees, nil
}

// GetUsersWithPermission returns users who have a specific permission.
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
		return nil, fmt.Errorf("error iterating employee rows: %w", err)
	}
	return employees, nil
}

// GetEmployeesByCompany returns employees for a company with pagination,
// including the user's username and full name.
// GetEmployeesByCompany returns a list of employee summaries (user_id, employee_id, username, full_name)
// for a given company, with pagination. Also returns the total number of employees in the company.
// GetEmployeesByCompany returns employees for a company with pagination,
// including the user's username and full name.
func (r *CompanyRepositoryImpl) GetEmployeesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	// Validate pagination params
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Count total active employees (or all) – adjust if you want only active
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count employees: %w", err)
	}

	// Main query: join with users to get username and full_name
	query := `
        SELECT
            ce.user_id,
            ce.employee_id,
            ce.role_id,
            ce.hire_date,
            ce.is_active,
            ce.reports_to,
            ce.created_at,
            ce.updated_at,
            u.username,
            u.full_name
        FROM company_employees ce
        INNER JOIN users u ON ce.user_id = u.user_id
        WHERE ce.company_id = $1
        ORDER BY ce.hire_date DESC
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query employees: %w", err)
	}
	defer rows.Close()

	employees := make([]*models.CompanyEmployee, 0, limit)
	for rows.Next() {
		var employee models.CompanyEmployee
		var reportsTo sql.NullString
		var fullName sql.NullString

		err := rows.Scan(
			&employee.UserID,
			&employee.EmployeeID,
			&employee.RoleID,
			&employee.HireDate,
			&employee.IsActive,
			&reportsTo,
			&employee.CreatedAt,
			&employee.UpdatedAt,
			&employee.Username,
			&fullName,
		)
		if err != nil {
			continue
		}

		employee.CompanyID = companyID

		if reportsTo.Valid {
			reportsToID, _ := uuid.Parse(reportsTo.String)
			employee.ReportsTo = &reportsToID
		}
		if fullName.Valid {
			employee.FullName = &fullName.String
		}

		employees = append(employees, &employee)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee rows: %w", err)
	}

	return employees, totalCount, nil
}

// GetEmployeesByDepartment returns employees in a department.
func (r *CompanyRepositoryImpl) GetEmployeesByDepartment(ctx context.Context, departmentID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
	var totalCount int
	countQuery := `
        SELECT COUNT(DISTINCT ce.user_id)
        FROM company_employees ce
        INNER JOIN role_departments rd ON ce.role_id = rd.role_id
        WHERE rd.department_id = $1 AND ce.is_active = true`
	err := r.client.QueryRow(ctx, countQuery, departmentID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get employees count for department: %w", err)
	}
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

// ---- Delete department and role-department mappings ----

// DeleteDepartment permanently deletes a department.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) DeleteDepartment(ctx context.Context, departmentID uuid.UUID) error {
	query := `DELETE FROM departments WHERE department_id = $1`
	result, err := r.client.Exec(ctx, query, departmentID)
	if err != nil {
		return fmt.Errorf("failed to delete department: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// RemoveAllRoleDepartments removes all role-department mappings for a department.
func (r *CompanyRepositoryImpl) RemoveAllRoleDepartments(ctx context.Context, departmentID uuid.UUID) error {
	query := `DELETE FROM role_departments WHERE department_id = $1`
	_, err := r.client.Exec(ctx, query, departmentID)
	if err != nil {
		return fmt.Errorf("failed to remove role-department mappings: %w", err)
	}
	return nil
}

// ---- System Departments (additional) ----

// GetSystemDepartmentsWithBitmask returns all system departments with bitmask.
func (r *CompanyRepositoryImpl) GetSystemDepartmentsWithBitmask(ctx context.Context) ([]*models.SystemDepartment, error) {
	query := `
		SELECT system_department_id, name, module_code, description, bitmask
		FROM system_departments
		ORDER BY name`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
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
	return systemDepartments, nil
}

// GetDepartmentBitmask returns the bitmask for a department name.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) GetDepartmentBitmask(ctx context.Context, departmentName string) (uint64, error) {
	query := `
		SELECT bitmask
		FROM system_departments
		WHERE name = $1`
	var bitmask sql.NullInt64
	err := r.client.QueryRow(ctx, query, departmentName).Scan(&bitmask)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, apperrors.ErrNotFound
		}
		return 0, fmt.Errorf("failed to get department bitmask: %w", err)
	}
	if !bitmask.Valid {
		return 0, nil
	}
	return uint64(bitmask.Int64), nil
}

// GetPermissionsByModules returns permissions for given modules.
// Duplicate of earlier but kept for interface completeness.
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
	return permissions, nil
}

// GetSystemDepartments returns all system departments.
func (r *CompanyRepositoryImpl) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	query := `
        SELECT system_department_id, name, module_code, description, bitmask
        FROM system_departments
        ORDER BY name`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
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
			continue
		}
		systemDepartments = append(systemDepartments, &dept)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating system department rows: %w", err)
	}
	return systemDepartments, nil
}

// GetSystemDepartmentByModule returns a system department by module code.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get system department: %w", err)
	}
	return &dept, nil
}

// GetSystemDepartment returns a system department by ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get system department: %w", err)
	}
	return &dept, nil
}

// ---- Department extended operations ----

// GetDepartmentsByCompany returns departments for a company.
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
	return departments, totalCount, nil
}

// GetDepartment returns a department by ID.
// Returns apperrors.ErrNotFound if not found.
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
			return nil, apperrors.ErrNotFound
		}
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
	return &department, nil
}

// GetDepartmentHierarchy returns the department hierarchy tree.
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
	return departments, nil
}

// GetEmployeeDepartment returns the primary department of an employee.
// Returns apperrors.ErrNotFound if no department found.
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
			return nil, apperrors.ErrNotFound
		}
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
	return &department, nil
}

// GetEmployeeDepartments returns all departments of an employee.
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
	return departments, nil
}

// ---- Positions ----

// DeletePosition deletes a position.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) DeletePosition(ctx context.Context, positionID uuid.UUID) error {
	query := `DELETE FROM positions WHERE position_id = $1`
	result, err := r.client.Exec(ctx, query, positionID)
	if err != nil {
		return fmt.Errorf("failed to delete position: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdatePositionStatus updates the is_open flag of a position.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) UpdatePositionStatus(ctx context.Context, positionID uuid.UUID, isOpen bool) error {
	query := `UPDATE positions SET is_open = $1, updated_at = $2 WHERE position_id = $3`
	result, err := r.client.Exec(ctx, query, isOpen, time.Now().UTC(), positionID)
	if err != nil {
		return fmt.Errorf("failed to update position status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// UpdateDepartmentParent updates the parent of a department.
// Returns apperrors.ErrNotFound if department or parent not found.
func (r *CompanyRepositoryImpl) UpdateDepartmentParent(
	ctx context.Context,
	departmentID uuid.UUID,
	parentDepartmentID *uuid.UUID,
) error {
	if parentDepartmentID != nil {
		if departmentID == *parentDepartmentID {
			return apperrors.ErrInvalidInput
		}
		parentDept, err := r.GetDepartment(ctx, *parentDepartmentID)
		if err != nil {
			return err
		}
		currentDept, err := r.GetDepartment(ctx, departmentID)
		if err != nil {
			return err
		}
		if parentDept.CompanyID != currentDept.CompanyID {
			return apperrors.ErrInvalidInput
		}
		if r.isCircularReference(ctx, departmentID, parentDepartmentID) {
			return apperrors.ErrInvalidInput
		}
	}
	query := `UPDATE departments SET parent_department_id = $1, updated_at = $2 WHERE department_id = $3`
	result, err := r.client.Exec(ctx, query, parentDepartmentID, time.Now().UTC(), departmentID)
	if err != nil {
		return fmt.Errorf("failed to update department parent: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *CompanyRepositoryImpl) isCircularReference(
	ctx context.Context,
	departmentID uuid.UUID,
	parentDepartmentID *uuid.UUID,
) bool {
	if parentDepartmentID == nil {
		return false
	}
	visited := make(map[uuid.UUID]bool)
	current := *parentDepartmentID
	for current != uuid.Nil {
		if current == departmentID {
			return true
		}
		if visited[current] {
			return true
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

// GetDepartmentChildren returns immediate child departments.
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
	return children, nil
}

// GetDepartmentTree returns the full tree structure under a department.
func (r *CompanyRepositoryImpl) GetDepartmentTree(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.DepartmentTree, error) {
	query := `
        WITH RECURSIVE dept_tree AS (
            SELECT
                d.department_id, d.department_name, d.parent_department_id,
                d.is_active, 1 as level,
                ARRAY[d.department_id] as path,
                d.created_at, d.updated_at
            FROM departments d
            WHERE d.department_id = $1 AND d.is_active = true
            UNION ALL
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
			continue
		}
		if parentDeptID.Valid {
			parentID, _ := uuid.Parse(parentDeptID.String)
			item.ParentDepartmentID = &parentID
		}
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
	return tree, nil
}

// GetDepartmentParents returns parent departments (ancestors).
func (r *CompanyRepositoryImpl) GetDepartmentParents(
	ctx context.Context,
	departmentID uuid.UUID,
) ([]*models.Department, error) {
	query := `
        WITH RECURSIVE dept_parents AS (
            SELECT
                d.department_id, d.department_name, d.parent_department_id,
                d.company_id, d.is_active,
                0 as level
            FROM departments d
            WHERE d.department_id = $1 AND d.is_active = true
            UNION ALL
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
	return parents, nil
}

// MoveDepartmentWithEmployees moves a department (and its employees) under a new parent.
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
	updateQuery := `UPDATE departments SET parent_department_id = $1, updated_at = $2 WHERE department_id = $3`
	_, err = tx.ExecContext(ctx, updateQuery, newParentDepartmentID, time.Now().UTC(), departmentID)
	if err != nil {
		return fmt.Errorf("failed to update department parent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// GetRootDepartments returns departments with no parent.
func (r *CompanyRepositoryImpl) GetRootDepartments(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*models.Department, error) {
	query := `
        SELECT 
            d.department_id,
            d.department_name,
            d.system_department_id,
            sd.name AS system_department_name,
            sd.module_code,
            d.is_active,
            d.created_at,
            d.updated_at
        FROM departments d
        LEFT JOIN system_departments sd 
            ON d.system_department_id = sd.system_department_id
        WHERE d.company_id = $1 
          AND d.parent_department_id IS NULL 
          AND d.is_active = true
        ORDER BY d.department_name ASC
    `
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to query root departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var dept models.Department
		var systemDeptID, systemDeptName, moduleCode sql.NullString

		err := rows.Scan(
			&dept.DepartmentID,
			&dept.DepartmentName,
			&systemDeptID,
			&systemDeptName,
			&moduleCode,
			&dept.IsActive,
			&dept.CreatedAt,
			&dept.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan department row: %w", err)
		}

		dept.CompanyID = companyID
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

		departments = append(departments, &dept)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating root department rows: %w", err)
	}
	return departments, nil
}

// CreateSubDepartment creates a sub-department under a parent.
// Returns apperrors.ErrNotFound if parent not found.
func (r *CompanyRepositoryImpl) CreateSubDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	parentDepartmentID uuid.UUID,
	departmentName string,
	systemDepartmentID uuid.UUID,
) (*models.Department, error) {
	departmentName = strings.TrimSpace(departmentName)
	if departmentName == "" {
		return nil, apperrors.ErrInvalidInput
	}
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
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
		return nil, apperrors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate parent department: %w", err)
	}
	if parentCompanyID != companyID {
		return nil, apperrors.ErrInvalidInput
	}
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
		return nil, fmt.Errorf("failed to create sub-department: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
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
	return department, nil
}

// GetSubDepartments returns sub-departments of a parent.
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
	return departments, nil
}

// GetCompanyByID is an alias for GetCompany (interface may require both).
func (r *CompanyRepositoryImpl) GetCompanyByID(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	return r.GetCompany(ctx, companyID)
}

// GetActiveDepartmentCount returns count of active departments.
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
		return 0, fmt.Errorf("failed to get active department count: %w", err)
	}
	return count, nil
}

// UpdateMaxDepartments updates the max_departments limit.
// Returns apperrors.ErrInvalidInput if value invalid, or if it would drop below active departments.
func (r *CompanyRepositoryImpl) UpdateMaxDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	newMaxDepartments int,
) error {
	if newMaxDepartments <= 0 {
		return apperrors.ErrInvalidInput
	}
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	var currentMax int
	err = tx.QueryRowContext(ctx, `
		SELECT max_departments
		FROM companies
		WHERE company_id = $1
		FOR UPDATE
	`, companyID).Scan(&currentMax)
	if err != nil {
		return err
	}
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
		return apperrors.ErrInvalidInput
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
	return nil
}

// CheckDepartmentLimit checks if company can create a new department.
// Returns apperrors.ErrInvalidInput if limit reached.
func (r *CompanyRepositoryImpl) CheckDepartmentLimit(
	ctx context.Context,
	companyID uuid.UUID,
) error {
	info, err := r.GetCompanyDepartmentInfo(ctx, companyID)
	if err != nil {
		return err
	}
	if info.ActiveDepartments >= info.MaxDepartments {
		return apperrors.ErrInvalidInput
	}
	return nil
}

// CompanyDepartmentInfo holds department limit info.
type CompanyDepartmentInfo struct {
	CompanyID            uuid.UUID
	MaxDepartments       int
	ActiveDepartments    int
	RemainingDepartments int
}

// GetCompanyDepartmentInfo returns department usage statistics.
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
		return nil, fmt.Errorf("failed to get company department info: %w", err)
	}
	info.RemainingDepartments = info.MaxDepartments - info.ActiveDepartments
	if info.RemainingDepartments < 0 {
		info.RemainingDepartments = 0
	}
	return &info, nil
}

// CreateCompanyDepartment creates a new department for a company.
// Returns apperrors.ErrDuplicate if department name already exists.
func (r *CompanyRepositoryImpl) CreateCompanyDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	departmentName string,
	systemDepartmentID uuid.UUID,
) (*models.Department, error) {
	departmentName = strings.TrimSpace(departmentName)
	if departmentName == "" {
		return nil, apperrors.ErrInvalidInput
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
			return nil, apperrors.ErrDuplicate
		}
		return nil, fmt.Errorf("failed to create department: %w", err)
	}
	department := &models.Department{
		DepartmentID:       departmentID,
		CompanyID:          companyID,
		DepartmentName:     departmentName,
		SystemDepartmentID: &systemDepartmentID,
		IsActive:           true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return department, nil
}

// GetDepartmentByID returns a department by ID (alias).
func (r *CompanyRepositoryImpl) GetDepartmentByID(
	ctx context.Context,
	departmentID uuid.UUID,
) (*models.Department, error) {
	return r.GetDepartment(ctx, departmentID)
}

// SearchDepartments searches departments within a company.
func (r *CompanyRepositoryImpl) SearchDepartments(
	ctx context.Context,
	companyID uuid.UUID,
	searchQuery string,
	limit int,
	offset int,
	includeInactive bool,
) ([]*models.DepartmentSearchResult, int, error) {
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
	if !includeInactive {
		whereClause += " AND d.is_active = true"
	}
	if searchQuery != "" {
		whereClause += " AND d.department_name ILIKE $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, "%"+searchQuery+"%")
	}
	var totalCount int
	err := r.client.QueryRow(
		ctx,
		countQuery+whereClause,
		queryParams...,
	).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count departments: %w", err)
	}
	searchSQL := baseQuery + whereClause +
		` ORDER BY d.department_name ASC
		  LIMIT $` + strconv.Itoa(len(queryParams)+1) +
		` OFFSET $` + strconv.Itoa(len(queryParams)+2)
	queryParams = append(queryParams, limit, offset)
	rows, err := r.client.Query(ctx, searchSQL, queryParams...)
	if err != nil {
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
	// Log duration removed
	return departments, totalCount, nil
}

// GetDepartmentSuggestions returns department suggestions for autocomplete.
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
	return departments, nil
}

// SoftDeleteDepartment deactivates and renames a department.
// Returns apperrors.ErrNotFound if not found.
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
	var deptName string
	err = tx.QueryRowContext(ctx, `
		SELECT department_name
		FROM departments
		WHERE department_id = $1
		  AND company_id = $2
		  AND is_active = true
	`, departmentID, companyID).Scan(&deptName)
	if err == sql.ErrNoRows {
		return apperrors.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to fetch department name: %w", err)
	}
	archivedName := fmt.Sprintf(
		"%s__archived_%d",
		deptName,
		time.Now().UnixNano()%10000,
	)
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
		return apperrors.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ActivateDepartment reactivates a department.
// Returns apperrors.ErrNotFound if not found.
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
		return apperrors.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to fetch department: %w", err)
	}
	finalName := deptName
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
	return nil
}

// UpdateEmployeePosition updates the position of an employee.
// Returns apperrors.ErrNotFound if employee not found.
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
		return fmt.Errorf("failed to update employee position: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetEmployeeWithPosition returns employee and associated position.
// Returns apperrors.ErrNotFound if employee not found.
// GetEmployeeWithPosition retrieves an employee with enriched details: role name, position title,
// work center code, department name, username, and full name.
// Returns apperrors.ErrNotFound if the employee does not exist.
func (r *CompanyRepositoryImpl) GetEmployeeWithPosition(ctx context.Context, companyID, userID uuid.UUID) (*models.EmployeeWithPositionDetails, error) {
	query := `
        SELECT
            ce.company_id,
            ce.user_id,
            ce.employee_id,
            ce.role_id,
            ce.position_id,
            ce.hire_date,
            ce.is_active,
            ce.reports_to,
            ce.created_at,
            ce.updated_at,
            COALESCE(r.role_name, '') AS role_name,
            COALESCE(p.title, '') AS position_title,
            COALESCE(p.work_center_code, '') AS work_center_code,
            COALESCE(d.department_name, '') AS department_name,
            u.username,
            COALESCE(u.full_name, '') AS full_name
        FROM company_employees ce
        LEFT JOIN roles r ON ce.role_id = r.role_id
        LEFT JOIN positions p ON ce.position_id = p.position_id
        LEFT JOIN departments d ON p.department_id = d.department_id
        LEFT JOIN users u ON ce.user_id = u.user_id
        WHERE ce.company_id = $1 AND ce.user_id = $2
    `

	var result models.EmployeeWithPositionDetails
	var reportsTo sql.NullString
	var positionID uuid.NullUUID

	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
		&result.CompanyID,
		&result.UserID,
		&result.EmployeeID,
		&result.RoleID,
		&positionID,
		&result.HireDate,
		&result.IsActive,
		&reportsTo,
		&result.CreatedAt,
		&result.UpdatedAt,
		&result.RoleName,
		&result.PositionTitle,
		&result.WorkCenterCode,
		&result.DepartmentName,
		&result.Username,
		&result.FullName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get employee with position: %w", err)
	}

	// Handle nullable fields
	if reportsTo.Valid {
		parsed, _ := uuid.Parse(reportsTo.String)
		result.ReportsTo = &parsed
	}
	if positionID.Valid {
		result.PositionID = &positionID.UUID
	}

	return &result, nil
}

// PositionExists checks if a position exists with given title in department.
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

// CreatePosition creates a new position.
// Returns apperrors.ErrDuplicate if title already exists in department.
func (r *CompanyRepositoryImpl) CreatePosition(ctx context.Context, position *models.Position) error {
	query := `
		INSERT INTO positions (
			position_id, company_id, department_id, title,
			is_open, is_schedulable, attendance_required,
			overtime_allowed, work_center_code,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.client.Exec(ctx, query,
		position.PositionID,
		position.CompanyID,
		position.DepartmentID,
		position.Title,
		position.IsOpen,
		position.IsSchedulable,
		position.AttendanceRequired,
		position.OvertimeAllowed,
		position.WorkCenterCode,
		position.CreatedAt,
		position.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23503" {
			if pgErr.Constraint == "fk_positions_work_center" {
				return apperrors.ErrNotFound
			}
		}
		return fmt.Errorf("failed to create position: %w", err)
	}
	return nil
}

// GetPosition returns a position by ID.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) GetPosition(ctx context.Context, positionID uuid.UUID) (*models.Position, error) {
	query := `
        SELECT
            p.position_id, p.company_id, p.department_id, p.title,
            p.is_open, p.is_schedulable, p.attendance_required,
            p.overtime_allowed, p.work_center_code, wc.name as work_center_name,
            p.created_at, p.updated_at
        FROM positions p
        LEFT JOIN attendance.work_centers wc ON p.company_id = wc.company_id AND p.work_center_code = wc.work_center_code
        WHERE p.position_id = $1`
	var position models.Position
	var workCenterCode sql.NullString
	var workCenterName sql.NullString
	err := r.client.QueryRow(ctx, query, positionID).Scan(
		&position.PositionID, &position.CompanyID, &position.DepartmentID,
		&position.Title, &position.IsOpen, &position.IsSchedulable,
		&position.AttendanceRequired, &position.OvertimeAllowed,
		&workCenterCode, &workCenterName,
		&position.CreatedAt, &position.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get position: %w", err)
	}
	if workCenterCode.Valid {
		position.WorkCenterCode = &workCenterCode.String
	}
	if workCenterName.Valid {
		position.WorkCenterName = &workCenterName.String
	}
	return &position, nil
}

// UpdatePosition updates a position.
// Returns apperrors.ErrNotFound if position not found.
func (r *CompanyRepositoryImpl) UpdatePosition(ctx context.Context, position *models.Position) error {
	position.UpdatedAt = time.Now().UTC()
	query := `
        UPDATE positions SET
            title = $1,
            department_id = $2,
            is_open = $3,
            is_schedulable = $4,
            attendance_required = $5,
            overtime_allowed = $6,
            work_center_code = $7,
            updated_at = $8
        WHERE position_id = $9`
	result, err := r.client.Exec(ctx, query,
		position.Title,
		position.DepartmentID,
		position.IsOpen,
		position.IsSchedulable,
		position.AttendanceRequired,
		position.OvertimeAllowed,
		position.WorkCenterCode,
		position.UpdatedAt,
		position.PositionID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23503" {
			if pgErr.Constraint == "fk_positions_work_center" {
				return apperrors.ErrNotFound
			}
		}
		return fmt.Errorf("failed to update position: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// GetPositionsByDepartment returns positions in a department.
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
		return nil, 0, fmt.Errorf("failed to count department positions: %w", err)
	}
	query := `
        SELECT
            p.position_id, p.company_id, p.title, p.is_open,
            p.is_schedulable, p.attendance_required, p.overtime_allowed,
            p.work_center_code, wc.name as work_center_name,
            p.created_at, p.updated_at, d.department_name
        FROM positions p
        INNER JOIN departments d ON p.department_id = d.department_id
        LEFT JOIN attendance.work_centers wc ON p.company_id = wc.company_id AND p.work_center_code = wc.work_center_code
        WHERE p.department_id = $1`
	if onlyOpen {
		query += ` AND p.is_open = true`
	}
	query += ` ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, departmentID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query department positions: %w", err)
	}
	defer rows.Close()
	positions := make([]*models.Position, 0, limit)
	for rows.Next() {
		var position models.Position
		var departmentName string
		var workCenterCode sql.NullString
		var workCenterName sql.NullString
		err := rows.Scan(
			&position.PositionID, &position.CompanyID, &position.Title,
			&position.IsOpen, &position.IsSchedulable, &position.AttendanceRequired,
			&position.OvertimeAllowed, &workCenterCode, &workCenterName,
			&position.CreatedAt, &position.UpdatedAt, &departmentName,
		)
		if err != nil {
			continue
		}
		position.DepartmentID = departmentID
		position.DepartmentName = departmentName
		if workCenterCode.Valid {
			position.WorkCenterCode = &workCenterCode.String
		}
		if workCenterName.Valid {
			position.WorkCenterName = &workCenterName.String
		}
		positions = append(positions, &position)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating department position rows: %w", err)
	}
	return positions, totalCount, nil
}

// GetPositionsByCompany returns positions for a company.
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
		return nil, 0, fmt.Errorf("failed to count positions: %w", err)
	}
	query := `
        SELECT
            p.position_id, p.department_id, p.title, p.is_open,
            p.is_schedulable, p.attendance_required, p.overtime_allowed,
            p.work_center_code, wc.name as work_center_name,
            p.created_at, p.updated_at
        FROM positions p
        LEFT JOIN attendance.work_centers wc ON p.company_id = wc.company_id AND p.work_center_code = wc.work_center_code
        WHERE p.company_id = $1`
	if onlyOpen {
		query += ` AND p.is_open = true`
	}
	query += ` ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query positions: %w", err)
	}
	defer rows.Close()
	positions := make([]*models.Position, 0, limit)
	for rows.Next() {
		var position models.Position
		var workCenterCode sql.NullString
		var workCenterName sql.NullString
		err := rows.Scan(
			&position.PositionID, &position.DepartmentID, &position.Title,
			&position.IsOpen, &position.IsSchedulable, &position.AttendanceRequired,
			&position.OvertimeAllowed, &workCenterCode, &workCenterName,
			&position.CreatedAt, &position.UpdatedAt,
		)
		if err != nil {
			continue
		}
		position.CompanyID = companyID
		if workCenterCode.Valid {
			position.WorkCenterCode = &workCenterCode.String
		}
		if workCenterName.Valid {
			position.WorkCenterName = &workCenterName.String
		}
		positions = append(positions, &position)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating position rows: %w", err)
	}
	return positions, totalCount, nil
}

// GetOpenPositions returns open positions (optionally filtered by isOpen).
func (r *CompanyRepositoryImpl) GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.Position, int, error) {
	if limit <= 0 {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}
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
		return nil, 0, fmt.Errorf("failed to count positions: %w", err)
	}
	query := `
		SELECT
			p.position_id,
			p.company_id,
			p.department_id,
			p.title,
			p.is_open,
			p.is_schedulable,
			p.attendance_required,
			p.overtime_allowed,
			p.work_center_code,
			wc.name as work_center_name,
			p.created_at,
			p.updated_at
		FROM positions p
		INNER JOIN departments d ON p.department_id = d.department_id
		LEFT JOIN attendance.work_centers wc ON p.company_id = wc.company_id AND p.work_center_code = wc.work_center_code
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
		return nil, 0, fmt.Errorf("failed to query open positions: %w", err)
	}
	defer rows.Close()
	var positions []*models.Position
	for rows.Next() {
		var position models.Position
		var workCenterCode sql.NullString
		var workCenterName sql.NullString
		err := rows.Scan(
			&position.PositionID,
			&position.CompanyID,
			&position.DepartmentID,
			&position.Title,
			&position.IsOpen,
			&position.IsSchedulable,
			&position.AttendanceRequired,
			&position.OvertimeAllowed,
			&workCenterCode,
			&workCenterName,
			&position.CreatedAt,
			&position.UpdatedAt,
		)
		if err != nil {
			continue
		}
		if workCenterCode.Valid {
			position.WorkCenterCode = &workCenterCode.String
		}
		if workCenterName.Valid {
			position.WorkCenterName = &workCenterName.String
		}
		positions = append(positions, &position)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating position rows: %w", err)
	}
	return positions, totalCount, nil
}

// WorkCenterExists checks if a work center exists.
func (r *CompanyRepositoryImpl) WorkCenterExists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM attendance.work_centers WHERE company_id = $1 AND work_center_code = $2)`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, workCenterCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check work center existence: %w", err)
	}
	return exists, nil
}

// ---- Company creation with departments and positions ----

// CreateCompany creates a new company with owner, departments, roles and permissions.
func (r *CompanyRepositoryImpl) CreateCompany(
	ctx context.Context,
	company *models.Company,
	additionalDepartments []string,
	ownerPositionTitle string,
	positionDetails *models.Position,
	workCenterDetails *models.WorkCenter,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	companyQuery := `
        INSERT INTO companies (
            company_id, company_name, owner_user_id, subscription_tier,
            subscription_status, max_employees, max_departments, data_region,
            is_active, created_at, updated_at, subscription_start_date,
            subscription_end_date, financial_year_start_month
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
		company.FinancialYearStartMonth,
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_companies_name_owner_unique") {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to create company: %w", err)
	}
	if workCenterDetails != nil && workCenterDetails.WorkCenterCode != "" {
		workCenterQuery := `
            INSERT INTO attendance.work_centers (
                work_center_code, company_id, name,
                description, timezone, is_active,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (company_id, work_center_code) DO NOTHING
        `
		_, err = tx.ExecContext(ctx, workCenterQuery,
			workCenterDetails.WorkCenterCode,
			company.CompanyID,
			workCenterDetails.Name,
			workCenterDetails.Description,
			workCenterDetails.Timezone,
			workCenterDetails.IsActive,
			company.CreatedAt,
			company.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to create work center: %w", err)
		}
	}
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
	var adminSystemDeptID uuid.UUID
	err = tx.QueryRowContext(ctx, `
        SELECT system_department_id
        FROM system_departments
        WHERE module_code = 'administration'
        LIMIT 1
    `).Scan(&adminSystemDeptID)
	if err != nil {
		return fmt.Errorf("failed to get administration system department: %w", err)
	}
	adminDeptID := uuid.New()
	departmentName := "Administration"
	_, err = tx.ExecContext(ctx, `
        INSERT INTO departments (
            department_id, company_id, department_name,
            system_department_id, is_active, created_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
    `,
		adminDeptID,
		company.CompanyID,
		departmentName,
		adminSystemDeptID,
		true,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create administration department: %w", err)
	}
	ownerPositionID := uuid.New()
	positionQuery := `
        INSERT INTO positions (
            position_id, company_id, department_id, title,
            is_open, is_schedulable, attendance_required,
            overtime_allowed, work_center_code,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `
	_, err = tx.ExecContext(ctx, positionQuery,
		ownerPositionID,
		company.CompanyID,
		adminDeptID,
		ownerPositionTitle,
		positionDetails.IsOpen,
		positionDetails.IsSchedulable,
		positionDetails.AttendanceRequired,
		positionDetails.OvertimeAllowed,
		positionDetails.WorkCenterCode,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create owner position: %w", err)
	}
	remainingSlots := company.MaxDepartments - 1
	if remainingSlots < 0 {
		remainingSlots = 0
	}
	if len(additionalDepartments) > remainingSlots {
		additionalDepartments = additionalDepartments[:remainingSlots]
	}
	ownerAccessDeptIDs := []uuid.UUID{adminDeptID}
	ownerAccessModules := []string{"administration"}
	for _, deptName := range additionalDepartments {
		deptID := uuid.New()
		var systemDeptID uuid.UUID
		err = tx.QueryRowContext(ctx, `
            SELECT system_department_id
            FROM system_departments
            WHERE module_code = $1
            LIMIT 1
        `, strings.ToLower(strings.TrimSpace(deptName))).Scan(&systemDeptID)
		if err != nil {
			systemDeptID = adminSystemDeptID
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
			continue
		}
		ownerAccessDeptIDs = append(ownerAccessDeptIDs, deptID)
		if systemDeptID == adminSystemDeptID {
			ownerAccessModules = append(ownerAccessModules, "administration")
		} else {
			ownerAccessModules = append(ownerAccessModules, strings.ToLower(deptName))
		}
	}
	for _, deptID := range ownerAccessDeptIDs {
		_, _ = tx.ExecContext(ctx,
			`INSERT INTO role_departments (role_id, department_id) VALUES ($1,$2)`,
			ownerRoleID,
			deptID,
		)
	}
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
		ownerPositionID,
		company.CreatedAt,
		true,
		company.CreatedAt,
		company.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert owner employee: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ---- Bulk role-department/permission operations ----

// AddRoleDepartments adds multiple departments to a role.
func (r *CompanyRepositoryImpl) AddRoleDepartments(ctx context.Context, roleID uuid.UUID, departmentIDs []uuid.UUID) error {
	query := `
        INSERT INTO role_departments (role_id, department_id, created_at)
        SELECT $1, unnest($2::uuid[]), NOW()
        ON CONFLICT (role_id, department_id) DO NOTHING`
	_, err := r.client.Exec(ctx, query, roleID, departmentIDs)
	if err != nil {
		return fmt.Errorf("failed to add role departments: %w", err)
	}
	return nil
}

// RemoveRoleDepartments removes multiple departments from a role.
func (r *CompanyRepositoryImpl) RemoveRoleDepartments(ctx context.Context, roleID uuid.UUID, departmentIDs []uuid.UUID) error {
	query := `
        DELETE FROM role_departments
        WHERE role_id = $1 AND department_id = ANY($2::uuid[])`
	_, err := r.client.Exec(ctx, query, roleID, departmentIDs)
	if err != nil {
		return fmt.Errorf("failed to remove role departments: %w", err)
	}
	return nil
}

// ClearRolePermissions removes all permissions from a role.
func (r *CompanyRepositoryImpl) ClearRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1`
	_, err := r.client.Exec(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("failed to clear role permissions: %w", err)
	}
	return nil
}

// AddRolePermissions adds multiple permissions to a role.
func (r *CompanyRepositoryImpl) AddRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, grantedBy uuid.UUID) error {
	query := `
        INSERT INTO role_permissions (role_id, permission_id, granted_at, granted_by)
        SELECT $1, unnest($2::uuid[]), NOW(), $3
        ON CONFLICT (role_id, permission_id) DO NOTHING`
	_, err := r.client.Exec(ctx, query, roleID, permissionIDs, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to add role permissions: %w", err)
	}
	return nil
}

// RemoveRolePermissions removes multiple permissions from a role.
func (r *CompanyRepositoryImpl) RemoveRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	query := `
        DELETE FROM role_permissions
        WHERE role_id = $1 AND permission_id = ANY($2::uuid[])`
	_, err := r.client.Exec(ctx, query, roleID, permissionIDs)
	if err != nil {
		return fmt.Errorf("failed to remove role permissions: %w", err)
	}
	return nil
}

// GetDepartmentByName returns a department by name within a company.
// Returns apperrors.ErrNotFound if not found.
func (r *CompanyRepositoryImpl) GetDepartmentByName(ctx context.Context, companyID uuid.UUID, departmentName string) (*models.Department, error) {
	query := `
        SELECT department_id, company_id, department_name, system_department_id,
               parent_department_id, is_active, created_at, updated_at
        FROM departments
        WHERE company_id = $1 AND department_name = $2 AND is_active = true`
	var dept models.Department
	err := r.client.QueryRow(ctx, query, companyID, departmentName).Scan(
		&dept.DepartmentID, &dept.CompanyID, &dept.DepartmentName, &dept.SystemDepartmentID,
		&dept.ParentDepartmentID, &dept.IsActive, &dept.CreatedAt, &dept.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get department by name: %w", err)
	}
	return &dept, nil
}

// GetDeactivatedDepartments returns all deactivated departments for a company.
func (r *CompanyRepositoryImpl) GetDeactivatedDepartments(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	query := `
        SELECT department_id, company_id, department_name, system_department_id,
               parent_department_id, is_active, created_at, updated_at
        FROM departments
        WHERE company_id = $1 AND is_active = false
        ORDER BY department_name ASC`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to query deactivated departments: %w", err)
	}
	defer rows.Close()
	var departments []*models.Department
	for rows.Next() {
		var dept models.Department
		var systemDeptID, parentDeptID sql.NullString
		err := rows.Scan(
			&dept.DepartmentID,
			&dept.CompanyID,
			&dept.DepartmentName,
			&systemDeptID,
			&parentDeptID,
			&dept.IsActive,
			&dept.CreatedAt,
			&dept.UpdatedAt,
		)
		if err != nil {
			continue
		}
		if systemDeptID.Valid {
			id, _ := uuid.Parse(systemDeptID.String)
			dept.SystemDepartmentID = &id
		}
		if parentDeptID.Valid {
			id, _ := uuid.Parse(parentDeptID.String)
			dept.ParentDepartmentID = &id
		}
		departments = append(departments, &dept)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating deactivated departments: %w", err)
	}
	return departments, nil
}

// GetRoleDepartments returns departments associated with a given role.
func (r *CompanyRepositoryImpl) GetRoleDepartmentsForPermission(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	query := `
        SELECT d.department_id, d.company_id, d.department_name,
               d.system_department_id, d.parent_department_id,
               d.is_active, d.created_at, d.updated_at
        FROM departments d
        INNER JOIN role_departments rd ON d.department_id = rd.department_id
        WHERE rd.role_id = $1
        ORDER BY d.department_name
    `
	rows, err := r.client.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query role departments: %w", err)
	}
	defer rows.Close()

	var departments []*models.Department
	for rows.Next() {
		var dept models.Department
		err := rows.Scan(
			&dept.DepartmentID,
			&dept.CompanyID,
			&dept.DepartmentName,
			&dept.SystemDepartmentID,
			&dept.ParentDepartmentID,
			&dept.IsActive,
			&dept.CreatedAt,
			&dept.UpdatedAt,
		)
		if err != nil {
			// log or handle error; for simplicity, continue
			continue
		}
		departments = append(departments, &dept)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department rows: %w", err)
	}
	return departments, nil
}

// GetEmployeeSummariesByCompany returns a list of employee summaries (minimal fields)
// for a given company, with pagination. Also returns the total count.
func (r *CompanyRepositoryImpl) GetEmployeeSummariesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]models.EmployeeSummary, int, error) {
	// Validate pagination
	if limit <= 0 || limit > DefaultCompanyPageSize {
		limit = DefaultCompanyPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Count total active employees
	var total int
	countQuery := `SELECT COUNT(*) FROM company_employees WHERE company_id = $1 AND is_active = true`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count active employees: %w", err)
	}

	// Query only active employees
	query := `
        SELECT
            ce.user_id,
            ce.employee_id,
            u.username,
            COALESCE(u.full_name, '') AS full_name
        FROM company_employees ce
        INNER JOIN users u ON ce.user_id = u.user_id
        WHERE ce.company_id = $1 AND ce.is_active = true
        ORDER BY ce.hire_date DESC
        LIMIT $2 OFFSET $3
    `

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query active employee summaries: %w", err)
	}
	defer rows.Close()

	summaries := make([]models.EmployeeSummary, 0, limit)
	for rows.Next() {
		var s models.EmployeeSummary
		err := rows.Scan(&s.UserID, &s.EmployeeID, &s.Username, &s.FullName)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan employee summary: %w", err)
		}
		summaries = append(summaries, s)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating rows: %w", err)
	}

	return summaries, total, nil
}

func (r *CompanyRepositoryImpl) UpdateEmployeeOfCompany(ctx context.Context, companyID, userID uuid.UUID, updates map[string]interface{}) error {
	// Build dynamic SET clause
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	for key, value := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", key, argIndex))
		args = append(args, value)
		argIndex++
	}

	// Add WHERE clause parameters
	args = append(args, companyID, userID)

	query := fmt.Sprintf(`
        UPDATE company_employees
        SET %s
        WHERE company_id = $%d AND user_id = $%d
    `, strings.Join(setClauses, ", "), argIndex, argIndex+1)

	_, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update employee: %w", err)
	}
	return nil
}
