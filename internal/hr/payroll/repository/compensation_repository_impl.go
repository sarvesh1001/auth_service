package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/payroll/models"
)

type compensationRepository struct {
	client *client.PostgresClient
}

func NewCompensationRepository(
	postgresClient *client.PostgresClient,
) CompensationRepository {
	return &compensationRepository{
		client: postgresClient,
	}
}

// ---------------------------------------------------------------------
// EMPLOYEE SALARY (Assignment Layer)
// ---------------------------------------------------------------------

func (r *compensationRepository) CreateEmployeeSalary(
	ctx context.Context,
	salary *models.EmployeeSalary,
) error {
	if salary.PayType == "" {
		salary.PayType = models.PayTypeMonthly
	}

	overlap, err := r.HasOverlappingSalaryAssignment(
		ctx,
		salary.CompanyID,
		salary.UserID,
		salary.EffectiveFrom,
		salary.EffectiveTo,
		nil,
	)
	if err != nil {
		return err
	}
	if overlap {
		return hrErrors.ErrSalaryOverlap
	}

	query := `
		INSERT INTO payroll.employee_salary (
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	if salary.EmployeeSalaryID == uuid.Nil {
		salary.EmployeeSalaryID = uuid.New()
	}
	if salary.CreatedAt.IsZero() {
		salary.CreatedAt = time.Now().UTC()
	}
	salary.Version = 1
	salary.UpdatedAt = salary.CreatedAt

	_, err = r.client.Exec(ctx, query,
		salary.EmployeeSalaryID,
		salary.CompanyID,
		salary.UserID,
		salary.SalaryStructureID,
		salary.MonthlyCTC,
		salary.PayType,
		salary.EffectiveFrom,
		salary.EffectiveTo,
		salary.IsActive,
		salary.Version,
		salary.CreatedAt,
		salary.UpdatedAt,
		salary.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create employee salary: %w", err)
	}
	return nil
}

func (r *compensationRepository) UpdateEmployeeSalary(
	ctx context.Context,
	salary *models.EmployeeSalary,
) error {
	overlap, err := r.HasOverlappingSalaryAssignment(
		ctx,
		salary.CompanyID,
		salary.UserID,
		salary.EffectiveFrom,
		salary.EffectiveTo,
		&salary.EmployeeSalaryID,
	)
	if err != nil {
		return err
	}
	if overlap {
		return hrErrors.ErrSalaryOverlap
	}

	query := `
		UPDATE payroll.employee_salary
		SET
			salary_structure_id = $1,
			monthly_ctc = $2,
			pay_type = $3,
			effective_from = $4,
			effective_to = $5,
			is_active = $6,
			version = version + 1,
			updated_at = $7,
			updated_by = $8
		WHERE employee_salary_id = $9
			AND version = $10
	`

	salary.UpdatedAt = time.Now().UTC()
	result, err := r.client.Exec(ctx, query,
		salary.SalaryStructureID,
		salary.MonthlyCTC,
		salary.PayType,
		salary.EffectiveFrom,
		salary.EffectiveTo,
		salary.IsActive,
		salary.UpdatedAt,
		salary.UpdatedBy,
		salary.EmployeeSalaryID,
		salary.Version,
	)
	if err != nil {
		return fmt.Errorf("failed to update employee salary: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeSalaryNotFound
	}
	salary.Version++
	return nil
}

func (r *compensationRepository) DeactivateEmployeeSalary(
	ctx context.Context,
	employeeSalaryID uuid.UUID,
	updatedBy uuid.UUID,
) error {
	query := `
		UPDATE payroll.employee_salary
		SET
			is_active = false,
			version = version + 1,
			updated_at = $2,
			updated_by = $3,
			deactivated_at = $2,
			deactivated_by = $3
		WHERE employee_salary_id = $1
	`
	result, err := r.client.Exec(ctx, query,
		employeeSalaryID,
		time.Now().UTC(),
		updatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to deactivate employee salary: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeSalaryNotFound
	}
	return nil
}

func (r *compensationRepository) GetEmployeeSalaryByID(
	ctx context.Context,
	employeeSalaryID uuid.UUID,
) (*models.EmployeeSalary, error) {
	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE employee_salary_id = $1
	`
	row := r.client.QueryRow(ctx, query, employeeSalaryID)
	var salary models.EmployeeSalary
	err := row.Scan(
		&salary.EmployeeSalaryID,
		&salary.CompanyID,
		&salary.UserID,
		&salary.SalaryStructureID,
		&salary.MonthlyCTC,
		&salary.PayType,
		&salary.EffectiveFrom,
		&salary.EffectiveTo,
		&salary.IsActive,
		&salary.Version,
		&salary.CreatedAt,
		&salary.UpdatedAt,
		&salary.UpdatedBy,
		&salary.DeactivatedAt,
		&salary.DeactivatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeSalaryNotFound
		}
		return nil, fmt.Errorf("failed to get employee salary: %w", err)
	}
	return &salary, nil
}

func (r *compensationRepository) GetActiveEmployeeSalary(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeSalary, error) {
	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND user_id = $2
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $3)
			AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, userID, asOf)
	var salary models.EmployeeSalary
	err := row.Scan(
		&salary.EmployeeSalaryID,
		&salary.CompanyID,
		&salary.UserID,
		&salary.SalaryStructureID,
		&salary.MonthlyCTC,
		&salary.PayType,
		&salary.EffectiveFrom,
		&salary.EffectiveTo,
		&salary.IsActive,
		&salary.Version,
		&salary.CreatedAt,
		&salary.UpdatedAt,
		&salary.UpdatedBy,
		&salary.DeactivatedAt,
		&salary.DeactivatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeSalaryNotFound
		}
		return nil, fmt.Errorf("failed to get active employee salary: %w", err)
	}
	return &salary, nil
}

func (r *compensationRepository) GetEmployeeSalaryHistory(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	page, pageSize int,
) ([]models.EmployeeSalary, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE company_id = $1 AND user_id = $2
		ORDER BY effective_from DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee salary history: %w", err)
	}
	defer rows.Close()

	var salaries []models.EmployeeSalary
	for rows.Next() {
		var s models.EmployeeSalary
		if err := rows.Scan(
			&s.EmployeeSalaryID,
			&s.CompanyID,
			&s.UserID,
			&s.SalaryStructureID,
			&s.MonthlyCTC,
			&s.PayType,
			&s.EffectiveFrom,
			&s.EffectiveTo,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.UpdatedAt,
			&s.UpdatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee salary: %w", err)
		}
		salaries = append(salaries, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return salaries, nil
}

func (r *compensationRepository) GetEmployeesWithActiveSalaryInPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT user_id
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND is_active = true
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $2)
	`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get employees with active salary: %w", err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var uid uuid.UUID
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan user ID: %w", err)
		}
		userIDs = append(userIDs, uid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return userIDs, nil
}

func (r *compensationRepository) CloseActiveSalaryBefore(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	newEffectiveFrom time.Time,
	closedBy uuid.UUID,
) error {
	query := `
		UPDATE payroll.employee_salary
		SET
			effective_to = $4 - INTERVAL '1 day',
			version = version + 1,
			updated_at = $5,
			updated_by = $6
		WHERE company_id = $1
			AND user_id = $2
			AND is_active = true
			AND effective_from < $4
			AND (effective_to IS NULL OR effective_to >= $4)
	`
	_, err := r.client.Exec(ctx, query,
		companyID,
		userID,
		newEffectiveFrom,
		time.Now().UTC(),
		closedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to close active salary: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// SALARY STRUCTURE (Template Layer)
// ---------------------------------------------------------------------

func (r *compensationRepository) CreateSalaryStructure(
	ctx context.Context,
	structure *models.SalaryStructure,
) error {
	query := `
		INSERT INTO payroll.salary_structure (
			salary_structure_id,
			company_id,
			structure_name,
			currency_code,
			is_active,
			version,
			created_at,
			created_by,
			updated_at,
			updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if structure.SalaryStructureID == uuid.Nil {
		structure.SalaryStructureID = uuid.New()
	}
	if structure.CreatedAt.IsZero() {
		structure.CreatedAt = time.Now().UTC()
	}
	structure.Version = 1
	structure.UpdatedAt = structure.CreatedAt
	structure.UpdatedBy = structure.CreatedBy

	_, err := r.client.Exec(ctx, query,
		structure.SalaryStructureID,
		structure.CompanyID,
		structure.StructureName,
		structure.CurrencyCode,
		structure.IsActive,
		structure.Version,
		structure.CreatedAt,
		structure.CreatedBy,
		structure.UpdatedAt,
		structure.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create salary structure: %w", err)
	}
	return nil
}

func (r *compensationRepository) UpdateSalaryStructure(
	ctx context.Context,
	structure *models.SalaryStructure,
) error {
	query := `
		UPDATE payroll.salary_structure
		SET
			structure_name = $1,
			currency_code = $2,
			is_active = $3,
			version = version + 1,
			updated_at = $4,
			updated_by = $5
		WHERE salary_structure_id = $6
			AND version = $7
	`
	structure.UpdatedAt = time.Now().UTC()
	result, err := r.client.Exec(ctx, query,
		structure.StructureName,
		structure.CurrencyCode,
		structure.IsActive,
		structure.UpdatedAt,
		structure.UpdatedBy,
		structure.SalaryStructureID,
		structure.Version,
	)
	if err != nil {
		return fmt.Errorf("failed to update salary structure: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrSalaryStructureNotFound
	}
	structure.Version++
	return nil
}

func (r *compensationRepository) DeactivateSalaryStructure(
	ctx context.Context,
	structureID uuid.UUID,
	updatedBy uuid.UUID,
) error {
	query := `
		UPDATE payroll.salary_structure
		SET
			is_active = false,
			version = version + 1,
			updated_at = $2,
			updated_by = $3,
			deactivated_at = $2,
			deactivated_by = $3
		WHERE salary_structure_id = $1
	`
	result, err := r.client.Exec(ctx, query,
		structureID,
		time.Now().UTC(),
		updatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to deactivate salary structure: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrSalaryStructureNotFound
	}
	return nil
}

func (r *compensationRepository) GetSalaryStructure(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
) (*models.SalaryStructure, error) {
	query := `
		SELECT
			salary_structure_id,
			company_id,
			structure_name,
			currency_code,
			is_active,
			version,
			created_at,
			created_by,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.salary_structure
		WHERE salary_structure_id = $1 AND company_id = $2
	`
	row := r.client.QueryRow(ctx, query, structureID, companyID)
	var s models.SalaryStructure
	err := row.Scan(
		&s.SalaryStructureID,
		&s.CompanyID,
		&s.StructureName,
		&s.CurrencyCode,
		&s.IsActive,
		&s.Version,
		&s.CreatedAt,
		&s.CreatedBy,
		&s.UpdatedAt,
		&s.UpdatedBy,
		&s.DeactivatedAt,
		&s.DeactivatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrSalaryStructureNotFound
		}
		return nil, fmt.Errorf("failed to get salary structure: %w", err)
	}
	return &s, nil
}

func (r *compensationRepository) GetSalaryStructuresByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	includeInactive bool,
) ([]models.SalaryStructure, error) {
	query := `
		SELECT
			salary_structure_id,
			company_id,
			structure_name,
			currency_code,
			is_active,
			version,
			created_at,
			created_by,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.salary_structure
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	if !includeInactive {
		query += " AND is_active = true"
	}
	query += " ORDER BY structure_name"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get salary structures: %w", err)
	}
	defer rows.Close()

	var structures []models.SalaryStructure
	for rows.Next() {
		var s models.SalaryStructure
		if err := rows.Scan(
			&s.SalaryStructureID,
			&s.CompanyID,
			&s.StructureName,
			&s.CurrencyCode,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.CreatedBy,
			&s.UpdatedAt,
			&s.UpdatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan salary structure: %w", err)
		}
		structures = append(structures, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return structures, nil
}

func (r *compensationRepository) IsSalaryStructureInUse(
	ctx context.Context,
	structureID uuid.UUID,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.employee_salary
			WHERE salary_structure_id = $1
		)
	`
	var inUse bool
	err := r.client.QueryRow(ctx, query, structureID).Scan(&inUse)
	if err != nil {
		return false, fmt.Errorf("failed to check salary structure usage: %w", err)
	}
	return inUse, nil
}

// ---------------------------------------------------------------------
// SALARY STRUCTURE COMPONENTS
// ---------------------------------------------------------------------

// resolveComponent returns the active component for (companyID, code).
func (r *compensationRepository) resolveComponent(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
) (*models.PayrollComponent, error) {
	const query = `
		SELECT
			component_id, company_id, component_code, component_type,
			description, is_taxable, is_system, is_active, contribution_side
		FROM payroll.payroll_component
		WHERE company_id = $1
		  AND component_code = $2
		  AND is_active = true
		LIMIT 1
	`
	var comp models.PayrollComponent
	err := r.client.QueryRow(ctx, query, companyID, componentCode).Scan(
		&comp.ComponentID,
		&comp.CompanyID,
		&comp.ComponentCode,
		&comp.ComponentType,
		&comp.Description,
		&comp.IsTaxable,
		&comp.IsSystem,
		&comp.IsActive,
		&comp.ContributionSide,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrPayrollComponentNotFound
		}
		return nil, fmt.Errorf("resolve component %s: %w", componentCode, err)
	}
	return &comp, nil
}

func (r *compensationRepository) AddStructureComponent(
	ctx context.Context,
	component *models.SalaryStructureComponent,
) error {
	exists, err := r.salaryStructureExists(ctx, component.SalaryStructureID, component.CompanyID)
	if err != nil {
		return err
	}
	if !exists {
		return hrErrors.ErrSalaryStructureNotFound
	}

	resolved, err := r.resolveComponent(ctx, component.CompanyID, component.ComponentCode)
	if err != nil {
		return err
	}
	component.ComponentID = resolved.ComponentID

	// Resolve optional based_on self-reference
	if component.BasedOnComponent != nil && *component.BasedOnComponent != "" {
		basedOn, err := r.resolveComponent(ctx, component.CompanyID, *component.BasedOnComponent)
		if err != nil {
			return fmt.Errorf("resolve based_on_component: %w", err)
		}
		component.BasedOnComponentID = &basedOn.ComponentID
	}

	query := `
        INSERT INTO payroll.salary_structure_component (
            mapping_id,
            salary_structure_id,
            company_id,
            component_id,
            calculation_type,
            value,
            based_on_component_id,
            sequence_order,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
	if component.MappingID == uuid.Nil {
		component.MappingID = uuid.New()
	}
	if component.CreatedAt.IsZero() {
		component.CreatedAt = time.Now().UTC()
	}

	_, err = r.client.Exec(ctx, query,
		component.MappingID,
		component.SalaryStructureID,
		component.CompanyID,
		component.ComponentID,
		component.CalculationType,
		component.Value,
		component.BasedOnComponentID,
		component.SequenceOrder,
		component.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add structure component: %w", err)
	}
	return nil
}

func (r *compensationRepository) UpdateStructureComponent(
	ctx context.Context,
	component *models.SalaryStructureComponent,
) error {
	resolved, err := r.resolveComponent(ctx, component.CompanyID, component.ComponentCode)
	if err != nil {
		return err
	}
	component.ComponentID = resolved.ComponentID

	if component.BasedOnComponent != nil && *component.BasedOnComponent != "" {
		basedOn, err := r.resolveComponent(ctx, component.CompanyID, *component.BasedOnComponent)
		if err != nil {
			return fmt.Errorf("resolve based_on_component: %w", err)
		}
		component.BasedOnComponentID = &basedOn.ComponentID
	} else {
		component.BasedOnComponentID = nil
	}

	query := `
		UPDATE payroll.salary_structure_component
		SET
			component_id = $1,
			calculation_type = $2,
			value = $3,
			based_on_component_id = $4,
			sequence_order = $5
		WHERE mapping_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		component.ComponentID,
		component.CalculationType,
		component.Value,
		component.BasedOnComponentID,
		component.SequenceOrder,
		component.MappingID,
	)
	if err != nil {
		return fmt.Errorf("failed to update structure component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrSalaryStructureComponentNotFound
	}
	return nil
}

func (r *compensationRepository) RemoveStructureComponent(
	ctx context.Context,
	mappingID uuid.UUID,
) error {
	query := `
		DELETE FROM payroll.salary_structure_component
		WHERE mapping_id = $1
	`
	result, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		return fmt.Errorf("failed to remove structure component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrSalaryStructureComponentNotFound
	}
	return nil
}

func (r *compensationRepository) GetStructureComponentByID(
	ctx context.Context,
	mappingID uuid.UUID,
) (*models.SalaryStructureComponent, error) {
	query := `
		SELECT
			ssc.mapping_id,
			ssc.salary_structure_id,
			ssc.company_id,
			ssc.component_id,
			pc.component_code,
			ssc.calculation_type,
			ssc.value,
			ssc.based_on_component_id,
			bopc.component_code AS based_on_component,
			ssc.sequence_order,
			ssc.created_at
		FROM payroll.salary_structure_component ssc
		JOIN payroll.payroll_component pc ON pc.component_id = ssc.component_id
		LEFT JOIN payroll.payroll_component bopc ON bopc.component_id = ssc.based_on_component_id
		WHERE ssc.mapping_id = $1
	`
	row := r.client.QueryRow(ctx, query, mappingID)
	var c models.SalaryStructureComponent
	err := row.Scan(
		&c.MappingID,
		&c.SalaryStructureID,
		&c.CompanyID,
		&c.ComponentID,
		&c.ComponentCode,
		&c.CalculationType,
		&c.Value,
		&c.BasedOnComponentID,
		&c.BasedOnComponent,
		&c.SequenceOrder,
		&c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrSalaryStructureComponentNotFound
		}
		return nil, fmt.Errorf("failed to get structure component: %w", err)
	}
	return &c, nil
}

func (r *compensationRepository) GetStructureComponents(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
) ([]models.SalaryStructureComponent, error) {
	return r.getStructureComponentsOrdered(ctx, structureID, companyID, false)
}

func (r *compensationRepository) GetStructureComponentsOrdered(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
) ([]models.SalaryStructureComponent, error) {
	return r.getStructureComponentsOrdered(ctx, structureID, companyID, true)
}

func (r *compensationRepository) getStructureComponentsOrdered(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
	ordered bool,
) ([]models.SalaryStructureComponent, error) {
	exists, err := r.salaryStructureExists(ctx, structureID, companyID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, hrErrors.ErrSalaryStructureNotFound
	}

	query := `
		SELECT
			ssc.mapping_id,
			ssc.salary_structure_id,
			ssc.company_id,
			ssc.component_id,
			pc.component_code,
			ssc.calculation_type,
			ssc.value,
			ssc.based_on_component_id,
			bopc.component_code AS based_on_component,
			ssc.sequence_order,
			ssc.created_at
		FROM payroll.salary_structure_component ssc
		JOIN payroll.payroll_component pc ON pc.component_id = ssc.component_id
		LEFT JOIN payroll.payroll_component bopc ON bopc.component_id = ssc.based_on_component_id
		WHERE ssc.salary_structure_id = $1
	`
	if ordered {
		query += " ORDER BY ssc.sequence_order"
	}

	rows, err := r.client.Query(ctx, query, structureID)
	if err != nil {
		return nil, fmt.Errorf("failed to get structure components: %w", err)
	}
	defer rows.Close()

	var components []models.SalaryStructureComponent
	for rows.Next() {
		var c models.SalaryStructureComponent
		if err := rows.Scan(
			&c.MappingID,
			&c.SalaryStructureID,
			&c.CompanyID,
			&c.ComponentID,
			&c.ComponentCode,
			&c.CalculationType,
			&c.Value,
			&c.BasedOnComponentID,
			&c.BasedOnComponent,
			&c.SequenceOrder,
			&c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan structure component: %w", err)
		}
		components = append(components, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return components, nil
}

func (r *compensationRepository) ReplaceStructureComponents(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
	components []models.SalaryStructureComponent,
) error {
	exists, err := r.salaryStructureExists(ctx, structureID, companyID)
	if err != nil {
		return err
	}
	if !exists {
		return hrErrors.ErrSalaryStructureNotFound
	}

	// Resolve all codes to IDs BEFORE touching the DB.
	for i := range components {
		resolved, err := r.resolveComponent(ctx, companyID, components[i].ComponentCode)
		if err != nil {
			return err
		}
		components[i].CompanyID = companyID
		components[i].ComponentID = resolved.ComponentID

		if components[i].BasedOnComponent != nil && *components[i].BasedOnComponent != "" {
			basedOn, err := r.resolveComponent(ctx, companyID, *components[i].BasedOnComponent)
			if err != nil {
				return fmt.Errorf("resolve based_on_component for %s: %w", components[i].ComponentCode, err)
			}
			components[i].BasedOnComponentID = &basedOn.ComponentID
		}
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, `
		DELETE FROM payroll.salary_structure_component
		WHERE salary_structure_id = $1
	`, structureID)
	if err != nil {
		return fmt.Errorf("failed to delete existing components: %w", err)
	}

	if len(components) > 0 {
		insertQuery := `
			INSERT INTO payroll.salary_structure_component (
				mapping_id,
				salary_structure_id,
				company_id,
				component_id,
				calculation_type,
				value,
				based_on_component_id,
				sequence_order,
				created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`
		stmt, err := tx.PrepareContext(ctx, insertQuery)
		if err != nil {
			return fmt.Errorf("failed to prepare insert statement: %w", err)
		}
		defer stmt.Close()

		for i := range components {
			c := &components[i]
			if c.MappingID == uuid.Nil {
				c.MappingID = uuid.New()
			}
			if c.CreatedAt.IsZero() {
				c.CreatedAt = time.Now().UTC()
			}
			_, err = stmt.ExecContext(ctx,
				c.MappingID,
				structureID,
				companyID,
				c.ComponentID,
				c.CalculationType,
				c.Value,
				c.BasedOnComponentID,
				c.SequenceOrder,
				c.CreatedAt,
			)
			if err != nil {
				return fmt.Errorf("failed to insert component %s: %w", c.ComponentCode, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// salaryStructureExists checks existence AND company ownership.
func (r *compensationRepository) salaryStructureExists(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
) (bool, error) {
	query := `SELECT EXISTS (
		SELECT 1 FROM payroll.salary_structure
		WHERE salary_structure_id = $1 AND company_id = $2
	)`
	var exists bool
	err := r.client.QueryRow(ctx, query, structureID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check salary structure existence: %w", err)
	}
	return exists, nil
}

// ---------------------------------------------------------------------
// VALIDATION & RESOLUTION HELPERS
// ---------------------------------------------------------------------

func (r *compensationRepository) HasOverlappingSalaryAssignment(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	effectiveFrom time.Time,
	effectiveTo *time.Time,
	excludeSalaryID *uuid.UUID,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.employee_salary
			WHERE company_id = $1
				AND user_id = $2
				AND is_active = true
				AND daterange(
						effective_from,
						COALESCE(effective_to, 'infinity'),
						'[]'
					)
					&& daterange(
						$3::date,
						COALESCE($4::date, 'infinity'),
						'[]'
					)
	`
	args := []interface{}{companyID, userID, effectiveFrom, effectiveTo}
	if excludeSalaryID != nil {
		query += " AND employee_salary_id <> $5"
		args = append(args, *excludeSalaryID)
	}
	query += ")"

	var overlaps bool
	err := r.client.QueryRow(ctx, query, args...).Scan(&overlaps)
	if err != nil {
		return false, fmt.Errorf("failed to check overlapping salary: %w", err)
	}
	return overlaps, nil
}

func (r *compensationRepository) IsSalaryStructureValid(
	ctx context.Context,
	structureID uuid.UUID,
) (bool, error) {
	query := `
		WITH comps AS (
			SELECT
				ssc.component_id,
				pc.component_type,
				ssc.sequence_order,
				COUNT(*) OVER (PARTITION BY ssc.component_id) AS code_dup
			FROM payroll.salary_structure_component ssc
			JOIN payroll.payroll_component pc ON pc.component_id = ssc.component_id
			WHERE ssc.salary_structure_id = $1
		)
		SELECT
			EXISTS (SELECT 1 FROM comps WHERE component_type = 'earning') AS has_earning,
			NOT EXISTS (SELECT 1 FROM comps WHERE component_type IS NULL) AS all_active,
			NOT EXISTS (SELECT 1 FROM comps WHERE code_dup > 1) AS no_dup_codes,
			NOT EXISTS (
				SELECT 1
				FROM comps
				GROUP BY sequence_order
				HAVING COUNT(*) > 1 AND sequence_order IS NOT NULL
			) AS unique_seq_order
	`
	var hasEarning, allActive, noDupCodes, uniqueSeqOrder bool
	err := r.client.QueryRow(ctx, query, structureID).Scan(
		&hasEarning,
		&allActive,
		&noDupCodes,
		&uniqueSeqOrder,
	)
	if err != nil {
		return false, fmt.Errorf("failed to validate salary structure: %w", err)
	}
	return hasEarning && allActive && noDupCodes && uniqueSeqOrder, nil
}

// ---------------------------------------------------------------------
// REPORTING & ANALYTICS SUPPORT
// ---------------------------------------------------------------------

func (r *compensationRepository) GetTotalMonthlyCTCByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
) (float64, error) {
	query := `
		SELECT COALESCE(SUM(monthly_ctc), 0)
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND is_active = true
			AND effective_from <= $2
			AND (effective_to IS NULL OR effective_to >= $2)
	`
	var total float64
	err := r.client.QueryRow(ctx, query, companyID, asOf).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to get total monthly CTC: %w", err)
	}
	return total, nil
}

func (r *compensationRepository) GetEmployeeCompensationSnapshot(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeSalary, error) {
	return r.GetActiveEmployeeSalary(ctx, companyID, userID, asOf)
}

// ---------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------

func (r *compensationRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM payroll.salary_structure LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil {
		return fmt.Errorf("compensation repository health check failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Component Metadata (from payroll.payroll_component)
// ---------------------------------------------------------------------

func (r *compensationRepository) GetComponent(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
) (*models.PayrollComponent, error) {
	const query = `
        SELECT
            component_id,
            company_id,
            component_code,
            component_type,
            description,
            is_taxable,
            is_system,
            is_active,
            contribution_side
        FROM payroll.payroll_component
        WHERE company_id = $1
          AND component_code = $2
          AND is_active = true
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, companyID, code)
	var comp models.PayrollComponent
	err := row.Scan(
		&comp.ComponentID,
		&comp.CompanyID,
		&comp.ComponentCode,
		&comp.ComponentType,
		&comp.Description,
		&comp.IsTaxable,
		&comp.IsSystem,
		&comp.IsActive,
		&comp.ContributionSide,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrPayrollComponentNotFound
		}
		return nil, fmt.Errorf("failed to get component: %w", err)
	}
	return &comp, nil
}

func (r *compensationRepository) GetComponentsByCodes(
	ctx context.Context,
	companyID uuid.UUID,
	codes []string,
) ([]*models.PayrollComponent, error) {

	if len(codes) == 0 {
		return []*models.PayrollComponent{}, nil
	}

	// Deduplicate
	codeSet := make(map[string]struct{})
	unique := make([]string, 0, len(codes))
	for _, c := range codes {
		if _, ok := codeSet[c]; !ok {
			codeSet[c] = struct{}{}
			unique = append(unique, c)
		}
	}
	codes = unique

	query := `
        SELECT
            component_id,
            company_id,
            component_code,
            component_type,
            description,
            is_taxable,
            is_system,
            is_active,
            contribution_side
        FROM payroll.payroll_component
        WHERE company_id = $1
          AND component_code = ANY($2)
          AND is_active = true
    `

	rows, err := r.client.Query(ctx, query, companyID, pq.Array(codes))
	if err != nil {
		return nil, fmt.Errorf("failed to get components by codes: %w", err)
	}
	defer rows.Close()

	var result []*models.PayrollComponent
	for rows.Next() {
		var comp models.PayrollComponent
		if err := rows.Scan(
			&comp.ComponentID,
			&comp.CompanyID,
			&comp.ComponentCode,
			&comp.ComponentType,
			&comp.Description,
			&comp.IsTaxable,
			&comp.IsSystem,
			&comp.IsActive,
			&comp.ContributionSide,
		); err != nil {
			return nil, fmt.Errorf("failed to scan component: %w", err)
		}
		result = append(result, &comp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return result, nil
}

func (r *compensationRepository) GetSalaryStructureWithComponents(
	ctx context.Context,
	structureID uuid.UUID,
	companyID uuid.UUID,
	asOf time.Time,
) (*models.SalaryStructure, []models.SalaryStructureComponent, error) {

	structureQuery := `
        SELECT
            salary_structure_id,
            company_id,
            structure_name,
            currency_code,
            is_active,
            version,
            created_at,
            created_by,
            updated_at,
            updated_by,
            deactivated_at,
            deactivated_by
        FROM payroll.salary_structure
        WHERE salary_structure_id = $1
          AND company_id = $2
          AND is_active = true
    `

	var structure models.SalaryStructure
	err := r.client.QueryRow(ctx, structureQuery, structureID, companyID).Scan(
		&structure.SalaryStructureID,
		&structure.CompanyID,
		&structure.StructureName,
		&structure.CurrencyCode,
		&structure.IsActive,
		&structure.Version,
		&structure.CreatedAt,
		&structure.CreatedBy,
		&structure.UpdatedAt,
		&structure.UpdatedBy,
		&structure.DeactivatedAt,
		&structure.DeactivatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, hrErrors.ErrSalaryStructureNotFound
		}
		return nil, nil, fmt.Errorf("failed to get salary structure: %w", err)
	}

	componentsQuery := `
        SELECT
            ssc.mapping_id,
            ssc.salary_structure_id,
            ssc.company_id,
            ssc.component_id,
            pc.component_code,
            ssc.calculation_type,
            ssc.value,
            ssc.based_on_component_id,
            bopc.component_code AS based_on_component,
            ssc.sequence_order,
            ssc.created_at
        FROM payroll.salary_structure_component ssc
        JOIN payroll.payroll_component pc ON pc.component_id = ssc.component_id
        LEFT JOIN payroll.payroll_component bopc ON bopc.component_id = ssc.based_on_component_id
        WHERE ssc.salary_structure_id = $1
        ORDER BY ssc.sequence_order
    `

	rows, err := r.client.Query(ctx, componentsQuery, structureID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get structure components: %w", err)
	}
	defer rows.Close()

	var components []models.SalaryStructureComponent
	for rows.Next() {
		var comp models.SalaryStructureComponent
		if err := rows.Scan(
			&comp.MappingID,
			&comp.SalaryStructureID,
			&comp.CompanyID,
			&comp.ComponentID,
			&comp.ComponentCode,
			&comp.CalculationType,
			&comp.Value,
			&comp.BasedOnComponentID,
			&comp.BasedOnComponent,
			&comp.SequenceOrder,
			&comp.CreatedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("failed to scan component: %w", err)
		}
		components = append(components, comp)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return &structure, components, nil
}

func (r *compensationRepository) GetEmployeeSalaryHistoryInRange(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]models.EmployeeSalary, error) {
	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND user_id = $2
			AND is_active = true
			AND effective_from <= $4
			AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get salary history in range: %w", err)
	}
	defer rows.Close()

	var salaries []models.EmployeeSalary
	for rows.Next() {
		var s models.EmployeeSalary
		if err := rows.Scan(
			&s.EmployeeSalaryID,
			&s.CompanyID,
			&s.UserID,
			&s.SalaryStructureID,
			&s.MonthlyCTC,
			&s.PayType,
			&s.EffectiveFrom,
			&s.EffectiveTo,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.UpdatedAt,
			&s.UpdatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee salary: %w", err)
		}
		salaries = append(salaries, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return salaries, nil
}

func (r *compensationRepository) GetActiveEmployeeSalaryForUpdate(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeSalary, error) {
	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND user_id = $2
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $3)
			AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
		FOR UPDATE
	`
	row := r.client.QueryRow(ctx, query, companyID, userID, asOf)
	var salary models.EmployeeSalary
	err := row.Scan(
		&salary.EmployeeSalaryID,
		&salary.CompanyID,
		&salary.UserID,
		&salary.SalaryStructureID,
		&salary.MonthlyCTC,
		&salary.PayType,
		&salary.EffectiveFrom,
		&salary.EffectiveTo,
		&salary.IsActive,
		&salary.Version,
		&salary.CreatedAt,
		&salary.UpdatedAt,
		&salary.UpdatedBy,
		&salary.DeactivatedAt,
		&salary.DeactivatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeSalaryNotFound
		}
		return nil, fmt.Errorf("failed to get active employee salary for update: %w", err)
	}
	return &salary, nil
}

func (r *compensationRepository) GetEmployeeSalaryHistoryInRangeForUpdate(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]models.EmployeeSalary, error) {
	query := `
		SELECT
			employee_salary_id,
			company_id,
			user_id,
			salary_structure_id,
			monthly_ctc,
			pay_type,
			effective_from,
			effective_to,
			is_active,
			version,
			created_at,
			updated_at,
			updated_by,
			deactivated_at,
			deactivated_by
		FROM payroll.employee_salary
		WHERE company_id = $1
			AND user_id = $2
			AND is_active = true
			AND effective_from <= $4
			AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from ASC
		FOR UPDATE
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get salary history for update: %w", err)
	}
	defer rows.Close()

	var salaries []models.EmployeeSalary
	for rows.Next() {
		var s models.EmployeeSalary
		if err := rows.Scan(
			&s.EmployeeSalaryID,
			&s.CompanyID,
			&s.UserID,
			&s.SalaryStructureID,
			&s.MonthlyCTC,
			&s.PayType,
			&s.EffectiveFrom,
			&s.EffectiveTo,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.UpdatedAt,
			&s.UpdatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee salary: %w", err)
		}
		salaries = append(salaries, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return salaries, nil
}
