package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type SalaryStructureRepository interface {
	// Core CRUD
	Create(ctx context.Context, s *models.SalaryStructure) error
	Update(ctx context.Context, s *models.SalaryStructure) error
	GetByID(ctx context.Context, structureID uuid.UUID, companyID uuid.UUID) (*models.SalaryStructure, error)
	GetByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]models.SalaryStructure, error)
	Deactivate(ctx context.Context, structureID uuid.UUID, deactivatedBy uuid.UUID) error

	// Component management
	AddComponent(ctx context.Context, comp *models.SalaryStructureComponent) error
	UpdateComponent(ctx context.Context, comp *models.SalaryStructureComponent) error
	RemoveComponent(ctx context.Context, mappingID uuid.UUID) error
	GetComponents(ctx context.Context, structureID uuid.UUID) ([]models.SalaryStructureComponent, error)
	GetComponentsOrdered(ctx context.Context, structureID uuid.UUID) ([]models.SalaryStructureComponent, error)
	ReplaceComponents(ctx context.Context, structureID uuid.UUID, comps []models.SalaryStructureComponent) error

	// Assignment checks
	IsStructureInUse(ctx context.Context, structureID uuid.UUID) (bool, error)
	HasOverlappingAssignment(ctx context.Context, companyID, userID uuid.UUID, effectiveFrom time.Time, excludeID *uuid.UUID) (bool, error)

	// Health
	HealthCheck(ctx context.Context) error
}

type salaryStructureRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewSalaryStructureRepository(pg *client.PostgresClient, logger *zap.Logger) SalaryStructureRepository {
	return &salaryStructureRepository{
		client: pg,
		logger: logger.Named("salary_structure_repo"),
	}
}

// ---------------------------------------------------------------------
// Core CRUD
// ---------------------------------------------------------------------

func (r *salaryStructureRepository) Create(ctx context.Context, s *models.SalaryStructure) error {
	query := `
		INSERT INTO payroll.salary_structure (
			salary_structure_id, company_id, structure_name, currency_code,
			is_active, version, created_at, created_by, updated_at, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if s.SalaryStructureID == uuid.Nil {
		s.SalaryStructureID = uuid.New()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	s.Version = 1
	s.UpdatedAt = s.CreatedAt
	s.UpdatedBy = s.CreatedBy

	_, err := r.client.Exec(ctx, query,
		s.SalaryStructureID,
		s.CompanyID,
		s.StructureName,
		s.CurrencyCode,
		s.IsActive,
		s.Version,
		s.CreatedAt,
		s.CreatedBy,
		s.UpdatedAt,
		s.UpdatedBy,
	)
	if err != nil {
		r.logger.Error("failed to create salary structure",
			util.String("company_id", s.CompanyID.String()),
			util.String("name", s.StructureName),
			util.ErrorField(err),
		)
		return fmt.Errorf("create salary structure: %w", err)
	}
	return nil
}

func (r *salaryStructureRepository) Update(ctx context.Context, s *models.SalaryStructure) error {
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
	s.UpdatedAt = time.Now().UTC()
	result, err := r.client.Exec(ctx, query,
		s.StructureName,
		s.CurrencyCode,
		s.IsActive,
		s.UpdatedAt,
		s.UpdatedBy,
		s.SalaryStructureID,
		s.Version,
	)
	if err != nil {
		r.logger.Error("failed to update salary structure",
			util.String("structure_id", s.SalaryStructureID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update salary structure: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("salary structure not found or version mismatch")
	}
	s.Version++
	return nil
}

func (r *salaryStructureRepository) GetByID(ctx context.Context, structureID, companyID uuid.UUID) (*models.SalaryStructure, error) {
	query := `
		SELECT
			salary_structure_id, company_id, structure_name, currency_code,
			is_active, version, created_at, created_by,
			updated_at, updated_by, deactivated_at, deactivated_by
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
			return nil, nil
		}
		r.logger.Error("failed to get salary structure by ID",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get salary structure by ID: %w", err)
	}
	return &s, nil
}

func (r *salaryStructureRepository) GetByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]models.SalaryStructure, error) {
	query := `
		SELECT
			salary_structure_id, company_id, structure_name, currency_code,
			is_active, version, created_at, created_by,
			updated_at, updated_by, deactivated_at, deactivated_by
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
		r.logger.Error("failed to get salary structures by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get salary structures by company: %w", err)
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
			return nil, fmt.Errorf("scan salary structure: %w", err)
		}
		structures = append(structures, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return structures, nil
}

func (r *salaryStructureRepository) Deactivate(ctx context.Context, structureID uuid.UUID, deactivatedBy uuid.UUID) error {
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
	result, err := r.client.Exec(ctx, query, structureID, time.Now().UTC(), deactivatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate salary structure",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("deactivate salary structure: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("salary structure not found")
	}
	return nil
}

// ---------------------------------------------------------------------
// Component management
// ---------------------------------------------------------------------

// componentExistsForCompany checks if a component code is active for the given company.
func (r *salaryStructureRepository) componentExistsForCompany(ctx context.Context, companyID uuid.UUID, componentCode string) (bool, error) {

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.payroll_component
			WHERE component_code = $2
			  AND is_active = true
			  AND (company_id = $1 OR company_id IS NULL)
		)
	`

	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, componentCode).Scan(&exists)

	if err != nil {
		r.logger.Error("failed to check component existence",
			util.String("company_id", companyID.String()),
			util.String("component_code", componentCode),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("check component existence: %w", err)
	}

	return exists, nil
}

// getStructureCompanyID returns the company ID of a salary structure.
func (r *salaryStructureRepository) getStructureCompanyID(ctx context.Context, structureID uuid.UUID) (uuid.UUID, error) {
	const query = `SELECT company_id FROM payroll.salary_structure WHERE salary_structure_id = $1`
	var companyID uuid.UUID
	err := r.client.QueryRow(ctx, query, structureID).Scan(&companyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("salary structure %s not found", structureID)
		}
		r.logger.Error("failed to get structure company ID",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err),
		)
		return uuid.Nil, fmt.Errorf("get structure company ID: %w", err)
	}
	return companyID, nil
}

func (r *salaryStructureRepository) AddComponent(ctx context.Context, comp *models.SalaryStructureComponent) error {
	// Ensure the component's company ID is set; if not, derive it from the structure.
	if comp.CompanyID == uuid.Nil {
		companyID, err := r.getStructureCompanyID(ctx, comp.SalaryStructureID)
		if err != nil {
			return fmt.Errorf("failed to resolve structure's company: %w", err)
		}
		comp.CompanyID = companyID
	}

	// Validate that the component exists and is active for the company.
	exists, err := r.componentExistsForCompany(ctx, comp.CompanyID, comp.ComponentCode)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("component %s is not active for company %s", comp.ComponentCode, comp.CompanyID)
	}

	query := `
		INSERT INTO payroll.salary_structure_component (
			mapping_id, salary_structure_id, component_code,
			calculation_type, value, based_on_component, sequence_order, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	if comp.MappingID == uuid.Nil {
		comp.MappingID = uuid.New()
	}
	if comp.CreatedAt.IsZero() {
		comp.CreatedAt = time.Now().UTC()
	}
	_, err = r.client.Exec(ctx, query,
		comp.MappingID,
		comp.SalaryStructureID,
		comp.ComponentCode,
		comp.CalculationType,
		comp.Value,
		comp.BasedOnComponent,
		comp.SequenceOrder,
		comp.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to add structure component",
			util.String("structure_id", comp.SalaryStructureID.String()),
			util.String("component", comp.ComponentCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("add structure component: %w", err)
	}
	return nil
}

func (r *salaryStructureRepository) UpdateComponent(ctx context.Context, comp *models.SalaryStructureComponent) error {
	// If the component code is being changed, validate the new code.
	// First, fetch the current component to see if code changed.
	var currentCode string
	const getCurrentQuery = `
		SELECT component_code
		FROM payroll.salary_structure_component
		WHERE mapping_id = $1
	`
	err := r.client.QueryRow(ctx, getCurrentQuery, comp.MappingID).Scan(&currentCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("component mapping %s not found", comp.MappingID)
		}
		r.logger.Error("failed to fetch current component code",
			util.String("mapping_id", comp.MappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("fetch current component: %w", err)
	}

	// If the component code changed, we need to validate the new one.
	if currentCode != comp.ComponentCode {
		// We need the company ID for validation. Try to get it from comp, or fetch from structure.
		if comp.CompanyID == uuid.Nil {
			// Need to get structure ID from this component. The comp already has SalaryStructureID.
			companyID, err := r.getStructureCompanyID(ctx, comp.SalaryStructureID)
			if err != nil {
				return fmt.Errorf("failed to resolve structure's company: %w", err)
			}
			comp.CompanyID = companyID
		}
		exists, err := r.componentExistsForCompany(ctx, comp.CompanyID, comp.ComponentCode)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("component %s is not active for company %s", comp.ComponentCode, comp.CompanyID)
		}
	}

	query := `
		UPDATE payroll.salary_structure_component
		SET
			component_code = $1,
			calculation_type = $2,
			value = $3,
			based_on_component = $4,
			sequence_order = $5
		WHERE mapping_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		comp.ComponentCode,
		comp.CalculationType,
		comp.Value,
		comp.BasedOnComponent,
		comp.SequenceOrder,
		comp.MappingID,
	)
	if err != nil {
		r.logger.Error("failed to update structure component",
			util.String("mapping_id", comp.MappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update structure component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("structure component not found")
	}
	return nil
}

func (r *salaryStructureRepository) RemoveComponent(ctx context.Context, mappingID uuid.UUID) error {
	query := `DELETE FROM payroll.salary_structure_component WHERE mapping_id = $1`
	result, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		r.logger.Error("failed to remove structure component",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("remove structure component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("structure component not found")
	}
	return nil
}

func (r *salaryStructureRepository) GetComponents(ctx context.Context, structureID uuid.UUID) ([]models.SalaryStructureComponent, error) {
	return r.getComponents(ctx, structureID, false)
}

func (r *salaryStructureRepository) GetComponentsOrdered(ctx context.Context, structureID uuid.UUID) ([]models.SalaryStructureComponent, error) {
	return r.getComponents(ctx, structureID, true)
}

func (r *salaryStructureRepository) getComponents(ctx context.Context, structureID uuid.UUID, ordered bool) ([]models.SalaryStructureComponent, error) {
	query := `
		SELECT
			mapping_id, salary_structure_id, component_code,
			calculation_type, value, based_on_component, sequence_order, created_at
		FROM payroll.salary_structure_component
		WHERE salary_structure_id = $1
	`
	if ordered {
		query += " ORDER BY sequence_order"
	}
	rows, err := r.client.Query(ctx, query, structureID)
	if err != nil {
		r.logger.Error("failed to get structure components",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get structure components: %w", err)
	}
	defer rows.Close()

	var components []models.SalaryStructureComponent
	for rows.Next() {
		var c models.SalaryStructureComponent
		if err := rows.Scan(
			&c.MappingID,
			&c.SalaryStructureID,
			&c.ComponentCode,
			&c.CalculationType,
			&c.Value,
			&c.BasedOnComponent,
			&c.SequenceOrder,
			&c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		components = append(components, c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return components, nil
}

func (r *salaryStructureRepository) ReplaceComponents(ctx context.Context, structureID uuid.UUID, comps []models.SalaryStructureComponent) error {
	// First, get the company ID of the structure.
	companyID, err := r.getStructureCompanyID(ctx, structureID)
	if err != nil {
		return fmt.Errorf("failed to resolve structure's company: %w", err)
	}

	// Validate all components before making any changes.
	for _, comp := range comps {
		exists, err := r.componentExistsForCompany(ctx, companyID, comp.ComponentCode)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("component %s is not active for company %s", comp.ComponentCode, companyID)
		}
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Delete existing components
	if _, err = tx.ExecContext(ctx, `DELETE FROM payroll.salary_structure_component WHERE salary_structure_id = $1`, structureID); err != nil {
		return fmt.Errorf("delete existing components: %w", err)
	}

	if len(comps) == 0 {
		return tx.Commit()
	}

	// Insert new components
	insertQuery := `
		INSERT INTO payroll.salary_structure_component (
			mapping_id, salary_structure_id, component_code,
			calculation_type, value, based_on_component, sequence_order, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	stmt, err := tx.PrepareContext(ctx, insertQuery)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, comp := range comps {
		if comp.MappingID == uuid.Nil {
			comp.MappingID = uuid.New()
		}
		if comp.CreatedAt.IsZero() {
			comp.CreatedAt = time.Now().UTC()
		}
		if _, err = stmt.ExecContext(ctx,
			comp.MappingID,
			structureID,
			comp.ComponentCode,
			comp.CalculationType,
			comp.Value,
			comp.BasedOnComponent,
			comp.SequenceOrder,
			comp.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert component %s: %w", comp.ComponentCode, err)
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------
// Assignment checks
// ---------------------------------------------------------------------

func (r *salaryStructureRepository) IsStructureInUse(ctx context.Context, structureID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM payroll.employee_salary WHERE salary_structure_id = $1)`
	var inUse bool
	err := r.client.QueryRow(ctx, query, structureID).Scan(&inUse)
	if err != nil {
		r.logger.Error("failed to check if structure is in use",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("check structure in use: %w", err)
	}
	return inUse, nil
}

func (r *salaryStructureRepository) HasOverlappingAssignment(ctx context.Context, companyID, userID uuid.UUID, effectiveFrom time.Time, excludeID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.employee_salary
			WHERE company_id = $1
			  AND user_id = $2
			  AND is_active = true
			  AND daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]')
			      && daterange($3::date, 'infinity', '[]')
	`
	args := []interface{}{companyID, userID, effectiveFrom}
	if excludeID != nil {
		query += " AND employee_salary_id != $" + fmt.Sprint(len(args)+1)
		args = append(args, *excludeID)
	}
	query += ")"
	var exists bool
	err := r.client.QueryRow(ctx, query, args...).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check overlapping assignment",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("check overlapping assignment: %w", err)
	}
	return exists, nil
}

// ---------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------

func (r *salaryStructureRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM payroll.salary_structure LIMIT 1`
	var one int
	err := r.client.QueryRow(ctx, query).Scan(&one)
	if err != nil {
		r.logger.Error("salary structure repository health check failed", util.ErrorField(err))
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}
