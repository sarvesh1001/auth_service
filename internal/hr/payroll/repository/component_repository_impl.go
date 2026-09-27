package repository

import (
	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/payroll/models"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type componentRepository struct {
	client *client.PostgresClient
}

func NewComponentRepository(
	postgresClient *client.PostgresClient,
) ComponentRepository {
	return &componentRepository{
		client: postgresClient,
	}
}

// ============================================================================
// QUERY METHODS
// ============================================================================

func (r *componentRepository) GetComponentsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) (map[string]*models.PayrollComponent, error) {

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
		  AND is_active = true
		ORDER BY component_code
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components by company: %w", err)
	}
	defer rows.Close()

	components := make(map[string]*models.PayrollComponent)

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
			return nil, fmt.Errorf("failed to scan component row: %w", err)
		}
		components[comp.ComponentCode] = &comp
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return components, nil
}

func (r *componentRepository) GetComponent(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
) (*models.PayrollComponent, error) {

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

func (r *componentRepository) GetComponentsByCodes(
	ctx context.Context,
	companyID uuid.UUID,
	codes []string,
) ([]*models.PayrollComponent, error) {

	if len(codes) == 0 {
		return []*models.PayrollComponent{}, nil
	}

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
		ORDER BY component_code
	`

	rows, err := r.client.Query(ctx, query, companyID, pq.Array(codes))
	if err != nil {
		return nil, fmt.Errorf("failed to get components by codes: %w", err)
	}
	defer rows.Close()

	var components []*models.PayrollComponent
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
			return nil, fmt.Errorf("failed to scan component row: %w", err)
		}
		components = append(components, &comp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return components, nil
}
