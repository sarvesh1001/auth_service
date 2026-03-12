package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type componentRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewComponentRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) ComponentRepository {
	return &componentRepository{
		client: postgresClient,
		logger: logger.Named("component_repo"),
	}
}

func (r *componentRepository) GetComponentsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) (map[string]*models.PayrollComponent, error) {

	query := `
		SELECT
			company_id,
			component_code,
			component_type,
			description,
			is_taxable,
			is_system,
			is_active,
			contribution_side
		FROM payroll.payroll_component
		WHERE (company_id = $1 OR company_id IS NULL)
		  AND is_active = true
		ORDER BY company_id DESC
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to query components by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get components: %w", err)
	}
	defer rows.Close()

	components := make(map[string]*models.PayrollComponent)

	for rows.Next() {
		var comp models.PayrollComponent

		if err := rows.Scan(
			&comp.CompanyID,
			&comp.ComponentCode,
			&comp.ComponentType,
			&comp.Description,
			&comp.IsTaxable,
			&comp.IsSystem,
			&comp.IsActive,
			&comp.ContributionSide,
		); err != nil {
			r.logger.Error("failed to scan component row",
				util.ErrorField(err),
			)
			return nil, fmt.Errorf("failed to scan component: %w", err)
		}

		// Company overrides should win
		if _, exists := components[comp.ComponentCode]; !exists {
			components[comp.ComponentCode] = &comp
		}
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
			company_id,
			component_code,
			component_type,
			description,
			is_taxable,
			is_system,
			is_active,
			contribution_side
		FROM payroll.payroll_component
		WHERE component_code = $2
		  AND is_active = true
		  AND (company_id = $1 OR company_id IS NULL)
		ORDER BY company_id DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, code)

	var comp models.PayrollComponent

	err := row.Scan(
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
			return nil, nil
		}

		r.logger.Error("failed to get component",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err),
		)

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
			company_id,
			component_code,
			component_type,
			description,
			is_taxable,
			is_system,
			is_active,
			contribution_side
		FROM payroll.payroll_component
		WHERE (company_id = $1 OR company_id IS NULL)
		  AND component_code = ANY($2)
		  AND is_active = true
		ORDER BY company_id DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, pq.Array(codes))
	if err != nil {
		r.logger.Error("failed to query components by codes",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get components by codes: %w", err)
	}
	defer rows.Close()

	componentMap := map[string]*models.PayrollComponent{}

	for rows.Next() {
		var comp models.PayrollComponent

		if err := rows.Scan(
			&comp.CompanyID,
			&comp.ComponentCode,
			&comp.ComponentType,
			&comp.Description,
			&comp.IsTaxable,
			&comp.IsSystem,
			&comp.IsActive,
			&comp.ContributionSide,
		); err != nil {
			r.logger.Error("failed to scan component row",
				util.ErrorField(err),
			)
			return nil, fmt.Errorf("failed to scan component: %w", err)
		}

		// ensure company override wins
		if _, exists := componentMap[comp.ComponentCode]; !exists {
			componentMap[comp.ComponentCode] = &comp
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	var components []*models.PayrollComponent
	for _, comp := range componentMap {
		components = append(components, comp)
	}

	return components, nil
}
