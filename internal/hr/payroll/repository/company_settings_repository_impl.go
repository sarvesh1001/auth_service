package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/payroll/models"
)

type companySettingsRepository struct {
	client *client.PostgresClient
}

func NewCompanySettingsRepository(
	postgresClient *client.PostgresClient,
) CompanySettingsRepository {
	return &companySettingsRepository{
		client: postgresClient,
	}
}

func (r *companySettingsRepository) GetPayrollSettings(ctx context.Context, companyID uuid.UUID) (*models.CompanyPayrollSettings, error) {
	query := `
		SELECT
			company_id,
			default_fine_component,
			default_arrears_component,
			default_loan_component,
			default_basic_component,
			created_at,
			updated_at
		FROM payroll.company_payroll_settings
		WHERE company_id = $1
	`
	row := r.client.QueryRow(ctx, query, companyID)

	var settings models.CompanyPayrollSettings
	err := row.Scan(
		&settings.CompanyID,
		&settings.DefaultFineComponent,
		&settings.DefaultArrearsComponent,
		&settings.DefaultLoanComponent,
		&settings.DefaultBasicComponent,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Use sentinel error instead of nil,nil
			return nil, hrErrors.ErrPayrollSettingsNotFound
		}
		return nil, fmt.Errorf("failed to get payroll settings: %w", err)
	}
	return &settings, nil
}

func (r *companySettingsRepository) UpsertPayrollSettings(ctx context.Context, settings *models.CompanyPayrollSettings) error {
	query := `
		INSERT INTO payroll.company_payroll_settings (
			company_id,
			default_fine_component,
			default_arrears_component,
			default_loan_component,
			default_basic_component,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (company_id) DO UPDATE SET
			default_fine_component = EXCLUDED.default_fine_component,
			default_arrears_component = EXCLUDED.default_arrears_component,
			default_loan_component = EXCLUDED.default_loan_component,
			default_basic_component = EXCLUDED.default_basic_component,
			updated_at = NOW()
	`
	_, err := r.client.Exec(ctx, query,
		nullString(settings.DefaultFineComponent),
		nullString(settings.DefaultArrearsComponent),
		nullString(settings.DefaultLoanComponent),
		nullString(settings.DefaultBasicComponent),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert payroll settings: %w", err)
	}
	return nil
}
