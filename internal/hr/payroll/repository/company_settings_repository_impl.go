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
	"go.uber.org/zap"
)

type companySettingsRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewCompanySettingsRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) CompanySettingsRepository {
	return &companySettingsRepository{
		client: postgresClient,
		logger: logger.Named("company_settings_repo"),
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
			return nil, nil
		}
		r.logger.Error("failed to get payroll settings",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
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
		settings.CompanyID,
		nullString(settings.DefaultFineComponent),
		nullString(settings.DefaultArrearsComponent),
		nullString(settings.DefaultLoanComponent),
		nullString(settings.DefaultBasicComponent),
	)
	if err != nil {
		r.logger.Error("failed to upsert payroll settings",
			util.String("company_id", settings.CompanyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert payroll settings: %w", err)
	}
	return nil
}
