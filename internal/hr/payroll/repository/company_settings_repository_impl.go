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

// GetPayrollSettings returns the company's payroll settings.
//
// DB stores the *_component_id columns; the *_component_code fields on the
// returned struct are JOIN-populated so callers can keep using codes.
func (r *companySettingsRepository) GetPayrollSettings(ctx context.Context, companyID uuid.UUID) (*models.CompanyPayrollSettings, error) {
	query := `
		SELECT
			s.company_id,
			s.default_fine_component_id,
			pc_fine.component_code AS default_fine_component,
			s.default_arrears_component_id,
			pc_arrears.component_code AS default_arrears_component,
			s.default_loan_component_id,
			pc_loan.component_code AS default_loan_component,
			s.default_basic_component_id,
			pc_basic.component_code AS default_basic_component,
			s.created_at,
			s.updated_at
		FROM payroll.company_payroll_settings s
		LEFT JOIN payroll.payroll_component pc_fine
		    ON pc_fine.component_id = s.default_fine_component_id
		LEFT JOIN payroll.payroll_component pc_arrears
		    ON pc_arrears.component_id = s.default_arrears_component_id
		LEFT JOIN payroll.payroll_component pc_loan
		    ON pc_loan.component_id = s.default_loan_component_id
		LEFT JOIN payroll.payroll_component pc_basic
		    ON pc_basic.component_id = s.default_basic_component_id
		WHERE s.company_id = $1
	`
	row := r.client.QueryRow(ctx, query, companyID)

	var settings models.CompanyPayrollSettings
	var fineID, arrearsID, loanID, basicID uuid.NullUUID
	var fineCode, arrearsCode, loanCode, basicCode sql.NullString

	err := row.Scan(
		&settings.CompanyID,
		&fineID,
		&fineCode,
		&arrearsID,
		&arrearsCode,
		&loanID,
		&loanCode,
		&basicID,
		&basicCode,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrPayrollSettingsNotFound
		}
		return nil, fmt.Errorf("failed to get payroll settings: %w", err)
	}

	if fineID.Valid {
		id := fineID.UUID
		settings.DefaultFineComponentID = &id
	}
	if fineCode.Valid {
		code := fineCode.String
		settings.DefaultFineComponentCode = &code
	}
	if arrearsID.Valid {
		id := arrearsID.UUID
		settings.DefaultArrearsComponentID = &id
	}
	if arrearsCode.Valid {
		code := arrearsCode.String
		settings.DefaultArrearsComponentCode = &code
	}
	if loanID.Valid {
		id := loanID.UUID
		settings.DefaultLoanComponentID = &id
	}
	if loanCode.Valid {
		code := loanCode.String
		settings.DefaultLoanComponentCode = &code
	}
	if basicID.Valid {
		id := basicID.UUID
		settings.DefaultBasicComponentID = &id
	}
	if basicCode.Valid {
		code := basicCode.String
		settings.DefaultBasicComponentCode = &code
	}

	return &settings, nil
}

// UpsertPayrollSettings inserts or updates payroll settings.
//
// Writes the *_component_id columns. Callers must populate the ID fields
// (typically by resolving the code via the component repository). The
// *_code fields on the struct are display-only and are ignored here.
func (r *companySettingsRepository) UpsertPayrollSettings(ctx context.Context, settings *models.CompanyPayrollSettings) error {
	query := `
		INSERT INTO payroll.company_payroll_settings (
			company_id,
			default_fine_component_id,
			default_arrears_component_id,
			default_loan_component_id,
			default_basic_component_id,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (company_id) DO UPDATE SET
			default_fine_component_id    = EXCLUDED.default_fine_component_id,
			default_arrears_component_id = EXCLUDED.default_arrears_component_id,
			default_loan_component_id    = EXCLUDED.default_loan_component_id,
			default_basic_component_id   = EXCLUDED.default_basic_component_id,
			updated_at = NOW()
	`
	_, err := r.client.Exec(ctx, query,
		settings.CompanyID,
		nullUUID(settings.DefaultFineComponentID),
		nullUUID(settings.DefaultArrearsComponentID),
		nullUUID(settings.DefaultLoanComponentID),
		nullUUID(settings.DefaultBasicComponentID),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert payroll settings: %w", err)
	}
	return nil
}
