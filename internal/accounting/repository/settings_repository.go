package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/accounting/models/settings"
	"auth-service/internal/util"
)

// AccountingSettingsRepository defines the interface for company accounting settings.
type AccountingSettingsRepository interface {
	// Core singleton operations per company
	Create(ctx context.Context, db DBTX, s *settings.AccountingSettings) error
	Upsert(ctx context.Context, db DBTX, s *settings.AccountingSettings) error
	UpsertForUpdate(ctx context.Context, db DBTX, s *settings.AccountingSettings) error
	GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) (*settings.AccountingSettings, error)
	GetByCompanyForUpdate(ctx context.Context, db DBTX, companyID uuid.UUID) (*settings.AccountingSettings, error)
	Update(ctx context.Context, db DBTX, s *settings.AccountingSettings) error

	// Partial updates (safe, race-free)
	UpdateFiscalYear(ctx context.Context, db DBTX, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID) error
	UpdateCurrency(ctx context.Context, db DBTX, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID) error
	UpdateTaxScheme(ctx context.Context, db DBTX, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID) error
	UpdateFlags(ctx context.Context, db DBTX, companyID uuid.UUID, allowIntercompany, autoReversal bool, updatedBy *uuid.UUID) error

	// Validation & utility
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID) (bool, error)
	GetFiscalStartMonth(ctx context.Context, db DBTX, companyID uuid.UUID) (int, error)

	// Fiscal computation – uses DB function compute_fiscal_fields
	GetFiscalYear(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (fiscalYear int, period int, err error)
}

// accountingSettingsRepository implements AccountingSettingsRepository.
type accountingSettingsRepository struct {
	logger *zap.Logger
}

// NewAccountingSettingsRepository creates a new repository instance.
func NewAccountingSettingsRepository(logger *zap.Logger) AccountingSettingsRepository {
	return &accountingSettingsRepository{
		logger: logger.Named("accounting_settings_repo"),
	}
}

// Create inserts new accounting settings for a company.
func (r *accountingSettingsRepository) Create(ctx context.Context, db DBTX, s *settings.AccountingSettings) error {
	// Normalize currency code
	s.CurrencyCode = strings.ToUpper(s.CurrencyCode)

	query := `
		INSERT INTO accounting.accounting_settings (
			company_id, fiscal_year_start_month, currency_code, tax_scheme,
			allow_intercompany_journal, auto_generate_reversals,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		s.CompanyID, s.FiscalYearStartMonth, s.CurrencyCode, s.TaxScheme,
		s.AllowIntercompanyJournal, s.AutoGenerateReversals,
		s.CreatedBy, s.UpdatedBy,
	).Scan(&s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create accounting settings",
			util.String("company_id", s.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create accounting settings: %w", err)
	}
	return nil
}

// Upsert creates or replaces settings for a company (safe for onboarding).
func (r *accountingSettingsRepository) Upsert(ctx context.Context, db DBTX, s *settings.AccountingSettings) error {
	// Normalize currency code
	s.CurrencyCode = strings.ToUpper(s.CurrencyCode)

	query := `
		INSERT INTO accounting.accounting_settings (
			company_id, fiscal_year_start_month, currency_code, tax_scheme,
			allow_intercompany_journal, auto_generate_reversals,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8)
		ON CONFLICT (company_id)
		DO UPDATE SET
			fiscal_year_start_month = EXCLUDED.fiscal_year_start_month,
			currency_code = EXCLUDED.currency_code,
			tax_scheme = EXCLUDED.tax_scheme,
			allow_intercompany_journal = EXCLUDED.allow_intercompany_journal,
			auto_generate_reversals = EXCLUDED.auto_generate_reversals,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		s.CompanyID, s.FiscalYearStartMonth, s.CurrencyCode, s.TaxScheme,
		s.AllowIntercompanyJournal, s.AutoGenerateReversals,
		s.CreatedBy, s.UpdatedBy,
	).Scan(&s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert accounting settings",
			util.String("company_id", s.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert accounting settings: %w", err)
	}
	return nil
}

// UpsertForUpdate locks the row (if exists) before upserting to avoid concurrency issues during onboarding.
func (r *accountingSettingsRepository) UpsertForUpdate(ctx context.Context, db DBTX, s *settings.AccountingSettings) error {
	// Lock existing row if any
	_, err := db.ExecContext(ctx, `
		SELECT 1 FROM accounting.accounting_settings
		WHERE company_id = $1
		FOR UPDATE
	`, s.CompanyID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("acquire lock for upsert: %w", err)
	}
	return r.Upsert(ctx, db, s)
}

// GetByCompany retrieves settings for a company. Returns ErrNotFound if not found.
func (r *accountingSettingsRepository) GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) (*settings.AccountingSettings, error) {
	query := `
		SELECT company_id, fiscal_year_start_month, currency_code, tax_scheme,
		       allow_intercompany_journal, auto_generate_reversals,
		       created_at, updated_at, created_by, updated_by
		FROM accounting.accounting_settings
		WHERE company_id = $1
	`
	var s settings.AccountingSettings
	var createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, companyID).Scan(
		&s.CompanyID, &s.FiscalYearStartMonth, &s.CurrencyCode, &s.TaxScheme,
		&s.AllowIntercompanyJournal, &s.AutoGenerateReversals,
		&s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get accounting settings",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get accounting settings: %w", err)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// GetByCompanyForUpdate retrieves settings with row-level lock for update. Returns ErrNotFound if not found.
func (r *accountingSettingsRepository) GetByCompanyForUpdate(ctx context.Context, db DBTX, companyID uuid.UUID) (*settings.AccountingSettings, error) {
	query := `
		SELECT company_id, fiscal_year_start_month, currency_code, tax_scheme,
		       allow_intercompany_journal, auto_generate_reversals,
		       created_at, updated_at, created_by, updated_by
		FROM accounting.accounting_settings
		WHERE company_id = $1
		FOR UPDATE
	`
	var s settings.AccountingSettings
	var createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, companyID).Scan(
		&s.CompanyID, &s.FiscalYearStartMonth, &s.CurrencyCode, &s.TaxScheme,
		&s.AllowIntercompanyJournal, &s.AutoGenerateReversals,
		&s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get accounting settings for update",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get accounting settings for update: %w", err)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// Update performs a full update of settings (use partial updates when possible).
func (r *accountingSettingsRepository) Update(ctx context.Context, db DBTX, s *settings.AccountingSettings) error {
	// Normalize currency code
	s.CurrencyCode = strings.ToUpper(s.CurrencyCode)

	query := `
		UPDATE accounting.accounting_settings
		SET fiscal_year_start_month = $2,
		    currency_code = $3,
		    tax_scheme = $4,
		    allow_intercompany_journal = $5,
		    auto_generate_reversals = $6,
		    updated_by = $7,
		    updated_at = NOW()
		WHERE company_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		s.CompanyID, s.FiscalYearStartMonth, s.CurrencyCode, s.TaxScheme,
		s.AllowIntercompanyJournal, s.AutoGenerateReversals,
		s.UpdatedBy,
	).Scan(&s.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		r.logger.Error("failed to update accounting settings",
			util.String("company_id", s.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update accounting settings: %w", err)
	}
	return nil
}

// UpdateFiscalYear changes only the fiscal year start month.
func (r *accountingSettingsRepository) UpdateFiscalYear(ctx context.Context, db DBTX, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID) error {
	if startMonth < 1 || startMonth > 12 {
		return fmt.Errorf("fiscal year start month must be between 1 and 12, got %d", startMonth)
	}
	query := `
		UPDATE accounting.accounting_settings
		SET fiscal_year_start_month = $2, updated_by = $3, updated_at = NOW()
		WHERE company_id = $1
	`
	result, err := db.ExecContext(ctx, query, companyID, startMonth, updatedBy)
	if err != nil {
		r.logger.Error("failed to update fiscal year",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update fiscal year: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateCurrency changes the functional currency (ISO code).
func (r *accountingSettingsRepository) UpdateCurrency(ctx context.Context, db DBTX, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID) error {
	currencyCode = strings.ToUpper(currencyCode)
	if len(currencyCode) != 3 {
		return fmt.Errorf("currency code must be ISO 4217 (3 letters), got %s", currencyCode)
	}
	query := `
		UPDATE accounting.accounting_settings
		SET currency_code = $2, updated_by = $3, updated_at = NOW()
		WHERE company_id = $1
	`
	result, err := db.ExecContext(ctx, query, companyID, currencyCode, updatedBy)
	if err != nil {
		r.logger.Error("failed to update currency",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update currency: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTaxScheme changes the tax scheme (accrual or cash). Uses enums.
func (r *accountingSettingsRepository) UpdateTaxScheme(ctx context.Context, db DBTX, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID) error {
	if taxScheme != enums.TaxSchemeAccrual && taxScheme != enums.TaxSchemeCash {
		return fmt.Errorf("tax scheme must be '%s' or '%s', got %s", enums.TaxSchemeAccrual, enums.TaxSchemeCash, taxScheme)
	}
	query := `
		UPDATE accounting.accounting_settings
		SET tax_scheme = $2, updated_by = $3, updated_at = NOW()
		WHERE company_id = $1
	`
	result, err := db.ExecContext(ctx, query, companyID, taxScheme, updatedBy)
	if err != nil {
		r.logger.Error("failed to update tax scheme",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update tax scheme: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateFlags changes the boolean flags (intercompany journals and auto reversals).
func (r *accountingSettingsRepository) UpdateFlags(ctx context.Context, db DBTX, companyID uuid.UUID, allowIntercompany, autoReversal bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.accounting_settings
		SET allow_intercompany_journal = $2,
		    auto_generate_reversals = $3,
		    updated_by = $4,
		    updated_at = NOW()
		WHERE company_id = $1
	`
	result, err := db.ExecContext(ctx, query, companyID, allowIntercompany, autoReversal, updatedBy)
	if err != nil {
		r.logger.Error("failed to update settings flags",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update flags: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Exists checks if settings exist for a given company.
func (r *accountingSettingsRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM accounting.accounting_settings WHERE company_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists accounting settings: %w", err)
	}
	return exists, nil
}

// GetFiscalStartMonth returns only the fiscal_year_start_month for a company.
func (r *accountingSettingsRepository) GetFiscalStartMonth(ctx context.Context, db DBTX, companyID uuid.UUID) (int, error) {
	query := `SELECT fiscal_year_start_month FROM accounting.accounting_settings WHERE company_id = $1`
	var startMonth int
	err := db.QueryRowContext(ctx, query, companyID).Scan(&startMonth)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		r.logger.Error("failed to get fiscal start month",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("get fiscal start month: %w", err)
	}
	return startMonth, nil
}

// GetFiscalYear computes fiscal year and period using the database function accounting.compute_fiscal_fields.
// This ensures consistency with ledger entry triggers.
func (r *accountingSettingsRepository) GetFiscalYear(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (fiscalYear int, period int, err error) {
	query := `
		SELECT fy.fiscal_year, fy.period
		FROM accounting.accounting_settings s,
		     LATERAL accounting.compute_fiscal_fields($2::date, s.fiscal_year_start_month) fy
		WHERE s.company_id = $1
	`
	err = db.QueryRowContext(ctx, query, companyID, date).Scan(&fiscalYear, &period)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		r.logger.Error("failed to compute fiscal year via DB function",
			util.String("company_id", companyID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("compute fiscal year: %w", err)
	}
	return fiscalYear, period, nil
}
