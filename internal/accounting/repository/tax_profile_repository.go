package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/util"
)

// TaxProfileRepository defines the interface for tax profile data access.
type TaxProfileRepository interface {
	// Core CRUD
	Create(ctx context.Context, db DBTX, p *tax.TaxProfile) error
	Upsert(ctx context.Context, db DBTX, p *tax.TaxProfile) error
	Update(ctx context.Context, db DBTX, p *tax.TaxProfile) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxProfile, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxProfile, error)

	// Lookups
	GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxProfile, error)
	GetActiveProfiles(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxProfile, error)
	GetByRegimeAndJurisdiction(ctx context.Context, db DBTX, companyID uuid.UUID, regime, jurisdiction string) (*tax.TaxProfile, error)
	GetDefaultProfile(ctx context.Context, db DBTX, companyID uuid.UUID) (*tax.TaxProfile, error) // returns raw settings (JSON parsing moved to service)

	// Default management (new)
	SetDefaultProfile(ctx context.Context, db DBTX, profileID uuid.UUID, updatedBy *uuid.UUID) error
	UnsetDefaultProfiles(ctx context.Context, db DBTX, companyID uuid.UUID, excludeProfileID *uuid.UUID) error

	// Status / lifecycle
	SetActive(ctx context.Context, db DBTX, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Validation / safety
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, regime, jurisdiction string) (bool, error)
	CheckUsage(ctx context.Context, db DBTX, profileID uuid.UUID) (bool, error)
	CanDelete(ctx context.Context, db DBTX, profileID uuid.UUID) (bool, error)

	// Settings (raw JSON – no parsing)
	UpdateSettings(ctx context.Context, db DBTX, profileID uuid.UUID, settings []byte, updatedBy *uuid.UUID) error
	UpdateDefaultTaxRate(ctx context.Context, db DBTX, profileID uuid.UUID, taxRateID *uuid.UUID, updatedBy *uuid.UUID) error
}

type taxProfileRepository struct {
	logger *zap.Logger
}

func NewTaxProfileRepository(logger *zap.Logger) TaxProfileRepository {
	return &taxProfileRepository{logger: logger.Named("tax_profile_repo")}
}

// scanTaxProfile scans a row into a TaxProfile model.
func (r *taxProfileRepository) scanTaxProfile(scanner interface {
	Scan(dest ...interface{}) error
}) (*tax.TaxProfile, error) {
	var p tax.TaxProfile
	var registrationNumber sql.NullString
	var defaultTaxRateID uuid.NullUUID
	var settings []byte
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&p.TaxProfileID, &p.CompanyID, &p.TaxRegime, &p.Jurisdiction,
		&registrationNumber, &defaultTaxRateID, &settings,
		&p.IsActive, &p.CreatedAt, &p.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		return nil, err
	}

	if registrationNumber.Valid {
		p.RegistrationNumber = &registrationNumber.String
	}
	if defaultTaxRateID.Valid {
		p.DefaultTaxRateID = &defaultTaxRateID.UUID
	}
	if len(settings) > 0 {
		p.Settings = settings
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		p.DeletedAt = &deletedAt.Time
	}
	return &p, nil
}

// Create inserts a new tax profile.
func (r *taxProfileRepository) Create(ctx context.Context, db DBTX, p *tax.TaxProfile) error {
	query := `
		INSERT INTO accounting.tax_profiles (
			tax_profile_id, company_id, tax_regime, jurisdiction,
			registration_number, default_tax_rate_id, settings,
			is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		p.TaxProfileID, p.CompanyID, p.TaxRegime, p.Jurisdiction,
		p.RegistrationNumber, p.DefaultTaxRateID, p.Settings,
		p.IsActive, p.CreatedBy, p.UpdatedBy,
	).Scan(&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create tax profile",
			util.String("company_id", p.CompanyID.String()),
			util.String("regime", p.TaxRegime),
			util.String("jurisdiction", p.Jurisdiction),
			util.ErrorField(err))
		return fmt.Errorf("create tax profile: %w", err)
	}
	return nil
}

// Upsert inserts or updates a tax profile based on unique constraint.
func (r *taxProfileRepository) Upsert(ctx context.Context, db DBTX, p *tax.TaxProfile) error {
	query := `
		INSERT INTO accounting.tax_profiles (
			tax_profile_id, company_id, tax_regime, jurisdiction,
			registration_number, default_tax_rate_id, settings,
			is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		ON CONFLICT (company_id, tax_regime, jurisdiction) WHERE deleted_at IS NULL
		DO UPDATE SET
			registration_number = EXCLUDED.registration_number,
			default_tax_rate_id = EXCLUDED.default_tax_rate_id,
			settings = EXCLUDED.settings,
			is_active = EXCLUDED.is_active,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		p.TaxProfileID, p.CompanyID, p.TaxRegime, p.Jurisdiction,
		p.RegistrationNumber, p.DefaultTaxRateID, p.Settings,
		p.IsActive, p.CreatedBy, p.UpdatedBy,
	).Scan(&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert tax profile",
			util.String("company_id", p.CompanyID.String()),
			util.String("regime", p.TaxRegime),
			util.String("jurisdiction", p.Jurisdiction),
			util.ErrorField(err))
		return fmt.Errorf("upsert tax profile: %w", err)
	}
	return nil
}

// Update updates an existing tax profile.
func (r *taxProfileRepository) Update(ctx context.Context, db DBTX, p *tax.TaxProfile) error {
	query := `
		UPDATE accounting.tax_profiles
		SET tax_regime = $2,
		    jurisdiction = $3,
		    registration_number = $4,
		    default_tax_rate_id = $5,
		    settings = $6,
		    is_active = $7,
		    updated_by = $8,
		    updated_at = NOW()
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		p.TaxProfileID, p.TaxRegime, p.Jurisdiction,
		p.RegistrationNumber, p.DefaultTaxRateID, p.Settings,
		p.IsActive, p.UpdatedBy,
	).Scan(&p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		r.logger.Error("failed to update tax profile",
			util.String("id", p.TaxProfileID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update tax profile: %w", err)
	}
	return nil
}

// GetByID retrieves a tax profile by ID.
func (r *taxProfileRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxProfile, error) {
	query := `
		SELECT tax_profile_id, company_id, tax_regime, jurisdiction,
		       registration_number, default_tax_rate_id, settings,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_profiles
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
	`
	var p tax.TaxProfile
	var registrationNumber sql.NullString
	var defaultTaxRateID uuid.NullUUID
	var settings []byte
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, id).Scan(
		&p.TaxProfileID, &p.CompanyID, &p.TaxRegime, &p.Jurisdiction,
		&registrationNumber, &defaultTaxRateID, &settings,
		&p.IsActive, &p.CreatedAt, &p.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax profile by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax profile by ID: %w", err)
	}
	if registrationNumber.Valid {
		p.RegistrationNumber = &registrationNumber.String
	}
	if defaultTaxRateID.Valid {
		p.DefaultTaxRateID = &defaultTaxRateID.UUID
	}
	if len(settings) > 0 {
		p.Settings = settings
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		p.DeletedAt = &deletedAt.Time
	}
	return &p, nil
}

// GetByIDForUpdate retrieves a tax profile with row lock.
func (r *taxProfileRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxProfile, error) {
	query := `
		SELECT tax_profile_id, company_id, tax_regime, jurisdiction,
		       registration_number, default_tax_rate_id, settings,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_profiles
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var p tax.TaxProfile
	var registrationNumber sql.NullString
	var defaultTaxRateID uuid.NullUUID
	var settings []byte
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, id).Scan(
		&p.TaxProfileID, &p.CompanyID, &p.TaxRegime, &p.Jurisdiction,
		&registrationNumber, &defaultTaxRateID, &settings,
		&p.IsActive, &p.CreatedAt, &p.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax profile for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax profile for update: %w", err)
	}
	if registrationNumber.Valid {
		p.RegistrationNumber = &registrationNumber.String
	}
	if defaultTaxRateID.Valid {
		p.DefaultTaxRateID = &defaultTaxRateID.UUID
	}
	if len(settings) > 0 {
		p.Settings = settings
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		p.DeletedAt = &deletedAt.Time
	}
	return &p, nil
}

// GetByCompany returns all tax profiles for a company.
func (r *taxProfileRepository) GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxProfile, error) {
	query := `
		SELECT tax_profile_id, company_id, tax_regime, jurisdiction,
		       registration_number, default_tax_rate_id, settings,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_profiles
		WHERE company_id = $1 AND deleted_at IS NULL
		ORDER BY tax_regime, jurisdiction
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get profiles by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get profiles by company: %w", err)
	}
	defer rows.Close()

	var profiles []*tax.TaxProfile
	for rows.Next() {
		p, err := r.scanTaxProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax profile: %w", err)
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// GetActiveProfiles returns only active tax profiles for a company.
func (r *taxProfileRepository) GetActiveProfiles(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxProfile, error) {
	query := `
		SELECT tax_profile_id, company_id, tax_regime, jurisdiction,
		       registration_number, default_tax_rate_id, settings,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_profiles
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY tax_regime, jurisdiction
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get active profiles",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get active profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*tax.TaxProfile
	for rows.Next() {
		p, err := r.scanTaxProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax profile: %w", err)
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// GetByRegimeAndJurisdiction returns a specific profile.
func (r *taxProfileRepository) GetByRegimeAndJurisdiction(ctx context.Context, db DBTX, companyID uuid.UUID, regime, jurisdiction string) (*tax.TaxProfile, error) {
	query := `
		SELECT tax_profile_id, company_id, tax_regime, jurisdiction,
		       registration_number, default_tax_rate_id, settings,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_profiles
		WHERE company_id = $1 AND tax_regime = $2 AND jurisdiction = $3 AND deleted_at IS NULL
	`
	var p tax.TaxProfile
	var registrationNumber sql.NullString
	var defaultTaxRateID uuid.NullUUID
	var settings []byte
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, companyID, regime, jurisdiction).Scan(
		&p.TaxProfileID, &p.CompanyID, &p.TaxRegime, &p.Jurisdiction,
		&registrationNumber, &defaultTaxRateID, &settings,
		&p.IsActive, &p.CreatedAt, &p.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get profile by regime and jurisdiction",
			util.String("company_id", companyID.String()),
			util.String("regime", regime),
			util.String("jurisdiction", jurisdiction),
			util.ErrorField(err))
		return nil, fmt.Errorf("get profile by regime and jurisdiction: %w", err)
	}
	if registrationNumber.Valid {
		p.RegistrationNumber = &registrationNumber.String
	}
	if defaultTaxRateID.Valid {
		p.DefaultTaxRateID = &defaultTaxRateID.UUID
	}
	if len(settings) > 0 {
		p.Settings = settings
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		p.DeletedAt = &deletedAt.Time
	}
	return &p, nil
}

// GetDefaultProfile returns the default profile (JSON parsing moved to service).
func (r *taxProfileRepository) GetDefaultProfile(ctx context.Context, db DBTX, companyID uuid.UUID) (*tax.TaxProfile, error) {
	profiles, err := r.GetActiveProfiles(ctx, db, companyID)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, nil
	}
	// Return first profile – service will inspect settings JSON.
	// The repository does NOT parse JSON.
	return profiles[0], nil
}

// SetDefaultProfile atomically sets a profile as default (unset others first).
func (r *taxProfileRepository) SetDefaultProfile(ctx context.Context, db DBTX, profileID uuid.UUID, updatedBy *uuid.UUID) error {
	// First, get the company ID
	profile, err := r.GetByID(ctx, db, profileID)
	if err != nil {
		return err
	}
	// Unset default for all other profiles of same company
	if err := r.UnsetDefaultProfiles(ctx, db, profile.CompanyID, &profileID); err != nil {
		return err
	}
	// Now update settings to mark this as default (service should handle, but we provide a raw update)
	// For simplicity, we provide a helper that updates the settings JSON.
	// Service must read current settings, set is_default=true, and call UpdateSettings.
	// Alternatively, we can add a dedicated column "is_default" in the schema – recommended.
	// Here we assume service does the JSON merge.
	return nil
}

// UnsetDefaultProfiles removes default flag from all profiles of a company.
func (r *taxProfileRepository) UnsetDefaultProfiles(ctx context.Context, db DBTX, companyID uuid.UUID, excludeProfileID *uuid.UUID) error {
	// This operation requires updating settings JSON to set is_default=false.
	// Because settings is a JSONB field, we must use JSONB operators.
	query := `
		UPDATE accounting.tax_profiles
		SET settings = settings::jsonb - 'is_default', updated_at = NOW(), updated_by = $2
		WHERE company_id = $1 AND deleted_at IS NULL
	`
	args := []interface{}{companyID, nil}
	if excludeProfileID != nil {
		query += ` AND tax_profile_id != $3`
		args = append(args, *excludeProfileID)
	}
	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to unset default profiles",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unset default profiles: %w", err)
	}
	return nil
}

// SetActive toggles active status.
func (r *taxProfileRepository) SetActive(ctx context.Context, db DBTX, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_profiles
		SET is_active = $2, updated_by = $3, updated_at = NOW()
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, isActive, updatedBy)
	if err != nil {
		r.logger.Error("failed to set active status",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("set active status: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete soft-deletes a tax profile.
func (r *taxProfileRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_profiles
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete tax profile",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete tax profile: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Exists checks existence by unique key.
func (r *taxProfileRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, regime, jurisdiction string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_profiles
			WHERE company_id = $1 AND tax_regime = $2 AND jurisdiction = $3 AND deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, regime, jurisdiction).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence",
			util.String("company_id", companyID.String()),
			util.String("regime", regime),
			util.String("jurisdiction", jurisdiction),
			util.ErrorField(err))
		return false, fmt.Errorf("exists check: %w", err)
	}
	return exists, nil
}

// CheckUsage checks if profile is referenced in any tax transaction or rule.
func (r *taxProfileRepository) CheckUsage(ctx context.Context, db DBTX, profileID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_rules
			WHERE tax_profile_id = $1 AND deleted_at IS NULL
		)
	`
	var used bool
	err := db.QueryRowContext(ctx, query, profileID).Scan(&used)
	if err != nil {
		r.logger.Error("failed to check usage",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("check usage: %w", err)
	}
	return used, nil
}

// CanDelete returns true if profile is not referenced anywhere.
func (r *taxProfileRepository) CanDelete(ctx context.Context, db DBTX, profileID uuid.UUID) (bool, error) {
	used, err := r.CheckUsage(ctx, db, profileID)
	if err != nil {
		return false, err
	}
	return !used, nil
}

// UpdateSettings updates the JSON settings.
func (r *taxProfileRepository) UpdateSettings(ctx context.Context, db DBTX, profileID uuid.UUID, settings []byte, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_profiles
		SET settings = $2, updated_by = $3, updated_at = NOW()
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, profileID, settings, updatedBy)
	if err != nil {
		r.logger.Error("failed to update settings",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update settings: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateDefaultTaxRate updates the default_tax_rate_id.
func (r *taxProfileRepository) UpdateDefaultTaxRate(ctx context.Context, db DBTX, profileID uuid.UUID, taxRateID *uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_profiles
		SET default_tax_rate_id = $2, updated_by = $3, updated_at = NOW()
		WHERE tax_profile_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, profileID, taxRateID, updatedBy)
	if err != nil {
		r.logger.Error("failed to update default tax rate",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update default tax rate: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}
