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

	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/util"
)

// TaxRateFilter defines filter criteria for listing tax rates
type TaxRateFilter struct {
	CompanyID uuid.UUID
	TaxName   string
	IsActive  *bool
	FromDate  *time.Time
	ToDate    *time.Time
	Search    string
}

// TaxRateRepository defines the interface for tax rate data access with time-awareness
type TaxRateRepository interface {
	// Core CRUD
	Create(ctx context.Context, db DBTX, r *tax.TaxRate) error
	Upsert(ctx context.Context, db DBTX, r *tax.TaxRate) error
	Update(ctx context.Context, db DBTX, r *tax.TaxRate) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxRate, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxRate, error)

	// Time-based lookups (CRITICAL)
	GetApplicableRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, date time.Time) (*tax.TaxRate, error)
	GetRatesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRate, error)
	GetActiveRates(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRate, error)

	// Listing & counting
	List(ctx context.Context, db DBTX, filter TaxRateFilter, p Pagination, s Sort) ([]*tax.TaxRate, error)
	Count(ctx context.Context, db DBTX, filter TaxRateFilter) (int64, error)

	// Status / lifecycle
	SetActive(ctx context.Context, db DBTX, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Validation / safety
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, effectiveFrom time.Time) (bool, error)
	CheckOverlappingRates(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, from time.Time, to *time.Time, excludeID uuid.UUID) (bool, error)
	CheckUsage(ctx context.Context, db DBTX, taxRateID uuid.UUID) (bool, error)

	// Versioning strategy
	CloseOpenRates(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, beforeDate time.Time) error
}

type taxRateRepository struct {
	logger *zap.Logger
}

// NewTaxRateRepository creates a new tax rate repository instance
func NewTaxRateRepository(logger *zap.Logger) TaxRateRepository {
	return &taxRateRepository{
		logger: logger.Named("tax_rate_repo"),
	}
}

// allowed sort fields for tax rates
var allowedTaxRateSortFields = map[string]bool{
	"tax_name":        true,
	"rate_percentage": true,
	"effective_from":  true,
	"effective_to":    true,
	"is_active":       true,
	"created_at":      true,
	"updated_at":      true,
}

func (r *taxRateRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "effective_from"
	}
	if !allowedTaxRateSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *taxRateRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *taxRateRepository) buildTaxRateFilter(filter TaxRateFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.TaxName != "" {
		conditions = append(conditions, fmt.Sprintf("tax_name = $%d", idx))
		args = append(args, filter.TaxName)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("effective_from >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("(effective_to <= $%d OR effective_to IS NULL)", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(tax_name ILIKE $%d)", idx))
		args = append(args, searchPattern)
		idx++
	}

	// Soft delete filter
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *taxRateRepository) scanTaxRate(scanner interface {
	Scan(dest ...interface{}) error
}) (*tax.TaxRate, error) {
	var tr tax.TaxRate
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&tr.TaxRateID, &tr.CompanyID, &tr.TaxName, &tr.RatePercentage,
		&tr.EffectiveFrom, &effectiveTo, &tr.IsActive,
		&tr.CreatedAt, &tr.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		tr.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		tr.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		tr.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		tr.DeletedAt = &deletedAt.Time
	}
	return &tr, nil
}

// Create inserts a new tax rate
func (r *taxRateRepository) Create(ctx context.Context, db DBTX, tr *tax.TaxRate) error {
	query := `
		INSERT INTO accounting.tax_rates (
			tax_rate_id, company_id, tax_name, rate_percentage,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8, $9)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		tr.TaxRateID, tr.CompanyID, tr.TaxName, tr.RatePercentage,
		tr.EffectiveFrom, tr.EffectiveTo, tr.IsActive,
		tr.CreatedBy, tr.UpdatedBy,
	).Scan(&tr.CreatedAt, &tr.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create tax rate",
			util.String("company_id", tr.CompanyID.String()),
			util.String("tax_name", tr.TaxName),
			util.ErrorField(err))
		return fmt.Errorf("create tax rate: %w", err)
	}
	return nil
}

// Upsert inserts or updates a tax rate (unique constraint on (company_id, tax_name, effective_from))
func (r *taxRateRepository) Upsert(ctx context.Context, db DBTX, tr *tax.TaxRate) error {
	query := `
		INSERT INTO accounting.tax_rates (
			tax_rate_id, company_id, tax_name, rate_percentage,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8, $9)
		ON CONFLICT (company_id, tax_name, effective_from) WHERE deleted_at IS NULL
		DO UPDATE SET
			rate_percentage = EXCLUDED.rate_percentage,
			effective_to = EXCLUDED.effective_to,
			is_active = EXCLUDED.is_active,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		tr.TaxRateID, tr.CompanyID, tr.TaxName, tr.RatePercentage,
		tr.EffectiveFrom, tr.EffectiveTo, tr.IsActive,
		tr.CreatedBy, tr.UpdatedBy,
	).Scan(&tr.CreatedAt, &tr.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert tax rate",
			util.String("company_id", tr.CompanyID.String()),
			util.String("tax_name", tr.TaxName),
			util.ErrorField(err))
		return fmt.Errorf("upsert tax rate: %w", err)
	}
	return nil
}

// Update updates an existing tax rate (only non‑historical fields)
func (r *taxRateRepository) Update(ctx context.Context, db DBTX, tr *tax.TaxRate) error {
	query := `
		UPDATE accounting.tax_rates
		SET tax_name = $2,
		    rate_percentage = $3,
		    effective_from = $4,
		    effective_to = $5,
		    is_active = $6,
		    updated_by = $7,
		    updated_at = NOW()
		WHERE tax_rate_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		tr.TaxRateID, tr.TaxName, tr.RatePercentage,
		tr.EffectiveFrom, tr.EffectiveTo, tr.IsActive,
		tr.UpdatedBy,
	).Scan(&tr.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("tax rate %s not found or deleted", tr.TaxRateID)
		}
		r.logger.Error("failed to update tax rate",
			util.String("id", tr.TaxRateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update tax rate: %w", err)
	}
	return nil
}

// GetByID retrieves a tax rate by ID
func (r *taxRateRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxRate, error) {
	query := `
		SELECT tax_rate_id, company_id, tax_name, rate_percentage,
		       effective_from, effective_to, is_active,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rates
		WHERE tax_rate_id = $1 AND deleted_at IS NULL
	`
	var tr tax.TaxRate
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, id).Scan(
		&tr.TaxRateID, &tr.CompanyID, &tr.TaxName, &tr.RatePercentage,
		&tr.EffectiveFrom, &effectiveTo, &tr.IsActive,
		&tr.CreatedAt, &tr.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get tax rate by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax rate by ID: %w", err)
	}
	if effectiveTo.Valid {
		tr.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		tr.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		tr.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		tr.DeletedAt = &deletedAt.Time
	}
	return &tr, nil
}

// GetByIDForUpdate retrieves a tax rate with row lock
func (r *taxRateRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxRate, error) {
	query := `
		SELECT tax_rate_id, company_id, tax_name, rate_percentage,
		       effective_from, effective_to, is_active,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rates
		WHERE tax_rate_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var tr tax.TaxRate
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, id).Scan(
		&tr.TaxRateID, &tr.CompanyID, &tr.TaxName, &tr.RatePercentage,
		&tr.EffectiveFrom, &effectiveTo, &tr.IsActive,
		&tr.CreatedAt, &tr.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get tax rate for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax rate for update: %w", err)
	}
	if effectiveTo.Valid {
		tr.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		tr.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		tr.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		tr.DeletedAt = &deletedAt.Time
	}
	return &tr, nil
}

// GetApplicableRate returns the tax rate that is effective on a given date
func (r *taxRateRepository) GetApplicableRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, date time.Time) (*tax.TaxRate, error) {
	query := `
		SELECT tax_rate_id, company_id, tax_name, rate_percentage,
		       effective_from, effective_to, is_active,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rates
		WHERE company_id = $1
		  AND tax_name = $2
		  AND is_active = true
		  AND deleted_at IS NULL
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	var tr tax.TaxRate
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, companyID, taxName, date).Scan(
		&tr.TaxRateID, &tr.CompanyID, &tr.TaxName, &tr.RatePercentage,
		&tr.EffectiveFrom, &effectiveTo, &tr.IsActive,
		&tr.CreatedAt, &tr.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get applicable tax rate",
			util.String("company_id", companyID.String()),
			util.String("tax_name", taxName),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("get applicable tax rate: %w", err)
	}
	if effectiveTo.Valid {
		tr.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		tr.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		tr.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		tr.DeletedAt = &deletedAt.Time
	}
	return &tr, nil
}

// GetRatesByCompany returns all tax rates for a company (including inactive)
func (r *taxRateRepository) GetRatesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRate, error) {
	filter := TaxRateFilter{CompanyID: companyID}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "effective_from", Direction: "DESC"})
}

// GetActiveRates returns all currently active tax rates for a company
func (r *taxRateRepository) GetActiveRates(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRate, error) {
	active := true
	filter := TaxRateFilter{
		CompanyID: companyID,
		IsActive:  &active,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "tax_name", Direction: "ASC"})
}

// List returns a paginated list of tax rates matching the filter
func (r *taxRateRepository) List(ctx context.Context, db DBTX, filter TaxRateFilter, p Pagination, s Sort) ([]*tax.TaxRate, error) {
	where, args := r.buildTaxRateFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT tax_rate_id, company_id, tax_name, rate_percentage,
		       effective_from, effective_to, is_active,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rates
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list tax rates",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list tax rates: %w", err)
	}
	defer rows.Close()

	var result []*tax.TaxRate
	for rows.Next() {
		tr, err := r.scanTaxRate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax rate: %w", err)
		}
		result = append(result, tr)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// Count returns the number of tax rates matching the filter
func (r *taxRateRepository) Count(ctx context.Context, db DBTX, filter TaxRateFilter) (int64, error) {
	where, args := r.buildTaxRateFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.tax_rates %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count tax rates",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count tax rates: %w", err)
	}
	return count, nil
}

// SetActive updates the active status of a tax rate
func (r *taxRateRepository) SetActive(ctx context.Context, db DBTX, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_rates
		SET is_active = $2, updated_by = $3, updated_at = NOW()
		WHERE tax_rate_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, isActive, updatedBy)
	if err != nil {
		r.logger.Error("failed to set tax rate active status",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("set tax rate active: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tax rate %s not found or deleted", id)
	}
	return nil
}

// Delete soft-deletes a tax rate
func (r *taxRateRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_rates
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE tax_rate_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete tax rate",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete tax rate: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tax rate %s not found or already deleted", id)
	}
	return nil
}

// Exists checks if a tax rate already exists with the same (company_id, tax_name, effective_from)
func (r *taxRateRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, effectiveFrom time.Time) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_rates
			WHERE company_id = $1 AND tax_name = $2 AND effective_from = $3 AND deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, taxName, effectiveFrom).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence",
			util.String("company_id", companyID.String()),
			util.String("tax_name", taxName),
			util.ErrorField(err))
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

// CheckOverlappingRates checks if there is any overlapping effective period for the same tax name
func (r *taxRateRepository) CheckOverlappingRates(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, from time.Time, to *time.Time, excludeID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_rates
			WHERE company_id = $1
			  AND tax_name = $2
			  AND deleted_at IS NULL
			  AND tax_rate_id != $3
			  AND effective_from <= COALESCE($5, effective_from)
			  AND (effective_to IS NULL OR effective_to >= $4)
		)
	`
	var exists bool
	// Use the new rate's from date for the overlap check:
	// - Existing rate's effective_from <= new_rate.effective_to (if new_rate.effective_to is set, else always true)
	// - Existing rate's effective_to >= new_rate.effective_from (if existing rate has no end, it overlaps)
	var effectiveToArg interface{} = to
	if to == nil {
		effectiveToArg = nil
	}
	err := db.QueryRowContext(ctx, query, companyID, taxName, excludeID, from, effectiveToArg).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check overlapping rates",
			util.String("company_id", companyID.String()),
			util.String("tax_name", taxName),
			util.ErrorField(err))
		return false, fmt.Errorf("check overlapping rates: %w", err)
	}
	return exists, nil
}

// CheckUsage checks if the tax rate is referenced in any transaction (tax_transactions) or tax actions
func (r *taxRateRepository) CheckUsage(ctx context.Context, db DBTX, taxRateID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_transactions
			WHERE tax_rate_id = $1
			UNION ALL
			SELECT 1 FROM accounting.tax_actions
			WHERE tax_rate_id = $1
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, taxRateID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check tax rate usage",
			util.String("tax_rate_id", taxRateID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("check usage: %w", err)
	}
	return exists, nil
}

// CloseOpenRates closes any open-ended (effective_to IS NULL) rate for the given tax name
// by setting effective_to = beforeDate - 1 day (or beforeDate as per business rule).
// We set effective_to = beforeDate (the new rate starts on beforeDate, so old rate ends the day before)
func (r *taxRateRepository) CloseOpenRates(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, beforeDate time.Time) error {
	// Set effective_to to the day before the new effective_from
	endDate := beforeDate.AddDate(0, 0, -1)
	query := `
		UPDATE accounting.tax_rates
		SET effective_to = $4,
		    updated_at = NOW(),
		    updated_by = $3
		WHERE company_id = $1
		  AND tax_name = $2
		  AND effective_to IS NULL
		  AND effective_from < $4
		  AND deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, companyID, taxName, nil, endDate)
	if err != nil {
		r.logger.Error("failed to close open rates",
			util.String("company_id", companyID.String()),
			util.String("tax_name", taxName),
			util.Time("before_date", beforeDate),
			util.ErrorField(err))
		return fmt.Errorf("close open rates: %w", err)
	}
	return nil
}
