// repository/addon_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// AddonRepository Interface
// ---------------------------------------------------------------------

type AddonRepository interface {
	Create(ctx context.Context, db DBTX, addon *models.Addon) error
	Update(ctx context.Context, db DBTX, addon *models.Addon) error
	Delete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Addon, error)

	List(ctx context.Context, db DBTX, filter AddonFilter, p Pagination, s Sort) ([]*models.Addon, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Addon, error)

	Exists(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Addon, int64, error)

	SetActive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error
	SetInactive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type AddonFilter struct {
	CompanyID       uuid.UUID
	AddonIDs        []uuid.UUID
	Name            *string
	BillingPolicyID *uuid.UUID
	IsActive        *bool
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type addonRepository struct {
	logger *zap.Logger
}

func NewAddonRepository(logger *zap.Logger) AddonRepository {
	return &addonRepository{
		logger: logger.Named("subscription_addon_repo"),
	}
}

const addonTable = "subscription.addons"

func (r *addonRepository) scanAddon(s scanner) (*models.Addon, error) {
	var a models.Addon
	var desc sql.NullString
	var deletedAt sql.NullTime
	err := s.Scan(
		&a.AddonID,
		&a.CompanyID,
		&a.Name,
		&desc,
		&a.BillingPolicyID,
		&a.Price,
		&a.Currency,
		&a.IsActive,
		&a.CreatedAt,
		&a.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan addon: %w", err)
	}
	if desc.Valid {
		a.Description = &desc.String
	}
	if deletedAt.Valid {
		a.DeletedAt.Time = deletedAt.Time
		a.DeletedAt.Valid = true
	}
	return &a, nil
}

func (r *addonRepository) buildAddonFilter(filter AddonFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// CompanyID required
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, filter.CompanyID)
	idx++

	if len(filter.AddonIDs) > 0 {
		placeholders := make([]string, len(filter.AddonIDs))
		for i, id := range filter.AddonIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("addon_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.BillingPolicyID != nil {
		conds = append(conds, fmt.Sprintf("billing_policy_id = $%d", idx))
		args = append(args, *filter.BillingPolicyID)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	conds = append(conds, "deleted_at IS NULL")

	return "WHERE " + strings.Join(conds, " AND "), args
}

var addonAllowedSort = map[string]bool{
	"addon_id":   true,
	"name":       true,
	"price":      true,
	"currency":   true,
	"is_active":  true,
	"created_at": true,
	"updated_at": true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *addonRepository) Create(ctx context.Context, db DBTX, addon *models.Addon) error {
	query := `
		INSERT INTO subscription.addons (
			addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		addon.AddonID,
		addon.CompanyID,
		addon.Name,
		addon.Description,
		addon.BillingPolicyID,
		addon.Price,
		addon.Currency,
		addon.IsActive,
	).Scan(&addon.CreatedAt, &addon.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create addon: %w", err)
	}
	return nil
}

func (r *addonRepository) Update(ctx context.Context, db DBTX, addon *models.Addon) error {
	query := `
		UPDATE subscription.addons SET
			name = $3,
			description = $4,
			billing_policy_id = $5,
			price = $6,
			currency = $7,
			is_active = $8,
			updated_at = NOW()
		WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		addon.AddonID,
		addon.CompanyID,
		addon.Name,
		addon.Description,
		addon.BillingPolicyID,
		addon.Price,
		addon.Currency,
		addon.IsActive,
	).Scan(&addon.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update addon: %w", err)
	}
	return nil
}

func (r *addonRepository) Delete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET deleted_at = NOW() WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, addonID, companyID)
	if err != nil {
		return fmt.Errorf("soft delete addon: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *addonRepository) GetByID(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, addonID, companyID)
	return r.scanAddon(row)
}

func (r *addonRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanAddon(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *addonRepository) List(ctx context.Context, db DBTX, filter AddonFilter, p Pagination, s Sort) ([]*models.Addon, int64, error) {
	where, args := r.buildAddonFilter(filter)
	orderBy, err := validateSort(s, addonAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", addonTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count addons: %w", err)
	}
	if total == 0 {
		return []*models.Addon{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, addonTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list addons: %w", err)
	}
	defer rows.Close()

	var result []*models.Addon
	for rows.Next() {
		addon, err := r.scanAddon(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, addon)
	}
	return result, total, rows.Err()
}

func (r *addonRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Addon, error) {
	filter := AddonFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	addons, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return addons, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *addonRepository) Exists(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.addons WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, addonID, companyID).Scan(&exists)
	return exists, err
}

func (r *addonRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.addons WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *addonRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Addon, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE company_id = $1 AND deleted_at IS NULL AND (name ILIKE $2 OR description ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", addonTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search addons count: %w", err)
	}
	if total == 0 {
		return []*models.Addon{}, 0, nil
	}

	baseQuery := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search addons: %w", err)
	}
	defer rows.Close()

	var result []*models.Addon
	for rows.Next() {
		addon, err := r.scanAddon(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, addon)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------

func (r *addonRepository) SetActive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET is_active = true, updated_at = NOW() WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, addonID, companyID)
	if err != nil {
		return fmt.Errorf("set active: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *addonRepository) SetInactive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET is_active = false, updated_at = NOW() WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, addonID, companyID)
	if err != nil {
		return fmt.Errorf("set inactive: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *addonRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE addon_id = $1 AND company_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, addonID, companyID)
	return r.scanAddon(row)
}
