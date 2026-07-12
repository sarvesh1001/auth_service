// FILE: repository/addon_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// AddonRepository Interface
// -------------------------------------------------------------------------

type AddonRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, addon *models.Addon) error
	GetByID(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Addon, error)
	Update(ctx context.Context, db DBTX, addon *models.Addon) error
	Delete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error

	SoftDelete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Pricing
	// -------------------------------------------------------------------------

	UpdatePrice(
		ctx context.Context,
		db DBTX,
		companyID,
		addonID uuid.UUID,
		price decimal.Decimal,
		currency string,
	) error

	UpdateBillingPolicy(
		ctx context.Context,
		db DBTX,
		companyID,
		addonID,
		billingPolicyID uuid.UUID,
	) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(
		ctx context.Context,
		db DBTX,
		filter AddonFilter,
		p Pagination,
		s Sort,
	) ([]*models.Addon, int64, error)

	Search(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		query string,
		limit,
		offset int,
	) ([]*models.Addon, int64, error)

	GetActive(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
	) ([]*models.Addon, error)

	GetByBillingPolicy(
		ctx context.Context,
		db DBTX,
		companyID,
		billingPolicyID uuid.UUID,
	) ([]*models.Addon, error)

	GetByPriceRange(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		min,
		max decimal.Decimal,
	) ([]*models.Addon, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(
		ctx context.Context,
		db DBTX,
		companyID,
		addonID uuid.UUID,
	) (*models.Addon, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type AddonFilter struct {
	CompanyID       uuid.UUID
	AddonIDs        []uuid.UUID
	Name            *string
	BillingPolicyID *uuid.UUID
	MinPrice        *decimal.Decimal
	MaxPrice        *decimal.Decimal
	Currency        *string
	IsActive        *bool
	CreatedFrom     *time.Time
	CreatedTo       *time.Time
	UpdatedFrom     *time.Time
	UpdatedTo       *time.Time
	Deleted         bool // if true, include soft-deleted records
}

// Pagination and Sort are assumed to be defined in a shared package.
// If not, you can define them here as done in other repositories.
// (We reuse the same Pagination/Sort structs; they are not redefined here.)

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type addonRepository struct {
	logger *zap.Logger
}

// NewAddonRepository creates a new AddonRepository.
func NewAddonRepository(logger *zap.Logger) AddonRepository {
	return &addonRepository{
		logger: logger.Named("subscription_addon_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *addonRepository) Create(ctx context.Context, db DBTX, addon *models.Addon) error {
	query := `
		INSERT INTO subscription.addons (
			addon_id, company_id, name, description, billing_policy_id,
			price, currency, is_active, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := db.ExecContext(ctx, query,
		addon.AddonID,
		addon.CompanyID,
		addon.Name,
		addon.Description,
		addon.BillingPolicyID,
		addon.Price,
		addon.Currency,
		addon.IsActive,
		addon.CreatedAt,
		addon.UpdatedAt,
		addon.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create addon", zap.Error(err))
		return fmt.Errorf("create addon: %w", err)
	}
	return nil
}

func (r *addonRepository) GetByID(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND addon_id = $2
	`
	var addon models.Addon
	err := db.QueryRowContext(ctx, query, companyID, addonID).Scan(
		&addon.AddonID,
		&addon.CompanyID,
		&addon.Name,
		&addon.Description,
		&addon.BillingPolicyID,
		&addon.Price,
		&addon.Currency,
		&addon.IsActive,
		&addon.CreatedAt,
		&addon.UpdatedAt,
		&addon.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get addon by ID", zap.Error(err))
		return nil, fmt.Errorf("get addon by ID: %w", err)
	}
	return &addon, nil
}

func (r *addonRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND name = $2
	`
	var addon models.Addon
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&addon.AddonID,
		&addon.CompanyID,
		&addon.Name,
		&addon.Description,
		&addon.BillingPolicyID,
		&addon.Price,
		&addon.Currency,
		&addon.IsActive,
		&addon.CreatedAt,
		&addon.UpdatedAt,
		&addon.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get addon by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get addon by name: %w", err)
	}
	return &addon, nil
}

func (r *addonRepository) Update(ctx context.Context, db DBTX, addon *models.Addon) error {
	query := `
		UPDATE subscription.addons
		SET name = $1,
		    description = $2,
		    billing_policy_id = $3,
		    price = $4,
		    currency = $5,
		    is_active = $6,
		    updated_at = $7,
		    deleted_at = $8
		WHERE company_id = $9 AND addon_id = $10
	`
	_, err := db.ExecContext(ctx, query,
		addon.Name,
		addon.Description,
		addon.BillingPolicyID,
		addon.Price,
		addon.Currency,
		addon.IsActive,
		addon.UpdatedAt,
		addon.DeletedAt,
		addon.CompanyID,
		addon.AddonID,
	)
	if err != nil {
		r.logger.Error("failed to update addon", zap.Error(err))
		return fmt.Errorf("update addon: %w", err)
	}
	return nil
}

func (r *addonRepository) Delete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `DELETE FROM subscription.addons WHERE company_id = $1 AND addon_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to delete addon", zap.Error(err))
		return fmt.Errorf("delete addon: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *addonRepository) Activate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET is_active = true, updated_at = NOW() WHERE company_id = $1 AND addon_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to activate addon", zap.Error(err))
		return fmt.Errorf("activate addon: %w", err)
	}
	return nil
}

func (r *addonRepository) Deactivate(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET is_active = false, updated_at = NOW() WHERE company_id = $1 AND addon_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to deactivate addon", zap.Error(err))
		return fmt.Errorf("deactivate addon: %w", err)
	}
	return nil
}

func (r *addonRepository) SoftDelete(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET deleted_at = NOW() WHERE company_id = $1 AND addon_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to soft delete addon", zap.Error(err))
		return fmt.Errorf("soft delete addon: %w", err)
	}
	return nil
}

func (r *addonRepository) Restore(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) error {
	query := `UPDATE subscription.addons SET deleted_at = NULL WHERE company_id = $1 AND addon_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to restore addon", zap.Error(err))
		return fmt.Errorf("restore addon: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Pricing
// -------------------------------------------------------------------------

func (r *addonRepository) UpdatePrice(
	ctx context.Context,
	db DBTX,
	companyID,
	addonID uuid.UUID,
	price decimal.Decimal,
	currency string,
) error {
	query := `
		UPDATE subscription.addons
		SET price = $1, currency = $2, updated_at = NOW()
		WHERE company_id = $3 AND addon_id = $4
	`
	_, err := db.ExecContext(ctx, query, price, currency, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to update addon price", zap.Error(err))
		return fmt.Errorf("update addon price: %w", err)
	}
	return nil
}

func (r *addonRepository) UpdateBillingPolicy(
	ctx context.Context,
	db DBTX,
	companyID,
	addonID,
	billingPolicyID uuid.UUID,
) error {
	query := `
		UPDATE subscription.addons
		SET billing_policy_id = $1, updated_at = NOW()
		WHERE company_id = $2 AND addon_id = $3
	`
	_, err := db.ExecContext(ctx, query, billingPolicyID, companyID, addonID)
	if err != nil {
		r.logger.Error("failed to update addon billing policy", zap.Error(err))
		return fmt.Errorf("update addon billing policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *addonRepository) Exists(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.addons WHERE company_id = $1 AND addon_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, addonID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *addonRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.addons WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by name: %w", err)
	}
	return exists, nil
}

func (r *addonRepository) IsActive(ctx context.Context, db DBTX, companyID, addonID uuid.UUID) (bool, error) {
	query := `SELECT is_active FROM subscription.addons WHERE company_id = $1 AND addon_id = $2 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, companyID, addonID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *addonRepository) List(
	ctx context.Context,
	db DBTX,
	filter AddonFilter,
	p Pagination,
	s Sort,
) ([]*models.Addon, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.addons %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count addons: %w", err)
	}
	if total == 0 {
		return []*models.Addon{}, 0, nil
	}

	// Build sort
	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list addons: %w", err)
	}
	defer rows.Close()

	var addons []*models.Addon
	for rows.Next() {
		var a models.Addon
		err := rows.Scan(
			&a.AddonID,
			&a.CompanyID,
			&a.Name,
			&a.Description,
			&a.BillingPolicyID,
			&a.Price,
			&a.Currency,
			&a.IsActive,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan addon: %w", err)
		}
		addons = append(addons, &a)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return addons, total, nil
}

func (r *addonRepository) Search(
	ctx context.Context,
	db DBTX,
	companyID uuid.UUID,
	query string,
	limit,
	offset int,
) ([]*models.Addon, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND name ILIKE $2"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.addons WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search addons: %w", err)
	}
	if total == 0 {
		return []*models.Addon{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search addons: %w", err)
	}
	defer rows.Close()

	var addons []*models.Addon
	for rows.Next() {
		var a models.Addon
		err := rows.Scan(
			&a.AddonID,
			&a.CompanyID,
			&a.Name,
			&a.Description,
			&a.BillingPolicyID,
			&a.Price,
			&a.Currency,
			&a.IsActive,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan addon: %w", err)
		}
		addons = append(addons, &a)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return addons, total, nil
}

func (r *addonRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active addons: %w", err)
	}
	defer rows.Close()

	var addons []*models.Addon
	for rows.Next() {
		var a models.Addon
		err := rows.Scan(
			&a.AddonID,
			&a.CompanyID,
			&a.Name,
			&a.Description,
			&a.BillingPolicyID,
			&a.Price,
			&a.Currency,
			&a.IsActive,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan addon: %w", err)
		}
		addons = append(addons, &a)
	}
	return addons, rows.Err()
}

func (r *addonRepository) GetByBillingPolicy(
	ctx context.Context,
	db DBTX,
	companyID,
	billingPolicyID uuid.UUID,
) ([]*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, billingPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by billing policy: %w", err)
	}
	defer rows.Close()

	var addons []*models.Addon
	for rows.Next() {
		var a models.Addon
		err := rows.Scan(
			&a.AddonID,
			&a.CompanyID,
			&a.Name,
			&a.Description,
			&a.BillingPolicyID,
			&a.Price,
			&a.Currency,
			&a.IsActive,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan addon: %w", err)
		}
		addons = append(addons, &a)
	}
	return addons, rows.Err()
}

func (r *addonRepository) GetByPriceRange(
	ctx context.Context,
	db DBTX,
	companyID uuid.UUID,
	min,
	max decimal.Decimal,
) ([]*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1
		  AND price >= $2 AND price <= $3
		  AND deleted_at IS NULL
		ORDER BY price ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, min, max)
	if err != nil {
		return nil, fmt.Errorf("get by price range: %w", err)
	}
	defer rows.Close()

	var addons []*models.Addon
	for rows.Next() {
		var a models.Addon
		err := rows.Scan(
			&a.AddonID,
			&a.CompanyID,
			&a.Name,
			&a.Description,
			&a.BillingPolicyID,
			&a.Price,
			&a.Currency,
			&a.IsActive,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan addon: %w", err)
		}
		addons = append(addons, &a)
	}
	return addons, rows.Err()
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *addonRepository) GetByIDForUpdate(
	ctx context.Context,
	db DBTX,
	companyID,
	addonID uuid.UUID,
) (*models.Addon, error) {
	query := `
		SELECT addon_id, company_id, name, description, billing_policy_id,
		       price, currency, is_active, created_at, updated_at, deleted_at
		FROM subscription.addons
		WHERE company_id = $1 AND addon_id = $2
		FOR UPDATE
	`
	var addon models.Addon
	err := db.QueryRowContext(ctx, query, companyID, addonID).Scan(
		&addon.AddonID,
		&addon.CompanyID,
		&addon.Name,
		&addon.Description,
		&addon.BillingPolicyID,
		&addon.Price,
		&addon.Currency,
		&addon.IsActive,
		&addon.CreatedAt,
		&addon.UpdatedAt,
		&addon.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get addon for update", zap.Error(err))
		return nil, fmt.Errorf("get addon for update: %w", err)
	}
	return &addon, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *addonRepository) buildFilterConditions(filter AddonFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, filter.CompanyID)
		argPos++
	}

	if len(filter.AddonIDs) > 0 {
		placeholders := make([]string, len(filter.AddonIDs))
		for i, id := range filter.AddonIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("addon_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.AddonIDs)
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argPos))
		args = append(args, "%"+*filter.Name+"%")
		argPos++
	}

	if filter.BillingPolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("billing_policy_id = $%d", argPos))
		args = append(args, *filter.BillingPolicyID)
		argPos++
	}

	if filter.MinPrice != nil {
		conditions = append(conditions, fmt.Sprintf("price >= $%d", argPos))
		args = append(args, *filter.MinPrice)
		argPos++
	}
	if filter.MaxPrice != nil {
		conditions = append(conditions, fmt.Sprintf("price <= $%d", argPos))
		args = append(args, *filter.MaxPrice)
		argPos++
	}

	if filter.Currency != nil {
		conditions = append(conditions, fmt.Sprintf("currency = $%d", argPos))
		args = append(args, *filter.Currency)
		argPos++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *filter.IsActive)
		argPos++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argPos))
		args = append(args, *filter.CreatedFrom)
		argPos++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argPos))
		args = append(args, *filter.CreatedTo)
		argPos++
	}

	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argPos))
		args = append(args, *filter.UpdatedFrom)
		argPos++
	}
	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argPos))
		args = append(args, *filter.UpdatedTo)
		argPos++
	}

	// Deleted handling
	if filter.Deleted {
		// Include soft-deleted records – no condition on deleted_at
	} else {
		conditions = append(conditions, "deleted_at IS NULL")
	}

	return conditions, args
}
