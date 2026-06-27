// repository/plan_item_repository.go
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
// PlanItemRepository Interface
// ---------------------------------------------------------------------

type PlanItemRepository interface {
	Create(ctx context.Context, db DBTX, item *models.PlanItem) error
	Update(ctx context.Context, db DBTX, item *models.PlanItem) error
	Delete(ctx context.Context, db DBTX, planItemID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error)
	GetByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (*models.PlanItem, error)

	List(ctx context.Context, db DBTX, filter PlanItemFilter, p Pagination, s Sort) ([]*models.PlanItem, int64, error)
	ListByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error)

	Exists(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, planID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error)

	SetActive(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	SetInactive(ctx context.Context, db DBTX, planItemID uuid.UUID) error

	GetByIDForUpdate(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type PlanItemFilter struct {
	PlanID          uuid.UUID
	PlanItemIDs     []uuid.UUID
	ItemType        *string
	Name            *string
	FeatureKey      *string
	BillingPolicyID *uuid.UUID
	IsMandatory     *bool
	IsActive        *bool
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type planItemRepository struct {
	logger *zap.Logger
}

func NewPlanItemRepository(logger *zap.Logger) PlanItemRepository {
	return &planItemRepository{
		logger: logger.Named("subscription_plan_item_repo"),
	}
}

const planItemTable = "subscription.plan_items"

func (r *planItemRepository) scanPlanItem(s scanner) (*models.PlanItem, error) {
	var item models.PlanItem
	var desc, featureKey, billingPolicyID sql.NullString
	var effectiveTo, deletedAt sql.NullTime
	err := s.Scan(
		&item.PlanItemID,
		&item.PlanID,
		&item.ItemType,
		&item.Name,
		&desc,
		&featureKey,
		&billingPolicyID,
		&item.Price,
		&item.Currency,
		&item.EffectiveFrom,
		&effectiveTo,
		&item.IsMandatory,
		&item.IsActive,
		&item.CreatedAt,
		&item.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan plan item: %w", err)
	}
	if desc.Valid {
		item.Description = &desc.String
	}
	if featureKey.Valid {
		item.FeatureKey = &featureKey.String
	}
	if billingPolicyID.Valid {
		uid, err := uuid.Parse(billingPolicyID.String)
		if err == nil {
			item.BillingPolicyID = &uid
		}
	}
	if effectiveTo.Valid {
		item.EffectiveTo = &effectiveTo.Time
	}
	if deletedAt.Valid {
		item.DeletedAt.Time = deletedAt.Time
		item.DeletedAt.Valid = true
	}
	return &item, nil
}

func (r *planItemRepository) buildPlanItemFilter(filter PlanItemFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// PlanID is required
	conds = append(conds, fmt.Sprintf("plan_id = $%d", idx))
	args = append(args, filter.PlanID)
	idx++

	if len(filter.PlanItemIDs) > 0 {
		placeholders := make([]string, len(filter.PlanItemIDs))
		for i, id := range filter.PlanItemIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("plan_item_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.ItemType != nil {
		conds = append(conds, fmt.Sprintf("item_type = $%d", idx))
		args = append(args, *filter.ItemType)
		idx++
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.FeatureKey != nil {
		conds = append(conds, fmt.Sprintf("feature_key = $%d", idx))
		args = append(args, *filter.FeatureKey)
		idx++
	}
	if filter.BillingPolicyID != nil {
		conds = append(conds, fmt.Sprintf("billing_policy_id = $%d", idx))
		args = append(args, *filter.BillingPolicyID)
		idx++
	}
	if filter.IsMandatory != nil {
		conds = append(conds, fmt.Sprintf("is_mandatory = $%d", idx))
		args = append(args, *filter.IsMandatory)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	// ignore soft-deleted
	conds = append(conds, "deleted_at IS NULL")

	return "WHERE " + strings.Join(conds, " AND "), args
}

var planItemAllowedSort = map[string]bool{
	"plan_item_id":   true,
	"item_type":      true,
	"name":           true,
	"price":          true,
	"currency":       true,
	"effective_from": true,
	"effective_to":   true,
	"is_mandatory":   true,
	"is_active":      true,
	"created_at":     true,
	"updated_at":     true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *planItemRepository) Create(ctx context.Context, db DBTX, item *models.PlanItem) error {
	query := `
		INSERT INTO subscription.plan_items (
			plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.PlanItemID,
		item.PlanID,
		item.ItemType,
		item.Name,
		item.Description,
		item.FeatureKey,
		item.BillingPolicyID,
		item.Price,
		item.Currency,
		item.EffectiveFrom,
		item.EffectiveTo,
		item.IsMandatory,
		item.IsActive,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) Update(ctx context.Context, db DBTX, item *models.PlanItem) error {
	query := `
		UPDATE subscription.plan_items SET
			item_type = $2,
			name = $3,
			description = $4,
			feature_key = $5,
			billing_policy_id = $6,
			price = $7,
			currency = $8,
			effective_from = $9,
			effective_to = $10,
			is_mandatory = $11,
			is_active = $12,
			updated_at = NOW()
		WHERE plan_item_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.PlanItemID,
		item.ItemType,
		item.Name,
		item.Description,
		item.FeatureKey,
		item.BillingPolicyID,
		item.Price,
		item.Currency,
		item.EffectiveFrom,
		item.EffectiveTo,
		item.IsMandatory,
		item.IsActive,
	).Scan(&item.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) Delete(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET deleted_at = NOW() WHERE plan_item_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		return fmt.Errorf("soft delete plan item: %w", err)
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

func (r *planItemRepository) GetByID(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_item_id = $1 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, planItemID)
	return r.scanPlanItem(row)
}

func (r *planItemRepository) GetByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_id = $1 AND name = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, planID, name)
	return r.scanPlanItem(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *planItemRepository) List(ctx context.Context, db DBTX, filter PlanItemFilter, p Pagination, s Sort) ([]*models.PlanItem, int64, error) {
	where, args := r.buildPlanItemFilter(filter)
	orderBy, err := validateSort(s, planItemAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", planItemTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count plan items: %w", err)
	}
	if total == 0 {
		return []*models.PlanItem{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at, deleted_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, planItemTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list plan items: %w", err)
	}
	defer rows.Close()

	var result []*models.PlanItem
	for rows.Next() {
		item, err := r.scanPlanItem(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

func (r *planItemRepository) ListByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error) {
	filter := PlanItemFilter{PlanID: planID}
	items, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return items, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *planItemRepository) Exists(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_items WHERE plan_item_id = $1 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, planItemID).Scan(&exists)
	return exists, err
}

func (r *planItemRepository) ExistsByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_items WHERE plan_id = $1 AND name = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, planID, name).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *planItemRepository) Search(ctx context.Context, db DBTX, planID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE plan_id = $1 AND deleted_at IS NULL AND (name ILIKE $2 OR description ILIKE $2)"
	args := []interface{}{planID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", planItemTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search plan items count: %w", err)
	}
	if total == 0 {
		return []*models.PlanItem{}, 0, nil
	}

	baseQuery := `
		SELECT plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plan_items
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search plan items: %w", err)
	}
	defer rows.Close()

	var result []*models.PlanItem
	for rows.Next() {
		item, err := r.scanPlanItem(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------

func (r *planItemRepository) SetActive(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET is_active = true, updated_at = NOW() WHERE plan_item_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		return fmt.Errorf("set active: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *planItemRepository) SetInactive(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET is_active = false, updated_at = NOW() WHERE plan_item_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planItemID)
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

func (r *planItemRepository) GetByIDForUpdate(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, item_type, name, description,
			feature_key, billing_policy_id, price, currency,
			effective_from, effective_to, is_mandatory, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_item_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, planItemID)
	return r.scanPlanItem(row)
}
