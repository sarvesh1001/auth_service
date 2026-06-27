// repository/entitlement_repository.go
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
// EntitlementRepository Interface
// ---------------------------------------------------------------------

type EntitlementRepository interface {
	Create(ctx context.Context, db DBTX, entitlement *models.Entitlement) error
	Update(ctx context.Context, db DBTX, entitlement *models.Entitlement) error
	Delete(ctx context.Context, db DBTX, entitlementID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error)
	GetByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (*models.Entitlement, error)

	List(ctx context.Context, db DBTX, filter EntitlementFilter, p Pagination, s Sort) ([]*models.Entitlement, int64, error)
	ListByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error)

	Exists(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error)
	ExistsByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (bool, error)

	Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type EntitlementFilter struct {
	EntitlementIDs []uuid.UUID
	PlanItemID     *uuid.UUID
	FeatureKey     *string
	IsEnabled      *bool
	LimitPeriod    *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type entitlementRepository struct {
	logger *zap.Logger
}

func NewEntitlementRepository(logger *zap.Logger) EntitlementRepository {
	return &entitlementRepository{
		logger: logger.Named("subscription_entitlement_repo"),
	}
}

const entitlementTable = "subscription.entitlements"

func (r *entitlementRepository) scanEntitlement(s scanner) (*models.Entitlement, error) {
	var e models.Entitlement
	var limitVal sql.NullFloat64
	var limitPeriod sql.NullString
	err := s.Scan(
		&e.EntitlementID,
		&e.PlanItemID,
		&e.FeatureKey,
		&limitVal,
		&limitPeriod,
		&e.IsEnabled,
		&e.CreatedAt,
		&e.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan entitlement: %w", err)
	}
	if limitVal.Valid {
		e.LimitValue = &limitVal.Float64
	}
	if limitPeriod.Valid {
		e.LimitPeriod = &limitPeriod.String
	}
	return &e, nil
}

func (r *entitlementRepository) buildEntitlementFilter(filter EntitlementFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if len(filter.EntitlementIDs) > 0 {
		placeholders := make([]string, len(filter.EntitlementIDs))
		for i, id := range filter.EntitlementIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("entitlement_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.PlanItemID != nil {
		conds = append(conds, fmt.Sprintf("plan_item_id = $%d", idx))
		args = append(args, *filter.PlanItemID)
		idx++
	}
	if filter.FeatureKey != nil {
		conds = append(conds, fmt.Sprintf("feature_key = $%d", idx))
		args = append(args, *filter.FeatureKey)
		idx++
	}
	if filter.IsEnabled != nil {
		conds = append(conds, fmt.Sprintf("is_enabled = $%d", idx))
		args = append(args, *filter.IsEnabled)
		idx++
	}
	if filter.LimitPeriod != nil {
		conds = append(conds, fmt.Sprintf("limit_period = $%d", idx))
		args = append(args, *filter.LimitPeriod)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var entitlementAllowedSort = map[string]bool{
	"entitlement_id": true,
	"feature_key":    true,
	"limit_value":    true,
	"limit_period":   true,
	"is_enabled":     true,
	"created_at":     true,
	"updated_at":     true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *entitlementRepository) Create(ctx context.Context, db DBTX, entitlement *models.Entitlement) error {
	query := `
		INSERT INTO subscription.entitlements (
			entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		entitlement.EntitlementID,
		entitlement.PlanItemID,
		entitlement.FeatureKey,
		entitlement.LimitValue,
		entitlement.LimitPeriod,
		entitlement.IsEnabled,
	).Scan(&entitlement.CreatedAt, &entitlement.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create entitlement: %w", err)
	}
	return nil
}

func (r *entitlementRepository) Update(ctx context.Context, db DBTX, entitlement *models.Entitlement) error {
	query := `
		UPDATE subscription.entitlements SET
			feature_key = $2,
			limit_value = $3,
			limit_period = $4,
			is_enabled = $5,
			updated_at = NOW()
		WHERE entitlement_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		entitlement.EntitlementID,
		entitlement.FeatureKey,
		entitlement.LimitValue,
		entitlement.LimitPeriod,
		entitlement.IsEnabled,
	).Scan(&entitlement.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update entitlement: %w", err)
	}
	return nil
}

func (r *entitlementRepository) Delete(ctx context.Context, db DBTX, entitlementID uuid.UUID) error {
	query := `DELETE FROM subscription.entitlements WHERE entitlement_id = $1`
	result, err := db.ExecContext(ctx, query, entitlementID)
	if err != nil {
		return fmt.Errorf("delete entitlement: %w", err)
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

func (r *entitlementRepository) GetByID(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		FROM subscription.entitlements
		WHERE entitlement_id = $1
	`
	row := db.QueryRowContext(ctx, query, entitlementID)
	return r.scanEntitlement(row)
}

func (r *entitlementRepository) GetByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		FROM subscription.entitlements
		WHERE plan_item_id = $1 AND feature_key = $2
	`
	row := db.QueryRowContext(ctx, query, planItemID, featureKey)
	return r.scanEntitlement(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *entitlementRepository) List(ctx context.Context, db DBTX, filter EntitlementFilter, p Pagination, s Sort) ([]*models.Entitlement, int64, error) {
	where, args := r.buildEntitlementFilter(filter)
	orderBy, err := validateSort(s, entitlementAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY feature_key"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", entitlementTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count entitlements: %w", err)
	}
	if total == 0 {
		return []*models.Entitlement{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, entitlementTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list entitlements: %w", err)
	}
	defer rows.Close()

	var result []*models.Entitlement
	for rows.Next() {
		e, err := r.scanEntitlement(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, e)
	}
	return result, total, rows.Err()
}

func (r *entitlementRepository) ListByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error) {
	filter := EntitlementFilter{PlanItemID: &planItemID}
	ents, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return ents, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *entitlementRepository) Exists(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.entitlements WHERE entitlement_id = $1)`
	err := db.QueryRowContext(ctx, query, entitlementID).Scan(&exists)
	return exists, err
}

func (r *entitlementRepository) ExistsByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.entitlements WHERE plan_item_id = $1 AND feature_key = $2)`
	err := db.QueryRowContext(ctx, query, planItemID, featureKey).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *entitlementRepository) Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE plan_item_id = $1 AND (feature_key ILIKE $2)"
	args := []interface{}{planItemID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", entitlementTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search entitlements count: %w", err)
	}
	if total == 0 {
		return []*models.Entitlement{}, 0, nil
	}

	baseQuery := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		FROM subscription.entitlements
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY feature_key LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search entitlements: %w", err)
	}
	defer rows.Close()

	var result []*models.Entitlement
	for rows.Next() {
		e, err := r.scanEntitlement(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, e)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *entitlementRepository) GetByIDForUpdate(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period,
			is_enabled, created_at, updated_at
		FROM subscription.entitlements
		WHERE entitlement_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, entitlementID)
	return r.scanEntitlement(row)
}
