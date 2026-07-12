// FILE: repository/entitlement_repository.go

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
	"auth-service/internal/subscription/models/enums"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// EntitlementRepository Interface
// -------------------------------------------------------------------------

type EntitlementRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, entitlement *models.Entitlement) error
	BulkCreate(ctx context.Context, db DBTX, entitlements []*models.Entitlement) error

	GetByID(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error)

	Update(ctx context.Context, db DBTX, entitlement *models.Entitlement) error
	Delete(ctx context.Context, db DBTX, entitlementID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Bulk Operations
	// -------------------------------------------------------------------------

	ReplaceByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID, entitlements []*models.Entitlement) error
	DeleteByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Enable(ctx context.Context, db DBTX, entitlementID uuid.UUID) error
	Disable(ctx context.Context, db DBTX, entitlementID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Limits
	// -------------------------------------------------------------------------

	UpdateLimit(ctx context.Context, db DBTX, entitlementID uuid.UUID, limitValue *decimal.Decimal, limitPeriod enums.LimitPeriod) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error)
	ExistsByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (bool, error)
	IsEnabled(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter EntitlementFilter, p Pagination, s Sort) ([]*models.Entitlement, int64, error)
	GetByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error)
	GetEnabledByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error)
	GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.Entitlement, error)
	GetByLimitPeriod(ctx context.Context, db DBTX, limitPeriod enums.LimitPeriod) ([]*models.Entitlement, error)

	Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type EntitlementFilter struct {
	EntitlementIDs []uuid.UUID
	PlanItemID     *uuid.UUID
	FeatureKey     *string
	LimitPeriod    *enums.LimitPeriod
	LimitValueMin  *decimal.Decimal
	LimitValueMax  *decimal.Decimal
	IsEnabled      *bool
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
	UpdatedFrom    *time.Time
	UpdatedTo      *time.Time
}

// Pagination and Sort are defined in the same package or shared.
// They are re‑declared here for completeness if not imported.
// If you have a shared package, you can remove these.

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type entitlementRepository struct {
	logger *zap.Logger
}

// NewEntitlementRepository creates a new EntitlementRepository.
func NewEntitlementRepository(logger *zap.Logger) EntitlementRepository {
	return &entitlementRepository{
		logger: logger.Named("subscription_entitlement_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *entitlementRepository) Create(ctx context.Context, db DBTX, entitlement *models.Entitlement) error {
	query := `
		INSERT INTO subscription.entitlements (
			entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := db.ExecContext(ctx, query,
		entitlement.EntitlementID,
		entitlement.PlanItemID,
		entitlement.FeatureKey,
		entitlement.LimitValue,
		string(entitlement.LimitPeriod),
		entitlement.IsEnabled,
		entitlement.CreatedAt,
		entitlement.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create entitlement", zap.Error(err))
		return fmt.Errorf("create entitlement: %w", err)
	}
	return nil
}

func (r *entitlementRepository) BulkCreate(ctx context.Context, db DBTX, entitlements []*models.Entitlement) error {
	if len(entitlements) == 0 {
		return nil
	}

	// Build a batch insert with multiple rows.
	valueStrings := make([]string, 0, len(entitlements))
	valueArgs := make([]interface{}, 0, len(entitlements)*8)

	for i, e := range entitlements {
		valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*8+1, i*8+2, i*8+3, i*8+4, i*8+5, i*8+6, i*8+7, i*8+8))
		valueArgs = append(valueArgs,
			e.EntitlementID,
			e.PlanItemID,
			e.FeatureKey,
			e.LimitValue,
			string(e.LimitPeriod),
			e.IsEnabled,
			e.CreatedAt,
			e.UpdatedAt,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO subscription.entitlements (
			entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
			created_at, updated_at
		) VALUES %s
	`, strings.Join(valueStrings, ","))

	_, err := db.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		r.logger.Error("failed to bulk create entitlements", zap.Error(err))
		return fmt.Errorf("bulk create entitlements: %w", err)
	}
	return nil
}

func (r *entitlementRepository) GetByID(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE entitlement_id = $1
	`
	var e models.Entitlement
	var limitPeriod string
	err := db.QueryRowContext(ctx, query, entitlementID).Scan(
		&e.EntitlementID,
		&e.PlanItemID,
		&e.FeatureKey,
		&e.LimitValue,
		&limitPeriod,
		&e.IsEnabled,
		&e.CreatedAt,
		&e.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get entitlement by ID", zap.Error(err))
		return nil, fmt.Errorf("get entitlement by ID: %w", err)
	}
	e.LimitPeriod = enums.LimitPeriod(limitPeriod)
	return &e, nil
}

func (r *entitlementRepository) Update(ctx context.Context, db DBTX, entitlement *models.Entitlement) error {
	query := `
		UPDATE subscription.entitlements
		SET plan_item_id = $1,
		    feature_key = $2,
		    limit_value = $3,
		    limit_period = $4,
		    is_enabled = $5,
		    updated_at = $6
		WHERE entitlement_id = $7
	`
	_, err := db.ExecContext(ctx, query,
		entitlement.PlanItemID,
		entitlement.FeatureKey,
		entitlement.LimitValue,
		string(entitlement.LimitPeriod),
		entitlement.IsEnabled,
		entitlement.UpdatedAt,
		entitlement.EntitlementID,
	)
	if err != nil {
		r.logger.Error("failed to update entitlement", zap.Error(err))
		return fmt.Errorf("update entitlement: %w", err)
	}
	return nil
}

func (r *entitlementRepository) Delete(ctx context.Context, db DBTX, entitlementID uuid.UUID) error {
	query := `DELETE FROM subscription.entitlements WHERE entitlement_id = $1`
	result, err := db.ExecContext(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("failed to delete entitlement", zap.Error(err))
		return fmt.Errorf("delete entitlement: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Bulk Operations
// -------------------------------------------------------------------------

func (r *entitlementRepository) ReplaceByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID, entitlements []*models.Entitlement) error {
	// Start a transaction (if not already in one) – but we assume the caller handles transaction.
	// We'll perform a delete and then bulk insert.
	if err := r.DeleteByPlanItem(ctx, db, planItemID); err != nil {
		return fmt.Errorf("delete existing entitlements: %w", err)
	}
	if len(entitlements) == 0 {
		return nil
	}
	return r.BulkCreate(ctx, db, entitlements)
}

func (r *entitlementRepository) DeleteByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `DELETE FROM subscription.entitlements WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to delete entitlements by plan item", zap.Error(err))
		return fmt.Errorf("delete entitlements by plan item: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *entitlementRepository) Enable(ctx context.Context, db DBTX, entitlementID uuid.UUID) error {
	query := `UPDATE subscription.entitlements SET is_enabled = true, updated_at = NOW() WHERE entitlement_id = $1`
	_, err := db.ExecContext(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("failed to enable entitlement", zap.Error(err))
		return fmt.Errorf("enable entitlement: %w", err)
	}
	return nil
}

func (r *entitlementRepository) Disable(ctx context.Context, db DBTX, entitlementID uuid.UUID) error {
	query := `UPDATE subscription.entitlements SET is_enabled = false, updated_at = NOW() WHERE entitlement_id = $1`
	_, err := db.ExecContext(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("failed to disable entitlement", zap.Error(err))
		return fmt.Errorf("disable entitlement: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Limits
// -------------------------------------------------------------------------

func (r *entitlementRepository) UpdateLimit(ctx context.Context, db DBTX, entitlementID uuid.UUID, limitValue *decimal.Decimal, limitPeriod enums.LimitPeriod) error {
	query := `
		UPDATE subscription.entitlements
		SET limit_value = $1, limit_period = $2, updated_at = NOW()
		WHERE entitlement_id = $3
	`
	_, err := db.ExecContext(ctx, query, limitValue, string(limitPeriod), entitlementID)
	if err != nil {
		r.logger.Error("failed to update limit", zap.Error(err))
		return fmt.Errorf("update limit: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *entitlementRepository) Exists(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.entitlements WHERE entitlement_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, entitlementID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *entitlementRepository) ExistsByFeature(ctx context.Context, db DBTX, planItemID uuid.UUID, featureKey string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.entitlements WHERE plan_item_id = $1 AND feature_key = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, planItemID, featureKey).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by feature: %w", err)
	}
	return exists, nil
}

func (r *entitlementRepository) IsEnabled(ctx context.Context, db DBTX, entitlementID uuid.UUID) (bool, error) {
	query := `SELECT is_enabled FROM subscription.entitlements WHERE entitlement_id = $1`
	var enabled bool
	err := db.QueryRowContext(ctx, query, entitlementID).Scan(&enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is enabled: %w", err)
	}
	return enabled, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *entitlementRepository) List(ctx context.Context, db DBTX, filter EntitlementFilter, p Pagination, s Sort) ([]*models.Entitlement, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.entitlements %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count entitlements: %w", err)
	}
	if total == 0 {
		return []*models.Entitlement{}, 0, nil
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
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var limitPeriod string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&limitPeriod,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(limitPeriod)
		entitlements = append(entitlements, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return entitlements, total, nil
}

func (r *entitlementRepository) GetByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE plan_item_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planItemID)
	if err != nil {
		return nil, fmt.Errorf("get by plan item: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var limitPeriod string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&limitPeriod,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(limitPeriod)
		entitlements = append(entitlements, &e)
	}
	return entitlements, rows.Err()
}

func (r *entitlementRepository) GetEnabledByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE plan_item_id = $1 AND is_enabled = true
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planItemID)
	if err != nil {
		return nil, fmt.Errorf("get enabled by plan item: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var limitPeriod string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&limitPeriod,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(limitPeriod)
		entitlements = append(entitlements, &e)
	}
	return entitlements, rows.Err()
}

func (r *entitlementRepository) GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE feature_key = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, featureKey)
	if err != nil {
		return nil, fmt.Errorf("get by feature: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var limitPeriod string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&limitPeriod,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(limitPeriod)
		entitlements = append(entitlements, &e)
	}
	return entitlements, rows.Err()
}

func (r *entitlementRepository) GetByLimitPeriod(ctx context.Context, db DBTX, limitPeriod enums.LimitPeriod) ([]*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE limit_period = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, string(limitPeriod))
	if err != nil {
		return nil, fmt.Errorf("get by limit period: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var lp string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&lp,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(lp)
		entitlements = append(entitlements, &e)
	}
	return entitlements, rows.Err()
}

func (r *entitlementRepository) Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error) {
	searchPattern := "%" + query + "%"
	where := "plan_item_id = $1 AND (feature_key ILIKE $2 OR CAST(limit_value AS TEXT) ILIKE $2)"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.entitlements WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, planItemID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search entitlements: %w", err)
	}
	if total == 0 {
		return []*models.Entitlement{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, planItemID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.Entitlement
	for rows.Next() {
		var e models.Entitlement
		var limitPeriod string
		err := rows.Scan(
			&e.EntitlementID,
			&e.PlanItemID,
			&e.FeatureKey,
			&e.LimitValue,
			&limitPeriod,
			&e.IsEnabled,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan entitlement: %w", err)
		}
		e.LimitPeriod = enums.LimitPeriod(limitPeriod)
		entitlements = append(entitlements, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return entitlements, total, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *entitlementRepository) GetByIDForUpdate(ctx context.Context, db DBTX, entitlementID uuid.UUID) (*models.Entitlement, error) {
	query := `
		SELECT entitlement_id, plan_item_id, feature_key, limit_value, limit_period, is_enabled,
		       created_at, updated_at
		FROM subscription.entitlements
		WHERE entitlement_id = $1
		FOR UPDATE
	`
	var e models.Entitlement
	var limitPeriod string
	err := db.QueryRowContext(ctx, query, entitlementID).Scan(
		&e.EntitlementID,
		&e.PlanItemID,
		&e.FeatureKey,
		&e.LimitValue,
		&limitPeriod,
		&e.IsEnabled,
		&e.CreatedAt,
		&e.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get entitlement for update", zap.Error(err))
		return nil, fmt.Errorf("get entitlement for update: %w", err)
	}
	e.LimitPeriod = enums.LimitPeriod(limitPeriod)
	return &e, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *entitlementRepository) buildFilterConditions(filter EntitlementFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.EntitlementIDs) > 0 {
		placeholders := make([]string, len(filter.EntitlementIDs))
		for i, id := range filter.EntitlementIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("entitlement_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.EntitlementIDs)
	}

	if filter.PlanItemID != nil {
		conditions = append(conditions, fmt.Sprintf("plan_item_id = $%d", argPos))
		args = append(args, *filter.PlanItemID)
		argPos++
	}

	if filter.FeatureKey != nil {
		conditions = append(conditions, fmt.Sprintf("feature_key = $%d", argPos))
		args = append(args, *filter.FeatureKey)
		argPos++
	}

	if filter.LimitPeriod != nil {
		conditions = append(conditions, fmt.Sprintf("limit_period = $%d", argPos))
		args = append(args, string(*filter.LimitPeriod))
		argPos++
	}

	if filter.LimitValueMin != nil {
		conditions = append(conditions, fmt.Sprintf("limit_value >= $%d", argPos))
		args = append(args, *filter.LimitValueMin)
		argPos++
	}
	if filter.LimitValueMax != nil {
		conditions = append(conditions, fmt.Sprintf("limit_value <= $%d", argPos))
		args = append(args, *filter.LimitValueMax)
		argPos++
	}

	if filter.IsEnabled != nil {
		conditions = append(conditions, fmt.Sprintf("is_enabled = $%d", argPos))
		args = append(args, *filter.IsEnabled)
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

	// No soft-delete on entitlements – they are directly deleted, so no deleted_at filter.
	return conditions, args
}
