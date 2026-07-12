// FILE: repository/plan_item_repository.go

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
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
// PlanItemRepository Interface (unchanged)
// -------------------------------------------------------------------------

type PlanItemRepository interface {
	Create(ctx context.Context, db DBTX, item *models.PlanItem) error
	BulkCreate(ctx context.Context, db DBTX, items []*models.PlanItem) error
	GetByID(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error)
	Update(ctx context.Context, db DBTX, item *models.PlanItem) error
	Delete(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	ReplaceByPlan(ctx context.Context, db DBTX, planID uuid.UUID, items []*models.PlanItem) error
	DeleteByPlan(ctx context.Context, db DBTX, planID uuid.UUID) error
	Activate(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	SoftDelete(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, planItemID uuid.UUID) error
	UpdatePrice(ctx context.Context, db DBTX, planItemID uuid.UUID, price decimal.Decimal, currency string) error
	UpdateBillingPolicy(ctx context.Context, db DBTX, planItemID, billingPolicyID uuid.UUID) error
	Exists(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter PlanItemFilter, p Pagination, s Sort) ([]*models.PlanItem, int64, error)
	Search(ctx context.Context, db DBTX, planID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error)
	GetByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error)
	GetActiveByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error)
	GetByType(ctx context.Context, db DBTX, planID uuid.UUID, itemType enums.ItemType) ([]*models.PlanItem, error)
	GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.PlanItem, error)
	GetByBillingPolicy(ctx context.Context, db DBTX, billingPolicyID uuid.UUID) ([]*models.PlanItem, error)
	GetEffective(ctx context.Context, db DBTX, planID uuid.UUID, at time.Time) ([]*models.PlanItem, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error)
}

type PlanItemFilter struct {
	PlanID          uuid.UUID
	PlanItemIDs     []uuid.UUID
	Name            *string
	ItemType        *enums.ItemType
	FeatureKey      *string
	BillingPolicyID *uuid.UUID
	MinPrice        *decimal.Decimal
	MaxPrice        *decimal.Decimal
	Currency        *string
	IsMandatory     *bool
	IsActive        *bool
	EffectiveFrom   *time.Time
	EffectiveTo     *time.Time
	CreatedFrom     *time.Time
	CreatedTo       *time.Time
	UpdatedFrom     *time.Time
	UpdatedTo       *time.Time
	Deleted         bool
	CompanyID       *uuid.UUID
	ProductID       *uuid.UUID
	MinTaxRate      *decimal.Decimal
	MaxTaxRate      *decimal.Decimal
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type planItemRepository struct {
	logger *zap.Logger
}

func NewPlanItemRepository(logger *zap.Logger) PlanItemRepository {
	return &planItemRepository{
		logger: logger.Named("subscription_plan_item_repo"),
	}
}

// -------------------------------------------------------------------------
// Helper functions for Metadata JSON serialization
// -------------------------------------------------------------------------

// serializeMetadata converts a map to JSON bytes, or returns nil if empty.
func serializeMetadata(m map[string]interface{}) interface{} {
	if m == nil || len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		// Log the error but return nil to avoid breaking insert.
		// The caller (repository) will log the error if the insert fails.
		return nil
	}
	return b
}

// deserializeMetadata unmarshals JSON bytes into a map.
func deserializeMetadata(data interface{}) (map[string]interface{}, error) {
	if data == nil {
		return nil, nil
	}
	var b []byte
	switch v := data.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return nil, fmt.Errorf("unexpected type for metadata: %T", data)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *planItemRepository) Create(ctx context.Context, db DBTX, item *models.PlanItem) error {
	query := `
		INSERT INTO subscription.plan_items (
			plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
			price, currency, effective_from, effective_to, is_mandatory, is_active,
			tax_rate, product_id, metadata,
			created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`
	_, err := db.ExecContext(ctx, query,
		item.PlanItemID,
		item.PlanID,
		item.CompanyID,
		string(item.ItemType),
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
		item.TaxRate,
		item.ProductID,
		serializeMetadata(item.Metadata),
		item.CreatedAt,
		item.UpdatedAt,
		item.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create plan item", zap.Error(err))
		return fmt.Errorf("create plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) BulkCreate(ctx context.Context, db DBTX, items []*models.PlanItem) error {
	if len(items) == 0 {
		return nil
	}

	valueStrings := make([]string, 0, len(items))
	args := make([]interface{}, 0, len(items)*20)
	argCounter := 1

	for _, item := range items {
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argCounter, argCounter+1, argCounter+2, argCounter+3, argCounter+4,
			argCounter+5, argCounter+6, argCounter+7, argCounter+8, argCounter+9,
			argCounter+10, argCounter+11, argCounter+12, argCounter+13, argCounter+14,
			argCounter+15, argCounter+16, argCounter+17, argCounter+18, argCounter+19,
		))
		args = append(args,
			item.PlanItemID,
			item.PlanID,
			item.CompanyID,
			string(item.ItemType),
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
			item.TaxRate,
			item.ProductID,
			serializeMetadata(item.Metadata),
			item.CreatedAt,
			item.UpdatedAt,
			item.DeletedAt,
		)
		argCounter += 20
	}

	query := fmt.Sprintf(`
		INSERT INTO subscription.plan_items (
			plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
			price, currency, effective_from, effective_to, is_mandatory, is_active,
			tax_rate, product_id, metadata,
			created_at, updated_at, deleted_at
		) VALUES %s
	`, strings.Join(valueStrings, ","))

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create plan items", zap.Error(err))
		return fmt.Errorf("bulk create plan items: %w", err)
	}
	return nil
}

func (r *planItemRepository) GetByID(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_item_id = $1
	`
	var item models.PlanItem
	var itemType string
	var metadataBytes []byte
	err := db.QueryRowContext(ctx, query, planItemID).Scan(
		&item.PlanItemID,
		&item.PlanID,
		&item.CompanyID,
		&itemType,
		&item.Name,
		&item.Description,
		&item.FeatureKey,
		&item.BillingPolicyID,
		&item.Price,
		&item.Currency,
		&item.EffectiveFrom,
		&item.EffectiveTo,
		&item.IsMandatory,
		&item.IsActive,
		&item.TaxRate,
		&item.ProductID,
		&metadataBytes,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan item by ID", zap.Error(err))
		return nil, fmt.Errorf("get plan item by ID: %w", err)
	}
	item.ItemType = enums.ItemType(itemType)
	if metadataBytes != nil {
		m, err := deserializeMetadata(metadataBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize metadata: %w", err)
		}
		item.Metadata = m
	}
	return &item, nil
}

func (r *planItemRepository) Update(ctx context.Context, db DBTX, item *models.PlanItem) error {
	query := `
		UPDATE subscription.plan_items
		SET item_type = $1,
		    name = $2,
		    description = $3,
		    feature_key = $4,
		    billing_policy_id = $5,
		    price = $6,
		    currency = $7,
		    effective_from = $8,
		    effective_to = $9,
		    is_mandatory = $10,
		    is_active = $11,
		    updated_at = $12,
		    deleted_at = $13,
		    tax_rate = $14,
		    product_id = $15,
		    metadata = $16,
		    company_id = $17
		WHERE plan_item_id = $18
	`
	_, err := db.ExecContext(ctx, query,
		string(item.ItemType),
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
		item.UpdatedAt,
		item.DeletedAt,
		item.TaxRate,
		item.ProductID,
		serializeMetadata(item.Metadata),
		item.CompanyID,
		item.PlanItemID,
	)
	if err != nil {
		r.logger.Error("failed to update plan item", zap.Error(err))
		return fmt.Errorf("update plan item: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Bulk Operations
// -------------------------------------------------------------------------

func (r *planItemRepository) ReplaceByPlan(ctx context.Context, db DBTX, planID uuid.UUID, items []*models.PlanItem) error {
	if err := r.DeleteByPlan(ctx, db, planID); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("delete existing plan items: %w", err)
	}
	if len(items) == 0 {
		return nil
	}
	return r.BulkCreate(ctx, db, items)
}

func (r *planItemRepository) DeleteByPlan(ctx context.Context, db DBTX, planID uuid.UUID) error {
	query := `DELETE FROM subscription.plan_items WHERE plan_id = $1`
	_, err := db.ExecContext(ctx, query, planID)
	if err != nil {
		r.logger.Error("failed to delete plan items by plan", zap.Error(err))
		return fmt.Errorf("delete plan items by plan: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *planItemRepository) Activate(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET is_active = true, updated_at = NOW() WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to activate plan item", zap.Error(err))
		return fmt.Errorf("activate plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) Deactivate(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET is_active = false, updated_at = NOW() WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to deactivate plan item", zap.Error(err))
		return fmt.Errorf("deactivate plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) SoftDelete(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET deleted_at = NOW() WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to soft delete plan item", zap.Error(err))
		return fmt.Errorf("soft delete plan item: %w", err)
	}
	return nil
}

func (r *planItemRepository) Restore(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET deleted_at = NULL WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to restore plan item", zap.Error(err))
		return fmt.Errorf("restore plan item: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Pricing
// -------------------------------------------------------------------------

func (r *planItemRepository) UpdatePrice(ctx context.Context, db DBTX, planItemID uuid.UUID, price decimal.Decimal, currency string) error {
	query := `UPDATE subscription.plan_items SET price = $1, currency = $2, updated_at = NOW() WHERE plan_item_id = $3`
	_, err := db.ExecContext(ctx, query, price, currency, planItemID)
	if err != nil {
		r.logger.Error("failed to update price", zap.Error(err))
		return fmt.Errorf("update price: %w", err)
	}
	return nil
}

func (r *planItemRepository) UpdateBillingPolicy(ctx context.Context, db DBTX, planItemID, billingPolicyID uuid.UUID) error {
	query := `UPDATE subscription.plan_items SET billing_policy_id = $1, updated_at = NOW() WHERE plan_item_id = $2`
	_, err := db.ExecContext(ctx, query, billingPolicyID, planItemID)
	if err != nil {
		r.logger.Error("failed to update billing policy", zap.Error(err))
		return fmt.Errorf("update billing policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *planItemRepository) Exists(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_items WHERE plan_item_id = $1 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, planItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *planItemRepository) ExistsByName(ctx context.Context, db DBTX, planID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_items WHERE plan_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, planID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by name: %w", err)
	}
	return exists, nil
}

func (r *planItemRepository) IsActive(ctx context.Context, db DBTX, planItemID uuid.UUID) (bool, error) {
	query := `SELECT is_active FROM subscription.plan_items WHERE plan_item_id = $1 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, planItemID).Scan(&active)
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

func (r *planItemRepository) List(ctx context.Context, db DBTX, filter PlanItemFilter, p Pagination, s Sort) ([]*models.PlanItem, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plan_items %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count plan items: %w", err)
	}
	if total == 0 {
		return []*models.PlanItem{}, 0, nil
	}

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
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list plan items: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, 0, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return items, total, nil
}

func (r *planItemRepository) Search(ctx context.Context, db DBTX, planID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error) {
	searchPattern := "%" + query + "%"
	where := "plan_id = $1 AND deleted_at IS NULL AND name ILIKE $2"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plan_items WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, planID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search plan items: %w", err)
	}
	if total == 0 {
		return []*models.PlanItem{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, planID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search plan items: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, 0, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return items, total, nil
}

func (r *planItemRepository) GetByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_id = $1 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planID)
	if err != nil {
		return nil, fmt.Errorf("get by plan: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetActiveByPlan(ctx context.Context, db DBTX, planID uuid.UUID) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planID)
	if err != nil {
		return nil, fmt.Errorf("get active by plan: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetByType(ctx context.Context, db DBTX, planID uuid.UUID, itemType enums.ItemType) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_id = $1 AND item_type = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planID, string(itemType))
	if err != nil {
		return nil, fmt.Errorf("get by type: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var it string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&it,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(it)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE feature_key = $1 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, featureKey)
	if err != nil {
		return nil, fmt.Errorf("get by feature: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetByBillingPolicy(ctx context.Context, db DBTX, billingPolicyID uuid.UUID) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE billing_policy_id = $1 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, billingPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by billing policy: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetEffective(ctx context.Context, db DBTX, planID uuid.UUID, at time.Time) ([]*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_id = $1
		  AND deleted_at IS NULL
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planID, at)
	if err != nil {
		return nil, fmt.Errorf("get effective: %w", err)
	}
	defer rows.Close()

	var items []*models.PlanItem
	for rows.Next() {
		var item models.PlanItem
		var itemType string
		var metadataBytes []byte
		err := rows.Scan(
			&item.PlanItemID,
			&item.PlanID,
			&item.CompanyID,
			&itemType,
			&item.Name,
			&item.Description,
			&item.FeatureKey,
			&item.BillingPolicyID,
			&item.Price,
			&item.Currency,
			&item.EffectiveFrom,
			&item.EffectiveTo,
			&item.IsMandatory,
			&item.IsActive,
			&item.TaxRate,
			&item.ProductID,
			&metadataBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan item: %w", err)
		}
		item.ItemType = enums.ItemType(itemType)
		if metadataBytes != nil {
			m, err := deserializeMetadata(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("deserialize metadata: %w", err)
			}
			item.Metadata = m
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *planItemRepository) GetByIDForUpdate(ctx context.Context, db DBTX, planItemID uuid.UUID) (*models.PlanItem, error) {
	query := `
		SELECT plan_item_id, plan_id, company_id, item_type, name, description, feature_key, billing_policy_id,
		       price, currency, effective_from, effective_to, is_mandatory, is_active,
		       tax_rate, product_id, metadata,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_items
		WHERE plan_item_id = $1
		FOR UPDATE
	`
	var item models.PlanItem
	var itemType string
	var metadataBytes []byte
	err := db.QueryRowContext(ctx, query, planItemID).Scan(
		&item.PlanItemID,
		&item.PlanID,
		&item.CompanyID,
		&itemType,
		&item.Name,
		&item.Description,
		&item.FeatureKey,
		&item.BillingPolicyID,
		&item.Price,
		&item.Currency,
		&item.EffectiveFrom,
		&item.EffectiveTo,
		&item.IsMandatory,
		&item.IsActive,
		&item.TaxRate,
		&item.ProductID,
		&metadataBytes,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan item for update", zap.Error(err))
		return nil, fmt.Errorf("get plan item for update: %w", err)
	}
	item.ItemType = enums.ItemType(itemType)
	if metadataBytes != nil {
		m, err := deserializeMetadata(metadataBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize metadata: %w", err)
		}
		item.Metadata = m
	}
	return &item, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *planItemRepository) buildFilterConditions(filter PlanItemFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argCounter := 1

	if filter.PlanID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("plan_id = $%d", argCounter))
		args = append(args, filter.PlanID)
		argCounter++
	}

	if len(filter.PlanItemIDs) > 0 {
		placeholders := make([]string, len(filter.PlanItemIDs))
		for i, id := range filter.PlanItemIDs {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, id)
			argCounter++
		}
		conditions = append(conditions, fmt.Sprintf("plan_item_id IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argCounter))
		args = append(args, "%"+*filter.Name+"%")
		argCounter++
	}

	if filter.ItemType != nil {
		conditions = append(conditions, fmt.Sprintf("item_type = $%d", argCounter))
		args = append(args, string(*filter.ItemType))
		argCounter++
	}

	if filter.FeatureKey != nil {
		conditions = append(conditions, fmt.Sprintf("feature_key = $%d", argCounter))
		args = append(args, *filter.FeatureKey)
		argCounter++
	}

	if filter.BillingPolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("billing_policy_id = $%d", argCounter))
		args = append(args, *filter.BillingPolicyID)
		argCounter++
	}

	if filter.MinPrice != nil {
		conditions = append(conditions, fmt.Sprintf("price >= $%d", argCounter))
		args = append(args, *filter.MinPrice)
		argCounter++
	}

	if filter.MaxPrice != nil {
		conditions = append(conditions, fmt.Sprintf("price <= $%d", argCounter))
		args = append(args, *filter.MaxPrice)
		argCounter++
	}

	if filter.Currency != nil {
		conditions = append(conditions, fmt.Sprintf("currency = $%d", argCounter))
		args = append(args, *filter.Currency)
		argCounter++
	}

	if filter.IsMandatory != nil {
		conditions = append(conditions, fmt.Sprintf("is_mandatory = $%d", argCounter))
		args = append(args, *filter.IsMandatory)
		argCounter++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argCounter))
		args = append(args, *filter.IsActive)
		argCounter++
	}

	if filter.EffectiveFrom != nil {
		conditions = append(conditions, fmt.Sprintf("effective_from >= $%d", argCounter))
		args = append(args, *filter.EffectiveFrom)
		argCounter++
	}

	if filter.EffectiveTo != nil {
		conditions = append(conditions, fmt.Sprintf("effective_to <= $%d", argCounter))
		args = append(args, *filter.EffectiveTo)
		argCounter++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argCounter))
		args = append(args, *filter.CreatedFrom)
		argCounter++
	}

	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argCounter))
		args = append(args, *filter.CreatedTo)
		argCounter++
	}

	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argCounter))
		args = append(args, *filter.UpdatedFrom)
		argCounter++
	}

	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argCounter))
		args = append(args, *filter.UpdatedTo)
		argCounter++
	}

	if filter.Deleted {
		conditions = append(conditions, "deleted_at IS NOT NULL")
	} else {
		conditions = append(conditions, "deleted_at IS NULL")
	}

	if filter.CompanyID != nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argCounter))
		args = append(args, *filter.CompanyID)
		argCounter++
	}

	if filter.ProductID != nil {
		conditions = append(conditions, fmt.Sprintf("product_id = $%d", argCounter))
		args = append(args, *filter.ProductID)
		argCounter++
	}

	if filter.MinTaxRate != nil {
		conditions = append(conditions, fmt.Sprintf("tax_rate >= $%d", argCounter))
		args = append(args, *filter.MinTaxRate)
		argCounter++
	}

	if filter.MaxTaxRate != nil {
		conditions = append(conditions, fmt.Sprintf("tax_rate <= $%d", argCounter))
		args = append(args, *filter.MaxTaxRate)
		argCounter++
	}

	return conditions, args
}

// Delete performs a hard delete of a plan item by ID.
func (r *planItemRepository) Delete(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `DELETE FROM subscription.plan_items WHERE plan_item_id = $1`
	result, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to delete plan item", zap.Error(err))
		return fmt.Errorf("delete plan item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
