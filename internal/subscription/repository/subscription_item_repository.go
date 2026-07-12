// FILE: repository/subscription_item_repository.go

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
// DBTX, Pagination, Sort (common definitions)
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// SubscriptionItemRepository Interface
// -------------------------------------------------------------------------

type SubscriptionItemRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, item *models.SubscriptionItem) error
	BulkCreate(ctx context.Context, db DBTX, items []*models.SubscriptionItem) error

	GetByID(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error)
	Update(ctx context.Context, db DBTX, item *models.SubscriptionItem) error
	Delete(ctx context.Context, db DBTX, subItemID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Bulk Operations
	// -------------------------------------------------------------------------

	ReplaceBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, items []*models.SubscriptionItem) error
	DeleteBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, subItemID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, subItemID uuid.UUID) error
	UpdateStatus(ctx context.Context, db DBTX, subItemID uuid.UUID, status enums.ItemStatus) error

	// -------------------------------------------------------------------------
	// Pricing
	// -------------------------------------------------------------------------

	UpdateQuantity(ctx context.Context, db DBTX, subItemID uuid.UUID, quantity decimal.Decimal) error
	UpdatePrice(ctx context.Context, db DBTX, subItemID uuid.UUID, unitPrice decimal.Decimal, currency string) error
	UpdateDates(ctx context.Context, db DBTX, subItemID uuid.UUID, startDate time.Time, endDate *time.Time) error

	// -------------------------------------------------------------------------
	// Invoice Mapping
	// -------------------------------------------------------------------------

	AddInvoiceItemMapping(ctx context.Context, db DBTX, mapping *models.SubscriptionInvoiceItemMap) error
	DeleteInvoiceItemMapping(ctx context.Context, db DBTX, mapID uuid.UUID) error
	GetInvoiceMappings(ctx context.Context, db DBTX, subItemID uuid.UUID) ([]*models.SubscriptionInvoiceItemMap, error)
	GetInvoiceMapping(ctx context.Context, db DBTX, mapID uuid.UUID) (*models.SubscriptionInvoiceItemMap, error)

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error)
	ExistsByPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (bool, error)
	IsActive(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error)
	HasAddon(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter SubscriptionItemFilter, p Pagination, s Sort) ([]*models.SubscriptionItem, int64, error)
	Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error)
	GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetActiveBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetByAddon(ctx context.Context, db DBTX, addonID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetByProduct(ctx context.Context, db DBTX, productID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetExpiringBetween(ctx context.Context, db DBTX, from, to time.Time) ([]*models.SubscriptionItem, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort (reused)
// -------------------------------------------------------------------------

type SubscriptionItemFilter struct {
	SubItemIDs     []uuid.UUID
	SubscriptionID *uuid.UUID
	PlanItemID     *uuid.UUID
	AddonID        *uuid.UUID
	ProductID      *uuid.UUID
	Status         *enums.ItemStatus
	Currency       *string

	QuantityMin *decimal.Decimal
	QuantityMax *decimal.Decimal

	UnitPriceMin *decimal.Decimal
	UnitPriceMax *decimal.Decimal

	StartDateFrom *time.Time
	StartDateTo   *time.Time

	EndDateFrom *time.Time
	EndDateTo   *time.Time

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type subscriptionItemRepository struct {
	logger *zap.Logger
}

func NewSubscriptionItemRepository(logger *zap.Logger) SubscriptionItemRepository {
	return &subscriptionItemRepository{
		logger: logger.Named("subscription_item_repo"),
	}
}

// -------------------------------------------------------------------------
// Helper: convert int status_id back to enums.ItemStatus
// -------------------------------------------------------------------------

func statusIDToItemStatus(id int) enums.ItemStatus {
	switch id {
	case 7:
		return enums.ItemStatusActive
	case 8:
		return enums.ItemStatusInactive
	default:
		return enums.ItemStatusActive
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) Create(ctx context.Context, db DBTX, item *models.SubscriptionItem) error {
	query := `
		INSERT INTO subscription.subscription_items (
			sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at, product_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := db.ExecContext(ctx, query,
		item.SubItemID,
		item.SubscriptionID,
		item.PlanItemID,
		item.AddonID,
		item.Quantity,
		item.UnitPrice,
		item.Currency,
		item.Status.ToStatusID(),
		item.StartDate,
		item.EndDate,
		item.Metadata,
		item.CreatedAt,
		item.UpdatedAt,
		item.ProductID,
	)
	if err != nil {
		r.logger.Error("failed to create subscription item", zap.Error(err))
		return fmt.Errorf("create subscription item: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) BulkCreate(ctx context.Context, db DBTX, items []*models.SubscriptionItem) error {
	if len(items) == 0 {
		return nil
	}

	valueStrings := make([]string, 0, len(items))
	args := make([]interface{}, 0, len(items)*14)
	argPos := 1
	for _, item := range items {
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argPos, argPos+1, argPos+2, argPos+3, argPos+4, argPos+5, argPos+6,
			argPos+7, argPos+8, argPos+9, argPos+10, argPos+11, argPos+12, argPos+13,
		))
		args = append(args,
			item.SubItemID,
			item.SubscriptionID,
			item.PlanItemID,
			item.AddonID,
			item.Quantity,
			item.UnitPrice,
			item.Currency,
			item.Status.ToStatusID(),
			item.StartDate,
			item.EndDate,
			item.Metadata,
			item.CreatedAt,
			item.UpdatedAt,
			item.ProductID,
		)
		argPos += 14
	}

	query := fmt.Sprintf(`
		INSERT INTO subscription.subscription_items (
			sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at, product_id
		) VALUES %s
	`, strings.Join(valueStrings, ","))

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create subscription items", zap.Error(err))
		return fmt.Errorf("bulk create subscription items: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) GetByID(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE sub_item_id = $1`
	var item models.SubscriptionItem
	err := r.scanItem(ctx, db, query, &item, subItemID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (r *subscriptionItemRepository) Update(ctx context.Context, db DBTX, item *models.SubscriptionItem) error {
	query := `
		UPDATE subscription.subscription_items
		SET subscription_id = $1,
		    plan_item_id = $2,
		    addon_id = $3,
		    quantity = $4,
		    unit_price = $5,
		    currency = $6,
		    status_id = $7,
		    start_date = $8,
		    end_date = $9,
		    metadata = $10,
		    updated_at = NOW(),
		    product_id = $11
		WHERE sub_item_id = $12
	`
	_, err := db.ExecContext(ctx, query,
		item.SubscriptionID,
		item.PlanItemID,
		item.AddonID,
		item.Quantity,
		item.UnitPrice,
		item.Currency,
		item.Status.ToStatusID(),
		item.StartDate,
		item.EndDate,
		item.Metadata,
		item.ProductID,
		item.SubItemID,
	)
	if err != nil {
		r.logger.Error("failed to update subscription item", zap.Error(err))
		return fmt.Errorf("update subscription item: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) Delete(ctx context.Context, db DBTX, subItemID uuid.UUID) error {
	query := `DELETE FROM subscription.subscription_items WHERE sub_item_id = $1`
	result, err := db.ExecContext(ctx, query, subItemID)
	if err != nil {
		r.logger.Error("failed to delete subscription item", zap.Error(err))
		return fmt.Errorf("delete subscription item: %w", err)
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

func (r *subscriptionItemRepository) ReplaceBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, items []*models.SubscriptionItem) error {
	if err := r.DeleteBySubscription(ctx, db, subscriptionID); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	return r.BulkCreate(ctx, db, items)
}

func (r *subscriptionItemRepository) DeleteBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) error {
	query := `DELETE FROM subscription.subscription_items WHERE subscription_id = $1`
	_, err := db.ExecContext(ctx, query, subscriptionID)
	if err != nil {
		r.logger.Error("failed to delete items by subscription", zap.Error(err))
		return fmt.Errorf("delete items by subscription: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) Activate(ctx context.Context, db DBTX, subItemID uuid.UUID) error {
	return r.updateStatus(ctx, db, subItemID, enums.ItemStatusActive)
}

func (r *subscriptionItemRepository) Deactivate(ctx context.Context, db DBTX, subItemID uuid.UUID) error {
	return r.updateStatus(ctx, db, subItemID, enums.ItemStatusInactive)
}

func (r *subscriptionItemRepository) UpdateStatus(ctx context.Context, db DBTX, subItemID uuid.UUID, status enums.ItemStatus) error {
	return r.updateStatus(ctx, db, subItemID, status)
}

func (r *subscriptionItemRepository) updateStatus(ctx context.Context, db DBTX, subItemID uuid.UUID, status enums.ItemStatus) error {
	query := `UPDATE subscription.subscription_items SET status_id = $1, updated_at = NOW() WHERE sub_item_id = $2`
	_, err := db.ExecContext(ctx, query, status.ToStatusID(), subItemID)
	if err != nil {
		r.logger.Error("failed to update subscription item status", zap.Error(err))
		return fmt.Errorf("update subscription item status: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Pricing
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) UpdateQuantity(ctx context.Context, db DBTX, subItemID uuid.UUID, quantity decimal.Decimal) error {
	query := `UPDATE subscription.subscription_items SET quantity = $1, updated_at = NOW() WHERE sub_item_id = $2`
	_, err := db.ExecContext(ctx, query, quantity, subItemID)
	if err != nil {
		r.logger.Error("failed to update quantity", zap.Error(err))
		return fmt.Errorf("update quantity: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) UpdatePrice(ctx context.Context, db DBTX, subItemID uuid.UUID, unitPrice decimal.Decimal, currency string) error {
	query := `UPDATE subscription.subscription_items SET unit_price = $1, currency = $2, updated_at = NOW() WHERE sub_item_id = $3`
	_, err := db.ExecContext(ctx, query, unitPrice, currency, subItemID)
	if err != nil {
		r.logger.Error("failed to update price", zap.Error(err))
		return fmt.Errorf("update price: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) UpdateDates(ctx context.Context, db DBTX, subItemID uuid.UUID, startDate time.Time, endDate *time.Time) error {
	query := `UPDATE subscription.subscription_items SET start_date = $1, end_date = $2, updated_at = NOW() WHERE sub_item_id = $3`
	_, err := db.ExecContext(ctx, query, startDate, endDate, subItemID)
	if err != nil {
		r.logger.Error("failed to update dates", zap.Error(err))
		return fmt.Errorf("update dates: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Invoice Mapping
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) AddInvoiceItemMapping(ctx context.Context, db DBTX, mapping *models.SubscriptionInvoiceItemMap) error {
	query := `
		INSERT INTO subscription.subscription_invoice_item_map (
			map_id, subscription_item_id, invoice_item_id, allocated_quantity, created_at
		) VALUES ($1, $2, $3, $4, $5)
	`
	_, err := db.ExecContext(ctx, query,
		mapping.MapID,
		mapping.SubscriptionItemID,
		mapping.InvoiceItemID,
		mapping.AllocatedQuantity,
		mapping.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to add invoice item mapping", zap.Error(err))
		return fmt.Errorf("add invoice item mapping: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) DeleteInvoiceItemMapping(ctx context.Context, db DBTX, mapID uuid.UUID) error {
	query := `DELETE FROM subscription.subscription_invoice_item_map WHERE map_id = $1`
	_, err := db.ExecContext(ctx, query, mapID)
	if err != nil {
		r.logger.Error("failed to delete invoice item mapping", zap.Error(err))
		return fmt.Errorf("delete invoice item mapping: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) GetInvoiceMappings(ctx context.Context, db DBTX, subItemID uuid.UUID) ([]*models.SubscriptionInvoiceItemMap, error) {
	query := `
		SELECT map_id, subscription_item_id, invoice_item_id, allocated_quantity, created_at
		FROM subscription.subscription_invoice_item_map
		WHERE subscription_item_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, subItemID)
	if err != nil {
		return nil, fmt.Errorf("get invoice mappings: %w", err)
	}
	defer rows.Close()

	var mappings []*models.SubscriptionInvoiceItemMap
	for rows.Next() {
		var m models.SubscriptionInvoiceItemMap
		if err := rows.Scan(&m.MapID, &m.SubscriptionItemID, &m.InvoiceItemID, &m.AllocatedQuantity, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		mappings = append(mappings, &m)
	}
	return mappings, rows.Err()
}

func (r *subscriptionItemRepository) GetInvoiceMapping(ctx context.Context, db DBTX, mapID uuid.UUID) (*models.SubscriptionInvoiceItemMap, error) {
	query := `
		SELECT map_id, subscription_item_id, invoice_item_id, allocated_quantity, created_at
		FROM subscription.subscription_invoice_item_map
		WHERE map_id = $1
	`
	var m models.SubscriptionInvoiceItemMap
	err := db.QueryRowContext(ctx, query, mapID).Scan(
		&m.MapID, &m.SubscriptionItemID, &m.InvoiceItemID, &m.AllocatedQuantity, &m.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get invoice mapping: %w", err)
	}
	return &m, nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) Exists(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_items WHERE sub_item_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, subItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return exists, nil
}

func (r *subscriptionItemRepository) ExistsByPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_items WHERE subscription_id = $1 AND plan_item_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, subscriptionID, planItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists by plan item: %w", err)
	}
	return exists, nil
}

func (r *subscriptionItemRepository) IsActive(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error) {
	activeID := enums.ItemStatusActive.ToStatusID()
	query := `SELECT status_id = $1 FROM subscription.subscription_items WHERE sub_item_id = $2`
	var active bool
	err := db.QueryRowContext(ctx, query, activeID, subItemID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check active: %w", err)
	}
	return active, nil
}

func (r *subscriptionItemRepository) HasAddon(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error) {
	query := `SELECT addon_id IS NOT NULL FROM subscription.subscription_items WHERE sub_item_id = $1`
	var has bool
	err := db.QueryRowContext(ctx, query, subItemID).Scan(&has)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check has addon: %w", err)
	}
	return has, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) List(ctx context.Context, db DBTX, filter SubscriptionItemFilter, p Pagination, s Sort) ([]*models.SubscriptionItem, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.subscription_items %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count items: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionItem{}, 0, nil
	}

	// Sort
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
		%s %s %s
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list items: %w", err)
	}
	defer rows.Close()

	var items []*models.SubscriptionItem
	for rows.Next() {
		var item models.SubscriptionItem
		if err := r.scanItemRows(rows, &item); err != nil {
			return nil, 0, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, &item)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return items, total, nil
}

func (r *subscriptionItemRepository) Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error) {
	searchPattern := "%" + query + "%"
	where := `si.subscription_id = $1 AND (pi.name ILIKE $2 OR si.metadata::text ILIKE $2)`
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM subscription.subscription_items si
		LEFT JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		WHERE %s
	`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, subscriptionID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionItem{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT si.sub_item_id, si.subscription_id, si.plan_item_id, si.addon_id,
		       si.quantity, si.unit_price, si.currency, si.status_id,
		       si.start_date, si.end_date, si.metadata, si.created_at, si.updated_at, si.product_id
		FROM subscription.subscription_items si
		LEFT JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		WHERE %s
		ORDER BY si.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, subscriptionID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search items: %w", err)
	}
	defer rows.Close()

	var items []*models.SubscriptionItem
	for rows.Next() {
		var item models.SubscriptionItem
		if err := r.scanItemRows(rows, &item); err != nil {
			return nil, 0, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, &item)
	}
	return items, total, rows.Err()
}

func (r *subscriptionItemRepository) GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE subscription_id = $1 ORDER BY created_at`
	rows, err := db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get by subscription: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

func (r *subscriptionItemRepository) GetActiveBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	activeID := enums.ItemStatusActive.ToStatusID()
	query := r.buildSelectQuery() + ` WHERE subscription_id = $1 AND status_id = $2 ORDER BY created_at`
	rows, err := db.QueryContext(ctx, query, subscriptionID, activeID)
	if err != nil {
		return nil, fmt.Errorf("get active by subscription: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

func (r *subscriptionItemRepository) GetByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE plan_item_id = $1 ORDER BY created_at`
	rows, err := db.QueryContext(ctx, query, planItemID)
	if err != nil {
		return nil, fmt.Errorf("get by plan item: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

func (r *subscriptionItemRepository) GetByAddon(ctx context.Context, db DBTX, addonID uuid.UUID) ([]*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE addon_id = $1 ORDER BY created_at`
	rows, err := db.QueryContext(ctx, query, addonID)
	if err != nil {
		return nil, fmt.Errorf("get by addon: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

func (r *subscriptionItemRepository) GetByProduct(ctx context.Context, db DBTX, productID uuid.UUID) ([]*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE product_id = $1 ORDER BY created_at`
	rows, err := db.QueryContext(ctx, query, productID)
	if err != nil {
		return nil, fmt.Errorf("get by product: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

func (r *subscriptionItemRepository) GetExpiringBetween(ctx context.Context, db DBTX, from, to time.Time) ([]*models.SubscriptionItem, error) {
	activeID := enums.ItemStatusActive.ToStatusID()
	query := r.buildSelectQuery() + `
		WHERE end_date BETWEEN $1 AND $2 AND status_id = $3
		ORDER BY end_date
	`
	rows, err := db.QueryContext(ctx, query, from, to, activeID)
	if err != nil {
		return nil, fmt.Errorf("get expiring between: %w", err)
	}
	defer rows.Close()
	return r.collectItems(rows)
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) GetByIDForUpdate(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error) {
	query := r.buildSelectQuery() + ` WHERE sub_item_id = $1 FOR UPDATE`
	var item models.SubscriptionItem
	err := r.scanItem(ctx, db, query, &item, subItemID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *subscriptionItemRepository) buildSelectQuery() string {
	return `
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
		       quantity, unit_price, currency, status_id,
		       start_date, end_date, metadata, created_at, updated_at, product_id
		FROM subscription.subscription_items
	`
}

func (r *subscriptionItemRepository) scanItem(ctx context.Context, db DBTX, query string, item *models.SubscriptionItem, args ...interface{}) error {
	var statusID int
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&item.SubItemID,
		&item.SubscriptionID,
		&item.PlanItemID,
		&item.AddonID,
		&item.Quantity,
		&item.UnitPrice,
		&item.Currency,
		&statusID,
		&item.StartDate,
		&item.EndDate,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.ProductID,
	)
	if err != nil {
		return err
	}
	item.Status = statusIDToItemStatus(statusID)
	return nil
}

func (r *subscriptionItemRepository) scanItemRows(rows *sql.Rows, item *models.SubscriptionItem) error {
	var statusID int
	err := rows.Scan(
		&item.SubItemID,
		&item.SubscriptionID,
		&item.PlanItemID,
		&item.AddonID,
		&item.Quantity,
		&item.UnitPrice,
		&item.Currency,
		&statusID,
		&item.StartDate,
		&item.EndDate,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.ProductID,
	)
	if err != nil {
		return err
	}
	item.Status = statusIDToItemStatus(statusID)
	return nil
}

func (r *subscriptionItemRepository) collectItems(rows *sql.Rows) ([]*models.SubscriptionItem, error) {
	var items []*models.SubscriptionItem
	for rows.Next() {
		var item models.SubscriptionItem
		if err := r.scanItemRows(rows, &item); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (r *subscriptionItemRepository) buildFilterConditions(filter SubscriptionItemFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.SubItemIDs) > 0 {
		placeholders := make([]string, len(filter.SubItemIDs))
		for i, id := range filter.SubItemIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("sub_item_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.SubItemIDs)
	}

	if filter.SubscriptionID != nil {
		conditions = append(conditions, fmt.Sprintf("subscription_id = $%d", argPos))
		args = append(args, *filter.SubscriptionID)
		argPos++
	}

	if filter.PlanItemID != nil {
		conditions = append(conditions, fmt.Sprintf("plan_item_id = $%d", argPos))
		args = append(args, *filter.PlanItemID)
		argPos++
	}

	if filter.AddonID != nil {
		conditions = append(conditions, fmt.Sprintf("addon_id = $%d", argPos))
		args = append(args, *filter.AddonID)
		argPos++
	}

	if filter.ProductID != nil {
		conditions = append(conditions, fmt.Sprintf("product_id = $%d", argPos))
		args = append(args, *filter.ProductID)
		argPos++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status_id = $%d", argPos))
		args = append(args, filter.Status.ToStatusID())
		argPos++
	}

	if filter.Currency != nil {
		conditions = append(conditions, fmt.Sprintf("currency = $%d", argPos))
		args = append(args, *filter.Currency)
		argPos++
	}

	if filter.QuantityMin != nil {
		conditions = append(conditions, fmt.Sprintf("quantity >= $%d", argPos))
		args = append(args, *filter.QuantityMin)
		argPos++
	}
	if filter.QuantityMax != nil {
		conditions = append(conditions, fmt.Sprintf("quantity <= $%d", argPos))
		args = append(args, *filter.QuantityMax)
		argPos++
	}

	if filter.UnitPriceMin != nil {
		conditions = append(conditions, fmt.Sprintf("unit_price >= $%d", argPos))
		args = append(args, *filter.UnitPriceMin)
		argPos++
	}
	if filter.UnitPriceMax != nil {
		conditions = append(conditions, fmt.Sprintf("unit_price <= $%d", argPos))
		args = append(args, *filter.UnitPriceMax)
		argPos++
	}

	addDateRange(&conditions, &args, &argPos, "start_date", filter.StartDateFrom, filter.StartDateTo)
	addDateRange(&conditions, &args, &argPos, "end_date", filter.EndDateFrom, filter.EndDateTo)
	addDateRange(&conditions, &args, &argPos, "created_at", filter.CreatedFrom, filter.CreatedTo)
	addDateRange(&conditions, &args, &argPos, "updated_at", filter.UpdatedFrom, filter.UpdatedTo)

	return conditions, args
}

// -------------------------------------------------------------------------
// Utility function for date ranges
// -------------------------------------------------------------------------
