// repository/item_repository.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/util"
)

// ErrInvalidSortField indicates that the provided sort field is not allowed.
var ErrInvalidSortField = errors.New("invalid sort field")

// ItemFilter for listing/filtering items
type ItemFilter struct {
	CompanyID uuid.UUID
	ItemType  *string // enums.ItemType as string
	IsActive  *bool
	Search    string // searches SKU, name, description
}

// ReorderItem result for reorder/low stock reporting
type ReorderItem struct {
	ItemID          uuid.UUID       `json:"itemId"`
	SKU             string          `json:"sku"`
	Name            string          `json:"name"`
	ReorderLevel    decimal.Decimal `json:"reorderLevel"`
	ReorderQuantity decimal.Decimal `json:"reorderQuantity"`
	AvailableQty    decimal.Decimal `json:"availableQty"`
}

// ItemRepository interface
type ItemRepository interface {
	// Core CRUD
	Create(ctx context.Context, db DBTX, item *models.Item) error
	BulkCreate(ctx context.Context, db DBTX, items []*models.Item) error
	GetByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.Item, error)
	GetByIDs(ctx context.Context, db DBTX, itemIDs []uuid.UUID) ([]*models.Item, error)
	GetBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (*models.Item, error)
	Update(ctx context.Context, db DBTX, item *models.Item) error
	Delete(ctx context.Context, db DBTX, itemID uuid.UUID) error // soft delete
	ExistsBySKUExcludingID(ctx context.Context, db DBTX, companyID uuid.UUID, sku string, excludeID uuid.UUID) (bool, error)

	// Listing & filtering
	List(ctx context.Context, db DBTX, filter ItemFilter, p Pagination, s Sort) ([]*models.Item, error)
	Count(ctx context.Context, db DBTX, filter ItemFilter) (int64, error)
	GetAllActiveItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Item, error)

	// Business queries
	GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, p Pagination, s Sort) ([]*models.Item, error)
	GetActiveItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Item, error)
	GetByType(ctx context.Context, db DBTX, companyID uuid.UUID, itemType enums.ItemType) ([]*models.Item, error)
	SearchItems(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int) ([]*models.Item, error)

	// Inventory / reorder support
	GetReorderItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*ReorderItem, error)
	GetLowStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*ReorderItem, error)

	// Validation helpers
	ExistsBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (bool, error)
	ExistsByID(ctx context.Context, db DBTX, itemID uuid.UUID) (bool, error)
}

type itemRepository struct {
	logger *zap.Logger
}

func NewItemRepository(logger *zap.Logger) ItemRepository {
	return &itemRepository{
		logger: logger.Named("item_repo"),
	}
}

// ---------- helpers ----------
func (r *itemRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		// Empty field is acceptable, use default
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("%w: %s", ErrInvalidSortField, s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *itemRepository) validatePagination(p Pagination) (int, int) {
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

func (r *itemRepository) buildItemFilter(filter ItemFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ItemType != nil && *filter.ItemType != "" {
		conds = append(conds, fmt.Sprintf("item_type = $%d", idx))
		args = append(args, *filter.ItemType)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("(sku ILIKE $%d OR name ILIKE $%d OR description ILIKE $%d)", idx, idx+1, idx+2))
		args = append(args, searchTerm, searchTerm, searchTerm)
		idx += 3
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Core CRUD ----------
func (r *itemRepository) Create(ctx context.Context, db DBTX, item *models.Item) error {
	query := `
		INSERT INTO items (
			item_id, company_id, sku, name, description, item_type, unit_of_measure,
			valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
			last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
			track_inventory, allow_negative_stock, is_sellable, is_purchasable,
			requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW(), $15, $16,
		          $17, $18, $19, $20, $21, $22, $23, $24)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.ItemID, item.CompanyID, item.SKU, item.Name, item.Description,
		string(item.ItemType), item.UnitOfMeasure, string(item.ValuationMethod),
		item.StandardCost, item.SellingPrice, item.ReorderLevel, item.ReorderQuantity,
		item.LastReorderedAt, item.IsActive, item.CreatedBy, item.UpdatedBy,
		item.TrackInventory, item.AllowNegativeStock, item.IsSellable, item.IsPurchasable,
		item.RequiresShipping, item.IsBatchTracked, item.IsSerialTracked, string(item.FulfillmentPolicy),
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create item", util.ErrorField(err))
		return fmt.Errorf("create item: %w", err)
	}
	return nil
}

func (r *itemRepository) BulkCreate(ctx context.Context, db DBTX, items []*models.Item) error {
	if len(items) == 0 {
		return nil
	}
	// Individual inserts to retrieve timestamps (batch size is expected to be small)
	for _, item := range items {
		query := `
			INSERT INTO items (
				item_id, company_id, sku, name, description, item_type, unit_of_measure,
				valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
				last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
				track_inventory, allow_negative_stock, is_sellable, is_purchasable,
				requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW(), $15, $16,
			          $17, $18, $19, $20, $21, $22, $23, $24)
			RETURNING created_at, updated_at
		`
		err := db.QueryRowContext(ctx, query,
			item.ItemID, item.CompanyID, item.SKU, item.Name, item.Description,
			string(item.ItemType), item.UnitOfMeasure, string(item.ValuationMethod),
			item.StandardCost, item.SellingPrice, item.ReorderLevel, item.ReorderQuantity,
			item.LastReorderedAt, item.IsActive, item.CreatedBy, item.UpdatedBy,
			item.TrackInventory, item.AllowNegativeStock, item.IsSellable, item.IsPurchasable,
			item.RequiresShipping, item.IsBatchTracked, item.IsSerialTracked, string(item.FulfillmentPolicy),
		).Scan(&item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			return fmt.Errorf("bulk create item: %w", err)
		}
	}
	return nil
}

func (r *itemRepository) GetByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.Item, error) {
	query := `
		SELECT item_id, company_id, sku, name, description, item_type, unit_of_measure,
		       valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
		       last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
		       track_inventory, allow_negative_stock, is_sellable, is_purchasable,
		       requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
		FROM items WHERE item_id = $1
	`
	row := db.QueryRowContext(ctx, query, itemID)
	return r.scanItem(row)
}

func (r *itemRepository) GetByIDs(ctx context.Context, db DBTX, itemIDs []uuid.UUID) ([]*models.Item, error) {
	if len(itemIDs) == 0 {
		return []*models.Item{}, nil
	}
	placeholders := make([]string, len(itemIDs))
	args := make([]interface{}, len(itemIDs))
	for i, id := range itemIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT item_id, company_id, sku, name, description, item_type, unit_of_measure,
		       valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
		       last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
		       track_inventory, allow_negative_stock, is_sellable, is_purchasable,
		       requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
		FROM items WHERE item_id IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get items by ids: %w", err)
	}
	defer rows.Close()

	var result []*models.Item
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *itemRepository) GetBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (*models.Item, error) {
	query := `
		SELECT item_id, company_id, sku, name, description, item_type, unit_of_measure,
		       valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
		       last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
		       track_inventory, allow_negative_stock, is_sellable, is_purchasable,
		       requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
		FROM items WHERE company_id = $1 AND sku = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, sku)
	return r.scanItem(row)
}

func (r *itemRepository) Update(ctx context.Context, db DBTX, item *models.Item) error {
	query := `
		UPDATE items SET
			sku = $2,
			name = $3,
			description = $4,
			item_type = $5,
			unit_of_measure = $6,
			valuation_method = $7,
			standard_cost = $8,
			selling_price = $9,
			reorder_level = $10,
			reorder_quantity = $11,
			last_reordered_at = $12,
			is_active = $13,
			updated_at = NOW(),
			updated_by = $14,
			track_inventory = $15,
			allow_negative_stock = $16,
			is_sellable = $17,
			is_purchasable = $18,
			requires_shipping = $19,
			is_batch_tracked = $20,
			is_serial_tracked = $21,
			fulfillment_policy = $22
		WHERE item_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.ItemID, item.SKU, item.Name, item.Description,
		string(item.ItemType), item.UnitOfMeasure, string(item.ValuationMethod),
		item.StandardCost, item.SellingPrice, item.ReorderLevel, item.ReorderQuantity,
		item.LastReorderedAt, item.IsActive, item.UpdatedBy,
		item.TrackInventory, item.AllowNegativeStock, item.IsSellable, item.IsPurchasable,
		item.RequiresShipping, item.IsBatchTracked, item.IsSerialTracked, string(item.FulfillmentPolicy),
	).Scan(&item.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: item %s", inventory_errors.ErrNotFound, item.ItemID)
		}
		return fmt.Errorf("update item: %w", err)
	}
	return nil
}

// Delete soft-deletes by setting is_active = false
func (r *itemRepository) Delete(ctx context.Context, db DBTX, itemID uuid.UUID) error {
	query := `UPDATE items SET is_active = false, updated_at = NOW() WHERE item_id = $1 RETURNING updated_at`
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, itemID).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: item %s", inventory_errors.ErrNotFound, itemID)
		}
		return fmt.Errorf("delete item: %w", err)
	}
	return nil
}

// ---------- Listing & filtering ----------
func (r *itemRepository) List(ctx context.Context, db DBTX, filter ItemFilter, p Pagination, s Sort) ([]*models.Item, error) {
	where, args := r.buildItemFilter(filter)

	allowedSort := map[string]bool{
		"sku":        true,
		"name":       true,
		"item_type":  true,
		"created_at": true,
		"updated_at": true,
		"item_id":    true, // 🔧 Add this line
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		// Return the error (including ErrInvalidSortField) to the caller
		return nil, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name ASC" // default sort when field is empty
	}

	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT item_id, company_id, sku, name, description, item_type, unit_of_measure,
		       valuation_method, standard_cost, selling_price, reorder_level, reorder_quantity,
		       last_reordered_at, is_active, created_at, updated_at, created_by, updated_by,
		       track_inventory, allow_negative_stock, is_sellable, is_purchasable,
		       requires_shipping, is_batch_tracked, is_serial_tracked, fulfillment_policy
		FROM items i
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer rows.Close()

	var result []*models.Item
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *itemRepository) Count(ctx context.Context, db DBTX, filter ItemFilter) (int64, error) {
	where, args := r.buildItemFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM items i %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count items: %w", err)
	}
	return count, nil
}

// ---------- Business queries ----------
func (r *itemRepository) GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, p Pagination, s Sort) ([]*models.Item, error) {
	filter := ItemFilter{CompanyID: companyID}
	return r.List(ctx, db, filter, p, s)
}

func (r *itemRepository) GetActiveItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Item, error) {
	active := true
	filter := ItemFilter{
		CompanyID: companyID,
		IsActive:  &active,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "name", Direction: "ASC"})
}

func (r *itemRepository) GetByType(ctx context.Context, db DBTX, companyID uuid.UUID, itemType enums.ItemType) ([]*models.Item, error) {
	typ := string(itemType)
	filter := ItemFilter{
		CompanyID: companyID,
		ItemType:  &typ,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "name", Direction: "ASC"})
}

func (r *itemRepository) SearchItems(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int) ([]*models.Item, error) {
	filter := ItemFilter{
		CompanyID: companyID,
		Search:    query,
	}
	p := Pagination{Limit: limit}
	if limit <= 0 {
		p.Limit = 20
	}
	return r.List(ctx, db, filter, p, Sort{Field: "name", Direction: "ASC"})
}

// ---------- Reorder / low stock ----------
func (r *itemRepository) GetReorderItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*ReorderItem, error) {
	query := `
		SELECT i.item_id, i.sku, i.name, COALESCE(i.reorder_level, 0) AS reorder_level,
		       COALESCE(i.reorder_quantity, 0) AS reorder_quantity,
		       COALESCE(SUM(sb.available_qty), 0) AS available_qty
		FROM items i
		LEFT JOIN stock_balances sb ON sb.item_id = i.item_id AND sb.company_id = i.company_id
		WHERE i.company_id = $1
		  AND i.is_active = true
		  AND COALESCE(i.reorder_level, 0) > 0
		GROUP BY i.item_id, i.sku, i.name, i.reorder_level, i.reorder_quantity
		HAVING COALESCE(SUM(sb.available_qty), 0) <= COALESCE(i.reorder_level, 0)
		ORDER BY (COALESCE(SUM(sb.available_qty), 0) / NULLIF(COALESCE(i.reorder_level, 0), 0)) ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get reorder items: %w", err)
	}
	defer rows.Close()

	var items []*ReorderItem
	for rows.Next() {
		var ri ReorderItem
		err := rows.Scan(&ri.ItemID, &ri.SKU, &ri.Name, &ri.ReorderLevel, &ri.ReorderQuantity, &ri.AvailableQty)
		if err != nil {
			return nil, fmt.Errorf("scan reorder item: %w", err)
		}
		items = append(items, &ri)
	}
	return items, rows.Err()
}

func (r *itemRepository) GetLowStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*ReorderItem, error) {
	// Same as reorder but without requiring reorder_level > 0 – includes any low stock
	query := `
		SELECT i.item_id, i.sku, i.name, COALESCE(i.reorder_level, 0) AS reorder_level,
		       COALESCE(i.reorder_quantity, 0) AS reorder_quantity,
		       COALESCE(SUM(sb.available_qty), 0) AS available_qty
		FROM items i
		LEFT JOIN stock_balances sb ON sb.item_id = i.item_id AND sb.company_id = i.company_id
		WHERE i.company_id = $1 AND i.is_active = true
		GROUP BY i.item_id, i.sku, i.name, i.reorder_level, i.reorder_quantity
		HAVING COALESCE(SUM(sb.available_qty), 0) <= COALESCE(i.reorder_level, 0)
		ORDER BY (COALESCE(SUM(sb.available_qty), 0) / NULLIF(COALESCE(i.reorder_level, 0), 0)) ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get low stock items: %w", err)
	}
	defer rows.Close()

	var items []*ReorderItem
	for rows.Next() {
		var ri ReorderItem
		err := rows.Scan(&ri.ItemID, &ri.SKU, &ri.Name, &ri.ReorderLevel, &ri.ReorderQuantity, &ri.AvailableQty)
		if err != nil {
			return nil, fmt.Errorf("scan low stock item: %w", err)
		}
		items = append(items, &ri)
	}
	return items, rows.Err()
}

// ---------- Validation helpers ----------
func (r *itemRepository) ExistsBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM items WHERE company_id = $1 AND sku = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, sku).Scan(&exists)
	return exists, err
}

func (r *itemRepository) ExistsByID(ctx context.Context, db DBTX, itemID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM items WHERE item_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, itemID).Scan(&exists)
	return exists, err
}

// ---------- scanner (includes new behavioral fields) ----------
func (r *itemRepository) scanItem(s scanner) (*models.Item, error) {
	var item models.Item
	var description sql.NullString
	var standardCost, sellingPrice, reorderLevel, reorderQuantity sql.NullFloat64
	var lastReorderedAt sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	var itemTypeStr, valuationMethodStr, fulfillmentPolicyStr string
	var trackInventory, allowNegativeStock, isSellable, isPurchasable, requiresShipping, isBatchTracked, isSerialTracked bool

	err := s.Scan(
		&item.ItemID, &item.CompanyID, &item.SKU, &item.Name, &description,
		&itemTypeStr, &item.UnitOfMeasure, &valuationMethodStr,
		&standardCost, &sellingPrice, &reorderLevel, &reorderQuantity,
		&lastReorderedAt, &item.IsActive, &item.CreatedAt, &item.UpdatedAt,
		&createdBy, &updatedBy,
		&trackInventory, &allowNegativeStock, &isSellable, &isPurchasable,
		&requiresShipping, &isBatchTracked, &isSerialTracked, &fulfillmentPolicyStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan item: %w", err)
	}

	// Convert nullable strings
	if description.Valid {
		item.Description = &description.String
	}
	// Convert enums
	item.ItemType = enums.ItemType(itemTypeStr)
	item.ValuationMethod = enums.ValuationMethod(valuationMethodStr)
	item.FulfillmentPolicy = enums.FulfillmentPolicy(fulfillmentPolicyStr)

	// Convert nullable numeric to *decimal.Decimal
	if standardCost.Valid {
		d := decimal.NewFromFloat(standardCost.Float64)
		item.StandardCost = &d
	}
	if sellingPrice.Valid {
		d := decimal.NewFromFloat(sellingPrice.Float64)
		item.SellingPrice = &d
	}
	if reorderLevel.Valid {
		d := decimal.NewFromFloat(reorderLevel.Float64)
		item.ReorderLevel = &d
	}
	if reorderQuantity.Valid {
		d := decimal.NewFromFloat(reorderQuantity.Float64)
		item.ReorderQuantity = &d
	}
	if lastReorderedAt.Valid {
		item.LastReorderedAt = &lastReorderedAt.Time
	}
	if createdBy.Valid {
		item.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		item.UpdatedBy = &updatedBy.UUID
	}

	// Set new boolean fields
	item.TrackInventory = trackInventory
	item.AllowNegativeStock = allowNegativeStock
	item.IsSellable = isSellable
	item.IsPurchasable = isPurchasable
	item.RequiresShipping = requiresShipping
	item.IsBatchTracked = isBatchTracked
	item.IsSerialTracked = isSerialTracked

	return &item, nil
}

// GetAllActiveItems returns all active items for a company (no pagination, used for batch valuation).
func (r *itemRepository) GetAllActiveItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Item, error) {
	active := true
	filter := ItemFilter{
		CompanyID: companyID,
		IsActive:  &active,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 100000}, Sort{Field: "item_id", Direction: "ASC"})
}
func (r *itemRepository) ExistsBySKUExcludingID(ctx context.Context, db DBTX, companyID uuid.UUID, sku string, excludeID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM items WHERE company_id = $1 AND sku = $2 AND item_id != $3)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, sku, excludeID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check SKU existence excluding ID: %w", err)
	}
	return exists, nil
}
