package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// ShipmentItemRepository defines operations for shipment items.
type ShipmentItemRepository interface {
	Create(ctx context.Context, tx DBTX, item *models.ShipmentItem) error
	GetByShipmentID(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.ShipmentItem, error)
	GetByFulfillmentItemID(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID) ([]*models.ShipmentItem, error)
	List(ctx context.Context, db DBTX, filter ShipmentItemFilter, p Pagination, s Sort) ([]*models.ShipmentItem, error)
	Update(ctx context.Context, tx DBTX, item *models.ShipmentItem) error
	Delete(ctx context.Context, tx DBTX, id uuid.UUID) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ShipmentItem, error) // <-- ADD

}

// ShipmentItemFilter for filtering list results.
type ShipmentItemFilter struct {
	CompanyID          *uuid.UUID
	ShipmentID         *uuid.UUID
	FulfillmentItemID  *uuid.UUID
	MinQuantityShipped *decimal.Decimal
}

type shipmentItemRepository struct {
	logger *zap.Logger
}

// NewShipmentItemRepository creates a new shipment item repository.
func NewShipmentItemRepository(logger *zap.Logger) ShipmentItemRepository {
	return &shipmentItemRepository{
		logger: logger.Named("shipment_item_repo"),
	}
}

// validateSort returns ORDER BY clause for allowed fields.
func (r *shipmentItemRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", fmt.Errorf("sort field required")
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

// validatePagination returns limit and offset.
func (r *shipmentItemRepository) validatePagination(p Pagination) (int, int) {
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

// buildFilter builds WHERE clause for ShipmentItemFilter.
func (r *shipmentItemRepository) buildFilter(filter ShipmentItemFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != nil {
		conds = append(conds, fmt.Sprintf("si.company_id = $%d", idx))
		args = append(args, *filter.CompanyID)
		idx++
	}
	if filter.ShipmentID != nil {
		conds = append(conds, fmt.Sprintf("si.shipment_id = $%d", idx))
		args = append(args, *filter.ShipmentID)
		idx++
	}
	if filter.FulfillmentItemID != nil {
		conds = append(conds, fmt.Sprintf("si.fulfillment_item_id = $%d", idx))
		args = append(args, *filter.FulfillmentItemID)
		idx++
	}
	if filter.MinQuantityShipped != nil {
		conds = append(conds, fmt.Sprintf("si.quantity_shipped >= $%d", idx))
		args = append(args, *filter.MinQuantityShipped)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanShipmentItem scans a single row into a ShipmentItem model.
func (r *shipmentItemRepository) scanShipmentItem(s scanner) (*models.ShipmentItem, error) {
	var item models.ShipmentItem
	err := s.Scan(
		&item.ShipmentItemID,
		&item.ShipmentID,
		&item.FulfillmentItemID,
		&item.QuantityShipped,
		&item.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan shipment item: %w", err)
	}
	return &item, nil
}

// Create inserts a new shipment item.
func (r *shipmentItemRepository) Create(ctx context.Context, tx DBTX, item *models.ShipmentItem) error {
	query := `
		INSERT INTO shipment_items (
			shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
		) VALUES ($1, $2, $3, $4, NOW())
		RETURNING created_at
	`
	err := tx.QueryRowContext(ctx, query,
		item.ShipmentItemID, item.ShipmentID, item.FulfillmentItemID, item.QuantityShipped,
	).Scan(&item.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create shipment item", util.ErrorField(err))
		return fmt.Errorf("create shipment item: %w", err)
	}
	return nil
}

// GetByShipmentID returns all shipment items for a given shipment.
func (r *shipmentItemRepository) GetByShipmentID(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.ShipmentItem, error) {
	query := `
		SELECT shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
		FROM shipment_items
		WHERE shipment_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, shipmentID)
	if err != nil {
		return nil, fmt.Errorf("get by shipment id: %w", err)
	}
	defer rows.Close()

	var items []*models.ShipmentItem
	for rows.Next() {
		it, err := r.scanShipmentItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// GetByFulfillmentItemID returns all shipment items linked to a specific fulfillment order item.
func (r *shipmentItemRepository) GetByFulfillmentItemID(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID) ([]*models.ShipmentItem, error) {
	query := `
		SELECT shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
		FROM shipment_items
		WHERE fulfillment_item_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, fulfillmentItemID)
	if err != nil {
		return nil, fmt.Errorf("get by fulfillment item id: %w", err)
	}
	defer rows.Close()

	var items []*models.ShipmentItem
	for rows.Next() {
		it, err := r.scanShipmentItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// List returns a paginated list of shipment items matching the filter.
func (r *shipmentItemRepository) List(ctx context.Context, db DBTX, filter ShipmentItemFilter, p Pagination, s Sort) ([]*models.ShipmentItem, error) {
	where, args := r.buildFilter(filter)

	allowedSort := map[string]bool{
		"created_at":       true,
		"quantity_shipped": true,
		"shipment_id":      true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}

	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
		FROM shipment_items si
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list shipment items: %w", err)
	}
	defer rows.Close()

	var items []*models.ShipmentItem
	for rows.Next() {
		it, err := r.scanShipmentItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}
func (r *shipmentItemRepository) Update(ctx context.Context, tx DBTX, item *models.ShipmentItem) error {
	query := `UPDATE shipment_items SET quantity_shipped = $2 WHERE shipment_item_id = $1`
	_, err := tx.ExecContext(ctx, query, item.ShipmentItemID, item.QuantityShipped)
	return err
}

func (r *shipmentItemRepository) Delete(ctx context.Context, tx DBTX, id uuid.UUID) error {
	query := `DELETE FROM shipment_items WHERE shipment_item_id = $1`
	_, err := tx.ExecContext(ctx, query, id)
	return err
}
func (r *shipmentItemRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ShipmentItem, error) {
	query := `
        SELECT shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
        FROM shipment_items
        WHERE shipment_item_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanShipmentItem(row)
}
