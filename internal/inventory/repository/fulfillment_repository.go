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

type FulfillmentRepository interface {
	CreateOrder(ctx context.Context, db DBTX, order *models.FulfillmentOrder) error
	GetOrderByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FulfillmentOrder, error)
	UpdateOrderStatus(ctx context.Context, db DBTX, id uuid.UUID, status string) error
	GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, refType string, refID uuid.UUID) ([]*models.FulfillmentOrder, error)
	ListOrders(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, p Pagination, s Sort) ([]*models.FulfillmentOrder, int64, error)

	AddOrderItems(ctx context.Context, db DBTX, items []*models.FulfillmentOrderItem) error
	GetOrderItems(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*models.FulfillmentOrderItem, error)
	UpdateFulfilledQty(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID, fulfilledQty decimal.Decimal, backorderedQty decimal.Decimal) error
	DeleteOrderItems(ctx context.Context, db DBTX, orderID uuid.UUID) error
}

type fulfillmentRepository struct {
	logger *zap.Logger
}

func NewFulfillmentRepository(logger *zap.Logger) FulfillmentRepository {
	return &fulfillmentRepository{
		logger: logger.Named("fulfillment_repo"),
	}
}

func (r *fulfillmentRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *fulfillmentRepository) validatePagination(p Pagination) (int, int) {
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

// ---------- Fulfillment Orders ----------

func (r *fulfillmentRepository) scanOrder(s scanner) (*models.FulfillmentOrder, error) {
	var order models.FulfillmentOrder
	err := s.Scan(
		&order.FulfillmentOrderID,
		&order.CompanyID,
		&order.ReferenceType,
		&order.ReferenceID,
		&order.WarehouseID,
		&order.Status,
		&order.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan fulfillment order: %w", err)
	}
	return &order, nil
}

func (r *fulfillmentRepository) CreateOrder(ctx context.Context, db DBTX, order *models.FulfillmentOrder) error {
	query := `
		INSERT INTO fulfillment_orders (
			fulfillment_order_id, company_id, reference_type, reference_id, warehouse_id, status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		order.FulfillmentOrderID, order.CompanyID, order.ReferenceType, order.ReferenceID,
		order.WarehouseID, order.Status,
	).Scan(&order.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create fulfillment order", util.ErrorField(err))
		return fmt.Errorf("create fulfillment order: %w", err)
	}
	return nil
}

func (r *fulfillmentRepository) GetOrderByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FulfillmentOrder, error) {
	query := `
		SELECT fulfillment_order_id, company_id, reference_type, reference_id, warehouse_id, status, created_at
		FROM fulfillment_orders
		WHERE fulfillment_order_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanOrder(row)
}

func (r *fulfillmentRepository) UpdateOrderStatus(ctx context.Context, db DBTX, id uuid.UUID, status string) error {
	query := `UPDATE fulfillment_orders SET status = $2 WHERE fulfillment_order_id = $1`
	res, err := db.ExecContext(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("update fulfillment order status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: fulfillment order %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *fulfillmentRepository) GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, refType string, refID uuid.UUID) ([]*models.FulfillmentOrder, error) {
	query := `
		SELECT fulfillment_order_id, company_id, reference_type, reference_id, warehouse_id, status, created_at
		FROM fulfillment_orders
		WHERE company_id = $1 AND reference_type = $2 AND reference_id = $3
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, refType, refID)
	if err != nil {
		return nil, fmt.Errorf("get by reference: %w", err)
	}
	defer rows.Close()

	var result []*models.FulfillmentOrder
	for rows.Next() {
		o, err := r.scanOrder(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

func (r *fulfillmentRepository) ListOrders(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, p Pagination, s Sort) ([]*models.FulfillmentOrder, int64, error) {
	conds := []string{"company_id = $1"}
	args := []interface{}{companyID}
	idx := 2

	if status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *status)
		idx++
	}

	where := fmt.Sprintf("WHERE %s", strings.Join(conds, " AND "))

	allowedSort := map[string]bool{"created_at": true, "status": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM fulfillment_orders %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count fulfillment orders: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT fulfillment_order_id, company_id, reference_type, reference_id, warehouse_id, status, created_at
		FROM fulfillment_orders
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list fulfillment orders: %w", err)
	}
	defer rows.Close()

	var result []*models.FulfillmentOrder
	for rows.Next() {
		o, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, o)
	}
	return result, total, rows.Err()
}

// ---------- Fulfillment Order Items ----------

func (r *fulfillmentRepository) scanOrderItem(s scanner) (*models.FulfillmentOrderItem, error) {
	var item models.FulfillmentOrderItem
	err := s.Scan(
		&item.FulfillmentItemID,
		&item.FulfillmentOrderID,
		&item.ItemID,
		&item.OrderedQty,
		&item.FulfilledQty,
		&item.BackorderedQty,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan fulfillment order item: %w", err)
	}
	return &item, nil
}

func (r *fulfillmentRepository) AddOrderItems(ctx context.Context, db DBTX, items []*models.FulfillmentOrderItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO fulfillment_order_items (
			fulfillment_item_id, fulfillment_order_id, item_id, ordered_qty, fulfilled_qty, backordered_qty
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	for _, it := range items {
		_, err := db.ExecContext(ctx, query,
			it.FulfillmentItemID, it.FulfillmentOrderID, it.ItemID,
			it.OrderedQty, it.FulfilledQty, it.BackorderedQty,
		)
		if err != nil {
			return fmt.Errorf("add fulfillment order item: %w", err)
		}
	}
	return nil
}

func (r *fulfillmentRepository) GetOrderItems(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*models.FulfillmentOrderItem, error) {
	query := `
		SELECT fulfillment_item_id, fulfillment_order_id, item_id, ordered_qty, fulfilled_qty, backordered_qty
		FROM fulfillment_order_items
		WHERE fulfillment_order_id = $1
		ORDER BY fulfillment_item_id
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get order items: %w", err)
	}
	defer rows.Close()

	var result []*models.FulfillmentOrderItem
	for rows.Next() {
		it, err := r.scanOrderItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, it)
	}
	return result, rows.Err()
}

func (r *fulfillmentRepository) UpdateFulfilledQty(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID, fulfilledQty decimal.Decimal, backorderedQty decimal.Decimal) error {
	query := `
		UPDATE fulfillment_order_items
		SET fulfilled_qty = $2, backordered_qty = $3
		WHERE fulfillment_item_id = $1
	`
	res, err := db.ExecContext(ctx, query, fulfillmentItemID, fulfilledQty, backorderedQty)
	if err != nil {
		return fmt.Errorf("update fulfilled quantity: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: fulfillment item %s", inventory_errors.ErrNotFound, fulfillmentItemID)
	}
	return nil
}

func (r *fulfillmentRepository) DeleteOrderItems(ctx context.Context, db DBTX, orderID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM fulfillment_order_items WHERE fulfillment_order_id = $1`, orderID)
	if err != nil {
		return fmt.Errorf("delete order items: %w", err)
	}
	return nil
}
