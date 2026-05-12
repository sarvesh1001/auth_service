package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// TransferOrderFilter defines filtering options for transfer orders
type TransferOrderFilter struct {
	CompanyID       uuid.UUID
	FromWarehouseID *uuid.UUID
	ToWarehouseID   *uuid.UUID
	Status          *string
	DateFrom        *time.Time
	DateTo          *time.Time
	Search          string
}

// TransferOrderRepository defines the interface for stock transfer order operations
type TransferOrderRepository interface {
	// Create creates a new transfer order along with its items (within a transaction)
	Create(ctx context.Context, db DBTX, order *models.StockTransferOrder, items []*models.StockTransferItem) error

	// GetByID retrieves a transfer order by ID
	GetByID(ctx context.Context, db DBTX, transferOrderID uuid.UUID) (*models.StockTransferOrder, error)

	// GetByNumber retrieves a transfer order by company and transfer number
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.StockTransferOrder, error)

	// UpdateStatus updates the status and optionally timestamps (dispatched_at / received_at)
	UpdateStatus(ctx context.Context, db DBTX, transferOrderID uuid.UUID, status string, dispatchedAt, receivedAt *time.Time) error

	// Dispatch marks the order as dispatched and sets dispatched_at
	Dispatch(ctx context.Context, db DBTX, transferOrderID uuid.UUID, dispatchedAt time.Time) error

	// Receive marks the order as received and sets received_at
	Receive(ctx context.Context, db DBTX, transferOrderID uuid.UUID, receivedAt time.Time) error

	// Cancel cancels a transfer order (only if not already dispatched/received)
	Cancel(ctx context.Context, db DBTX, transferOrderID uuid.UUID) error

	// List retrieves transfer orders with optional filters and pagination
	List(ctx context.Context, db DBTX, filter TransferOrderFilter, p Pagination, s Sort) ([]*models.StockTransferOrder, int64, error)

	// AddItems adds items to an existing transfer order
	AddItems(ctx context.Context, db DBTX, transferOrderID uuid.UUID, items []*models.StockTransferItem) error

	// GetItems retrieves all items for a transfer order
	GetItems(ctx context.Context, db DBTX, transferOrderID uuid.UUID) ([]*models.StockTransferItem, error)

	// UpdateItemQuantity updates the quantity of a specific transfer item
	UpdateItemQuantity(ctx context.Context, db DBTX, transferItemID uuid.UUID, quantity decimal.Decimal) error

	// RemoveItem removes an item from a transfer order
	RemoveItem(ctx context.Context, db DBTX, transferItemID uuid.UUID) error

	// ExistsByNumber checks if a transfer number already exists for the company
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error)
}

type transferOrderRepository struct {
	logger *zap.Logger
}

// NewTransferOrderRepository creates a new instance of TransferOrderRepository
func NewTransferOrderRepository(logger *zap.Logger) TransferOrderRepository {
	return &transferOrderRepository{
		logger: logger.Named("transfer_order_repo"),
	}
}

// validateSort validates and formats sort parameters
func (r *transferOrderRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

// validatePagination validates and returns limit/offset
func (r *transferOrderRepository) validatePagination(p Pagination) (int, int) {
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

// buildTransferOrderFilter builds WHERE clause and arguments for filtering
func (r *transferOrderRepository) buildTransferOrderFilter(filter TransferOrderFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.FromWarehouseID != nil {
		conds = append(conds, fmt.Sprintf("from_warehouse_id = $%d", idx))
		args = append(args, *filter.FromWarehouseID)
		idx++
	}
	if filter.ToWarehouseID != nil {
		conds = append(conds, fmt.Sprintf("to_warehouse_id = $%d", idx))
		args = append(args, *filter.ToWarehouseID)
		idx++
	}
	if filter.Status != nil && *filter.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("transfer_number ILIKE $%d", idx))
		args = append(args, search)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanTransferOrder scans a single row into a StockTransferOrder
func (r *transferOrderRepository) scanTransferOrder(s scanner) (*models.StockTransferOrder, error) {
	var order models.StockTransferOrder
	var dispatchedAt, receivedAt sql.NullTime

	err := s.Scan(
		&order.TransferOrderID,
		&order.CompanyID,
		&order.TransferNumber,
		&order.FromWarehouseID,
		&order.ToWarehouseID,
		&order.Status,
		&dispatchedAt,
		&receivedAt,
		&order.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan transfer order: %w", err)
	}

	if dispatchedAt.Valid {
		order.DispatchedAt = &dispatchedAt.Time
	}
	if receivedAt.Valid {
		order.ReceivedAt = &receivedAt.Time
	}

	return &order, nil
}

// scanTransferItem scans a row into StockTransferItem
func (r *transferOrderRepository) scanTransferItem(s scanner) (*models.StockTransferItem, error) {
	var item models.StockTransferItem
	err := s.Scan(
		&item.TransferItemID,
		&item.TransferOrderID,
		&item.ItemID,
		&item.Quantity,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan transfer item: %w", err)
	}
	return &item, nil
}

// Create creates a new transfer order with its items (all in one transaction – caller must provide a transaction)
func (r *transferOrderRepository) Create(ctx context.Context, db DBTX, order *models.StockTransferOrder, items []*models.StockTransferItem) error {
	// Insert the order
	orderQuery := `
		INSERT INTO stock_transfer_orders (
			transfer_order_id, company_id, transfer_number, from_warehouse_id, to_warehouse_id,
			status, dispatched_at, received_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, orderQuery,
		order.TransferOrderID,
		order.CompanyID,
		order.TransferNumber,
		order.FromWarehouseID,
		order.ToWarehouseID,
		order.Status,
		order.DispatchedAt,
		order.ReceivedAt,
	).Scan(&order.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create transfer order", util.ErrorField(err))
		return fmt.Errorf("create transfer order: %w", err)
	}

	// Insert items
	if len(items) > 0 {
		if err := r.AddItems(ctx, db, order.TransferOrderID, items); err != nil {
			return err
		}
	}

	return nil
}

// GetByID retrieves a transfer order by ID
func (r *transferOrderRepository) GetByID(ctx context.Context, db DBTX, transferOrderID uuid.UUID) (*models.StockTransferOrder, error) {
	query := `
		SELECT transfer_order_id, company_id, transfer_number, from_warehouse_id, to_warehouse_id,
		       status, dispatched_at, received_at, created_at
		FROM stock_transfer_orders
		WHERE transfer_order_id = $1
	`
	row := db.QueryRowContext(ctx, query, transferOrderID)
	return r.scanTransferOrder(row)
}

// GetByNumber retrieves a transfer order by company and transfer number
func (r *transferOrderRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.StockTransferOrder, error) {
	query := `
		SELECT transfer_order_id, company_id, transfer_number, from_warehouse_id, to_warehouse_id,
		       status, dispatched_at, received_at, created_at
		FROM stock_transfer_orders
		WHERE company_id = $1 AND transfer_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, number)
	return r.scanTransferOrder(row)
}

// UpdateStatus updates the status and optionally timestamps
func (r *transferOrderRepository) UpdateStatus(ctx context.Context, db DBTX, transferOrderID uuid.UUID, status string, dispatchedAt, receivedAt *time.Time) error {
	query := `
		UPDATE stock_transfer_orders
		SET status = $2, dispatched_at = $3, received_at = $4
		WHERE transfer_order_id = $1
	`
	result, err := db.ExecContext(ctx, query, transferOrderID, status, dispatchedAt, receivedAt)
	if err != nil {
		return fmt.Errorf("update transfer order status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: transfer order %s", inventory_errors.ErrNotFound, transferOrderID)
	}
	return nil
}

// Dispatch marks the order as dispatched
func (r *transferOrderRepository) Dispatch(ctx context.Context, db DBTX, transferOrderID uuid.UUID, dispatchedAt time.Time) error {
	return r.UpdateStatus(ctx, db, transferOrderID, "dispatched", &dispatchedAt, nil)
}

// Receive marks the order as received
func (r *transferOrderRepository) Receive(ctx context.Context, db DBTX, transferOrderID uuid.UUID, receivedAt time.Time) error {
	return r.UpdateStatus(ctx, db, transferOrderID, "received", nil, &receivedAt)
}

// Cancel cancels the transfer order (only allowed if not dispatched/received)
func (r *transferOrderRepository) Cancel(ctx context.Context, db DBTX, transferOrderID uuid.UUID) error {
	// First check current status to ensure it's allowed
	order, err := r.GetByID(ctx, db, transferOrderID)
	if err != nil {
		return err
	}
	if order.Status == "dispatched" || order.Status == "received" {
		return fmt.Errorf("cannot cancel transfer order in status %s", order.Status)
	}
	return r.UpdateStatus(ctx, db, transferOrderID, "cancelled", nil, nil)
}

// List retrieves transfer orders with optional filters and pagination
func (r *transferOrderRepository) List(ctx context.Context, db DBTX, filter TransferOrderFilter, p Pagination, s Sort) ([]*models.StockTransferOrder, int64, error) {
	where, args := r.buildTransferOrderFilter(filter)

	allowedSort := map[string]bool{
		"transfer_number": true,
		"status":          true,
		"created_at":      true,
		"dispatched_at":   true,
		"received_at":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}

	limit, offset := r.validatePagination(p)

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM stock_transfer_orders %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count transfer orders: %w", err)
	}
	if total == 0 {
		return []*models.StockTransferOrder{}, 0, nil
	}

	// Query with pagination
	query := fmt.Sprintf(`
		SELECT transfer_order_id, company_id, transfer_number, from_warehouse_id, to_warehouse_id,
		       status, dispatched_at, received_at, created_at
		FROM stock_transfer_orders
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list transfer orders: %w", err)
	}
	defer rows.Close()

	var result []*models.StockTransferOrder
	for rows.Next() {
		order, err := r.scanTransferOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, order)
	}

	return result, total, rows.Err()
}

// AddItems adds items to an existing transfer order
func (r *transferOrderRepository) AddItems(ctx context.Context, db DBTX, transferOrderID uuid.UUID, items []*models.StockTransferItem) error {
	if len(items) == 0 {
		return nil
	}

	query := `
		INSERT INTO stock_transfer_items (
			transfer_item_id, transfer_order_id, item_id, quantity
		) VALUES ($1, $2, $3, $4)
	`
	for _, it := range items {
		it.TransferOrderID = transferOrderID
		_, err := db.ExecContext(ctx, query,
			it.TransferItemID, it.TransferOrderID, it.ItemID, it.Quantity,
		)
		if err != nil {
			return fmt.Errorf("add transfer item: %w", err)
		}
	}
	return nil
}

// GetItems retrieves all items for a transfer order
func (r *transferOrderRepository) GetItems(ctx context.Context, db DBTX, transferOrderID uuid.UUID) ([]*models.StockTransferItem, error) {
	query := `
		SELECT transfer_item_id, transfer_order_id, item_id, quantity
		FROM stock_transfer_items
		WHERE transfer_order_id = $1
		ORDER BY transfer_item_id
	`
	rows, err := db.QueryContext(ctx, query, transferOrderID)
	if err != nil {
		return nil, fmt.Errorf("get transfer items: %w", err)
	}
	defer rows.Close()

	var items []*models.StockTransferItem
	for rows.Next() {
		it, err := r.scanTransferItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// UpdateItemQuantity updates the quantity of a specific transfer item
func (r *transferOrderRepository) UpdateItemQuantity(ctx context.Context, db DBTX, transferItemID uuid.UUID, quantity decimal.Decimal) error {
	query := `
		UPDATE stock_transfer_items
		SET quantity = $2
		WHERE transfer_item_id = $1
	`
	result, err := db.ExecContext(ctx, query, transferItemID, quantity)
	if err != nil {
		return fmt.Errorf("update transfer item quantity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: transfer item %s", inventory_errors.ErrNotFound, transferItemID)
	}
	return nil
}

// RemoveItem removes an item from a transfer order
func (r *transferOrderRepository) RemoveItem(ctx context.Context, db DBTX, transferItemID uuid.UUID) error {
	query := `DELETE FROM stock_transfer_items WHERE transfer_item_id = $1`
	result, err := db.ExecContext(ctx, query, transferItemID)
	if err != nil {
		return fmt.Errorf("remove transfer item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: transfer item %s", inventory_errors.ErrNotFound, transferItemID)
	}
	return nil
}

// ExistsByNumber checks if a transfer number already exists for the company
func (r *transferOrderRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM stock_transfer_orders WHERE company_id = $1 AND transfer_number = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, number).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check transfer number exists: %w", err)
	}
	return exists, nil
}
