package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// ReorderOrderRepository defines operations for reorder_orders table.
type ReorderOrderRepository interface {
	Create(ctx context.Context, db DBTX, order *models.ReorderOrder) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ReorderOrder, error)
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string) error
	UpdateReference(ctx context.Context, db DBTX, id uuid.UUID, refType string, refID uuid.UUID) error
	ListPending(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ReorderOrder, error)
	ExistsPendingForItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) (bool, error)

	// UpdateOrderWithReference updates status, reference_type, reference_id for a reorder order.
	UpdateOrderWithReference(ctx context.Context, db DBTX, order *models.ReorderOrder) error

	// ExistsOpenForItem checks for existing reorder with status IN ('pending', 'approved')
	ExistsOpenForItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) (bool, error)
	ListByFilters(ctx context.Context, db DBTX, filters ReorderFilters) ([]*models.ReorderOrder, int, error)
}

type reorderOrderRepository struct {
	logger *zap.Logger
}

func NewReorderOrderRepository(logger *zap.Logger) ReorderOrderRepository {
	return &reorderOrderRepository{logger: logger.Named("reorder_repo")}
}

func (r *reorderOrderRepository) Create(ctx context.Context, db DBTX, order *models.ReorderOrder) error {
	query := `
        INSERT INTO reorder_orders (
            reorder_order_id, company_id, item_id, warehouse_id, requested_qty,
            status, source, reference_type, reference_id, generated_at,
            created_at, updated_at, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW(), $11)
        RETURNING created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		order.ReorderOrderID, order.CompanyID, order.ItemID, order.WarehouseID, order.RequestedQty,
		order.Status, order.Source, order.ReferenceType, order.ReferenceID,
		order.GeneratedAt, order.CreatedBy,
	).Scan(&order.CreatedAt, &order.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create reorder order", util.ErrorField(err))
		return fmt.Errorf("create reorder order: %w", err)
	}
	return nil
}

func (r *reorderOrderRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ReorderOrder, error) {
	query := `
		SELECT reorder_order_id, company_id, item_id, warehouse_id, requested_qty,
		       status, source, reference_type, reference_id, generated_at,
		       created_at, updated_at, created_by
		FROM reorder_orders
		WHERE reorder_order_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanOrder(row)
}

func (r *reorderOrderRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string) error {
	query := `UPDATE reorder_orders SET status = $2, updated_at = NOW() WHERE reorder_order_id = $1`
	res, err := db.ExecContext(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: reorder order %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *reorderOrderRepository) UpdateReference(ctx context.Context, db DBTX, id uuid.UUID, refType string, refID uuid.UUID) error {
	query := `
		UPDATE reorder_orders
		SET reference_type = $2, reference_id = $3, updated_at = NOW()
		WHERE reorder_order_id = $1
	`
	res, err := db.ExecContext(ctx, query, id, refType, refID)
	if err != nil {
		return fmt.Errorf("update reference: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: reorder order %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *reorderOrderRepository) ListPending(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ReorderOrder, error) {
	filters := ReorderFilters{
		CompanyID: companyID,
		Status:    "pending",
		Page:      1,
		PageSize:  1000, // large enough to get all
	}
	orders, _, err := r.ListByFilters(ctx, db, filters)
	return orders, err
}
func (r *reorderOrderRepository) ExistsPendingForItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM reorder_orders
			WHERE company_id = $1 AND item_id = $2 AND warehouse_id = $3 AND status = 'pending'
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists pending: %w", err)
	}
	return exists, nil
}

// ExistsOpenForItem checks for an existing reorder order with status 'pending' or 'approved'
// for the same company, item, and warehouse. This prevents duplicate open reorder requests.
func (r *reorderOrderRepository) ExistsOpenForItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM reorder_orders
			WHERE company_id = $1 
			  AND item_id = $2 
			  AND warehouse_id = $3 
			  AND status IN ('pending', 'approved')
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists open reorder: %w", err)
	}
	return exists, nil
}

func (r *reorderOrderRepository) scanOrder(row scanner) (*models.ReorderOrder, error) {
	var o models.ReorderOrder
	var refType sql.NullString
	var refID uuid.NullUUID
	var createdBy uuid.NullUUID

	err := row.Scan(
		&o.ReorderOrderID, &o.CompanyID, &o.ItemID, &o.WarehouseID, &o.RequestedQty,
		&o.Status, &o.Source, &refType, &refID, &o.GeneratedAt,
		&o.CreatedAt, &o.UpdatedAt, &createdBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan reorder order: %w", err)
	}
	if refType.Valid {
		o.ReferenceType = &refType.String
	}
	if refID.Valid {
		o.ReferenceID = &refID.UUID
	}
	if createdBy.Valid {
		o.CreatedBy = &createdBy.UUID
	}
	return &o, nil
}

type ReorderFilters struct {
	CompanyID   uuid.UUID
	Status      string    // empty means all statuses
	ItemID      uuid.UUID // zero means no filter
	WarehouseID uuid.UUID // zero means no filter
	Page        int
	PageSize    int
}

// ListByFilters returns reorder orders matching the filters, with pagination.
// It returns the list of orders and the total count (without pagination) for pagination metadata.

// ListByFilters implementation
func (r *reorderOrderRepository) ListByFilters(ctx context.Context, db DBTX, filters ReorderFilters) ([]*models.ReorderOrder, int, error) {
	// Build WHERE clause
	conditions := []string{"company_id = $1"}
	args := []interface{}{filters.CompanyID}
	idx := 2

	if filters.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, filters.Status)
		idx++
	}
	if filters.ItemID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, filters.ItemID)
		idx++
	}
	if filters.WarehouseID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, filters.WarehouseID)
		idx++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM reorder_orders WHERE %s", whereClause)
	var total int
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count reorder orders: %w", err)
	}
	if total == 0 {
		return []*models.ReorderOrder{}, 0, nil
	}

	// Pagination
	limit := filters.PageSize
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (filters.Page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
        SELECT reorder_order_id, company_id, item_id, warehouse_id, requested_qty,
               status, source, reference_type, reference_id, generated_at,
               created_at, updated_at, created_by
        FROM reorder_orders
        WHERE %s
        ORDER BY generated_at DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query reorder orders: %w", err)
	}
	defer rows.Close()

	var orders []*models.ReorderOrder
	for rows.Next() {
		o, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		orders = append(orders, o)
	}
	return orders, total, rows.Err()
}

// UpdateOrderWithReference implementation
func (r *reorderOrderRepository) UpdateOrderWithReference(ctx context.Context, db DBTX, order *models.ReorderOrder) error {
	query := `
        UPDATE reorder_orders
        SET status = $2, reference_type = $3, reference_id = $4, updated_at = NOW()
        WHERE reorder_order_id = $1
    `
	_, err := db.ExecContext(ctx, query,
		order.ReorderOrderID,
		order.Status,
		order.ReferenceType,
		order.ReferenceID,
	)
	if err != nil {
		return fmt.Errorf("update order with reference: %w", err)
	}
	return nil
}
