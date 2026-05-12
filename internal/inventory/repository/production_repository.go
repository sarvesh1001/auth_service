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

// ProductionOrderFilter for listing / searching
type ProductionOrderFilter struct {
	CompanyID     uuid.UUID
	Status        string // draft, released, started, completed, cancelled
	ProductItemID *uuid.UUID
	DateFrom      *time.Time
	DateTo        *time.Time
	Search        string // order_number
}

// ProductionOrderRepository interface
type ProductionOrderRepository interface {
	Create(ctx context.Context, db DBTX, order *models.ProductionOrder) error
	GetByID(ctx context.Context, db DBTX, orderID, companyID uuid.UUID) (*models.ProductionOrder, error)
	GetByOrderNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (*models.ProductionOrder, error)
	Update(ctx context.Context, db DBTX, order *models.ProductionOrder) error
	UpdateStatus(ctx context.Context, db DBTX, orderID uuid.UUID, status string, updatedAt time.Time) error
	List(ctx context.Context, db DBTX, filter ProductionOrderFilter, p Pagination, s Sort) ([]*models.ProductionOrder, error)
	Count(ctx context.Context, db DBTX, filter ProductionOrderFilter) (int64, error)
	AddComponent(ctx context.Context, db DBTX, comp *models.ProductionOrderComponent) error
	GetComponents(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*models.ProductionOrderComponent, error)
	UpdateComponentActualQuantity(ctx context.Context, db DBTX, componentID uuid.UUID, actualQty decimal.Decimal, movementID *uuid.UUID) error
	DeleteComponents(ctx context.Context, db DBTX, orderID uuid.UUID) error
}

type productionOrderRepository struct {
	logger *zap.Logger
}

func NewProductionOrderRepository(logger *zap.Logger) ProductionOrderRepository {
	return &productionOrderRepository{
		logger: logger.Named("production_order_repo"),
	}
}

// ---- helpers ----
func (r *productionOrderRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *productionOrderRepository) validatePagination(p Pagination) (int, int) {
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

func (r *productionOrderRepository) buildFilter(filter ProductionOrderFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}
	if filter.ProductItemID != nil {
		conds = append(conds, fmt.Sprintf("product_item_id = $%d", idx))
		args = append(args, *filter.ProductItemID)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("planned_start_date >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("planned_end_date <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("order_number ILIKE $%d", idx))
		args = append(args, search)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---- scanning helpers ----
func (r *productionOrderRepository) scanOrder(sc scanner) (*models.ProductionOrder, error) {
	var order models.ProductionOrder
	var plannedStart, plannedEnd sql.NullTime
	var actualStart, actualEnd sql.NullTime
	var createdBy uuid.NullUUID
	var sourceRefType sql.NullString
	var sourceRefID uuid.NullUUID

	err := sc.Scan(
		&order.ProductionOrderID,
		&order.CompanyID,
		&order.OrderNumber,
		&order.ProductItemID,
		&order.BOMID,
		&order.PlannedQuantity,
		&order.ProducedQuantity,
		&order.Status,
		&plannedStart,
		&plannedEnd,
		&actualStart,
		&actualEnd,
		&order.WarehouseID,
		&createdBy,
		&order.CreatedAt,
		&order.UpdatedAt,
		&sourceRefType,
		&sourceRefID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan production order: %w", err)
	}

	if plannedStart.Valid {
		order.PlannedStartDate = &plannedStart.Time
	}
	if plannedEnd.Valid {
		order.PlannedEndDate = &plannedEnd.Time
	}
	if actualStart.Valid {
		order.ActualStartTime = &actualStart.Time
	}
	if actualEnd.Valid {
		order.ActualEndTime = &actualEnd.Time
	}
	if createdBy.Valid {
		order.CreatedBy = &createdBy.UUID
	}
	if sourceRefType.Valid {
		order.SourceReferenceType = &sourceRefType.String
	}
	if sourceRefID.Valid {
		order.SourceReferenceID = &sourceRefID.UUID
	}
	return &order, nil
}

func (r *productionOrderRepository) scanComponent(sc scanner) (*models.ProductionOrderComponent, error) {
	var comp models.ProductionOrderComponent
	var batchID, movementID uuid.NullUUID

	err := sc.Scan(
		&comp.ComponentID,
		&comp.ProductionOrderID,
		&comp.ItemID,
		&batchID,
		&comp.PlannedQuantity,
		&comp.ActualQuantity,
		&movementID,
		&comp.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan component: %w", err)
	}

	if batchID.Valid {
		comp.BatchID = &batchID.UUID
	}
	if movementID.Valid {
		comp.MovementID = &movementID.UUID
	}
	return &comp, nil
}

// ---- implementation ----
func (r *productionOrderRepository) Create(ctx context.Context, db DBTX, order *models.ProductionOrder) error {
	query := `
		INSERT INTO production_orders (
			production_order_id, company_id, order_number, product_item_id, bom_id,
			planned_quantity, produced_quantity, status,
			planned_start_date, planned_end_date, actual_start_time, actual_end_time,
			warehouse_id, created_by, created_at, updated_at,
			source_reference_type, source_reference_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW(), $15, $16)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		order.ProductionOrderID, order.CompanyID, order.OrderNumber, order.ProductItemID, order.BOMID,
		order.PlannedQuantity, order.ProducedQuantity, order.Status,
		order.PlannedStartDate, order.PlannedEndDate, order.ActualStartTime, order.ActualEndTime,
		order.WarehouseID, order.CreatedBy,
		order.SourceReferenceType, order.SourceReferenceID,
	).Scan(&order.CreatedAt, &order.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create production order", util.ErrorField(err))
		return fmt.Errorf("create production order: %w", err)
	}
	return nil
}

func (r *productionOrderRepository) GetByID(ctx context.Context, db DBTX, orderID, companyID uuid.UUID) (*models.ProductionOrder, error) {
	query := `
		SELECT production_order_id, company_id, order_number, product_item_id, bom_id,
		       planned_quantity, produced_quantity, status,
		       planned_start_date, planned_end_date, actual_start_time, actual_end_time,
		       warehouse_id, created_by, created_at, updated_at,
		       source_reference_type, source_reference_id
		FROM production_orders
		WHERE production_order_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, orderID, companyID)
	return r.scanOrder(row)
}

func (r *productionOrderRepository) GetByOrderNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (*models.ProductionOrder, error) {
	query := `
		SELECT production_order_id, company_id, order_number, product_item_id, bom_id,
		       planned_quantity, produced_quantity, status,
		       planned_start_date, planned_end_date, actual_start_time, actual_end_time,
		       warehouse_id, created_by, created_at, updated_at,
		       source_reference_type, source_reference_id
		FROM production_orders
		WHERE company_id = $1 AND order_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, orderNumber)
	return r.scanOrder(row)
}

func (r *productionOrderRepository) Update(ctx context.Context, db DBTX, order *models.ProductionOrder) error {
	query := `
		UPDATE production_orders SET
			order_number = $2,
			product_item_id = $3,
			bom_id = $4,
			planned_quantity = $5,
			produced_quantity = $6,
			status = $7,
			planned_start_date = $8,
			planned_end_date = $9,
			actual_start_time = $10,
			actual_end_time = $11,
			warehouse_id = $12,
			updated_at = NOW(),
			source_reference_type = $13,
			source_reference_id = $14
		WHERE production_order_id = $1 AND company_id = $15
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		order.ProductionOrderID, order.OrderNumber, order.ProductItemID, order.BOMID,
		order.PlannedQuantity, order.ProducedQuantity, order.Status,
		order.PlannedStartDate, order.PlannedEndDate, order.ActualStartTime, order.ActualEndTime,
		order.WarehouseID,
		order.SourceReferenceType, order.SourceReferenceID,
		order.CompanyID,
	).Scan(&order.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: production order %s", inventory_errors.ErrNotFound, order.ProductionOrderID)
		}
		return fmt.Errorf("update production order: %w", err)
	}
	return nil
}

func (r *productionOrderRepository) UpdateStatus(ctx context.Context, db DBTX, orderID uuid.UUID, status string, updatedAt time.Time) error {
	query := `UPDATE production_orders SET status = $2, updated_at = $3 WHERE production_order_id = $1 RETURNING updated_at`
	var returnedUpdatedAt time.Time
	err := db.QueryRowContext(ctx, query, orderID, status, updatedAt).Scan(&returnedUpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: order %s", inventory_errors.ErrNotFound, orderID)
		}
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

func (r *productionOrderRepository) List(ctx context.Context, db DBTX, filter ProductionOrderFilter, p Pagination, s Sort) ([]*models.ProductionOrder, error) {
	where, args := r.buildFilter(filter)
	allowedSort := map[string]bool{
		"order_number":       true,
		"status":             true,
		"planned_start_date": true,
		"created_at":         true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT production_order_id, company_id, order_number, product_item_id, bom_id,
		       planned_quantity, produced_quantity, status,
		       planned_start_date, planned_end_date, actual_start_time, actual_end_time,
		       warehouse_id, created_by, created_at, updated_at,
		       source_reference_type, source_reference_id
		FROM production_orders
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list production orders: %w", err)
	}
	defer rows.Close()

	var result []*models.ProductionOrder
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, order)
	}
	return result, rows.Err()
}

func (r *productionOrderRepository) Count(ctx context.Context, db DBTX, filter ProductionOrderFilter) (int64, error) {
	where, args := r.buildFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM production_orders %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count production orders: %w", err)
	}
	return count, nil
}

func (r *productionOrderRepository) AddComponent(ctx context.Context, db DBTX, comp *models.ProductionOrderComponent) error {
	query := `
		INSERT INTO production_order_components (
			component_id, production_order_id, item_id, batch_id,
			planned_quantity, actual_quantity, movement_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		comp.ComponentID, comp.ProductionOrderID, comp.ItemID, comp.BatchID,
		comp.PlannedQuantity, comp.ActualQuantity, comp.MovementID,
	).Scan(&comp.CreatedAt)
	if err != nil {
		return fmt.Errorf("add component: %w", err)
	}
	return nil
}

func (r *productionOrderRepository) GetComponents(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*models.ProductionOrderComponent, error) {
	query := `
		SELECT component_id, production_order_id, item_id, batch_id,
		       planned_quantity, actual_quantity, movement_id, created_at
		FROM production_order_components
		WHERE production_order_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get components: %w", err)
	}
	defer rows.Close()

	var components []*models.ProductionOrderComponent
	for rows.Next() {
		comp, err := r.scanComponent(rows)
		if err != nil {
			return nil, err
		}
		components = append(components, comp)
	}
	return components, rows.Err()
}

func (r *productionOrderRepository) UpdateComponentActualQuantity(ctx context.Context, db DBTX, componentID uuid.UUID, actualQty decimal.Decimal, movementID *uuid.UUID) error {
	query := `
		UPDATE production_order_components
		SET actual_quantity = $2, movement_id = $3
		WHERE component_id = $1
	`
	_, err := db.ExecContext(ctx, query, componentID, actualQty, movementID)
	if err != nil {
		return fmt.Errorf("update component actual quantity: %w", err)
	}
	return nil
}

func (r *productionOrderRepository) DeleteComponents(ctx context.Context, db DBTX, orderID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM production_order_components WHERE production_order_id = $1`, orderID)
	if err != nil {
		return fmt.Errorf("delete components: %w", err)
	}
	return nil
}
