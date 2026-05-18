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

type ProductionOrderConsumptionRepository interface {
	Create(ctx context.Context, db DBTX, consumption *models.ProductionOrderComponentConsumption) error
	GetByID(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID) (*models.ProductionOrderComponentConsumption, error)
	GetByProductionOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.ProductionOrderComponentConsumption, error)
	GetByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) ([]*models.ProductionOrderComponentConsumption, error)
	GetByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (*models.ProductionOrderComponentConsumption, error)
	GetTotalConsumedByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) (decimal.Decimal, error)
	GetTotalConsumedByOrderAndComponent(ctx context.Context, db DBTX, companyID, orderID, componentID uuid.UUID) (decimal.Decimal, error)
	List(ctx context.Context, db DBTX, filter ConsumptionFilter, p Pagination, s Sort) ([]*models.ProductionOrderComponentConsumption, int64, error)
	UpdateNotes(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID, notes string) error
	Delete(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID) error
	ExistsByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (bool, error)
}

type ConsumptionFilter struct {
	CompanyID         uuid.UUID
	ProductionOrderID *uuid.UUID
	ComponentID       *uuid.UUID
	ItemID            *uuid.UUID
	FromConsumedAt    *time.Time
	ToConsumedAt      *time.Time
}

type productionOrderConsumptionRepository struct {
	logger *zap.Logger
}

func NewProductionOrderConsumptionRepository(logger *zap.Logger) ProductionOrderConsumptionRepository {
	return &productionOrderConsumptionRepository{
		logger: logger.Named("prod_order_consumption_repo"),
	}
}

// ---------------------------
// Helper
// ---------------------------

func (r *productionOrderConsumptionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
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

func (r *productionOrderConsumptionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *productionOrderConsumptionRepository) buildConsumptionFilter(filter ConsumptionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ProductionOrderID != nil {
		conds = append(conds, fmt.Sprintf("production_order_id = $%d", idx))
		args = append(args, *filter.ProductionOrderID)
		idx++
	}
	if filter.ComponentID != nil {
		conds = append(conds, fmt.Sprintf("component_id = $%d", idx))
		args = append(args, *filter.ComponentID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.FromConsumedAt != nil {
		conds = append(conds, fmt.Sprintf("consumed_at >= $%d", idx))
		args = append(args, *filter.FromConsumedAt)
		idx++
	}
	if filter.ToConsumedAt != nil {
		conds = append(conds, fmt.Sprintf("consumed_at <= $%d", idx))
		args = append(args, *filter.ToConsumedAt)
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------------------------
// Scanner
// ---------------------------
func (r *productionOrderConsumptionRepository) scanConsumption(s scanner) (*models.ProductionOrderComponentConsumption, error) {
	var c models.ProductionOrderComponentConsumption
	var batchID, createdBy uuid.NullUUID
	var notes sql.NullString
	err := s.Scan(
		&c.ConsumptionID,
		&c.CompanyID,
		&c.ComponentID,
		&c.ProductionOrderID,
		&c.ItemID,
		&batchID,
		&c.QuantityConsumed,
		&c.MovementID,
		&c.ConsumedAt,
		&createdBy,
		&notes,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan consumption: %w", err)
	}
	if batchID.Valid {
		c.BatchID = &batchID.UUID
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if notes.Valid {
		c.Notes = &notes.String
	}
	return &c, nil
}

// ---------------------------
// Create
// ---------------------------
func (r *productionOrderConsumptionRepository) Create(ctx context.Context, db DBTX, consumption *models.ProductionOrderComponentConsumption) error {
	query := `
		INSERT INTO production_order_component_consumptions (
			consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
			quantity_consumed, movement_id, consumed_at, created_by, notes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING consumed_at
	`
	err := db.QueryRowContext(ctx, query,
		consumption.ConsumptionID,
		consumption.CompanyID,
		consumption.ComponentID,
		consumption.ProductionOrderID,
		consumption.ItemID,
		nullUUIDParam(consumption.BatchID),
		consumption.QuantityConsumed,
		consumption.MovementID,
		consumption.ConsumedAt,
		nullUUIDParam(consumption.CreatedBy),
		consumption.Notes,
	).Scan(&consumption.ConsumedAt)
	if err != nil {
		r.logger.Error("failed to create consumption record", util.ErrorField(err))
		return fmt.Errorf("create consumption: %w", err)
	}
	return nil
}

// ---------------------------
// GetByID
// ---------------------------
func (r *productionOrderConsumptionRepository) GetByID(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID) (*models.ProductionOrderComponentConsumption, error) {
	query := `
		SELECT consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
		       quantity_consumed, movement_id, consumed_at, created_by, notes
		FROM production_order_component_consumptions
		WHERE consumption_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, consumptionID, companyID)
	return r.scanConsumption(row)
}

// ---------------------------
// GetByProductionOrder
// ---------------------------
func (r *productionOrderConsumptionRepository) GetByProductionOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.ProductionOrderComponentConsumption, error) {
	query := `
		SELECT consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
		       quantity_consumed, movement_id, consumed_at, created_by, notes
		FROM production_order_component_consumptions
		WHERE company_id = $1 AND production_order_id = $2
		ORDER BY consumed_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, orderID)
	if err != nil {
		return nil, fmt.Errorf("get consumptions by order: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderComponentConsumption
	for rows.Next() {
		c, err := r.scanConsumption(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// ---------------------------
// GetByComponent
// ---------------------------
func (r *productionOrderConsumptionRepository) GetByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) ([]*models.ProductionOrderComponentConsumption, error) {
	query := `
		SELECT consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
		       quantity_consumed, movement_id, consumed_at, created_by, notes
		FROM production_order_component_consumptions
		WHERE company_id = $1 AND component_id = $2
		ORDER BY consumed_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, componentID)
	if err != nil {
		return nil, fmt.Errorf("get consumptions by component: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderComponentConsumption
	for rows.Next() {
		c, err := r.scanConsumption(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// ---------------------------
// GetByMovementID
// ---------------------------
func (r *productionOrderConsumptionRepository) GetByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (*models.ProductionOrderComponentConsumption, error) {
	query := `
		SELECT consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
		       quantity_consumed, movement_id, consumed_at, created_by, notes
		FROM production_order_component_consumptions
		WHERE company_id = $1 AND movement_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, movementID)
	return r.scanConsumption(row)
}

// ---------------------------
// Total consumed by component (across all orders)
// ---------------------------
func (r *productionOrderConsumptionRepository) GetTotalConsumedByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(quantity_consumed), 0)
		FROM production_order_component_consumptions
		WHERE company_id = $1 AND component_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, componentID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total consumed by component: %w", err)
	}
	return total, nil
}

// ---------------------------
// Total consumed by order + component
// ---------------------------
func (r *productionOrderConsumptionRepository) GetTotalConsumedByOrderAndComponent(ctx context.Context, db DBTX, companyID, orderID, componentID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(quantity_consumed), 0)
		FROM production_order_component_consumptions
		WHERE company_id = $1 AND production_order_id = $2 AND component_id = $3
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, orderID, componentID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total consumed by order/component: %w", err)
	}
	return total, nil
}

// ---------------------------
// List with filters + pagination
// ---------------------------
func (r *productionOrderConsumptionRepository) List(ctx context.Context, db DBTX, filter ConsumptionFilter, p Pagination, s Sort) ([]*models.ProductionOrderComponentConsumption, int64, error) {
	where, args := r.buildConsumptionFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"consumed_at":       true,
		"quantity_consumed": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY consumed_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM production_order_component_consumptions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count consumptions: %w", err)
	}
	if total == 0 {
		return []*models.ProductionOrderComponentConsumption{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT consumption_id, company_id, component_id, production_order_id, item_id, batch_id,
		       quantity_consumed, movement_id, consumed_at, created_by, notes
		FROM production_order_component_consumptions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list consumptions: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderComponentConsumption
	for rows.Next() {
		c, err := r.scanConsumption(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

// ---------------------------
// UpdateNotes
// ---------------------------
func (r *productionOrderConsumptionRepository) UpdateNotes(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID, notes string) error {
	query := `
		UPDATE production_order_component_consumptions
		SET notes = $3
		WHERE consumption_id = $1 AND company_id = $2
	`
	result, err := db.ExecContext(ctx, query, consumptionID, companyID, notes)
	if err != nil {
		return fmt.Errorf("update notes: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: consumption %s", inventory_errors.ErrNotFound, consumptionID)
	}
	return nil
}

// ---------------------------
// Delete
// ---------------------------
func (r *productionOrderConsumptionRepository) Delete(ctx context.Context, db DBTX, companyID, consumptionID uuid.UUID) error {
	query := `DELETE FROM production_order_component_consumptions WHERE consumption_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, consumptionID, companyID)
	if err != nil {
		return fmt.Errorf("delete consumption: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: consumption %s", inventory_errors.ErrNotFound, consumptionID)
	}
	return nil
}

// ---------------------------
// ExistsByMovementID
// ---------------------------
func (r *productionOrderConsumptionRepository) ExistsByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM production_order_component_consumptions WHERE company_id = $1 AND movement_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, movementID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by movement id: %w", err)
	}
	return exists, nil
}
