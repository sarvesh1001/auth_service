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

// InventoryCycleCountRepository defines operations for cycle counts.
type InventoryCycleCountRepository interface {
	Create(ctx context.Context, tx DBTX, count *models.InventoryCycleCount) error
	GetByID(ctx context.Context, db DBTX, cycleCountID uuid.UUID) (*models.InventoryCycleCount, error)
	GetByUnique(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID, itemID *uuid.UUID, scheduledDate *time.Time) (*models.InventoryCycleCount, error) // new method
	UpdateStatus(ctx context.Context, tx DBTX, cycleCountID uuid.UUID, status string, updatedAt time.Time) error
	CompleteCount(ctx context.Context, tx DBTX, cycleCountID uuid.UUID, countedBy uuid.UUID, actualQuantity decimal.Decimal, adjustmentMovementID *uuid.UUID) error
	ListByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID, filter CycleCountFilter, p Pagination, s Sort) ([]*models.InventoryCycleCount, int64, error)
	Update(ctx context.Context, tx DBTX, count *models.InventoryCycleCount) error // optional, for full update
	Delete(ctx context.Context, tx DBTX, cycleCountID uuid.UUID) error
}

// CycleCountFilter for listing.
type CycleCountFilter struct {
	CompanyID   uuid.UUID
	WarehouseID *uuid.UUID
	ItemID      *uuid.UUID
	LocationID  *uuid.UUID
	CountType   *string
	Status      *string
	DateFrom    *time.Time
	DateTo      *time.Time
}

type inventoryCycleCountRepository struct {
	logger *zap.Logger
}

func NewInventoryCycleCountRepository(logger *zap.Logger) InventoryCycleCountRepository {
	return &inventoryCycleCountRepository{
		logger: logger.Named("inventory_cycle_count_repo"),
	}
}

func (r *inventoryCycleCountRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *inventoryCycleCountRepository) validatePagination(p Pagination) (int, int) {
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

func (r *inventoryCycleCountRepository) buildCycleCountFilter(filter CycleCountFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, *filter.WarehouseID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.LocationID != nil {
		conds = append(conds, fmt.Sprintf("location_id = $%d", idx))
		args = append(args, *filter.LocationID)
		idx++
	}
	if filter.CountType != nil && *filter.CountType != "" {
		conds = append(conds, fmt.Sprintf("count_type = $%d", idx))
		args = append(args, *filter.CountType)
		idx++
	}
	if filter.Status != nil && *filter.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("scheduled_date >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("scheduled_date <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *inventoryCycleCountRepository) scanCycleCount(s scanner) (*models.InventoryCycleCount, error) {
	var cc models.InventoryCycleCount
	var itemID, locationID, countedBy, adjustmentMovementID uuid.NullUUID
	var scheduledDate, countedAt sql.NullTime
	var expectedQuantity, actualQuantity sql.NullFloat64

	err := s.Scan(
		&cc.CycleCountID,
		&cc.CompanyID,
		&cc.WarehouseID,
		&itemID,
		&locationID,
		&cc.CountType,
		&cc.Status,
		&scheduledDate,
		&countedBy,
		&countedAt,
		&expectedQuantity,
		&actualQuantity,
		&cc.Variance,
		&adjustmentMovementID,
		&cc.CreatedAt,
		&cc.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan cycle count: %w", err)
	}

	if itemID.Valid {
		cc.ItemID = &itemID.UUID
	}
	if locationID.Valid {
		cc.LocationID = &locationID.UUID
	}
	if scheduledDate.Valid {
		cc.ScheduledDate = &scheduledDate.Time
	}
	if countedBy.Valid {
		cc.CountedBy = &countedBy.UUID
	}
	if countedAt.Valid {
		cc.CountedAt = &countedAt.Time
	}
	if expectedQuantity.Valid {
		cc.ExpectedQuantity = decimal.NewFromFloat(expectedQuantity.Float64)
	}
	if actualQuantity.Valid {
		cc.ActualQuantity = decimal.NewFromFloat(actualQuantity.Float64)
	}
	if adjustmentMovementID.Valid {
		cc.AdjustmentMovementID = &adjustmentMovementID.UUID
	}
	return &cc, nil
}

// Create inserts a new cycle count record. Returns inventory_errors.ErrDuplicate if a record already exists
// for the same company, warehouse, item, and scheduled date.
func (r *inventoryCycleCountRepository) Create(ctx context.Context, tx DBTX, count *models.InventoryCycleCount) error {
	query := `
		INSERT INTO inventory_cycle_counts (
			cycle_count_id, company_id, warehouse_id, item_id, location_id,
			count_type, status, scheduled_date, counted_by, counted_at,
			expected_quantity, actual_quantity, adjustment_movement_id,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := tx.QueryRowContext(ctx, query,
		count.CycleCountID,
		count.CompanyID,
		count.WarehouseID,
		nullUUIDParam(count.ItemID),
		nullUUIDParam(count.LocationID),
		count.CountType,
		count.Status,
		count.ScheduledDate,
		nullUUIDParam(count.CountedBy),
		count.CountedAt,
		count.ExpectedQuantity,
		count.ActualQuantity,
		nullUUIDParam(count.AdjustmentMovementID),
	).Scan(&count.CreatedAt, &count.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create cycle count", util.ErrorField(err))
		// Detect unique constraint violation (duplicate company/warehouse/item/date)
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return inventory_errors.ErrDuplicate
		}
		return fmt.Errorf("create cycle count: %w", err)
	}
	return nil
}

// GetByID retrieves a cycle count by its ID.
func (r *inventoryCycleCountRepository) GetByID(ctx context.Context, db DBTX, cycleCountID uuid.UUID) (*models.InventoryCycleCount, error) {
	query := `
		SELECT cycle_count_id, company_id, warehouse_id, item_id, location_id,
		       count_type, status, scheduled_date, counted_by, counted_at,
		       expected_quantity, actual_quantity, variance, adjustment_movement_id,
		       created_at, updated_at
		FROM inventory_cycle_counts
		WHERE cycle_count_id = $1
	`
	row := db.QueryRowContext(ctx, query, cycleCountID)
	return r.scanCycleCount(row)
}

// GetByUnique retrieves a cycle count by its natural key: company_id, warehouse_id, item_id, scheduled_date.
// Returns inventory_errors.ErrNotFound if not found.
func (r *inventoryCycleCountRepository) GetByUnique(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID, itemID *uuid.UUID, scheduledDate *time.Time) (*models.InventoryCycleCount, error) {
	query := `
		SELECT cycle_count_id, company_id, warehouse_id, item_id, location_id,
		       count_type, status, scheduled_date, counted_by, counted_at,
		       expected_quantity, actual_quantity, variance, adjustment_movement_id,
		       created_at, updated_at
		FROM inventory_cycle_counts
		WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3 AND scheduled_date = $4
	`
	row := db.QueryRowContext(ctx, query, companyID, warehouseID, nullUUIDParam(itemID), scheduledDate)
	return r.scanCycleCount(row)
}

// UpdateStatus updates only the status of a cycle count.
func (r *inventoryCycleCountRepository) UpdateStatus(ctx context.Context, tx DBTX, cycleCountID uuid.UUID, status string, updatedAt time.Time) error {
	query := `
		UPDATE inventory_cycle_counts
		SET status = $2, updated_at = $3
		WHERE cycle_count_id = $1
	`
	result, err := tx.ExecContext(ctx, query, cycleCountID, status, updatedAt)
	if err != nil {
		return fmt.Errorf("update cycle count status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: cycle count %s", inventory_errors.ErrNotFound, cycleCountID)
	}
	return nil
}

// CompleteCount marks a cycle count as completed, records counted_by, counted_at, actual_quantity, and optional adjustment movement.
func (r *inventoryCycleCountRepository) CompleteCount(ctx context.Context, tx DBTX, cycleCountID uuid.UUID, countedBy uuid.UUID, actualQuantity decimal.Decimal, adjustmentMovementID *uuid.UUID) error {
	query := `
		UPDATE inventory_cycle_counts
		SET status = 'completed',
		    counted_by = $2,
		    counted_at = NOW(),
		    actual_quantity = $3,
		    adjustment_movement_id = $4,
		    updated_at = NOW()
		WHERE cycle_count_id = $1
		RETURNING updated_at
	`
	var updatedAt time.Time
	err := tx.QueryRowContext(ctx, query, cycleCountID, countedBy, actualQuantity, nullUUIDParam(adjustmentMovementID)).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: cycle count %s", inventory_errors.ErrNotFound, cycleCountID)
		}
		return fmt.Errorf("complete cycle count: %w", err)
	}
	return nil
}

// ListByWarehouse returns cycle counts for a specific warehouse with filtering and pagination.
func (r *inventoryCycleCountRepository) ListByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID, filter CycleCountFilter, p Pagination, s Sort) ([]*models.InventoryCycleCount, int64, error) {
	// Ensure the filter uses the provided company and warehouse
	filter.CompanyID = companyID
	filter.WarehouseID = &warehouseID

	where, args := r.buildCycleCountFilter(filter)

	allowedSort := map[string]bool{
		"scheduled_date": true,
		"created_at":     true,
		"status":         true,
		"count_type":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY scheduled_date DESC, created_at DESC"
	}

	limit, offset := r.validatePagination(p)

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM inventory_cycle_counts %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count cycle counts: %w", err)
	}
	if total == 0 {
		return []*models.InventoryCycleCount{}, 0, nil
	}

	// Main query
	query := fmt.Sprintf(`
		SELECT cycle_count_id, company_id, warehouse_id, item_id, location_id,
		       count_type, status, scheduled_date, counted_by, counted_at,
		       expected_quantity, actual_quantity, variance, adjustment_movement_id,
		       created_at, updated_at
		FROM inventory_cycle_counts
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list cycle counts: %w", err)
	}
	defer rows.Close()

	var result []*models.InventoryCycleCount
	for rows.Next() {
		cc, err := r.scanCycleCount(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, cc)
	}
	return result, total, rows.Err()
}

// Update updates the entire cycle count record (optional, for full updates).
func (r *inventoryCycleCountRepository) Update(ctx context.Context, tx DBTX, count *models.InventoryCycleCount) error {
	query := `
		UPDATE inventory_cycle_counts
		SET warehouse_id = $2,
		    item_id = $3,
		    location_id = $4,
		    count_type = $5,
		    status = $6,
		    scheduled_date = $7,
		    counted_by = $8,
		    counted_at = $9,
		    expected_quantity = $10,
		    actual_quantity = $11,
		    adjustment_movement_id = $12,
		    updated_at = NOW()
		WHERE cycle_count_id = $1
		RETURNING updated_at
	`
	err := tx.QueryRowContext(ctx, query,
		count.CycleCountID,
		count.WarehouseID,
		nullUUIDParam(count.ItemID),
		nullUUIDParam(count.LocationID),
		count.CountType,
		count.Status,
		count.ScheduledDate,
		nullUUIDParam(count.CountedBy),
		count.CountedAt,
		count.ExpectedQuantity,
		count.ActualQuantity,
		nullUUIDParam(count.AdjustmentMovementID),
	).Scan(&count.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: cycle count %s", inventory_errors.ErrNotFound, count.CycleCountID)
		}
		return fmt.Errorf("update cycle count: %w", err)
	}
	return nil
}

// Delete permanently removes a cycle count (soft delete not required – use status = 'cancelled').
func (r *inventoryCycleCountRepository) Delete(ctx context.Context, tx DBTX, cycleCountID uuid.UUID) error {
	query := `DELETE FROM inventory_cycle_counts WHERE cycle_count_id = $1`
	result, err := tx.ExecContext(ctx, query, cycleCountID)
	if err != nil {
		return fmt.Errorf("delete cycle count: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: cycle count %s", inventory_errors.ErrNotFound, cycleCountID)
	}
	return nil
}
