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

// ========== Filter & DTOs ==========

type MovementFilter struct {
	CompanyID       uuid.UUID
	MovementType    *string
	ReferenceType   *string
	ReferenceID     *uuid.UUID
	WarehouseID     *uuid.UUID
	FromWarehouseID *uuid.UUID
	ItemID          *uuid.UUID
	BatchID         *uuid.UUID
	DateFrom        *time.Time
	DateTo          *time.Time
	MinQuantity     *float64
	MaxQuantity     *float64
	Status          *string // new
}

type MovementTrail struct {
	Movement      *models.StockMovement
	Allocations   []*models.StockAllocation
	LedgerEntries []*models.StockLedger
}

// ========== Interface ==========

type MovementRepository interface {
	// Core write
	CreateMovement(ctx context.Context, db DBTX, movement *models.StockMovement) error
	BulkCreateMovements(ctx context.Context, db DBTX, movements []*models.StockMovement) error
	CreateIfNotExists(ctx context.Context, db DBTX, movement *models.StockMovement) (*models.StockMovement, error)
	UpdateStatus(ctx context.Context, db DBTX, movementID uuid.UUID, status string) error
	UpdateMovement(ctx context.Context, db DBTX, movement *models.StockMovement) error // for linking reservation/shipment/transfer
	GetCOGSByPeriod(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, from, to time.Time) (decimal.Decimal, error)

	// Fetch
	GetByID(ctx context.Context, db DBTX, movementID uuid.UUID) (*models.StockMovement, error)
	GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType string, referenceID uuid.UUID) ([]*models.StockMovement, error)
	List(ctx context.Context, db DBTX, filter MovementFilter, p Pagination, s Sort) ([]*models.StockMovement, error)
	Count(ctx context.Context, db DBTX, filter MovementFilter) (int64, error)
	IsCancelled(ctx context.Context, db DBTX, movementID uuid.UUID) (bool, error)

	// Specialized
	GetItemMovements(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, from, to time.Time) ([]*models.StockMovement, error)
	GetWarehouseMovements(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID, from, to time.Time) ([]*models.StockMovement, error)
	GetBatchMovements(ctx context.Context, db DBTX, companyID uuid.UUID, batchID uuid.UUID) ([]*models.StockMovement, error)

	// Transfer support
	GetTransferMovements(ctx context.Context, db DBTX, companyID uuid.UUID, referenceID uuid.UUID) ([]*models.StockMovement, error)

	// New: fetch by shipment or transfer
	GetByShipmentID(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.StockMovement, error)
	GetByTransferOrderID(ctx context.Context, db DBTX, transferOrderID uuid.UUID) ([]*models.StockMovement, error)

	// Validation / checks
	ExistsByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType string, referenceID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, batchID *uuid.UUID) (bool, error)

	// Costing support
	GetLatestUnitCost(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID) (float64, error)
	GetAverageCost(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID) (float64, error)

	// Audit
	GetMovementTrail(ctx context.Context, db DBTX, movementID uuid.UUID) (*MovementTrail, error)
}

// ========== Implementation ==========

type movementRepository struct {
	logger *zap.Logger
}

func NewMovementRepository(logger *zap.Logger) MovementRepository {
	return &movementRepository{
		logger: logger.Named("movement_repo"),
	}
}

// ---------- helpers ----------

func (r *movementRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *movementRepository) validatePagination(p Pagination) (int, int) {
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

func (r *movementRepository) buildMovementFilter(filter MovementFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.MovementType != nil {
		conds = append(conds, fmt.Sprintf("movement_type = $%d", idx))
		args = append(args, *filter.MovementType)
		idx++
	}
	if filter.ReferenceType != nil {
		conds = append(conds, fmt.Sprintf("reference_type = $%d", idx))
		args = append(args, *filter.ReferenceType)
		idx++
	}
	if filter.ReferenceID != nil {
		conds = append(conds, fmt.Sprintf("reference_id = $%d", idx))
		args = append(args, *filter.ReferenceID)
		idx++
	}
	if filter.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, *filter.WarehouseID)
		idx++
	}
	if filter.FromWarehouseID != nil {
		conds = append(conds, fmt.Sprintf("from_warehouse_id = $%d", idx))
		args = append(args, *filter.FromWarehouseID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.BatchID != nil {
		conds = append(conds, fmt.Sprintf("batch_id = $%d", idx))
		args = append(args, *filter.BatchID)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("movement_date >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("movement_date <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}
	if filter.MinQuantity != nil {
		conds = append(conds, fmt.Sprintf("(quantity_in >= $%d OR quantity_out >= $%d)", idx, idx))
		args = append(args, *filter.MinQuantity)
		idx++
	}
	if filter.MaxQuantity != nil {
		conds = append(conds, fmt.Sprintf("(quantity_in <= $%d OR quantity_out <= $%d)", idx, idx))
		args = append(args, *filter.MaxQuantity)
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- core write (updated with new columns) ----------

func (r *movementRepository) CreateMovement(ctx context.Context, db DBTX, movement *models.StockMovement) error {
	query := `
		INSERT INTO stock_movements (
			movement_id, company_id, movement_type, reference_type, reference_id,
			movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
			quantity_in, quantity_out, unit_cost, reason, created_at, created_by,
			status, reservation_id, shipment_id, transfer_order_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), $15, $16, $17, $18, $19)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		movement.MovementID, movement.CompanyID, movement.MovementType, movement.ReferenceType, movement.ReferenceID,
		movement.MovementDate, movement.WarehouseID, movement.FromWarehouseID, movement.ItemID, movement.BatchID,
		movement.QuantityIn.InexactFloat64(), movement.QuantityOut.InexactFloat64(), movement.UnitCost.InexactFloat64(),
		movement.Reason, movement.CreatedBy,
		movement.Status, movement.ReservationID, movement.ShipmentID, movement.TransferOrderID,
	).Scan(&movement.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create movement", util.ErrorField(err))
		return fmt.Errorf("create movement: %w", err)
	}
	return nil
}

func (r *movementRepository) BulkCreateMovements(ctx context.Context, db DBTX, movements []*models.StockMovement) error {
	if len(movements) == 0 {
		return nil
	}
	query := `
		INSERT INTO stock_movements (
			movement_id, company_id, movement_type, reference_type, reference_id,
			movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
			quantity_in, quantity_out, unit_cost, reason, created_at, created_by,
			status, reservation_id, shipment_id, transfer_order_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), $15, $16, $17, $18, $19)
		RETURNING created_at
	`
	for _, m := range movements {
		err := db.QueryRowContext(ctx, query,
			m.MovementID, m.CompanyID, m.MovementType, m.ReferenceType, m.ReferenceID,
			m.MovementDate, m.WarehouseID, m.FromWarehouseID, m.ItemID, m.BatchID,
			m.QuantityIn.InexactFloat64(), m.QuantityOut.InexactFloat64(), m.UnitCost.InexactFloat64(),
			m.Reason, m.CreatedBy,
			m.Status, m.ReservationID, m.ShipmentID, m.TransferOrderID,
		).Scan(&m.CreatedAt)
		if err != nil {
			return fmt.Errorf("bulk create movement: %w", err)
		}
	}
	return nil
}

func (r *movementRepository) CreateIfNotExists(ctx context.Context, db DBTX, movement *models.StockMovement) (*models.StockMovement, error) {
	exists, err := r.ExistsByReference(ctx, db, movement.CompanyID,
		nullStr(movement.ReferenceType), nullUUID(movement.ReferenceID),
		movement.ItemID, movement.WarehouseID, movement.BatchID)
	if err != nil {
		return nil, err
	}
	if exists {
		filter := MovementFilter{
			CompanyID:     movement.CompanyID,
			ReferenceType: movement.ReferenceType,
			ReferenceID:   movement.ReferenceID,
			ItemID:        &movement.ItemID,
			WarehouseID:   &movement.WarehouseID,
			BatchID:       movement.BatchID,
		}
		list, err := r.List(ctx, db, filter, Pagination{Limit: 1}, Sort{Field: "created_at", Direction: "DESC"})
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("idempotency: movement claimed exists but not found")
		}
		return list[0], nil
	}
	if err := r.CreateMovement(ctx, db, movement); err != nil {
		return nil, err
	}
	return movement, nil
}

func (r *movementRepository) UpdateStatus(ctx context.Context, db DBTX, movementID uuid.UUID, status string) error {
	query := `UPDATE stock_movements SET status = $2 WHERE movement_id = $1`
	res, err := db.ExecContext(ctx, query, movementID, status)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: movement %s", inventory_errors.ErrNotFound, movementID)
	}
	return nil
}

func (r *movementRepository) UpdateMovement(ctx context.Context, db DBTX, movement *models.StockMovement) error {
	query := `
		UPDATE stock_movements
		SET reservation_id = $2,
		    shipment_id = $3,
		    transfer_order_id = $4,
		    status = $5
		WHERE movement_id = $1
	`
	_, err := db.ExecContext(ctx, query,
		movement.MovementID, movement.ReservationID, movement.ShipmentID, movement.TransferOrderID, movement.Status)
	if err != nil {
		return fmt.Errorf("update movement: %w", err)
	}
	return nil
}

// ---------- fetch operations (SELECT now includes new columns) ----------

func (r *movementRepository) GetByID(ctx context.Context, db DBTX, movementID uuid.UUID) (*models.StockMovement, error) {
	query := `
		SELECT movement_id, company_id, movement_type, reference_type, reference_id,
		       movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
		       quantity_in, quantity_out, unit_cost, total_cost, reason, created_at, created_by,
		       status, reservation_id, shipment_id, transfer_order_id
		FROM stock_movements
		WHERE movement_id = $1
	`
	row := db.QueryRowContext(ctx, query, movementID)
	return r.scanMovement(row)
}

func (r *movementRepository) GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType string, referenceID uuid.UUID) ([]*models.StockMovement, error) {
	filter := MovementFilter{
		CompanyID:     companyID,
		ReferenceType: &referenceType,
		ReferenceID:   &referenceID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "movement_date", Direction: "ASC"})
}

func (r *movementRepository) List(ctx context.Context, db DBTX, filter MovementFilter, p Pagination, s Sort) ([]*models.StockMovement, error) {
	where, args := r.buildMovementFilter(filter)
	allowedSort := map[string]bool{
		"movement_date": true,
		"created_at":    true,
		"movement_type": true,
		"reference_id":  true,
		"status":        true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY movement_date DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT movement_id, company_id, movement_type, reference_type, reference_id,
		       movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
		       quantity_in, quantity_out, unit_cost, total_cost, reason, created_at, created_by,
		       status, reservation_id, shipment_id, transfer_order_id
		FROM stock_movements
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list movements: %w", err)
	}
	defer rows.Close()

	var result []*models.StockMovement
	for rows.Next() {
		m, err := r.scanMovement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func (r *movementRepository) Count(ctx context.Context, db DBTX, filter MovementFilter) (int64, error) {
	where, args := r.buildMovementFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM stock_movements %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count movements: %w", err)
	}
	return count, nil
}

// ---------- specialized queries ----------

func (r *movementRepository) GetItemMovements(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, from, to time.Time) ([]*models.StockMovement, error) {
	filter := MovementFilter{
		CompanyID: companyID,
		ItemID:    &itemID,
		DateFrom:  &from,
		DateTo:    &to,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "movement_date", Direction: "ASC"})
}

func (r *movementRepository) GetWarehouseMovements(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID, from, to time.Time) ([]*models.StockMovement, error) {
	filter := MovementFilter{
		CompanyID:   companyID,
		WarehouseID: &warehouseID,
		DateFrom:    &from,
		DateTo:      &to,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "movement_date", Direction: "ASC"})
}

func (r *movementRepository) GetBatchMovements(ctx context.Context, db DBTX, companyID uuid.UUID, batchID uuid.UUID) ([]*models.StockMovement, error) {
	filter := MovementFilter{
		CompanyID: companyID,
		BatchID:   &batchID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "movement_date", Direction: "ASC"})
}

// ---------- transfer support ----------

func (r *movementRepository) GetTransferMovements(ctx context.Context, db DBTX, companyID uuid.UUID, referenceID uuid.UUID) ([]*models.StockMovement, error) {
	refType := "transfer"
	filter := MovementFilter{
		CompanyID:     companyID,
		ReferenceType: &refType,
		ReferenceID:   &referenceID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 100}, Sort{Field: "movement_date", Direction: "ASC"})
}

// ---------- new methods for shipment/transfer links ----------

func (r *movementRepository) GetByShipmentID(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.StockMovement, error) {
	query := `
		SELECT movement_id, company_id, movement_type, reference_type, reference_id,
		       movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
		       quantity_in, quantity_out, unit_cost, total_cost, reason, created_at, created_by,
		       status, reservation_id, shipment_id, transfer_order_id
		FROM stock_movements
		WHERE shipment_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, shipmentID)
	if err != nil {
		return nil, fmt.Errorf("get by shipment id: %w", err)
	}
	defer rows.Close()
	var result []*models.StockMovement
	for rows.Next() {
		m, err := r.scanMovement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}
func (r *movementRepository) GetByTransferOrderID(ctx context.Context, db DBTX, transferOrderID uuid.UUID) ([]*models.StockMovement, error) {
	query := `
		SELECT movement_id, company_id, movement_type, reference_type, reference_id,
		       movement_date, warehouse_id, from_warehouse_id, item_id, batch_id,
		       quantity_in, quantity_out, unit_cost, total_cost, reason, created_at, created_by,
		       status, reservation_id, shipment_id, transfer_order_id
		FROM stock_movements
		WHERE transfer_order_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, transferOrderID)
	if err != nil {
		return nil, fmt.Errorf("get by transfer order id: %w", err)
	}
	defer rows.Close()
	var result []*models.StockMovement
	for rows.Next() {
		m, err := r.scanMovement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// ---------- validation / checks ----------

func (r *movementRepository) ExistsByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType string, referenceID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, batchID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM stock_movements
			WHERE company_id = $1
			  AND reference_type = $2
			  AND reference_id = $3
			  AND item_id = $4
			  AND warehouse_id = $5
			  AND ($6::uuid IS NULL OR batch_id = $6)
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, referenceType, referenceID, itemID, warehouseID, batchID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by reference: %w", err)
	}
	return exists, nil
}

// ---------- costing support ----------

func (r *movementRepository) GetLatestUnitCost(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID) (float64, error) {
	query := `
		SELECT unit_cost
		FROM stock_movements
		WHERE company_id = $1 AND item_id = $2 AND warehouse_id = $3
		  AND quantity_in > 0
		ORDER BY movement_date DESC, created_at DESC
		LIMIT 1
	`
	var cost float64
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&cost)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get latest unit cost: %w", err)
	}
	return cost, nil
}

func (r *movementRepository) GetAverageCost(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID) (float64, error) {
	query := `
		SELECT COALESCE(SUM(total_cost) / NULLIF(SUM(CASE WHEN quantity_in > 0 THEN quantity_in ELSE quantity_out END), 0), 0)
		FROM stock_movements
		WHERE company_id = $1 AND item_id = $2 AND warehouse_id = $3
		  AND quantity_in > 0
	`
	var avg float64
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&avg)
	if err != nil {
		return 0, fmt.Errorf("get average cost: %w", err)
	}
	return avg, nil
}

// ---------- audit ----------

func (r *movementRepository) GetMovementTrail(ctx context.Context, db DBTX, movementID uuid.UUID) (*MovementTrail, error) {
	trail := &MovementTrail{}

	movement, err := r.GetByID(ctx, db, movementID)
	if err != nil {
		return nil, err
	}
	trail.Movement = movement

	allocQuery := `
		SELECT allocation_id, company_id, movement_id, source_ledger_id, quantity, unit_cost, created_at
		FROM stock_allocations
		WHERE movement_id = $1
	`
	rows, err := db.QueryContext(ctx, allocQuery, movementID)
	if err != nil {
		return nil, fmt.Errorf("get allocations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		a := &models.StockAllocation{}
		err := rows.Scan(&a.AllocationID, &a.CompanyID, &a.MovementID, &a.SourceLedgerID, &a.Quantity, &a.UnitCost, &a.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan allocation: %w", err)
		}
		trail.Allocations = append(trail.Allocations, a)
	}

	ledgerQuery := `
		SELECT ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
		       transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at
		FROM stock_ledger
		WHERE movement_id = $1
	`
	rows2, err := db.QueryContext(ctx, ledgerQuery, movementID)
	if err != nil {
		return nil, fmt.Errorf("get ledger entries: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		l := &models.StockLedger{}
		err := rows2.Scan(&l.LedgerID, &l.CompanyID, &l.WarehouseID, &l.ItemID, &l.BatchID, &l.MovementID,
			&l.TransactionDate, &l.QuantityIn, &l.QuantityOut, &l.UnitCost, &l.RunningBalance, &l.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan ledger: %w", err)
		}
		trail.LedgerEntries = append(trail.LedgerEntries, l)
	}

	return trail, nil
}

// ---------- scanning helper (updated to include new columns) ----------

func (r *movementRepository) scanMovement(s scanner) (*models.StockMovement, error) {
	var m models.StockMovement
	var referenceType, reason sql.NullString
	var referenceID, fromWarehouseID, batchID, createdBy uuid.NullUUID
	var status string
	var reservationID, shipmentID, transferOrderID uuid.NullUUID
	var quantityIn, quantityOut, unitCost, totalCost float64

	err := s.Scan(
		&m.MovementID, &m.CompanyID, &m.MovementType, &referenceType, &referenceID,
		&m.MovementDate, &m.WarehouseID, &fromWarehouseID, &m.ItemID, &batchID,
		&quantityIn, &quantityOut, &unitCost, &totalCost, &reason, &m.CreatedAt, &createdBy,
		&status, &reservationID, &shipmentID, &transferOrderID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan movement: %w", err)
	}

	if referenceType.Valid {
		m.ReferenceType = &referenceType.String
	}
	if referenceID.Valid {
		m.ReferenceID = &referenceID.UUID
	}
	if fromWarehouseID.Valid {
		m.FromWarehouseID = &fromWarehouseID.UUID
	}
	if batchID.Valid {
		m.BatchID = &batchID.UUID
	}
	if reason.Valid {
		m.Reason = &reason.String
	}
	if createdBy.Valid {
		m.CreatedBy = &createdBy.UUID
	}
	m.Status = status
	if reservationID.Valid {
		m.ReservationID = &reservationID.UUID
	}
	if shipmentID.Valid {
		m.ShipmentID = &shipmentID.UUID
	}
	if transferOrderID.Valid {
		m.TransferOrderID = &transferOrderID.UUID
	}
	m.QuantityIn = decimal.NewFromFloat(quantityIn)
	m.QuantityOut = decimal.NewFromFloat(quantityOut)
	m.UnitCost = decimal.NewFromFloat(unitCost)
	_ = totalCost

	return &m, nil
}

func nullStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullUUID(u *uuid.UUID) uuid.UUID {
	if u == nil {
		return uuid.Nil
	}
	return *u
}

// GetCOGSByPeriod returns total cost of goods sold (sales_out and consumption) for an item.
func (r *movementRepository) GetCOGSByPeriod(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, from, to time.Time) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(SUM(total_cost), 0)
        FROM stock_movements
        WHERE company_id = $1
          AND item_id = $2
          AND movement_type IN ('sales_out', 'production_out', 'adjustment_out')
          AND movement_date BETWEEN $3 AND $4
    `
	var cogs float64
	err := db.QueryRowContext(ctx, query, companyID, itemID, from, to).Scan(&cogs)
	if err != nil {
		return decimal.Zero, fmt.Errorf("GetCOGSByPeriod: %w", err)
	}
	return decimal.NewFromFloat(cogs), nil
}

func (r *movementRepository) IsCancelled(ctx context.Context, db DBTX, movementID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM stock_movements
		WHERE reference_type = 'cancellation'
		  AND reference_id = $1
	)`
	var exists bool
	err := db.QueryRowContext(ctx, query, movementID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check cancellation: %w", err)
	}
	return exists, nil
}
