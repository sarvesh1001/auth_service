// repository/stock_ledger_repository.go
package repository

import (
	"context"
	"database/sql"
	"errors"
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

// DailyBalance – used for time‑series analytics
type DailyBalance struct {
	Date           time.Time
	ClosingBalance float64
}

// StockLedgerFilter for ledger queries
type StockLedgerFilter struct {
	CompanyID   uuid.UUID
	ItemID      *uuid.UUID
	BatchID     *uuid.UUID
	WarehouseID *uuid.UUID
	DateFrom    *time.Time
	DateTo      *time.Time
	MovementID  *uuid.UUID
}

// StockLedgerRepository interface – immutable ledger, FIFO support, audit
type StockLedgerRepository interface {
	// Write operations (only inserts, never update/delete)
	Create(ctx context.Context, db DBTX, entry *models.StockLedger) error
	BulkCreate(ctx context.Context, db DBTX, entries []*models.StockLedger) error

	// FIFO layers – use stored remaining_quantity for performance
	GetFIFOLayers(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, warehouseID *uuid.UUID, asOfDate time.Time) ([]*FIFOLayer, error)

	// Update remaining quantity after partial allocation (FIFO consumption)
	UpdateRemainingQuantity(ctx context.Context, db DBTX, ledgerID uuid.UUID, remainingQty decimal.Decimal) error

	// Fetch single / by movement / by item+batch
	GetByID(ctx context.Context, db DBTX, ledgerID uuid.UUID) (*models.StockLedger, error)
	GetByMovementID(ctx context.Context, db DBTX, movementID uuid.UUID) ([]*models.StockLedger, error)
	GetByItemBatch(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchID *uuid.UUID) ([]*models.StockLedger, error)

	// FIFO & costing (legacy, may be replaced by GetFIFOLayers)
	GetAvailableLayersFIFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) ([]*models.StockLedger, error)
	GetBalanceBeforeDate(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, date time.Time) (float64, error)
	GetLatestBalance(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) (float64, error)

	// List + Count with filters
	List(ctx context.Context, db DBTX, filter StockLedgerFilter, p Pagination, s Sort) ([]*models.StockLedger, error)
	Count(ctx context.Context, db DBTX, filter StockLedgerFilter) (int64, error)

	// Audit & time‑series
	GetLedgerStatement(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, from, to time.Time) ([]*models.StockLedger, error)
	GetDailyClosingBalances(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, from, to time.Time) ([]*DailyBalance, error)

	// Consistency & repair
	CheckNegativeStock(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) (bool, error)
	RebuildRunningBalance(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) error
}

type stockLedgerRepository struct {
	logger *zap.Logger
}

func NewStockLedgerRepository(logger *zap.Logger) StockLedgerRepository {
	return &stockLedgerRepository{
		logger: logger.Named("stock_ledger_repo"),
	}
}

// ---------- helpers ----------
func (r *stockLedgerRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *stockLedgerRepository) validatePagination(p Pagination) (int, int) {
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

func (r *stockLedgerRepository) buildLedgerFilter(filter StockLedgerFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
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
	if filter.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, *filter.WarehouseID)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("transaction_date >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("transaction_date <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}
	if filter.MovementID != nil {
		conds = append(conds, fmt.Sprintf("movement_id = $%d", idx))
		args = append(args, *filter.MovementID)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanLedger – returns ErrNotFound when no row exists
// Includes remaining_quantity column (nullable)
func (r *stockLedgerRepository) scanLedger(s scanner) (*models.StockLedger, error) {
	var entry models.StockLedger
	var warehouseID, batchID uuid.NullUUID
	var remainingQty sql.NullFloat64

	err := s.Scan(
		&entry.LedgerID,
		&entry.CompanyID,
		&warehouseID,
		&entry.ItemID,
		&batchID,
		&entry.MovementID,
		&entry.TransactionDate,
		&entry.QuantityIn,
		&entry.QuantityOut,
		&entry.UnitCost,
		&entry.RunningBalance,
		&entry.CreatedAt,
		&remainingQty,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan ledger: %w", err)
	}

	if warehouseID.Valid {
		entry.WarehouseID = &warehouseID.UUID
	}
	if batchID.Valid {
		entry.BatchID = &batchID.UUID
	}
	if remainingQty.Valid {
		rem := decimal.NewFromFloat(remainingQty.Float64)
		entry.RemainingQuantity = &rem
	} else {
		entry.RemainingQuantity = nil
	}
	return &entry, nil
}

// ---------- Write operations ----------
func (r *stockLedgerRepository) Create(ctx context.Context, db DBTX, entry *models.StockLedger) error {
	query := `
		INSERT INTO stock_ledger (
			ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
			transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at,
			remaining_quantity
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	var remainingQty interface{}
	if entry.RemainingQuantity != nil {
		remainingQty = entry.RemainingQuantity
	} else {
		remainingQty = nil
	}
	_, err := db.ExecContext(ctx, query,
		entry.LedgerID, entry.CompanyID, entry.WarehouseID, entry.ItemID, entry.BatchID,
		entry.MovementID, entry.TransactionDate, entry.QuantityIn, entry.QuantityOut,
		entry.UnitCost, entry.RunningBalance, entry.CreatedAt, remainingQty,
	)
	if err != nil {
		r.logger.Error("failed to create ledger entry", util.ErrorField(err))
		return fmt.Errorf("create ledger entry: %w", err)
	}
	return nil
}

func (r *stockLedgerRepository) BulkCreate(ctx context.Context, db DBTX, entries []*models.StockLedger) error {
	if len(entries) == 0 {
		return nil
	}
	for _, e := range entries {
		if err := r.Create(ctx, db, e); err != nil {
			return fmt.Errorf("bulk create failed at entry %v: %w", e.LedgerID, err)
		}
	}
	return nil
}

// ---------- Update remaining quantity (used by FIFO allocation) ----------
func (r *stockLedgerRepository) UpdateRemainingQuantity(ctx context.Context, db DBTX, ledgerID uuid.UUID, remainingQty decimal.Decimal) error {
	query := `
		UPDATE stock_ledger
		SET remaining_quantity = $2
		WHERE ledger_id = $1
	`
	_, err := db.ExecContext(ctx, query, ledgerID, remainingQty)
	if err != nil {
		return fmt.Errorf("update remaining quantity: %w", err)
	}
	return nil
}

// ---------- Fetch methods ----------
func (r *stockLedgerRepository) GetByID(ctx context.Context, db DBTX, ledgerID uuid.UUID) (*models.StockLedger, error) {
	query := `
		SELECT ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
		       transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at,
		       remaining_quantity
		FROM stock_ledger WHERE ledger_id = $1
	`
	row := db.QueryRowContext(ctx, query, ledgerID)
	entry, err := r.scanLedger(row)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			return nil, fmt.Errorf("%w: ledger %s", inventory_errors.ErrNotFound, ledgerID)
		}
		return nil, err
	}
	return entry, nil
}

func (r *stockLedgerRepository) GetByMovementID(ctx context.Context, db DBTX, movementID uuid.UUID) ([]*models.StockLedger, error) {
	query := `
		SELECT ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
		       transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at,
		       remaining_quantity
		FROM stock_ledger WHERE movement_id = $1
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, movementID)
	if err != nil {
		return nil, fmt.Errorf("get by movement id: %w", err)
	}
	defer rows.Close()

	var result []*models.StockLedger
	for rows.Next() {
		e, err := r.scanLedger(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (r *stockLedgerRepository) GetByItemBatch(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchID *uuid.UUID) ([]*models.StockLedger, error) {
	filter := StockLedgerFilter{
		CompanyID: companyID,
		ItemID:    &itemID,
		BatchID:   batchID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "transaction_date", Direction: "ASC"})
}

// ---------- FIFO & costing ----------
func (r *stockLedgerRepository) GetAvailableLayersFIFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) ([]*models.StockLedger, error) {
	query := `
		SELECT ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
		       transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at,
		       remaining_quantity
		FROM stock_ledger
		WHERE company_id = $1
		  AND item_id = $2
		  AND ($3::uuid IS NULL OR warehouse_id = $3)
		  AND quantity_in > 0
		  AND COALESCE(remaining_quantity, quantity_in - quantity_out) > 0
		ORDER BY transaction_date ASC, created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get available layers FIFO: %w", err)
	}
	defer rows.Close()

	var layers []*models.StockLedger
	for rows.Next() {
		l, err := r.scanLedger(rows)
		if err != nil {
			return nil, err
		}
		layers = append(layers, l)
	}
	return layers, rows.Err()
}

func (r *stockLedgerRepository) GetBalanceBeforeDate(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, date time.Time) (float64, error) {
	query := `
		SELECT COALESCE(running_balance, 0)
		FROM stock_ledger
		WHERE company_id = $1
		  AND item_id = $2
		  AND ($3::uuid IS NULL OR warehouse_id = $3)
		  AND transaction_date < $4
		ORDER BY transaction_date DESC, created_at DESC
		LIMIT 1
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID, date).Scan(&balance)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get balance before date: %w", err)
	}
	f64, _ := balance.Float64()
	return f64, nil
}

func (r *stockLedgerRepository) GetLatestBalance(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) (float64, error) {
	query := `
		SELECT COALESCE(running_balance, 0)
		FROM stock_ledger
		WHERE company_id = $1
		  AND item_id = $2
		  AND ($3::uuid IS NULL OR warehouse_id = $3)
		ORDER BY transaction_date DESC, created_at DESC
		LIMIT 1
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&balance)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get latest balance: %w", err)
	}
	f64, _ := balance.Float64()
	return f64, nil
}

// ---------- List & Count ----------
func (r *stockLedgerRepository) List(ctx context.Context, db DBTX, filter StockLedgerFilter, p Pagination, s Sort) ([]*models.StockLedger, error) {
	where, args := r.buildLedgerFilter(filter)

	allowedSort := map[string]bool{
		"transaction_date": true,
		"created_at":       true,
		"running_balance":  true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY transaction_date ASC, created_at ASC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT ledger_id, company_id, warehouse_id, item_id, batch_id, movement_id,
		       transaction_date, quantity_in, quantity_out, unit_cost, running_balance, created_at,
		       remaining_quantity
		FROM stock_ledger
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ledger entries: %w", err)
	}
	defer rows.Close()

	var result []*models.StockLedger
	for rows.Next() {
		e, err := r.scanLedger(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (r *stockLedgerRepository) Count(ctx context.Context, db DBTX, filter StockLedgerFilter) (int64, error) {
	where, args := r.buildLedgerFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM stock_ledger %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count ledger entries: %w", err)
	}
	return count, nil
}

// ---------- Audit & time‑series ----------
func (r *stockLedgerRepository) GetLedgerStatement(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, from, to time.Time) ([]*models.StockLedger, error) {
	filter := StockLedgerFilter{
		CompanyID:   companyID,
		ItemID:      &itemID,
		WarehouseID: warehouseID,
		DateFrom:    &from,
		DateTo:      &to,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "transaction_date", Direction: "ASC"})
}

func (r *stockLedgerRepository) GetDailyClosingBalances(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID, from, to time.Time) ([]*DailyBalance, error) {
	query := `
		WITH daily AS (
			SELECT DISTINCT transaction_date
			FROM generate_series($1::date, $2::date, '1 day'::interval) AS transaction_date
		)
		SELECT d.transaction_date,
		       COALESCE(
		           (SELECT running_balance
		            FROM stock_ledger sl
		            WHERE sl.company_id = $3
		              AND sl.item_id = $4
		              AND ($5::uuid IS NULL OR sl.warehouse_id = $5)
		              AND sl.transaction_date <= d.transaction_date
		            ORDER BY sl.transaction_date DESC, sl.created_at DESC
		            LIMIT 1), 0) AS closing_balance
		FROM daily d
		ORDER BY d.transaction_date ASC
	`
	rows, err := db.QueryContext(ctx, query, from, to, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get daily closing balances: %w", err)
	}
	defer rows.Close()

	var results []*DailyBalance
	for rows.Next() {
		var db DailyBalance
		var balance decimal.Decimal
		if err := rows.Scan(&db.Date, &balance); err != nil {
			return nil, fmt.Errorf("scan daily balance: %w", err)
		}
		db.ClosingBalance, _ = balance.Float64()
		results = append(results, &db)
	}
	return results, rows.Err()
}

// ---------- Consistency & repair ----------
func (r *stockLedgerRepository) CheckNegativeStock(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM stock_ledger
			WHERE company_id = $1
			  AND item_id = $2
			  AND ($3::uuid IS NULL OR warehouse_id = $3)
			  AND running_balance < 0
			LIMIT 1
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check negative stock: %w", err)
	}
	return exists, nil
}

func (r *stockLedgerRepository) RebuildRunningBalance(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) error {
	query := `
		WITH ordered AS (
			SELECT ledger_id,
			       SUM(quantity_in - quantity_out) OVER (ORDER BY transaction_date ASC, created_at ASC) AS new_balance
			FROM stock_ledger
			WHERE company_id = $1
			  AND item_id = $2
			  AND ($3::uuid IS NULL OR warehouse_id = $3)
		)
		UPDATE stock_ledger
		SET running_balance = ordered.new_balance
		FROM ordered
		WHERE stock_ledger.ledger_id = ordered.ledger_id
	`
	_, err := db.ExecContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return fmt.Errorf("rebuild running balance: %w", err)
	}
	return nil
}

// GetFIFOLayers returns active inbound layers using stored remaining_quantity (if set)
// or falling back to on‑the‑fly calculation. This is the preferred method for FIFO valuation.
func (r *stockLedgerRepository) GetFIFOLayers(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, warehouseID *uuid.UUID, asOfDate time.Time) ([]*FIFOLayer, error) {
	// First, try to use stored remaining_quantity for speed.
	queryStored := `
        SELECT ledger_id, transaction_date, quantity_in, unit_cost,
               COALESCE(remaining_quantity, quantity_in - quantity_out) AS remaining_qty
        FROM stock_ledger
        WHERE company_id = $1
          AND item_id = $2
          AND ($3::uuid IS NULL OR warehouse_id = $3)
          AND transaction_date <= $4
          AND quantity_in > 0
          AND COALESCE(remaining_quantity, quantity_in - quantity_out) > 0
        ORDER BY transaction_date, created_at
    `
	rows, err := db.QueryContext(ctx, queryStored, companyID, itemID, warehouseID, asOfDate)
	if err != nil {
		return nil, fmt.Errorf("GetFIFOLayers query (stored): %w", err)
	}
	defer rows.Close()

	var layers []*FIFOLayer
	for rows.Next() {
		var l FIFOLayer
		if err := rows.Scan(&l.LedgerID, &l.TransactionDate, &l.QuantityIn, &l.UnitCost, &l.RemainingQty); err != nil {
			return nil, fmt.Errorf("scan FIFO layer: %w", err)
		}
		layers = append(layers, &l)
	}
	return layers, rows.Err()
}

// FIFOLayer represents a remaining cost layer for FIFO valuation.
type FIFOLayer struct {
	LedgerID        uuid.UUID
	TransactionDate time.Time
	QuantityIn      decimal.Decimal
	UnitCost        decimal.Decimal
	RemainingQty    decimal.Decimal
}
