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

type StockBalanceRepository interface {
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StockBalance, error)
	GetByItemWarehouse(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*models.StockBalance, error)
	GetAvailableStock(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) ([]*models.StockBalance, error)
	GetByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID) ([]*models.StockBalance, error)
	GetByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) ([]*models.StockBalance, error)
	GetByItems(ctx context.Context, db DBTX, companyID uuid.UUID, itemIDs []uuid.UUID) ([]*models.StockBalance, error)
	GetByWarehouses(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseIDs []uuid.UUID) ([]*models.StockBalance, error)
	UpsertStock(ctx context.Context, db DBTX, balance *models.StockBalance) error
	IncreaseStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error
	DecreaseStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error
	ReserveStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error
	ReleaseReservation(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error
	GetForUpdate(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*models.StockBalance, error)
	CheckAvailability(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, requiredQty float64) (bool, error)
	GetTotalOnHand(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, warehouseID *uuid.UUID) (decimal.Decimal, error)
	GetTotalStockByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) (float64, error)
	GetByWarehouseAndItem(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID) (decimal.Decimal, error)
	GetTotalStockByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID) (float64, error)
	GetLowStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.StockBalance, error)
	GetByFilters(ctx context.Context, db DBTX, filter StockBalanceFilter) ([]*models.StockBalance, error)
	GetOutOfStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.StockBalance, error)
}

type stockBalanceRepository struct {
	logger *zap.Logger
}

func NewStockBalanceRepository(logger *zap.Logger) StockBalanceRepository {
	return &stockBalanceRepository{
		logger: logger.Named("stock_balance_repo"),
	}
}

func toDecimal(f float64) decimal.Decimal {
	return decimal.NewFromFloat(f).Truncate(4)
}

func toFloat64(d decimal.Decimal) float64 {
	f, _ := d.Float64()
	return f
}

// nullUUIDParam returns nil for a nil or zero UUID pointer.
// Used in INSERT/UPDATE to set batch_id = NULL.
func nullUUIDParam(uuidPtr *uuid.UUID) interface{} {
	if uuidPtr == nil || *uuidPtr == uuid.Nil {
		return nil
	}
	return *uuidPtr
}

func (r *stockBalanceRepository) scanStockBalance(s scanner) (*models.StockBalance, error) {
	var sb models.StockBalance
	var batchID uuid.NullUUID
	err := s.Scan(
		&sb.StockBalanceID,
		&sb.CompanyID,
		&sb.WarehouseID,
		&sb.ItemID,
		&batchID,
		&sb.QuantityOnHand,
		&sb.ReservedQty,
		&sb.AvailableQty,
		&sb.LastMovementAt,
		&sb.CreatedAt,
		&sb.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan stock balance: %w", err)
	}
	if batchID.Valid {
		sb.BatchID = &batchID.UUID
	}
	return &sb, nil
}

func (r *stockBalanceRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StockBalance, error) {
	query := `
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE stock_balance_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStockBalance(row)
}

// GetByItemWarehouse – split query to avoid untyped NULL parameter
func (r *stockBalanceRepository) GetByItemWarehouse(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*models.StockBalance, error) {
	var row *sql.Row
	if batchID == nil {
		// No batch specified: match NULL batch_id
		query := `
			SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
			       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
			       created_at, updated_at
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
		`
		row = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID)
	} else {
		// Specific batch (including zero UUID) – match exactly
		query := `
			SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
			       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
			       created_at, updated_at
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
		`
		row = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID, *batchID)
	}
	return r.scanStockBalance(row)
}

func (r *stockBalanceRepository) GetAvailableStock(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) ([]*models.StockBalance, error) {
	query := `
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE company_id = $1 AND item_id = $2 AND available_qty > 0
		ORDER BY warehouse_id, batch_id
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID)
	if err != nil {
		return nil, fmt.Errorf("get available stock: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID) ([]*models.StockBalance, error) {
	query := `
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE company_id = $1 AND warehouse_id = $2
		ORDER BY item_id, batch_id
	`
	rows, err := db.QueryContext(ctx, query, companyID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get by warehouse: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) ([]*models.StockBalance, error) {
	query := `
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE company_id = $1 AND item_id = $2
		ORDER BY warehouse_id, batch_id
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID)
	if err != nil {
		return nil, fmt.Errorf("get by item: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetByItems(ctx context.Context, db DBTX, companyID uuid.UUID, itemIDs []uuid.UUID) ([]*models.StockBalance, error) {
	if len(itemIDs) == 0 {
		return []*models.StockBalance{}, nil
	}
	placeholders := make([]string, len(itemIDs))
	args := make([]interface{}, len(itemIDs)+1)
	args[0] = companyID
	for i, id := range itemIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := fmt.Sprintf(`
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE company_id = $1 AND item_id IN (%s)
	`, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get by items: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetByWarehouses(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseIDs []uuid.UUID) ([]*models.StockBalance, error) {
	if len(warehouseIDs) == 0 {
		return []*models.StockBalance{}, nil
	}
	placeholders := make([]string, len(warehouseIDs))
	args := make([]interface{}, len(warehouseIDs)+1)
	args[0] = companyID
	for i, id := range warehouseIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := fmt.Sprintf(`
		SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
		       created_at, updated_at
		FROM stock_balances
		WHERE company_id = $1 AND warehouse_id IN (%s)
	`, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get by warehouses: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

// UpsertStock uses partial unique indexes to handle NULL and non‑NULL batch_id
func (r *stockBalanceRepository) UpsertStock(ctx context.Context, db DBTX, balance *models.StockBalance) error {
	var query string
	var args []interface{}

	if balance.BatchID == nil {
		query = `
			INSERT INTO stock_balances (
				stock_balance_id, company_id, warehouse_id, item_id, batch_id,
				quantity_on_hand, reserved_qty, last_movement_at, created_at, updated_at
			) VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, NOW(), NOW())
			ON CONFLICT (company_id, warehouse_id, item_id) WHERE batch_id IS NULL
			DO UPDATE SET
				quantity_on_hand = EXCLUDED.quantity_on_hand,
				reserved_qty = EXCLUDED.reserved_qty,
				last_movement_at = EXCLUDED.last_movement_at,
				updated_at = NOW()
		`
		args = []interface{}{
			balance.StockBalanceID,
			balance.CompanyID,
			balance.WarehouseID,
			balance.ItemID,
			balance.QuantityOnHand,
			balance.ReservedQty,
			balance.LastMovementAt,
		}
	} else {
		query = `
			INSERT INTO stock_balances (
				stock_balance_id, company_id, warehouse_id, item_id, batch_id,
				quantity_on_hand, reserved_qty, last_movement_at, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
			ON CONFLICT (company_id, warehouse_id, item_id, batch_id) WHERE batch_id IS NOT NULL
			DO UPDATE SET
				quantity_on_hand = EXCLUDED.quantity_on_hand,
				reserved_qty = EXCLUDED.reserved_qty,
				last_movement_at = EXCLUDED.last_movement_at,
				updated_at = NOW()
		`
		args = []interface{}{
			balance.StockBalanceID,
			balance.CompanyID,
			balance.WarehouseID,
			balance.ItemID,
			*balance.BatchID,
			balance.QuantityOnHand,
			balance.ReservedQty,
			balance.LastMovementAt,
		}
	}

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("upsert stock failed", util.ErrorField(err))
		return fmt.Errorf("upsert stock: %w", err)
	}
	return nil
}

// IncreaseStock uses partial unique indexes for conflict detection
func (r *stockBalanceRepository) IncreaseStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error {
	qtyDec := toDecimal(quantity)

	if batchID == nil || *batchID == uuid.Nil {
		// Non-batch stock: conflict on (company_id, warehouse_id, item_id) WHERE batch_id IS NULL
		query := `
			INSERT INTO stock_balances (stock_balance_id, company_id, warehouse_id, item_id, batch_id, quantity_on_hand, reserved_qty)
			VALUES (gen_random_uuid(), $1, $2, $3, NULL, $4, 0)
			ON CONFLICT (company_id, warehouse_id, item_id) WHERE batch_id IS NULL
			DO UPDATE SET quantity_on_hand = stock_balances.quantity_on_hand + EXCLUDED.quantity_on_hand,
			              updated_at = NOW()
		`
		_, err := db.ExecContext(ctx, query, companyID, warehouseID, itemID, qtyDec)
		if err != nil {
			return fmt.Errorf("increase stock: %w", err)
		}
		return nil
	}

	// Batch-tracked stock: conflict on (company_id, warehouse_id, item_id, batch_id) WHERE batch_id IS NOT NULL
	query := `
		INSERT INTO stock_balances (stock_balance_id, company_id, warehouse_id, item_id, batch_id, quantity_on_hand, reserved_qty)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 0)
		ON CONFLICT (company_id, warehouse_id, item_id, batch_id) WHERE batch_id IS NOT NULL
		DO UPDATE SET quantity_on_hand = stock_balances.quantity_on_hand + EXCLUDED.quantity_on_hand,
		              updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, warehouseID, itemID, *batchID, qtyDec)
	if err != nil {
		return fmt.Errorf("increase stock: %w", err)
	}
	return nil
}

func (r *stockBalanceRepository) DecreaseStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error {
	qtyDec := toDecimal(quantity)
	var res sql.Result
	var err error
	if batchID == nil {
		query := `
			UPDATE stock_balances
			SET quantity_on_hand = quantity_on_hand - $4,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, qtyDec)
	} else {
		query := `
			UPDATE stock_balances
			SET quantity_on_hand = quantity_on_hand - $5,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, *batchID, qtyDec)
	}
	if err != nil {
		return fmt.Errorf("decrease stock: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: stock record not found for item", inventory_errors.ErrNotFound)
	}
	return nil
}

func (r *stockBalanceRepository) ReserveStock(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error {
	qtyDec := toDecimal(quantity)
	var res sql.Result
	var err error

	if batchID == nil {
		query := `
			UPDATE stock_balances
			SET reserved_qty = reserved_qty + $4,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
			  AND (quantity_on_hand - reserved_qty) >= $4
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, qtyDec)
	} else {
		query := `
			UPDATE stock_balances
			SET reserved_qty = reserved_qty + $5,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
			  AND (quantity_on_hand - reserved_qty) >= $5
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, *batchID, qtyDec)
	}
	if err != nil {
		return fmt.Errorf("reserve stock: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return inventory_errors.ErrInsufficientStock
	}
	return nil
}

func (r *stockBalanceRepository) ReleaseReservation(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, quantity float64) error {
	qtyDec := toDecimal(quantity)
	var res sql.Result
	var err error

	if batchID == nil {
		query := `
			UPDATE stock_balances
			SET reserved_qty = reserved_qty - $4,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
			  AND reserved_qty >= $4
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, qtyDec)
	} else {
		query := `
			UPDATE stock_balances
			SET reserved_qty = reserved_qty - $5,
			    updated_at = NOW()
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
			  AND reserved_qty >= $5
		`
		res, err = db.ExecContext(ctx, query, companyID, warehouseID, itemID, *batchID, qtyDec)
	}
	if err != nil {
		return fmt.Errorf("release reservation: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: reservation not found or insufficient reserved quantity", inventory_errors.ErrNotFound)
	}
	return nil
}

func (r *stockBalanceRepository) GetForUpdate(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*models.StockBalance, error) {
	var row *sql.Row
	if batchID == nil {
		query := `
			SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
			       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
			       created_at, updated_at
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
			FOR UPDATE
		`
		row = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID)
	} else {
		query := `
			SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
			       quantity_on_hand, reserved_qty, available_qty, last_movement_at,
			       created_at, updated_at
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
			FOR UPDATE
		`
		row = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID, *batchID)
	}
	return r.scanStockBalance(row)
}

func (r *stockBalanceRepository) CheckAvailability(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID, requiredQty float64) (bool, error) {
	qtyDec := toDecimal(requiredQty)
	var available bool
	var err error

	if batchID == nil {
		query := `
			SELECT (quantity_on_hand - reserved_qty) >= $4
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id IS NULL
		`
		err = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID, qtyDec).Scan(&available)
	} else {
		query := `
			SELECT (quantity_on_hand - reserved_qty) >= $5
			FROM stock_balances
			WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3
			  AND batch_id = $4
		`
		err = db.QueryRowContext(ctx, query, companyID, warehouseID, itemID, *batchID, qtyDec).Scan(&available)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check availability: %w", err)
	}
	return available, nil
}

func (r *stockBalanceRepository) GetTotalStockByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID) (float64, error) {
	query := `
		SELECT COALESCE(SUM(quantity_on_hand), 0)
		FROM stock_balances
		WHERE company_id = $1 AND item_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, itemID).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("get total stock by item: %w", err)
	}
	return toFloat64(total), nil
}

func (r *stockBalanceRepository) GetTotalStockByWarehouse(ctx context.Context, db DBTX, companyID, warehouseID uuid.UUID) (float64, error) {
	query := `
		SELECT COALESCE(SUM(quantity_on_hand), 0)
		FROM stock_balances
		WHERE company_id = $1 AND warehouse_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, warehouseID).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("get total stock by warehouse: %w", err)
	}
	return toFloat64(total), nil
}

func (r *stockBalanceRepository) GetLowStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.StockBalance, error) {
	query := `
		SELECT sb.stock_balance_id, sb.company_id, sb.warehouse_id, sb.item_id, sb.batch_id,
		       sb.quantity_on_hand, sb.reserved_qty, sb.available_qty, sb.last_movement_at,
		       sb.created_at, sb.updated_at
		FROM stock_balances sb
		JOIN items i ON i.item_id = sb.item_id AND i.company_id = sb.company_id
		WHERE sb.company_id = $1
		  AND sb.available_qty > 0
		  AND sb.available_qty < COALESCE(i.reorder_level, 0)
		ORDER BY (sb.available_qty / NULLIF(i.reorder_level, 0)) ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get low stock items: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetOutOfStockItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.StockBalance, error) {
	query := `
		SELECT sb.stock_balance_id, sb.company_id, sb.warehouse_id, sb.item_id, sb.batch_id,
		       sb.quantity_on_hand, sb.reserved_qty, sb.available_qty, sb.last_movement_at,
		       sb.created_at, sb.updated_at
		FROM stock_balances sb
		WHERE sb.company_id = $1
		  AND sb.available_qty <= 0
		ORDER BY sb.warehouse_id, sb.item_id
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get out of stock items: %w", err)
	}
	defer rows.Close()
	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetTotalOnHand(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, warehouseID *uuid.UUID) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(SUM(quantity_on_hand), 0)
        FROM stock_balances
        WHERE company_id = $1 AND item_id = $2
          AND ($3::uuid IS NULL OR warehouse_id = $3)
    `
	var total float64
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("GetTotalOnHand: %w", err)
	}
	return decimal.NewFromFloat(total), nil
}

type StockBalanceFilter struct {
	CompanyID   uuid.UUID
	WarehouseID *uuid.UUID
	ItemID      *uuid.UUID
	BatchID     *uuid.UUID
	MinOnHand   *decimal.Decimal
	MinAvail    *decimal.Decimal
}

func (r *stockBalanceRepository) GetByFilters(ctx context.Context, db DBTX, filter StockBalanceFilter) ([]*models.StockBalance, error) {
	conditions := []string{"company_id = $1"}
	args := []interface{}{filter.CompanyID}
	argIdx := 2

	if filter.WarehouseID != nil {
		conditions = append(conditions, fmt.Sprintf("warehouse_id = $%d", argIdx))
		args = append(args, *filter.WarehouseID)
		argIdx++
	}
	if filter.ItemID != nil {
		conditions = append(conditions, fmt.Sprintf("item_id = $%d", argIdx))
		args = append(args, *filter.ItemID)
		argIdx++
	}
	if filter.BatchID != nil {
		conditions = append(conditions, fmt.Sprintf("batch_id = $%d", argIdx))
		args = append(args, nullUUIDParam(filter.BatchID))
		argIdx++
	}
	if filter.MinOnHand != nil {
		conditions = append(conditions, fmt.Sprintf("quantity_on_hand >= $%d", argIdx))
		args = append(args, filter.MinOnHand)
		argIdx++
	}
	if filter.MinAvail != nil {
		conditions = append(conditions, fmt.Sprintf("available_qty >= $%d", argIdx))
		args = append(args, filter.MinAvail)
		argIdx++
	}

	query := `
        SELECT stock_balance_id, company_id, warehouse_id, item_id, batch_id,
               quantity_on_hand, reserved_qty, available_qty, last_movement_at,
               created_at, updated_at
        FROM stock_balances
        WHERE ` + strings.Join(conditions, " AND ") + `
        ORDER BY warehouse_id, item_id, batch_id NULLS FIRST
    `

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("GetByFilters query: %w", err)
	}
	defer rows.Close()

	var results []*models.StockBalance
	for rows.Next() {
		sb, err := r.scanStockBalance(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, sb)
	}
	return results, rows.Err()
}

func (r *stockBalanceRepository) GetByWarehouseAndItem(ctx context.Context, db DBTX, companyID, warehouseID, itemID uuid.UUID) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(SUM(available_qty), 0)
        FROM stock_balances
        WHERE company_id = $1
          AND warehouse_id = $2
          AND item_id = $3
    `
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, warehouseID, itemID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get by warehouse and item: %w", err)
	}
	return total, nil
}
