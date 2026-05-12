// repository/batch_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// BatchAllocationCandidate – used for FIFO/FEFO picking logic
type BatchAllocationCandidate struct {
	BatchID      uuid.UUID  `json:"batchId"`
	BatchNumber  string     `json:"batchNumber"`
	ExpiryDate   *time.Time `json:"expiryDate,omitempty"`
	AvailableQty float64    `json:"availableQty"`
	CostPerUnit  float64    `json:"costPerUnit"`
}

// BatchWithStock – joins batch + stock_balances data
type BatchWithStock struct {
	BatchID        uuid.UUID  `json:"batchId"`
	BatchNumber    string     `json:"batchNumber"`
	ExpiryDate     *time.Time `json:"expiryDate,omitempty"`
	ManufacturedAt *time.Time `json:"manufacturedAt,omitempty"`
	AvailableQty   float64    `json:"availableQty"`
	ReservedQty    float64    `json:"reservedQty"`
	CostPerUnit    float64    `json:"costPerUnit"`
}

// BatchFilter for advanced queries
type BatchFilter struct {
	CompanyID        uuid.UUID
	ItemID           *uuid.UUID
	IsActive         *bool
	ExpiryFrom       *time.Time
	ExpiryTo         *time.Time
	ManufacturedFrom *time.Time
	ManufacturedTo   *time.Time
	Search           string // search in batch_number or supplier_batch
}

// scanner interface – matches both *sql.Row and *sql.Rows
type scanner interface {
	Scan(dest ...interface{}) error
}

// BatchRepository interface
type BatchRepository interface {
	// Core CRUD
	Create(ctx context.Context, db DBTX, batch *models.Batch) error
	GetByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.Batch, error)
	GetByIDs(ctx context.Context, db DBTX, batchIDs []uuid.UUID) ([]*models.Batch, error)
	Update(ctx context.Context, db DBTX, batch *models.Batch) error
	Delete(ctx context.Context, db DBTX, batchID uuid.UUID) error

	// Business queries
	GetByItem(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, filter BatchFilter, p Pagination, s Sort) ([]*models.Batch, error)
	GetActiveBatchesByItem(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID) ([]*models.Batch, error)
	GetBatchByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchNumber string) (*models.Batch, error)

	// NEW: light-weight existence check to prevent duplicate batches
	ExistsByBatchNumber(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchNumber string) (bool, error)

	// Inventory critical – allocation & stock
	GetAvailableBatchesFIFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, requiredQty float64) ([]*BatchAllocationCandidate, error)
	GetAvailableBatchesFEFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, requiredQty float64) ([]*BatchAllocationCandidate, error)
	GetBatchesWithStock(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) ([]*BatchWithStock, error)

	// Expiry management
	GetExpiringBatches(ctx context.Context, db DBTX, companyID uuid.UUID, days int) ([]*models.Batch, error)
	GetExpiredBatches(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Batch, error)

	// Stock operations
	UpdateRemainingQuantity(ctx context.Context, db DBTX, batchID uuid.UUID, newQty float64) error
	AdjustBatchQuantity(ctx context.Context, db DBTX, batchID uuid.UUID, delta float64) error
}

type batchRepository struct {
	logger *zap.Logger
}

func NewBatchRepository(logger *zap.Logger) BatchRepository {
	return &batchRepository{
		logger: logger.Named("batch_repo"),
	}
}

// ---------- helpers ----------
func (r *batchRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *batchRepository) validatePagination(p Pagination) (int, int) {
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

func (r *batchRepository) buildBatchFilter(filter BatchFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("b.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("b.item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("b.is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.ExpiryFrom != nil {
		conds = append(conds, fmt.Sprintf("b.expiry_date >= $%d", idx))
		args = append(args, *filter.ExpiryFrom)
		idx++
	}
	if filter.ExpiryTo != nil {
		conds = append(conds, fmt.Sprintf("b.expiry_date <= $%d", idx))
		args = append(args, *filter.ExpiryTo)
		idx++
	}
	if filter.ManufacturedFrom != nil {
		conds = append(conds, fmt.Sprintf("b.manufactured_date >= $%d", idx))
		args = append(args, *filter.ManufacturedFrom)
		idx++
	}
	if filter.ManufacturedTo != nil {
		conds = append(conds, fmt.Sprintf("b.manufactured_date <= $%d", idx))
		args = append(args, *filter.ManufacturedTo)
		idx++
	}
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("(b.batch_number ILIKE $%d OR b.supplier_batch ILIKE $%d)", idx, idx+1))
		args = append(args, searchTerm, searchTerm)
		idx += 2
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Core CRUD (with RETURNING for timestamps) ----------

func (r *batchRepository) Create(ctx context.Context, db DBTX, batch *models.Batch) error {
	query := `
		INSERT INTO batches (
			batch_id, company_id, item_id, batch_number, supplier_batch,
			manufactured_date, expiry_date, received_date, quantity, remaining_qty,
			cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW(), $13, $14)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		batch.BatchID, batch.CompanyID, batch.ItemID, batch.BatchNumber, batch.SupplierBatch,
		batch.ManufacturedDate, batch.ExpiryDate, batch.ReceivedDate, batch.Quantity, batch.RemainingQty,
		batch.CostPerUnit, batch.IsActive, batch.CreatedBy, batch.UpdatedBy,
	).Scan(&batch.CreatedAt, &batch.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create batch", util.ErrorField(err))
		return fmt.Errorf("create batch: %w", err)
	}
	return nil
}

func (r *batchRepository) GetByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.Batch, error) {
	query := `
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches WHERE batch_id = $1
	`
	row := db.QueryRowContext(ctx, query, batchID)
	return r.scanBatch(row)
}

func (r *batchRepository) GetByIDs(ctx context.Context, db DBTX, batchIDs []uuid.UUID) ([]*models.Batch, error) {
	if len(batchIDs) == 0 {
		return []*models.Batch{}, nil
	}
	placeholders := make([]string, len(batchIDs))
	args := make([]interface{}, len(batchIDs))
	for i, id := range batchIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches WHERE batch_id IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get batches by ids: %w", err)
	}
	defer rows.Close()

	var result []*models.Batch
	for rows.Next() {
		b, err := r.scanBatch(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

func (r *batchRepository) Update(ctx context.Context, db DBTX, batch *models.Batch) error {
	query := `
		UPDATE batches SET
			batch_number = $2,
			supplier_batch = $3,
			manufactured_date = $4,
			expiry_date = $5,
			received_date = $6,
			quantity = $7,
			remaining_qty = $8,
			cost_per_unit = $9,
			is_active = $10,
			updated_at = NOW(),
			updated_by = $11
		WHERE batch_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		batch.BatchID, batch.BatchNumber, batch.SupplierBatch,
		batch.ManufacturedDate, batch.ExpiryDate, batch.ReceivedDate,
		batch.Quantity, batch.RemainingQty, batch.CostPerUnit, batch.IsActive, batch.UpdatedBy,
	).Scan(&batch.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: batch %s", inventory_errors.ErrNotFound, batch.BatchID)
		}
		return fmt.Errorf("update batch: %w", err)
	}
	return nil
}

func (r *batchRepository) Delete(ctx context.Context, db DBTX, batchID uuid.UUID) error {
	// Soft delete: just deactivate (business rule)
	query := `UPDATE batches SET is_active = false, updated_at = NOW() WHERE batch_id = $1`
	res, err := db.ExecContext(ctx, query, batchID)
	if err != nil {
		return fmt.Errorf("delete batch: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: batch %s", inventory_errors.ErrNotFound, batchID)
	}
	return nil
}

// ---------- Business queries ----------

func (r *batchRepository) GetByItem(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, filter BatchFilter, p Pagination, s Sort) ([]*models.Batch, error) {
	filter.CompanyID = companyID
	filter.ItemID = &itemID
	where, args := r.buildBatchFilter(filter)

	allowedSort := map[string]bool{
		"created_at":    true,
		"received_date": true,
		"expiry_date":   true,
		"batch_number":  true,
		"cost_per_unit": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY received_date DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches b
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get by item: %w", err)
	}
	defer rows.Close()

	var result []*models.Batch
	for rows.Next() {
		b, err := r.scanBatch(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

func (r *batchRepository) GetActiveBatchesByItem(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID) ([]*models.Batch, error) {
	filter := BatchFilter{
		CompanyID: companyID,
		ItemID:    &itemID,
		IsActive:  boolPtr(true),
	}
	return r.GetByItem(ctx, db, companyID, itemID, filter, Pagination{Limit: 1000}, Sort{Field: "received_date", Direction: "ASC"})
}

func (r *batchRepository) GetBatchByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchNumber string) (*models.Batch, error) {
	query := `
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches
		WHERE company_id = $1 AND item_id = $2 AND batch_number = $3
	`
	row := db.QueryRowContext(ctx, query, companyID, itemID, batchNumber)
	return r.scanBatch(row)
}

// ---------- NEW: ExistsByBatchNumber ----------
func (r *batchRepository) ExistsByBatchNumber(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, batchNumber string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM batches WHERE company_id = $1 AND item_id = $2 AND batch_number = $3)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, itemID, batchNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check batch existence: %w", err)
	}
	return exists, nil
}

// ---------- Critical allocation queries ----------

func (r *batchRepository) GetAvailableBatchesFIFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, requiredQty float64) ([]*BatchAllocationCandidate, error) {
	query := `
		SELECT b.batch_id, b.batch_number, b.expiry_date,
		       sb.available_qty, b.cost_per_unit
		FROM batches b
		JOIN stock_balances sb ON sb.batch_id = b.batch_id
		WHERE b.company_id = $1
		  AND b.item_id = $2
		  AND sb.warehouse_id = $3
		  AND sb.available_qty > 0
		  AND b.is_active = true
		ORDER BY b.received_date ASC, b.created_at ASC
		FOR UPDATE
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("fifo allocation query: %w", err)
	}
	defer rows.Close()

	var candidates []*BatchAllocationCandidate
	var remaining = requiredQty
	for rows.Next() && remaining > 0 {
		var c BatchAllocationCandidate
		err := rows.Scan(&c.BatchID, &c.BatchNumber, &c.ExpiryDate, &c.AvailableQty, &c.CostPerUnit)
		if err != nil {
			return nil, fmt.Errorf("scan fifo candidate: %w", err)
		}
		candidates = append(candidates, &c)
		remaining -= c.AvailableQty
	}
	return candidates, rows.Err()
}

func (r *batchRepository) GetAvailableBatchesFEFO(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID uuid.UUID, requiredQty float64) ([]*BatchAllocationCandidate, error) {
	query := `
		SELECT b.batch_id, b.batch_number, b.expiry_date,
		       sb.available_qty, b.cost_per_unit
		FROM batches b
		JOIN stock_balances sb ON sb.batch_id = b.batch_id
		WHERE b.company_id = $1
		  AND b.item_id = $2
		  AND sb.warehouse_id = $3
		  AND sb.available_qty > 0
		  AND b.is_active = true
		ORDER BY b.expiry_date ASC NULLS LAST, b.received_date ASC
		FOR UPDATE
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("fefo allocation query: %w", err)
	}
	defer rows.Close()

	var candidates []*BatchAllocationCandidate
	var remaining = requiredQty
	for rows.Next() && remaining > 0 {
		var c BatchAllocationCandidate
		err := rows.Scan(&c.BatchID, &c.BatchNumber, &c.ExpiryDate, &c.AvailableQty, &c.CostPerUnit)
		if err != nil {
			return nil, fmt.Errorf("scan fefo candidate: %w", err)
		}
		candidates = append(candidates, &c)
		remaining -= c.AvailableQty
	}
	return candidates, rows.Err()
}

func (r *batchRepository) GetBatchesWithStock(ctx context.Context, db DBTX, companyID uuid.UUID, itemID uuid.UUID, warehouseID *uuid.UUID) ([]*BatchWithStock, error) {
	query := `
		SELECT b.batch_id, b.batch_number, b.expiry_date, b.manufactured_date,
		       sb.available_qty, sb.reserved_qty, b.cost_per_unit
		FROM batches b
		JOIN stock_balances sb ON sb.batch_id = b.batch_id
		WHERE b.company_id = $1
		  AND b.item_id = $2
		  AND b.is_active = true
		  AND ($3::uuid IS NULL OR sb.warehouse_id = $3)
		ORDER BY b.received_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get batches with stock: %w", err)
	}
	defer rows.Close()

	var result []*BatchWithStock
	for rows.Next() {
		var bs BatchWithStock
		err := rows.Scan(&bs.BatchID, &bs.BatchNumber, &bs.ExpiryDate, &bs.ManufacturedAt,
			&bs.AvailableQty, &bs.ReservedQty, &bs.CostPerUnit)
		if err != nil {
			return nil, fmt.Errorf("scan batch stock: %w", err)
		}
		result = append(result, &bs)
	}
	return result, rows.Err()
}

// ---------- Expiry management ----------

func (r *batchRepository) GetExpiringBatches(ctx context.Context, db DBTX, companyID uuid.UUID, days int) ([]*models.Batch, error) {
	query := `
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches
		WHERE company_id = $1
		  AND is_active = true
		  AND expiry_date IS NOT NULL
		  AND expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE + $2 * INTERVAL '1 day'
		ORDER BY expiry_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, days)
	if err != nil {
		return nil, fmt.Errorf("get expiring batches: %w", err)
	}
	defer rows.Close()

	var batches []*models.Batch
	for rows.Next() {
		b, err := r.scanBatch(rows)
		if err != nil {
			return nil, err
		}
		batches = append(batches, b)
	}
	return batches, rows.Err()
}

func (r *batchRepository) GetExpiredBatches(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Batch, error) {
	query := `
		SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		       manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		       cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches
		WHERE company_id = $1
		  AND is_active = true
		  AND expiry_date IS NOT NULL
		  AND expiry_date < CURRENT_DATE
		ORDER BY expiry_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get expired batches: %w", err)
	}
	defer rows.Close()

	var batches []*models.Batch
	for rows.Next() {
		b, err := r.scanBatch(rows)
		if err != nil {
			return nil, err
		}
		batches = append(batches, b)
	}
	return batches, rows.Err()
}

// ---------- Stock operations (with RETURNING) ----------

func (r *batchRepository) UpdateRemainingQuantity(ctx context.Context, db DBTX, batchID uuid.UUID, newQty float64) error {
	query := `
		UPDATE batches SET remaining_qty = $2, updated_at = NOW()
		WHERE batch_id = $1
		RETURNING updated_at
	`
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, query, batchID, newQty).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: batch %s", inventory_errors.ErrNotFound, batchID)
		}
		return fmt.Errorf("update remaining qty: %w", err)
	}
	return nil
}

func (r *batchRepository) AdjustBatchQuantity(ctx context.Context, db DBTX, batchID uuid.UUID, delta float64) error {
	query := `
		UPDATE batches
		SET remaining_qty = remaining_qty + $2, updated_at = NOW()
		WHERE batch_id = $1 AND remaining_qty + $2 >= 0
		RETURNING updated_at
	`
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, query, batchID, delta).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: batch %s or insufficient remaining_qty", inventory_errors.ErrNotFound, batchID)
		}
		return fmt.Errorf("adjust batch qty: %w", err)
	}
	return nil
}

// ---------- scanner helper (fixed to return ErrNotFound) ----------
func (r *batchRepository) scanBatch(s scanner) (*models.Batch, error) {
	var b models.Batch
	var supplierBatch sql.NullString
	var manufacturedDate, expiryDate, receivedDate sql.NullTime
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&b.BatchID, &b.CompanyID, &b.ItemID, &b.BatchNumber, &supplierBatch,
		&manufacturedDate, &expiryDate, &receivedDate,
		&b.Quantity, &b.RemainingQty, &b.CostPerUnit, &b.IsActive,
		&b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan batch: %w", err)
	}

	if supplierBatch.Valid {
		b.SupplierBatch = &supplierBatch.String
	}
	if manufacturedDate.Valid {
		b.ManufacturedDate = &manufacturedDate.Time
	}
	if expiryDate.Valid {
		b.ExpiryDate = &expiryDate.Time
	}
	if receivedDate.Valid {
		b.ReceivedDate = &receivedDate.Time
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		b.UpdatedBy = &updatedBy.UUID
	}
	return &b, nil
}

// helper
func boolPtr(b bool) *bool {
	return &b
}
