// repository/analysis_repo.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// DBTX is the common database interface (shared across all repositories)
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Pagination limits and offset
type Pagination struct {
	Limit  int
	Offset int
}

// Sort field and direction
type Sort struct {
	Field     string
	Direction string // ASC, DESC
}

// ========== Filters ==========

type SnapshotFilter struct {
	CompanyID   uuid.UUID
	DateFrom    *time.Time
	DateTo      *time.Time
	WarehouseID *uuid.UUID
	ItemID      *uuid.UUID
}

type AgingFilter struct {
	CompanyID    uuid.UUID
	SnapshotDate *time.Time
	WarehouseID  *uuid.UUID
	ItemID       *uuid.UUID
	AgingBucket  string // e.g. "0-30", "31-60", "61-90", "90+"
}

type TurnoverFilter struct {
	CompanyID     uuid.UUID
	YearMonthFrom *time.Time
	YearMonthTo   *time.Time
	WarehouseID   *uuid.UUID
	ItemID        *uuid.UUID
}

type ABCFilter struct {
	CompanyID uuid.UUID
	Date      *time.Time
	Class     string // "A", "B", "C"
	ItemID    *uuid.UUID
}

type DemandFilter struct {
	CompanyID   uuid.UUID
	DateFrom    *time.Time
	DateTo      *time.Time
	WarehouseID *uuid.UUID
	ItemID      *uuid.UUID
}

// ========== Advanced DTOs ==========

type ValuationSummary struct {
	TotalQuantity float64
	TotalValue    float64
	AvgCost       float64
}

type SlowMovingItem struct {
	ItemID      string
	ItemName    string
	DaysInStock int
	Quantity    float64
	TotalValue  float64
}

type FastMovingItem struct {
	ItemID        string
	ItemName      string
	ConsumedQty   float64
	TurnoverRatio float64
}

type StockRiskItem struct {
	ItemID        string
	ItemName      string
	AvailableQty  float64
	AvgDailyUsage float64
	DaysLeft      float64
}

// ========== Repository Interface ==========

type InventoryAnalysisRepository interface {
	// Snapshots
	BulkInsertSnapshots(ctx context.Context, db DBTX, snapshots []*models.DailyInventorySnapshot) error
	GetSnapshotByDate(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, warehouseID *uuid.UUID) ([]*models.DailyInventorySnapshot, error)
	GetSnapshotRange(ctx context.Context, db DBTX, filter SnapshotFilter, p Pagination, s Sort) ([]*models.DailyInventorySnapshot, error)
	UpsertProductionMetric(ctx context.Context, db DBTX, metric *models.ProductionMetric) error
	// Aging
	BulkInsertAging(ctx context.Context, db DBTX, aging []*models.InventoryAging) error
	GetInventoryAging(ctx context.Context, db DBTX, filter AgingFilter, p Pagination, s Sort) ([]*models.InventoryAging, error)

	// Turnover
	UpsertTurnoverMetrics(ctx context.Context, db DBTX, metrics *models.InventoryTurnoverMetrics) error
	GetTurnoverMetrics(ctx context.Context, db DBTX, filter TurnoverFilter, p Pagination, s Sort) ([]*models.InventoryTurnoverMetrics, error)
	UpsertMovementSummary(ctx context.Context, db DBTX, summary *models.MovementDailySummary) error

	// GetMovementSummary retrieves movement summaries within a date range, optionally filtered by warehouse and item.
	GetMovementSummary(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time, warehouseID, itemID *uuid.UUID) ([]*models.MovementDailySummary, error)

	// ABC Classification
	BulkInsertABC(ctx context.Context, db DBTX, records []*models.ABCClassification) error
	GetABCClassification(ctx context.Context, db DBTX, filter ABCFilter, p Pagination, s Sort) ([]*models.ABCClassification, error)

	// Demand History
	BulkInsertDemand(ctx context.Context, db DBTX, demand []*models.DemandHistory) error
	GetDemandHistory(ctx context.Context, db DBTX, filter DemandFilter, p Pagination, s Sort) ([]*models.DemandHistory, error)

	// Advanced Analytics
	GetInventoryValuationSummary(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (*ValuationSummary, error)
	GetSlowMovingItems(ctx context.Context, db DBTX, companyID uuid.UUID, days int) ([]*SlowMovingItem, error)
	GetFastMovingItems(ctx context.Context, db DBTX, companyID uuid.UUID, limit int) ([]*FastMovingItem, error)
	GetStockOutRiskItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*StockRiskItem, error)
}

// ========== Implementation ==========

type inventoryAnalysisRepository struct {
	logger *zap.Logger
}

func NewInventoryAnalysisRepository(logger *zap.Logger) InventoryAnalysisRepository {
	return &inventoryAnalysisRepository{
		logger: logger.Named("inventory_analysis_repo"),
	}
}

// ---------- Helpers ----------

func (r *inventoryAnalysisRepository) validateSort(s Sort, allowedFields map[string]bool) (string, error) {
	field := s.Field
	if field == "" {
		// default field depends on context; caller should provide fallback
		return "", fmt.Errorf("sort field is required")
	}
	if !allowedFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *inventoryAnalysisRepository) validatePagination(p Pagination) (int, int) {
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

// ---------- Snapshots ----------

func (r *inventoryAnalysisRepository) BulkInsertSnapshots(ctx context.Context, db DBTX, snapshots []*models.DailyInventorySnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	// Using batched INSERT for simplicity; for >1000 rows consider COPY
	query := `INSERT INTO daily_inventory_snapshot 
		(snapshot_id, company_id, snapshot_date, warehouse_id, item_id, batch_id,
		 quantity_on_hand, reserved_qty, available_qty, unit_cost, days_of_stock, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (snapshot_id) DO NOTHING`

	for _, s := range snapshots {
		_, err := db.ExecContext(ctx, query,
			s.SnapshotID, s.CompanyID, s.SnapshotDate, s.WarehouseID, s.ItemID, s.BatchID,
			s.QuantityOnHand, s.ReservedQty, s.AvailableQty, s.UnitCost, s.DaysOfStock, s.CreatedAt,
		)
		if err != nil {
			r.logger.Error("failed to insert snapshot", util.ErrorField(err))
			return fmt.Errorf("bulk insert snapshots: %w", err)
		}
	}
	return nil
}

func (r *inventoryAnalysisRepository) GetSnapshotByDate(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, warehouseID *uuid.UUID) ([]*models.DailyInventorySnapshot, error) {
	filter := SnapshotFilter{
		CompanyID:   companyID,
		DateFrom:    &date,
		DateTo:      &date,
		WarehouseID: warehouseID,
	}
	return r.GetSnapshotRange(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "snapshot_date", Direction: "DESC"})
}

func (r *inventoryAnalysisRepository) GetSnapshotRange(ctx context.Context, db DBTX, filter SnapshotFilter, p Pagination, s Sort) ([]*models.DailyInventorySnapshot, error) {
	where, args := r.buildSnapshotFilter(filter)
	allowedSort := map[string]bool{
		"snapshot_date":    true,
		"quantity_on_hand": true,
		"unit_cost":        true,
		"total_value":      true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY snapshot_date DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT snapshot_id, company_id, snapshot_date, warehouse_id, item_id, batch_id,
		       quantity_on_hand, reserved_qty, available_qty, unit_cost, total_value, days_of_stock, created_at
		FROM daily_inventory_snapshot
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get snapshot range: %w", err)
	}
	defer rows.Close()

	var result []*models.DailyInventorySnapshot
	for rows.Next() {
		s := &models.DailyInventorySnapshot{}
		err := rows.Scan(
			&s.SnapshotID, &s.CompanyID, &s.SnapshotDate, &s.WarehouseID, &s.ItemID, &s.BatchID,
			&s.QuantityOnHand, &s.ReservedQty, &s.AvailableQty, &s.UnitCost, &s.TotalValue, &s.DaysOfStock, &s.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *inventoryAnalysisRepository) buildSnapshotFilter(f SnapshotFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1
	if f.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, f.CompanyID.String())
		idx++
	}
	if f.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("snapshot_date >= $%d", idx))
		args = append(args, *f.DateFrom)
		idx++
	}
	if f.DateTo != nil {
		conds = append(conds, fmt.Sprintf("snapshot_date <= $%d", idx))
		args = append(args, *f.DateTo)
		idx++
	}
	if f.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, f.WarehouseID.String())
		idx++
	}
	if f.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, f.ItemID.String())
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Aging ----------

func (r *inventoryAnalysisRepository) BulkInsertAging(ctx context.Context, db DBTX, aging []*models.InventoryAging) error {
	if len(aging) == 0 {
		return nil
	}
	query := `INSERT INTO inventory_aging 
		(aging_id, company_id, snapshot_date, warehouse_id, item_id, batch_id,
		 days_in_stock, aging_bucket, quantity, unit_cost, total_value, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	for _, a := range aging {
		_, err := db.ExecContext(ctx, query,
			a.AgingID, a.CompanyID, a.SnapshotDate, a.WarehouseID, a.ItemID, a.BatchID,
			a.DaysInStock, a.AgingBucket, a.Quantity, a.UnitCost, a.TotalValue, a.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("bulk insert aging: %w", err)
		}
	}
	return nil
}

func (r *inventoryAnalysisRepository) GetInventoryAging(ctx context.Context, db DBTX, filter AgingFilter, p Pagination, s Sort) ([]*models.InventoryAging, error) {
	where, args := r.buildAgingFilter(filter)
	allowedSort := map[string]bool{"snapshot_date": true, "days_in_stock": true, "aging_bucket": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY days_in_stock DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT aging_id, company_id, snapshot_date, warehouse_id, item_id, batch_id,
		       days_in_stock, aging_bucket, quantity, unit_cost, total_value, created_at
		FROM inventory_aging
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get inventory aging: %w", err)
	}
	defer rows.Close()

	var res []*models.InventoryAging
	for rows.Next() {
		a := &models.InventoryAging{}
		err := rows.Scan(
			&a.AgingID, &a.CompanyID, &a.SnapshotDate, &a.WarehouseID, &a.ItemID, &a.BatchID,
			&a.DaysInStock, &a.AgingBucket, &a.Quantity, &a.UnitCost, &a.TotalValue, &a.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan aging: %w", err)
		}
		res = append(res, a)
	}
	return res, rows.Err()
}

func (r *inventoryAnalysisRepository) buildAgingFilter(f AgingFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1
	if f.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, f.CompanyID.String())
		idx++
	}
	if f.SnapshotDate != nil {
		conds = append(conds, fmt.Sprintf("snapshot_date = $%d", idx))
		args = append(args, *f.SnapshotDate)
		idx++
	}
	if f.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, f.WarehouseID.String())
		idx++
	}
	if f.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, f.ItemID.String())
		idx++
	}
	if f.AgingBucket != "" {
		conds = append(conds, fmt.Sprintf("aging_bucket = $%d", idx))
		args = append(args, f.AgingBucket)
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Turnover ----------

func (r *inventoryAnalysisRepository) UpsertTurnoverMetrics(ctx context.Context, db DBTX, metrics *models.InventoryTurnoverMetrics) error {
	query := `
		INSERT INTO inventory_turnover_metrics 
		(turnover_id, company_id, year_month, warehouse_id, item_id, total_consumed_qty,
		 total_consumed_value, avg_inventory_qty, days_inventory, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (company_id, year_month, warehouse_id, item_id) 
		DO UPDATE SET
			total_consumed_qty = EXCLUDED.total_consumed_qty,
			total_consumed_value = EXCLUDED.total_consumed_value,
			avg_inventory_qty = EXCLUDED.avg_inventory_qty,
			days_inventory = EXCLUDED.days_inventory,
			created_at = EXCLUDED.created_at
	`
	_, err := db.ExecContext(ctx, query,
		metrics.TurnoverID, metrics.CompanyID, metrics.YearMonth, metrics.WarehouseID, metrics.ItemID,
		metrics.TotalConsumedQty, metrics.TotalConsumedValue, metrics.AvgInventoryQty,
		metrics.DaysInventory, metrics.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert turnover metrics: %w", err)
	}
	return nil
}

func (r *inventoryAnalysisRepository) GetTurnoverMetrics(ctx context.Context, db DBTX, filter TurnoverFilter, p Pagination, s Sort) ([]*models.InventoryTurnoverMetrics, error) {
	where, args := r.buildTurnoverFilter(filter)
	allowedSort := map[string]bool{"year_month": true, "turnover_ratio": true, "avg_inventory_qty": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY year_month DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT turnover_id, company_id, year_month, warehouse_id, item_id, total_consumed_qty,
		       total_consumed_value, avg_inventory_qty, turnover_ratio, days_inventory, created_at
		FROM inventory_turnover_metrics
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get turnover metrics: %w", err)
	}
	defer rows.Close()

	var res []*models.InventoryTurnoverMetrics
	for rows.Next() {
		t := &models.InventoryTurnoverMetrics{}
		err := rows.Scan(
			&t.TurnoverID, &t.CompanyID, &t.YearMonth, &t.WarehouseID, &t.ItemID,
			&t.TotalConsumedQty, &t.TotalConsumedValue, &t.AvgInventoryQty,
			&t.TurnoverRatio, &t.DaysInventory, &t.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan turnover: %w", err)
		}
		res = append(res, t)
	}
	return res, rows.Err()
}

func (r *inventoryAnalysisRepository) buildTurnoverFilter(f TurnoverFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1
	if f.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, f.CompanyID.String())
		idx++
	}
	if f.YearMonthFrom != nil {
		conds = append(conds, fmt.Sprintf("year_month >= $%d", idx))
		args = append(args, *f.YearMonthFrom)
		idx++
	}
	if f.YearMonthTo != nil {
		conds = append(conds, fmt.Sprintf("year_month <= $%d", idx))
		args = append(args, *f.YearMonthTo)
		idx++
	}
	if f.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, f.WarehouseID.String())
		idx++
	}
	if f.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, f.ItemID.String())
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- ABC ----------

func (r *inventoryAnalysisRepository) BulkInsertABC(ctx context.Context, db DBTX, records []*models.ABCClassification) error {
	if len(records) == 0 {
		return nil
	}
	query := `INSERT INTO abc_classification 
		(classification_id, company_id, classification_date, item_id, warehouse_id,
		 annual_consumption_value, cumulative_percent, abc_class, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	for _, abc := range records {
		_, err := db.ExecContext(ctx, query,
			abc.ClassificationID, abc.CompanyID, abc.ClassificationDate, abc.ItemID, abc.WarehouseID,
			abc.AnnualConsumptionValue, abc.CumulativePercent, abc.ABCClass, abc.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("bulk insert abc: %w", err)
		}
	}
	return nil
}

func (r *inventoryAnalysisRepository) GetABCClassification(ctx context.Context, db DBTX, filter ABCFilter, p Pagination, s Sort) ([]*models.ABCClassification, error) {
	where, args := r.buildABCFilter(filter)
	allowedSort := map[string]bool{"classification_date": true, "abc_class": true, "annual_consumption_value": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY classification_date DESC, annual_consumption_value DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT classification_id, company_id, classification_date, item_id, warehouse_id,
		       annual_consumption_value, cumulative_percent, abc_class, created_at
		FROM abc_classification
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get abc classification: %w", err)
	}
	defer rows.Close()

	var res []*models.ABCClassification
	for rows.Next() {
		abc := &models.ABCClassification{}
		err := rows.Scan(
			&abc.ClassificationID, &abc.CompanyID, &abc.ClassificationDate, &abc.ItemID, &abc.WarehouseID,
			&abc.AnnualConsumptionValue, &abc.CumulativePercent, &abc.ABCClass, &abc.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan abc: %w", err)
		}
		res = append(res, abc)
	}
	return res, rows.Err()
}

func (r *inventoryAnalysisRepository) buildABCFilter(f ABCFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1
	if f.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, f.CompanyID.String())
		idx++
	}
	if f.Date != nil {
		conds = append(conds, fmt.Sprintf("classification_date = $%d", idx))
		args = append(args, *f.Date)
		idx++
	}
	if f.Class != "" {
		conds = append(conds, fmt.Sprintf("abc_class = $%d", idx))
		args = append(args, f.Class)
		idx++
	}
	if f.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, f.ItemID.String())
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Demand ----------

func (r *inventoryAnalysisRepository) BulkInsertDemand(ctx context.Context, db DBTX, demand []*models.DemandHistory) error {
	if len(demand) == 0 {
		return nil
	}
	query := `INSERT INTO demand_history 
		(demand_id, company_id, demand_date, item_id, warehouse_id,
		 quantity_demanded, quantity_shipped, backorder_qty, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	for _, d := range demand {
		_, err := db.ExecContext(ctx, query,
			d.DemandID, d.CompanyID, d.DemandDate, d.ItemID, d.WarehouseID,
			d.QuantityDemanded, d.QuantityShipped, d.BackorderQty, d.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("bulk insert demand: %w", err)
		}
	}
	return nil
}

func (r *inventoryAnalysisRepository) GetDemandHistory(ctx context.Context, db DBTX, filter DemandFilter, p Pagination, s Sort) ([]*models.DemandHistory, error) {
	where, args := r.buildDemandFilter(filter)
	allowedSort := map[string]bool{"demand_date": true, "quantity_demanded": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY demand_date DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT demand_id, company_id, demand_date, item_id, warehouse_id,
		       quantity_demanded, quantity_shipped, backorder_qty, created_at
		FROM demand_history
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get demand history: %w", err)
	}
	defer rows.Close()

	var res []*models.DemandHistory
	for rows.Next() {
		d := &models.DemandHistory{}
		err := rows.Scan(
			&d.DemandID, &d.CompanyID, &d.DemandDate, &d.ItemID, &d.WarehouseID,
			&d.QuantityDemanded, &d.QuantityShipped, &d.BackorderQty, &d.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan demand: %w", err)
		}
		res = append(res, d)
	}
	return res, rows.Err()
}

func (r *inventoryAnalysisRepository) buildDemandFilter(f DemandFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1
	if f.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, f.CompanyID.String())
		idx++
	}
	if f.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("demand_date >= $%d", idx))
		args = append(args, *f.DateFrom)
		idx++
	}
	if f.DateTo != nil {
		conds = append(conds, fmt.Sprintf("demand_date <= $%d", idx))
		args = append(args, *f.DateTo)
		idx++
	}
	if f.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, f.WarehouseID.String())
		idx++
	}
	if f.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, f.ItemID.String())
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- Advanced Analytics ----------

func (r *inventoryAnalysisRepository) GetInventoryValuationSummary(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (*ValuationSummary, error) {
	query := `
		SELECT COALESCE(SUM(quantity_on_hand), 0),
		       COALESCE(SUM(total_value), 0),
		       CASE WHEN SUM(quantity_on_hand) > 0 THEN SUM(total_value)/SUM(quantity_on_hand) ELSE 0 END
		FROM daily_inventory_snapshot
		WHERE company_id = $1 AND snapshot_date = $2
	`
	var summary ValuationSummary
	err := db.QueryRowContext(ctx, query, companyID.String(), date).Scan(
		&summary.TotalQuantity, &summary.TotalValue, &summary.AvgCost,
	)
	if err != nil {
		return nil, fmt.Errorf("get inventory valuation summary: %w", err)
	}
	return &summary, nil
}

func (r *inventoryAnalysisRepository) GetSlowMovingItems(ctx context.Context, db DBTX, companyID uuid.UUID, days int) ([]*SlowMovingItem, error) {
	query := `
		SELECT i.item_id, i.name, a.days_in_stock, a.quantity, a.total_value
		FROM inventory_aging a
		JOIN items i ON i.item_id = a.item_id
		WHERE a.company_id = $1
		  AND a.days_in_stock >= $2
		  AND a.snapshot_date = (
		      SELECT MAX(snapshot_date) FROM inventory_aging WHERE company_id = $1
		  )
		ORDER BY a.days_in_stock DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID.String(), days)
	if err != nil {
		return nil, fmt.Errorf("get slow moving items: %w", err)
	}
	defer rows.Close()

	var items []*SlowMovingItem
	for rows.Next() {
		it := &SlowMovingItem{}
		err := rows.Scan(&it.ItemID, &it.ItemName, &it.DaysInStock, &it.Quantity, &it.TotalValue)
		if err != nil {
			return nil, fmt.Errorf("scan slow moving item: %w", err)
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

func (r *inventoryAnalysisRepository) GetFastMovingItems(ctx context.Context, db DBTX, companyID uuid.UUID, limit int) ([]*FastMovingItem, error) {
	query := `
		SELECT i.item_id, i.name, t.total_consumed_qty, t.turnover_ratio
		FROM inventory_turnover_metrics t
		JOIN items i ON i.item_id = t.item_id
		WHERE t.company_id = $1
		  AND t.year_month >= date_trunc('month', now() - interval '3 months')
		ORDER BY t.turnover_ratio DESC
		LIMIT $2
	`
	rows, err := db.QueryContext(ctx, query, companyID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("get fast moving items: %w", err)
	}
	defer rows.Close()

	var items []*FastMovingItem
	for rows.Next() {
		it := &FastMovingItem{}
		err := rows.Scan(&it.ItemID, &it.ItemName, &it.ConsumedQty, &it.TurnoverRatio)
		if err != nil {
			return nil, fmt.Errorf("scan fast moving item: %w", err)
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

func (r *inventoryAnalysisRepository) GetStockOutRiskItems(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*StockRiskItem, error) {
	// avg daily usage from last 30 days of demand_history
	query := `
		WITH daily_usage AS (
			SELECT item_id, 
			       COALESCE(SUM(quantity_shipped), 0) / 30.0 AS avg_daily
			FROM demand_history
			WHERE company_id = $1
			  AND demand_date >= now() - interval '30 days'
			GROUP BY item_id
		),
		current_stock AS (
			SELECT sb.item_id, SUM(sb.available_qty) AS available
			FROM stock_balances sb
			WHERE sb.company_id = $1
			GROUP BY sb.item_id
		)
		SELECT i.item_id, i.name,
		       COALESCE(cs.available, 0) AS available_qty,
		       COALESCE(du.avg_daily, 0) AS avg_daily_usage,
		       CASE WHEN COALESCE(du.avg_daily, 0) > 0 
		            THEN COALESCE(cs.available, 0) / du.avg_daily 
		            ELSE 999999 END AS days_left
		FROM items i
		LEFT JOIN current_stock cs ON i.item_id = cs.item_id
		LEFT JOIN daily_usage du ON i.item_id = du.item_id
		WHERE i.company_id = $1
		  AND i.is_active = true
		  AND COALESCE(cs.available, 0) < 100   -- threshold configurable
		ORDER BY days_left ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID.String())
	if err != nil {
		return nil, fmt.Errorf("get stock out risk items: %w", err)
	}
	defer rows.Close()

	var items []*StockRiskItem
	for rows.Next() {
		it := &StockRiskItem{}
		err := rows.Scan(&it.ItemID, &it.ItemName, &it.AvailableQty, &it.AvgDailyUsage, &it.DaysLeft)
		if err != nil {
			return nil, fmt.Errorf("scan stock risk item: %w", err)
		}
		items = append(items, it)
	}
	return items, rows.Err()
}
func (r *inventoryAnalysisRepository) UpsertMovementSummary(ctx context.Context, db DBTX, summary *models.MovementDailySummary) error {
	query := `
        INSERT INTO movement_daily_summary (
            summary_id, company_id, date, warehouse_id, item_id, movement_type,
            total_quantity_in, total_quantity_out, transaction_count, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (company_id, date, warehouse_id, item_id, movement_type)
        DO UPDATE SET
            total_quantity_in = movement_daily_summary.total_quantity_in + EXCLUDED.total_quantity_in,
            total_quantity_out = movement_daily_summary.total_quantity_out + EXCLUDED.total_quantity_out,
            transaction_count = movement_daily_summary.transaction_count + EXCLUDED.transaction_count,
            updated_at = NOW()
    `
	var warehouseID interface{}
	if summary.WarehouseID != nil {
		warehouseID = *summary.WarehouseID
	} else {
		warehouseID = nil
	}

	_, err := db.ExecContext(ctx, query,
		summary.SummaryID, summary.CompanyID, summary.Date,
		warehouseID, // now *uuid.UUID or nil
		summary.ItemID, summary.MovementType,
		summary.TotalQuantityIn, summary.TotalQuantityOut, summary.TransactionCount,
		summary.CreatedAt, summary.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to upsert movement summary", util.ErrorField(err))
		return fmt.Errorf("upsert movement summary: %w", err)
	}
	return nil
}
func (r *inventoryAnalysisRepository) GetMovementSummary(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time, warehouseID, itemID *uuid.UUID) ([]*models.MovementDailySummary, error) {
	where := "company_id = $1 AND date BETWEEN $2 AND $3"
	args := []interface{}{companyID, from, to}
	idx := 4

	if warehouseID != nil {
		where += fmt.Sprintf(" AND warehouse_id = $%d", idx)
		args = append(args, *warehouseID)
		idx++
	}
	if itemID != nil {
		where += fmt.Sprintf(" AND item_id = $%d", idx)
		args = append(args, *itemID)
		idx++
	}

	query := fmt.Sprintf(`
        SELECT summary_id, company_id, date, warehouse_id, item_id, movement_type,
               total_quantity_in, total_quantity_out, transaction_count, created_at, updated_at
        FROM movement_daily_summary
        WHERE %s
        ORDER BY date DESC, movement_type
    `, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get movement summary: %w", err)
	}
	defer rows.Close()

	var results []*models.MovementDailySummary
	for rows.Next() {
		var m models.MovementDailySummary
		var warehouseUUID uuid.NullUUID // ✅ fixed: use uuid.NullUUID, not sql.NullUUID

		err := rows.Scan(
			&m.SummaryID, &m.CompanyID, &m.Date, &warehouseUUID, &m.ItemID, &m.MovementType,
			&m.TotalQuantityIn, &m.TotalQuantityOut, &m.TransactionCount,
			&m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan movement summary: %w", err)
		}
		if warehouseUUID.Valid {
			m.WarehouseID = &warehouseUUID.UUID
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// Helper function (add to the same file)
func nullStringPtr(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}
func (r *inventoryAnalysisRepository) UpsertProductionMetric(ctx context.Context, db DBTX, metric *models.ProductionMetric) error {
	query := `
		INSERT INTO production_metrics (
			metric_id, company_id, date, product_item_id,
			total_produced_qty, total_consumed_raw_qty, efficiency,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		ON CONFLICT (company_id, date, product_item_id)
		DO UPDATE SET
			total_produced_qty = production_metrics.total_produced_qty + EXCLUDED.total_produced_qty,
			total_consumed_raw_qty = production_metrics.total_consumed_raw_qty + EXCLUDED.total_consumed_raw_qty,
			-- Efficiency is recomputed as weighted average? For simplicity, take the latest non‑NULL.
			efficiency = COALESCE(EXCLUDED.efficiency, production_metrics.efficiency),
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		metric.MetricID,
		metric.CompanyID,
		metric.Date,
		metric.ProductItemID,
		metric.TotalProducedQty,
		metric.TotalConsumedRawQty,
		metric.Efficiency,
	)
	if err != nil {
		r.logger.Error("failed to upsert production metric",
			zap.String("company_id", metric.CompanyID.String()),     // add .String()
			zap.String("product_id", metric.ProductItemID.String()), // add .String()
			zap.Error(err))
		return fmt.Errorf("upsert production metric: %w", err)
	}
	return nil
}
