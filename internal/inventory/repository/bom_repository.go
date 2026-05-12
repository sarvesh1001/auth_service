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

// BOMExplosionResult represents a single level of exploded BOM component
type BOMExplosionResult struct {
	ItemID      uuid.UUID  `json:"itemId"`
	RequiredQty float64    `json:"requiredQty"`
	Level       int        `json:"level"`
	ParentItem  *uuid.UUID `json:"parentItem,omitempty"`
}

// ComponentCost holds cost details for a single component
type ComponentCost struct {
	ItemID   uuid.UUID       `json:"itemId"`
	Quantity decimal.Decimal `json:"quantity"`
	UnitCost decimal.Decimal `json:"unitCost"`
	Total    decimal.Decimal `json:"total"`
}

// BOMCostResult is the result of BOM cost roll‑up
type BOMCostResult struct {
	BOMID      uuid.UUID       `json:"bomId"`
	TotalCost  decimal.Decimal `json:"totalCost"`
	Components []ComponentCost `json:"components"`
}

// BOMFilter defines filters for listing BOMs
type BOMFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
}

// BOMRepository defines all operations for Bill of Materials
type BOMRepository interface {
	// BOM header
	CreateBOM(ctx context.Context, db DBTX, bom *models.BOM) error
	GetBOMByID(ctx context.Context, db DBTX, bomID uuid.UUID) (*models.BOM, error)
	GetActiveBOMByProduct(ctx context.Context, db DBTX, companyID uuid.UUID, productItemID uuid.UUID) (*models.BOM, error)
	GetBOMVersions(ctx context.Context, db DBTX, companyID uuid.UUID, productItemID uuid.UUID) ([]*models.BOM, error)
	UpdateBOM(ctx context.Context, db DBTX, bom *models.BOM) error
	DeactivateBOM(ctx context.Context, db DBTX, bomID uuid.UUID) error
	DeleteBOM(ctx context.Context, db DBTX, bomID uuid.UUID) error

	// BOM items
	AddBOMItems(ctx context.Context, db DBTX, items []*models.BOMItem) error
	ReplaceBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID, items []*models.BOMItem) error
	GetBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID) ([]*models.BOMItem, error)
	DeleteBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID) error

	// Single item operations
	GetBOMItemByID(ctx context.Context, db DBTX, bomItemID uuid.UUID) (*models.BOMItem, error)
	UpdateBOMItem(ctx context.Context, db DBTX, bomItem *models.BOMItem) error
	DeleteBOMItem(ctx context.Context, db DBTX, bomItemID uuid.UUID, companyID uuid.UUID) error
	ExistsBOMByProductAndVersion(ctx context.Context, db DBTX, companyID, productItemID uuid.UUID, version int) (bool, error)
	ExistsBOMItemByComponent(ctx context.Context, db DBTX, bomID, componentItemID uuid.UUID) (bool, error)

	// BOM explosion
	ExplodeBOM(ctx context.Context, db DBTX, bomID uuid.UUID, requiredQty decimal.Decimal) ([]*BOMExplosionResult, error)
	GetDirectComponents(ctx context.Context, db DBTX, bomID uuid.UUID) ([]*models.BOMItem, error)
	GetBOMByIDAndCompany(ctx context.Context, db DBTX, bomID, companyID uuid.UUID) (*models.BOM, error)

	// Costing
	CalculateBOMCost(ctx context.Context, db DBTX, bomID uuid.UUID) (*BOMCostResult, error)

	// Paginated list
	ListBOMs(ctx context.Context, db DBTX, filter BOMFilter, p Pagination, s Sort) ([]*models.BOM, int64, error)
}

type bomRepository struct {
	logger *zap.Logger
}

func NewBOMRepository(logger *zap.Logger) BOMRepository {
	return &bomRepository{
		logger: logger.Named("bom_repo"),
	}
}

// ---------- helpers ----------

func (r *bomRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *bomRepository) validatePagination(p Pagination) (int, int) {
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

func (r *bomRepository) scanBOM(s scanner) (*models.BOM, error) {
	var b models.BOM
	var createdBy, updatedBy uuid.NullUUID
	err := s.Scan(
		&b.BOMID, &b.CompanyID, &b.ProductItemID, &b.BOMCode, &b.Name,
		&b.Version, &b.Quantity, &b.IsActive,
		&b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan BOM: %w", err)
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		b.UpdatedBy = &updatedBy.UUID
	}
	return &b, nil
}

func (r *bomRepository) scanBOMItem(s scanner) (*models.BOMItem, error) {
	var bi models.BOMItem
	var scrap sql.NullFloat64
	err := s.Scan(
		&bi.BOMItemID, &bi.BOMID, &bi.ComponentItemID, &bi.Quantity,
		&scrap, &bi.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan BOM item: %w", err)
	}
	if scrap.Valid {
		scrapDec := decimal.NewFromFloat(scrap.Float64)
		bi.ScrapPercentage = &scrapDec
	}
	return &bi, nil
}

func (r *bomRepository) getItemCost(ctx context.Context, db DBTX, itemID uuid.UUID) (decimal.Decimal, error) {
	query := `SELECT COALESCE(standard_cost, 0) FROM items WHERE item_id = $1`
	var cost float64
	err := db.QueryRowContext(ctx, query, itemID).Scan(&cost)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get item cost: %w", err)
	}
	return decimal.NewFromFloat(cost), nil
}

// ---------- BOM header ----------

func (r *bomRepository) CreateBOM(ctx context.Context, db DBTX, bom *models.BOM) error {
	query := `
		INSERT INTO boms (
			bom_id, company_id, product_item_id, bom_code, name,
			version, quantity, is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		bom.BOMID, bom.CompanyID, bom.ProductItemID, bom.BOMCode, bom.Name,
		bom.Version, bom.Quantity, bom.IsActive, bom.CreatedBy, bom.UpdatedBy,
	).Scan(&bom.CreatedAt, &bom.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create BOM", util.ErrorField(err))
		return fmt.Errorf("create BOM: %w", err)
	}
	return nil
}

func (r *bomRepository) GetBOMByID(ctx context.Context, db DBTX, bomID uuid.UUID) (*models.BOM, error) {
	query := `
		SELECT bom_id, company_id, product_item_id, bom_code, name,
		       version, quantity, is_active, created_at, updated_at, created_by, updated_by
		FROM boms WHERE bom_id = $1
	`
	row := db.QueryRowContext(ctx, query, bomID)
	return r.scanBOM(row)
}

func (r *bomRepository) GetActiveBOMByProduct(ctx context.Context, db DBTX, companyID uuid.UUID, productItemID uuid.UUID) (*models.BOM, error) {
	query := `
		SELECT bom_id, company_id, product_item_id, bom_code, name,
		       version, quantity, is_active, created_at, updated_at, created_by, updated_by
		FROM boms
		WHERE company_id = $1 AND product_item_id = $2 AND is_active = true
		ORDER BY version DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, productItemID)
	return r.scanBOM(row)
}

func (r *bomRepository) GetBOMVersions(ctx context.Context, db DBTX, companyID uuid.UUID, productItemID uuid.UUID) ([]*models.BOM, error) {
	query := `
		SELECT bom_id, company_id, product_item_id, bom_code, name,
		       version, quantity, is_active, created_at, updated_at, created_by, updated_by
		FROM boms
		WHERE company_id = $1 AND product_item_id = $2
		ORDER BY version DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, productItemID)
	if err != nil {
		return nil, fmt.Errorf("get BOM versions: %w", err)
	}
	defer rows.Close()

	var result []*models.BOM
	for rows.Next() {
		b, err := r.scanBOM(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// UpdateBOM - dynamically builds SET clause including version
func (r *bomRepository) UpdateBOM(ctx context.Context, db DBTX, bom *models.BOM) error {
	query := `UPDATE boms SET updated_at = NOW()`
	args := []interface{}{bom.BOMID}
	argIdx := 2

	if bom.BOMCode != "" {
		query += fmt.Sprintf(", bom_code = $%d", argIdx)
		args = append(args, bom.BOMCode)
		argIdx++
	}
	if bom.Name != "" {
		query += fmt.Sprintf(", name = $%d", argIdx)
		args = append(args, bom.Name)
		argIdx++
	}
	if bom.Quantity != decimal.Zero {
		query += fmt.Sprintf(", quantity = $%d", argIdx)
		args = append(args, bom.Quantity)
		argIdx++
	}
	if bom.Version != 0 {
		query += fmt.Sprintf(", version = $%d", argIdx)
		args = append(args, bom.Version)
		argIdx++
	}
	if bom.IsActive {
		query += fmt.Sprintf(", is_active = $%d", argIdx)
		args = append(args, bom.IsActive)
		argIdx++
	}
	if bom.UpdatedBy != nil {
		query += fmt.Sprintf(", updated_by = $%d", argIdx)
		args = append(args, bom.UpdatedBy)
		argIdx++
	}

	query += fmt.Sprintf(" WHERE bom_id = $1 RETURNING updated_at")

	err := db.QueryRowContext(ctx, query, args...).Scan(&bom.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: BOM %s", inventory_errors.ErrNotFound, bom.BOMID)
		}
		return fmt.Errorf("update BOM: %w", err)
	}
	return nil
}

func (r *bomRepository) DeactivateBOM(ctx context.Context, db DBTX, bomID uuid.UUID) error {
	query := `
		UPDATE boms SET is_active = false, updated_at = NOW()
		WHERE bom_id = $1
		RETURNING updated_at
	`
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, query, bomID).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: BOM %s", inventory_errors.ErrNotFound, bomID)
		}
		return fmt.Errorf("deactivate BOM: %w", err)
	}
	return nil
}

func (r *bomRepository) DeleteBOM(ctx context.Context, db DBTX, bomID uuid.UUID) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("DeleteBOM requires a transaction")
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM bom_items WHERE bom_id = $1`, bomID)
	if err != nil {
		return fmt.Errorf("delete BOM items: %w", err)
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM boms WHERE bom_id = $1`, bomID)
	if err != nil {
		return fmt.Errorf("delete BOM: %w", err)
	}
	return nil
}

// ---------- BOM items ----------

func (r *bomRepository) AddBOMItems(ctx context.Context, db DBTX, items []*models.BOMItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO bom_items (bom_item_id, bom_id, component_item_id, quantity, scrap_percentage, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING created_at
	`
	for _, it := range items {
		var scrap interface{}
		if it.ScrapPercentage != nil {
			scrap, _ = it.ScrapPercentage.Float64()
		} else {
			scrap = 0
		}
		err := db.QueryRowContext(ctx, query,
			it.BOMItemID, it.BOMID, it.ComponentItemID, it.Quantity, scrap,
		).Scan(&it.CreatedAt)
		if err != nil {
			return fmt.Errorf("add BOM item: %w", err)
		}
	}
	return nil
}

func (r *bomRepository) ReplaceBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID, items []*models.BOMItem) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("ReplaceBOMItems requires a transaction")
	}
	if err := r.DeleteBOMItems(ctx, tx, bomID); err != nil {
		return err
	}
	return r.AddBOMItems(ctx, tx, items)
}

func (r *bomRepository) GetBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID) ([]*models.BOMItem, error) {
	query := `
		SELECT bom_item_id, bom_id, component_item_id, quantity, scrap_percentage, created_at
		FROM bom_items
		WHERE bom_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, bomID)
	if err != nil {
		return nil, fmt.Errorf("get BOM items: %w", err)
	}
	defer rows.Close()

	var result []*models.BOMItem
	for rows.Next() {
		bi, err := r.scanBOMItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, bi)
	}
	return result, rows.Err()
}

func (r *bomRepository) DeleteBOMItems(ctx context.Context, db DBTX, bomID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM bom_items WHERE bom_id = $1`, bomID)
	if err != nil {
		return fmt.Errorf("delete BOM items: %w", err)
	}
	return nil
}

// ---------- Single BOM item operations ----------

func (r *bomRepository) GetBOMItemByID(ctx context.Context, db DBTX, bomItemID uuid.UUID) (*models.BOMItem, error) {
	query := `
		SELECT bom_item_id, bom_id, component_item_id, quantity, scrap_percentage, created_at
		FROM bom_items
		WHERE bom_item_id = $1
	`
	row := db.QueryRowContext(ctx, query, bomItemID)
	return r.scanBOMItem(row)
}

func (r *bomRepository) UpdateBOMItem(ctx context.Context, db DBTX, bomItem *models.BOMItem) error {
	query := `
		UPDATE bom_items SET
			quantity = $2,
			scrap_percentage = $3
		WHERE bom_item_id = $1
	`
	var scrap interface{}
	if bomItem.ScrapPercentage != nil {
		scrap, _ = bomItem.ScrapPercentage.Float64()
	} else {
		scrap = 0
	}
	res, err := db.ExecContext(ctx, query, bomItem.BOMItemID, bomItem.Quantity, scrap)
	if err != nil {
		return fmt.Errorf("update BOM item: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: BOM item %s", inventory_errors.ErrNotFound, bomItem.BOMItemID)
	}
	return nil
}

func (r *bomRepository) DeleteBOMItem(ctx context.Context, db DBTX, bomItemID uuid.UUID, companyID uuid.UUID) error {
	checkQuery := `
		SELECT 1 FROM bom_items bi
		JOIN boms b ON bi.bom_id = b.bom_id
		WHERE bi.bom_item_id = $1 AND b.company_id = $2
	`
	var exists int
	err := db.QueryRowContext(ctx, checkQuery, bomItemID, companyID).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return inventory_errors.ErrNotFound
		}
		return fmt.Errorf("check BOM item ownership: %w", err)
	}
	_, err = db.ExecContext(ctx, `DELETE FROM bom_items WHERE bom_item_id = $1`, bomItemID)
	if err != nil {
		return fmt.Errorf("delete BOM item: %w", err)
	}
	return nil
}

// ---------- ListBOMs with pagination ----------

func (r *bomRepository) ListBOMs(ctx context.Context, db DBTX, filter BOMFilter, p Pagination, s Sort) ([]*models.BOM, int64, error) {
	whereClause, args := r.buildBOMFilter(filter)

	allowedSort := map[string]bool{
		"bom_code":   true,
		"name":       true,
		"version":    true,
		"created_at": true,
		"updated_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT bom_id, company_id, product_item_id, bom_code, name,
		       version, quantity, is_active, created_at, updated_at, created_by, updated_by
		FROM boms
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list BOMs: %w", err)
	}
	defer rows.Close()

	var result []*models.BOM
	for rows.Next() {
		b, err := r.scanBOM(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, b)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM boms %s", whereClause)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args[:len(args)-2]...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count BOMs: %w", err)
	}

	return result, total, nil
}

func (r *bomRepository) buildBOMFilter(filter BOMFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- BOM explosion ----------

func (r *bomRepository) ExplodeBOM(ctx context.Context, db DBTX, bomID uuid.UUID, requiredQty decimal.Decimal) ([]*BOMExplosionResult, error) {
	query := `
		WITH RECURSIVE bom_cte AS (
			SELECT
				b.product_item_id AS item_id,
				b.quantity AS qty_per_parent,
				$2::numeric AS required_qty,
				0 AS level,
				NULL::uuid AS parent_item,
				b.bom_id
			FROM boms b
			WHERE b.bom_id = $1
			UNION ALL
			SELECT
				bi.component_item_id,
				bi.quantity,
				(cte.required_qty * bi.quantity / cte.qty_per_parent) AS required_qty,
				cte.level + 1,
				cte.item_id,
				bi.bom_id
			FROM bom_cte cte
			JOIN bom_items bi ON bi.bom_id = cte.bom_id
		)
		SELECT
			item_id,
			SUM(required_qty) AS total_required_qty,
			level,
			parent_item
		FROM bom_cte
		GROUP BY item_id, level, parent_item
		ORDER BY level, item_id
	`
	rows, err := db.QueryContext(ctx, query, bomID, requiredQty)
	if err != nil {
		return nil, fmt.Errorf("explode BOM: %w", err)
	}
	defer rows.Close()

	var results []*BOMExplosionResult
	for rows.Next() {
		var itemID uuid.UUID
		var totalQty float64
		var level int
		var parentNull uuid.NullUUID

		err := rows.Scan(&itemID, &totalQty, &level, &parentNull)
		if err != nil {
			return nil, fmt.Errorf("scan explosion result: %w", err)
		}
		var parentItem *uuid.UUID
		if parentNull.Valid {
			parentItem = &parentNull.UUID
		}
		results = append(results, &BOMExplosionResult{
			ItemID:      itemID,
			RequiredQty: totalQty,
			Level:       level,
			ParentItem:  parentItem,
		})
	}
	return results, rows.Err()
}

func (r *bomRepository) GetDirectComponents(ctx context.Context, db DBTX, bomID uuid.UUID) ([]*models.BOMItem, error) {
	return r.GetBOMItems(ctx, db, bomID)
}

// ---------- Costing ----------

func (r *bomRepository) CalculateBOMCost(ctx context.Context, db DBTX, bomID uuid.UUID) (*BOMCostResult, error) {
	explosion, err := r.ExplodeBOM(ctx, db, bomID, decimal.NewFromInt(1))
	if err != nil {
		return nil, fmt.Errorf("explode for costing: %w", err)
	}
	componentTotals := make(map[uuid.UUID]decimal.Decimal)
	for _, res := range explosion {
		if res.Level == 0 {
			continue
		}
		componentTotals[res.ItemID] = componentTotals[res.ItemID].Add(decimal.NewFromFloat(res.RequiredQty))
	}

	var components []ComponentCost
	var totalCost decimal.Decimal

	for itemID, qty := range componentTotals {
		unitCost, err := r.getItemCost(ctx, db, itemID)
		if err != nil {
			r.logger.Warn("failed to get cost for item, using zero", util.String("item_id", itemID.String()), util.ErrorField(err))
			unitCost = decimal.Zero
		}
		lineTotal := unitCost.Mul(qty)
		components = append(components, ComponentCost{
			ItemID:   itemID,
			Quantity: qty,
			UnitCost: unitCost,
			Total:    lineTotal,
		})
		totalCost = totalCost.Add(lineTotal)
	}

	return &BOMCostResult{
		BOMID:      bomID,
		TotalCost:  totalCost,
		Components: components,
	}, nil
}

// ExistsBOMByProductAndVersion checks if a BOM with given company, product, and version already exists.
func (r *bomRepository) ExistsBOMByProductAndVersion(ctx context.Context, db DBTX, companyID, productItemID uuid.UUID, version int) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM boms WHERE company_id = $1 AND product_item_id = $2 AND version = $3)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, productItemID, version).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check BOM existence: %w", err)
	}
	return exists, nil
}

// ExistsBOMItemByComponent checks if a component already exists in the given BOM.
func (r *bomRepository) ExistsBOMItemByComponent(ctx context.Context, db DBTX, bomID, componentItemID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM bom_items WHERE bom_id = $1 AND component_item_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, bomID, componentItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check BOM item existence: %w", err)
	}
	return exists, nil
}

// GetBOMByIDAndCompany retrieves a BOM by its ID and company ID.
func (r *bomRepository) GetBOMByIDAndCompany(ctx context.Context, db DBTX, bomID, companyID uuid.UUID) (*models.BOM, error) {
	query := `
        SELECT bom_id, company_id, product_item_id, bom_code, name,
               version, quantity, is_active, created_at, updated_at, created_by, updated_by
        FROM boms
        WHERE bom_id = $1 AND company_id = $2
    `
	row := db.QueryRowContext(ctx, query, bomID, companyID)
	return r.scanBOM(row)
}
