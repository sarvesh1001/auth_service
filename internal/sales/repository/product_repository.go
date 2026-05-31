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

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
)

// -------------------------------------------------------------------------
// Types & Interface
// -------------------------------------------------------------------------

type ProductRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, product *models.Product) error
	GetByID(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (*models.Product, error)
	GetBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (*models.Product, error)
	Update(ctx context.Context, db DBTX, product *models.Product) error
	Delete(ctx context.Context, db DBTX, companyID, productID uuid.UUID) error

	// Status / lifecycle
	SetActiveStatus(ctx context.Context, db DBTX, companyID, productID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (bool, error)
	ExistsBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (bool, error)

	// Inventory linkage
	GetByInventoryItemID(ctx context.Context, db DBTX, companyID, inventoryItemID uuid.UUID) (*models.Product, error)
	ExistsByInventoryItemID(ctx context.Context, db DBTX, companyID, inventoryItemID uuid.UUID) (bool, error)
	UpdateInventoryItemLink(ctx context.Context, db DBTX, companyID, productID uuid.UUID, inventoryItemID *uuid.UUID, updatedBy *uuid.UUID) error
	ExistsInventoryItemByIDAndCompany(ctx context.Context, db DBTX, itemID, companyID uuid.UUID) (bool, error) // NEW

	// Pricing
	UpdateUnitPrice(ctx context.Context, db DBTX, companyID, productID uuid.UUID, unitPrice decimal.Decimal, updatedBy *uuid.UUID) error
	GetUnitPrice(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (decimal.Decimal, error)
	GetProductsByPriceRange(ctx context.Context, db DBTX, companyID uuid.UUID, minPrice, maxPrice *decimal.Decimal) ([]*models.Product, error)

	// Sales analytics / reporting (precomputed from fact tables)
	GetTopSellingProducts(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error)
	GetProductsNeverSold(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Product, error)
	GetProductsWithReturns(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*models.Product, error)

	// Querying / listing
	List(ctx context.Context, db DBTX, filter ProductFilter, p Pagination, s Sort) ([]*models.Product, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Product, int64, error)

	// Concurrency / locking
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (*models.Product, error)
}

// ProductFilter defines filter criteria for product listing.
type ProductFilter struct {
	CompanyID        uuid.UUID
	IsActive         *bool
	ProductIDs       []uuid.UUID
	SKU              *string
	Name             *string
	InventoryItemID  *uuid.UUID // exact match
	HasInventoryItem *bool      // true = inventory_item_id IS NOT NULL, false = IS NULL
	MinUnitPrice     *decimal.Decimal
	MaxUnitPrice     *decimal.Decimal
	SearchTerm       *string // searches across sku, name, description
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
	UpdatedFrom      *time.Time
	UpdatedTo        *time.Time
}

type productRepository struct {
	logger *zap.Logger
}

func NewProductRepository(logger *zap.Logger) ProductRepository {
	return &productRepository{
		logger: logger.Named("sales_product_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *productRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *productRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *productRepository) validatePagination(p Pagination) (int, int) {
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

func (r *productRepository) buildFilter(filter ProductFilter) (string, []interface{}) {
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
	if len(filter.ProductIDs) > 0 {
		placeholders := make([]string, len(filter.ProductIDs))
		for i, id := range filter.ProductIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("product_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SKU != nil {
		conds = append(conds, fmt.Sprintf("sku = $%d", idx))
		args = append(args, *filter.SKU)
		idx++
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name ILIKE $%d", idx))
		args = append(args, "%"+*filter.Name+"%")
		idx++
	}
	if filter.InventoryItemID != nil {
		conds = append(conds, fmt.Sprintf("inventory_item_id = $%d", idx))
		args = append(args, *filter.InventoryItemID)
		idx++
	}
	if filter.HasInventoryItem != nil {
		if *filter.HasInventoryItem {
			conds = append(conds, "inventory_item_id IS NOT NULL")
		} else {
			conds = append(conds, "inventory_item_id IS NULL")
		}
	}
	if filter.MinUnitPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price >= $%d", idx))
		args = append(args, *filter.MinUnitPrice)
		idx++
	}
	if filter.MaxUnitPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price <= $%d", idx))
		args = append(args, *filter.MaxUnitPrice)
		idx++
	}
	if filter.SearchTerm != nil && *filter.SearchTerm != "" {
		term := "%" + *filter.SearchTerm + "%"
		conds = append(conds, fmt.Sprintf("(sku ILIKE $%d OR name ILIKE $%d OR description ILIKE $%d)", idx, idx+1, idx+2))
		args = append(args, term, term, term)
		idx += 3
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanProduct maps a database row to models.Product
func (r *productRepository) scanProduct(s scanner) (*models.Product, error) {
	var p models.Product
	var createdBy, updatedBy uuid.NullUUID
	var description sql.NullString

	err := s.Scan(
		&p.ProductID,
		&p.CompanyID,
		&p.SKU,
		&p.Name,
		&description,
		&p.UnitPrice,
		&p.IsActive,
		&p.InventoryItemID,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan product: %w", err)
	}
	if description.Valid {
		p.Description = &description.String
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	return &p, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *productRepository) Create(ctx context.Context, db DBTX, product *models.Product) error {
	query := `
		INSERT INTO sales.products (
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			NOW(), NOW(), $9, $10
		)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		product.ProductID,
		product.CompanyID,
		product.SKU,
		product.Name,
		product.Description,
		product.UnitPrice,
		product.IsActive,
		r.nullUUIDParam(product.InventoryItemID),
		r.nullUUIDParam(product.CreatedBy),
		r.nullUUIDParam(product.UpdatedBy),
	).Scan(&product.CreatedAt, &product.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create product", zap.Error(err))
		return fmt.Errorf("create product: %w", err)
	}
	return nil
}

func (r *productRepository) GetByID(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (*models.Product, error) {
	query := `
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE company_id = $1 AND product_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, productID)
	return r.scanProduct(row)
}

func (r *productRepository) GetBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (*models.Product, error) {
	query := `
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE company_id = $1 AND sku = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, sku)
	return r.scanProduct(row)
}

func (r *productRepository) Update(ctx context.Context, db DBTX, product *models.Product) error {
	query := `
		UPDATE sales.products SET
			sku = $3,
			name = $4,
			description = $5,
			unit_price = $6,
			is_active = $7,
			inventory_item_id = $8,
			updated_at = NOW(),
			updated_by = $9
		WHERE product_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		product.ProductID,
		product.CompanyID,
		product.SKU,
		product.Name,
		product.Description,
		product.UnitPrice,
		product.IsActive,
		r.nullUUIDParam(product.InventoryItemID),
		r.nullUUIDParam(product.UpdatedBy),
	).Scan(&product.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update product: %w", err)
	}
	return nil
}

func (r *productRepository) Delete(ctx context.Context, db DBTX, companyID, productID uuid.UUID) error {
	query := `DELETE FROM sales.products WHERE company_id = $1 AND product_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, productID)
	if err != nil {
		return fmt.Errorf("delete product: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / lifecycle
// -------------------------------------------------------------------------

func (r *productRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, productID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.products
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND product_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, productID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *productRepository) Exists(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.products WHERE company_id = $1 AND product_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, productID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *productRepository) ExistsBySKU(ctx context.Context, db DBTX, companyID uuid.UUID, sku string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.products WHERE company_id = $1 AND sku = $2)`
	err := db.QueryRowContext(ctx, query, companyID, sku).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by sku: %w", err)
	}
	return exists, nil
}

func (r *productRepository) IsActive(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.products WHERE company_id = $1 AND product_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, productID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Inventory linkage
// -------------------------------------------------------------------------

func (r *productRepository) GetByInventoryItemID(ctx context.Context, db DBTX, companyID, inventoryItemID uuid.UUID) (*models.Product, error) {
	query := `
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE company_id = $1 AND inventory_item_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, inventoryItemID)
	return r.scanProduct(row)
}

func (r *productRepository) ExistsByInventoryItemID(ctx context.Context, db DBTX, companyID, inventoryItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.products WHERE company_id = $1 AND inventory_item_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, inventoryItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by inventory item id: %w", err)
	}
	return exists, nil
}

func (r *productRepository) UpdateInventoryItemLink(ctx context.Context, db DBTX, companyID, productID uuid.UUID, inventoryItemID *uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.products
		SET inventory_item_id = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND product_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, productID, r.nullUUIDParam(inventoryItemID), r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update inventory item link: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Pricing
// -------------------------------------------------------------------------

func (r *productRepository) UpdateUnitPrice(ctx context.Context, db DBTX, companyID, productID uuid.UUID, unitPrice decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.products
		SET unit_price = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND product_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, productID, unitPrice, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update unit price: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *productRepository) GetUnitPrice(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (decimal.Decimal, error) {
	var price decimal.Decimal
	query := `SELECT unit_price FROM sales.products WHERE company_id = $1 AND product_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, productID).Scan(&price)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, errors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get unit price: %w", err)
	}
	return price, nil
}

func (r *productRepository) GetProductsByPriceRange(ctx context.Context, db DBTX, companyID uuid.UUID, minPrice, maxPrice *decimal.Decimal) ([]*models.Product, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if minPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price >= $%d", idx))
		args = append(args, *minPrice)
		idx++
	}
	if maxPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price <= $%d", idx))
		args = append(args, *maxPrice)
		idx++
	}
	whereClause := strings.Join(conds, " AND ")

	query := fmt.Sprintf(`
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE %s
		ORDER BY unit_price ASC
	`, whereClause)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get products by price range: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Sales analytics / reporting (precomputed from fact tables)
// -------------------------------------------------------------------------

// GetTopSellingProducts returns products ordered by total quantity sold within the optional date range.
// It reads from the pre‑aggregated product_sales_fact table.
func (r *productRepository) GetTopSellingProducts(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("f.company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if from != nil {
		conds = append(conds, fmt.Sprintf("f.date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("f.date <= $%d", idx))
		args = append(args, *to)
		idx++
	}

	whereClause := strings.Join(conds, " AND ")

	query := fmt.Sprintf(`
		SELECT 
			p.product_id, p.company_id, p.sku, p.name, p.description,
			p.unit_price, p.is_active, p.inventory_item_id,
			p.created_at, p.updated_at, p.created_by, p.updated_by
		FROM sales.products p
		JOIN (
			SELECT product_id, SUM(quantity_sold) as total_sold
			FROM sales_analytics.product_sales_fact f
			WHERE %s
			GROUP BY product_id
			ORDER BY total_sold DESC
			LIMIT $%d
		) f ON p.product_id = f.product_id
		WHERE p.company_id = $1
		ORDER BY f.total_sold DESC
	`, whereClause, idx)

	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top selling products from fact table: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// GetProductsNeverSold returns products that have no entries in product_sales_fact.
func (r *productRepository) GetProductsNeverSold(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Product, error) {
	query := `
		SELECT 
			p.product_id, p.company_id, p.sku, p.name, p.description,
			p.unit_price, p.is_active, p.inventory_item_id,
			p.created_at, p.updated_at, p.created_by, p.updated_by
		FROM sales.products p
		LEFT JOIN sales_analytics.product_sales_fact f 
			ON p.product_id = f.product_id AND p.company_id = f.company_id
		WHERE p.company_id = $1
		  AND (f.product_id IS NULL OR f.quantity_sold = 0)
		ORDER BY p.name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get products never sold from fact table: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// GetProductsWithReturns returns products that have at least one return record in product_returns_fact within the optional date range.
func (r *productRepository) GetProductsWithReturns(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*models.Product, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("rf.company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if from != nil {
		conds = append(conds, fmt.Sprintf("rf.date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("rf.date <= $%d", idx))
		args = append(args, *to)
		idx++
	}

	whereClause := strings.Join(conds, " AND ")

	query := fmt.Sprintf(`
		SELECT DISTINCT
			p.product_id, p.company_id, p.sku, p.name, p.description,
			p.unit_price, p.is_active, p.inventory_item_id,
			p.created_at, p.updated_at, p.created_by, p.updated_by
		FROM sales.products p
		JOIN sales_analytics.product_returns_fact rf ON p.product_id = rf.product_id
		WHERE %s
		ORDER BY p.name
	`, whereClause)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get products with returns from fact table: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Listing & Search
// -------------------------------------------------------------------------

func (r *productRepository) List(ctx context.Context, db DBTX, filter ProductFilter, p Pagination, s Sort) ([]*models.Product, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"sku":        true,
		"name":       true,
		"unit_price": true,
		"is_active":  true,
		"created_at": true,
		"updated_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.products %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count products: %w", err)
	}
	if total == 0 {
		return []*models.Product{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list products: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *productRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Product, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.products
		WHERE company_id = $1
		AND (sku ILIKE $2 OR name ILIKE $3 OR description ILIKE $4)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Product{}, 0, nil
	}

	dataQuery := `
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE company_id = $1
		AND (sku ILIKE $2 OR name ILIKE $3 OR description ILIKE $4)
		ORDER BY name ASC
		LIMIT $5 OFFSET $6
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.Product
	for rows.Next() {
		p, err := r.scanProduct(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *productRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (*models.Product, error) {
	query := `
		SELECT 
			product_id, company_id, sku, name, description,
			unit_price, is_active, inventory_item_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.products
		WHERE company_id = $1 AND product_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, productID)
	return r.scanProduct(row)
}

// ExistsInventoryItemByIDAndCompany checks if an item exists in the inventory.items table
// and belongs to the given company. Returns true only if the item is active.
func (r *productRepository) ExistsInventoryItemByIDAndCompany(ctx context.Context, db DBTX, itemID, companyID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM items WHERE item_id = $1 AND company_id = $2 AND is_active = true)`
	var exists bool
	err := db.QueryRowContext(ctx, query, itemID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check inventory item existence: %w", err)
	}
	return exists, nil
}
