package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// WarehouseFilter for listing warehouses
type WarehouseFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string // matches code, name, or location
}

// WarehouseRepository defines all warehouse data access methods
type WarehouseRepository interface {
	// Create
	Create(ctx context.Context, db DBTX, warehouse *models.Warehouse) error
	BulkCreate(ctx context.Context, db DBTX, warehouses []*models.Warehouse) error

	// Read
	GetByID(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) (*models.Warehouse, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Warehouse, error)
	GetByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) ([]*models.Warehouse, error)
	List(ctx context.Context, db DBTX, filter WarehouseFilter, p Pagination, s Sort) ([]*models.Warehouse, error)
	Count(ctx context.Context, db DBTX, filter WarehouseFilter) (int64, error)

	// Update
	Update(ctx context.Context, db DBTX, warehouse *models.Warehouse) error
	UpdateStatus(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID, isActive bool) error

	// Delete (soft)
	SoftDelete(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) error

	// Validation / helpers
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) (bool, error)
	CodeExists(ctx context.Context, db DBTX, companyID uuid.UUID, code string, excludeID *uuid.UUID) (bool, error)

	// Business helpers
	GetActiveWarehouses(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Warehouse, error)
	GetDefaultWarehouse(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.Warehouse, error)
}

type warehouseRepository struct {
	logger *zap.Logger
}

func NewWarehouseRepository(logger *zap.Logger) WarehouseRepository {
	return &warehouseRepository{
		logger: logger.Named("warehouse_repo"),
	}
}

// ---------- helpers ----------
func (r *warehouseRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *warehouseRepository) validatePagination(p Pagination) (int, int) {
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

func (r *warehouseRepository) buildWarehouseFilter(filter WarehouseFilter) (string, []interface{}) {
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
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("(code ILIKE $%d OR name ILIKE $%d OR location ILIKE $%d)", idx, idx+1, idx+2))
		args = append(args, searchTerm, searchTerm, searchTerm)
		idx += 3
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanWarehouse now includes is_default and all new columns
func (r *warehouseRepository) scanWarehouse(sc scanner) (*models.Warehouse, error) {
	var w models.Warehouse
	var location sql.NullString
	var createdBy, updatedBy uuid.NullUUID
	var locationID uuid.NullUUID
	var warehouseType sql.NullString
	var allowNegativeStock bool
	var isDefault bool

	err := sc.Scan(
		&w.WarehouseID, &w.CompanyID, &w.Code, &w.Name, &location,
		&w.IsActive, &w.CreatedAt, &w.UpdatedAt, &createdBy, &updatedBy,
		&isDefault, // is_default column
		&locationID, &warehouseType, &allowNegativeStock,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan warehouse: %w", err)
	}

	if location.Valid {
		w.Location = &location.String
	}
	if createdBy.Valid {
		w.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		w.UpdatedBy = &updatedBy.UUID
	}
	w.IsDefault = isDefault
	if locationID.Valid {
		w.LocationID = &locationID.UUID
	}
	if warehouseType.Valid {
		w.WarehouseType = &warehouseType.String
	}
	w.AllowNegativeStock = allowNegativeStock

	return &w, nil
}

// ---------- Create ----------
func (r *warehouseRepository) Create(ctx context.Context, db DBTX, warehouse *models.Warehouse) error {
	query := `
		INSERT INTO warehouses (
			warehouse_id, company_id, code, name, location, is_active,
			created_at, updated_at, created_by, updated_by,
			is_default, location_id, warehouse_type, allow_negative_stock
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		warehouse.WarehouseID, warehouse.CompanyID, warehouse.Code, warehouse.Name,
		warehouse.Location, warehouse.IsActive, warehouse.CreatedBy, warehouse.UpdatedBy,
		warehouse.IsDefault, nullUUIDParam(warehouse.LocationID), warehouse.WarehouseType, warehouse.AllowNegativeStock,
	).Scan(&warehouse.CreatedAt, &warehouse.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create warehouse", util.ErrorField(err))
		return fmt.Errorf("create warehouse: %w", err)
	}
	return nil
}

func (r *warehouseRepository) BulkCreate(ctx context.Context, db DBTX, warehouses []*models.Warehouse) error {
	if len(warehouses) == 0 {
		return nil
	}
	// Insert each warehouse individually – bulk warehouse creation is typically small.
	for _, w := range warehouses {
		query := `
			INSERT INTO warehouses (
				warehouse_id, company_id, code, name, location, is_active,
				created_at, updated_at, created_by, updated_by,
				is_default, location_id, warehouse_type, allow_negative_stock
			) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8, $9, $10, $11, $12)
			RETURNING created_at, updated_at
		`
		err := db.QueryRowContext(ctx, query,
			w.WarehouseID, w.CompanyID, w.Code, w.Name, w.Location,
			w.IsActive, w.CreatedBy, w.UpdatedBy,
			w.IsDefault, nullUUIDParam(w.LocationID), w.WarehouseType, w.AllowNegativeStock,
		).Scan(&w.CreatedAt, &w.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create warehouse failed", util.ErrorField(err))
			return fmt.Errorf("bulk create warehouse: %w", err)
		}
	}
	return nil
}

// ---------- Read ----------
func (r *warehouseRepository) GetByID(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) (*models.Warehouse, error) {
	query := `
        SELECT warehouse_id, company_id, code, name, location, is_active,
               created_at, updated_at, created_by, updated_by,
               is_default, location_id, warehouse_type, allow_negative_stock
        FROM warehouses
        WHERE company_id = $1 AND warehouse_id = $2
    `
	row := db.QueryRowContext(ctx, query, companyID, warehouseID)
	warehouse, err := r.scanWarehouse(row)
	if err != nil {
		return nil, err
	}
	if warehouse == nil {
		return nil, fmt.Errorf("%w: warehouse %s", inventory_errors.ErrNotFound, warehouseID)
	}
	// *** ADD THIS CHECK ***
	if !warehouse.IsActive {
		return nil, fmt.Errorf("%w: warehouse %s is inactive", inventory_errors.ErrNotFound, warehouseID)
	}
	return warehouse, nil
}
func (r *warehouseRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Warehouse, error) {
	query := `
		SELECT warehouse_id, company_id, code, name, location, is_active,
		       created_at, updated_at, created_by, updated_by,
		       is_default, location_id, warehouse_type, allow_negative_stock
		FROM warehouses
		WHERE company_id = $1 AND code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	warehouse, err := r.scanWarehouse(row)
	if err != nil {
		return nil, err
	}
	if warehouse == nil {
		return nil, fmt.Errorf("%w: warehouse with code %s", inventory_errors.ErrNotFound, code)
	}
	return warehouse, nil
}

func (r *warehouseRepository) GetByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) ([]*models.Warehouse, error) {
	if len(ids) == 0 {
		return []*models.Warehouse{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+1)
	args[0] = companyID
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := fmt.Sprintf(`
		SELECT warehouse_id, company_id, code, name, location, is_active,
		       created_at, updated_at, created_by, updated_by,
		       is_default, location_id, warehouse_type, allow_negative_stock
		FROM warehouses
		WHERE company_id = $1 AND warehouse_id IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get warehouses by ids: %w", err)
	}
	defer rows.Close()

	var result []*models.Warehouse
	for rows.Next() {
		w, err := r.scanWarehouse(rows)
		if err != nil {
			return nil, err
		}
		if w != nil {
			result = append(result, w)
		}
	}
	return result, rows.Err()
}

func (r *warehouseRepository) List(ctx context.Context, db DBTX, filter WarehouseFilter, p Pagination, s Sort) ([]*models.Warehouse, error) {
	where, args := r.buildWarehouseFilter(filter)

	allowedSort := map[string]bool{
		"code":           true,
		"name":           true,
		"created_at":     true,
		"updated_at":     true,
		"warehouse_type": true,
		"is_default":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY name ASC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT warehouse_id, company_id, code, name, location, is_active,
		       created_at, updated_at, created_by, updated_by,
		       is_default, location_id, warehouse_type, allow_negative_stock
		FROM warehouses
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list warehouses: %w", err)
	}
	defer rows.Close()

	var result []*models.Warehouse
	for rows.Next() {
		w, err := r.scanWarehouse(rows)
		if err != nil {
			return nil, err
		}
		if w != nil {
			result = append(result, w)
		}
	}
	return result, rows.Err()
}

func (r *warehouseRepository) Count(ctx context.Context, db DBTX, filter WarehouseFilter) (int64, error) {
	where, args := r.buildWarehouseFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM warehouses %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count warehouses: %w", err)
	}
	return count, nil
}

// ---------- Update ----------
func (r *warehouseRepository) Update(ctx context.Context, db DBTX, warehouse *models.Warehouse) error {
	query := `
		UPDATE warehouses SET
			code = $2,
			name = $3,
			location = $4,
			is_active = $5,
			updated_at = NOW(),
			updated_by = $6,
			is_default = $7,
			location_id = $8,
			warehouse_type = $9,
			allow_negative_stock = $10
		WHERE company_id = $11 AND warehouse_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		warehouse.WarehouseID, warehouse.Code, warehouse.Name, warehouse.Location,
		warehouse.IsActive, warehouse.UpdatedBy, warehouse.IsDefault,
		nullUUIDParam(warehouse.LocationID), warehouse.WarehouseType, warehouse.AllowNegativeStock,
		warehouse.CompanyID,
	).Scan(&warehouse.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: warehouse %s", inventory_errors.ErrNotFound, warehouse.WarehouseID)
		}
		return fmt.Errorf("update warehouse: %w", err)
	}
	return nil
}

func (r *warehouseRepository) UpdateStatus(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID, isActive bool) error {
	query := `
		UPDATE warehouses
		SET is_active = $3, updated_at = NOW()
		WHERE company_id = $1 AND warehouse_id = $2
		RETURNING updated_at
	`
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, companyID, warehouseID, isActive).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: warehouse %s", inventory_errors.ErrNotFound, warehouseID)
		}
		return fmt.Errorf("update warehouse status: %w", err)
	}
	return nil
}

// ---------- Soft Delete ----------
func (r *warehouseRepository) SoftDelete(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, warehouseID, false)
}

// ---------- Validation ----------
func (r *warehouseRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, warehouseID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM warehouses WHERE company_id = $1 AND warehouse_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, warehouseID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check warehouse exists: %w", err)
	}
	return exists, nil
}

func (r *warehouseRepository) CodeExists(ctx context.Context, db DBTX, companyID uuid.UUID, code string, excludeID *uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM warehouses WHERE company_id = $1 AND code = $2`
	args := []interface{}{companyID, code}
	if excludeID != nil {
		query += ` AND warehouse_id != $3`
		args = append(args, *excludeID)
	}
	query += `)`
	var exists bool
	err := db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check warehouse code exists: %w", err)
	}
	return exists, nil
}

// ---------- Business helpers ----------
func (r *warehouseRepository) GetActiveWarehouses(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Warehouse, error) {
	filter := WarehouseFilter{
		CompanyID: companyID,
		IsActive:  boolPtr(true),
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

func (r *warehouseRepository) GetDefaultWarehouse(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.Warehouse, error) {
	query := `
		SELECT warehouse_id, company_id, code, name, location, is_active,
		       created_at, updated_at, created_by, updated_by,
		       is_default, location_id, warehouse_type, allow_negative_stock
		FROM warehouses
		WHERE company_id = $1 AND is_default = true
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID)
	warehouse, err := r.scanWarehouse(row)
	if err != nil {
		return nil, err
	}
	if warehouse == nil {
		return nil, fmt.Errorf("%w: default warehouse for company %s", inventory_errors.ErrNotFound, companyID)
	}
	return warehouse, nil
}
