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

type InventoryLocationRepository interface {
	Create(ctx context.Context, db DBTX, loc *models.InventoryLocation) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.InventoryLocation, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.InventoryLocation, error)
	Update(ctx context.Context, db DBTX, loc *models.InventoryLocation) error
	SoftDelete(ctx context.Context, db DBTX, id uuid.UUID) error
	List(ctx context.Context, db DBTX, companyID uuid.UUID, parentID *uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error)
	GetTree(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.InventoryLocation, error) // full hierarchy
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string, excludeID *uuid.UUID) (bool, error)
}

type inventoryLocationRepository struct {
	logger *zap.Logger
}

func NewInventoryLocationRepository(logger *zap.Logger) InventoryLocationRepository {
	return &inventoryLocationRepository{
		logger: logger.Named("location_repo"),
	}
}

func (r *inventoryLocationRepository) scanLocation(s scanner) (*models.InventoryLocation, error) {
	var loc models.InventoryLocation
	var parentID uuid.NullUUID
	var locationType sql.NullString

	err := s.Scan(
		&loc.LocationID,
		&loc.CompanyID,
		&loc.Code,
		&loc.Name,
		&locationType,
		&parentID,
		&loc.IsActive,
		&loc.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan location: %w", err)
	}

	if locationType.Valid {
		loc.LocationType = &locationType.String
	}
	if parentID.Valid {
		loc.ParentLocationID = &parentID.UUID
	}
	return &loc, nil
}

func (r *inventoryLocationRepository) Create(ctx context.Context, db DBTX, loc *models.InventoryLocation) error {
	query := `
		INSERT INTO inventory_locations (
			location_id, company_id, code, name, location_type, parent_location_id, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		loc.LocationID, loc.CompanyID, loc.Code, loc.Name,
		loc.LocationType, loc.ParentLocationID, loc.IsActive,
	).Scan(&loc.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create inventory location", util.ErrorField(err))
		return fmt.Errorf("create location: %w", err)
	}
	return nil
}

func (r *inventoryLocationRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.InventoryLocation, error) {
	query := `
		SELECT location_id, company_id, code, name, location_type, parent_location_id, is_active, created_at
		FROM inventory_locations
		WHERE location_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanLocation(row)
}

func (r *inventoryLocationRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.InventoryLocation, error) {
	query := `
		SELECT location_id, company_id, code, name, location_type, parent_location_id, is_active, created_at
		FROM inventory_locations
		WHERE company_id = $1 AND code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanLocation(row)
}

func (r *inventoryLocationRepository) Update(ctx context.Context, db DBTX, loc *models.InventoryLocation) error {
	query := `
		UPDATE inventory_locations
		SET code = $2, name = $3, location_type = $4, parent_location_id = $5, is_active = $6
		WHERE location_id = $1
	`
	res, err := db.ExecContext(ctx, query,
		loc.LocationID, loc.Code, loc.Name, loc.LocationType, loc.ParentLocationID, loc.IsActive)
	if err != nil {
		return fmt.Errorf("update location: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: location %s", inventory_errors.ErrNotFound, loc.LocationID)
	}
	return nil
}

func (r *inventoryLocationRepository) SoftDelete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `UPDATE inventory_locations SET is_active = false WHERE location_id = $1`
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("soft delete location: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: location %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *inventoryLocationRepository) List(ctx context.Context, db DBTX, companyID uuid.UUID, parentID *uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error) {
	conds := []string{"company_id = $1"}
	args := []interface{}{companyID}
	idx := 2

	if parentID != nil {
		conds = append(conds, fmt.Sprintf("parent_location_id = $%d", idx))
		args = append(args, *parentID)
		idx++
	}
	if activeOnly {
		conds = append(conds, "is_active = true")
	}

	query := fmt.Sprintf(`
		SELECT location_id, company_id, code, name, location_type, parent_location_id, is_active, created_at
		FROM inventory_locations
		WHERE %s
		ORDER BY code
	`, strings.Join(conds, " AND "))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list locations: %w", err)
	}
	defer rows.Close()

	var result []*models.InventoryLocation
	for rows.Next() {
		loc, err := r.scanLocation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, loc)
	}
	return result, rows.Err()
}

// GetTree returns all locations for a company with parent-child relationships (no specific ordering; client can build tree).
func (r *inventoryLocationRepository) GetTree(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.InventoryLocation, error) {
	query := `
		SELECT location_id, company_id, code, name, location_type, parent_location_id, is_active, created_at
		FROM inventory_locations
		WHERE company_id = $1
		ORDER BY parent_location_id NULLS FIRST, code
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get location tree: %w", err)
	}
	defer rows.Close()

	var result []*models.InventoryLocation
	for rows.Next() {
		loc, err := r.scanLocation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, loc)
	}
	return result, rows.Err()
}

func (r *inventoryLocationRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string, excludeID *uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM inventory_locations WHERE company_id = $1 AND code = $2`
	args := []interface{}{companyID, code}
	if excludeID != nil {
		query += ` AND location_id != $3`
		args = append(args, *excludeID)
	}
	query += `)`
	var exists bool
	err := db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check location code exists: %w", err)
	}
	return exists, nil
}
