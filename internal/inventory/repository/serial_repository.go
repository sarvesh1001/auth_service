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

type SerialRepository interface {
	Create(ctx context.Context, db DBTX, serial *models.SerialNumber) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.SerialNumber, error)
	GetBySerialNumber(ctx context.Context, db DBTX, companyID uuid.UUID, serialNumber string) (*models.SerialNumber, error)
	GetByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, status *string) ([]*models.SerialNumber, error)
	UpdateStatus(ctx context.Context, db DBTX, serialID uuid.UUID, status string) error
	AssignToWarehouse(ctx context.Context, db DBTX, serialID, warehouseID uuid.UUID) error
	AssignToBatch(ctx context.Context, db DBTX, serialID, batchID uuid.UUID) error
	List(ctx context.Context, db DBTX, filter SerialFilter, p Pagination, s Sort) ([]*models.SerialNumber, int64, error)
}

type SerialFilter struct {
	CompanyID   uuid.UUID
	ItemID      *uuid.UUID
	WarehouseID *uuid.UUID
	BatchID     *uuid.UUID
	Status      *string
	Search      string
}

type serialRepository struct {
	logger *zap.Logger
}

func NewSerialRepository(logger *zap.Logger) SerialRepository {
	return &serialRepository{
		logger: logger.Named("serial_repo"),
	}
}

func (r *serialRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *serialRepository) validatePagination(p Pagination) (int, int) {
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

func (r *serialRepository) buildFilter(filter SerialFilter) (string, []interface{}) {
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
	if filter.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, *filter.WarehouseID)
		idx++
	}
	if filter.BatchID != nil {
		conds = append(conds, fmt.Sprintf("batch_id = $%d", idx))
		args = append(args, *filter.BatchID)
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		conds = append(conds, fmt.Sprintf("serial_number ILIKE $%d", idx))
		args = append(args, search)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *serialRepository) scanSerial(s scanner) (*models.SerialNumber, error) {
	var serial models.SerialNumber
	var warehouseID, batchID uuid.NullUUID
	var status sql.NullString

	err := s.Scan(
		&serial.SerialID,
		&serial.CompanyID,
		&serial.ItemID,
		&serial.SerialNumber,
		&warehouseID,
		&batchID,
		&status,
		&serial.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan serial number: %w", err)
	}
	if warehouseID.Valid {
		serial.WarehouseID = &warehouseID.UUID
	}
	if batchID.Valid {
		serial.BatchID = &batchID.UUID
	}
	if status.Valid {
		serial.Status = &status.String
	}
	return &serial, nil
}

func (r *serialRepository) Create(ctx context.Context, db DBTX, serial *models.SerialNumber) error {
	query := `
		INSERT INTO serial_numbers (
			serial_id, company_id, item_id, serial_number, warehouse_id, batch_id, status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		serial.SerialID, serial.CompanyID, serial.ItemID, serial.SerialNumber,
		serial.WarehouseID, serial.BatchID, serial.Status,
	).Scan(&serial.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create serial number", util.ErrorField(err))
		return fmt.Errorf("create serial number: %w", err)
	}
	return nil
}

func (r *serialRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.SerialNumber, error) {
	query := `
		SELECT serial_id, company_id, item_id, serial_number, warehouse_id, batch_id, status, created_at
		FROM serial_numbers
		WHERE serial_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanSerial(row)
}

func (r *serialRepository) GetBySerialNumber(ctx context.Context, db DBTX, companyID uuid.UUID, serialNumber string) (*models.SerialNumber, error) {
	query := `
		SELECT serial_id, company_id, item_id, serial_number, warehouse_id, batch_id, status, created_at
		FROM serial_numbers
		WHERE company_id = $1 AND serial_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, serialNumber)
	return r.scanSerial(row)
}

func (r *serialRepository) GetByItem(ctx context.Context, db DBTX, companyID, itemID uuid.UUID, status *string) ([]*models.SerialNumber, error) {
	conds := []string{"company_id = $1", "item_id = $2"}
	args := []interface{}{companyID, itemID}
	idx := 3

	if status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *status)
		idx++
	}

	query := fmt.Sprintf(`
		SELECT serial_id, company_id, item_id, serial_number, warehouse_id, batch_id, status, created_at
		FROM serial_numbers
		WHERE %s
		ORDER BY created_at DESC
	`, strings.Join(conds, " AND "))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get serials by item: %w", err)
	}
	defer rows.Close()

	var result []*models.SerialNumber
	for rows.Next() {
		s, err := r.scanSerial(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *serialRepository) UpdateStatus(ctx context.Context, db DBTX, serialID uuid.UUID, status string) error {
	query := `UPDATE serial_numbers SET status = $2 WHERE serial_id = $1`
	res, err := db.ExecContext(ctx, query, serialID, status)
	if err != nil {
		return fmt.Errorf("update serial status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: serial %s", inventory_errors.ErrNotFound, serialID)
	}
	return nil
}

func (r *serialRepository) AssignToWarehouse(ctx context.Context, db DBTX, serialID, warehouseID uuid.UUID) error {
	query := `UPDATE serial_numbers SET warehouse_id = $2 WHERE serial_id = $1`
	res, err := db.ExecContext(ctx, query, serialID, warehouseID)
	if err != nil {
		return fmt.Errorf("assign serial to warehouse: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: serial %s", inventory_errors.ErrNotFound, serialID)
	}
	return nil
}

func (r *serialRepository) AssignToBatch(ctx context.Context, db DBTX, serialID, batchID uuid.UUID) error {
	query := `UPDATE serial_numbers SET batch_id = $2 WHERE serial_id = $1`
	res, err := db.ExecContext(ctx, query, serialID, batchID)
	if err != nil {
		return fmt.Errorf("assign serial to batch: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: serial %s", inventory_errors.ErrNotFound, serialID)
	}
	return nil
}

func (r *serialRepository) List(ctx context.Context, db DBTX, filter SerialFilter, p Pagination, s Sort) ([]*models.SerialNumber, int64, error) {
	where, args := r.buildFilter(filter)
	allowedSort := map[string]bool{
		"serial_number": true,
		"created_at":    true,
		"status":        true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM serial_numbers %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count serial numbers: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT serial_id, company_id, item_id, serial_number, warehouse_id, batch_id, status, created_at
		FROM serial_numbers
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list serial numbers: %w", err)
	}
	defer rows.Close()

	var result []*models.SerialNumber
	for rows.Next() {
		s, err := r.scanSerial(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, s)
	}
	return result, total, rows.Err()
}
