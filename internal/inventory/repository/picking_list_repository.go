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

type PickingListRepository interface {
	Create(ctx context.Context, db DBTX, pickingList *models.PickingList) error
	GetByID(ctx context.Context, db DBTX, pickingListID uuid.UUID) (*models.PickingList, error)
	GetByFulfillmentOrder(ctx context.Context, db DBTX, fulfillmentOrderID uuid.UUID) ([]*models.PickingList, error)
	UpdateStatus(ctx context.Context, db DBTX, pickingListID uuid.UUID, status string, pickedAt, completedAt *time.Time) error
	AssignPicker(ctx context.Context, db DBTX, pickingListID, assignedTo uuid.UUID) error
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, limit, offset int) ([]*models.PickingList, int64, error)
	Delete(ctx context.Context, db DBTX, pickingListID uuid.UUID) error
}

type pickingListRepository struct {
	logger *zap.Logger
}

func NewPickingListRepository(logger *zap.Logger) PickingListRepository {
	return &pickingListRepository{
		logger: logger.Named("picking_list_repo"),
	}
}

func (r *pickingListRepository) scanPickingList(s scanner) (*models.PickingList, error) {
	var pl models.PickingList
	var assignedToUUID uuid.NullUUID
	var pickedAt, completedAt sql.NullTime

	err := s.Scan(
		&pl.PickingListID,
		&pl.CompanyID,
		&pl.FulfillmentOrderID,
		&pl.WarehouseID,
		&pl.Status,
		&assignedToUUID,
		&pl.CreatedAt,
		&pickedAt,
		&completedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan picking list: %w", err)
	}

	if assignedToUUID.Valid {
		pl.AssignedTo = &assignedToUUID.UUID
	}
	if pickedAt.Valid {
		pl.PickedAt = &pickedAt.Time
	}
	if completedAt.Valid {
		pl.CompletedAt = &completedAt.Time
	}

	return &pl, nil
}

func (r *pickingListRepository) Create(ctx context.Context, db DBTX, pickingList *models.PickingList) error {
	query := `
		INSERT INTO picking_lists (
			picking_list_id, company_id, fulfillment_order_id, warehouse_id,
			status, assigned_to, created_at, picked_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		pickingList.PickingListID,
		pickingList.CompanyID,
		pickingList.FulfillmentOrderID,
		pickingList.WarehouseID,
		pickingList.Status,
		pickingList.AssignedTo,
		pickingList.PickedAt,
		pickingList.CompletedAt,
	).Scan(&pickingList.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create picking list", util.ErrorField(err))
		return fmt.Errorf("create picking list: %w", err)
	}
	return nil
}

func (r *pickingListRepository) GetByID(ctx context.Context, db DBTX, pickingListID uuid.UUID) (*models.PickingList, error) {
	query := `
		SELECT picking_list_id, company_id, fulfillment_order_id, warehouse_id,
		       status, assigned_to, created_at, picked_at, completed_at
		FROM picking_lists
		WHERE picking_list_id = $1
	`
	row := db.QueryRowContext(ctx, query, pickingListID)
	return r.scanPickingList(row)
}

func (r *pickingListRepository) GetByFulfillmentOrder(ctx context.Context, db DBTX, fulfillmentOrderID uuid.UUID) ([]*models.PickingList, error) {
	query := `
		SELECT picking_list_id, company_id, fulfillment_order_id, warehouse_id,
		       status, assigned_to, created_at, picked_at, completed_at
		FROM picking_lists
		WHERE fulfillment_order_id = $1
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, fulfillmentOrderID)
	if err != nil {
		return nil, fmt.Errorf("get by fulfillment order: %w", err)
	}
	defer rows.Close()

	var result []*models.PickingList
	for rows.Next() {
		pl, err := r.scanPickingList(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, pl)
	}
	return result, rows.Err()
}

func (r *pickingListRepository) UpdateStatus(ctx context.Context, db DBTX, pickingListID uuid.UUID, status string, pickedAt, completedAt *time.Time) error {
	query := `
		UPDATE picking_lists
		SET status = $2, picked_at = $3, completed_at = $4
		WHERE picking_list_id = $1
	`
	res, err := db.ExecContext(ctx, query, pickingListID, status, pickedAt, completedAt)
	if err != nil {
		return fmt.Errorf("update picking list status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: picking list %s", inventory_errors.ErrNotFound, pickingListID)
	}
	return nil
}

func (r *pickingListRepository) AssignPicker(ctx context.Context, db DBTX, pickingListID, assignedTo uuid.UUID) error {
	query := `
		UPDATE picking_lists
		SET assigned_to = $2
		WHERE picking_list_id = $1
	`
	res, err := db.ExecContext(ctx, query, pickingListID, assignedTo)
	if err != nil {
		return fmt.Errorf("assign picker: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: picking list %s", inventory_errors.ErrNotFound, pickingListID)
	}
	return nil
}

func (r *pickingListRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, limit, offset int) ([]*models.PickingList, int64, error) {
	conds := []string{"company_id = $1"}
	args := []interface{}{companyID}
	idx := 2

	if status != nil && *status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *status)
		idx++
	}

	where := "WHERE " + strings.Join(conds, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM picking_lists %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count picking lists: %w", err)
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT picking_list_id, company_id, fulfillment_order_id, warehouse_id,
		       status, assigned_to, created_at, picked_at, completed_at
		FROM picking_lists
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list picking lists: %w", err)
	}
	defer rows.Close()

	var result []*models.PickingList
	for rows.Next() {
		pl, err := r.scanPickingList(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, pl)
	}
	return result, total, rows.Err()
}

func (r *pickingListRepository) Delete(ctx context.Context, db DBTX, pickingListID uuid.UUID) error {
	query := `DELETE FROM picking_lists WHERE picking_list_id = $1`
	res, err := db.ExecContext(ctx, query, pickingListID)
	if err != nil {
		return fmt.Errorf("delete picking list: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: picking list %s", inventory_errors.ErrNotFound, pickingListID)
	}
	return nil
}
