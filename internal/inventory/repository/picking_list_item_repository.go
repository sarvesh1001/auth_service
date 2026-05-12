package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

type PickingListItemRepository interface {
	Create(ctx context.Context, tx DBTX, item *models.PickingListItem) error
	BulkCreate(ctx context.Context, tx DBTX, items []*models.PickingListItem) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PickingListItem, error)
	GetByPickingList(ctx context.Context, db DBTX, pickingListID uuid.UUID) ([]*models.PickingListItem, error)
	UpdatePickedQty(ctx context.Context, tx DBTX, pickingItemID uuid.UUID, pickedQty decimal.Decimal) error
	Update(ctx context.Context, tx DBTX, item *models.PickingListItem) error
	DeleteByPickingList(ctx context.Context, tx DBTX, pickingListID uuid.UUID) error
	ListByFulfillmentItem(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID) ([]*models.PickingListItem, error)
}

type pickingListItemRepository struct {
	logger *zap.Logger
}

func NewPickingListItemRepository(logger *zap.Logger) PickingListItemRepository {
	return &pickingListItemRepository{
		logger: logger.Named("picking_list_item_repo"),
	}
}

func (r *pickingListItemRepository) scanItem(sc scanner) (*models.PickingListItem, error) {
	var item models.PickingListItem
	err := sc.Scan(
		&item.PickingItemID,
		&item.PickingListID,
		&item.FulfillmentItemID,
		&item.OrderedQty,
		&item.PickedQty,
		&item.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan picking list item: %w", err)
	}
	return &item, nil
}

func (r *pickingListItemRepository) Create(ctx context.Context, tx DBTX, item *models.PickingListItem) error {
	query := `
		INSERT INTO picking_list_items (
			picking_item_id, picking_list_id, fulfillment_item_id,
			ordered_qty, picked_qty, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING created_at
	`
	err := tx.QueryRowContext(ctx, query,
		item.PickingItemID, item.PickingListID, item.FulfillmentItemID,
		item.OrderedQty, item.PickedQty,
	).Scan(&item.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create picking list item", util.ErrorField(err))
		return fmt.Errorf("create picking list item: %w", err)
	}
	return nil
}

func (r *pickingListItemRepository) BulkCreate(ctx context.Context, tx DBTX, items []*models.PickingListItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO picking_list_items (
			picking_item_id, picking_list_id, fulfillment_item_id,
			ordered_qty, picked_qty, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
	`
	for _, it := range items {
		_, err := tx.ExecContext(ctx, query,
			it.PickingItemID, it.PickingListID, it.FulfillmentItemID,
			it.OrderedQty, it.PickedQty,
		)
		if err != nil {
			return fmt.Errorf("bulk create picking list item: %w", err)
		}
	}
	return nil
}

func (r *pickingListItemRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PickingListItem, error) {
	query := `
		SELECT picking_item_id, picking_list_id, fulfillment_item_id,
		       ordered_qty, picked_qty, created_at
		FROM picking_list_items WHERE picking_item_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanItem(row)
}

func (r *pickingListItemRepository) GetByPickingList(ctx context.Context, db DBTX, pickingListID uuid.UUID) ([]*models.PickingListItem, error) {
	query := `
		SELECT picking_item_id, picking_list_id, fulfillment_item_id,
		       ordered_qty, picked_qty, created_at
		FROM picking_list_items WHERE picking_list_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, pickingListID)
	if err != nil {
		return nil, fmt.Errorf("get by picking list: %w", err)
	}
	defer rows.Close()

	var result []*models.PickingListItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *pickingListItemRepository) UpdatePickedQty(ctx context.Context, tx DBTX, pickingItemID uuid.UUID, pickedQty decimal.Decimal) error {
	query := `
		UPDATE picking_list_items
		SET picked_qty = $2
		WHERE picking_item_id = $1
	`
	result, err := tx.ExecContext(ctx, query, pickingItemID, pickedQty)
	if err != nil {
		return fmt.Errorf("update picked quantity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: picking item %s", inventory_errors.ErrNotFound, pickingItemID)
	}
	return nil
}

func (r *pickingListItemRepository) Update(ctx context.Context, tx DBTX, item *models.PickingListItem) error {
	query := `
		UPDATE picking_list_items
		SET ordered_qty = $2, picked_qty = $3
		WHERE picking_item_id = $1
	`
	_, err := tx.ExecContext(ctx, query, item.PickingItemID, item.OrderedQty, item.PickedQty)
	if err != nil {
		return fmt.Errorf("update picking list item: %w", err)
	}
	return nil
}

func (r *pickingListItemRepository) DeleteByPickingList(ctx context.Context, tx DBTX, pickingListID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM picking_list_items WHERE picking_list_id = $1`, pickingListID)
	if err != nil {
		return fmt.Errorf("delete by picking list: %w", err)
	}
	return nil
}

func (r *pickingListItemRepository) ListByFulfillmentItem(ctx context.Context, db DBTX, fulfillmentItemID uuid.UUID) ([]*models.PickingListItem, error) {
	query := `
		SELECT picking_item_id, picking_list_id, fulfillment_item_id,
		       ordered_qty, picked_qty, created_at
		FROM picking_list_items WHERE fulfillment_item_id = $1
	`
	rows, err := db.QueryContext(ctx, query, fulfillmentItemID)
	if err != nil {
		return nil, fmt.Errorf("list by fulfillment item: %w", err)
	}
	defer rows.Close()

	var result []*models.PickingListItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
