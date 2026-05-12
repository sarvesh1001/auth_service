package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

type PackingListItemRepository interface {
	Create(ctx context.Context, db DBTX, item *models.PackingListItem) error
	BulkCreate(ctx context.Context, db DBTX, items []*models.PackingListItem) error
	GetByPackingList(ctx context.Context, db DBTX, packingListID uuid.UUID) ([]*models.PackingListItem, error)
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PackingListItem, error)
	UpdatePackedQty(ctx context.Context, db DBTX, id uuid.UUID, packedQty decimal.Decimal) error
	DeleteByPackingList(ctx context.Context, db DBTX, packingListID uuid.UUID) error
}

type packingListItemRepository struct {
	logger *zap.Logger
}

func NewPackingListItemRepository(logger *zap.Logger) PackingListItemRepository {
	return &packingListItemRepository{
		logger: logger.Named("packing_list_item_repo"),
	}
}

func (r *packingListItemRepository) scanPackingListItem(s scanner) (*models.PackingListItem, error) {
	var item models.PackingListItem
	var createdAt time.Time

	err := s.Scan(
		&item.PackingItemID,
		&item.PackingListID,
		&item.ShipmentItemID,
		&item.PackedQty,
		&createdAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan packing list item: %w", err)
	}
	item.CreatedAt = createdAt
	return &item, nil
}

func (r *packingListItemRepository) Create(ctx context.Context, db DBTX, item *models.PackingListItem) error {
	query := `
		INSERT INTO packing_list_items (
			packing_item_id, packing_list_id, shipment_item_id, packed_qty, created_at
		) VALUES ($1, $2, $3, $4, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		item.PackingItemID, item.PackingListID, item.ShipmentItemID, item.PackedQty,
	)
	if err != nil {
		r.logger.Error("failed to create packing list item", util.ErrorField(err))
		return fmt.Errorf("create packing list item: %w", err)
	}
	return nil
}

func (r *packingListItemRepository) BulkCreate(ctx context.Context, db DBTX, items []*models.PackingListItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO packing_list_items (
			packing_item_id, packing_list_id, shipment_item_id, packed_qty, created_at
		) VALUES ($1, $2, $3, $4, NOW())
	`
	for _, it := range items {
		_, err := db.ExecContext(ctx, query,
			it.PackingItemID, it.PackingListID, it.ShipmentItemID, it.PackedQty,
		)
		if err != nil {
			return fmt.Errorf("bulk create packing list item: %w", err)
		}
	}
	return nil
}

func (r *packingListItemRepository) GetByPackingList(ctx context.Context, db DBTX, packingListID uuid.UUID) ([]*models.PackingListItem, error) {
	query := `
		SELECT packing_item_id, packing_list_id, shipment_item_id, packed_qty, created_at
		FROM packing_list_items
		WHERE packing_list_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, packingListID)
	if err != nil {
		return nil, fmt.Errorf("get by packing list: %w", err)
	}
	defer rows.Close()

	var result []*models.PackingListItem
	for rows.Next() {
		it, err := r.scanPackingListItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, it)
	}
	return result, rows.Err()
}

func (r *packingListItemRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PackingListItem, error) {
	query := `
		SELECT packing_item_id, packing_list_id, shipment_item_id, packed_qty, created_at
		FROM packing_list_items
		WHERE packing_item_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanPackingListItem(row)
}

func (r *packingListItemRepository) UpdatePackedQty(ctx context.Context, db DBTX, id uuid.UUID, packedQty decimal.Decimal) error {
	query := `
		UPDATE packing_list_items
		SET packed_qty = $2
		WHERE packing_item_id = $1
	`
	res, err := db.ExecContext(ctx, query, id, packedQty)
	if err != nil {
		return fmt.Errorf("update packed qty: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: packing list item %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *packingListItemRepository) DeleteByPackingList(ctx context.Context, db DBTX, packingListID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM packing_list_items WHERE packing_list_id = $1`, packingListID)
	if err != nil {
		return fmt.Errorf("delete by packing list: %w", err)
	}
	return nil
}
