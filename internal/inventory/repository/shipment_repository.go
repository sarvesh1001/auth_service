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

type ShipmentRepository interface {
	Create(ctx context.Context, db DBTX, shipment *models.Shipment) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Shipment, error)
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, shippedAt, deliveredAt *time.Time) error
	GetByFulfillmentOrder(ctx context.Context, db DBTX, fulfillmentOrderID uuid.UUID) ([]*models.Shipment, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, p Pagination, s Sort) ([]*models.Shipment, int64, error)
	ExistsByShipmentNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error)
}

type shipmentRepository struct {
	logger *zap.Logger
}

func NewShipmentRepository(logger *zap.Logger) ShipmentRepository {
	return &shipmentRepository{
		logger: logger.Named("shipment_repo"),
	}
}

func (r *shipmentRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *shipmentRepository) validatePagination(p Pagination) (int, int) {
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

func (r *shipmentRepository) scanShipment(s scanner) (*models.Shipment, error) {
	var sh models.Shipment
	var shippedAt, deliveredAt sql.NullTime

	err := s.Scan(
		&sh.ShipmentID,
		&sh.CompanyID,
		&sh.FulfillmentOrderID,
		&sh.WarehouseID,
		&sh.ShipmentNumber,
		&sh.ShipmentStatus,
		&shippedAt,
		&deliveredAt,
		&sh.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan shipment: %w", err)
	}
	if shippedAt.Valid {
		sh.ShippedAt = &shippedAt.Time
	}
	if deliveredAt.Valid {
		sh.DeliveredAt = &deliveredAt.Time
	}
	return &sh, nil
}

func (r *shipmentRepository) Create(ctx context.Context, db DBTX, shipment *models.Shipment) error {
	query := `
		INSERT INTO shipments (
			shipment_id, company_id, fulfillment_order_id, warehouse_id, shipment_number,
			shipment_status, shipped_at, delivered_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		shipment.ShipmentID, shipment.CompanyID, shipment.FulfillmentOrderID, shipment.WarehouseID,
		shipment.ShipmentNumber, shipment.ShipmentStatus, shipment.ShippedAt, shipment.DeliveredAt,
	).Scan(&shipment.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create shipment", util.ErrorField(err))
		return fmt.Errorf("create shipment: %w", err)
	}
	return nil
}

func (r *shipmentRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Shipment, error) {
	query := `
		SELECT shipment_id, company_id, fulfillment_order_id, warehouse_id, shipment_number,
		       shipment_status, shipped_at, delivered_at, created_at
		FROM shipments
		WHERE shipment_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanShipment(row)
}

func (r *shipmentRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, shippedAt, deliveredAt *time.Time) error {
	query := `
		UPDATE shipments
		SET shipment_status = $2, shipped_at = $3, delivered_at = $4
		WHERE shipment_id = $1
	`
	res, err := db.ExecContext(ctx, query, id, status, shippedAt, deliveredAt)
	if err != nil {
		return fmt.Errorf("update shipment status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: shipment %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *shipmentRepository) GetByFulfillmentOrder(ctx context.Context, db DBTX, fulfillmentOrderID uuid.UUID) ([]*models.Shipment, error) {
	query := `
		SELECT shipment_id, company_id, fulfillment_order_id, warehouse_id, shipment_number,
		       shipment_status, shipped_at, delivered_at, created_at
		FROM shipments
		WHERE fulfillment_order_id = $1
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, fulfillmentOrderID)
	if err != nil {
		return nil, fmt.Errorf("get by fulfillment order: %w", err)
	}
	defer rows.Close()

	var result []*models.Shipment
	for rows.Next() {
		sh, err := r.scanShipment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, sh)
	}
	return result, rows.Err()
}

func (r *shipmentRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, status *string, p Pagination, s Sort) ([]*models.Shipment, int64, error) {
	conds := []string{"company_id = $1"}
	args := []interface{}{companyID}
	idx := 2

	if status != nil {
		conds = append(conds, fmt.Sprintf("shipment_status = $%d", idx))
		args = append(args, *status)
		idx++
	}

	where := fmt.Sprintf("WHERE %s", strings.Join(conds, " AND "))

	allowedSort := map[string]bool{"created_at": true, "shipment_status": true, "shipped_at": true}
	orderBy, _ := r.validateSort(s, allowedSort)
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM shipments %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count shipments: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT shipment_id, company_id, fulfillment_order_id, warehouse_id, shipment_number,
		       shipment_status, shipped_at, delivered_at, created_at
		FROM shipments
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list shipments: %w", err)
	}
	defer rows.Close()

	var result []*models.Shipment
	for rows.Next() {
		sh, err := r.scanShipment(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, sh)
	}
	return result, total, rows.Err()
}

func (r *shipmentRepository) ExistsByShipmentNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM shipments WHERE company_id = $1 AND shipment_number = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, number).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check shipment number exists: %w", err)
	}
	return exists, nil
}
