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

// ReservationFilter – flexible query conditions
type ReservationFilter struct {
	CompanyID       uuid.UUID
	ReservationType string
	ReferenceID     *uuid.UUID
	WarehouseID     *uuid.UUID
	ItemID          *uuid.UUID
	BatchID         *uuid.UUID
	Status          string // active, partially_fulfilled, fulfilled, cancelled, expired
	CreatedFrom     *time.Time
	CreatedTo       *time.Time
}

// ReservationRepository interface – state‑driven, stock‑aware, safe for concurrency
type ReservationRepository interface {
	// Core state changes
	Create(ctx context.Context, db DBTX, res *models.Reservation) error
	BulkCreate(ctx context.Context, db DBTX, reservations []*models.Reservation) error
	Fulfill(ctx context.Context, db DBTX, reservationID uuid.UUID, fulfilledAt time.Time) error
	UpdateFulfilledQuantity(ctx context.Context, db DBTX, reservationID uuid.UUID, additionalFulfilledQty decimal.Decimal) error
	Cancel(ctx context.Context, db DBTX, reservationID uuid.UUID, cancelledAt time.Time) error
	Expire(ctx context.Context, db DBTX, now time.Time) (int64, error)

	// Fetching
	GetByID(ctx context.Context, db DBTX, reservationID uuid.UUID) (*models.Reservation, error)
	GetByReference(ctx context.Context, db DBTX, referenceType string, referenceID uuid.UUID) ([]*models.Reservation, error)
	GetActiveByItemWarehouse(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) ([]*models.Reservation, error)
	List(ctx context.Context, db DBTX, filter ReservationFilter, p Pagination, s Sort) ([]*models.Reservation, error)
	Count(ctx context.Context, db DBTX, filter ReservationFilter) (int64, error)
	GetActiveByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reservationType string, referenceID uuid.UUID) (*models.Reservation, error)

	// Stock‑aware helpers
	GetReservedQuantity(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error)
	GetAvailableToReserve(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error)
	GetExpiredActive(ctx context.Context, db DBTX, companyID uuid.UUID, now time.Time) ([]*models.Reservation, error)

	// Row‑level locking (critical for concurrency)
	GetForUpdate(ctx context.Context, db DBTX, reservationID uuid.UUID) (*models.Reservation, error)
	GetActiveForUpdateByItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) ([]*models.Reservation, error)
}

type reservationRepository struct {
	logger *zap.Logger
}

func NewReservationRepository(logger *zap.Logger) ReservationRepository {
	return &reservationRepository{
		logger: logger.Named("reservation_repo"),
	}
}

// ---------- helpers ----------

func (r *reservationRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *reservationRepository) validatePagination(p Pagination) (int, int) {
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

func (r *reservationRepository) buildReservationFilter(filter ReservationFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ReservationType != "" {
		conds = append(conds, fmt.Sprintf("reservation_type = $%d", idx))
		args = append(args, filter.ReservationType)
		idx++
	}
	if filter.ReferenceID != nil {
		conds = append(conds, fmt.Sprintf("reference_id = $%d", idx))
		args = append(args, *filter.ReferenceID)
		idx++
	}
	if filter.WarehouseID != nil {
		conds = append(conds, fmt.Sprintf("warehouse_id = $%d", idx))
		args = append(args, *filter.WarehouseID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.BatchID != nil {
		conds = append(conds, fmt.Sprintf("batch_id = $%d", idx))
		args = append(args, *filter.BatchID)
		idx++
	}
	if filter.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
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

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- scanner (includes fulfilled_quantity) ----------
func (r *reservationRepository) scanReservation(s scanner) (*models.Reservation, error) {
	var res models.Reservation
	var batchID uuid.NullUUID
	var expiresAt, fulfilledAt, cancelledAt sql.NullTime
	var createdBy uuid.NullUUID
	var fulfilledQuantity decimal.Decimal

	err := s.Scan(
		&res.ReservationID,
		&res.CompanyID,
		&res.ReservationType,
		&res.ReferenceID,
		&res.WarehouseID,
		&res.ItemID,
		&batchID,
		&res.Quantity,
		&res.Status,
		&res.CreatedAt,
		&expiresAt,
		&createdBy,
		&fulfilledAt,
		&cancelledAt,
		&fulfilledQuantity,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan reservation: %w", err)
	}

	if batchID.Valid {
		res.BatchID = &batchID.UUID
	}
	if expiresAt.Valid {
		res.ExpiresAt = &expiresAt.Time
	}
	if fulfilledAt.Valid {
		res.FulfilledAt = &fulfilledAt.Time
	}
	if cancelledAt.Valid {
		res.CancelledAt = &cancelledAt.Time
	}
	if createdBy.Valid {
		res.CreatedBy = &createdBy.UUID
	}
	res.FulfilledQuantity = fulfilledQuantity

	return &res, nil
}

// ---------- Core state changes ----------

func (r *reservationRepository) Create(ctx context.Context, db DBTX, res *models.Reservation) error {
	query := `
		INSERT INTO reservations (
			reservation_id, company_id, reservation_type, reference_id,
			warehouse_id, item_id, batch_id, quantity, status,
			created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12, $13, $14)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		res.ReservationID, res.CompanyID, res.ReservationType, res.ReferenceID,
		res.WarehouseID, res.ItemID, res.BatchID, res.Quantity, res.Status,
		res.ExpiresAt, res.CreatedBy, res.FulfilledAt, res.CancelledAt, res.FulfilledQuantity,
	).Scan(&res.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create reservation", util.ErrorField(err))
		return fmt.Errorf("create reservation: %w", err)
	}
	return nil
}

func (r *reservationRepository) BulkCreate(ctx context.Context, db DBTX, reservations []*models.Reservation) error {
	if len(reservations) == 0 {
		return nil
	}
	query := `
		INSERT INTO reservations (
			reservation_id, company_id, reservation_type, reference_id,
			warehouse_id, item_id, batch_id, quantity, status,
			created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12, $13, $14)
		RETURNING created_at
	`
	for _, res := range reservations {
		err := db.QueryRowContext(ctx, query,
			res.ReservationID, res.CompanyID, res.ReservationType, res.ReferenceID,
			res.WarehouseID, res.ItemID, res.BatchID, res.Quantity, res.Status,
			res.ExpiresAt, res.CreatedBy, res.FulfilledAt, res.CancelledAt, res.FulfilledQuantity,
		).Scan(&res.CreatedAt)
		if err != nil {
			return fmt.Errorf("bulk create reservation: %w", err)
		}
	}
	return nil
}

// Fulfill marks an active reservation as fully fulfilled.
func (r *reservationRepository) Fulfill(ctx context.Context, db DBTX, reservationID uuid.UUID, fulfilledAt time.Time) error {
	query := `
		UPDATE reservations
		SET status = 'fulfilled', fulfilled_at = $2, fulfilled_quantity = quantity
		WHERE reservation_id = $1 AND status = 'active'
	`
	result, err := db.ExecContext(ctx, query, reservationID, fulfilledAt)
	if err != nil {
		return fmt.Errorf("fulfill reservation: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("fulfill reservation: could not get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: reservation %s not active", inventory_errors.ErrNotFound, reservationID)
	}
	return nil
}

// UpdateFulfilledQuantity increments the fulfilled quantity and updates status to 'partially_fulfilled' or 'fulfilled' as appropriate.
// Fixed: uses separate placeholders for SET status and CASE condition to avoid PostgreSQL type mismatch.
func (r *reservationRepository) UpdateFulfilledQuantity(ctx context.Context, db DBTX, reservationID uuid.UUID, additionalFulfilledQty decimal.Decimal) error {
	// First get current reservation with lock
	res, err := r.GetForUpdate(ctx, db, reservationID)
	if err != nil {
		return err
	}
	if res.Status != "active" && res.Status != "partially_fulfilled" {
		return fmt.Errorf("cannot fulfill reservation in status %s", res.Status)
	}

	newFulfilled := res.FulfilledQuantity.Add(additionalFulfilledQty)
	newStatus := "partially_fulfilled"
	if newFulfilled.GreaterThanOrEqual(res.Quantity) {
		newStatus = "fulfilled"
		newFulfilled = res.Quantity // cap at original quantity
	}

	// NOTE: $3 is used for the SET status, $4 for the CASE condition – same value but separate placeholder
	query := `
		UPDATE reservations
		SET fulfilled_quantity = $2, status = $3, fulfilled_at = CASE WHEN $4 = 'fulfilled' THEN NOW() ELSE fulfilled_at END
		WHERE reservation_id = $1
	`
	_, err = db.ExecContext(ctx, query, reservationID, newFulfilled, newStatus, newStatus)
	if err != nil {
		return fmt.Errorf("update fulfilled quantity: %w", err)
	}
	return nil
}

// Cancel marks an active or partially_fulfilled reservation as cancelled.
func (r *reservationRepository) Cancel(ctx context.Context, db DBTX, reservationID uuid.UUID, cancelledAt time.Time) error {
	query := `
		UPDATE reservations
		SET status = 'cancelled', cancelled_at = $2
		WHERE reservation_id = $1 AND status IN ('active', 'partially_fulfilled')
	`
	result, err := db.ExecContext(ctx, query, reservationID, cancelledAt)
	if err != nil {
		return fmt.Errorf("cancel reservation: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cancel reservation: could not get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: reservation %s not active or partially_fulfilled", inventory_errors.ErrNotFound, reservationID)
	}
	return nil
}

// Expire cancels all active reservations whose expires_at < now, setting status to 'expired'.
func (r *reservationRepository) Expire(ctx context.Context, db DBTX, now time.Time) (int64, error) {
	query := `
		UPDATE reservations
		SET status = 'expired', cancelled_at = $1
		WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < $1
	`
	result, err := db.ExecContext(ctx, query, now)
	if err != nil {
		return 0, fmt.Errorf("expire reservations: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expire reservations: could not get rows affected: %w", err)
	}
	return count, nil
}

// ---------- Fetching (updated SELECTs to include fulfilled_quantity) ----------

func (r *reservationRepository) GetByID(ctx context.Context, db DBTX, reservationID uuid.UUID) (*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations WHERE reservation_id = $1
	`
	row := db.QueryRowContext(ctx, query, reservationID)
	return r.scanReservation(row)
}

func (r *reservationRepository) GetByReference(ctx context.Context, db DBTX, referenceType string, referenceID uuid.UUID) ([]*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE reservation_type = $1 AND reference_id = $2
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, referenceType, referenceID)
	if err != nil {
		return nil, fmt.Errorf("get by reference: %w", err)
	}
	defer rows.Close()

	var result []*models.Reservation
	for rows.Next() {
		res, err := r.scanReservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, rows.Err()
}

func (r *reservationRepository) GetActiveByItemWarehouse(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) ([]*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE company_id = $1 AND item_id = $2 AND warehouse_id = $3 AND status IN ('active', 'partially_fulfilled')
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get active by item/warehouse: %w", err)
	}
	defer rows.Close()

	var result []*models.Reservation
	for rows.Next() {
		res, err := r.scanReservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, rows.Err()
}

func (r *reservationRepository) List(ctx context.Context, db DBTX, filter ReservationFilter, p Pagination, s Sort) ([]*models.Reservation, error) {
	where, args := r.buildReservationFilter(filter)

	allowedSort := map[string]bool{
		"created_at":     true,
		"reservation_id": true,
		"status":         true,
		"expires_at":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list reservations: %w", err)
	}
	defer rows.Close()

	var result []*models.Reservation
	for rows.Next() {
		res, err := r.scanReservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, rows.Err()
}

func (r *reservationRepository) Count(ctx context.Context, db DBTX, filter ReservationFilter) (int64, error) {
	where, args := r.buildReservationFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM reservations %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count reservations: %w", err)
	}
	return count, nil
}

// ---------- Stock‑aware helpers (unchanged logic, but statuses updated) ----------

func (r *reservationRepository) GetReservedQuantity(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error) {
	// Active and partially_fulfilled reservations still hold reserved quantity.
	query := `
		SELECT COALESCE(SUM(quantity - fulfilled_quantity), 0)
		FROM reservations
		WHERE company_id = $1
		  AND item_id = $2
		  AND warehouse_id = $3
		  AND status IN ('active', 'partially_fulfilled')
		  AND ($4::uuid IS NULL OR batch_id = $4)
	`
	var total float64
	err := db.QueryRowContext(ctx, query, companyID, itemID, warehouseID, batchID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get reserved quantity: %w", err)
	}
	return decimal.NewFromFloat(total), nil
}

func (r *reservationRepository) GetAvailableToReserve(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error) {
	// Available = stock_on_hand - reserved_qty - (open reservation quantities)
	query := `
		SELECT COALESCE(
			(SELECT available_qty FROM stock_balances
			 WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3 AND ($4::uuid IS NULL OR batch_id = $4)
			 LIMIT 1), 0
		) - COALESCE(
			(SELECT COALESCE(SUM(quantity - fulfilled_quantity), 0) FROM reservations
			 WHERE company_id = $1 AND item_id = $3 AND warehouse_id = $2 AND status IN ('active', 'partially_fulfilled')
			   AND ($4::uuid IS NULL OR batch_id = $4)), 0
		) AS available
	`
	var available float64
	err := db.QueryRowContext(ctx, query, companyID, warehouseID, itemID, batchID).Scan(&available)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get available to reserve: %w", err)
	}
	return decimal.NewFromFloat(available), nil
}

// ---------- Row‑level locking (updated SELECTs) ----------

func (r *reservationRepository) GetForUpdate(ctx context.Context, db DBTX, reservationID uuid.UUID) (*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE reservation_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, reservationID)
	return r.scanReservation(row)
}

func (r *reservationRepository) GetActiveForUpdateByItem(ctx context.Context, db DBTX, companyID, itemID, warehouseID uuid.UUID) ([]*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE company_id = $1
		  AND item_id = $2
		  AND warehouse_id = $3
		  AND status IN ('active', 'partially_fulfilled')
		ORDER BY created_at ASC
		FOR UPDATE
	`
	rows, err := db.QueryContext(ctx, query, companyID, itemID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get active for update by item: %w", err)
	}
	defer rows.Close()

	var result []*models.Reservation
	for rows.Next() {
		res, err := r.scanReservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, rows.Err()
}

func (r *reservationRepository) GetExpiredActive(ctx context.Context, db DBTX, companyID uuid.UUID, now time.Time) ([]*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE company_id = $1 AND status = 'active' AND expires_at IS NOT NULL AND expires_at < $2
		FOR UPDATE
	`
	rows, err := db.QueryContext(ctx, query, companyID, now)
	if err != nil {
		return nil, fmt.Errorf("get expired active: %w", err)
	}
	defer rows.Close()
	var result []*models.Reservation
	for rows.Next() {
		res, err := r.scanReservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, rows.Err()
}

func (r *reservationRepository) GetActiveByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reservationType string, referenceID uuid.UUID) (*models.Reservation, error) {
	query := `
		SELECT reservation_id, company_id, reservation_type, reference_id,
		       warehouse_id, item_id, batch_id, quantity, status,
		       created_at, expires_at, created_by, fulfilled_at, cancelled_at, fulfilled_quantity
		FROM reservations
		WHERE company_id = $1 AND reservation_type = $2 AND reference_id = $3 AND status IN ('active', 'partially_fulfilled')
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, reservationType, referenceID)
	return r.scanReservation(row)
}
