package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PackingListRepository interface {
	Create(ctx context.Context, db DBTX, list *models.PackingList) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PackingList, error)
	GetByShipment(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.PackingList, error)
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, packedAt, verifiedAt *time.Time) error
	CompletePacking(ctx context.Context, db DBTX, id uuid.UUID, completedAt time.Time) error // <-- NEW
	VerifyPacking(ctx context.Context, db DBTX, id uuid.UUID, verifiedBy *uuid.UUID, verifiedAt time.Time) error
	List(ctx context.Context, db DBTX, filter PackingListFilter, p Pagination, s Sort) ([]*models.PackingList, int64, error)
	UpdateStatusToPacked(ctx context.Context, tx *sql.Tx, packingListID uuid.UUID, packedBy *uuid.UUID, packedAt time.Time) error
}

type PackingListFilter struct {
	CompanyID  uuid.UUID
	ShipmentID *uuid.UUID
	Status     *string
	PackedBy   *uuid.UUID
	DateFrom   *time.Time
	DateTo     *time.Time
}

type packingListRepository struct {
	logger *zap.Logger
}

func NewPackingListRepository(logger *zap.Logger) PackingListRepository {
	return &packingListRepository{
		logger: logger.Named("packing_list_repo"),
	}
}

func (r *packingListRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *packingListRepository) validatePagination(p Pagination) (int, int) {
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

func (r *packingListRepository) buildFilter(filter PackingListFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ShipmentID != nil {
		conds = append(conds, fmt.Sprintf("shipment_id = $%d", idx))
		args = append(args, *filter.ShipmentID)
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.PackedBy != nil {
		conds = append(conds, fmt.Sprintf("packed_by = $%d", idx))
		args = append(args, *filter.PackedBy)
		idx++
	}
	if filter.DateFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *packingListRepository) scanPackingList(s scanner) (*models.PackingList, error) {
	var pl models.PackingList
	var packedBy uuid.NullUUID
	var packedAt, verifiedAt, completedAt sql.NullTime
	var createdAt time.Time

	err := s.Scan(
		&pl.PackingListID,
		&pl.CompanyID,
		&pl.ShipmentID,
		&pl.Status,
		&packedBy,
		&createdAt,
		&packedAt,
		&verifiedAt,
		&completedAt, // <-- NEW
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan packing list: %w", err)
	}
	pl.CreatedAt = createdAt
	if packedBy.Valid {
		pl.PackedBy = &packedBy.UUID
	}
	if packedAt.Valid {
		pl.PackedAt = &packedAt.Time
	}
	if verifiedAt.Valid {
		pl.VerifiedAt = &verifiedAt.Time
	}
	if completedAt.Valid {
		pl.CompletedAt = &completedAt.Time
	}
	return &pl, nil
}

func (r *packingListRepository) Create(ctx context.Context, db DBTX, list *models.PackingList) error {
	query := `
		INSERT INTO packing_lists (
			packing_list_id, company_id, shipment_id, status, packed_by,
			created_at, packed_at, verified_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		list.PackingListID, list.CompanyID, list.ShipmentID,
		list.Status, list.PackedBy, list.PackedAt, list.VerifiedAt, list.CompletedAt,
	).Scan(&list.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create packing list", util.ErrorField(err))
		return fmt.Errorf("create packing list: %w", err)
	}
	return nil
}

func (r *packingListRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.PackingList, error) {
	query := `
		SELECT packing_list_id, company_id, shipment_id, status, packed_by,
		       created_at, packed_at, verified_at, completed_at
		FROM packing_lists
		WHERE packing_list_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanPackingList(row)
}

func (r *packingListRepository) GetByShipment(ctx context.Context, db DBTX, shipmentID uuid.UUID) ([]*models.PackingList, error) {
	filter := PackingListFilter{
		ShipmentID: &shipmentID,
	}
	lists, _, err := r.List(ctx, db, filter, Pagination{Limit: 100}, Sort{Field: "created_at", Direction: "DESC"})
	return lists, err
}

func (r *packingListRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, packedAt, verifiedAt *time.Time) error {
	query := `
		UPDATE packing_lists
		SET status = $2, packed_at = $3, verified_at = $4
		WHERE packing_list_id = $1
	`
	res, err := db.ExecContext(ctx, query, id, status, packedAt, verifiedAt)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: packing list %s", inventory_errors.ErrNotFound, id)
	}
	return nil
}

// CompletePacking marks packing list as completed and sets completed_at.
func (r *packingListRepository) CompletePacking(ctx context.Context, db DBTX, id uuid.UUID, completedAt time.Time) error {
	query := `
		UPDATE packing_lists
		SET status = 'completed', completed_at = $2
		WHERE packing_list_id = $1 AND status = 'verified'
	`
	res, err := db.ExecContext(ctx, query, id, completedAt)
	if err != nil {
		return fmt.Errorf("complete packing: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: packing list %s not in 'verified' state", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *packingListRepository) VerifyPacking(ctx context.Context, db DBTX, id uuid.UUID, verifiedBy *uuid.UUID, verifiedAt time.Time) error {
	query := `
		UPDATE packing_lists
		SET status = 'verified', verified_at = $2, packed_by = $3
		WHERE packing_list_id = $1 AND status = 'packed'
	`
	res, err := db.ExecContext(ctx, query, id, verifiedAt, verifiedBy)
	if err != nil {
		return fmt.Errorf("verify packing: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: packing list %s not in 'packed' state", inventory_errors.ErrNotFound, id)
	}
	return nil
}

func (r *packingListRepository) List(ctx context.Context, db DBTX, filter PackingListFilter, p Pagination, s Sort) ([]*models.PackingList, int64, error) {
	where, args := r.buildFilter(filter)
	allowedSort := map[string]bool{
		"created_at":   true,
		"status":       true,
		"packed_at":    true,
		"verified_at":  true,
		"completed_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM packing_lists %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count packing lists: %w", err)
	}
	if total == 0 {
		return []*models.PackingList{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT packing_list_id, company_id, shipment_id, status, packed_by,
		       created_at, packed_at, verified_at, completed_at
		FROM packing_lists
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list packing lists: %w", err)
	}
	defer rows.Close()

	var result []*models.PackingList
	for rows.Next() {
		pl, err := r.scanPackingList(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, pl)
	}
	return result, total, rows.Err()
}

// UpdateStatusToPacked updates the packing list status to 'packed', sets packed_at and packed_by.
func (r *packingListRepository) UpdateStatusToPacked(ctx context.Context, tx *sql.Tx, packingListID uuid.UUID, packedBy *uuid.UUID, packedAt time.Time) error {
	query := `
        UPDATE packing_lists
        SET status = 'packed', packed_at = $1, packed_by = $2
        WHERE packing_list_id = $3
    `
	_, err := tx.ExecContext(ctx, query, packedAt, packedBy, packingListID)
	if err != nil {
		return fmt.Errorf("update packing list to packed: %w", err)
	}
	return nil
}
