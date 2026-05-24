package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type DiscountPriorityRepository interface {
	GetPriority(ctx context.Context, db DBTX, companyID uuid.UUID, discountType string, discountID *uuid.UUID) (int, error)
	SetPriority(ctx context.Context, db DBTX, priority *discount.DiscountPriority) error
	DeletePriority(ctx context.Context, db DBTX, companyID, priorityID uuid.UUID) error
	List(ctx context.Context, db DBTX, filter DiscountPriorityFilter, p Pagination, s Sort) ([]*discount.DiscountPriority, int64, error)
	Exists(ctx context.Context, db DBTX, companyID, priorityID uuid.UUID) (bool, error)
}

type DiscountPriorityFilter struct {
	CompanyID    uuid.UUID
	DiscountType *string
	DiscountID   *uuid.UUID
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type discountPriorityRepository struct {
	logger *zap.Logger
}

func NewDiscountPriorityRepository(logger *zap.Logger) DiscountPriorityRepository {
	return &discountPriorityRepository{
		logger: logger.Named("sales_discount_priority_repo"),
	}
}

// Helpers

func (r *discountPriorityRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *discountPriorityRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *discountPriorityRepository) validatePagination(p Pagination) (int, int) {
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

func (r *discountPriorityRepository) buildFilter(filter DiscountPriorityFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.DiscountType != nil {
		conds = append(conds, fmt.Sprintf("discount_type = $%d", idx))
		args = append(args, *filter.DiscountType)
		idx++
	}
	if filter.DiscountID != nil {
		conds = append(conds, fmt.Sprintf("discount_id = $%d", idx))
		args = append(args, *filter.DiscountID)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *discountPriorityRepository) scanPriority(s scanner) (*discount.DiscountPriority, error) {
	var p discount.DiscountPriority
	var discountID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&p.PriorityID,
		&p.CompanyID,
		&p.DiscountType,
		&discountID,
		&p.Priority,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan discount priority: %w", err)
	}
	if discountID.Valid {
		p.DiscountID = &discountID.UUID
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
// Business logic
// -------------------------------------------------------------------------

func (r *discountPriorityRepository) GetPriority(ctx context.Context, db DBTX, companyID uuid.UUID, discountType string, discountID *uuid.UUID) (int, error) {
	query := `
		SELECT priority
		FROM sales.discount_priorities
		WHERE company_id = $1 AND discount_type = $2 AND (discount_id = $3 OR discount_id IS NULL)
		ORDER BY discount_id NULLS LAST
		LIMIT 1
	`
	var priority int
	err := db.QueryRowContext(ctx, query, companyID, discountType, r.nullUUIDParam(discountID)).Scan(&priority)
	if err != nil {
		if err == sql.ErrNoRows {
			// Default priority: 100 (lowest)
			return 100, nil
		}
		return 0, fmt.Errorf("get priority: %w", err)
	}
	return priority, nil
}

func (r *discountPriorityRepository) SetPriority(ctx context.Context, db DBTX, priority *discount.DiscountPriority) error {
	// Upsert: if exists, update; else insert.
	query := `
		INSERT INTO sales.discount_priorities (priority_id, company_id, discount_type, discount_id, priority, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), $6, $7)
		ON CONFLICT (company_id, discount_type, discount_id) DO UPDATE
		SET priority = EXCLUDED.priority,
			updated_at = NOW(),
			updated_by = EXCLUDED.updated_by
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		priority.PriorityID,
		priority.CompanyID,
		priority.DiscountType,
		r.nullUUIDParam(priority.DiscountID),
		priority.Priority,
		r.nullUUIDParam(priority.CreatedBy),
		r.nullUUIDParam(priority.UpdatedBy),
	).Scan(&priority.CreatedAt, &priority.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to set discount priority", zap.Error(err))
		return fmt.Errorf("set discount priority: %w", err)
	}
	return nil
}

func (r *discountPriorityRepository) DeletePriority(ctx context.Context, db DBTX, companyID, priorityID uuid.UUID) error {
	query := `DELETE FROM sales.discount_priorities WHERE priority_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, priorityID, companyID)
	if err != nil {
		return fmt.Errorf("delete discount priority: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *discountPriorityRepository) List(ctx context.Context, db DBTX, filter DiscountPriorityFilter, p Pagination, s Sort) ([]*discount.DiscountPriority, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}
	allowedSort := map[string]bool{
		"discount_type": true,
		"priority":      true,
		"created_at":    true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY priority ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.discount_priorities %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count priorities: %w", err)
	}
	if total == 0 {
		return []*discount.DiscountPriority{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT priority_id, company_id, discount_type, discount_id, priority, created_at, updated_at, created_by, updated_by
		FROM sales.discount_priorities
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list priorities: %w", err)
	}
	defer rows.Close()

	var result []*discount.DiscountPriority
	for rows.Next() {
		p, err := r.scanPriority(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *discountPriorityRepository) Exists(ctx context.Context, db DBTX, companyID, priorityID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_priorities WHERE priority_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, priorityID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists priority: %w", err)
	}
	return exists, nil
}
