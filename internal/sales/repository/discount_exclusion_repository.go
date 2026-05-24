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

type DiscountExclusionRepository interface {
	Create(ctx context.Context, db DBTX, ex *discount.DiscountExclusion) error
	Delete(ctx context.Context, db DBTX, companyID, exclusionID uuid.UUID) error
	AreExcluded(ctx context.Context, db DBTX, companyID uuid.UUID, typeA string, idA uuid.UUID, typeB string, idB uuid.UUID) (bool, error)
	GetExclusionsForDiscount(ctx context.Context, db DBTX, companyID uuid.UUID, discountType string, discountID uuid.UUID) ([]*discount.DiscountExclusion, error)
	List(ctx context.Context, db DBTX, filter DiscountExclusionFilter, p Pagination, s Sort) ([]*discount.DiscountExclusion, int64, error)
	Exists(ctx context.Context, db DBTX, companyID, exclusionID uuid.UUID) (bool, error)
}

type DiscountExclusionFilter struct {
	CompanyID     uuid.UUID
	DiscountTypeA *string
	DiscountIDA   *uuid.UUID
	DiscountTypeB *string
	DiscountIDB   *uuid.UUID
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type discountExclusionRepository struct {
	logger *zap.Logger
}

func NewDiscountExclusionRepository(logger *zap.Logger) DiscountExclusionRepository {
	return &discountExclusionRepository{
		logger: logger.Named("sales_discount_exclusion_repo"),
	}
}

// Helpers

func (r *discountExclusionRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *discountExclusionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *discountExclusionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *discountExclusionRepository) buildFilter(filter DiscountExclusionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.DiscountTypeA != nil {
		conds = append(conds, fmt.Sprintf("discount_type_a = $%d", idx))
		args = append(args, *filter.DiscountTypeA)
		idx++
	}
	if filter.DiscountIDA != nil {
		conds = append(conds, fmt.Sprintf("discount_id_a = $%d", idx))
		args = append(args, *filter.DiscountIDA)
		idx++
	}
	if filter.DiscountTypeB != nil {
		conds = append(conds, fmt.Sprintf("discount_type_b = $%d", idx))
		args = append(args, *filter.DiscountTypeB)
		idx++
	}
	if filter.DiscountIDB != nil {
		conds = append(conds, fmt.Sprintf("discount_id_b = $%d", idx))
		args = append(args, *filter.DiscountIDB)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *discountExclusionRepository) scanExclusion(s scanner) (*discount.DiscountExclusion, error) {
	var ex discount.DiscountExclusion
	var createdBy uuid.NullUUID

	err := s.Scan(
		&ex.ExclusionID,
		&ex.CompanyID,
		&ex.DiscountTypeA,
		&ex.DiscountIDA,
		&ex.DiscountTypeB,
		&ex.DiscountIDB,
		&ex.CreatedAt,
		&createdBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan discount exclusion: %w", err)
	}
	if createdBy.Valid {
		ex.CreatedBy = &createdBy.UUID
	}
	return &ex, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *discountExclusionRepository) Create(ctx context.Context, db DBTX, ex *discount.DiscountExclusion) error {
	query := `
		INSERT INTO sales.discount_exclusions (
			exclusion_id, company_id, discount_type_a, discount_id_a, discount_type_b, discount_id_b, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		ex.ExclusionID,
		ex.CompanyID,
		ex.DiscountTypeA,
		ex.DiscountIDA,
		ex.DiscountTypeB,
		ex.DiscountIDB,
		r.nullUUIDParam(ex.CreatedBy),
	).Scan(&ex.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create discount exclusion", zap.Error(err))
		return fmt.Errorf("create discount exclusion: %w", err)
	}
	return nil
}

func (r *discountExclusionRepository) Delete(ctx context.Context, db DBTX, companyID, exclusionID uuid.UUID) error {
	query := `DELETE FROM sales.discount_exclusions WHERE exclusion_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, exclusionID, companyID)
	if err != nil {
		return fmt.Errorf("delete discount exclusion: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *discountExclusionRepository) AreExcluded(ctx context.Context, db DBTX, companyID uuid.UUID, typeA string, idA uuid.UUID, typeB string, idB uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.discount_exclusions
			WHERE company_id = $1
				AND ((discount_type_a = $2 AND discount_id_a = $3 AND discount_type_b = $4 AND discount_id_b = $5)
				  OR (discount_type_a = $4 AND discount_id_a = $5 AND discount_type_b = $2 AND discount_id_b = $3))
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, typeA, idA, typeB, idB).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("are excluded: %w", err)
	}
	return exists, nil
}

func (r *discountExclusionRepository) GetExclusionsForDiscount(ctx context.Context, db DBTX, companyID uuid.UUID, discountType string, discountID uuid.UUID) ([]*discount.DiscountExclusion, error) {
	query := `
		SELECT exclusion_id, company_id, discount_type_a, discount_id_a, discount_type_b, discount_id_b, created_at, created_by
		FROM sales.discount_exclusions
		WHERE company_id = $1 AND (discount_type_a = $2 AND discount_id_a = $3 OR discount_type_b = $2 AND discount_id_b = $3)
	`
	rows, err := db.QueryContext(ctx, query, companyID, discountType, discountID)
	if err != nil {
		return nil, fmt.Errorf("get exclusions for discount: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountExclusion
	for rows.Next() {
		ex, err := r.scanExclusion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ex)
	}
	return result, rows.Err()
}

func (r *discountExclusionRepository) List(ctx context.Context, db DBTX, filter DiscountExclusionFilter, p Pagination, s Sort) ([]*discount.DiscountExclusion, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}
	allowedSort := map[string]bool{
		"created_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.discount_exclusions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count exclusions: %w", err)
	}
	if total == 0 {
		return []*discount.DiscountExclusion{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT exclusion_id, company_id, discount_type_a, discount_id_a, discount_type_b, discount_id_b, created_at, created_by
		FROM sales.discount_exclusions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list exclusions: %w", err)
	}
	defer rows.Close()

	var result []*discount.DiscountExclusion
	for rows.Next() {
		ex, err := r.scanExclusion(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ex)
	}
	return result, total, rows.Err()
}

func (r *discountExclusionRepository) Exists(ctx context.Context, db DBTX, companyID, exclusionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_exclusions WHERE exclusion_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, exclusionID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists exclusion: %w", err)
	}
	return exists, nil
}
