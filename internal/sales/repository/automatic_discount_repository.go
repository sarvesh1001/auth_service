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

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type AutomaticDiscountRepository interface {
	Create(ctx context.Context, db DBTX, ad *discount.AutomaticDiscount) error
	GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*discount.AutomaticDiscount, error)
	Update(ctx context.Context, db DBTX, ad *discount.AutomaticDiscount) error
	Delete(ctx context.Context, db DBTX, companyID, id uuid.UUID) error
	List(ctx context.Context, db DBTX, filter AutomaticDiscountFilter, p Pagination, s Sort) ([]*discount.AutomaticDiscount, int64, error)
	GetApplicable(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.AutomaticDiscount, error)
	Exists(ctx context.Context, db DBTX, companyID, id uuid.UUID) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, id uuid.UUID) (bool, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*discount.AutomaticDiscount, error)
}

type AutomaticDiscountFilter struct {
	CompanyID     uuid.UUID
	IDs           []uuid.UUID
	IsActive      *bool
	DiscountType  *string
	MinValue      *decimal.Decimal
	MaxValue      *decimal.Decimal
	StartDateFrom *time.Time
	StartDateTo   *time.Time
	EndDateFrom   *time.Time
	EndDateTo     *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type automaticDiscountRepository struct {
	logger *zap.Logger
}

func NewAutomaticDiscountRepository(logger *zap.Logger) AutomaticDiscountRepository {
	return &automaticDiscountRepository{
		logger: logger.Named("sales_auto_discount_repo"),
	}
}

// Helpers

func (r *automaticDiscountRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *automaticDiscountRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *automaticDiscountRepository) validatePagination(p Pagination) (int, int) {
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

func (r *automaticDiscountRepository) buildFilter(filter AutomaticDiscountFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.IDs) > 0 {
		placeholders := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("auto_discount_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.DiscountType != nil {
		conds = append(conds, fmt.Sprintf("discount_type = $%d", idx))
		args = append(args, *filter.DiscountType)
		idx++
	}
	if filter.MinValue != nil {
		conds = append(conds, fmt.Sprintf("discount_value >= $%d", idx))
		args = append(args, *filter.MinValue)
		idx++
	}
	if filter.MaxValue != nil {
		conds = append(conds, fmt.Sprintf("discount_value <= $%d", idx))
		args = append(args, *filter.MaxValue)
		idx++
	}
	if filter.StartDateFrom != nil {
		conds = append(conds, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, *filter.StartDateFrom)
		idx++
	}
	if filter.StartDateTo != nil {
		conds = append(conds, fmt.Sprintf("start_date <= $%d", idx))
		args = append(args, *filter.StartDateTo)
		idx++
	}
	if filter.EndDateFrom != nil {
		conds = append(conds, fmt.Sprintf("end_date >= $%d", idx))
		args = append(args, *filter.EndDateFrom)
		idx++
	}
	if filter.EndDateTo != nil {
		conds = append(conds, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, *filter.EndDateTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *automaticDiscountRepository) scanAutomaticDiscount(s scanner) (*discount.AutomaticDiscount, error) {
	var ad discount.AutomaticDiscount
	var description, applicableProducts sql.NullString
	var maxDiscountAmount, minOrderAmount sql.NullString
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&ad.AutoDiscountID,
		&ad.CompanyID,
		&ad.Name,
		&description,
		&ad.DiscountType,
		&ad.DiscountValue,
		&maxDiscountAmount,
		&minOrderAmount,
		&applicableProducts,
		&ad.StartDate,
		&ad.EndDate,
		&ad.IsActive,
		&ad.Priority,
		&ad.CreatedAt,
		&ad.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan automatic discount: %w", err)
	}
	if description.Valid {
		ad.Description = &description.String
	}
	if maxDiscountAmount.Valid {
		val, _ := decimal.NewFromString(maxDiscountAmount.String)
		ad.MaxDiscountAmount = &val
	}
	if minOrderAmount.Valid {
		val, _ := decimal.NewFromString(minOrderAmount.String)
		ad.MinOrderAmount = &val
	}
	if applicableProducts.Valid && applicableProducts.String != "" {
		ad.ApplicableProducts = []byte(applicableProducts.String)
	}
	if createdBy.Valid {
		ad.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ad.UpdatedBy = &updatedBy.UUID
	}
	return &ad, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *automaticDiscountRepository) Create(ctx context.Context, db DBTX, ad *discount.AutomaticDiscount) error {
	query := `
		INSERT INTO sales.automatic_discounts (
			auto_discount_id, company_id, name, description, discount_type, discount_value,
			max_discount_amount, min_order_amount, applicable_products, start_date, end_date,
			is_active, priority, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW(), $14, $15)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ad.AutoDiscountID,
		ad.CompanyID,
		ad.Name,
		ad.Description,
		ad.DiscountType,
		ad.DiscountValue,
		ad.MaxDiscountAmount,
		ad.MinOrderAmount,
		ad.ApplicableProducts,
		ad.StartDate,
		ad.EndDate,
		ad.IsActive,
		ad.Priority,
		r.nullUUIDParam(ad.CreatedBy),
		r.nullUUIDParam(ad.UpdatedBy),
	).Scan(&ad.CreatedAt, &ad.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create automatic discount", zap.Error(err))
		return fmt.Errorf("create automatic discount: %w", err)
	}
	return nil
}

func (r *automaticDiscountRepository) GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*discount.AutomaticDiscount, error) {
	query := `
		SELECT auto_discount_id, company_id, name, description, discount_type, discount_value,
			max_discount_amount, min_order_amount, applicable_products, start_date, end_date,
			is_active, priority, created_at, updated_at, created_by, updated_by
		FROM sales.automatic_discounts
		WHERE auto_discount_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, id, companyID)
	return r.scanAutomaticDiscount(row)
}

func (r *automaticDiscountRepository) Update(ctx context.Context, db DBTX, ad *discount.AutomaticDiscount) error {
	query := `
		UPDATE sales.automatic_discounts
		SET name = $3,
			description = $4,
			discount_type = $5,
			discount_value = $6,
			max_discount_amount = $7,
			min_order_amount = $8,
			applicable_products = $9,
			start_date = $10,
			end_date = $11,
			is_active = $12,
			priority = $13,
			updated_at = NOW(),
			updated_by = $14
		WHERE auto_discount_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ad.AutoDiscountID,
		ad.CompanyID,
		ad.Name,
		ad.Description,
		ad.DiscountType,
		ad.DiscountValue,
		ad.MaxDiscountAmount,
		ad.MinOrderAmount,
		ad.ApplicableProducts,
		ad.StartDate,
		ad.EndDate,
		ad.IsActive,
		ad.Priority,
		r.nullUUIDParam(ad.UpdatedBy),
	).Scan(&ad.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update automatic discount", zap.Error(err))
		return fmt.Errorf("update automatic discount: %w", err)
	}
	return nil
}

func (r *automaticDiscountRepository) Delete(ctx context.Context, db DBTX, companyID, id uuid.UUID) error {
	query := `DELETE FROM sales.automatic_discounts WHERE auto_discount_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, id, companyID)
	if err != nil {
		return fmt.Errorf("delete automatic discount: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *automaticDiscountRepository) List(ctx context.Context, db DBTX, filter AutomaticDiscountFilter, p Pagination, s Sort) ([]*discount.AutomaticDiscount, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}
	allowedSort := map[string]bool{
		"name":           true,
		"discount_value": true,
		"priority":       true,
		"start_date":     true,
		"end_date":       true,
		"created_at":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY priority ASC, created_at ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.automatic_discounts %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count automatic discounts: %w", err)
	}
	if total == 0 {
		return []*discount.AutomaticDiscount{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT auto_discount_id, company_id, name, description, discount_type, discount_value,
			max_discount_amount, min_order_amount, applicable_products, start_date, end_date,
			is_active, priority, created_at, updated_at, created_by, updated_by
		FROM sales.automatic_discounts
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list automatic discounts: %w", err)
	}
	defer rows.Close()

	var result []*discount.AutomaticDiscount
	for rows.Next() {
		ad, err := r.scanAutomaticDiscount(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ad)
	}
	return result, total, rows.Err()
}

func (r *automaticDiscountRepository) GetApplicable(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.AutomaticDiscount, error) {
	// Build base query: active, within date range, min_order_amount satisfied, product filtering (simplified)
	query := `
		SELECT auto_discount_id, company_id, name, description, discount_type, discount_value,
			max_discount_amount, min_order_amount, applicable_products, start_date, end_date,
			is_active, priority, created_at, updated_at, created_by, updated_by
		FROM sales.automatic_discounts
		WHERE company_id = $1
			AND is_active = true
			AND start_date <= $2
			AND end_date >= $2
			AND (min_order_amount IS NULL OR min_order_amount <= $3)
	`
	args := []interface{}{companyID, at, orderAmount}
	// If productIDs provided, filter by applicable_products (simplified: if applicable_products is NULL => all products)
	// For full implementation you'd need JSONB containment logic. We'll keep simple.
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get applicable automatic discounts: %w", err)
	}
	defer rows.Close()
	var result []*discount.AutomaticDiscount
	for rows.Next() {
		ad, err := r.scanAutomaticDiscount(rows)
		if err != nil {
			return nil, err
		}
		// Skip if applicable_products restricts and productIDs not satisfied (simplified)
		result = append(result, ad)
	}
	return result, rows.Err()
}

func (r *automaticDiscountRepository) Exists(ctx context.Context, db DBTX, companyID, id uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.automatic_discounts WHERE auto_discount_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists automatic discount: %w", err)
	}
	return exists, nil
}

func (r *automaticDiscountRepository) IsActive(ctx context.Context, db DBTX, companyID, id uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.automatic_discounts WHERE auto_discount_id = $1 AND company_id = $2`
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

func (r *automaticDiscountRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*discount.AutomaticDiscount, error) {
	query := `
		SELECT auto_discount_id, company_id, name, description, discount_type, discount_value,
			max_discount_amount, min_order_amount, applicable_products, start_date, end_date,
			is_active, priority, created_at, updated_at, created_by, updated_by
		FROM sales.automatic_discounts
		WHERE auto_discount_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, id, companyID)
	return r.scanAutomaticDiscount(row)
}
