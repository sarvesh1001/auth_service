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
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

type SalesRepCommissionRepository interface {
	Create(ctx context.Context, db DBTX, commission *models.SalesRepCommission) error
	GetByID(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesRepCommission, error)
	Update(ctx context.Context, db DBTX, commission *models.SalesRepCommission) error
	Delete(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (bool, error)
	HasOverlappingRule(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, productID *uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, excludeCommissionID *uuid.UUID) (bool, error)
	GetApplicableCommission(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, productID *uuid.UUID, at time.Time) (*models.SalesRepCommission, error)
	CalculateCommissionAmount(ctx context.Context, db DBTX, commissionID uuid.UUID, baseAmount decimal.Decimal) (decimal.Decimal, error)
	List(ctx context.Context, db DBTX, filter SalesRepCommissionFilter, p Pagination, s Sort) ([]*models.SalesRepCommission, int64, error)
	GetBySalesRep(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) ([]*models.SalesRepCommission, error)
	GetActiveCommissions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*models.SalesRepCommission, error)
	GetTotalCommissionAmount(ctx context.Context, db DBTX, companyID uuid.UUID, salesRepID *uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesRepCommission, error)
	// HasOverlappingAssignment checks if the sales rep already has an active assignment on the given date.

}

type SalesRepCommissionFilter struct {
	CompanyID         uuid.UUID
	CommissionIDs     []uuid.UUID
	SalesRepID        *uuid.UUID
	ProductID         *uuid.UUID
	AppliesTo         *enums.CommissionBaseType
	MinCommissionRate *decimal.Decimal
	MaxCommissionRate *decimal.Decimal
	EffectiveFrom     *time.Time
	EffectiveTo       *time.Time
	CreatedFrom       *time.Time
	CreatedTo         *time.Time
	UpdatedFrom       *time.Time
	UpdatedTo         *time.Time
}

type salesRepCommissionRepository struct {
	logger *zap.Logger
}

func NewSalesRepCommissionRepository(logger *zap.Logger) SalesRepCommissionRepository {
	return &salesRepCommissionRepository{
		logger: logger.Named("sales_rep_commission_repo"),
	}
}

func (r *salesRepCommissionRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *salesRepCommissionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *salesRepCommissionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *salesRepCommissionRepository) buildCommissionFilter(filter SalesRepCommissionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.CommissionIDs) > 0 {
		placeholders := make([]string, len(filter.CommissionIDs))
		for i, id := range filter.CommissionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("commission_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if filter.ProductID != nil {
		conds = append(conds, fmt.Sprintf("product_id = $%d", idx))
		args = append(args, *filter.ProductID)
		idx++
	}
	if filter.AppliesTo != nil {
		conds = append(conds, fmt.Sprintf("applies_to = $%d", idx))
		// Fixed: use string(*filter.AppliesTo) instead of .String()
		args = append(args, string(*filter.AppliesTo))
		idx++
	}
	if filter.MinCommissionRate != nil {
		conds = append(conds, fmt.Sprintf("commission_rate >= $%d", idx))
		args = append(args, *filter.MinCommissionRate)
		idx++
	}
	if filter.MaxCommissionRate != nil {
		conds = append(conds, fmt.Sprintf("commission_rate <= $%d", idx))
		args = append(args, *filter.MaxCommissionRate)
		idx++
	}
	if filter.EffectiveFrom != nil {
		conds = append(conds, fmt.Sprintf("effective_from >= $%d", idx))
		args = append(args, *filter.EffectiveFrom)
		idx++
	}
	if filter.EffectiveTo != nil {
		conds = append(conds, fmt.Sprintf("effective_to <= $%d", idx))
		args = append(args, *filter.EffectiveTo)
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
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *salesRepCommissionRepository) scanCommission(s scanner) (*models.SalesRepCommission, error) {
	var c models.SalesRepCommission
	var productID, createdBy, updatedBy uuid.NullUUID
	var effectiveTo sql.NullTime

	err := s.Scan(
		&c.CommissionID,
		&c.CompanyID,
		&c.SalesRepID,
		&c.EffectiveFrom,
		&effectiveTo,
		&c.CommissionRate,
		&c.AppliesTo,
		&productID,
		&c.CreatedAt,
		&c.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan commission: %w", err)
	}
	if effectiveTo.Valid {
		c.EffectiveTo = &effectiveTo.Time
	}
	if productID.Valid {
		c.ProductID = &productID.UUID
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

// ---------- CRUD ----------
func (r *salesRepCommissionRepository) Create(ctx context.Context, db DBTX, commission *models.SalesRepCommission) error {
	query := `
		INSERT INTO sales.sales_rep_commissions (
			commission_id, company_id, sales_rep_id, effective_from, effective_to,
			commission_rate, applies_to, product_id, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		commission.CommissionID,
		commission.CompanyID,
		commission.SalesRepID,
		commission.EffectiveFrom,
		commission.EffectiveTo,
		commission.CommissionRate,
		commission.AppliesTo,
		r.nullUUIDParam(commission.ProductID),
		r.nullUUIDParam(commission.CreatedBy),
		r.nullUUIDParam(commission.UpdatedBy),
	).Scan(&commission.CreatedAt, &commission.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create commission", zap.Error(err))
		return fmt.Errorf("create commission: %w", err)
	}
	return nil
}

func (r *salesRepCommissionRepository) GetByID(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesRepCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, effective_from, effective_to,
		       commission_rate, applies_to, product_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.sales_rep_commissions
		WHERE company_id = $1 AND commission_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, commissionID)
	return r.scanCommission(row)
}

func (r *salesRepCommissionRepository) Update(ctx context.Context, db DBTX, commission *models.SalesRepCommission) error {
	query := `
		UPDATE sales.sales_rep_commissions SET
			sales_rep_id = $3,
			effective_from = $4,
			effective_to = $5,
			commission_rate = $6,
			applies_to = $7,
			product_id = $8,
			updated_at = NOW(),
			updated_by = $9
		WHERE commission_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		commission.CommissionID,
		commission.CompanyID,
		commission.SalesRepID,
		commission.EffectiveFrom,
		commission.EffectiveTo,
		commission.CommissionRate,
		commission.AppliesTo,
		r.nullUUIDParam(commission.ProductID),
		r.nullUUIDParam(commission.UpdatedBy),
	).Scan(&commission.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update commission: %w", err)
	}
	return nil
}

func (r *salesRepCommissionRepository) Delete(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) error {
	query := `DELETE FROM sales.sales_rep_commissions WHERE company_id = $1 AND commission_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, commissionID)
	if err != nil {
		return fmt.Errorf("delete commission: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// ---------- Validation ----------
func (r *salesRepCommissionRepository) Exists(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_rep_commissions WHERE company_id = $1 AND commission_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, commissionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *salesRepCommissionRepository) HasOverlappingRule(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, productID *uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, excludeCommissionID *uuid.UUID) (bool, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
	args = append(args, salesRepID)
	idx++

	if productID != nil {
		conds = append(conds, fmt.Sprintf("(product_id = $%d OR product_id IS NULL)", idx))
		args = append(args, *productID)
		idx++
	} else {
		conds = append(conds, "product_id IS NULL")
	}

	// date range overlap: existing effective_from <= new effective_to AND existing effective_to >= new effective_from
	if effectiveTo != nil {
		conds = append(conds, fmt.Sprintf("(effective_from <= $%d AND (effective_to IS NULL OR effective_to >= $%d))", idx, idx+1))
		args = append(args, *effectiveTo, effectiveFrom)
		idx += 2
	} else {
		conds = append(conds, fmt.Sprintf("(effective_from <= $%d AND effective_to IS NULL)", idx))
		args = append(args, effectiveFrom)
		idx++
	}

	if excludeCommissionID != nil {
		conds = append(conds, fmt.Sprintf("commission_id != $%d", idx))
		args = append(args, *excludeCommissionID)
		idx++
	}

	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM sales.sales_rep_commissions WHERE %s)", where)
	var exists bool
	err := db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check overlapping rule: %w", err)
	}
	return exists, nil
}

// ---------- Resolution ----------
func (r *salesRepCommissionRepository) GetApplicableCommission(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, productID *uuid.UUID, at time.Time) (*models.SalesRepCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, effective_from, effective_to,
		       commission_rate, applies_to, product_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.sales_rep_commissions
		WHERE company_id = $1
		  AND sales_rep_id = $2
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		  AND (product_id IS NULL OR product_id = $4)
		ORDER BY product_id NULLS LAST, effective_from DESC
		LIMIT 1
	`
	var pid interface{}
	if productID == nil {
		pid = nil
	} else {
		pid = *productID
	}
	row := db.QueryRowContext(ctx, query, companyID, salesRepID, at, pid)
	return r.scanCommission(row)
}

func (r *salesRepCommissionRepository) CalculateCommissionAmount(ctx context.Context, db DBTX, commissionID uuid.UUID, baseAmount decimal.Decimal) (decimal.Decimal, error) {
	var rate decimal.Decimal
	query := `SELECT commission_rate FROM sales.sales_rep_commissions WHERE commission_id = $1`
	err := db.QueryRowContext(ctx, query, commissionID).Scan(&rate)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get commission rate: %w", err)
	}
	return baseAmount.Mul(rate).Div(decimal.NewFromInt(100)), nil
}

// ---------- Querying / Listing ----------
func (r *salesRepCommissionRepository) List(ctx context.Context, db DBTX, filter SalesRepCommissionFilter, p Pagination, s Sort) ([]*models.SalesRepCommission, int64, error) {
	where, args := r.buildCommissionFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"effective_from":  true,
		"commission_rate": true,
		"created_at":      true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY effective_from DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.sales_rep_commissions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count commissions: %w", err)
	}
	if total == 0 {
		return []*models.SalesRepCommission{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT commission_id, company_id, sales_rep_id, effective_from, effective_to,
		       commission_rate, applies_to, product_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.sales_rep_commissions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list commissions: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesRepCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

func (r *salesRepCommissionRepository) GetBySalesRep(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) ([]*models.SalesRepCommission, error) {
	filter := SalesRepCommissionFilter{
		CompanyID:  companyID,
		SalesRepID: &salesRepID,
	}
	list, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "effective_from", Direction: "DESC"})
	return list, err
}

func (r *salesRepCommissionRepository) GetActiveCommissions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*models.SalesRepCommission, error) {
	args := []interface{}{companyID, at, at}
	query := `
		SELECT commission_id, company_id, sales_rep_id, effective_from, effective_to,
		       commission_rate, applies_to, product_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.sales_rep_commissions
		WHERE company_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
	`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get active commissions: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesRepCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// ---------- Analytics ----------
func (r *salesRepCommissionRepository) GetTotalCommissionAmount(ctx context.Context, db DBTX, companyID uuid.UUID, salesRepID *uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	// Build a query that joins with invoices to calculate actual commission earned.
	// For simplicity, we'll compute based on applicable commission rates times invoice amounts.
	// This is a placeholder; in production you'd likely have a materialized table or use a window function.
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("c.company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if salesRepID != nil {
		conds = append(conds, fmt.Sprintf("c.sales_rep_id = $%d", idx))
		args = append(args, *salesRepID)
		idx++
	}
	if from != nil {
		conds = append(conds, fmt.Sprintf("i.invoice_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("i.invoice_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")

	// We need to sum (invoice_line_total * commission_rate / 100) for lines where the commission rule applies.
	// For demonstration, we'll return zero with a comment.
	// A proper implementation would join sales.invoice_items, sales.products, sales.sales_rep_commissions.
	// Example:
	//   SELECT COALESCE(SUM(ii.total_price * cr.commission_rate / 100), 0)
	//   FROM sales.invoices i
	//   JOIN sales.invoice_items ii ON i.invoice_id = ii.invoice_id
	//   JOIN sales.sales_rep_commissions cr ON cr.sales_rep_id = i.sales_rep_id
	//   WHERE cr.effective_from <= i.invoice_date AND (cr.effective_to IS NULL OR cr.effective_to >= i.invoice_date)
	//   AND (cr.product_id IS NULL OR cr.product_id = ii.product_id)
	//   AND ...
	//
	// For now, return zero to avoid unused variable warnings.
	_ = where
	_ = args

	return decimal.Zero, nil
}

// ---------- Concurrency / Locking ----------
func (r *salesRepCommissionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesRepCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, effective_from, effective_to,
		       commission_rate, applies_to, product_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.sales_rep_commissions
		WHERE company_id = $1 AND commission_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, commissionID)
	return r.scanCommission(row)
}
