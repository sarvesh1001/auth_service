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

	saleserrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// Interface & Filter
// -------------------------------------------------------------------------

type CouponRepository interface {
	Create(ctx context.Context, db DBTX, coupon *discount.Coupon) error
	GetByID(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (*discount.Coupon, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*discount.Coupon, error)
	Update(ctx context.Context, db DBTX, coupon *discount.Coupon) error
	Delete(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) error // soft delete

	GetApplicableCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error)
	GetBestCoupon(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error)

	SetActiveStatus(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	IsActive(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (bool, error)
	IsExpired(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, at time.Time) (bool, error)
	Exists(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)

	IsApplicableForOrderAmount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (bool, error)
	IsApplicableForProduct(ctx context.Context, db DBTX, companyID, couponID, productID uuid.UUID) (bool, error)
	IsCustomerEligible(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (bool, error)
	CanCustomerUseCoupon(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (bool, error)
	ValidateCoupon(ctx context.Context, db DBTX, companyID uuid.UUID, code string, customerID *uuid.UUID, orderAmount decimal.Decimal, productIDs []uuid.UUID, at time.Time) (*discount.Coupon, error)

	// GetStackingType returns the stacking_type for a coupon (stackable, exclusive, none)
	GetStackingType(ctx context.Context, db DBTX, couponID uuid.UUID) (string, error)

	CreateUsage(ctx context.Context, db DBTX, usage *discount.CouponUsage) error
	GetUsageByID(ctx context.Context, db DBTX, usageID uuid.UUID) (*discount.CouponUsage, error)
	GetUsagesByCoupon(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) ([]*discount.CouponUsage, error)
	GetUsagesByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*discount.CouponUsage, error)
	GetUsageByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*discount.CouponUsage, error)
	GetTotalUsageCount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (int64, error)
	GetCustomerUsageCount(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (int64, error)
	HasCustomerUsedCoupon(ctx context.Context, db DBTX, companyID, couponID, customerID, orderID uuid.UUID) (bool, error)
	DeleteUsage(ctx context.Context, db DBTX, usageID uuid.UUID) error

	CalculateDiscount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error)
	GetMaximumDiscount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error)

	List(ctx context.Context, db DBTX, filter CouponFilter, p Pagination, s Sort) ([]*discount.Coupon, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*discount.Coupon, int64, error)
	GetActiveCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error)
	GetExpiredCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error)
	GetCouponsExpiringSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Coupon, error)

	GetTotalDiscountGiven(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopCouponsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetTopCouponsByDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetUnusedCoupons(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*discount.Coupon, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (*discount.Coupon, error)
}

type CouponFilter struct {
	CompanyID        uuid.UUID
	CouponIDs        []uuid.UUID
	IsActive         *bool
	DiscountTypes    []enums.DiscountType
	Code             *string
	MinDiscountValue *decimal.Decimal
	MaxDiscountValue *decimal.Decimal
	MinOrderAmount   *decimal.Decimal
	MaxOrderAmount   *decimal.Decimal
	StartDateFrom    *time.Time
	StartDateTo      *time.Time
	EndDateFrom      *time.Time
	EndDateTo        *time.Time
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
	UpdatedFrom      *time.Time
	UpdatedTo        *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type couponRepository struct {
	logger *zap.Logger
}

func NewCouponRepository(logger *zap.Logger) CouponRepository {
	return &couponRepository{
		logger: logger.Named("sales_coupon_repo"),
	}
}

// Helper functions

func (r *couponRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *couponRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *couponRepository) validatePagination(p Pagination) (int, int) {
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

// buildCouponFilter adds deleted_at IS NULL automatically
func (r *couponRepository) buildCouponFilter(filter CouponFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// Always exclude soft‑deleted coupons
	conds = append(conds, "deleted_at IS NULL")

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.CouponIDs) > 0 {
		placeholders := make([]string, len(filter.CouponIDs))
		for i, id := range filter.CouponIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("coupon_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if len(filter.DiscountTypes) > 0 {
		placeholders := make([]string, len(filter.DiscountTypes))
		for i, dt := range filter.DiscountTypes {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, dt.String())
			idx++
		}
		conds = append(conds, fmt.Sprintf("discount_type IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Code != nil {
		conds = append(conds, fmt.Sprintf("code = $%d", idx))
		args = append(args, *filter.Code)
		idx++
	}
	if filter.MinDiscountValue != nil {
		conds = append(conds, fmt.Sprintf("discount_value >= $%d", idx))
		args = append(args, *filter.MinDiscountValue)
		idx++
	}
	if filter.MaxDiscountValue != nil {
		conds = append(conds, fmt.Sprintf("discount_value <= $%d", idx))
		args = append(args, *filter.MaxDiscountValue)
		idx++
	}
	if filter.MinOrderAmount != nil {
		conds = append(conds, fmt.Sprintf("min_order_amount >= $%d", idx))
		args = append(args, *filter.MinOrderAmount)
		idx++
	}
	if filter.MaxOrderAmount != nil {
		conds = append(conds, fmt.Sprintf("min_order_amount <= $%d", idx))
		args = append(args, *filter.MaxOrderAmount)
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

// scanCoupon now includes stacking_type and deleted_at
func (r *couponRepository) scanCoupon(s scanner) (*discount.Coupon, error) {
	var c discount.Coupon
	var usageLimit, perUserLimit sql.NullInt32
	var maxDiscountAmount, minOrderAmount sql.NullString
	var applicableItems []byte
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := s.Scan(
		&c.CouponID,
		&c.CompanyID,
		&c.Code,
		&c.DiscountType,
		&c.DiscountValue,
		&maxDiscountAmount,
		&c.StartDate,
		&c.EndDate,
		&usageLimit,
		&perUserLimit,
		&minOrderAmount,
		&applicableItems,
		&c.IsActive,
		&c.CreatedAt,
		&c.UpdatedAt,
		&createdBy,
		&updatedBy,
		&deletedAt,
		&c.StackingType, // <-- ADDED stacking_type
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, saleserrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan coupon: %w", err)
	}

	if deletedAt.Valid {
		c.DeletedAt = &deletedAt.Time
	}
	if maxDiscountAmount.Valid {
		val, err := decimal.NewFromString(maxDiscountAmount.String)
		if err == nil {
			c.MaxDiscountAmount = &val
		}
	}
	if minOrderAmount.Valid {
		val, err := decimal.NewFromString(minOrderAmount.String)
		if err == nil {
			c.MinOrderAmount = &val
		}
	}
	if usageLimit.Valid {
		val := int(usageLimit.Int32)
		c.UsageLimit = &val
	}
	if perUserLimit.Valid {
		val := int(perUserLimit.Int32)
		c.PerUserLimit = &val
	}
	if applicableItems != nil {
		c.ApplicableItems = applicableItems
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

func (r *couponRepository) scanCouponUsage(s scanner) (*discount.CouponUsage, error) {
	var u discount.CouponUsage
	err := s.Scan(
		&u.UsageID,
		&u.CouponID,
		&u.CustomerID,
		&u.OrderID,
		&u.DiscountAmount,
		&u.UsedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, saleserrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan coupon usage: %w", err)
	}
	return &u, nil
}

// -------------------------------------------------------------------------
// COUPON CRUD (including stacking_type)
// -------------------------------------------------------------------------

func (r *couponRepository) Create(ctx context.Context, db DBTX, coupon *discount.Coupon) error {
	query := `
		INSERT INTO sales.coupons (
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, stacking_type,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			NOW(), NOW(), $15, $16
		)
		RETURNING created_at, updated_at
	`
	var maxDiscount, minOrder interface{}
	if coupon.MaxDiscountAmount != nil {
		maxDiscount = coupon.MaxDiscountAmount.String()
	} else {
		maxDiscount = nil
	}
	if coupon.MinOrderAmount != nil {
		minOrder = coupon.MinOrderAmount.String()
	} else {
		minOrder = nil
	}
	var usageLimit, perUserLimit interface{}
	if coupon.UsageLimit != nil {
		usageLimit = *coupon.UsageLimit
	} else {
		usageLimit = nil
	}
	if coupon.PerUserLimit != nil {
		perUserLimit = *coupon.PerUserLimit
	} else {
		perUserLimit = nil
	}
	applicable := coupon.ApplicableItems
	if applicable == nil {
		applicable = []byte("{}")
	}

	err := db.QueryRowContext(ctx, query,
		coupon.CouponID,
		coupon.CompanyID,
		coupon.Code,
		coupon.DiscountType.String(),
		coupon.DiscountValue,
		maxDiscount,
		coupon.StartDate,
		coupon.EndDate,
		usageLimit,
		perUserLimit,
		minOrder,
		applicable,
		coupon.IsActive,
		coupon.StackingType, // <-- ADDED stacking_type
		r.nullUUIDParam(coupon.CreatedBy),
		r.nullUUIDParam(coupon.UpdatedBy),
	).Scan(&coupon.CreatedAt, &coupon.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create coupon", zap.Error(err))
		return fmt.Errorf("create coupon: %w", err)
	}
	return nil
}

func (r *couponRepository) GetByID(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, couponID)
	return r.scanCoupon(row)
}

func (r *couponRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanCoupon(row)
}

func (r *couponRepository) Update(ctx context.Context, db DBTX, coupon *discount.Coupon) error {
	query := `
		UPDATE sales.coupons SET
			code = $3,
			discount_type = $4,
			discount_value = $5,
			max_discount_amount = $6,
			start_date = $7,
			end_date = $8,
			usage_limit = $9,
			per_user_limit = $10,
			min_order_amount = $11,
			applicable_items = $12,
			is_active = $13,
			deleted_at = $14,
			stacking_type = $15,
			updated_at = NOW(),
			updated_by = $16
		WHERE coupon_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	var maxDiscount, minOrder interface{}
	if coupon.MaxDiscountAmount != nil {
		maxDiscount = coupon.MaxDiscountAmount.String()
	} else {
		maxDiscount = nil
	}
	if coupon.MinOrderAmount != nil {
		minOrder = coupon.MinOrderAmount.String()
	} else {
		minOrder = nil
	}
	var usageLimit, perUserLimit interface{}
	if coupon.UsageLimit != nil {
		usageLimit = *coupon.UsageLimit
	} else {
		usageLimit = nil
	}
	if coupon.PerUserLimit != nil {
		perUserLimit = *coupon.PerUserLimit
	} else {
		perUserLimit = nil
	}
	applicable := coupon.ApplicableItems
	if applicable == nil {
		applicable = []byte("{}")
	}
	var deletedAt interface{}
	if coupon.DeletedAt != nil {
		deletedAt = *coupon.DeletedAt
	} else {
		deletedAt = nil
	}

	err := db.QueryRowContext(ctx, query,
		coupon.CouponID,
		coupon.CompanyID,
		coupon.Code,
		coupon.DiscountType.String(),
		coupon.DiscountValue,
		maxDiscount,
		coupon.StartDate,
		coupon.EndDate,
		usageLimit,
		perUserLimit,
		minOrder,
		applicable,
		coupon.IsActive,
		deletedAt,
		coupon.StackingType, // <-- ADDED stacking_type
		r.nullUUIDParam(coupon.UpdatedBy),
	).Scan(&coupon.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return saleserrors.ErrNotFound
		}
		return fmt.Errorf("update coupon: %w", err)
	}
	return nil
}

// Delete implements soft delete (sets deleted_at and is_active=false)
func (r *couponRepository) Delete(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) error {
	query := `
		UPDATE sales.coupons
		SET deleted_at = NOW(), is_active = false, updated_at = NOW()
		WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, couponID)
	if err != nil {
		return fmt.Errorf("soft delete coupon: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return saleserrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// STATUS / LIFECYCLE
// -------------------------------------------------------------------------

func (r *couponRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.coupons
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, couponID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return saleserrors.ErrNotFound
	}
	return nil
}

func (r *couponRepository) IsActive(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, couponID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, saleserrors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

func (r *couponRepository) IsExpired(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, at time.Time) (bool, error) {
	var expired bool
	query := `SELECT end_date < $3 FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, couponID, at).Scan(&expired)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, saleserrors.ErrNotFound
		}
		return false, fmt.Errorf("is expired: %w", err)
	}
	return expired, nil
}

func (r *couponRepository) Exists(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, couponID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *couponRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.coupons WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// VALIDATION / APPLICABILITY (all include deleted_at IS NULL)
// -------------------------------------------------------------------------

func (r *couponRepository) IsApplicableForOrderAmount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (bool, error) {
	var minOrder sql.NullString
	query := `SELECT min_order_amount FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, couponID).Scan(&minOrder)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, saleserrors.ErrNotFound
		}
		return false, fmt.Errorf("get min order amount: %w", err)
	}
	if !minOrder.Valid {
		return true, nil
	}
	minAmt, err := decimal.NewFromString(minOrder.String)
	if err != nil {
		return false, fmt.Errorf("parse min order amount: %w", err)
	}
	return orderAmount.GreaterThanOrEqual(minAmt), nil
}

func (r *couponRepository) IsApplicableForProduct(ctx context.Context, db DBTX, companyID, couponID, productID uuid.UUID) (bool, error) {
	var applicable []byte
	query := `SELECT applicable_items FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, couponID).Scan(&applicable)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, saleserrors.ErrNotFound
		}
		return false, fmt.Errorf("get applicable items: %w", err)
	}
	if len(applicable) == 0 || string(applicable) == "{}" || string(applicable) == "null" {
		return true, nil
	}
	return strings.Contains(string(applicable), productID.String()), nil
}

func (r *couponRepository) IsCustomerEligible(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (bool, error) {
	// No customer eligibility by default
	return true, nil
}

func (r *couponRepository) CanCustomerUseCoupon(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (bool, error) {
	limit, err := r.GetCustomerUsageCount(ctx, db, companyID, couponID, customerID)
	if err != nil {
		return false, err
	}
	var perUserLimit int
	query := `SELECT per_user_limit FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL`
	err = db.QueryRowContext(ctx, query, companyID, couponID).Scan(&perUserLimit)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, saleserrors.ErrNotFound
		}
		return false, fmt.Errorf("get per_user_limit: %w", err)
	}
	if perUserLimit <= 0 {
		return true, nil
	}
	return limit < int64(perUserLimit), nil
}

func (r *couponRepository) ValidateCoupon(ctx context.Context, db DBTX, companyID uuid.UUID, code string, customerID *uuid.UUID, orderAmount decimal.Decimal, productIDs []uuid.UUID, at time.Time) (*discount.Coupon, error) {
	coupon, err := r.GetByCode(ctx, db, companyID, code)
	if err != nil {
		return nil, err
	}
	if !coupon.IsActive {
		return nil, saleserrors.ErrCouponInactive
	}
	if at.After(coupon.EndDate) || at.Before(coupon.StartDate) {
		return nil, saleserrors.ErrCouponExpired
	}
	if coupon.UsageLimit != nil {
		used, err := r.GetTotalUsageCount(ctx, db, companyID, coupon.CouponID)
		if err != nil {
			return nil, err
		}
		if used >= int64(*coupon.UsageLimit) {
			return nil, saleserrors.ErrCouponUsageLimit
		}
	}
	if customerID != nil {
		eligible, err := r.CanCustomerUseCoupon(ctx, db, companyID, coupon.CouponID, *customerID)
		if err != nil {
			return nil, err
		}
		if !eligible {
			return nil, saleserrors.ErrCouponUsageLimit
		}
	}
	if coupon.MinOrderAmount != nil && orderAmount.LessThan(*coupon.MinOrderAmount) {
		return nil, fmt.Errorf("order amount %s below minimum %s", orderAmount.String(), coupon.MinOrderAmount.String())
	}
	if len(productIDs) > 0 && coupon.ApplicableItems != nil && len(coupon.ApplicableItems) > 0 && string(coupon.ApplicableItems) != "{}" {
		applicable := false
		for _, pid := range productIDs {
			ok, err := r.IsApplicableForProduct(ctx, db, companyID, coupon.CouponID, pid)
			if err != nil {
				return nil, err
			}
			if ok {
				applicable = true
				break
			}
		}
		if !applicable {
			return nil, fmt.Errorf("coupon not applicable for any product in the order")
		}
	}
	return coupon, nil
}

// -------------------------------------------------------------------------
// USAGE TRACKING (unchanged)
// -------------------------------------------------------------------------

func (r *couponRepository) CreateUsage(ctx context.Context, db DBTX, usage *discount.CouponUsage) error {
	query := `
		INSERT INTO sales.coupon_usages (
			usage_id, coupon_id, customer_id, order_id, discount_amount, used_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING used_at
	`
	err := db.QueryRowContext(ctx, query,
		usage.UsageID,
		usage.CouponID,
		usage.CustomerID,
		usage.OrderID,
		usage.DiscountAmount,
		usage.UsedAt,
	).Scan(&usage.UsedAt)
	if err != nil {
		r.logger.Error("failed to create coupon usage", zap.Error(err))
		return fmt.Errorf("create usage: %w", err)
	}
	return nil
}

func (r *couponRepository) GetUsageByID(ctx context.Context, db DBTX, usageID uuid.UUID) (*discount.CouponUsage, error) {
	query := `
		SELECT usage_id, coupon_id, customer_id, order_id, discount_amount, used_at
		FROM sales.coupon_usages
		WHERE usage_id = $1
	`
	row := db.QueryRowContext(ctx, query, usageID)
	return r.scanCouponUsage(row)
}

func (r *couponRepository) GetUsagesByCoupon(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) ([]*discount.CouponUsage, error) {
	query := `
		SELECT cu.usage_id, cu.coupon_id, cu.customer_id, cu.order_id, cu.discount_amount, cu.used_at
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.coupon_id = $2 AND c.deleted_at IS NULL
		ORDER BY cu.used_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, couponID)
	if err != nil {
		return nil, fmt.Errorf("get usages by coupon: %w", err)
	}
	defer rows.Close()
	var result []*discount.CouponUsage
	for rows.Next() {
		u, err := r.scanCouponUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetUsagesByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*discount.CouponUsage, error) {
	query := `
		SELECT cu.usage_id, cu.coupon_id, cu.customer_id, cu.order_id, cu.discount_amount, cu.used_at
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.customer_id = $2 AND c.deleted_at IS NULL
		ORDER BY cu.used_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, customerID)
	if err != nil {
		return nil, fmt.Errorf("get usages by customer: %w", err)
	}
	defer rows.Close()
	var result []*discount.CouponUsage
	for rows.Next() {
		u, err := r.scanCouponUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetUsageByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*discount.CouponUsage, error) {
	query := `
		SELECT cu.usage_id, cu.coupon_id, cu.customer_id, cu.order_id, cu.discount_amount, cu.used_at
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.order_id = $2 AND c.deleted_at IS NULL
	`
	rows, err := db.QueryContext(ctx, query, companyID, orderID)
	if err != nil {
		return nil, fmt.Errorf("get usage by order: %w", err)
	}
	defer rows.Close()
	var result []*discount.CouponUsage
	for rows.Next() {
		u, err := r.scanCouponUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetTotalUsageCount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (int64, error) {
	var count int64
	query := `
		SELECT COUNT(*)
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.coupon_id = $2 AND c.deleted_at IS NULL
	`
	err := db.QueryRowContext(ctx, query, companyID, couponID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("get total usage count: %w", err)
	}
	return count, nil
}

func (r *couponRepository) GetCustomerUsageCount(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID) (int64, error) {
	var count int64
	query := `
		SELECT COUNT(*)
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.coupon_id = $2 AND cu.customer_id = $3 AND c.deleted_at IS NULL
	`
	err := db.QueryRowContext(ctx, query, companyID, couponID, customerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("get customer usage count: %w", err)
	}
	return count, nil
}

func (r *couponRepository) HasCustomerUsedCoupon(ctx context.Context, db DBTX, companyID, couponID, customerID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM sales.coupon_usages cu
			JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
			WHERE c.company_id = $1 AND cu.coupon_id = $2 AND cu.customer_id = $3 AND cu.order_id = $4 AND c.deleted_at IS NULL
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, couponID, customerID, orderID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has customer used coupon: %w", err)
	}
	return exists, nil
}

func (r *couponRepository) DeleteUsage(ctx context.Context, db DBTX, usageID uuid.UUID) error {
	query := `DELETE FROM sales.coupon_usages WHERE usage_id = $1`
	result, err := db.ExecContext(ctx, query, usageID)
	if err != nil {
		return fmt.Errorf("delete usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return saleserrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// DISCOUNT CALCULATION
// -------------------------------------------------------------------------

func (r *couponRepository) CalculateDiscount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error) {
	coupon, err := r.GetByID(ctx, db, companyID, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	var discount decimal.Decimal
	switch coupon.DiscountType {
	case enums.DiscountTypePercentage:
		discount = orderAmount.Mul(coupon.DiscountValue).Div(decimal.NewFromInt(100))
	case enums.DiscountTypeFixed:
		discount = coupon.DiscountValue
	default:
		discount = decimal.Zero
	}
	if coupon.MaxDiscountAmount != nil && discount.GreaterThan(*coupon.MaxDiscountAmount) {
		discount = *coupon.MaxDiscountAmount
	}
	if discount.GreaterThan(orderAmount) {
		discount = orderAmount
	}
	return discount, nil
}

func (r *couponRepository) GetMaximumDiscount(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error) {
	coupon, err := r.GetByID(ctx, db, companyID, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	max := orderAmount
	if coupon.MaxDiscountAmount != nil && max.GreaterThan(*coupon.MaxDiscountAmount) {
		max = *coupon.MaxDiscountAmount
	}
	return max, nil
}

// -------------------------------------------------------------------------
// QUERYING / LISTING
// -------------------------------------------------------------------------

func (r *couponRepository) List(ctx context.Context, db DBTX, filter CouponFilter, p Pagination, s Sort) ([]*discount.Coupon, int64, error) {
	where, args := r.buildCouponFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"code": true, "discount_value": true, "start_date": true, "end_date": true,
		"is_active": true, "created_at": true, "updated_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.coupons %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count coupons: %w", err)
	}
	if total == 0 {
		return []*discount.Coupon{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list coupons: %w", err)
	}
	defer rows.Close()

	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

func (r *couponRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*discount.Coupon, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.coupons
		WHERE company_id = $1 AND code ILIKE $2 AND deleted_at IS NULL
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*discount.Coupon{}, 0, nil
	}

	dataQuery := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND code ILIKE $2 AND deleted_at IS NULL
		ORDER BY code ASC
		LIMIT $3 OFFSET $4
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

func (r *couponRepository) GetActiveCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND is_active = true AND start_date <= $2 AND end_date >= $2 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get active coupons: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetExpiredCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND end_date < $2 AND deleted_at IS NULL
		ORDER BY end_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get expired coupons: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetCouponsExpiringSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND is_active = true AND end_date < $2 AND end_date >= NOW() AND deleted_at IS NULL
		ORDER BY end_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, before)
	if err != nil {
		return nil, fmt.Errorf("get coupons expiring soon: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// ANALYTICS / REPORTING (already join with deleted_at filter)
// -------------------------------------------------------------------------

func (r *couponRepository) GetTotalDiscountGiven(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("c.company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "c.deleted_at IS NULL")
	if from != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(cu.discount_amount), 0)
		FROM sales.coupon_usages cu
		JOIN sales.coupons c ON c.coupon_id = cu.coupon_id
		WHERE %s
	`, where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total discount given: %w", err)
	}
	return total, nil
}

func (r *couponRepository) GetTopCouponsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("c.company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "c.deleted_at IS NULL")
	if from != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT
			c.coupon_id, c.company_id, c.code, c.discount_type, c.discount_value,
			c.max_discount_amount, c.start_date, c.end_date, c.usage_limit, c.per_user_limit,
			c.min_order_amount, c.applicable_items, c.is_active, c.created_at, c.updated_at,
			c.created_by, c.updated_by, c.deleted_at, c.stacking_type
		FROM sales.coupons c
		JOIN sales.coupon_usages cu ON c.coupon_id = cu.coupon_id
		WHERE %s
		GROUP BY c.coupon_id
		ORDER BY COUNT(cu.usage_id) DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top coupons by usage: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetTopCouponsByDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("c.company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "c.deleted_at IS NULL")
	if from != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("cu.used_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT
			c.coupon_id, c.company_id, c.code, c.discount_type, c.discount_value,
			c.max_discount_amount, c.start_date, c.end_date, c.usage_limit, c.per_user_limit,
			c.min_order_amount, c.applicable_items, c.is_active, c.created_at, c.updated_at,
			c.created_by, c.updated_by, c.deleted_at, c.stacking_type
		FROM sales.coupons c
		JOIN sales.coupon_usages cu ON c.coupon_id = cu.coupon_id
		WHERE %s
		GROUP BY c.coupon_id
		ORDER BY SUM(cu.discount_amount) DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top coupons by discount amount: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *couponRepository) GetUnusedCoupons(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*discount.Coupon, error) {
	query := `
		SELECT
			c.coupon_id, c.company_id, c.code, c.discount_type, c.discount_value,
			c.max_discount_amount, c.start_date, c.end_date, c.usage_limit, c.per_user_limit,
			c.min_order_amount, c.applicable_items, c.is_active, c.created_at, c.updated_at,
			c.created_by, c.updated_by, c.deleted_at, c.stacking_type
		FROM sales.coupons c
		LEFT JOIN sales.coupon_usages cu ON c.coupon_id = cu.coupon_id
		WHERE c.company_id = $1 AND cu.usage_id IS NULL AND c.deleted_at IS NULL
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get unused coupons: %w", err)
	}
	defer rows.Close()
	var result []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// CONCURRENCY / LOCKING
// -------------------------------------------------------------------------

func (r *couponRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, couponID uuid.UUID) (*discount.Coupon, error) {
	query := `
		SELECT
			coupon_id, company_id, code, discount_type, discount_value,
			max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
			min_order_amount, applicable_items, is_active, created_at, updated_at,
			created_by, updated_by, deleted_at, stacking_type
		FROM sales.coupons
		WHERE company_id = $1 AND coupon_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, couponID)
	return r.scanCoupon(row)
}

func (r *couponRepository) GetApplicableCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error) {
	query := `
        SELECT coupon_id, company_id, code, discount_type, discount_value,
               max_discount_amount, start_date, end_date, usage_limit, per_user_limit,
               min_order_amount, applicable_items, is_active, created_at, updated_at,
               created_by, updated_by, deleted_at, stacking_type
        FROM sales.coupons
        WHERE company_id = $1
          AND is_active = true
          AND start_date <= $2
          AND end_date >= $2
          AND deleted_at IS NULL
    `
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get applicable coupons: %w", err)
	}
	defer rows.Close()

	var coupons []*discount.Coupon
	for rows.Next() {
		c, err := r.scanCoupon(rows)
		if err != nil {
			return nil, err
		}
		// Validate per-user limit
		if customerID != nil && c.PerUserLimit != nil {
			used, err := r.GetCustomerUsageCount(ctx, db, companyID, c.CouponID, *customerID)
			if err == nil && used >= int64(*c.PerUserLimit) {
				continue
			}
		}
		// Validate min order amount
		if c.MinOrderAmount != nil && orderAmount.LessThan(*c.MinOrderAmount) {
			continue
		}
		// Validate product applicability
		if len(productIDs) > 0 && len(c.ApplicableItems) > 0 && string(c.ApplicableItems) != "{}" {
			applicable := false
			for _, pid := range productIDs {
				if strings.Contains(string(c.ApplicableItems), pid.String()) {
					applicable = true
					break
				}
			}
			if !applicable {
				continue
			}
		}
		coupons = append(coupons, c)
	}
	return coupons, rows.Err()
}

func (r *couponRepository) GetBestCoupon(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error) {
	coupons, err := r.GetApplicableCoupons(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, decimal.Zero, err
	}
	var bestCoupon *discount.Coupon
	var bestDiscount decimal.Decimal
	for _, c := range coupons {
		amount, err := r.CalculateDiscount(ctx, db, companyID, c.CouponID, orderAmount)
		if err != nil {
			continue
		}
		if amount.GreaterThan(bestDiscount) {
			bestDiscount = amount
			bestCoupon = c
		}
	}
	return bestCoupon, bestDiscount, nil
}

// GetStackingType returns the stacking_type for a coupon
func (r *couponRepository) GetStackingType(ctx context.Context, db DBTX, couponID uuid.UUID) (string, error) {
	var stackingType string
	query := `SELECT stacking_type FROM sales.coupons WHERE coupon_id = $1 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, couponID).Scan(&stackingType)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", saleserrors.ErrNotFound
		}
		return "", fmt.Errorf("get stacking type: %w", err)
	}
	return stackingType, nil
}
