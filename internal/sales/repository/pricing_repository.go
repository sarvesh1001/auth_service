package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"gorm.io/datatypes"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/discount"
	"strings"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// PricingRepository Implementation
// -------------------------------------------------------------------------
type PricingRepository interface {

	// -------------------------------------------------------------------------
	// PRODUCT PRICING
	// -------------------------------------------------------------------------

	GetProductBasePrice(
		ctx context.Context,
		db DBTX,
		companyID, productID uuid.UUID,
	) (decimal.Decimal, error)

	GetProductsBasePrices(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		productIDs []uuid.UUID,
	) (map[uuid.UUID]decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// CUSTOMER PRICING
	// -------------------------------------------------------------------------

	GetCustomerCreditLimit(
		ctx context.Context,
		db DBTX,
		companyID, customerID uuid.UUID,
	) (decimal.Decimal, error)

	GetCustomerOutstandingBalance(
		ctx context.Context,
		db DBTX,
		companyID, customerID uuid.UUID,
	) (decimal.Decimal, error)

	CanCustomerPurchaseAmount(
		ctx context.Context,
		db DBTX,
		companyID, customerID uuid.UUID,
		amount decimal.Decimal,
	) (bool, error)

	// -------------------------------------------------------------------------
	// COUPON RESOLUTION
	// -------------------------------------------------------------------------

	GetApplicableCoupons(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		customerID *uuid.UUID,
		productIDs []uuid.UUID,
		orderAmount decimal.Decimal,
		at time.Time,
	) ([]*discount.Coupon, error)

	GetBestCoupon(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		customerID *uuid.UUID,
		productIDs []uuid.UUID,
		orderAmount decimal.Decimal,
		at time.Time,
	) (*discount.Coupon, decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// PROMOTION RESOLUTION
	// -------------------------------------------------------------------------

	GetApplicablePromotions(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		customerID *uuid.UUID,
		productIDs []uuid.UUID,
		orderAmount decimal.Decimal,
		at time.Time,
	) ([]*discount.Promotion, error)

	GetBestPromotion(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		customerID *uuid.UUID,
		productIDs []uuid.UUID,
		orderAmount decimal.Decimal,
		at time.Time,
	) (*discount.Promotion, decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// DISCOUNT CALCULATIONS
	// -------------------------------------------------------------------------

	CalculateCouponDiscount(
		ctx context.Context,
		db DBTX,
		coupon *discount.Coupon,
		orderAmount decimal.Decimal,
	) (decimal.Decimal, error)

	CalculatePromotionDiscount(
		ctx context.Context,
		db DBTX,
		promotion *discount.Promotion,
		rules []*discount.PromotionRule,
		orderAmount decimal.Decimal,
		productIDs []uuid.UUID,
	) (decimal.Decimal, error)

	CalculateCombinedDiscount(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		customerID *uuid.UUID,
		productIDs []uuid.UUID,
		orderAmount decimal.Decimal,
		at time.Time,
	) (
		totalDiscount decimal.Decimal,
		appliedCoupons []*discount.Coupon,
		appliedPromotions []*discount.Promotion,
		err error,
	)

	// -------------------------------------------------------------------------
	// TAX CALCULATIONS
	// -------------------------------------------------------------------------

	CalculateTaxAmount(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		entityType string,
		entityID uuid.UUID,
		taxableAmount decimal.Decimal,
	) (decimal.Decimal, error)

	CalculateLineTax(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		productID uuid.UUID,
		lineAmount decimal.Decimal,
	) (decimal.Decimal, error)

	CalculateOrderTax(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		orderID uuid.UUID,
	) (decimal.Decimal, error)

	CalculateInvoiceTax(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		invoiceID uuid.UUID,
	) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// PRICE PREVIEW / QUOTATION
	// -------------------------------------------------------------------------

	PreviewOrderPricing(
		ctx context.Context,
		db DBTX,
		input *PricingPreviewInput,
	) (*PricingPreviewResult, error)

	PreviewInvoicePricing(
		ctx context.Context,
		db DBTX,
		input *PricingPreviewInput,
	) (*PricingPreviewResult, error)

	// -------------------------------------------------------------------------
	// VALIDATION / POLICY
	// -------------------------------------------------------------------------

	ValidatePricing(
		ctx context.Context,
		db DBTX,
		input *PricingValidationInput,
	) error

	ValidateDiscountCombination(
		ctx context.Context,
		db DBTX,
		couponIDs []uuid.UUID,
		promotionIDs []uuid.UUID,
	) error

	// -------------------------------------------------------------------------
	// ANALYTICS / REPORTING
	// -------------------------------------------------------------------------

	GetAverageDiscountRate(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		from *time.Time,
		to *time.Time,
	) (decimal.Decimal, error)

	GetTotalDiscountAmount(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		from *time.Time,
		to *time.Time,
	) (decimal.Decimal, error)

	GetEffectiveRevenueAfterDiscounts(
		ctx context.Context,
		db DBTX,
		companyID uuid.UUID,
		from *time.Time,
		to *time.Time,
	) (decimal.Decimal, error)
}

type PricingPreviewInput struct {
	CompanyID uuid.UUID

	CustomerID *uuid.UUID

	ProductLines []*PricingProductLine

	CouponCodes []string

	OrderAmount decimal.Decimal

	Currency string

	PricedAt time.Time
}

type PricingProductLine struct {
	ProductID uuid.UUID

	Quantity decimal.Decimal

	UnitPrice decimal.Decimal
}

type PricingPreviewResult struct {
	Subtotal decimal.Decimal

	DiscountTotal decimal.Decimal

	TaxTotal decimal.Decimal

	GrandTotal decimal.Decimal

	AppliedCoupons []*discount.Coupon

	AppliedPromotions []*discount.Promotion

	TaxSnapshots []*models.TaxSnapshot
}

type PricingValidationInput struct {
	CompanyID uuid.UUID

	CustomerID *uuid.UUID

	ProductIDs []uuid.UUID

	CouponIDs []uuid.UUID

	PromotionIDs []uuid.UUID

	OrderAmount decimal.Decimal

	ValidateCreditLimit bool

	ValidateCouponRules bool

	ValidatePromotionRules bool
}
type pricingRepository struct {
	logger *zap.Logger
}

func NewPricingRepository(logger *zap.Logger) PricingRepository {
	return &pricingRepository{
		logger: logger.Named("sales_pricing_repo"),
	}
}

// -------------------------------------------------------------------------
// PRODUCT PRICING
// -------------------------------------------------------------------------

func (r *pricingRepository) GetProductBasePrice(ctx context.Context, db DBTX, companyID, productID uuid.UUID) (decimal.Decimal, error) {
	query := `SELECT unit_price FROM sales.products WHERE company_id = $1 AND product_id = $2 AND is_active = true`
	var price decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, productID).Scan(&price)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		r.logger.Error("failed to get product base price", zap.Error(err))
		return decimal.Zero, fmt.Errorf("get product base price: %w", err)
	}
	return price, nil
}

func (r *pricingRepository) GetProductsBasePrices(ctx context.Context, db DBTX, companyID uuid.UUID, productIDs []uuid.UUID) (map[uuid.UUID]decimal.Decimal, error) {
	if len(productIDs) == 0 {
		return make(map[uuid.UUID]decimal.Decimal), nil
	}
	placeholders := make([]string, len(productIDs))
	args := make([]interface{}, 0, len(productIDs)+1)
	args = append(args, companyID)
	for i, id := range productIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	query := fmt.Sprintf(`
		SELECT product_id, unit_price
		FROM sales.products
		WHERE company_id = $1 AND product_id IN (%s) AND is_active = true
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get products base prices", zap.Error(err))
		return nil, fmt.Errorf("get products base prices: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]decimal.Decimal)
	for rows.Next() {
		var pid uuid.UUID
		var price decimal.Decimal
		if err := rows.Scan(&pid, &price); err != nil {
			return nil, fmt.Errorf("scan product price: %w", err)
		}
		result[pid] = price
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// CUSTOMER PRICING
// -------------------------------------------------------------------------

func (r *pricingRepository) GetCustomerCreditLimit(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	query := `SELECT COALESCE(credit_limit, 0) FROM sales.customers WHERE company_id = $1 AND customer_id = $2`
	var limit decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&limit)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		r.logger.Error("failed to get customer credit limit", zap.Error(err))
		return decimal.Zero, fmt.Errorf("get customer credit limit: %w", err)
	}
	return limit, nil
}

func (r *pricingRepository) GetCustomerOutstandingBalance(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount_due), 0)
		FROM sales.invoices
		WHERE company_id = $1 AND customer_id = $2 AND status NOT IN ('paid', 'cancelled')
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&balance)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, nil
		}
		r.logger.Error("failed to get customer outstanding balance", zap.Error(err))
		return decimal.Zero, fmt.Errorf("get customer outstanding balance: %w", err)
	}
	return balance, nil
}

func (r *pricingRepository) CanCustomerPurchaseAmount(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, amount decimal.Decimal) (bool, error) {
	creditLimit, err := r.GetCustomerCreditLimit(ctx, db, companyID, customerID)
	if err != nil {
		if err == salesErrors.ErrNotFound {
			// No credit limit means unlimited
			return true, nil
		}
		return false, err
	}
	if creditLimit.IsZero() {
		return true, nil
	}
	outstanding, err := r.GetCustomerOutstandingBalance(ctx, db, companyID, customerID)
	if err != nil {
		return false, err
	}
	newTotal := outstanding.Add(amount)
	return newTotal.LessThanOrEqual(creditLimit), nil
}

// -------------------------------------------------------------------------
// COUPON RESOLUTION
// -------------------------------------------------------------------------

func (r *pricingRepository) GetApplicableCoupons(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error) {
	// Base query: active coupons valid at the given time
	query := `
		SELECT coupon_id, company_id, code, discount_type, discount_value, max_discount_amount,
		       start_date, end_date, usage_limit, per_user_limit, min_order_amount, applicable_items,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM sales.coupons
		WHERE company_id = $1
		  AND is_active = true
		  AND start_date <= $2
		  AND end_date >= $2
	`
	args := []interface{}{companyID, at}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to fetch applicable coupons", zap.Error(err))
		return nil, fmt.Errorf("get applicable coupons: %w", err)
	}
	defer rows.Close()

	var coupons []*discount.Coupon
	for rows.Next() {
		var c discount.Coupon
		// Use datatypes.JSON directly – it implements sql.Scanner
		var applicableItems datatypes.JSON
		err := rows.Scan(
			&c.CouponID, &c.CompanyID, &c.Code, &c.DiscountType, &c.DiscountValue, &c.MaxDiscountAmount,
			&c.StartDate, &c.EndDate, &c.UsageLimit, &c.PerUserLimit, &c.MinOrderAmount, &applicableItems,
			&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy, &c.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan coupon: %w", err)
		}
		// Assign the scanned value
		c.ApplicableItems = applicableItems
		coupons = append(coupons, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Filter by min_order_amount
	var filtered []*discount.Coupon
	for _, c := range coupons {
		if c.MinOrderAmount != nil && orderAmount.LessThan(*c.MinOrderAmount) {
			continue
		}
		// TODO: filter by applicable_items (productIDs) if needed
		filtered = append(filtered, c)
	}
	return filtered, nil
}
func (r *pricingRepository) GetBestCoupon(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error) {
	coupons, err := r.GetApplicableCoupons(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if len(coupons) == 0 {
		return nil, decimal.Zero, nil
	}
	var bestCoupon *discount.Coupon
	bestDiscount := decimal.Zero
	for _, c := range coupons {
		discountAmount, err := r.CalculateCouponDiscount(ctx, db, c, orderAmount)
		if err != nil {
			r.logger.Warn("failed to calculate coupon discount", zap.String("coupon_id", c.CouponID.String()), zap.Error(err))
			continue
		}
		if discountAmount.GreaterThan(bestDiscount) {
			bestDiscount = discountAmount
			bestCoupon = c
		}
	}
	return bestCoupon, bestDiscount, nil
}

// -------------------------------------------------------------------------
// PROMOTION RESOLUTION
// -------------------------------------------------------------------------

func (r *pricingRepository) GetApplicablePromotions(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description, start_date, end_date, is_active, priority,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		  AND is_active = true
		  AND start_date <= $2
		  AND end_date >= $2
		ORDER BY priority DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		r.logger.Error("failed to fetch applicable promotions", zap.Error(err))
		return nil, fmt.Errorf("get applicable promotions: %w", err)
	}
	defer rows.Close()

	var promotions []*discount.Promotion
	for rows.Next() {
		var p discount.Promotion
		err := rows.Scan(
			&p.PromotionID, &p.CompanyID, &p.Name, &p.Description, &p.StartDate, &p.EndDate,
			&p.IsActive, &p.Priority, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan promotion: %w", err)
		}
		promotions = append(promotions, &p)
	}
	return promotions, rows.Err()
}

func (r *pricingRepository) GetBestPromotion(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error) {
	promotions, err := r.GetApplicablePromotions(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if len(promotions) == 0 {
		return nil, decimal.Zero, nil
	}
	var bestPromo *discount.Promotion
	bestDiscount := decimal.Zero
	for _, p := range promotions {
		rules, err := r.getPromotionRules(ctx, db, p.PromotionID)
		if err != nil {
			r.logger.Warn("failed to get promotion rules", zap.String("promotion_id", p.PromotionID.String()), zap.Error(err))
			continue
		}
		discountAmount, err := r.CalculatePromotionDiscount(ctx, db, p, rules, orderAmount, productIDs)
		if err != nil {
			r.logger.Warn("failed to calculate promotion discount", zap.Error(err))
			continue
		}
		if discountAmount.GreaterThan(bestDiscount) {
			bestDiscount = discountAmount
			bestPromo = p
		}
	}
	return bestPromo, bestDiscount, nil
}

func (r *pricingRepository) getPromotionRules(ctx context.Context, db DBTX, promotionID uuid.UUID) ([]*discount.PromotionRule, error) {
	query := `
		SELECT rule_id, promotion_id, rule_type, rule_config, discount_type, discount_value, max_discount, created_at
		FROM sales.promotion_rules
		WHERE promotion_id = $1
	`
	rows, err := db.QueryContext(ctx, query, promotionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*discount.PromotionRule
	for rows.Next() {
		var rule discount.PromotionRule
		var ruleConfig datatypes.JSON
		err := rows.Scan(
			&rule.RuleID, &rule.PromotionID, &rule.RuleType, &ruleConfig,
			&rule.DiscountType, &rule.DiscountValue, &rule.MaxDiscount, &rule.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan promotion rule: %w", err)
		}
		rule.RuleConfig = ruleConfig
		rules = append(rules, &rule)
	}
	return rules, rows.Err()
}

// -------------------------------------------------------------------------
// DISCOUNT CALCULATIONS
// -------------------------------------------------------------------------

func (r *pricingRepository) CalculateCouponDiscount(ctx context.Context, db DBTX, coupon *discount.Coupon, orderAmount decimal.Decimal) (decimal.Decimal, error) {
	switch coupon.DiscountType {
	case "percentage":
		discount := orderAmount.Mul(coupon.DiscountValue.Div(decimal.NewFromInt(100)))
		if coupon.MaxDiscountAmount != nil && discount.GreaterThan(*coupon.MaxDiscountAmount) {
			discount = *coupon.MaxDiscountAmount
		}
		return discount, nil
	case "fixed_amount":
		if coupon.DiscountValue.GreaterThan(orderAmount) {
			return orderAmount, nil
		}
		return coupon.DiscountValue, nil
	default:
		return decimal.Zero, fmt.Errorf("unsupported discount type: %s", coupon.DiscountType)
	}
}

func (r *pricingRepository) CalculatePromotionDiscount(ctx context.Context, db DBTX, promotion *discount.Promotion, rules []*discount.PromotionRule, orderAmount decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	// Simplistic: sum discounts from all rules (buy_x_get_y not implemented)
	total := decimal.Zero
	for _, rule := range rules {
		var discount decimal.Decimal
		switch rule.DiscountType {
		case "percentage":
			discount = orderAmount.Mul(rule.DiscountValue.Div(decimal.NewFromInt(100)))
			if rule.MaxDiscount != nil && discount.GreaterThan(*rule.MaxDiscount) {
				discount = *rule.MaxDiscount
			}
		case "fixed_amount":
			if rule.DiscountValue.GreaterThan(orderAmount) {
				discount = orderAmount
			} else {
				discount = rule.DiscountValue
			}
		default:
			continue
		}
		total = total.Add(discount)
	}
	if total.GreaterThan(orderAmount) {
		total = orderAmount
	}
	return total, nil
}

func (r *pricingRepository) CalculateCombinedDiscount(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (decimal.Decimal, []*discount.Coupon, []*discount.Promotion, error) {
	// Best coupon
	bestCoupon, couponDiscount, err := r.GetBestCoupon(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return decimal.Zero, nil, nil, err
	}
	// Best promotion
	bestPromo, promoDiscount, err := r.GetBestPromotion(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return decimal.Zero, nil, nil, err
	}
	// In real world you might combine, but for simplicity take the higher
	var totalDiscount decimal.Decimal
	var appliedCoupons []*discount.Coupon
	var appliedPromotions []*discount.Promotion
	if couponDiscount.GreaterThan(promoDiscount) {
		totalDiscount = couponDiscount
		if bestCoupon != nil {
			appliedCoupons = []*discount.Coupon{bestCoupon}
		}
	} else {
		totalDiscount = promoDiscount
		if bestPromo != nil {
			appliedPromotions = []*discount.Promotion{bestPromo}
		}
	}
	if totalDiscount.GreaterThan(orderAmount) {
		totalDiscount = orderAmount
	}
	return totalDiscount, appliedCoupons, appliedPromotions, nil
}

// -------------------------------------------------------------------------
// TAX CALCULATIONS
// -------------------------------------------------------------------------

// Stub – you need to implement based on your tax table (e.g., accounting.tax_rates)
func (r *pricingRepository) CalculateTaxAmount(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, taxableAmount decimal.Decimal) (decimal.Decimal, error) {
	// Example: fetch tax rate from a tax_rates table (replace with actual)
	// For now, return 0 (no tax)
	return decimal.Zero, nil
}

func (r *pricingRepository) CalculateLineTax(ctx context.Context, db DBTX, companyID uuid.UUID, productID uuid.UUID, lineAmount decimal.Decimal) (decimal.Decimal, error) {
	// Similar stub
	return decimal.Zero, nil
}

func (r *pricingRepository) CalculateOrderTax(ctx context.Context, db DBTX, companyID uuid.UUID, orderID uuid.UUID) (decimal.Decimal, error) {
	// Sum tax_amount from order_items? Or use tax_snapshots
	query := `SELECT COALESCE(SUM(tax_amount), 0) FROM sales.order_items WHERE order_id = $1`
	var tax decimal.Decimal
	err := db.QueryRowContext(ctx, query, orderID).Scan(&tax)
	if err != nil {
		return decimal.Zero, fmt.Errorf("calculate order tax: %w", err)
	}
	return tax, nil
}

func (r *pricingRepository) CalculateInvoiceTax(ctx context.Context, db DBTX, companyID uuid.UUID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	query := `SELECT COALESCE(SUM(tax_amount), 0) FROM sales.invoice_items WHERE invoice_id = $1`
	var tax decimal.Decimal
	err := db.QueryRowContext(ctx, query, invoiceID).Scan(&tax)
	if err != nil {
		return decimal.Zero, fmt.Errorf("calculate invoice tax: %w", err)
	}
	return tax, nil
}

// -------------------------------------------------------------------------
// PRICE PREVIEW / QUOTATION
// -------------------------------------------------------------------------

func (r *pricingRepository) PreviewOrderPricing(ctx context.Context, db DBTX, input *PricingPreviewInput) (*PricingPreviewResult, error) {
	// Compute subtotal from product lines
	subtotal := decimal.Zero
	for _, line := range input.ProductLines {
		lineTotal := line.UnitPrice.Mul(line.Quantity)
		subtotal = subtotal.Add(lineTotal)
	}
	// Apply best discount
	productIDs := make([]uuid.UUID, len(input.ProductLines))
	for i, line := range input.ProductLines {
		productIDs[i] = line.ProductID
	}
	discountTotal, appliedCoupons, appliedPromotions, err := r.CalculateCombinedDiscount(ctx, db, input.CompanyID, input.CustomerID, productIDs, subtotal, input.PricedAt)
	if err != nil {
		return nil, err
	}
	afterDiscount := subtotal.Sub(discountTotal)
	// Calculate tax (stub)
	taxTotal, err := r.CalculateTaxAmount(ctx, db, input.CompanyID, "order_preview", uuid.Nil, afterDiscount)
	if err != nil {
		return nil, err
	}
	grandTotal := afterDiscount.Add(taxTotal)
	return &PricingPreviewResult{
		Subtotal:          subtotal,
		DiscountTotal:     discountTotal,
		TaxTotal:          taxTotal,
		GrandTotal:        grandTotal,
		AppliedCoupons:    appliedCoupons,
		AppliedPromotions: appliedPromotions,
		TaxSnapshots:      nil,
	}, nil
}

func (r *pricingRepository) PreviewInvoicePricing(ctx context.Context, db DBTX, input *PricingPreviewInput) (*PricingPreviewResult, error) {
	// Same as order preview for now
	return r.PreviewOrderPricing(ctx, db, input)
}

// -------------------------------------------------------------------------
// VALIDATION / POLICY
// -------------------------------------------------------------------------

func (r *pricingRepository) ValidatePricing(ctx context.Context, db DBTX, input *PricingValidationInput) error {
	// Validate credit limit
	if input.ValidateCreditLimit && input.CustomerID != nil {
		ok, err := r.CanCustomerPurchaseAmount(ctx, db, input.CompanyID, *input.CustomerID, input.OrderAmount)
		if err != nil {
			return err
		}
		if !ok {
			return salesErrors.ErrConflict // or a specific error
		}
	}
	// Validate coupon rules (e.g., usage limits)
	if input.ValidateCouponRules {
		for _, couponID := range input.CouponIDs {
			// Check coupon exists and is valid
			var count int
			query := `SELECT COUNT(*) FROM sales.coupons WHERE company_id = $1 AND coupon_id = $2 AND is_active = true AND start_date <= NOW() AND end_date >= NOW()`
			err := db.QueryRowContext(ctx, query, input.CompanyID, couponID).Scan(&count)
			if err != nil {
				return err
			}
			if count == 0 {
				return salesErrors.ErrCouponExpired
			}
			// Check usage limit per customer if customer is given
			if input.CustomerID != nil {
				var usageCount int
				usageQuery := `SELECT COUNT(*) FROM sales.coupon_usages WHERE coupon_id = $1 AND customer_id = $2`
				err := db.QueryRowContext(ctx, usageQuery, couponID, *input.CustomerID).Scan(&usageCount)
				if err != nil {
					return err
				}
				// Get per_user_limit from coupon (simplified)
				var perUserLimit *int
				err = db.QueryRowContext(ctx, `SELECT per_user_limit FROM sales.coupons WHERE coupon_id = $1`, couponID).Scan(&perUserLimit)
				if err == nil && perUserLimit != nil && usageCount >= *perUserLimit {
					return salesErrors.ErrCouponUsageLimit
				}
			}
		}
	}
	// Validate promotion rules
	if input.ValidatePromotionRules {
		for _, promoID := range input.PromotionIDs {
			var count int
			query := `SELECT COUNT(*) FROM sales.promotions WHERE company_id = $1 AND promotion_id = $2 AND is_active = true AND start_date <= NOW() AND end_date >= NOW()`
			err := db.QueryRowContext(ctx, query, input.CompanyID, promoID).Scan(&count)
			if err != nil {
				return err
			}
			if count == 0 {
				return salesErrors.ErrPromotionInactive
			}
		}
	}
	return nil
}

func (r *pricingRepository) ValidateDiscountCombination(ctx context.Context, db DBTX, couponIDs []uuid.UUID, promotionIDs []uuid.UUID) error {
	// For simplicity, assume any combination is allowed
	return nil
}

// -------------------------------------------------------------------------
// ANALYTICS / REPORTING
// -------------------------------------------------------------------------

func (r *pricingRepository) GetAverageDiscountRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	where := "company_id = $1"
	args := []interface{}{companyID}
	argIdx := 2
	if from != nil {
		where += fmt.Sprintf(" AND order_date >= $%d", argIdx)
		args = append(args, *from)
		argIdx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND order_date <= $%d", argIdx)
		args = append(args, *to)
	}
	query := fmt.Sprintf(`
		SELECT COALESCE(AVG(discount_total / NULLIF(subtotal, 0)) * 100, 0)
		FROM sales.orders
		WHERE %s AND subtotal > 0
	`, where)
	var avg decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get average discount rate: %w", err)
	}
	return avg, nil
}

func (r *pricingRepository) GetTotalDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	where := "company_id = $1"
	args := []interface{}{companyID}
	argIdx := 2
	if from != nil {
		where += fmt.Sprintf(" AND order_date >= $%d", argIdx)
		args = append(args, *from)
		argIdx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND order_date <= $%d", argIdx)
		args = append(args, *to)
	}
	query := fmt.Sprintf("SELECT COALESCE(SUM(discount_total), 0) FROM sales.orders WHERE %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total discount amount: %w", err)
	}
	return total, nil
}

func (r *pricingRepository) GetEffectiveRevenueAfterDiscounts(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	where := "company_id = $1"
	args := []interface{}{companyID}
	argIdx := 2
	if from != nil {
		where += fmt.Sprintf(" AND order_date >= $%d", argIdx)
		args = append(args, *from)
		argIdx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND order_date <= $%d", argIdx)
		args = append(args, *to)
	}
	query := fmt.Sprintf("SELECT COALESCE(SUM(grand_total), 0) FROM sales.orders WHERE %s", where)
	var revenue decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&revenue)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get effective revenue: %w", err)
	}
	return revenue, nil
}
