package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/repository"
)

// PricingService orchestrates price resolution, discount application, tax calculation,
// and credit validation for orders, quotes, and invoices.
type PricingService interface {
	// Base price resolution
	GetProductBasePrice(ctx context.Context, companyID, productID uuid.UUID) (decimal.Decimal, error)
	GetProductsBasePrices(ctx context.Context, companyID uuid.UUID, productIDs []uuid.UUID) (map[uuid.UUID]decimal.Decimal, error)

	// Order pricing
	CalculateOrderPricing(ctx context.Context, req *CalculateOrderPricingRequest) (*PricingCalculationResult, error)
	PreviewOrderPricing(ctx context.Context, req *OrderPricingPreviewRequest) (*PricingPreviewResult, error)
	CalculateOrderTax(ctx context.Context, companyID, orderID uuid.UUID) (decimal.Decimal, error)
	CalculateOrderDiscounts(ctx context.Context, companyID, orderID uuid.UUID, at time.Time) (*DiscountCalculationResult, error)

	// Quote pricing
	CalculateQuotePricing(ctx context.Context, req *CalculateQuotePricingRequest) (*PricingCalculationResult, error)
	PreviewQuotePricing(ctx context.Context, req *QuotePricingPreviewRequest) (*PricingPreviewResult, error)
	CalculateQuoteTax(ctx context.Context, companyID, quoteID uuid.UUID) (decimal.Decimal, error)
	CalculateQuoteDiscounts(ctx context.Context, companyID, quoteID uuid.UUID, at time.Time) (*DiscountCalculationResult, error)

	// Invoice pricing
	CalculateInvoicePricing(ctx context.Context, req *CalculateInvoicePricingRequest) (*PricingCalculationResult, error)
	PreviewInvoicePricing(ctx context.Context, req *InvoicePricingPreviewRequest) (*PricingPreviewResult, error)
	CalculateInvoiceTax(ctx context.Context, companyID, invoiceID uuid.UUID) (decimal.Decimal, error)
	CalculateInvoiceDiscounts(ctx context.Context, companyID, invoiceID uuid.UUID, at time.Time) (*DiscountCalculationResult, error)

	// Tax calculations
	CalculateLineTax(ctx context.Context, companyID, productID uuid.UUID, lineAmount decimal.Decimal) (decimal.Decimal, error)
	CalculateTaxAmount(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, taxableAmount decimal.Decimal) (decimal.Decimal, error)

	// Discount engine integration
	GetApplicableCoupons(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error)
	GetBestCoupon(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error)
	GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error)
	GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error)
	CalculateCombinedDiscount(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*DiscountCalculationResult, error)
	ValidateDiscountCombination(ctx context.Context, companyID uuid.UUID, couponIDs, promotionIDs []uuid.UUID) error // FIXED: added companyID

	// Credit validation
	GetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetCustomerOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	CanCustomerPurchaseAmount(ctx context.Context, companyID, customerID uuid.UUID, amount decimal.Decimal) (bool, error)

	// Validation
	ValidatePricing(ctx context.Context, req *PricingValidationRequest) error
	ValidateOrderPricing(ctx context.Context, companyID, orderID uuid.UUID) error
	ValidateQuotePricing(ctx context.Context, companyID, quoteID uuid.UUID) error
	ValidateInvoicePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error

	// Analytics
	GetAverageDiscountRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetEffectiveRevenueAfterDiscounts(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
}

// pricingService implements PricingService.
type pricingService struct {
	pricingRepo   repository.PricingRepository
	productRepo   repository.ProductRepository
	couponRepo    repository.CouponRepository
	promotionRepo repository.PromotionRepository
	orderRepo     repository.OrderRepository
	quoteRepo     repository.QuoteRepository
	invoiceRepo   repository.InvoiceRepository
	customerSvc   CustomerService
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

// NewPricingService creates a new PricingService instance.
func NewPricingService(
	pricingRepo repository.PricingRepository,
	productRepo repository.ProductRepository,
	couponRepo repository.CouponRepository,
	promotionRepo repository.PromotionRepository,
	orderRepo repository.OrderRepository,
	quoteRepo repository.QuoteRepository,
	invoiceRepo repository.InvoiceRepository,
	customerSvc CustomerService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PricingService {
	return &pricingService{
		pricingRepo:   pricingRepo,
		productRepo:   productRepo,
		couponRepo:    couponRepo,
		promotionRepo: promotionRepo,
		orderRepo:     orderRepo,
		quoteRepo:     quoteRepo,
		invoiceRepo:   invoiceRepo,
		customerSvc:   customerSvc,
		pgClient:      pgClient,
		logger:        logger.Named("pricing_service"),
	}
}

// ---------------------------------------------------------------------
// Base price resolution
// ---------------------------------------------------------------------

func (s *pricingService) GetProductBasePrice(ctx context.Context, companyID, productID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.productRepo.GetUnitPrice(ctx, db, companyID, productID)
}

func (s *pricingService) GetProductsBasePrices(ctx context.Context, companyID uuid.UUID, productIDs []uuid.UUID) (map[uuid.UUID]decimal.Decimal, error) {
	db := s.pgClient.DB
	result := make(map[uuid.UUID]decimal.Decimal, len(productIDs))
	for _, pid := range productIDs {
		price, err := s.productRepo.GetUnitPrice(ctx, db, companyID, pid)
		if err != nil {
			return nil, fmt.Errorf("get price for product %s: %w", pid, err)
		}
		result[pid] = price
	}
	return result, nil
}

// ---------------------------------------------------------------------
// Order pricing
// ---------------------------------------------------------------------

func (s *pricingService) CalculateOrderPricing(ctx context.Context, req *CalculateOrderPricingRequest) (*PricingCalculationResult, error) {
	if err := s.validatePricingRequest(req.CompanyID, req.CustomerID, req.Lines); err != nil {
		return nil, err
	}
	at := req.At
	if at.IsZero() {
		at = time.Now()
	}

	db := s.pgClient.DB

	// 1. Compute subtotal from lines (using base price if UnitPrice not given)
	linesRes := make([]*PricingLineResult, 0, len(req.Lines))
	var subtotal decimal.Decimal
	for _, line := range req.Lines {
		unitPrice := line.UnitPrice
		if unitPrice == nil {
			base, err := s.productRepo.GetUnitPrice(ctx, db, req.CompanyID, line.ProductID)
			if err != nil {
				return nil, fmt.Errorf("get base price for product %s: %w", line.ProductID, err)
			}
			unitPrice = &base
		}
		lineSubtotal := unitPrice.Mul(line.Quantity)
		subtotal = subtotal.Add(lineSubtotal)

		linesRes = append(linesRes, &PricingLineResult{
			ProductID:       line.ProductID,
			Quantity:        line.Quantity,
			BasePrice:       *unitPrice,
			FinalLineAmount: lineSubtotal,
		})
	}

	// 2. Get discount result (combined coupons + promotions)
	productIDs := make([]uuid.UUID, len(req.Lines))
	for i, l := range req.Lines {
		productIDs[i] = l.ProductID
	}
	discountRes, err := s.CalculateCombinedDiscount(ctx, req.CompanyID, req.CustomerID, productIDs, subtotal, at)
	if err != nil {
		return nil, fmt.Errorf("calculate combined discount: %w", err)
	}

	// 3. Apply discount to each line proportionally
	discountRemaining := discountRes.DiscountTotal
	for _, lineRes := range linesRes {
		lineSubtotal := lineRes.BasePrice.Mul(lineRes.Quantity)
		if subtotal.IsZero() {
			continue
		}
		lineDiscount := discountRes.DiscountTotal.Mul(lineSubtotal.Div(subtotal))
		if lineDiscount.GreaterThan(discountRemaining) {
			lineDiscount = discountRemaining
		}
		lineRes.DiscountAmount = lineDiscount
		discountRemaining = discountRemaining.Sub(lineDiscount)
		lineRes.FinalLineAmount = lineSubtotal.Sub(lineDiscount)
	}

	// 4. Calculate tax if requested
	var taxTotal decimal.Decimal
	if req.CalculateTax {
		for i, lineRes := range linesRes {
			tax, err := s.pricingRepo.CalculateLineTax(ctx, db, req.CompanyID, linesRes[i].ProductID, lineRes.FinalLineAmount)
			if err != nil {
				return nil, fmt.Errorf("calculate line tax for product %s: %w", lineRes.ProductID, err)
			}
			lineRes.TaxAmount = tax
			taxTotal = taxTotal.Add(tax)
			lineRes.FinalLineAmount = lineRes.FinalLineAmount.Add(tax)
		}
	}

	grandTotal := subtotal.Sub(discountRes.DiscountTotal).Add(taxTotal)

	return &PricingCalculationResult{
		Subtotal:          subtotal,
		DiscountTotal:     discountRes.DiscountTotal,
		TaxTotal:          taxTotal,
		GrandTotal:        grandTotal,
		LineResults:       linesRes,
		AppliedCoupons:    discountRes.AppliedCoupons,
		AppliedPromotions: discountRes.AppliedPromotions,
	}, nil
}

// PreviewOrderPricing calculates a pricing preview using the repository.
func (s *pricingService) PreviewOrderPricing(ctx context.Context, req *OrderPricingPreviewRequest) (*PricingPreviewResult, error) {
	logger := s.logger.With(
		zap.String("method", "PreviewOrderPricing"),
		zap.String("company_id", req.CompanyID.String()),
	)
	logger.Info("service entry")

	// 1. Set pricing timestamp
	at := req.At
	if at == nil || at.IsZero() {
		now := time.Now()
		at = &now
		logger.Debug("using current time for pricing", zap.Time("at", *at))
	} else {
		logger.Debug("using provided timestamp", zap.Time("at", *at))
	}

	db := s.pgClient.DB

	// 2. Build product lines with unit prices
	lines := make([]*repository.PricingProductLine, len(req.Items))
	for i, it := range req.Items {
		unitPrice := it.UnitPrice
		if unitPrice == nil {
			logger.Debug("no unit price provided, fetching base price", zap.String("product_id", it.ProductID.String()))
			base, err := s.productRepo.GetUnitPrice(ctx, db, req.CompanyID, it.ProductID)
			if err != nil {
				logger.Error("failed to get base price", zap.Error(err), zap.String("product_id", it.ProductID.String()))
				return nil, fmt.Errorf("get base price for product %s: %w", it.ProductID, err)
			}
			unitPrice = &base
			logger.Debug("base price fetched", zap.String("product_id", it.ProductID.String()), zap.String("base_price", base.String()))
		} else {
			logger.Debug("using provided unit price", zap.String("product_id", it.ProductID.String()), zap.String("unit_price", unitPrice.String()))
		}
		lines[i] = &repository.PricingProductLine{
			ProductID: it.ProductID,
			Quantity:  it.Quantity,
			UnitPrice: *unitPrice,
		}
	}

	// 3. Prepare repository input
	input := &repository.PricingPreviewInput{
		CompanyID:    req.CompanyID,
		CustomerID:   req.CustomerID,
		ProductLines: lines,
		CouponCodes:  req.CouponCodes,
		PricedAt:     *at,
	}
	logger.Debug("calling pricingRepo.PreviewOrderPricing",
		zap.Int("product_count", len(input.ProductLines)),
		zap.Strings("coupon_codes", input.CouponCodes))

	// 4. Call repository
	preview, err := s.pricingRepo.PreviewOrderPricing(ctx, db, input)
	if err != nil {
		logger.Error("repository error", zap.Error(err))
		return nil, err
	}

	logger.Info("service returning success",
		zap.String("subtotal", preview.Subtotal.String()),
		zap.String("discount_total", preview.DiscountTotal.String()),
		zap.String("grand_total", preview.GrandTotal.String()))

	return &PricingPreviewResult{
		Subtotal:          preview.Subtotal,
		DiscountTotal:     preview.DiscountTotal,
		TaxTotal:          preview.TaxTotal,
		GrandTotal:        preview.GrandTotal,
		AppliedCoupons:    preview.AppliedCoupons,
		AppliedPromotions: preview.AppliedPromotions,
	}, nil
}
func (s *pricingService) CalculateOrderTax(ctx context.Context, companyID, orderID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.CalculateOrderTax(ctx, db, companyID, orderID)
}

func (s *pricingService) CalculateOrderDiscounts(ctx context.Context, companyID, orderID uuid.UUID, at time.Time) (*DiscountCalculationResult, error) {
	db := s.pgClient.DB
	order, err := s.orderRepo.GetByID(ctx, db, companyID, orderID)
	if err != nil {
		return nil, err
	}
	items, err := s.orderRepo.GetItems(ctx, db, companyID, orderID)
	if err != nil {
		return nil, err
	}
	productIDs := make([]uuid.UUID, len(items))
	for i, it := range items {
		productIDs[i] = it.ProductID
	}
	return s.CalculateCombinedDiscount(ctx, companyID, &order.CustomerID, productIDs, order.Subtotal, at)
}

// ---------------------------------------------------------------------
// Quote pricing
// ---------------------------------------------------------------------

func (s *pricingService) CalculateQuotePricing(ctx context.Context, req *CalculateQuotePricingRequest) (*PricingCalculationResult, error) {
	orderReq := &CalculateOrderPricingRequest{
		CompanyID:    req.CompanyID,
		CustomerID:   req.CustomerID,
		Lines:        req.Lines,
		CouponCodes:  req.CouponCodes,
		CalculateTax: req.CalculateTax,
		At:           req.At,
	}
	return s.CalculateOrderPricing(ctx, orderReq)
}

func (s *pricingService) PreviewQuotePricing(ctx context.Context, req *QuotePricingPreviewRequest) (*PricingPreviewResult, error) {
	orderPreviewReq := &OrderPricingPreviewRequest{
		CompanyID:   req.CompanyID,
		CustomerID:  req.CustomerID,
		Items:       make([]*CreateOrderItemRequest, len(req.Items)),
		CouponCodes: req.CouponCodes,
		At:          req.At,
	}
	for i, it := range req.Items {
		orderPreviewReq.Items[i] = &CreateOrderItemRequest{
			ProductID:      it.ProductID,
			Quantity:       it.Quantity,
			UnitPrice:      it.UnitPrice,
			DiscountAmount: it.DiscountAmount,
			Metadata:       it.Metadata,
		}
	}
	return s.PreviewOrderPricing(ctx, orderPreviewReq)
}

func (s *pricingService) CalculateQuoteTax(ctx context.Context, companyID, quoteID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	_, err := s.quoteRepo.GetByID(ctx, db, companyID, quoteID)
	if err != nil {
		return decimal.Zero, err
	}
	items, err := s.quoteRepo.GetItems(ctx, db, companyID, quoteID)
	if err != nil {
		return decimal.Zero, err
	}
	var taxTotal decimal.Decimal
	for _, it := range items {
		tax, err := s.pricingRepo.CalculateLineTax(ctx, db, companyID, it.ProductID, it.UnitPrice.Mul(it.Quantity).Sub(it.DiscountAmount))
		if err != nil {
			return decimal.Zero, err
		}
		taxTotal = taxTotal.Add(tax)
	}
	return taxTotal, nil
}

func (s *pricingService) CalculateQuoteDiscounts(ctx context.Context, companyID, quoteID uuid.UUID, at time.Time) (*DiscountCalculationResult, error) {
	db := s.pgClient.DB
	quote, err := s.quoteRepo.GetByID(ctx, db, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	items, err := s.quoteRepo.GetItems(ctx, db, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	productIDs := make([]uuid.UUID, len(items))
	for i, it := range items {
		productIDs[i] = it.ProductID
	}
	return s.CalculateCombinedDiscount(ctx, companyID, &quote.CustomerID, productIDs, quote.Subtotal, at)
}

// ---------------------------------------------------------------------
// Invoice pricing
// ---------------------------------------------------------------------

func (s *pricingService) CalculateInvoicePricing(ctx context.Context, req *CalculateInvoicePricingRequest) (*PricingCalculationResult, error) {
	orderReq := &CalculateOrderPricingRequest{
		CompanyID:    req.CompanyID,
		CustomerID:   req.CustomerID,
		Lines:        req.Lines,
		CouponCodes:  req.CouponCodes,
		CalculateTax: req.CalculateTax,
		At:           req.At,
	}
	return s.CalculateOrderPricing(ctx, orderReq)
}

func (s *pricingService) PreviewInvoicePricing(ctx context.Context, req *InvoicePricingPreviewRequest) (*PricingPreviewResult, error) {
	orderPreviewReq := &OrderPricingPreviewRequest{
		CompanyID:   req.CompanyID,
		CustomerID:  req.CustomerID,
		Items:       make([]*CreateOrderItemRequest, len(req.Items)),
		CouponCodes: req.CouponCodes,
		At:          req.At,
	}
	for i, it := range req.Items {
		orderPreviewReq.Items[i] = &CreateOrderItemRequest{
			ProductID:      it.ProductID,
			Quantity:       it.Quantity,
			UnitPrice:      it.UnitPrice,
			DiscountAmount: it.Discount,
			Metadata:       it.Metadata,
		}
	}
	return s.PreviewOrderPricing(ctx, orderPreviewReq)
}

func (s *pricingService) CalculateInvoiceTax(ctx context.Context, companyID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	_, err := s.invoiceRepo.GetByID(ctx, db, companyID, invoiceID)
	if err != nil {
		return decimal.Zero, err
	}
	items, err := s.invoiceRepo.GetItems(ctx, db, companyID, invoiceID)
	if err != nil {
		return decimal.Zero, err
	}
	var taxTotal decimal.Decimal
	for _, it := range items {
		discount := decimal.Zero
		if it.DiscountAmount != nil {
			discount = *it.DiscountAmount
		}
		tax, err := s.pricingRepo.CalculateLineTax(ctx, db, companyID, *it.ProductID, it.UnitPrice.Mul(it.Quantity).Sub(discount))
		if err != nil {
			return decimal.Zero, err
		}
		taxTotal = taxTotal.Add(tax)
	}
	return taxTotal, nil
}

func (s *pricingService) CalculateInvoiceDiscounts(ctx context.Context, companyID, invoiceID uuid.UUID, at time.Time) (*DiscountCalculationResult, error) {
	db := s.pgClient.DB
	invoice, err := s.invoiceRepo.GetByID(ctx, db, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	items, err := s.invoiceRepo.GetItems(ctx, db, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	productIDs := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		if it.ProductID != nil {
			productIDs = append(productIDs, *it.ProductID)
		}
	}
	return s.CalculateCombinedDiscount(ctx, companyID, &invoice.CustomerID, productIDs, invoice.Subtotal, at)
}

// ---------------------------------------------------------------------
// Tax calculations
// ---------------------------------------------------------------------

func (s *pricingService) CalculateLineTax(ctx context.Context, companyID, productID uuid.UUID, lineAmount decimal.Decimal) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.CalculateLineTax(ctx, db, companyID, productID, lineAmount)
}

func (s *pricingService) CalculateTaxAmount(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, taxableAmount decimal.Decimal) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.CalculateTaxAmount(ctx, db, companyID, entityType, entityID, taxableAmount)
}

// ---------------------------------------------------------------------
// Discount engine integration (delegated to PricingRepository)
// ---------------------------------------------------------------------

func (s *pricingService) GetApplicableCoupons(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetApplicableCoupons(ctx, db, companyID, customerID, productIDs, orderAmount, at)
}

func (s *pricingService) GetBestCoupon(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetBestCoupon(ctx, db, companyID, customerID, productIDs, orderAmount, at)
}

func (s *pricingService) GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetApplicablePromotions(ctx, db, companyID, customerID, productIDs, orderAmount, at)
}

func (s *pricingService) GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetBestPromotion(ctx, db, companyID, customerID, productIDs, orderAmount, at)
}

func (s *pricingService) CalculateCombinedDiscount(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*DiscountCalculationResult, error) {
	db := s.pgClient.DB
	totalDiscount, coupons, promos, err := s.pricingRepo.CalculateCombinedDiscount(ctx, db, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, err
	}
	return &DiscountCalculationResult{
		DiscountTotal:     totalDiscount,
		AppliedCoupons:    coupons,
		AppliedPromotions: promos,
	}, nil
}

// ValidateDiscountCombination enforces exclusive discount rules (stackingType = "exclusive")
func (s *pricingService) ValidateDiscountCombination(ctx context.Context, companyID uuid.UUID, couponIDs, promotionIDs []uuid.UUID) error {
	db := s.pgClient.DB

	// 1. Fetch all coupons with company isolation
	var coupons []*discount.Coupon
	if len(couponIDs) > 0 {
		var err error
		coupons, err = s.couponRepo.FindByIDs(ctx, db, companyID, couponIDs)
		if err != nil {
			return fmt.Errorf("fetch coupons: %w", err)
		}
		if len(coupons) != len(couponIDs) {
			return salesErrors.ErrNotFound
		}
	}

	// 2. Fetch all promotions with company isolation
	var promotions []*discount.Promotion
	if len(promotionIDs) > 0 {
		var err error
		promotions, err = s.promotionRepo.FindByIDs(ctx, db, companyID, promotionIDs)
		if err != nil {
			return fmt.Errorf("fetch promotions: %w", err)
		}
		if len(promotions) != len(promotionIDs) {
			return salesErrors.ErrNotFound
		}
	}

	// 3. Count exclusive discounts (StackingType == "exclusive")
	exclusiveCount := 0
	for _, c := range coupons {
		if c.StackingType == "exclusive" {
			exclusiveCount++
		}
	}
	for _, p := range promotions {
		if p.StackingType == "exclusive" {
			exclusiveCount++
		}
	}

	// 4. If more than one exclusive discount, reject
	if exclusiveCount > 1 {
		return fmt.Errorf("%w: cannot combine two or more exclusive discounts", salesErrors.ErrInvalidInput)
	}

	// 5. If exactly one exclusive discount, ensure no other discount exists
	if exclusiveCount == 1 && (len(coupons)+len(promotions) > 1) {
		return fmt.Errorf("%w: exclusive discount cannot be combined with any other discount", salesErrors.ErrInvalidInput)
	}

	// 6. Delegate to repository for any additional stacking rules (e.g., stacking groups)
	// Note: repository method does NOT require companyID
	return s.pricingRepo.ValidateDiscountCombination(ctx, db, couponIDs, promotionIDs)
}

// ---------------------------------------------------------------------
// Credit validation (delegated to CustomerService)
// ---------------------------------------------------------------------

func (s *pricingService) GetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	return s.customerSvc.GetCreditLimit(ctx, companyID, customerID)
}

func (s *pricingService) GetCustomerOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	return s.customerSvc.GetOutstandingBalance(ctx, companyID, customerID)
}

func (s *pricingService) CanCustomerPurchaseAmount(ctx context.Context, companyID, customerID uuid.UUID, amount decimal.Decimal) (bool, error) {
	return s.customerSvc.CanCustomerPurchaseAmount(ctx, companyID, customerID, amount)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (s *pricingService) ValidatePricing(ctx context.Context, req *PricingValidationRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if len(req.Lines) == 0 {
		return fmt.Errorf("%w: at least one line required", salesErrors.ErrInvalidInput)
	}
	for _, line := range req.Lines {
		if line.ProductID == uuid.Nil {
			return fmt.Errorf("%w: product_id required in line", salesErrors.ErrInvalidInput)
		}
		if line.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}

func (s *pricingService) ValidateOrderPricing(ctx context.Context, companyID, orderID uuid.UUID) error {
	db := s.pgClient.DB
	items, err := s.orderRepo.GetItems(ctx, db, companyID, orderID)
	if err != nil {
		return err
	}
	var computedSubtotal, computedDiscount, computedTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		computedSubtotal = computedSubtotal.Add(lineSub)
		if it.DiscountAmount != nil {
			computedDiscount = computedDiscount.Add(*it.DiscountAmount)
		}
		if it.TaxAmount != nil {
			computedTax = computedTax.Add(*it.TaxAmount)
		}
	}
	order, err := s.orderRepo.GetByID(ctx, db, companyID, orderID)
	if err != nil {
		return err
	}
	if !order.Subtotal.Equal(computedSubtotal) ||
		!order.DiscountTotal.Equal(computedDiscount) ||
		!order.TaxTotal.Equal(computedTax) {
		return fmt.Errorf("pricing mismatch: stored totals do not match line items")
	}
	return nil
}

func (s *pricingService) ValidateQuotePricing(ctx context.Context, companyID, quoteID uuid.UUID) error {
	db := s.pgClient.DB
	items, err := s.quoteRepo.GetItems(ctx, db, companyID, quoteID)
	if err != nil {
		return err
	}
	var computedSubtotal, computedDiscount, computedTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		computedSubtotal = computedSubtotal.Add(lineSub)
		computedDiscount = computedDiscount.Add(it.DiscountAmount)
		computedTax = computedTax.Add(it.TaxAmount)
	}
	quote, err := s.quoteRepo.GetByID(ctx, db, companyID, quoteID)
	if err != nil {
		return err
	}
	if !quote.Subtotal.Equal(computedSubtotal) ||
		!quote.DiscountTotal.Equal(computedDiscount) ||
		!quote.TaxTotal.Equal(computedTax) {
		return fmt.Errorf("pricing mismatch: stored totals do not match line items")
	}
	return nil
}

func (s *pricingService) ValidateInvoicePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	db := s.pgClient.DB
	items, err := s.invoiceRepo.GetItems(ctx, db, companyID, invoiceID)
	if err != nil {
		return err
	}
	var computedSubtotal, computedDiscount, computedTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		computedSubtotal = computedSubtotal.Add(lineSub)
		if it.DiscountAmount != nil {
			computedDiscount = computedDiscount.Add(*it.DiscountAmount)
		}
		if it.TaxAmount != nil {
			computedTax = computedTax.Add(*it.TaxAmount)
		}
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, db, companyID, invoiceID)
	if err != nil {
		return err
	}
	if !invoice.Subtotal.Equal(computedSubtotal) ||
		!invoice.DiscountTotal.Equal(computedDiscount) ||
		!invoice.TaxTotal.Equal(computedTax) {
		return fmt.Errorf("pricing mismatch: stored totals do not match line items")
	}
	return nil
}

// ---------------------------------------------------------------------
// Analytics (delegated to PricingRepository)
// ---------------------------------------------------------------------

func (s *pricingService) GetAverageDiscountRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetAverageDiscountRate(ctx, db, companyID, from, to)
}

func (s *pricingService) GetTotalDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetTotalDiscountAmount(ctx, db, companyID, from, to)
}

func (s *pricingService) GetEffectiveRevenueAfterDiscounts(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.pricingRepo.GetEffectiveRevenueAfterDiscounts(ctx, db, companyID, from, to)
}

// ---------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------

func (s *pricingService) validatePricingRequest(companyID uuid.UUID, customerID *uuid.UUID, lines []PricingLineInput) error {
	if companyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if len(lines) == 0 {
		return fmt.Errorf("%w: at least one line required", salesErrors.ErrInvalidInput)
	}
	for _, line := range lines {
		if line.ProductID == uuid.Nil {
			return fmt.Errorf("%w: product_id required", salesErrors.ErrInvalidInput)
		}
		if line.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}
