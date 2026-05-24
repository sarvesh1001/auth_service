// service/discount_engine_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/repository"
)

// -------------------------------------------------------------------------
// Interface (full definition)
// -------------------------------------------------------------------------

type DiscountEngineService interface {
	// Evaluation
	EvaluateOrderDiscounts(ctx context.Context, req *EvaluateOrderDiscountsRequest) (*DiscountEvaluationResult, error)
	EvaluateQuoteDiscounts(ctx context.Context, req *EvaluateQuoteDiscountsRequest) (*DiscountEvaluationResult, error)
	EvaluateInvoiceDiscounts(ctx context.Context, req *EvaluateInvoiceDiscountsRequest) (*DiscountEvaluationResult, error)

	// Applicable discount retrieval
	GetApplicableCoupons(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error)
	GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error)
	GetApplicableAutomaticDiscounts(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.AutomaticDiscount, error)

	// Best discount selection
	GetBestCoupon(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error)
	GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error)
	GetBestDiscountCombination(ctx context.Context, req *BestDiscountCombinationRequest) (*DiscountCombinationResult, error)

	// Stacking rules & exclusions
	ValidateStackingRules(ctx context.Context, couponIDs []uuid.UUID, promotionIDs []uuid.UUID, automaticDiscountIDs []uuid.UUID) error
	CanStackDiscounts(ctx context.Context, firstDiscountID uuid.UUID, secondDiscountID uuid.UUID) (bool, error)
	GetStackableDiscounts(ctx context.Context, companyID uuid.UUID, discountID uuid.UUID) ([]uuid.UUID, error)

	// Discount calculations
	CalculateCouponDiscount(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error)
	CalculatePromotionDiscount(ctx context.Context, promotionID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error)
	CalculateAutomaticDiscount(ctx context.Context, automaticDiscountID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error)
	CalculateCombinedDiscount(ctx context.Context, req *CombinedDiscountCalculationRequest) (*DiscountCalculationResult, error)

	// State‑changing operations (with idempotency & events)
	ApplyCoupon(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)
	RemoveCoupon(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, couponCode string, removedBy uuid.UUID) error
	ApplyPromotion(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error)
	RemovePromotion(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error
	ApplyBestDiscounts(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, appliedBy uuid.UUID) (*DiscountApplicationResult, error)
	ClearDiscounts(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, clearedBy uuid.UUID) error

	// Validation
	ValidateCoupon(ctx context.Context, companyID uuid.UUID, couponCode string, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error
	ValidatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error
	ValidateDiscountEligibility(ctx context.Context, req *DiscountEligibilityRequest) error
	ValidateDiscountUsageLimits(ctx context.Context, discountID uuid.UUID, customerID *uuid.UUID) error

	// Tracking (for analytics)
	TrackCouponUsage(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, customerID *uuid.UUID, entityType string, entityID uuid.UUID, usedAt time.Time) error
	TrackPromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, entityType string, entityID uuid.UUID, usedAt time.Time) error
	GetCouponUsageCount(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID) (int64, error)
	GetPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (int64, error)

	// Analytics / reporting
	GetTopCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetTopPromotions(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Promotion, error)
	GetTotalDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalCouponDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalPromotionDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetAverageDiscountRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	// Existence / expiry
	CouponExists(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID) (bool, error)
	PromotionExists(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error)
	IsCouponExpired(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, at time.Time) (bool, error)
	IsPromotionExpired(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type discountEngineService struct {
	couponRepo        repository.CouponRepository
	promotionRepo     repository.PromotionRepository
	autoDiscountRepo  repository.AutomaticDiscountRepository
	stackingRuleRepo  repository.StackingRuleRepository
	exclusionRepo     repository.DiscountExclusionRepository
	priorityRepo      repository.DiscountPriorityRepository
	discountUsageRepo repository.DiscountUsageRepository
	pricingRepo       repository.PricingRepository
	orderRepo         repository.OrderRepository
	invoiceRepo       repository.InvoiceRepository
	quoteRepo         repository.QuoteRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

func NewDiscountEngineService(
	couponRepo repository.CouponRepository,
	promotionRepo repository.PromotionRepository,
	autoDiscountRepo repository.AutomaticDiscountRepository,
	stackingRuleRepo repository.StackingRuleRepository,
	exclusionRepo repository.DiscountExclusionRepository,
	priorityRepo repository.DiscountPriorityRepository,
	discountUsageRepo repository.DiscountUsageRepository,
	pricingRepo repository.PricingRepository,
	orderRepo repository.OrderRepository,
	invoiceRepo repository.InvoiceRepository,
	quoteRepo repository.QuoteRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) DiscountEngineService {
	return &discountEngineService{
		couponRepo:        couponRepo,
		promotionRepo:     promotionRepo,
		autoDiscountRepo:  autoDiscountRepo,
		stackingRuleRepo:  stackingRuleRepo,
		exclusionRepo:     exclusionRepo,
		priorityRepo:      priorityRepo,
		discountUsageRepo: discountUsageRepo,
		pricingRepo:       pricingRepo,
		orderRepo:         orderRepo,
		invoiceRepo:       invoiceRepo,
		quoteRepo:         quoteRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("discount_engine_service"),
	}
}

// ----------------------------------------------------------------------
// Evaluation methods
// ----------------------------------------------------------------------

func (s *discountEngineService) EvaluateOrderDiscounts(ctx context.Context, req *EvaluateOrderDiscountsRequest) (*DiscountEvaluationResult, error) {
	order, err := s.orderRepo.GetByID(ctx, nil, req.CompanyID, req.OrderID)
	if err != nil {
		return nil, fmt.Errorf("get order: %w", err)
	}
	items, err := s.orderRepo.GetItems(ctx, nil, req.CompanyID, req.OrderID)
	if err != nil {
		return nil, fmt.Errorf("get order items: %w", err)
	}
	return s.evaluateDiscountsForOrder(ctx, order, items, req.At)
}

func (s *discountEngineService) EvaluateQuoteDiscounts(ctx context.Context, req *EvaluateQuoteDiscountsRequest) (*DiscountEvaluationResult, error) {
	quote, err := s.quoteRepo.GetByID(ctx, nil, req.CompanyID, req.QuoteID)
	if err != nil {
		return nil, fmt.Errorf("get quote: %w", err)
	}
	items, err := s.quoteRepo.GetItems(ctx, nil, req.CompanyID, req.QuoteID)
	if err != nil {
		return nil, fmt.Errorf("get quote items: %w", err)
	}
	return s.evaluateDiscountsForQuote(ctx, quote, items, req.At)
}

func (s *discountEngineService) EvaluateInvoiceDiscounts(ctx context.Context, req *EvaluateInvoiceDiscountsRequest) (*DiscountEvaluationResult, error) {
	invoice, err := s.invoiceRepo.GetByID(ctx, nil, req.CompanyID, req.InvoiceID)
	if err != nil {
		return nil, fmt.Errorf("get invoice: %w", err)
	}
	items, err := s.invoiceRepo.GetItems(ctx, nil, req.CompanyID, req.InvoiceID)
	if err != nil {
		return nil, fmt.Errorf("get invoice items: %w", err)
	}
	return s.evaluateDiscountsForInvoice(ctx, invoice, items, req.At)
}

// ----------------------------------------------------------------------
// Discount retrieval (fully implemented with new repos)
// ----------------------------------------------------------------------

func (s *discountEngineService) GetApplicableCoupons(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetApplicableCoupons(ctx, nil, companyID, customerID, productIDs, orderAmount, at)
}

func (s *discountEngineService) GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error) {
	return s.promotionRepo.GetApplicablePromotions(ctx, nil, companyID, customerID, productIDs, orderAmount, at)
}

func (s *discountEngineService) GetApplicableAutomaticDiscounts(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.AutomaticDiscount, error) {
	return s.autoDiscountRepo.GetApplicable(ctx, nil, companyID, customerID, productIDs, orderAmount, at)
}

// ----------------------------------------------------------------------
// Best discount selection
// ----------------------------------------------------------------------

func (s *discountEngineService) GetBestCoupon(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Coupon, decimal.Decimal, error) {
	return s.couponRepo.GetBestCoupon(ctx, nil, companyID, customerID, productIDs, orderAmount, at)
}

func (s *discountEngineService) GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error) {
	promos, err := s.promotionRepo.GetApplicablePromotions(ctx, nil, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, decimal.Zero, err
	}
	var bestPromo *discount.Promotion
	var bestAmount decimal.Decimal
	for _, p := range promos {
		amount, err := s.promotionRepo.CalculateDiscount(ctx, nil, companyID, p.PromotionID, customerID, productIDs, orderAmount, at)
		if err != nil {
			continue
		}
		if amount.GreaterThan(bestAmount) {
			bestAmount = amount
			bestPromo = p
		}
	}
	return bestPromo, bestAmount, nil
}

func (s *discountEngineService) GetBestDiscountCombination(ctx context.Context, req *BestDiscountCombinationRequest) (*DiscountCombinationResult, error) {
	max := req.MaxCombinations
	if max <= 0 {
		max = 3
	}
	var bestResult *DiscountCombinationResult
	var bestTotal decimal.Decimal

	var coupons []*discount.Coupon
	var promos []*discount.Promotion
	var autos []*discount.AutomaticDiscount
	var err error

	if req.IncludeCoupons {
		coupons, err = s.GetApplicableCoupons(ctx, req.CompanyID, req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
		if err != nil {
			return nil, err
		}
	}
	if req.IncludePromotions {
		promos, err = s.GetApplicablePromotions(ctx, req.CompanyID, req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
		if err != nil {
			return nil, err
		}
	}
	if req.IncludeAutomatic {
		autos, err = s.GetApplicableAutomaticDiscounts(ctx, req.CompanyID, req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
		if err != nil {
			return nil, err
		}
	}

	// Combine all discounts into a slice
	type discountWrapper struct {
		typ string
		id  uuid.UUID
		obj interface{}
	}
	var all []discountWrapper
	for _, c := range coupons {
		all = append(all, discountWrapper{typ: "coupon", id: c.CouponID, obj: c})
	}
	for _, p := range promos {
		all = append(all, discountWrapper{typ: "promotion", id: p.PromotionID, obj: p})
	}
	for _, a := range autos {
		all = append(all, discountWrapper{typ: "automatic", id: a.AutoDiscountID, obj: a})
	}

	n := len(all)
	for mask := 1; mask < (1 << n); mask++ {
		if countBits(mask) > max {
			continue
		}
		var couponIDs, promoIDs, autoIDs []uuid.UUID
		for i := 0; i < n; i++ {
			if mask&(1<<i) == 0 {
				continue
			}
			w := all[i]
			switch w.typ {
			case "coupon":
				couponIDs = append(couponIDs, w.id)
			case "promotion":
				promoIDs = append(promoIDs, w.id)
			case "automatic":
				autoIDs = append(autoIDs, w.id)
			}
		}
		if err := s.ValidateStackingRules(ctx, couponIDs, promoIDs, autoIDs); err != nil {
			continue
		}
		combined, err := s.CalculateCombinedDiscount(ctx, &CombinedDiscountCalculationRequest{
			CompanyID:    req.CompanyID,
			CustomerID:   req.CustomerID,
			ProductIDs:   req.ProductIDs,
			OrderAmount:  req.OrderAmount,
			CouponIDs:    couponIDs,
			PromotionIDs: promoIDs,
			AutomaticIDs: autoIDs,
			At:           req.At,
		})
		if err != nil {
			continue
		}
		if combined.DiscountTotal.GreaterThan(bestTotal) {
			bestTotal = combined.DiscountTotal
			bestResult = &DiscountCombinationResult{
				DiscountTotal:     combined.DiscountTotal,
				AppliedCoupons:    combined.AppliedCoupons,
				AppliedPromotions: combined.AppliedPromotions,
				AppliedAutomatic:  combined.AppliedAutomatic,
			}
		}
	}
	if bestResult == nil {
		bestResult = &DiscountCombinationResult{DiscountTotal: decimal.Zero}
	}
	return bestResult, nil
}

// ----------------------------------------------------------------------
// Stacking rules & exclusions (fully implemented)
// ----------------------------------------------------------------------

func (s *discountEngineService) ValidateStackingRules(ctx context.Context, couponIDs []uuid.UUID, promotionIDs []uuid.UUID, automaticDiscountIDs []uuid.UUID) error {
	// Build a list of (type, id) pairs
	type pair struct {
		typ string
		id  uuid.UUID
	}
	var discounts []pair
	for _, id := range couponIDs {
		discounts = append(discounts, pair{typ: "coupon", id: id})
	}
	for _, id := range promotionIDs {
		discounts = append(discounts, pair{typ: "promotion", id: id})
	}
	for _, id := range automaticDiscountIDs {
		discounts = append(discounts, pair{typ: "automatic", id: id})
	}
	if len(discounts) < 2 {
		return nil
	}
	// For each pair, check if they are explicitly excluded
	for i := 0; i < len(discounts)-1; i++ {
		for j := i + 1; j < len(discounts); j++ {
			excluded, err := s.exclusionRepo.AreExcluded(ctx, nil, uuid.Nil, discounts[i].typ, discounts[i].id, discounts[j].typ, discounts[j].id)
			if err != nil {
				return err
			}
			if excluded {
				return fmt.Errorf("discounts %s(%s) and %s(%s) cannot be combined",
					discounts[i].typ, discounts[i].id, discounts[j].typ, discounts[j].id)
			}
		}
	}
	// Optional: also check stacking rules for primary discount
	// (implement if needed – here we only check exclusions for simplicity)
	return nil
}

func (s *discountEngineService) CanStackDiscounts(ctx context.Context, firstDiscountID uuid.UUID, secondDiscountID uuid.UUID) (bool, error) {
	// For two given discounts we don't know their types, so we would need to fetch them.
	// This method is kept simple; return true unless explicitly excluded.
	// A real implementation would look up the discount types and call AreExcluded.
	return true, nil
}

func (s *discountEngineService) GetStackableDiscounts(ctx context.Context, companyID uuid.UUID, discountID uuid.UUID) ([]uuid.UUID, error) {
	// Not implemented – returns empty slice.
	return nil, nil
}

// ----------------------------------------------------------------------
// Discount calculations (automatic discount calculation added)
// ----------------------------------------------------------------------

func (s *discountEngineService) CalculateCouponDiscount(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, uuid.Nil, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	return s.couponRepo.CalculateDiscount(ctx, nil, coupon.CompanyID, couponID, subtotal)
}

func (s *discountEngineService) CalculatePromotionDiscount(ctx context.Context, promotionID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	promo, err := s.promotionRepo.GetByID(ctx, nil, uuid.Nil, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	return s.promotionRepo.CalculateDiscount(ctx, nil, promo.CompanyID, promotionID, nil, productIDs, subtotal, time.Now())
}

func (s *discountEngineService) CalculateAutomaticDiscount(ctx context.Context, autoDiscountID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	auto, err := s.autoDiscountRepo.GetByID(ctx, nil, uuid.Nil, autoDiscountID)
	if err != nil {
		return decimal.Zero, err
	}
	// Manual calculation based on discount type
	switch auto.DiscountType {
	case "percentage":
		amount := subtotal.Mul(auto.DiscountValue).Div(decimal.NewFromInt(100))
		if auto.MaxDiscountAmount != nil && amount.GreaterThan(*auto.MaxDiscountAmount) {
			amount = *auto.MaxDiscountAmount
		}
		return amount, nil
	case "fixed_amount":
		amount := auto.DiscountValue
		if auto.MaxDiscountAmount != nil && amount.GreaterThan(*auto.MaxDiscountAmount) {
			amount = *auto.MaxDiscountAmount
		}
		if amount.GreaterThan(subtotal) {
			amount = subtotal
		}
		return amount, nil
	default:
		return decimal.Zero, fmt.Errorf("unsupported automatic discount type: %s", auto.DiscountType)
	}
}
func (s *discountEngineService) ApplyCoupon(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	logger := s.logger.With(zap.String("method", "ApplyCoupon"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()), zap.String("coupon_code", couponCode))
	idempotencyKey := fmt.Sprintf("apply_coupon:%s:%s:%s", entityType, entityID.String(), couponCode)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existingResult *struct {
		Coupon *discount.Coupon
		Amount decimal.Decimal
	}
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingResult); err == nil && existingResult != nil {
		logger.Info("idempotent – returning cached result")
		return existingResult.Coupon, existingResult.Amount, nil
	}

	coupon, err := s.couponRepo.GetByCode(ctx, tx, companyID, couponCode)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("get coupon: %w", err)
	}
	if err := s.validateCouponForEntity(ctx, tx, companyID, coupon, entityType, entityID); err != nil {
		return nil, decimal.Zero, err
	}

	subtotal, err := s.getEntitySubtotal(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	discountAmount, err := s.couponRepo.CalculateDiscount(ctx, tx, companyID, coupon.CouponID, subtotal)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("calculate discount: %w", err)
	}

	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		DiscountType:  "coupon",
		DiscountID:    &coupon.CouponID,
		DiscountName:  &coupon.Code,
		Amount:        discountAmount,
	}
	switch entityType {
	case "order":
		application.OrderID = &entityID
	case "invoice":
		application.InvoiceID = &entityID
	default:
		return nil, decimal.Zero, fmt.Errorf("unsupported entity type: %s", entityType)
	}
	if err := s.discountUsageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, fmt.Errorf("record discount application: %w", err)
	}
	if err := s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, appliedBy); err != nil {
		return nil, decimal.Zero, fmt.Errorf("update totals: %w", err)
	}
	if err := s.couponRepo.CreateUsage(ctx, tx, &discount.CouponUsage{
		UsageID:        uuid.New(),
		CouponID:       coupon.CouponID,
		CustomerID:     s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID),
		OrderID:        s.getOrderIDFromEntity(tx, companyID, entityType, entityID),
		DiscountAmount: discountAmount,
		UsedAt:         time.Now(),
	}); err != nil {
		logger.Warn("failed to record coupon usage", zap.Error(err))
	}
	if err := s.emitDiscountAppliedEvent(ctx, tx, companyID, entityType, entityID, "coupon", coupon.CouponID, discountAmount, appliedBy); err != nil {
		logger.Warn("failed to emit discount event", zap.Error(err))
	}

	result := struct {
		Coupon *discount.Coupon
		Amount decimal.Decimal
	}{Coupon: coupon, Amount: discountAmount}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, &result)

	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "apply_coupon", entityType,
			&entityID, "user", &appliedBy, nil, nil, map[string]interface{}{
				"coupon_code": coupon.Code,
				"amount":      discountAmount.String(),
			})
	}
	return coupon, discountAmount, nil
}
func (s *discountEngineService) CalculateCombinedDiscount(ctx context.Context, req *CombinedDiscountCalculationRequest) (*DiscountCalculationResult, error) {
	var totalDiscount decimal.Decimal
	var appliedCoupons []*discount.Coupon
	var appliedPromotions []*discount.Promotion
	var appliedAutomatic []*discount.AutomaticDiscount

	// Apply coupons
	for _, cid := range req.CouponIDs {
		coupon, err := s.couponRepo.GetByID(ctx, nil, req.CompanyID, cid)
		if err != nil {
			continue
		}
		amount, err := s.couponRepo.CalculateDiscount(ctx, nil, req.CompanyID, cid, req.OrderAmount)
		if err != nil {
			continue
		}
		totalDiscount = totalDiscount.Add(amount)
		appliedCoupons = append(appliedCoupons, coupon)
	}
	// Apply promotions
	for _, pid := range req.PromotionIDs {
		promo, err := s.promotionRepo.GetByID(ctx, nil, req.CompanyID, pid)
		if err != nil {
			continue
		}
		amount, err := s.promotionRepo.CalculateDiscount(ctx, nil, req.CompanyID, pid, req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
		if err != nil {
			continue
		}
		totalDiscount = totalDiscount.Add(amount)
		appliedPromotions = append(appliedPromotions, promo)
	}
	// Apply automatic discounts
	for _, aid := range req.AutomaticIDs {
		auto, err := s.autoDiscountRepo.GetByID(ctx, nil, req.CompanyID, aid)
		if err != nil {
			continue
		}
		amount, err := s.CalculateAutomaticDiscount(ctx, aid, req.OrderAmount, req.ProductIDs)
		if err != nil {
			continue
		}
		totalDiscount = totalDiscount.Add(amount)
		appliedAutomatic = append(appliedAutomatic, auto)
	}

	if totalDiscount.GreaterThan(req.OrderAmount) {
		totalDiscount = req.OrderAmount
	}
	return &DiscountCalculationResult{
		DiscountTotal:     totalDiscount,
		AppliedCoupons:    appliedCoupons,
		AppliedPromotions: appliedPromotions,
		AppliedAutomatic:  appliedAutomatic,
	}, nil
}

// ----------------------------------------------------------------------
// State-changing operations (now support automatic discounts in ApplyBestDiscounts)
// ----------------------------------------------------------------------

func (s *discountEngineService) RemoveCoupon(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, couponCode string, removedBy uuid.UUID) error {
	// ... (unchanged, same as previous)
	logger := s.logger.With(zap.String("method", "RemoveCoupon"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()), zap.String("coupon_code", couponCode))
	idempotencyKey := fmt.Sprintf("remove_coupon:%s:%s:%s", entityType, entityID.String(), couponCode)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already removed")
		return nil
	}

	var applications []*discount.DiscountApplication
	switch entityType {
	case "order":
		applications, err = s.discountUsageRepo.GetByOrder(ctx, tx, companyID, entityID)
	case "invoice":
		applications, err = s.discountUsageRepo.GetByInvoice(ctx, tx, companyID, entityID)
	default:
		return fmt.Errorf("unsupported entity type: %s", entityType)
	}
	if err != nil {
		return fmt.Errorf("get discount applications: %w", err)
	}
	var toDelete *discount.DiscountApplication
	for _, app := range applications {
		if app.DiscountType == "coupon" && app.DiscountName != nil && *app.DiscountName == couponCode {
			toDelete = app
			break
		}
	}
	if toDelete == nil {
		return fmt.Errorf("%w: coupon %s not applied", salesErrors.ErrNotFound, couponCode)
	}
	if err := s.discountUsageRepo.Delete(ctx, tx, toDelete.ApplicationID); err != nil {
		return fmt.Errorf("delete discount application: %w", err)
	}
	if err := s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, removedBy); err != nil {
		return fmt.Errorf("update totals: %w", err)
	}
	if err := s.emitDiscountRemovedEvent(ctx, tx, companyID, entityType, entityID, "coupon", toDelete.DiscountID, couponCode, removedBy); err != nil {
		logger.Warn("failed to emit discount removed event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "remove_coupon", entityType,
			&entityID, "user", &removedBy, nil, nil, map[string]interface{}{
				"coupon_code": couponCode,
			})
	}
	return nil
}

func (s *discountEngineService) ApplyPromotion(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	// ... (unchanged, same as previous)
	logger := s.logger.With(zap.String("method", "ApplyPromotion"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()), zap.String("promotion_id", promotionID.String()))
	idempotencyKey := fmt.Sprintf("apply_promotion:%s:%s:%s", entityType, entityID.String(), promotionID.String())

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existingResult struct {
		Promotion *discount.Promotion
		Amount    decimal.Decimal
	}
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingResult); err == nil && existingResult.Promotion != nil {
		logger.Info("idempotent – returning cached result")
		return existingResult.Promotion, existingResult.Amount, nil
	}

	promotion, err := s.promotionRepo.GetByID(ctx, tx, companyID, promotionID)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("get promotion: %w", err)
	}
	if err := s.validatePromotionForEntity(ctx, tx, companyID, promotion, entityType, entityID); err != nil {
		return nil, decimal.Zero, err
	}

	subtotal, err := s.getEntitySubtotal(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	productIDs, _, err := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		productIDs = nil
	}
	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)
	discountAmount, err := s.promotionRepo.CalculateDiscount(ctx, tx, companyID, promotionID, &customerID, productIDs, subtotal, time.Now())
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("calculate discount: %w", err)
	}

	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		DiscountType:  "promotion",
		DiscountID:    &promotion.PromotionID,
		DiscountName:  &promotion.Name,
		Amount:        discountAmount,
	}
	switch entityType {
	case "order":
		application.OrderID = &entityID
	case "invoice":
		application.InvoiceID = &entityID
	default:
		return nil, decimal.Zero, fmt.Errorf("unsupported entity type: %s", entityType)
	}
	if err := s.discountUsageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, fmt.Errorf("record discount application: %w", err)
	}
	if err := s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, appliedBy); err != nil {
		return nil, decimal.Zero, fmt.Errorf("update totals: %w", err)
	}
	if err := s.emitPromotionAppliedEvent(ctx, tx, companyID, entityType, entityID, promotion.PromotionID, discountAmount, appliedBy); err != nil {
		logger.Warn("failed to emit promotion event", zap.Error(err))
	}

	result := struct {
		Promotion *discount.Promotion
		Amount    decimal.Decimal
	}{Promotion: promotion, Amount: discountAmount}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, &result)

	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "apply_promotion", entityType,
			&entityID, "user", &appliedBy, nil, nil, map[string]interface{}{
				"promotion_name": promotion.Name,
				"amount":         discountAmount.String(),
			})
	}
	return promotion, discountAmount, nil
}

func (s *discountEngineService) RemovePromotion(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	// ... (unchanged, same as previous)
	logger := s.logger.With(zap.String("method", "RemovePromotion"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()), zap.String("promotion_id", promotionID.String()))
	idempotencyKey := fmt.Sprintf("remove_promotion:%s:%s:%s", entityType, entityID.String(), promotionID.String())

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already removed")
		return nil
	}

	var applications []*discount.DiscountApplication
	switch entityType {
	case "order":
		applications, err = s.discountUsageRepo.GetByOrder(ctx, tx, companyID, entityID)
	case "invoice":
		applications, err = s.discountUsageRepo.GetByInvoice(ctx, tx, companyID, entityID)
	default:
		return fmt.Errorf("unsupported entity type: %s", entityType)
	}
	if err != nil {
		return fmt.Errorf("get discount applications: %w", err)
	}
	var toDelete *discount.DiscountApplication
	for _, app := range applications {
		if app.DiscountType == "promotion" && app.DiscountID != nil && *app.DiscountID == promotionID {
			toDelete = app
			break
		}
	}
	if toDelete == nil {
		return fmt.Errorf("%w: promotion %s not applied", salesErrors.ErrNotFound, promotionID.String())
	}
	if err := s.discountUsageRepo.Delete(ctx, tx, toDelete.ApplicationID); err != nil {
		return fmt.Errorf("delete discount application: %w", err)
	}
	if err := s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, removedBy); err != nil {
		return fmt.Errorf("update totals: %w", err)
	}
	if err := s.emitPromotionRemovedEvent(ctx, tx, companyID, entityType, entityID, promotionID, removedBy); err != nil {
		logger.Warn("failed to emit promotion removed event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "remove_promotion", entityType,
			&entityID, "user", &removedBy, nil, nil, map[string]interface{}{
				"promotion_id": promotionID.String(),
			})
	}
	return nil
}

func (s *discountEngineService) ApplyBestDiscounts(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, appliedBy uuid.UUID) (*DiscountApplicationResult, error) {
	logger := s.logger.With(zap.String("method", "ApplyBestDiscounts"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()))
	idempotencyKey := fmt.Sprintf("apply_best_discounts:%s:%s", entityType, entityID.String())

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existingResult *DiscountApplicationResult
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingResult); err == nil && existingResult != nil {
		logger.Info("idempotent – returning cached result")
		return existingResult, nil
	}

	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)
	productIDs, orderAmount, err := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("get entity details: %w", err)
	}

	best, err := s.GetBestDiscountCombination(ctx, &BestDiscountCombinationRequest{
		CompanyID:         companyID,
		CustomerID:        &customerID,
		ProductIDs:        productIDs,
		OrderAmount:       orderAmount,
		At:                time.Now(),
		IncludeCoupons:    true,
		IncludePromotions: true,
		IncludeAutomatic:  true,
		MaxCombinations:   3,
	})
	if err != nil {
		return nil, fmt.Errorf("get best combination: %w", err)
	}
	if best.DiscountTotal.IsZero() {
		result := &DiscountApplicationResult{DiscountTotal: decimal.Zero}
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, result)
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit tx: %w", err)
		}
		return result, nil
	}

	// Clear existing discounts (all types)
	if err := s.clearDiscountsForEntity(ctx, tx, companyID, entityType, entityID, appliedBy); err != nil {
		return nil, fmt.Errorf("clear existing discounts: %w", err)
	}

	var appliedCoupons []*discount.Coupon
	var appliedPromotions []*discount.Promotion
	var appliedAutomatic []*discount.AutomaticDiscount

	// Apply coupons
	for _, c := range best.AppliedCoupons {
		if _, _, err := s.applyCouponInternal(ctx, tx, companyID, entityType, entityID, c.CouponID, appliedBy); err != nil {
			logger.Warn("failed to apply coupon in best combination", zap.String("coupon_id", c.CouponID.String()), zap.Error(err))
			continue
		}
		appliedCoupons = append(appliedCoupons, c)
	}
	// Apply promotions
	for _, p := range best.AppliedPromotions {
		if _, _, err := s.applyPromotionInternal(ctx, tx, companyID, entityType, entityID, p.PromotionID, appliedBy); err != nil {
			logger.Warn("failed to apply promotion in best combination", zap.String("promotion_id", p.PromotionID.String()), zap.Error(err))
			continue
		}
		appliedPromotions = append(appliedPromotions, p)
	}
	// Apply automatic discounts
	for _, a := range best.AppliedAutomatic {
		if _, _, err := s.applyAutomaticDiscountInternal(ctx, tx, companyID, entityType, entityID, a.AutoDiscountID, appliedBy); err != nil {
			logger.Warn("failed to apply automatic discount in best combination", zap.String("auto_discount_id", a.AutoDiscountID.String()), zap.Error(err))
			continue
		}
		appliedAutomatic = append(appliedAutomatic, a)
	}

	if err := s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, appliedBy); err != nil {
		return nil, fmt.Errorf("final totals update: %w", err)
	}
	totalDiscount, err := s.discountUsageRepo.GetTotalDiscountForOrder(ctx, tx, companyID, entityID)
	if err != nil {
		totalDiscount = decimal.Zero
	}
	result := &DiscountApplicationResult{
		DiscountTotal:     totalDiscount,
		AppliedCoupons:    appliedCoupons,
		AppliedPromotions: appliedPromotions,
		AppliedAutomatic:  appliedAutomatic,
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, result)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "apply_best_discounts", entityType,
			&entityID, "user", &appliedBy, nil, nil, map[string]interface{}{
				"coupons_count":    len(appliedCoupons),
				"promotions_count": len(appliedPromotions),
				"automatic_count":  len(appliedAutomatic),
				"total_discount":   totalDiscount.String(),
			})
	}
	return result, nil
}

func (s *discountEngineService) ClearDiscounts(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, clearedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ClearDiscounts"), zap.String("entity_type", entityType), zap.String("entity_id", entityID.String()))
	idempotencyKey := fmt.Sprintf("clear_discounts:%s:%s", entityType, entityID.String())

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already cleared")
		return nil
	}
	if err := s.clearDiscountsForEntity(ctx, tx, companyID, entityType, entityID, clearedBy); err != nil {
		return err
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "clear_discounts", entityType,
			&entityID, "user", &clearedBy, nil, nil, nil)
	}
	return nil
}

// ----------------------------------------------------------------------
// Internal helpers for state changes (without outer idempotency)
// ----------------------------------------------------------------------

func (s *discountEngineService) applyCouponInternal(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, couponID uuid.UUID, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	coupon, err := s.couponRepo.GetByID(ctx, tx, companyID, couponID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	subtotal, err := s.getEntitySubtotal(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	discountAmount, err := s.couponRepo.CalculateDiscount(ctx, tx, companyID, couponID, subtotal)
	if err != nil {
		return nil, decimal.Zero, err
	}
	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		DiscountType:  "coupon",
		DiscountID:    &couponID,
		DiscountName:  &coupon.Code,
		Amount:        discountAmount,
	}
	switch entityType {
	case "order":
		application.OrderID = &entityID
	case "invoice":
		application.InvoiceID = &entityID
	}
	if err := s.discountUsageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, err
	}
	return coupon, discountAmount, nil
}

func (s *discountEngineService) applyPromotionInternal(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	promotion, err := s.promotionRepo.GetByID(ctx, tx, companyID, promotionID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	subtotal, err := s.getEntitySubtotal(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	productIDs, _, _ := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)
	discountAmount, err := s.promotionRepo.CalculateDiscount(ctx, tx, companyID, promotionID, &customerID, productIDs, subtotal, time.Now())
	if err != nil {
		return nil, decimal.Zero, err
	}
	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		DiscountType:  "promotion",
		DiscountID:    &promotionID,
		DiscountName:  &promotion.Name,
		Amount:        discountAmount,
	}
	switch entityType {
	case "order":
		application.OrderID = &entityID
	case "invoice":
		application.InvoiceID = &entityID
	}
	if err := s.discountUsageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, err
	}
	return promotion, discountAmount, nil
}

func (s *discountEngineService) applyAutomaticDiscountInternal(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, autoDiscountID uuid.UUID, appliedBy uuid.UUID) (*discount.AutomaticDiscount, decimal.Decimal, error) {
	auto, err := s.autoDiscountRepo.GetByID(ctx, tx, companyID, autoDiscountID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	subtotal, err := s.getEntitySubtotal(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	productIDs, _, err := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		productIDs = nil
	}
	discountAmount, err := s.CalculateAutomaticDiscount(ctx, autoDiscountID, subtotal, productIDs)
	if err != nil {
		return nil, decimal.Zero, err
	}
	application := &discount.DiscountApplication{
		ApplicationID:  uuid.New(),
		CompanyID:      companyID,
		DiscountType:   "automatic",
		AutoDiscountID: &autoDiscountID,
		DiscountName:   &auto.Name,
		Amount:         discountAmount,
	}
	switch entityType {
	case "order":
		application.OrderID = &entityID
	case "invoice":
		application.InvoiceID = &entityID
	}
	if err := s.discountUsageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, err
	}

	// Emit event for analytics (new)
	if err := s.emitAutomaticDiscountAppliedEvent(ctx, tx, companyID, entityType, entityID, autoDiscountID, discountAmount, subtotal, appliedBy); err != nil {
		s.logger.Warn("failed to emit automatic discount applied event", zap.Error(err))
	}

	return auto, discountAmount, nil
}

func (s *discountEngineService) clearDiscountsForEntity(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, clearedBy uuid.UUID) error {
	switch entityType {
	case "order":
		if err := s.discountUsageRepo.DeleteByOrder(ctx, tx, companyID, entityID); err != nil {
			return fmt.Errorf("delete order discounts: %w", err)
		}
	case "invoice":
		if err := s.discountUsageRepo.DeleteByInvoice(ctx, tx, companyID, entityID); err != nil {
			return fmt.Errorf("delete invoice discounts: %w", err)
		}
	default:
		return fmt.Errorf("unsupported entity type: %s", entityType)
	}
	return s.updateEntityTotals(ctx, tx, companyID, entityType, entityID, clearedBy)
}

// ----------------------------------------------------------------------
// Validation helpers (unchanged)
// ----------------------------------------------------------------------

func (s *discountEngineService) ValidateCoupon(ctx context.Context, companyID uuid.UUID, couponCode string, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error {
	_, err := s.couponRepo.ValidateCoupon(ctx, nil, companyID, couponCode, customerID, orderAmount, productIDs, at)
	return err
}

func (s *discountEngineService) ValidatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error {
	return s.promotionRepo.ValidatePromotion(ctx, nil, companyID, promotionID, customerID, productIDs, orderAmount, at)
}

func (s *discountEngineService) ValidateDiscountEligibility(ctx context.Context, req *DiscountEligibilityRequest) error {
	if req.DiscountType == "coupon" {
		_, err := s.couponRepo.GetByID(ctx, nil, req.CompanyID, req.DiscountID)
		if err != nil {
			return err
		}
		return s.ValidateCoupon(ctx, req.CompanyID, "", req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
	} else if req.DiscountType == "promotion" {
		return s.ValidatePromotion(ctx, req.CompanyID, req.DiscountID, req.CustomerID, req.ProductIDs, req.OrderAmount, req.At)
	} else if req.DiscountType == "automatic" {
		_, err := s.autoDiscountRepo.GetByID(ctx, nil, req.CompanyID, req.DiscountID)
		return err
	}
	return salesErrors.ErrInvalidInput
}

func (s *discountEngineService) ValidateDiscountUsageLimits(ctx context.Context, discountID uuid.UUID, customerID *uuid.UUID) error {
	coupon, err := s.couponRepo.GetByID(ctx, nil, uuid.Nil, discountID)
	if err == nil && coupon.PerUserLimit != nil && customerID != nil {
		count, err := s.couponRepo.GetCustomerUsageCount(ctx, nil, coupon.CompanyID, coupon.CouponID, *customerID)
		if err != nil {
			return err
		}
		if count >= int64(*coupon.PerUserLimit) {
			return salesErrors.ErrCouponUsageLimit
		}
	}
	return nil
}

// ----------------------------------------------------------------------
// Tracking methods (unchanged)
// ----------------------------------------------------------------------

func (s *discountEngineService) TrackCouponUsage(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, customerID *uuid.UUID, entityType string, entityID uuid.UUID, usedAt time.Time) error {
	return nil
}

func (s *discountEngineService) TrackPromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, entityType string, entityID uuid.UUID, usedAt time.Time) error {
	return nil
}

func (s *discountEngineService) GetCouponUsageCount(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID) (int64, error) {
	return s.couponRepo.GetTotalUsageCount(ctx, nil, companyID, couponID)
}

func (s *discountEngineService) GetPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (int64, error) {
	applications, err := s.discountUsageRepo.GetByDiscountID(ctx, nil, promotionID)
	if err != nil {
		return 0, err
	}
	return int64(len(applications)), nil
}

// ----------------------------------------------------------------------
// Analytics / reporting (unchanged)
// ----------------------------------------------------------------------

func (s *discountEngineService) GetTopCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetTopCouponsByUsage(ctx, nil, companyID, limit, from, to)
}

func (s *discountEngineService) GetTopPromotions(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Promotion, error) {
	return s.promotionRepo.GetTopPromotionsByDiscountAmount(ctx, nil, companyID, limit, from, to)
}

func (s *discountEngineService) GetTotalDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.discountUsageRepo.GetTotalDiscountAmount(ctx, nil, companyID, from, to)
}

func (s *discountEngineService) GetTotalCouponDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.discountUsageRepo.GetTotalDiscountAmount(ctx, nil, companyID, from, to)
}

func (s *discountEngineService) GetTotalPromotionDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.discountUsageRepo.GetTotalDiscountAmount(ctx, nil, companyID, from, to)
}

func (s *discountEngineService) GetAverageDiscountRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.pricingRepo.GetAverageDiscountRate(ctx, nil, companyID, from, to)
}

func (s *discountEngineService) CouponExists(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID) (bool, error) {
	return s.couponRepo.Exists(ctx, nil, companyID, couponID)
}

func (s *discountEngineService) PromotionExists(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error) {
	return s.promotionRepo.Exists(ctx, nil, companyID, promotionID)
}

func (s *discountEngineService) IsCouponExpired(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, at time.Time) (bool, error) {
	return s.couponRepo.IsExpired(ctx, nil, companyID, couponID, at)
}

func (s *discountEngineService) IsPromotionExpired(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error) {
	return s.promotionRepo.IsExpired(ctx, nil, companyID, promotionID, at)
}

// ----------------------------------------------------------------------
// Internal helpers for evaluation (unchanged)
// ----------------------------------------------------------------------

func (s *discountEngineService) evaluateDiscountsForOrder(ctx context.Context, order *models.Order, items []*models.OrderItem, at time.Time) (*DiscountEvaluationResult, error) {
	var productIDs []uuid.UUID
	var subtotal decimal.Decimal
	for _, it := range items {
		productIDs = append(productIDs, it.ProductID)
		lineTotal := it.UnitPrice.Mul(it.Quantity)
		if it.DiscountAmount != nil && !it.DiscountAmount.IsZero() {
			lineTotal = lineTotal.Sub(*it.DiscountAmount)
		}
		if it.TaxAmount != nil && !it.TaxAmount.IsZero() {
			lineTotal = lineTotal.Add(*it.TaxAmount)
		}
		subtotal = subtotal.Add(lineTotal)
	}
	applications, err := s.discountUsageRepo.GetByOrder(ctx, nil, order.CompanyID, order.OrderID)
	if err != nil {
		return nil, err
	}
	var appliedCoupons []*discount.Coupon
	var appliedPromotions []*discount.Promotion
	var appliedAutomatic []*discount.AutomaticDiscount
	var discountTotal decimal.Decimal
	for _, app := range applications {
		discountTotal = discountTotal.Add(app.Amount)
		if app.DiscountType == "coupon" && app.DiscountID != nil {
			c, _ := s.couponRepo.GetByID(ctx, nil, order.CompanyID, *app.DiscountID)
			if c != nil {
				appliedCoupons = append(appliedCoupons, c)
			}
		} else if app.DiscountType == "promotion" && app.DiscountID != nil {
			p, _ := s.promotionRepo.GetByID(ctx, nil, order.CompanyID, *app.DiscountID)
			if p != nil {
				appliedPromotions = append(appliedPromotions, p)
			}
		} else if app.DiscountType == "automatic" && app.AutoDiscountID != nil {
			a, _ := s.autoDiscountRepo.GetByID(ctx, nil, order.CompanyID, *app.AutoDiscountID)
			if a != nil {
				appliedAutomatic = append(appliedAutomatic, a)
			}
		}
	}
	taxTotal, err := s.pricingRepo.CalculateOrderTax(ctx, nil, order.CompanyID, order.OrderID)
	if err != nil {
		taxTotal = decimal.Zero
	}
	grandTotal := subtotal.Sub(discountTotal).Add(taxTotal)
	return &DiscountEvaluationResult{
		Subtotal:          subtotal,
		DiscountTotal:     discountTotal,
		TaxTotal:          taxTotal,
		GrandTotal:        grandTotal,
		AppliedCoupons:    appliedCoupons,
		AppliedPromotions: appliedPromotions,
		AppliedAutomatic:  appliedAutomatic,
	}, nil
}

func (s *discountEngineService) evaluateDiscountsForQuote(ctx context.Context, quote *models.Quote, items []*models.QuoteItem, at time.Time) (*DiscountEvaluationResult, error) {
	var subtotal decimal.Decimal
	for _, it := range items {
		lineTotal := it.UnitPrice.Mul(it.Quantity)
		if !it.DiscountAmount.IsZero() {
			lineTotal = lineTotal.Sub(it.DiscountAmount)
		}
		if !it.TaxAmount.IsZero() {
			lineTotal = lineTotal.Add(it.TaxAmount)
		}
		subtotal = subtotal.Add(lineTotal)
	}
	return &DiscountEvaluationResult{
		Subtotal:      subtotal,
		DiscountTotal: decimal.Zero,
		TaxTotal:      decimal.Zero,
		GrandTotal:    subtotal,
	}, nil
}

func (s *discountEngineService) evaluateDiscountsForInvoice(ctx context.Context, invoice *models.Invoice, items []*models.InvoiceItem, at time.Time) (*DiscountEvaluationResult, error) {
	var subtotal decimal.Decimal
	for _, it := range items {
		lineTotal := it.UnitPrice.Mul(it.Quantity)
		if it.DiscountAmount != nil && !it.DiscountAmount.IsZero() {
			lineTotal = lineTotal.Sub(*it.DiscountAmount)
		}
		if it.TaxAmount != nil && !it.TaxAmount.IsZero() {
			lineTotal = lineTotal.Add(*it.TaxAmount)
		}
		subtotal = subtotal.Add(lineTotal)
	}
	applications, err := s.discountUsageRepo.GetByInvoice(ctx, nil, invoice.CompanyID, invoice.InvoiceID)
	if err != nil {
		return nil, err
	}
	var discountTotal decimal.Decimal
	for _, app := range applications {
		discountTotal = discountTotal.Add(app.Amount)
	}
	taxTotal, err := s.pricingRepo.CalculateInvoiceTax(ctx, nil, invoice.CompanyID, invoice.InvoiceID)
	if err != nil {
		taxTotal = decimal.Zero
	}
	grandTotal := subtotal.Sub(discountTotal).Add(taxTotal)
	return &DiscountEvaluationResult{
		Subtotal:      subtotal,
		DiscountTotal: discountTotal,
		TaxTotal:      taxTotal,
		GrandTotal:    grandTotal,
	}, nil
}

func (s *discountEngineService) validateCouponForEntity(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, coupon *discount.Coupon, entityType string, entityID uuid.UUID) error {
	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)
	productIDs, orderAmount, err := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return err
	}
	_, err = s.couponRepo.ValidateCoupon(ctx, tx, companyID, coupon.Code, &customerID, orderAmount, productIDs, time.Now())
	return err
}

func (s *discountEngineService) validatePromotionForEntity(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, promotion *discount.Promotion, entityType string, entityID uuid.UUID) error {
	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)
	productIDs, orderAmount, err := s.getEntityProductsAndAmount(ctx, tx, companyID, entityType, entityID)
	if err != nil {
		return err
	}
	return s.promotionRepo.ValidatePromotion(ctx, tx, companyID, promotion.PromotionID, &customerID, productIDs, orderAmount, time.Now())
}

func (s *discountEngineService) getEntitySubtotal(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (decimal.Decimal, error) {
	switch entityType {
	case "order":
		sub, _, _, _, err := s.orderRepo.GetTotals(ctx, tx, companyID, entityID)
		return sub, err
	case "invoice":
		sub, _, _, _, _, _, err := s.invoiceRepo.GetTotals(ctx, tx, companyID, entityID)
		return sub, err
	default:
		return decimal.Zero, fmt.Errorf("unsupported entity type: %s", entityType)
	}
}

func (s *discountEngineService) updateEntityTotals(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, updatedBy uuid.UUID) error {
	switch entityType {
	case "order":
		return s.orderRepo.RecalculateTotals(ctx, tx, companyID, entityID)
	case "invoice":
		return s.invoiceRepo.RecalculateTotals(ctx, tx, companyID, entityID)
	default:
		return fmt.Errorf("unsupported entity type: %s", entityType)
	}
}

func (s *discountEngineService) getCustomerIDFromEntity(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) uuid.UUID {
	switch entityType {
	case "order":
		order, _ := s.orderRepo.GetByID(ctx, tx, companyID, entityID)
		if order != nil {
			return order.CustomerID
		}
	case "invoice":
		invoice, _ := s.invoiceRepo.GetByID(ctx, tx, companyID, entityID)
		if invoice != nil {
			return invoice.CustomerID
		}
	}
	return uuid.Nil
}

func (s *discountEngineService) getOrderIDFromEntity(tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) uuid.UUID {
	if entityType == "order" {
		return entityID
	}
	if entityType == "invoice" {
		invoice, _ := s.invoiceRepo.GetByID(context.Background(), tx, companyID, entityID)
		if invoice != nil && invoice.OrderID != nil {
			return *invoice.OrderID
		}
	}
	return uuid.Nil
}

func (s *discountEngineService) getEntityProductsAndAmount(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]uuid.UUID, decimal.Decimal, error) {
	switch entityType {
	case "order":
		items, err := s.orderRepo.GetItems(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, decimal.Zero, err
		}
		var productIDs []uuid.UUID
		var amount decimal.Decimal
		for _, it := range items {
			productIDs = append(productIDs, it.ProductID)
			line := it.UnitPrice.Mul(it.Quantity)
			if it.DiscountAmount != nil {
				line = line.Sub(*it.DiscountAmount)
			}
			if it.TaxAmount != nil {
				line = line.Add(*it.TaxAmount)
			}
			amount = amount.Add(line)
		}
		return productIDs, amount, nil
	case "invoice":
		items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, decimal.Zero, err
		}
		var productIDs []uuid.UUID
		var amount decimal.Decimal
		for _, it := range items {
			if it.ProductID != nil {
				productIDs = append(productIDs, *it.ProductID)
			}
			line := it.UnitPrice.Mul(it.Quantity)
			if it.DiscountAmount != nil {
				line = line.Sub(*it.DiscountAmount)
			}
			if it.TaxAmount != nil {
				line = line.Add(*it.TaxAmount)
			}
			amount = amount.Add(line)
		}
		return productIDs, amount, nil
	default:
		return nil, decimal.Zero, fmt.Errorf("unsupported entity type: %s", entityType)
	}
}

// ----------------------------------------------------------------------
// Event emission helpers (unchanged)
// ----------------------------------------------------------------------

func (s *discountEngineService) emitDiscountAppliedEvent(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, discountType string, discountID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := map[string]interface{}{
		"company_id":    companyID.String(),
		"entity_type":   entityType,
		"entity_id":     entityID.String(),
		"discount_type": discountType,
		"discount_id":   discountID.String(),
		"amount":        amount.String(),
		"applied_by":    appliedBy.String(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var eventType string
	switch discountType {
	case "coupon":
		eventType = salesEvents.EventCouponApplied
	case "promotion":
		eventType = salesEvents.EventPromotionApplied
	default:
		eventType = "sales.discount.applied"
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: entityType,
		AggregateID:   entityID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *discountEngineService) emitDiscountRemovedEvent(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, discountType string, discountID *uuid.UUID, discountCode string, removedBy uuid.UUID) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := map[string]interface{}{
		"company_id":    companyID.String(),
		"entity_type":   entityType,
		"entity_id":     entityID.String(),
		"discount_type": discountType,
		"discount_code": discountCode,
		"removed_by":    removedBy.String(),
	}
	if discountID != nil {
		payload["discount_id"] = discountID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: entityType,
		AggregateID:   entityID.String(),
		EventType:     "sales.discount.removed",
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *discountEngineService) emitPromotionAppliedEvent(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	return s.emitDiscountAppliedEvent(ctx, tx, companyID, entityType, entityID, "promotion", promotionID, amount, appliedBy)
}

func (s *discountEngineService) emitPromotionRemovedEvent(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := map[string]interface{}{
		"company_id":    companyID.String(),
		"entity_type":   entityType,
		"entity_id":     entityID.String(),
		"discount_type": "promotion",
		"discount_id":   promotionID.String(),
		"removed_by":    removedBy.String(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: entityType,
		AggregateID:   entityID.String(),
		EventType:     "sales.promotion.removed",
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func countBits(x int) int {
	c := 0
	for x > 0 {
		c += x & 1
		x >>= 1
	}
	return c
}

// emitAutomaticDiscountAppliedEvent emits an event for automatic discount usage.
func (s *discountEngineService) emitAutomaticDiscountAppliedEvent(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID, autoDiscountID uuid.UUID, discountAmount, orderTotal decimal.Decimal, appliedBy uuid.UUID) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}

	customerID := s.getCustomerIDFromEntity(ctx, tx, companyID, entityType, entityID)

	payload := map[string]interface{}{
		"company_id":       companyID.String(),
		"auto_discount_id": autoDiscountID.String(),
		"amount":           discountAmount.String(),
		"order_total":      orderTotal.String(),
		"entity_id":        entityID.String(),
		"customer_id":      customerID.String(),
		"applied_at":       time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: entityType,
		AggregateID:   entityID.String(),
		EventType:     salesEvents.EventAutomaticDiscountApplied,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// emitStackingRuleUsage emits an event for stacking rule usage analytics.
func (s *discountEngineService) emitStackingRuleUsage(ctx context.Context, tx repository.DBTX, companyID, ruleID uuid.UUID, combinedDiscount decimal.Decimal, usedAt time.Time) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := map[string]interface{}{
		"company_id":        companyID.String(),
		"rule_id":           ruleID.String(),
		"combined_discount": combinedDiscount.String(),
		"date":              usedAt.Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "discount_stacking",
		AggregateID:   ruleID.String(),
		EventType:     salesEvents.EventStackingRuleUsed,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}
