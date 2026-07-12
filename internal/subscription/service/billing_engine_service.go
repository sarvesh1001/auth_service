// FILE: ./subscription/service/billing_engine_service.go
package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesModels "auth-service/internal/sales/models"
	"auth-service/internal/sales/service"
	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// ---------- Input types ----------
type BillingInput struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	BillingDate    time.Time
	PeriodStart    time.Time
	PeriodEnd      time.Time
	InvoiceType    InvoiceType
	PlanChange     *PlanChangeContext
}

type InvoiceType string

const (
	InvoiceTypeInitial         InvoiceType = "initial"
	InvoiceTypeRenewal         InvoiceType = "renewal"
	InvoiceTypeUpgrade         InvoiceType = "upgrade"
	InvoiceTypeDowngrade       InvoiceType = "downgrade"
	InvoiceTypeProration       InvoiceType = "proration"
	InvoiceTypeAddon           InvoiceType = "addon"
	InvoiceTypeManual          InvoiceType = "manual"
	InvoiceTypeTrialConversion InvoiceType = "trial_conversion"
)

type PlanChangeContext struct {
	OldPlanID     uuid.UUID
	NewPlanID     uuid.UUID
	EffectiveDate time.Time
}

// ---------- Internal context & result ----------
type BillingContext struct {
	Subscription      *models.Subscription
	Plan              *models.Plan
	BillingPolicy     *models.BillingPolicy
	RenewalPolicy     *models.RenewalPolicy
	ProrationPolicy   *models.ProrationPolicy
	SubscriptionItems []*models.SubscriptionItem
	Input             BillingInput
}

type PricingResult struct {
	Subtotal      decimal.Decimal
	DiscountTotal decimal.Decimal
	TaxTotal      decimal.Decimal
	GrandTotal    decimal.Decimal
	LineItems     []InvoiceLineItem
}

type InvoiceLineItem struct {
	ProductID   uuid.UUID
	Description string
	Quantity    decimal.Decimal
	UnitPrice   decimal.Decimal
	Discount    decimal.Decimal
	Tax         decimal.Decimal
	Total       decimal.Decimal
	TaxRate     *decimal.Decimal
}

// ---------- Service ----------
type BillingEngineService struct {
	subRepo             repository.SubscriptionRepository
	subItemRepo         repository.SubscriptionItemRepository
	planRepo            repository.PlanRepository
	planItemRepo        repository.PlanItemRepository
	billingPolicyRepo   repository.BillingPolicyRepository
	prorationPolicyRepo repository.ProrationPolicyRepository
	renewalPolicyRepo   repository.RenewalPolicyRepository

	pricingService  service.PricingService
	couponService   service.CouponService
	discountService service.DiscountEngineService
	taxService      service.TaxIntegrationService
	invoiceService  service.InvoiceService

	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewBillingEngineService(
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	billingPolicyRepo repository.BillingPolicyRepository,
	prorationPolicyRepo repository.ProrationPolicyRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	pricingService service.PricingService,
	couponService service.CouponService,
	discountService service.DiscountEngineService,
	taxService service.TaxIntegrationService,
	invoiceService service.InvoiceService,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) *BillingEngineService {
	return &BillingEngineService{
		subRepo:             subRepo,
		subItemRepo:         subItemRepo,
		planRepo:            planRepo,
		planItemRepo:        planItemRepo,
		billingPolicyRepo:   billingPolicyRepo,
		prorationPolicyRepo: prorationPolicyRepo,
		renewalPolicyRepo:   renewalPolicyRepo,
		pricingService:      pricingService,
		couponService:       couponService,
		discountService:     discountService,
		taxService:          taxService,
		invoiceService:      invoiceService,
		pgClient:            pgClient,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		logger:              logger.Named("billing_engine"),
	}
}

// ---------- Public entry methods ----------
func (s *BillingEngineService) GenerateInitialInvoice(ctx context.Context, companyID, subscriptionID uuid.UUID, periodStart, periodEnd time.Time) (*salesModels.Invoice, error) {
	input := BillingInput{
		CompanyID:      companyID,
		SubscriptionID: subscriptionID,
		BillingDate:    time.Now(),
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		InvoiceType:    InvoiceTypeInitial,
	}
	return s.GenerateInvoice(ctx, input)
}

// GenerateRenewalInvoice now uses a non‑nil DBTX (s.pgClient.DB)
// and includes proper error handling for missing records.
func (s *BillingEngineService) GenerateRenewalInvoice(ctx context.Context, companyID, subscriptionID uuid.UUID) (*salesModels.Invoice, error) {
	db := s.pgClient.DB

	sub, err := s.subRepo.GetByID(ctx, db, companyID, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}
	if sub == nil {
		return nil, errors.ErrNotFound
	}
	if sub.Status != enums.SubStatusActive && sub.Status != enums.SubStatusPending && sub.Status != enums.SubStatusTrial {
		return nil, errors.ErrSubscriptionNotRenewable
	}

	plan, err := s.planRepo.GetByID(ctx, db, companyID, sub.PlanID)
	if err != nil {
		return nil, fmt.Errorf("get plan: %w", err)
	}
	if plan == nil {
		return nil, errors.ErrPlanNotFound
	}

	billingPolicy, err := s.billingPolicyRepo.GetByID(ctx, db, companyID, plan.BillingPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get billing policy: %w", err)
	}
	if billingPolicy == nil {
		return nil, errors.ErrNotFound
	}

	start := time.Now()
	if sub.EndDate != nil {
		start = *sub.EndDate
	}
	end := nextBillingDate(start, billingPolicy)

	input := BillingInput{
		CompanyID:      companyID,
		SubscriptionID: subscriptionID,
		BillingDate:    time.Now(),
		PeriodStart:    start,
		PeriodEnd:      end,
		InvoiceType:    InvoiceTypeRenewal,
	}
	return s.GenerateInvoice(ctx, input)
}

func (s *BillingEngineService) GenerateUpgradeInvoice(ctx context.Context, companyID, subscriptionID uuid.UUID, oldPlanID, newPlanID uuid.UUID, effectiveDate time.Time) (*salesModels.Invoice, error) {
	input := BillingInput{
		CompanyID:      companyID,
		SubscriptionID: subscriptionID,
		BillingDate:    effectiveDate,
		PeriodStart:    time.Now(),
		PeriodEnd:      time.Now().AddDate(0, 1, 0),
		InvoiceType:    InvoiceTypeUpgrade,
		PlanChange: &PlanChangeContext{
			OldPlanID:     oldPlanID,
			NewPlanID:     newPlanID,
			EffectiveDate: effectiveDate,
		},
	}
	return s.GenerateInvoice(ctx, input)
}

// GenerateDowngradeInvoice generates an invoice for a downgrade plan change.
func (s *BillingEngineService) GenerateDowngradeInvoice(ctx context.Context, companyID, subscriptionID uuid.UUID, oldPlanID, newPlanID uuid.UUID, effectiveDate time.Time) (*salesModels.Invoice, error) {
	input := BillingInput{
		CompanyID:      companyID,
		SubscriptionID: subscriptionID,
		BillingDate:    effectiveDate,
		PeriodStart:    time.Now(),
		PeriodEnd:      time.Now().AddDate(0, 1, 0),
		InvoiceType:    InvoiceTypeDowngrade,
		PlanChange: &PlanChangeContext{
			OldPlanID:     oldPlanID,
			NewPlanID:     newPlanID,
			EffectiveDate: effectiveDate,
		},
	}
	return s.GenerateInvoice(ctx, input)
}

// Additional entry methods (addon, trial conversion) can be added similarly.

// ---------- Core orchestration ----------
func (s *BillingEngineService) GenerateInvoice(ctx context.Context, input BillingInput) (*salesModels.Invoice, error) {
	logger := s.logger.With(
		zap.String("subscription_id", input.SubscriptionID.String()),
		zap.String("invoice_type", string(input.InvoiceType)),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := fmt.Sprintf("billing-%s-%s-%d", input.SubscriptionID.String(), input.InvoiceType, input.BillingDate.Unix())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – invoice already generated, skipping")
		return nil, nil
	}

	ctxData, err := s.loadBillingContext(ctx, tx, input)
	if err != nil {
		return nil, fmt.Errorf("load context: %w", err)
	}

	pricing, err := s.calculatePricing(ctx, tx, ctxData)
	if err != nil {
		return nil, fmt.Errorf("calculate pricing: %w", err)
	}

	invoiceReq := s.buildInvoiceRequest(ctxData, pricing)

	invoice, err := s.invoiceService.CreateDraftInvoice(ctx, invoiceReq)
	if err != nil {
		return nil, fmt.Errorf("create invoice: %w", err)
	}

	if err := s.updateSubscriptionAfterInvoice(ctx, tx, ctxData, invoice, input); err != nil {
		return nil, fmt.Errorf("update subscription: %w", err)
	}

	if err := s.recordCouponUsage(ctx, tx, ctxData, invoice); err != nil {
		logger.Warn("failed to record coupon usage", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.emitInvoiceGeneratedEvent(ctx, invoice, ctxData)
	s.auditInvoice(ctx, invoice, ctxData)

	return invoice, nil
}

// ---------- Private loading & helpers ----------
func (s *BillingEngineService) loadBillingContext(ctx context.Context, tx *sql.Tx, input BillingInput) (*BillingContext, error) {
	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, input.CompanyID, input.SubscriptionID)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, errors.ErrNotFound
	}

	plan, err := s.planRepo.GetByID(ctx, tx, input.CompanyID, sub.PlanID)
	if err != nil || plan == nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}

	billingPolicy, err := s.billingPolicyRepo.GetByID(ctx, tx, input.CompanyID, plan.BillingPolicyID)
	if err != nil {
		return nil, err
	}
	renewalPolicy, err := s.renewalPolicyRepo.GetByID(ctx, tx, input.CompanyID, plan.RenewalPolicyID)
	if err != nil {
		return nil, err
	}
	prorationPolicy, err := s.prorationPolicyRepo.GetByID(ctx, tx, input.CompanyID, plan.ProrationPolicyID)
	if err != nil {
		return nil, err
	}

	subItems, err := s.subItemRepo.GetBySubscription(ctx, tx, sub.SubscriptionID)
	if err != nil {
		return nil, err
	}
	if len(subItems) == 0 {
		return nil, errors.ErrNoSubscriptionItems
	}

	return &BillingContext{
		Subscription:      sub,
		Plan:              plan,
		BillingPolicy:     billingPolicy,
		RenewalPolicy:     renewalPolicy,
		ProrationPolicy:   prorationPolicy,
		SubscriptionItems: subItems,
		Input:             input,
	}, nil
}

func (s *BillingEngineService) calculatePricing(ctx context.Context, tx *sql.Tx, ctxData *BillingContext) (*PricingResult, error) {
	var lineItems []InvoiceLineItem
	var subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal

	for _, subItem := range ctxData.SubscriptionItems {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, subItem.PlanItemID)
		if err != nil {
			return nil, err
		}

		unitPrice := subItem.UnitPrice
		quantity := subItem.Quantity
		lineTotalBefore := unitPrice.Mul(quantity)

		// ---- Discounts (using DiscountEngineService) ----
		productID := uuid.Nil
		if subItem.ProductID != nil {
			productID = *subItem.ProductID
		}
		discReq := &service.CombinedDiscountCalculationRequest{
			CompanyID:   ctxData.Input.CompanyID,
			CustomerID:  &ctxData.Subscription.CustomerID,
			ProductIDs:  []uuid.UUID{productID},
			OrderAmount: lineTotalBefore,
			At:          ctxData.Input.BillingDate,
		}
		discResult, err := s.discountService.CalculateCombinedDiscount(ctx, discReq)
		if err != nil {
			return nil, fmt.Errorf("calculate discounts: %w", err)
		}
		autoDiscount := discResult.DiscountTotal

		// ---- Coupon ----
		var couponDiscount decimal.Decimal
		if ctxData.Subscription.CouponID != nil {
			couponDiscount, err = s.couponService.CalculateDiscount(ctx, ctxData.Input.CompanyID, *ctxData.Subscription.CouponID, lineTotalBefore)
			if err != nil {
				return nil, err
			}
		}
		lineDiscount := autoDiscount.Add(couponDiscount)
		if lineDiscount.GreaterThan(lineTotalBefore) {
			lineDiscount = lineTotalBefore
		}

		// ---- Tax ----
		taxableAmount := lineTotalBefore.Sub(lineDiscount)
		taxResult, err := s.taxService.CalculateLineTax(ctx, &service.CalculateLineTaxRequest{
			CompanyID:     ctxData.Input.CompanyID,
			ProductID:     productID,
			LineAmount:    lineTotalBefore,
			TaxableAmount: taxableAmount,
			CustomerID:    &ctxData.Subscription.CustomerID,
		})
		if err != nil {
			return nil, err
		}
		taxAmount := taxResult.TaxAmount

		lineItem := InvoiceLineItem{
			ProductID:   productID,
			Description: planItem.Name,
			Quantity:    quantity,
			UnitPrice:   unitPrice,
			Discount:    lineDiscount,
			Tax:         taxAmount,
			Total:       taxableAmount.Add(taxAmount),
			TaxRate:     &taxResult.ApplicableRate,
		}
		lineItems = append(lineItems, lineItem)

		subtotal = subtotal.Add(lineTotalBefore)
		discountTotal = discountTotal.Add(lineDiscount)
		taxTotal = taxTotal.Add(taxAmount)
		grandTotal = grandTotal.Add(lineItem.Total)
	}

	return &PricingResult{
		Subtotal:      subtotal,
		DiscountTotal: discountTotal,
		TaxTotal:      taxTotal,
		GrandTotal:    grandTotal,
		LineItems:     lineItems,
	}, nil
}

func (s *BillingEngineService) buildInvoiceRequest(ctxData *BillingContext, pricing *PricingResult) *service.CreateInvoiceRequest {
	items := make([]service.CreateInvoiceItemRequest, len(pricing.LineItems))
	for i, li := range pricing.LineItems {
		items[i] = service.CreateInvoiceItemRequest{
			ProductID:   li.ProductID,
			Quantity:    li.Quantity,
			UnitPrice:   &li.UnitPrice,
			Discount:    &li.Discount,
			TaxRate:     li.TaxRate,
			OrderItemID: nil,
			Metadata:    nil,
		}
	}

	dueDate := ctxData.Input.BillingDate.AddDate(0, 0, ctxData.BillingPolicy.AdvanceDays)

	currency := "USD"
	if len(ctxData.SubscriptionItems) > 0 {
		currency = ctxData.SubscriptionItems[0].Currency
	}

	return &service.CreateInvoiceRequest{
		CompanyID:     ctxData.Input.CompanyID,
		CustomerID:    ctxData.Subscription.CustomerID,
		OrderID:       nil,
		InvoiceNumber: "",
		InvoiceDate:   ctxData.Input.BillingDate,
		DueDate:       dueDate,
		Currency:      currency,
		Notes:         ptrString(fmt.Sprintf("Generated from subscription %s", ctxData.Subscription.SubscriptionID.String())),
		Items:         items,
		CreatedBy:     nil,
		SalesRepID:    nil,
	}
}

func (s *BillingEngineService) updateSubscriptionAfterInvoice(ctx context.Context, tx *sql.Tx, ctxData *BillingContext, invoice *salesModels.Invoice, input BillingInput) error {
	sub := ctxData.Subscription
	sub.CurrentInvoiceID = &invoice.InvoiceID
	sub.LastInvoiceID = &invoice.InvoiceID

	if input.InvoiceType == InvoiceTypeRenewal {
		newEnd := nextBillingDate(*sub.EndDate, ctxData.BillingPolicy)
		sub.EndDate = &newEnd
	}
	return s.subRepo.Update(ctx, tx, sub)
}

func (s *BillingEngineService) recordCouponUsage(ctx context.Context, tx *sql.Tx, ctxData *BillingContext, invoice *salesModels.Invoice) error {
	if ctxData.Subscription.CouponID == nil {
		return nil
	}
	// In a real implementation, compute the actual coupon discount from the invoice.
	// For now, we pass zero.
	return s.couponService.RecordInvoiceCouponUsage(ctx, ctxData.Input.CompanyID, *ctxData.Subscription.CouponID, invoice.InvoiceID, &ctxData.Subscription.CustomerID, decimal.Zero, ctxData.Input.BillingDate)
}

// ---------- Event & Audit ----------
func (s *BillingEngineService) emitInvoiceGeneratedEvent(ctx context.Context, invoice *salesModels.Invoice, ctxData *BillingContext) {
	contractNumber := ""
	if ctxData.Subscription.ContractNumber != nil {
		contractNumber = *ctxData.Subscription.ContractNumber
	}

	couponID := ""
	if ctxData.Subscription.CouponID != nil {
		couponID = ctxData.Subscription.CouponID.String()
	}

	salesOrderID := ""
	if ctxData.Subscription.SalesOrderID != nil {
		salesOrderID = ctxData.Subscription.SalesOrderID.String()
	}

	payload := events.SubscriptionPayload{
		SubscriptionID: ctxData.Subscription.SubscriptionID.String(),
		CompanyID:      ctxData.Input.CompanyID.String(),
		CustomerID:     ctxData.Subscription.CustomerID.String(),
		PlanID:         ctxData.Subscription.PlanID.String(),
		Status:         string(ctxData.Subscription.Status),
		StartDate:      ctxData.Subscription.StartDate.Format(time.RFC3339),
		EndDate:        ctxData.Subscription.EndDate.Format(time.RFC3339),
		AutoRenew:      ctxData.Subscription.AutoRenew,
		Currency:       "USD",
		TotalAmount:    invoice.GrandTotal.String(),
		ContractNumber: contractNumber,
		CouponID:       couponID,
		SalesOrderID:   salesOrderID,
		Version:        ctxData.Subscription.Version,
	}
	s.logger.Info("Invoice generated – emitting SubscriptionUpdated event", zap.Any("payload", payload))
}

func (s *BillingEngineService) auditInvoice(ctx context.Context, invoice *salesModels.Invoice, ctxData *BillingContext) {
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ctxData.Input.CompanyID, "subscription", "invoice_generated", "subscription",
			&ctxData.Subscription.SubscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"invoice_id": invoice.InvoiceID.String(),
				"total":      invoice.GrandTotal,
				"type":       ctxData.Input.InvoiceType,
			})
	}
}

// ---------- Utilities ----------
func ptrString(s string) *string {
	return &s
}

func nextBillingDate(from time.Time, policy *models.BillingPolicy) time.Time {
	// Implement based on policy.FrequencyID and BillingInterval.
	// For demo, add 1 month.
	return from.AddDate(0, 1, 0)
}
