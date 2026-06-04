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
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"
)

// ----------------------------------------------------------------------------
// Interface definition
// ----------------------------------------------------------------------------

type QuoteService interface {
	CreateQuote(ctx context.Context, req *CreateQuoteRequest) (*models.Quote, error)
	UpdateQuote(ctx context.Context, companyID, quoteID uuid.UUID, req *UpdateQuoteRequest) (*models.Quote, error)
	DeleteQuote(ctx context.Context, companyID, quoteID uuid.UUID, deletedBy uuid.UUID) error
	GetQuoteByID(ctx context.Context, companyID, quoteID uuid.UUID) (*models.Quote, error)
	GetQuoteByNumber(ctx context.Context, companyID uuid.UUID, quoteNumber string, revision int) (*models.Quote, error)
	ListQuotes(ctx context.Context, filter QuoteListFilter, p Pagination, s Sort) ([]*models.Quote, int64, error)
	SearchQuotes(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Quote, int64, error)
	GetQuotesByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Quote, int64, error)
	AddItems(ctx context.Context, companyID, quoteID uuid.UUID, items []*CreateQuoteItemRequest, updatedBy uuid.UUID) error
	ReplaceItems(ctx context.Context, companyID, quoteID uuid.UUID, items []*CreateQuoteItemRequest, updatedBy uuid.UUID) error
	RemoveItem(ctx context.Context, companyID, quoteID, quoteItemID uuid.UUID, updatedBy uuid.UUID) error
	GetQuoteItems(ctx context.Context, companyID, quoteID uuid.UUID) ([]*models.QuoteItem, error)
	ApplyCoupon(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, updatedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)
	RemoveCoupon(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, updatedBy uuid.UUID) error
	ApplyBestDiscounts(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	PreviewPricing(ctx context.Context, req *QuotePricingPreviewRequest) (*QuotePricingPreviewResult, error)
	RecalculateTotals(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	GetQuoteTotals(ctx context.Context, companyID, quoteID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error)
	CreateRevision(ctx context.Context, companyID, quoteID uuid.UUID, req *CreateQuoteRevisionRequest) (*models.Quote, error)
	GetLatestRevision(ctx context.Context, companyID uuid.UUID, quoteNumber string) (*models.Quote, error)
	UpdateStatus(ctx context.Context, companyID, quoteID uuid.UUID, status enums.QuoteStatus, updatedBy uuid.UUID) error
	MarkSent(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	AcceptQuote(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	RejectQuote(ctx context.Context, companyID, quoteID uuid.UUID, reason *string, updatedBy uuid.UUID) error
	ExpireQuote(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	GetExpiringQuotes(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Quote, error)
	ConvertToOrder(ctx context.Context, companyID, quoteID uuid.UUID, req *ConvertQuoteToOrderRequest) (*models.Order, error)
	IsConverted(ctx context.Context, companyID, quoteID uuid.UUID) (bool, error)
	AssignSalesRep(ctx context.Context, companyID, quoteID, salesRepID uuid.UUID, updatedBy uuid.UUID) error
	RemoveSalesRep(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error
	ValidateQuote(ctx context.Context, quote *models.Quote, items []*models.QuoteItem) error
	ValidateQuoteStatusTransition(ctx context.Context, currentStatus, nextStatus enums.QuoteStatus) error
	ValidateQuoteItems(ctx context.Context, companyID uuid.UUID, items []*CreateQuoteItemRequest) error
	ValidatePricing(ctx context.Context, companyID, quoteID uuid.UUID) error
	ValidateConversion(ctx context.Context, companyID, quoteID uuid.UUID) error
	GetQuoteConversionRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalQuotedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	QuoteExists(ctx context.Context, companyID, quoteID uuid.UUID) (bool, error)
	QuoteNumberExists(ctx context.Context, companyID uuid.UUID, quoteNumber string, revision int) (bool, error)
	IsExpired(ctx context.Context, companyID, quoteID uuid.UUID, at time.Time) (bool, error)
}

// ----------------------------------------------------------------------------
// Request / Response types
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Service implementation
// ----------------------------------------------------------------------------

type quoteService struct {
	quoteRepo         repository.QuoteRepository
	orderSvc          OrderService // changed from orderRepo to OrderService
	productRepo       repository.ProductRepository
	customerSvc       CustomerService
	pricingRepo       repository.PricingRepository
	couponRepo        repository.CouponRepository
	promotionRepo     repository.PromotionRepository
	discountUsageRepo repository.DiscountUsageRepository
	taxSnapshotRepo   repository.TaxSnapshotRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

func NewQuoteService(
	quoteRepo repository.QuoteRepository,
	orderSvc OrderService, // added
	productRepo repository.ProductRepository,
	customerSvc CustomerService,
	pricingRepo repository.PricingRepository,
	couponRepo repository.CouponRepository,
	promotionRepo repository.PromotionRepository,
	discountUsageRepo repository.DiscountUsageRepository,
	taxSnapshotRepo repository.TaxSnapshotRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) QuoteService {
	return &quoteService{
		quoteRepo:         quoteRepo,
		orderSvc:          orderSvc,
		productRepo:       productRepo,
		customerSvc:       customerSvc,
		pricingRepo:       pricingRepo,
		couponRepo:        couponRepo,
		promotionRepo:     promotionRepo,
		discountUsageRepo: discountUsageRepo,
		taxSnapshotRepo:   taxSnapshotRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("quote_service"),
	}
}

// ----------------------------------------------------------------------------
// CRUD & lifecycle operations
// ----------------------------------------------------------------------------

func (s *quoteService) CreateQuote(ctx context.Context, req *CreateQuoteRequest) (*models.Quote, error) {
	logger := s.logger.With(zap.String("method", "CreateQuote"))
	if err := s.validateCreateQuoteRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quoteNumber := req.QuoteNumber
	if quoteNumber == "" {
		quoteNumber, err = s.generateQuoteNumber(tx, req.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("generate quote number: %w", err)
		}
	}

	exists, err := s.quoteRepo.ExistsByNumber(ctx, tx, req.CompanyID, quoteNumber, 1)
	if err != nil {
		return nil, fmt.Errorf("check quote number: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: quote number %s already exists", salesErrors.ErrDuplicate, quoteNumber)
	}

	quoteDate := req.QuoteDate
	if quoteDate.IsZero() {
		quoteDate = time.Now().Truncate(24 * time.Hour)
	}
	currency := req.Currency
	if currency == "" {
		currency = "USD"
	}

	quote := &models.Quote{
		QuoteID:       uuid.New(),
		CompanyID:     req.CompanyID,
		CustomerID:    req.CustomerID,
		QuoteNumber:   quoteNumber,
		Revision:      1,
		QuoteDate:     quoteDate,
		ExpiryDate:    req.ExpiryDate,
		Status:        enums.QuoteStatusDraft,
		Currency:      currency,
		Subtotal:      decimal.Zero,
		DiscountTotal: decimal.Zero,
		TaxTotal:      decimal.Zero,
		Notes:         req.Notes,
		SalesRepID:    req.SalesRepID,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.CreatedBy,
	}

	if err := s.quoteRepo.Create(ctx, tx, quote, nil); err != nil {
		return nil, fmt.Errorf("create quote: %w", err)
	}

	if len(req.Items) > 0 {
		if err := s.addQuoteItems(ctx, tx, quote, req.Items); err != nil {
			return nil, err
		}
	}

	if err := s.recalculateQuoteTotals(ctx, tx, quote.QuoteID); err != nil {
		return nil, fmt.Errorf("recalculate totals: %w", err)
	}

	for _, code := range req.CouponCodes {
		if _, _, err := s.applyCouponInternal(ctx, tx, req.CompanyID, quote.QuoteID, code); err != nil {
			logger.Warn("failed to apply coupon", zap.String("code", code), zap.Error(err))
		}
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quote.QuoteID); err != nil {
		return nil, fmt.Errorf("recalculate totals after coupons: %w", err)
	}

	if err := s.emitQuoteEvent(ctx, tx, quote, salesEvents.EventQuoteCreated, nil); err != nil {
		logger.Warn("failed to emit quote created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_quote", "quote",
			&quote.QuoteID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"quote_number": quote.QuoteNumber,
				"revision":     quote.Revision,
			})
	}

	return s.quoteRepo.GetByID(ctx, nil, req.CompanyID, quote.QuoteID)
}

func (s *quoteService) UpdateQuote(ctx context.Context, companyID, quoteID uuid.UUID, req *UpdateQuoteRequest) (*models.Quote, error) {
	logger := s.logger.With(zap.String("method", "UpdateQuote"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	if quote.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return nil, fmt.Errorf("%w: only draft quotes can be updated", salesErrors.ErrInvalidStatus)
	}

	changes := make(map[string]interface{})
	if req.ExpiryDate != nil {
		quote.ExpiryDate = req.ExpiryDate
		changes["expiry_date"] = req.ExpiryDate
	}
	if req.Currency != nil {
		quote.Currency = *req.Currency
		changes["currency"] = req.Currency
	}
	if req.Notes != nil {
		quote.Notes = req.Notes
		changes["notes"] = req.Notes
	}
	if req.SalesRepID != nil {
		quote.SalesRepID = req.SalesRepID
		changes["sales_rep_id"] = req.SalesRepID
	}
	quote.UpdatedBy = req.UpdatedBy

	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return nil, fmt.Errorf("update quote: %w", err)
	}

	if err := s.emitQuoteEvent(ctx, tx, quote, salesEvents.EventQuoteUpdated, nil); err != nil {
		logger.Warn("failed to emit quote updated event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_quote", "quote",
			&quoteID, "user", req.UpdatedBy, nil, nil, changes)
	}

	return quote, nil
}

func (s *quoteService) DeleteQuote(ctx context.Context, companyID, quoteID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteQuote"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByID(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: only draft quotes can be deleted", salesErrors.ErrInvalidStatus)
	}

	if err := s.quoteRepo.Delete(ctx, tx, companyID, quoteID); err != nil {
		return fmt.Errorf("delete quote: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_quote", "quote",
			&quoteID, "user", &deletedBy, nil, nil, nil)
	}

	logger.Info("quote deleted", zap.String("quote_number", quote.QuoteNumber), zap.Int("revision", quote.Revision))
	return nil
}

// ----------------------------------------------------------------------------
// Retrieval methods
// ----------------------------------------------------------------------------

func (s *quoteService) GetQuoteByID(ctx context.Context, companyID, quoteID uuid.UUID) (*models.Quote, error) {
	return s.quoteRepo.GetByID(ctx, nil, companyID, quoteID)
}

func (s *quoteService) GetQuoteByNumber(ctx context.Context, companyID uuid.UUID, quoteNumber string, revision int) (*models.Quote, error) {
	return s.quoteRepo.GetByNumber(ctx, nil, companyID, quoteNumber, revision)
}

func (s *quoteService) ListQuotes(ctx context.Context, filter QuoteListFilter, p Pagination, srt Sort) ([]*models.Quote, int64, error) {
	repoFilter := repository.QuoteFilter{
		CompanyID:     filter.CompanyID,
		CustomerID:    filter.CustomerID,
		SalesRepID:    filter.SalesRepID,
		QuoteDateFrom: filter.FromDate,
		QuoteDateTo:   filter.ToDate,
		MinGrandTotal: filter.MinTotal,
		MaxGrandTotal: filter.MaxTotal,
	}
	if filter.Status != nil {
		repoFilter.Statuses = []enums.QuoteStatus{*filter.Status}
	}
	// SearchTerm does not exist in QuoteFilter – searching is handled by SearchQuotes method.
	return s.quoteRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}
func (s *quoteService) SearchQuotes(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Quote, int64, error) {
	return s.quoteRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *quoteService) GetQuotesByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Quote, int64, error) {
	return s.quoteRepo.GetByCustomer(ctx, nil, companyID, customerID,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

// ----------------------------------------------------------------------------
// Line item management
// ----------------------------------------------------------------------------

func (s *quoteService) AddItems(ctx context.Context, companyID, quoteID uuid.UUID, items []*CreateQuoteItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: cannot add items to quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	if err := s.addQuoteItems(ctx, tx, quote, items); err != nil {
		return err
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) ReplaceItems(ctx context.Context, companyID, quoteID uuid.UUID, items []*CreateQuoteItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: cannot replace items for quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	if err := s.quoteRepo.ReplaceItems(ctx, tx, companyID, quoteID, nil); err != nil {
		return fmt.Errorf("clear items: %w", err)
	}
	if len(items) > 0 {
		if err := s.addQuoteItems(ctx, tx, quote, items); err != nil {
			return err
		}
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) RemoveItem(ctx context.Context, companyID, quoteID, quoteItemID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: cannot remove item from quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	if err := s.quoteRepo.DeleteItem(ctx, tx, companyID, quoteID, quoteItemID); err != nil {
		return err
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) GetQuoteItems(ctx context.Context, companyID, quoteID uuid.UUID) ([]*models.QuoteItem, error) {
	return s.quoteRepo.GetItems(ctx, nil, companyID, quoteID)
}

// ----------------------------------------------------------------------------
// Discount & pricing
// ----------------------------------------------------------------------------

func (s *quoteService) ApplyCoupon(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, updatedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if quote.CompanyID != companyID {
		return nil, decimal.Zero, salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return nil, decimal.Zero, fmt.Errorf("%w: cannot apply coupon to quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	coupon, discountAmount, err := s.applyCouponInternal(ctx, tx, companyID, quoteID, couponCode)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return nil, decimal.Zero, err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return nil, decimal.Zero, err
	}
	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	return coupon, discountAmount, nil
}

func (s *quoteService) RemoveCoupon(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: cannot remove coupon from quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	if err := s.removeCouponInternal(ctx, tx, companyID, quoteID, couponCode); err != nil {
		return err
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) ApplyBestDiscounts(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusDraft {
		return fmt.Errorf("%w: cannot apply discounts to quote with status %s", salesErrors.ErrInvalidStatus, quote.Status)
	}

	items, err := s.quoteRepo.GetItems(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	orderAmount := s.calcSubtotalFromItems(items)
	productIDs := make([]uuid.UUID, len(items))
	for idx, it := range items {
		productIDs[idx] = it.ProductID
	}
	totalDiscount, _, _, err := s.pricingRepo.CalculateCombinedDiscount(ctx, tx, companyID, &quote.CustomerID, productIDs, orderAmount, time.Now())
	if err != nil {
		return err
	}
	quote.DiscountTotal = totalDiscount
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) PreviewPricing(ctx context.Context, req *QuotePricingPreviewRequest) (*QuotePricingPreviewResult, error) {
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}

	// Convert items to PricingProductLine (used by PricingPreviewInput)
	productLines := make([]*repository.PricingProductLine, len(req.Items))
	for idx, it := range req.Items {
		unitPrice := decimal.Zero
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		} else {
			// Fetch current product unit price if not provided
			var err error
			unitPrice, err = s.productRepo.GetUnitPrice(ctx, nil, req.CompanyID, it.ProductID)
			if err != nil {
				return nil, fmt.Errorf("failed to get unit price for product %s: %w", it.ProductID, err)
			}
		}
		discount := decimal.Zero
		if it.DiscountAmount != nil {
			discount = *it.DiscountAmount
		}
		productLines[idx] = &repository.PricingProductLine{
			ProductID: it.ProductID,
			Quantity:  it.Quantity,
			UnitPrice: unitPrice,
			// Note: PricingProductLine doesn't have DiscountAmount field.
			// Discounts are applied separately via coupon codes or promotions.
		}
		_ = discount // discount will be handled via coupon codes; line‑level discounts not supported in preview
	}

	preview, err := s.pricingRepo.PreviewOrderPricing(ctx, nil, &repository.PricingPreviewInput{
		CompanyID:    req.CompanyID,
		CustomerID:   req.CustomerID,
		ProductLines: productLines, // correct field name
		CouponCodes:  req.CouponCodes,
		PricedAt:     at, // correct field name
	})
	if err != nil {
		return nil, err
	}

	return &QuotePricingPreviewResult{
		Subtotal:          preview.Subtotal,
		DiscountTotal:     preview.DiscountTotal,
		TaxTotal:          preview.TaxTotal,
		GrandTotal:        preview.GrandTotal,
		AppliedCoupons:    preview.AppliedCoupons,
		AppliedPromotions: preview.AppliedPromotions,
	}, nil
}
func (s *quoteService) RecalculateTotals(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.recalculateQuoteTotals(ctx, tx, quoteID); err != nil {
		return err
	}
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) GetQuoteTotals(ctx context.Context, companyID, quoteID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error) {
	return s.quoteRepo.GetTotals(ctx, nil, companyID, quoteID)
}

// ----------------------------------------------------------------------------
// Revision management
// ----------------------------------------------------------------------------

func (s *quoteService) CreateRevision(ctx context.Context, companyID, quoteID uuid.UUID, req *CreateQuoteRevisionRequest) (*models.Quote, error) {
	logger := s.logger.With(zap.String("method", "CreateRevision"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	oldQuote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	if oldQuote.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if oldQuote.Status != enums.QuoteStatusDraft {
		return nil, fmt.Errorf("%w: only draft quotes can be revised", salesErrors.ErrInvalidStatus)
	}

	newRevision := oldQuote.Revision + 1
	exists, err := s.quoteRepo.ExistsByNumber(ctx, tx, companyID, oldQuote.QuoteNumber, newRevision)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: revision %d already exists for quote %s", salesErrors.ErrDuplicate, newRevision, oldQuote.QuoteNumber)
	}

	newQuote := &models.Quote{
		QuoteID:       uuid.New(),
		CompanyID:     oldQuote.CompanyID,
		CustomerID:    oldQuote.CustomerID,
		QuoteNumber:   oldQuote.QuoteNumber,
		Revision:      newRevision,
		QuoteDate:     time.Now().Truncate(24 * time.Hour),
		ExpiryDate:    req.ExpiryDate,
		Status:        enums.QuoteStatusDraft,
		Currency:      oldQuote.Currency,
		Subtotal:      decimal.Zero,
		DiscountTotal: decimal.Zero,
		TaxTotal:      decimal.Zero,
		Notes:         req.Notes,
		SalesRepID:    oldQuote.SalesRepID,
		CreatedBy:     req.UpdatedBy,
		UpdatedBy:     req.UpdatedBy,
	}
	if err := s.quoteRepo.Create(ctx, tx, newQuote, nil); err != nil {
		return nil, fmt.Errorf("create revision: %w", err)
	}

	var items []*CreateQuoteItemRequest
	if len(req.Items) > 0 {
		items = req.Items
	} else {
		oldItems, err := s.quoteRepo.GetItems(ctx, tx, companyID, oldQuote.QuoteID)
		if err != nil {
			return nil, err
		}
		items = make([]*CreateQuoteItemRequest, len(oldItems))
		for idx, it := range oldItems {
			items[idx] = &CreateQuoteItemRequest{
				ProductID:      it.ProductID,
				Quantity:       it.Quantity,
				UnitPrice:      &it.UnitPrice,
				DiscountAmount: &it.DiscountAmount,
				Metadata:       it.Metadata,
			}
		}
	}
	if err := s.addQuoteItems(ctx, tx, newQuote, items); err != nil {
		return nil, err
	}
	for _, code := range req.CouponCodes {
		_, _, _ = s.applyCouponInternal(ctx, tx, companyID, newQuote.QuoteID, code)
	}
	if err := s.recalculateQuoteTotals(ctx, tx, newQuote.QuoteID); err != nil {
		return nil, err
	}
	if err := s.emitQuoteEvent(ctx, tx, newQuote, salesEvents.EventQuoteCreated, nil); err != nil {
		logger.Warn("failed to emit quote revision event", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return newQuote, nil
}

func (s *quoteService) GetLatestRevision(ctx context.Context, companyID uuid.UUID, quoteNumber string) (*models.Quote, error) {
	// List all revisions of this quote number and pick the highest revision.
	// Note: you may want to add a dedicated method to repository for efficiency.
	filter := repository.QuoteFilter{
		CompanyID:   companyID,
		QuoteNumber: &quoteNumber,
	}
	quotes, _, err := s.quoteRepo.List(ctx, nil, filter, repository.Pagination{Limit: 1000, Offset: 0}, repository.Sort{Field: "revision", Direction: "DESC"})
	if err != nil {
		return nil, err
	}
	if len(quotes) == 0 {
		return nil, fmt.Errorf("%w: quote number %s not found", salesErrors.ErrNotFound, quoteNumber)
	}
	return quotes[0], nil
}

// ----------------------------------------------------------------------------
// Status transitions
// ----------------------------------------------------------------------------

func (s *quoteService) UpdateStatus(ctx context.Context, companyID, quoteID uuid.UUID, status enums.QuoteStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.validateStatusTransition(quote.Status, status); err != nil {
		return err
	}
	if err := s.quoteRepo.UpdateStatus(ctx, tx, companyID, quoteID, status, &updatedBy); err != nil {
		return err
	}
	quote.Status = status
	if err := s.emitQuoteEvent(ctx, tx, quote, s.mapStatusToEvent(status), nil); err != nil {
		s.logger.Warn("failed to emit status change event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *quoteService) MarkSent(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, quoteID, enums.QuoteStatusSent, updatedBy)
}

func (s *quoteService) AcceptQuote(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, quoteID, enums.QuoteStatusAccepted, updatedBy)
}

func (s *quoteService) RejectQuote(ctx context.Context, companyID, quoteID uuid.UUID, reason *string, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.validateStatusTransition(quote.Status, enums.QuoteStatusRejected); err != nil {
		return err
	}
	if reason != nil {
		newNotes := *reason
		if quote.Notes != nil {
			newNotes = *quote.Notes + "\nRejection reason: " + *reason
		}
		quote.Notes = &newNotes
	}
	quote.Status = enums.QuoteStatusRejected
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	if err := s.emitQuoteEvent(ctx, tx, quote, salesEvents.EventQuoteRejected, nil); err != nil {
		s.logger.Warn("failed to emit reject event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *quoteService) ExpireQuote(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, quoteID, enums.QuoteStatusExpired, updatedBy)
}

func (s *quoteService) GetExpiringQuotes(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Quote, error) {
	return s.quoteRepo.GetExpiringQuotes(ctx, nil, companyID, before)
}

// ----------------------------------------------------------------------------
// Conversion to order
// ----------------------------------------------------------------------------

func (s *quoteService) ConvertToOrder(ctx context.Context, companyID, quoteID uuid.UUID, req *ConvertQuoteToOrderRequest) (*models.Order, error) {
	logger := s.logger.With(zap.String("method", "ConvertToOrder"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	if quote.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if quote.Status != enums.QuoteStatusAccepted {
		return nil, fmt.Errorf("%w: only accepted quotes can be converted", salesErrors.ErrInvalidTransition)
	}
	converted, err := s.quoteRepo.IsConverted(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	if converted {
		return nil, fmt.Errorf("%w: quote already converted to an order", salesErrors.ErrDuplicate)
	}
	if quote.ExpiryDate != nil && time.Now().After(*quote.ExpiryDate) {
		return nil, fmt.Errorf("%w: quote has expired", salesErrors.ErrInvalidStatus)
	}

	// Build order creation request from quote
	items := make([]*CreateOrderItemRequest, 0)
	quoteItems, err := s.quoteRepo.GetItems(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, err
	}
	for _, qi := range quoteItems {
		discount := qi.DiscountAmount
		items = append(items, &CreateOrderItemRequest{
			ProductID:      qi.ProductID,
			Quantity:       qi.Quantity,
			UnitPrice:      &qi.UnitPrice,
			DiscountAmount: &discount,
			Metadata:       qi.Metadata,
		})
	}
	orderReq := &CreateOrderRequest{
		CompanyID:       quote.CompanyID,
		CustomerID:      quote.CustomerID,
		OrderDate:       req.OrderDate,
		Currency:        quote.Currency,
		Notes:           req.Notes,
		ShippingAddress: req.ShippingAddress,
		BillingAddress:  req.BillingAddress,
		SalesRepID:      quote.SalesRepID,
		Items:           items,
		CreatedBy:       req.UpdatedBy,
	}

	// Generate unique idempotency key for this conversion
	idempotencyKey := fmt.Sprintf("convert-quote-%s", quoteID.String())
	order, err := s.orderSvc.CreateDraftOrder(ctx, orderReq, idempotencyKey)
	if err != nil {
		return nil, fmt.Errorf("create order from quote: %w", err)
	}

	// Mark quote as converted (using the same transaction that created the order)
	// Note: The order was created inside its own transaction, which is already committed.
	// To keep both consistent, we should use the same transaction. Since CreateDraftOrder
	// commits its own transaction, we cannot reuse that tx. This is a known limitation.
	// For true atomicity, you would need to refactor OrderService to accept an existing tx.
	// Here we simply update the quote in a new transaction, which may lead to inconsistency.
	// A better approach is to pass the tx into CreateDraftOrder (not implemented).
	// For now, we do a separate update. In production, modify OrderService to accept a tx.
	tx2, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx2.Rollback()
	if err := s.quoteRepo.ConvertToOrder(ctx, tx2, companyID, quoteID, order.OrderID, req.UpdatedBy); err != nil {
		return nil, err
	}
	// Emit quote converted event
	if err := s.emitQuoteEvent(ctx, tx2, quote, salesEvents.EventQuoteConverted, map[string]interface{}{"order_id": order.OrderID.String()}); err != nil {
		logger.Warn("failed to emit quote converted event", zap.Error(err))
	}
	if err := tx2.Commit(); err != nil {
		return nil, err
	}

	return order, nil
}
func (s *quoteService) IsConverted(ctx context.Context, companyID, quoteID uuid.UUID) (bool, error) {
	return s.quoteRepo.IsConverted(ctx, nil, companyID, quoteID)
}

// ----------------------------------------------------------------------------
// Sales rep assignment
// ----------------------------------------------------------------------------

func (s *quoteService) AssignSalesRep(ctx context.Context, companyID, quoteID, salesRepID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	quote.SalesRepID = &salesRepID
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *quoteService) RemoveSalesRep(ctx context.Context, companyID, quoteID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	quote.SalesRepID = nil
	quote.UpdatedBy = &updatedBy
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return err
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

func (s *quoteService) ValidateQuote(ctx context.Context, quote *models.Quote, items []*models.QuoteItem) error {
	if quote.QuoteNumber == "" {
		return fmt.Errorf("%w: quote number required", salesErrors.ErrInvalidInput)
	}
	if quote.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: quote must contain at least one item", salesErrors.ErrInvalidInput)
	}
	for _, it := range items {
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}

func (s *quoteService) ValidateQuoteStatusTransition(ctx context.Context, currentStatus, nextStatus enums.QuoteStatus) error {
	return s.validateStatusTransition(currentStatus, nextStatus)
}

func (s *quoteService) ValidateQuoteItems(ctx context.Context, companyID uuid.UUID, items []*CreateQuoteItemRequest) error {
	for _, it := range items {
		if it.ProductID == uuid.Nil {
			return fmt.Errorf("%w: product_id required", salesErrors.ErrInvalidInput)
		}
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
		exists, err := s.productRepo.Exists(ctx, nil, companyID, it.ProductID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: product %s not found", salesErrors.ErrNotFound, it.ProductID)
		}
	}
	return nil
}

func (s *quoteService) ValidatePricing(ctx context.Context, companyID, quoteID uuid.UUID) error {
	subtotal, discountTotal, taxTotal, grandTotal, err := s.quoteRepo.GetTotals(ctx, nil, companyID, quoteID)
	if err != nil {
		return err
	}
	items, err := s.quoteRepo.GetItems(ctx, nil, companyID, quoteID)
	if err != nil {
		return err
	}
	var calcSubtotal, calcDiscount, calcTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		calcSubtotal = calcSubtotal.Add(lineSub)
		calcDiscount = calcDiscount.Add(it.DiscountAmount)
		calcTax = calcTax.Add(it.TaxAmount)
	}
	calcGrand := calcSubtotal.Sub(calcDiscount).Add(calcTax)
	if !subtotal.Equal(calcSubtotal) || !discountTotal.Equal(calcDiscount) || !taxTotal.Equal(calcTax) || !grandTotal.Equal(calcGrand) {
		return fmt.Errorf("pricing validation failed: stored totals do not match line items")
	}
	return nil
}

func (s *quoteService) ValidateConversion(ctx context.Context, companyID, quoteID uuid.UUID) error {
	quote, err := s.quoteRepo.GetByID(ctx, nil, companyID, quoteID)
	if err != nil {
		return err
	}
	if quote.Status != enums.QuoteStatusAccepted {
		return fmt.Errorf("%w: only accepted quotes can be converted", salesErrors.ErrInvalidTransition)
	}
	if quote.ExpiryDate != nil && time.Now().After(*quote.ExpiryDate) {
		return fmt.Errorf("%w: quote has expired", salesErrors.ErrInvalidStatus)
	}
	converted, err := s.quoteRepo.IsConverted(ctx, nil, companyID, quoteID)
	if err != nil {
		return err
	}
	if converted {
		return fmt.Errorf("%w: quote already converted", salesErrors.ErrDuplicate)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Analytics & reporting
// ----------------------------------------------------------------------------

func (s *quoteService) GetQuoteConversionRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.quoteRepo.GetQuoteConversionRate(ctx, nil, companyID, from, to)
}

func (s *quoteService) GetTotalQuotedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.quoteRepo.GetTotalQuotedRevenue(ctx, nil, companyID, from, to)
}

// ----------------------------------------------------------------------------
// Existence helpers
// ----------------------------------------------------------------------------

func (s *quoteService) QuoteExists(ctx context.Context, companyID, quoteID uuid.UUID) (bool, error) {
	return s.quoteRepo.Exists(ctx, nil, companyID, quoteID)
}

func (s *quoteService) QuoteNumberExists(ctx context.Context, companyID uuid.UUID, quoteNumber string, revision int) (bool, error) {
	return s.quoteRepo.ExistsByNumber(ctx, nil, companyID, quoteNumber, revision)
}

func (s *quoteService) IsExpired(ctx context.Context, companyID, quoteID uuid.UUID, at time.Time) (bool, error) {
	return s.quoteRepo.IsExpired(ctx, nil, companyID, quoteID, at)
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

func (s *quoteService) validateCreateQuoteRequest(req *CreateQuoteRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return fmt.Errorf("%w: at least one item required", salesErrors.ErrInvalidInput)
	}
	return s.ValidateQuoteItems(context.Background(), req.CompanyID, req.Items)
}

func (s *quoteService) addQuoteItems(ctx context.Context, tx repository.DBTX, quote *models.Quote, items []*CreateQuoteItemRequest) error {
	quoteItems := make([]*models.QuoteItem, 0, len(items))
	for _, it := range items {
		product, err := s.productRepo.GetByID(ctx, tx, quote.CompanyID, it.ProductID)
		if err != nil {
			return fmt.Errorf("product %s: %w", it.ProductID, err)
		}
		if !product.IsActive {
			return fmt.Errorf("%w: product %s is inactive", salesErrors.ErrProductInactive, product.SKU)
		}
		unitPrice := product.UnitPrice
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		}
		discount := decimal.Zero
		if it.DiscountAmount != nil {
			discount = *it.DiscountAmount
		}
		item := &models.QuoteItem{
			QuoteItemID:         uuid.New(),
			QuoteID:             quote.QuoteID,
			ProductID:           product.ProductID,
			ProductNameSnapshot: product.Name,
			Quantity:            it.Quantity,
			UnitPrice:           unitPrice,
			DiscountAmount:      discount,
			TaxAmount:           decimal.Zero,
			Metadata:            it.Metadata,
		}
		quoteItems = append(quoteItems, item)
	}
	return s.quoteRepo.AddItems(ctx, tx, quote.CompanyID, quote.QuoteID, quoteItems)
}

func (s *quoteService) recalculateQuoteTotals(ctx context.Context, tx repository.DBTX, quoteID uuid.UUID) error {
	quote, err := s.quoteRepo.GetByID(ctx, tx, uuid.Nil, quoteID)
	if err != nil {
		return err
	}
	items, err := s.quoteRepo.GetItems(ctx, tx, quote.CompanyID, quoteID)
	if err != nil {
		return err
	}
	var subtotal, discountTotal, taxTotal decimal.Decimal
	for _, it := range items {
		lineSubtotal := it.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineSubtotal)
		discountTotal = discountTotal.Add(it.DiscountAmount)
		taxable := lineSubtotal.Sub(it.DiscountAmount)
		tax, err := s.pricingRepo.CalculateLineTax(ctx, tx, quote.CompanyID, it.ProductID, taxable)
		if err != nil {
			return fmt.Errorf("calculate line tax: %w", err)
		}
		it.TaxAmount = tax
		taxTotal = taxTotal.Add(tax)
		updateQuery := `UPDATE sales.quote_items SET tax_amount = $1 WHERE quote_item_id = $2`
		if _, err := tx.ExecContext(ctx, updateQuery, tax, it.QuoteItemID); err != nil {
			return fmt.Errorf("update item tax: %w", err)
		}
	}
	quote.Subtotal = subtotal
	quote.DiscountTotal = discountTotal
	quote.TaxTotal = taxTotal
	// grandTotal is computed by stored generated column, no need to set
	if err := s.quoteRepo.Update(ctx, tx, quote); err != nil {
		return fmt.Errorf("update quote totals: %w", err)
	}
	return nil
}

func (s *quoteService) applyCouponInternal(ctx context.Context, tx repository.DBTX, companyID, quoteID uuid.UUID, couponCode string) (*discount.Coupon, decimal.Decimal, error) {
	coupon, err := s.couponRepo.ValidateCoupon(ctx, tx, companyID, couponCode, nil, decimal.Zero, nil, time.Now())
	if err != nil {
		return nil, decimal.Zero, err
	}
	subtotal, _, _, _, err := s.quoteRepo.GetTotals(ctx, tx, companyID, quoteID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	discountAmount, err := s.couponRepo.CalculateDiscount(ctx, tx, companyID, coupon.CouponID, subtotal)
	if err != nil {
		return nil, decimal.Zero, err
	}
	return coupon, discountAmount, nil
}

func (s *quoteService) removeCouponInternal(ctx context.Context, tx repository.DBTX, companyID, quoteID uuid.UUID, couponCode string) error {
	// No persistent storage of applied coupons on quote, so nothing to remove.
	return nil
}

func (s *quoteService) generateQuoteNumber(tx repository.DBTX, companyID uuid.UUID) (string, error) {
	prefix := companyID.String()[:8]
	timestamp := time.Now().UnixMilli()
	quoteNumber := fmt.Sprintf("QT-%s-%d", prefix, timestamp)
	exists, err := s.quoteRepo.ExistsByNumber(context.Background(), tx, companyID, quoteNumber, 1)
	if err != nil {
		return "", err
	}
	if exists {
		return fmt.Sprintf("QT-%s-%d-1", prefix, timestamp), nil
	}
	return quoteNumber, nil
}

func (s *quoteService) validateStatusTransition(current, next enums.QuoteStatus) error {
	transitions := map[enums.QuoteStatus][]enums.QuoteStatus{
		enums.QuoteStatusDraft:     {enums.QuoteStatusSent, enums.QuoteStatusRejected},
		enums.QuoteStatusSent:      {enums.QuoteStatusAccepted, enums.QuoteStatusRejected, enums.QuoteStatusExpired},
		enums.QuoteStatusAccepted:  {enums.QuoteStatusConverted},
		enums.QuoteStatusRejected:  {},
		enums.QuoteStatusExpired:   {},
		enums.QuoteStatusConverted: {},
	}
	allowed, ok := transitions[current]
	if !ok {
		return fmt.Errorf("%w: unknown status %s", salesErrors.ErrInvalidStatus, current)
	}
	for _, s := range allowed {
		if s == next {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidTransition, current, next)
}

func (s *quoteService) mapStatusToEvent(status enums.QuoteStatus) string {
	switch status {
	case enums.QuoteStatusSent:
		return salesEvents.EventQuoteSent
	case enums.QuoteStatusAccepted:
		return salesEvents.EventQuoteAccepted
	case enums.QuoteStatusRejected:
		return salesEvents.EventQuoteRejected
	case enums.QuoteStatusExpired:
		return salesEvents.EventQuoteExpired
	case enums.QuoteStatusConverted:
		return salesEvents.EventQuoteConverted
	default:
		return salesEvents.EventQuoteUpdated
	}
}

func (s *quoteService) emitQuoteEvent(ctx context.Context, tx repository.DBTX, quote *models.Quote, eventType string, extra map[string]interface{}) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	expiry := ""
	if quote.ExpiryDate != nil {
		expiry = quote.ExpiryDate.Format(time.RFC3339)
	}
	payload := salesEvents.QuotePayload{
		QuoteID:     quote.QuoteID.String(),
		CompanyID:   quote.CompanyID.String(),
		CustomerID:  quote.CustomerID.String(),
		QuoteNumber: quote.QuoteNumber,
		Revision:    quote.Revision,
		Status:      string(quote.Status), // fixed
		GrandTotal:  quote.GrandTotal.String(),
		ExpiryDate:  expiry, // fixed: empty string if nil
	}
	if extra != nil {
		// optionally merge extra fields (not needed for standard events)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "quote",
		AggregateID:   quote.QuoteID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *quoteService) calcSubtotalFromItems(items []*models.QuoteItem) decimal.Decimal {
	var total decimal.Decimal
	for _, it := range items {
		total = total.Add(it.UnitPrice.Mul(it.Quantity))
	}
	return total
}
