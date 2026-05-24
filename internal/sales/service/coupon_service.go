package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
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
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"
)

// CouponService defines all coupon management and application operations.
type CouponService interface {
	CreateCoupon(ctx context.Context, req *CreateCouponRequest) (*discount.Coupon, error)
	UpdateCoupon(ctx context.Context, companyID, couponID uuid.UUID, req *UpdateCouponRequest) (*discount.Coupon, error)
	DeleteCoupon(ctx context.Context, companyID, couponID uuid.UUID, deletedBy uuid.UUID) error
	GetCouponByID(ctx context.Context, companyID, couponID uuid.UUID) (*discount.Coupon, error)
	GetCouponByCode(ctx context.Context, companyID uuid.UUID, code string) (*discount.Coupon, error)
	ListCoupons(ctx context.Context, filter CouponListFilter, p Pagination, s Sort) ([]*discount.Coupon, int64, error)
	SearchCoupons(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*discount.Coupon, int64, error)
	GetActiveCoupons(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error)

	ActivateCoupon(ctx context.Context, companyID, couponID uuid.UUID, updatedBy uuid.UUID) error
	DeactivateCoupon(ctx context.Context, companyID, couponID uuid.UUID, updatedBy uuid.UUID) error
	IsCouponActive(ctx context.Context, companyID, couponID uuid.UUID, at time.Time) (bool, error)
	ExpireCoupon(ctx context.Context, companyID, couponID uuid.UUID, expiredBy uuid.UUID) error

	ValidateCoupon(ctx context.Context, companyID uuid.UUID, couponCode string, customerID *uuid.UUID, orderAmount decimal.Decimal, productIDs []uuid.UUID, at time.Time) error
	ValidateCouponDates(ctx context.Context, coupon *discount.Coupon, at time.Time) error
	ValidateCouponUsageLimit(ctx context.Context, companyID, couponID uuid.UUID) error
	ValidateCustomerUsageLimit(ctx context.Context, companyID, couponID, customerID uuid.UUID) error
	ValidateMinimumOrderAmount(ctx context.Context, coupon *discount.Coupon, orderAmount decimal.Decimal) error
	ValidateCouponProducts(ctx context.Context, coupon *discount.Coupon, productIDs []uuid.UUID) error
	CanCustomerUseCoupon(ctx context.Context, companyID, couponID, customerID uuid.UUID, at time.Time) (bool, error)

	CalculateDiscount(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal) (decimal.Decimal, error)
	CalculateDiscountForProducts(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error)

	ApplyCouponToOrder(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)
	ApplyCouponToQuote(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)
	ApplyCouponToInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)

	RemoveCouponFromOrder(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, removedBy uuid.UUID) error
	RemoveCouponFromQuote(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, removedBy uuid.UUID) error
	RemoveCouponFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, couponCode string, removedBy uuid.UUID) error

	RecordCouponUsage(ctx context.Context, req *RecordCouponUsageRequest) error
	RecordOrderCouponUsage(ctx context.Context, companyID, couponID, orderID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	RecordQuoteCouponUsage(ctx context.Context, companyID, couponID, quoteID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	RecordInvoiceCouponUsage(ctx context.Context, companyID, couponID, invoiceID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error

	GetCouponUsageCount(ctx context.Context, companyID, couponID uuid.UUID) (int64, error)
	GetCustomerCouponUsageCount(ctx context.Context, companyID, couponID, customerID uuid.UUID) (int64, error)
	GetCouponUsageHistory(ctx context.Context, companyID, couponID uuid.UUID, p Pagination, s Sort) ([]*discount.CouponUsage, int64, error)

	GetTopCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetMostUsedCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetHighestDiscountCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error)
	GetTotalCouponDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCouponRedemptionRate(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	CouponExists(ctx context.Context, companyID, couponID uuid.UUID) (bool, error)
	CouponCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	IsCouponExpired(ctx context.Context, companyID, couponID uuid.UUID, at time.Time) (bool, error)
	IsCouponUsageLimitReached(ctx context.Context, companyID, couponID uuid.UUID) (bool, error)
	IsCustomerUsageLimitReached(ctx context.Context, companyID, couponID, customerID uuid.UUID) (bool, error)
}

type couponService struct {
	couponRepo       repository.CouponRepository
	usageRepo        repository.DiscountUsageRepository
	orderRepo        repository.OrderRepository
	quoteRepo        repository.QuoteRepository
	invoiceRepo      repository.InvoiceRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewCouponService(
	couponRepo repository.CouponRepository,
	usageRepo repository.DiscountUsageRepository,
	orderRepo repository.OrderRepository,
	quoteRepo repository.QuoteRepository,
	invoiceRepo repository.InvoiceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) CouponService {
	return &couponService{
		couponRepo:       couponRepo,
		usageRepo:        usageRepo,
		orderRepo:        orderRepo,
		quoteRepo:        quoteRepo,
		invoiceRepo:      invoiceRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("coupon_service"),
	}
}

// ---------------------------------------------------------------------
//  Validation helpers
// ---------------------------------------------------------------------

func (s *couponService) validateCouponDates(coupon *discount.Coupon, at time.Time) error {
	if at.Before(coupon.StartDate) {
		return fmt.Errorf("%w: coupon not yet active", salesErrors.ErrInvalidInput)
	}
	if at.After(coupon.EndDate) {
		return fmt.Errorf("%w: coupon expired", salesErrors.ErrCouponExpired)
	}
	return nil
}

func (s *couponService) validateCouponUsageLimit(ctx context.Context, tx repository.DBTX, companyID, couponID uuid.UUID) error {
	coupon, err := s.couponRepo.GetByID(ctx, tx, companyID, couponID)
	if err != nil {
		return err
	}
	if coupon.UsageLimit == nil {
		return nil
	}
	used, err := s.couponRepo.GetTotalUsageCount(ctx, tx, companyID, couponID)
	if err != nil {
		return err
	}
	if used >= int64(*coupon.UsageLimit) {
		return fmt.Errorf("%w: coupon usage limit reached", salesErrors.ErrCouponUsageLimit)
	}
	return nil
}

func (s *couponService) validateCustomerUsageLimit(ctx context.Context, tx repository.DBTX, companyID, couponID, customerID uuid.UUID) error {
	coupon, err := s.couponRepo.GetByID(ctx, tx, companyID, couponID)
	if err != nil {
		return err
	}
	if coupon.PerUserLimit == nil {
		return nil
	}
	used, err := s.couponRepo.GetCustomerUsageCount(ctx, tx, companyID, couponID, customerID)
	if err != nil {
		return err
	}
	if used >= int64(*coupon.PerUserLimit) {
		return fmt.Errorf("%w: customer reached per‑user limit for this coupon", salesErrors.ErrCouponUsageLimit)
	}
	return nil
}

func (s *couponService) validateMinimumOrderAmount(coupon *discount.Coupon, orderAmount decimal.Decimal) error {
	if coupon.MinOrderAmount != nil && orderAmount.LessThan(*coupon.MinOrderAmount) {
		return fmt.Errorf("%w: order amount %s below minimum %s", salesErrors.ErrInvalidInput,
			orderAmount.String(), coupon.MinOrderAmount.String())
	}
	return nil
}

func (s *couponService) validateCouponProducts(coupon *discount.Coupon, productIDs []uuid.UUID) error {
	if coupon.ApplicableItems == nil || len(coupon.ApplicableItems) == 0 {
		return nil
	}
	var rule struct {
		ProductIDs []uuid.UUID `json:"product_ids"`
	}
	if err := json.Unmarshal(coupon.ApplicableItems, &rule); err != nil {
		return fmt.Errorf("invalid applicable_items for coupon %s: %w", coupon.CouponID, err)
	}
	if len(rule.ProductIDs) == 0 {
		return nil
	}
	allowed := make(map[uuid.UUID]bool)
	for _, pid := range rule.ProductIDs {
		allowed[pid] = true
	}
	for _, pid := range productIDs {
		if !allowed[pid] {
			return fmt.Errorf("%w: coupon not applicable to product %s", salesErrors.ErrInvalidInput, pid)
		}
	}
	return nil
}
func (s *couponService) calculateDiscountAmount(coupon *discount.Coupon, subtotal decimal.Decimal) decimal.Decimal {
	var discount decimal.Decimal
	switch coupon.DiscountType {
	case enums.DiscountTypePercentage:
		discount = subtotal.Mul(coupon.DiscountValue.Div(decimal.NewFromInt(100)))
		if coupon.MaxDiscountAmount != nil && discount.GreaterThan(*coupon.MaxDiscountAmount) {
			discount = *coupon.MaxDiscountAmount
		}
	case enums.DiscountTypeFixed:
		discount = coupon.DiscountValue
		if coupon.MaxDiscountAmount != nil && discount.GreaterThan(*coupon.MaxDiscountAmount) {
			discount = *coupon.MaxDiscountAmount
		}
		if discount.GreaterThan(subtotal) {
			discount = subtotal
		}
	default:
		discount = decimal.Zero
	}
	return discount
}

// recordUsage only works for orders (schema limitation)
func (s *couponService) recordUsage(ctx context.Context, tx repository.DBTX, companyID, couponID, orderID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	if orderID == uuid.Nil {
		return nil
	}
	usage := &discount.CouponUsage{
		UsageID:        uuid.New(),
		CouponID:       couponID,
		CustomerID:     *customerID,
		OrderID:        orderID,
		DiscountAmount: discountAmount,
		UsedAt:         usedAt,
	}
	return s.couponRepo.CreateUsage(ctx, tx, usage)
}

// emitCouponEvent expects a *sql.Tx (concrete)
func (s *couponService) emitCouponEvent(ctx context.Context, tx *sql.Tx, coupon *discount.Coupon, eventType string) error {
	payload := map[string]interface{}{
		"coupon_id":      coupon.CouponID.String(),
		"company_id":     coupon.CompanyID.String(),
		"code":           coupon.Code,
		"discount_type":  coupon.DiscountType.String(),
		"discount_value": coupon.DiscountValue.String(),
		"is_active":      coupon.IsActive,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "coupon",
		AggregateID:   coupon.CouponID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// ---------------------------------------------------------------------
//  CreateCoupon
// ---------------------------------------------------------------------

func (s *couponService) CreateCoupon(ctx context.Context, req *CreateCouponRequest) (*discount.Coupon, error) {
	if err := s.validateCreateCoupon(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *discount.Coupon
	if err := s.idempotencyStore.Get(ctx, tx, req.IdempotencyKey, &cached); err == nil && cached != nil {
		s.logger.Info("idempotent create coupon", zap.String("key", req.IdempotencyKey))
		return cached, nil
	}

	exists, err := s.couponRepo.ExistsByCode(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: coupon code %s already exists", salesErrors.ErrDuplicate, req.Code)
	}

	coupon := &discount.Coupon{
		CouponID:          uuid.New(),
		CompanyID:         req.CompanyID,
		Code:              req.Code,
		DiscountType:      req.DiscountType,
		DiscountValue:     req.DiscountValue,
		MaxDiscountAmount: req.MaxDiscountAmount,
		StartDate:         req.StartDate,
		EndDate:           req.EndDate,
		UsageLimit:        req.UsageLimit,
		PerUserLimit:      req.PerUserLimit,
		MinOrderAmount:    req.MinOrderAmount,
		ApplicableItems:   req.ApplicableItems,
		IsActive:          true,
		CreatedBy:         req.CreatedBy,
		UpdatedBy:         req.CreatedBy,
	}
	if err := s.couponRepo.Create(ctx, tx, coupon); err != nil {
		return nil, fmt.Errorf("create coupon: %w", err)
	}

	// tx is *sql.Tx, pass directly
	if err := s.emitCouponEvent(ctx, tx, coupon, salesEvents.EventCouponCreated); err != nil {
		s.logger.Warn("failed to emit coupon created event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, req.IdempotencyKey, coupon)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_coupon", "coupon",
			&coupon.CouponID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": coupon.Code,
			})
	}
	return coupon, nil
}

func (s *couponService) validateCreateCoupon(req *CreateCouponRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if req.DiscountValue.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: discount_value must be positive", salesErrors.ErrInvalidInput)
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		return fmt.Errorf("%w: start_date and end_date required", salesErrors.ErrInvalidInput)
	}
	if req.StartDate.After(req.EndDate) {
		return fmt.Errorf("%w: start_date must be before end_date", salesErrors.ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------
//  UpdateCoupon
// ---------------------------------------------------------------------

func (s *couponService) UpdateCoupon(ctx context.Context, companyID, couponID uuid.UUID, req *UpdateCouponRequest) (*discount.Coupon, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *discount.Coupon
	if err := s.idempotencyStore.Get(ctx, tx, req.IdempotencyKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	coupon, err := s.couponRepo.GetByIDForUpdate(ctx, tx, companyID, couponID)
	if err != nil {
		return nil, err
	}
	if coupon.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := map[string]interface{}{}

	if req.Code != nil && *req.Code != coupon.Code {
		exists, err := s.couponRepo.ExistsByCode(ctx, tx, companyID, *req.Code)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: coupon code %s already exists", salesErrors.ErrDuplicate, *req.Code)
		}
		changes["code"] = map[string]string{"old": coupon.Code, "new": *req.Code}
		coupon.Code = *req.Code
	}
	if req.DiscountType != nil && *req.DiscountType != coupon.DiscountType {
		changes["discount_type"] = map[string]enums.DiscountType{"old": coupon.DiscountType, "new": *req.DiscountType}
		coupon.DiscountType = *req.DiscountType
	}
	if req.DiscountValue != nil && !req.DiscountValue.Equal(coupon.DiscountValue) {
		changes["discount_value"] = map[string]string{"old": coupon.DiscountValue.String(), "new": req.DiscountValue.String()}
		coupon.DiscountValue = *req.DiscountValue
	}
	if req.MaxDiscountAmount != nil {
		coupon.MaxDiscountAmount = req.MaxDiscountAmount
	}
	if req.StartDate != nil {
		coupon.StartDate = *req.StartDate
	}
	if req.EndDate != nil {
		coupon.EndDate = *req.EndDate
	}
	if req.UsageLimit != nil {
		coupon.UsageLimit = req.UsageLimit
	}
	if req.PerUserLimit != nil {
		coupon.PerUserLimit = req.PerUserLimit
	}
	if req.MinOrderAmount != nil {
		coupon.MinOrderAmount = req.MinOrderAmount
	}
	if req.ApplicableItems != nil {
		coupon.ApplicableItems = req.ApplicableItems
	}
	coupon.UpdatedBy = req.UpdatedBy

	if err := s.couponRepo.Update(ctx, tx, coupon); err != nil {
		return nil, fmt.Errorf("update coupon: %w", err)
	}

	if err := s.emitCouponEvent(ctx, tx, coupon, salesEvents.EventCouponUpdated); err != nil {
		s.logger.Warn("failed to emit coupon updated event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, req.IdempotencyKey, coupon)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_coupon", "coupon",
			&couponID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return coupon, nil
}

// ---------------------------------------------------------------------
//  DeleteCoupon
// ---------------------------------------------------------------------

func (s *couponService) DeleteCoupon(ctx context.Context, companyID, couponID uuid.UUID, deletedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, deletedBy.String(), &processed); err == nil && processed {
		return nil
	}

	coupon, err := s.couponRepo.GetByID(ctx, tx, companyID, couponID)
	if err != nil {
		return err
	}
	if coupon.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	if err := s.couponRepo.Delete(ctx, tx, companyID, couponID); err != nil {
		return fmt.Errorf("delete coupon: %w", err)
	}

	if err := s.emitCouponEvent(ctx, tx, coupon, salesEvents.EventCouponDeleted); err != nil {
		s.logger.Warn("failed to emit coupon deleted event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, deletedBy.String(), true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_coupon", "coupon",
			&couponID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

// ---------------------------------------------------------------------
//  Basic getters
// ---------------------------------------------------------------------

func (s *couponService) GetCouponByID(ctx context.Context, companyID, couponID uuid.UUID) (*discount.Coupon, error) {
	return s.couponRepo.GetByID(ctx, nil, companyID, couponID)
}

func (s *couponService) GetCouponByCode(ctx context.Context, companyID uuid.UUID, code string) (*discount.Coupon, error) {
	return s.couponRepo.GetByCode(ctx, nil, companyID, code)
}

func (s *couponService) ListCoupons(ctx context.Context, filter CouponListFilter, p Pagination, srt Sort) ([]*discount.Coupon, int64, error) {
	repoFilter := repository.CouponFilter{
		CompanyID:   filter.CompanyID,
		Code:        filter.Code,
		IsActive:    filter.IsActive,
		CreatedFrom: filter.CreatedFrom,
		CreatedTo:   filter.CreatedTo,
	}
	return s.couponRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *couponService) SearchCoupons(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*discount.Coupon, int64, error) {
	return s.couponRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *couponService) GetActiveCoupons(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetActiveCoupons(ctx, nil, companyID, at)
}

// ---------------------------------------------------------------------
//  Activation / deactivation
// ---------------------------------------------------------------------

func (s *couponService) ActivateCoupon(ctx context.Context, companyID, couponID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, couponID, true, updatedBy)
}

func (s *couponService) DeactivateCoupon(ctx context.Context, companyID, couponID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, couponID, false, updatedBy)
}

func (s *couponService) setActiveStatus(ctx context.Context, companyID, couponID uuid.UUID, active bool, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.couponRepo.SetActiveStatus(ctx, tx, companyID, couponID, active, &updatedBy); err != nil {
		return err
	}
	coupon, _ := s.couponRepo.GetByID(ctx, tx, companyID, couponID)
	if coupon != nil {
		eventType := salesEvents.EventCouponDeactivated
		if active {
			eventType = salesEvents.EventCouponActivated
		}
		_ = s.emitCouponEvent(ctx, tx, coupon, eventType)
	}
	return tx.Commit()
}

func (s *couponService) IsCouponActive(ctx context.Context, companyID, couponID uuid.UUID, at time.Time) (bool, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	if !coupon.IsActive {
		return false, nil
	}
	if at.Before(coupon.StartDate) || at.After(coupon.EndDate) {
		return false, nil
	}
	return true, nil
}

func (s *couponService) ExpireCoupon(ctx context.Context, companyID, couponID uuid.UUID, expiredBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	coupon, err := s.couponRepo.GetByIDForUpdate(ctx, tx, companyID, couponID)
	if err != nil {
		return err
	}
	now := time.Now()
	coupon.EndDate = now
	coupon.UpdatedBy = &expiredBy
	if err := s.couponRepo.Update(ctx, tx, coupon); err != nil {
		return fmt.Errorf("update coupon end date: %w", err)
	}
	_ = s.emitCouponEvent(ctx, tx, coupon, salesEvents.EventCouponUpdated)
	return tx.Commit()
}

// ---------------------------------------------------------------------
//  Validation methods (public wrappers)
// ---------------------------------------------------------------------

func (s *couponService) ValidateCoupon(ctx context.Context, companyID uuid.UUID, couponCode string, customerID *uuid.UUID, orderAmount decimal.Decimal, productIDs []uuid.UUID, at time.Time) error {
	coupon, err := s.couponRepo.GetByCode(ctx, nil, companyID, couponCode)
	if err != nil {
		return err
	}
	if err := s.validateCouponDates(coupon, at); err != nil {
		return err
	}
	if !coupon.IsActive {
		return fmt.Errorf("%w: coupon inactive", salesErrors.ErrCouponInactive)
	}
	if err := s.validateMinimumOrderAmount(coupon, orderAmount); err != nil {
		return err
	}
	if err := s.validateCouponProducts(coupon, productIDs); err != nil {
		return err
	}
	if customerID != nil && *customerID != uuid.Nil {
		if err := s.validateCustomerUsageLimit(ctx, nil, companyID, coupon.CouponID, *customerID); err != nil {
			return err
		}
	}
	if err := s.validateCouponUsageLimit(ctx, nil, companyID, coupon.CouponID); err != nil {
		return err
	}
	return nil
}

func (s *couponService) ValidateCouponDates(ctx context.Context, coupon *discount.Coupon, at time.Time) error {
	return s.validateCouponDates(coupon, at)
}

func (s *couponService) ValidateCouponUsageLimit(ctx context.Context, companyID, couponID uuid.UUID) error {
	return s.validateCouponUsageLimit(ctx, nil, companyID, couponID)
}

func (s *couponService) ValidateCustomerUsageLimit(ctx context.Context, companyID, couponID, customerID uuid.UUID) error {
	return s.validateCustomerUsageLimit(ctx, nil, companyID, couponID, customerID)
}

func (s *couponService) ValidateMinimumOrderAmount(ctx context.Context, coupon *discount.Coupon, orderAmount decimal.Decimal) error {
	return s.validateMinimumOrderAmount(coupon, orderAmount)
}

func (s *couponService) ValidateCouponProducts(ctx context.Context, coupon *discount.Coupon, productIDs []uuid.UUID) error {
	return s.validateCouponProducts(coupon, productIDs)
}

func (s *couponService) CanCustomerUseCoupon(ctx context.Context, companyID, couponID, customerID uuid.UUID, at time.Time) (bool, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	if err := s.validateCouponDates(coupon, at); err != nil {
		return false, nil
	}
	if !coupon.IsActive {
		return false, nil
	}
	if err := s.validateCustomerUsageLimit(ctx, nil, companyID, couponID, customerID); err != nil {
		return false, nil
	}
	if err := s.validateCouponUsageLimit(ctx, nil, companyID, couponID); err != nil {
		return false, nil
	}
	return true, nil
}

// ---------------------------------------------------------------------
//  Discount calculation
// ---------------------------------------------------------------------

func (s *couponService) CalculateDiscount(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal) (decimal.Decimal, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, uuid.Nil, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	return s.calculateDiscountAmount(coupon, subtotal), nil
}

func (s *couponService) CalculateDiscountForProducts(ctx context.Context, couponID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	return s.CalculateDiscount(ctx, couponID, subtotal)
}

// ---------------------------------------------------------------------
//  Apply coupon to order (fully supported)
// ---------------------------------------------------------------------

func (s *couponService) ApplyCouponToOrder(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, decimal.Zero, err
	}

	// only draft orders can accept coupons
	if order.Status != enums.OrderStatusDraft {
		return nil, decimal.Zero, fmt.Errorf("%w: coupon can only be applied to draft orders", salesErrors.ErrInvalidStatus)
	}

	coupon, err := s.couponRepo.GetByCode(ctx, tx, companyID, couponCode)
	if err != nil {
		return nil, decimal.Zero, err
	}

	at := time.Now()
	if err := s.validateCouponDates(coupon, at); err != nil {
		return nil, decimal.Zero, err
	}
	if !coupon.IsActive {
		return nil, decimal.Zero, fmt.Errorf("%w: coupon inactive", salesErrors.ErrCouponInactive)
	}

	items, err := s.orderRepo.GetItems(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	productIDs := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		productIDs = append(productIDs, it.ProductID)
	}
	if err := s.validateCouponProducts(coupon, productIDs); err != nil {
		return nil, decimal.Zero, err
	}
	if err := s.validateMinimumOrderAmount(coupon, order.Subtotal); err != nil {
		return nil, decimal.Zero, err
	}
	if order.CustomerID != uuid.Nil {
		if err := s.validateCustomerUsageLimit(ctx, tx, companyID, coupon.CouponID, order.CustomerID); err != nil {
			return nil, decimal.Zero, err
		}
	}
	if err := s.validateCouponUsageLimit(ctx, tx, companyID, coupon.CouponID); err != nil {
		return nil, decimal.Zero, err
	}

	existingApps, err := s.usageRepo.GetByOrder(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	for _, app := range existingApps {
		if app.DiscountID != nil && *app.DiscountID == coupon.CouponID && app.DiscountType == "coupon" {
			return nil, decimal.Zero, fmt.Errorf("%w: coupon already applied to this order", salesErrors.ErrDuplicate)
		}
	}

	discountAmount := s.calculateDiscountAmount(coupon, order.Subtotal)
	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		OrderID:       &orderID,
		DiscountType:  "coupon",
		DiscountID:    &coupon.CouponID,
		DiscountName:  &coupon.Code,
		Amount:        discountAmount,
		CreatedAt:     at,
	}
	if err := s.usageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, fmt.Errorf("record discount application: %w", err)
	}
	if err := s.orderRepo.RecalculateTotals(ctx, tx, companyID, orderID); err != nil {
		return nil, decimal.Zero, fmt.Errorf("recalculate order totals: %w", err)
	}
	if order.CustomerID != uuid.Nil {
		_ = s.recordUsage(ctx, tx, companyID, coupon.CouponID, orderID, &order.CustomerID, discountAmount, at)
	}
	// Emit analytics event instead of the old CRUD event
	if err := s.emitCouponAppliedEvent(ctx, tx, companyID, coupon.CouponID, coupon.Code,
		discountAmount, order.Subtotal, "order", orderID, &order.CustomerID, at); err != nil {
		s.logger.Warn("failed to emit coupon applied event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	return coupon, discountAmount, nil
}

// ---------------------------------------------------------------------
//  Apply coupon to quote (NOT SUPPORTED by schema)
// ---------------------------------------------------------------------

func (s *couponService) ApplyCouponToQuote(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	return nil, decimal.Zero, fmt.Errorf("%w: applying coupons to quotes is not supported (discount_applications lacks quote_id)", ErrNotSupported)
}

// ---------------------------------------------------------------------
//  Apply coupon to invoice (supported)
// ---------------------------------------------------------------------

func (s *couponService) ApplyCouponToInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, couponCode string, appliedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return nil, decimal.Zero, fmt.Errorf("%w: can only apply coupon to draft invoice", salesErrors.ErrInvalidStatus)
	}
	coupon, err := s.couponRepo.GetByCode(ctx, tx, companyID, couponCode)
	if err != nil {
		return nil, decimal.Zero, err
	}
	at := time.Now()

	if err := s.validateCouponDates(coupon, at); err != nil {
		return nil, decimal.Zero, err
	}
	if !coupon.IsActive {
		return nil, decimal.Zero, fmt.Errorf("%w: coupon inactive", salesErrors.ErrCouponInactive)
	}
	items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	productIDs := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		if it.ProductID != nil {
			productIDs = append(productIDs, *it.ProductID)
		}
	}
	if err := s.validateCouponProducts(coupon, productIDs); err != nil {
		return nil, decimal.Zero, err
	}
	if err := s.validateMinimumOrderAmount(coupon, invoice.Subtotal); err != nil {
		return nil, decimal.Zero, err
	}
	if invoice.CustomerID != uuid.Nil {
		if err := s.validateCustomerUsageLimit(ctx, tx, companyID, coupon.CouponID, invoice.CustomerID); err != nil {
			return nil, decimal.Zero, err
		}
	}
	if err := s.validateCouponUsageLimit(ctx, tx, companyID, coupon.CouponID); err != nil {
		return nil, decimal.Zero, err
	}

	// Prevent duplicate application
	existingApps, err := s.usageRepo.GetByInvoice(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	for _, app := range existingApps {
		if app.DiscountID != nil && *app.DiscountID == coupon.CouponID && app.DiscountType == "coupon" {
			return nil, decimal.Zero, fmt.Errorf("%w: coupon already applied to this invoice", salesErrors.ErrDuplicate)
		}
	}

	discountAmount := s.calculateDiscountAmount(coupon, invoice.Subtotal)
	application := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		InvoiceID:     &invoiceID,
		DiscountType:  "coupon",
		DiscountID:    &coupon.CouponID,
		DiscountName:  &coupon.Code,
		Amount:        discountAmount,
		CreatedAt:     at,
	}
	if err := s.usageRepo.Create(ctx, tx, application); err != nil {
		return nil, decimal.Zero, fmt.Errorf("record discount application: %w", err)
	}
	if err := s.invoiceRepo.RecalculateTotals(ctx, tx, companyID, invoiceID); err != nil {
		return nil, decimal.Zero, err
	}
	// Emit analytics event instead of the old CRUD event
	var customerIDPtr *uuid.UUID
	if invoice.CustomerID != uuid.Nil {
		customerIDPtr = &invoice.CustomerID
	}
	if err := s.emitCouponAppliedEvent(ctx, tx, companyID, coupon.CouponID, coupon.Code,
		discountAmount, invoice.Subtotal, "invoice", invoiceID, customerIDPtr, at); err != nil {
		s.logger.Warn("failed to emit coupon applied event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	return coupon, discountAmount, nil
}

// ---------------------------------------------------------------------
//  Remove coupon from order
// ---------------------------------------------------------------------

func (s *couponService) RemoveCouponFromOrder(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, removedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	coupon, err := s.couponRepo.GetByCode(ctx, tx, companyID, couponCode)
	if err != nil {
		return err
	}
	apps, err := s.usageRepo.GetByOrder(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	var toDelete *discount.DiscountApplication
	for _, app := range apps {
		if app.DiscountID != nil && *app.DiscountID == coupon.CouponID && app.DiscountType == "coupon" {
			toDelete = app
			break
		}
	}
	if toDelete == nil {
		return fmt.Errorf("%w: coupon not applied to order", salesErrors.ErrNotFound)
	}
	if err := s.usageRepo.Delete(ctx, tx, toDelete.ApplicationID); err != nil {
		return fmt.Errorf("remove discount application: %w", err)
	}
	if err := s.orderRepo.RecalculateTotals(ctx, tx, companyID, orderID); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------
//  Remove coupon from quote (not supported)
// ---------------------------------------------------------------------

func (s *couponService) RemoveCouponFromQuote(ctx context.Context, companyID, quoteID uuid.UUID, couponCode string, removedBy uuid.UUID) error {
	return fmt.Errorf("%w: removing coupons from quotes is not supported", ErrNotSupported)
}

// ---------------------------------------------------------------------
//  Remove coupon from invoice
// ---------------------------------------------------------------------

func (s *couponService) RemoveCouponFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, couponCode string, removedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	coupon, err := s.couponRepo.GetByCode(ctx, tx, companyID, couponCode)
	if err != nil {
		return err
	}
	apps, err := s.usageRepo.GetByInvoice(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	var toDelete *discount.DiscountApplication
	for _, app := range apps {
		if app.DiscountID != nil && *app.DiscountID == coupon.CouponID && app.DiscountType == "coupon" {
			toDelete = app
			break
		}
	}
	if toDelete == nil {
		return fmt.Errorf("%w: coupon not applied to invoice", salesErrors.ErrNotFound)
	}
	if err := s.usageRepo.Delete(ctx, tx, toDelete.ApplicationID); err != nil {
		return fmt.Errorf("remove discount application: %w", err)
	}
	if err := s.invoiceRepo.RecalculateTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------
//  Record coupon usage (only order supported)
// ---------------------------------------------------------------------

func (s *couponService) RecordCouponUsage(ctx context.Context, req *RecordCouponUsageRequest) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.recordUsage(ctx, tx, req.CompanyID, req.CouponID, req.OrderID, req.CustomerID, req.DiscountAmount, req.UsedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *couponService) RecordOrderCouponUsage(ctx context.Context, companyID, couponID, orderID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.recordUsage(ctx, tx, companyID, couponID, orderID, customerID, discountAmount, usedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *couponService) RecordQuoteCouponUsage(ctx context.Context, companyID, couponID, quoteID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	return fmt.Errorf("%w: quote usage tracking not supported", ErrNotSupported)
}

func (s *couponService) RecordInvoiceCouponUsage(ctx context.Context, companyID, couponID, invoiceID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	return fmt.Errorf("%w: invoice usage tracking not supported", ErrNotSupported)
}

// ---------------------------------------------------------------------
//  Usage queries
// ---------------------------------------------------------------------

func (s *couponService) GetCouponUsageCount(ctx context.Context, companyID, couponID uuid.UUID) (int64, error) {
	return s.couponRepo.GetTotalUsageCount(ctx, nil, companyID, couponID)
}

func (s *couponService) GetCustomerCouponUsageCount(ctx context.Context, companyID, couponID, customerID uuid.UUID) (int64, error) {
	return s.couponRepo.GetCustomerUsageCount(ctx, nil, companyID, couponID, customerID)
}

func (s *couponService) GetCouponUsageHistory(ctx context.Context, companyID, couponID uuid.UUID, p Pagination, srt Sort) ([]*discount.CouponUsage, int64, error) {
	allUsages, err := s.couponRepo.GetUsagesByCoupon(ctx, nil, companyID, couponID)
	if err != nil {
		return nil, 0, err
	}
	total := int64(len(allUsages))

	// apply sorting (simple: by UsedAt desc as default)
	sort.Slice(allUsages, func(i, j int) bool {
		if srt.Field == "used_at" && srt.Direction == "asc" {
			return allUsages[i].UsedAt.Before(allUsages[j].UsedAt)
		}
		return allUsages[i].UsedAt.After(allUsages[j].UsedAt) // default desc
	})

	// apply pagination
	start := p.Offset
	if start < 0 {
		start = 0
	}
	end := start + p.Limit
	if end > int(total) {
		end = int(total)
	}
	if start > int(total) {
		return []*discount.CouponUsage{}, total, nil
	}
	return allUsages[start:end], total, nil
}

// ---------------------------------------------------------------------
//  Analytics methods
// ---------------------------------------------------------------------

func (s *couponService) GetTopCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetTopCouponsByDiscountAmount(ctx, nil, companyID, limit, from, to)
}

func (s *couponService) GetMostUsedCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetTopCouponsByUsage(ctx, nil, companyID, limit, from, to)
}

func (s *couponService) GetHighestDiscountCoupons(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*discount.Coupon, error) {
	return s.couponRepo.GetTopCouponsByDiscountAmount(ctx, nil, companyID, limit, from, to)
}

func (s *couponService) GetTotalCouponDiscountAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.couponRepo.GetTotalDiscountGiven(ctx, nil, companyID, from, to)
}

func (s *couponService) GetCouponRedemptionRate(ctx context.Context, companyID uuid.UUID, couponID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	used, err := s.couponRepo.GetTotalUsageCount(ctx, nil, companyID, couponID)
	if err != nil {
		return decimal.Zero, err
	}
	if coupon.UsageLimit == nil || *coupon.UsageLimit == 0 {
		return decimal.Zero, nil
	}
	rate := decimal.NewFromInt(used).Div(decimal.NewFromInt(int64(*coupon.UsageLimit))).Mul(decimal.NewFromInt(100))
	return rate, nil
}

// ---------------------------------------------------------------------
//  Existence helpers
// ---------------------------------------------------------------------

func (s *couponService) CouponExists(ctx context.Context, companyID, couponID uuid.UUID) (bool, error) {
	return s.couponRepo.Exists(ctx, nil, companyID, couponID)
}

func (s *couponService) CouponCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.couponRepo.ExistsByCode(ctx, nil, companyID, code)
}

func (s *couponService) IsCouponExpired(ctx context.Context, companyID, couponID uuid.UUID, at time.Time) (bool, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	return at.After(coupon.EndDate), nil
}

func (s *couponService) IsCouponUsageLimitReached(ctx context.Context, companyID, couponID uuid.UUID) (bool, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	if coupon.UsageLimit == nil {
		return false, nil
	}
	used, err := s.couponRepo.GetTotalUsageCount(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	return used >= int64(*coupon.UsageLimit), nil
}

func (s *couponService) IsCustomerUsageLimitReached(ctx context.Context, companyID, couponID, customerID uuid.UUID) (bool, error) {
	coupon, err := s.couponRepo.GetByID(ctx, nil, companyID, couponID)
	if err != nil {
		return false, err
	}
	if coupon.PerUserLimit == nil {
		return false, nil
	}
	used, err := s.couponRepo.GetCustomerUsageCount(ctx, nil, companyID, couponID, customerID)
	if err != nil {
		return false, err
	}
	return used >= int64(*coupon.PerUserLimit), nil
}

// emitCouponAppliedEvent sends the detailed coupon usage event for analytics.
func (s *couponService) emitCouponAppliedEvent(
	ctx context.Context,
	tx *sql.Tx,
	companyID, couponID uuid.UUID,
	code string,
	discountAmount, orderSubtotal decimal.Decimal,
	entityType string,
	entityID uuid.UUID,
	customerID *uuid.UUID,
	usedAt time.Time,
) error {
	payload := salesEvents.CouponAppliedPayload{
		CouponID:       couponID.String(),
		CompanyID:      companyID.String(),
		Code:           code,
		DiscountAmount: discountAmount.String(),
		OrderSubtotal:  orderSubtotal.String(),
		EntityType:     entityType,
		EntityID:       entityID.String(),
		UsedAt:         usedAt.Format(time.RFC3339),
	}
	if customerID != nil {
		cid := customerID.String()
		payload.CustomerID = &cid
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "coupon",
		AggregateID:   couponID.String(),
		EventType:     salesEvents.EventCouponApplied,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
