// file: internal/sales/service/order_service.go
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

// ============================================================================
// OrderService interface (as provided in the prompt)
// ============================================================================

type OrderService interface {
	// ORDER CREATION / CRUD
	CreateDraftOrder(ctx context.Context, req *CreateOrderRequest) (*models.Order, error)
	UpdateOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, req *UpdateOrderRequest) (*models.Order, error)
	DeleteOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, deletedBy uuid.UUID) error
	GetOrderByID(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) (*models.Order, error)
	GetOrderByNumber(ctx context.Context, companyID uuid.UUID, orderNumber string) (*models.Order, error)
	ListOrders(ctx context.Context, filter OrderListFilter, p Pagination, s Sort) ([]*models.Order, int64, error)
	SearchOrders(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*models.Order, int64, error)
	GetOrdersByCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Order, int64, error)

	// ORDER ITEM MANAGEMENT
	AddItems(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, items []*CreateOrderItemRequest, updatedBy uuid.UUID) error
	ReplaceItems(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, items []*CreateOrderItemRequest, updatedBy uuid.UUID) error
	RemoveItem(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, orderItemID uuid.UUID, updatedBy uuid.UUID) error
	GetOrderItems(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) ([]*models.OrderItem, error)

	// PRICING / DISCOUNTS
	ApplyCoupon(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, couponCode string, updatedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error)
	RemoveCoupon(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, couponCode string, updatedBy uuid.UUID) error
	ApplyBestDiscounts(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, updatedBy uuid.UUID) error
	PreviewPricing(ctx context.Context, req *OrderPricingPreviewRequest) (*OrderPricingPreviewResult, error)
	RecalculateTotals(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, updatedBy uuid.UUID) error
	GetOrderTotals(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error)

	// STATUS TRANSITIONS
	UpdateStatus(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, status enums.OrderStatus, updatedBy uuid.UUID) error
	ConfirmOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, updatedBy uuid.UUID) error
	MarkProcessing(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, updatedBy uuid.UUID) error
	MarkShipped(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, shippedAt time.Time, updatedBy uuid.UUID) error
	MarkDelivered(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, deliveredAt time.Time, updatedBy uuid.UUID) error
	CancelOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, reason string, cancelledBy uuid.UUID) error

	// SALES REP MANAGEMENT
	AssignSalesRep(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, salesRepID uuid.UUID, updatedBy uuid.UUID) error
	RemoveSalesRep(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, updatedBy uuid.UUID) error

	// ORDER VALIDATION
	ValidateOrder(ctx context.Context, order *models.Order, items []*models.OrderItem) error
	ValidateOrderStatusTransition(ctx context.Context, currentStatus enums.OrderStatus, nextStatus enums.OrderStatus) error
	ValidateOrderItems(ctx context.Context, companyID uuid.UUID, items []*CreateOrderItemRequest) error
	ValidatePricing(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) error

	// QUERY / ANALYTICS
	GetPendingOrders(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error)
	GetOrdersReadyForInvoicing(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error)
	GetOrderRevenue(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetAverageOrderValue(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetTopOrdersByValue(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*models.Order, error)

	// EXISTENCE / HELPERS
	OrderExists(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) (bool, error)
	OrderNumberExists(ctx context.Context, companyID uuid.UUID, orderNumber string) (bool, error)
	HasInvoices(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) (bool, error)
	HasReturns(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID) (bool, error)
}

// ============================================================================
// orderService implementation
// ============================================================================

type orderService struct {
	orderRepo         repository.OrderRepository
	productRepo       repository.ProductRepository
	customerSvc       CustomerService
	pricingRepo       repository.PricingRepository
	couponRepo        repository.CouponRepository
	promotionRepo     repository.PromotionRepository
	discountUsageRepo repository.DiscountUsageRepository
	taxSnapshotRepo   repository.TaxSnapshotRepository
	discountEngine    DiscountEngineService
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

// NewOrderService creates a new order service instance.
func NewOrderService(
	orderRepo repository.OrderRepository,
	productRepo repository.ProductRepository,
	customerSvc CustomerService,
	pricingRepo repository.PricingRepository,
	couponRepo repository.CouponRepository,
	promotionRepo repository.PromotionRepository,
	discountUsageRepo repository.DiscountUsageRepository,
	taxSnapshotRepo repository.TaxSnapshotRepository,
	discountEngine DiscountEngineService,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) OrderService {
	return &orderService{
		orderRepo:         orderRepo,
		productRepo:       productRepo,
		customerSvc:       customerSvc,
		pricingRepo:       pricingRepo,
		couponRepo:        couponRepo,
		promotionRepo:     promotionRepo,
		discountUsageRepo: discountUsageRepo,
		taxSnapshotRepo:   taxSnapshotRepo,
		discountEngine:    discountEngine,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("order_service"),
	}
}

// ----------------------------------------------------------------------------
// ORDER CREATION / CRUD
// ----------------------------------------------------------------------------

func (s *orderService) UpdateOrder(ctx context.Context, companyID, orderID uuid.UUID, req *UpdateOrderRequest) (*models.Order, error) {
	logger := s.logger.With(zap.String("method", "UpdateOrder"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	if order.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return nil, fmt.Errorf("%w: only draft orders can be updated", salesErrors.ErrInvalidStatus)
	}

	changes := make(map[string]interface{})

	if req.ExternalRef != nil {
		if *req.ExternalRef != "" {
			exists, err := s.orderRepo.ExistsByExternalRef(ctx, tx, companyID, *req.ExternalRef)
			if err != nil {
				return nil, err
			}
			if exists && (order.ExternalRef == nil || *order.ExternalRef != *req.ExternalRef) {
				return nil, fmt.Errorf("%w: external reference %s already used", salesErrors.ErrDuplicate, *req.ExternalRef)
			}
		}
		order.ExternalRef = req.ExternalRef
		changes["external_ref"] = req.ExternalRef
	}
	if req.OrderDate != nil {
		order.OrderDate = *req.OrderDate
		changes["order_date"] = req.OrderDate
	}
	if req.Currency != nil {
		order.Currency = *req.Currency
		changes["currency"] = req.Currency
	}
	if req.Notes != nil {
		order.Notes = req.Notes
		changes["notes"] = req.Notes
	}
	if req.ShippingAddress != nil {
		order.ShippingAddress = *req.ShippingAddress
		changes["shipping_address"] = req.ShippingAddress
	}
	if req.BillingAddress != nil {
		order.BillingAddress = *req.BillingAddress
		changes["billing_address"] = req.BillingAddress
	}
	if req.SalesRepID != nil {
		order.SalesRepID = req.SalesRepID
		changes["sales_rep_id"] = req.SalesRepID
	}

	order.UpdatedBy = req.UpdatedBy

	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return nil, fmt.Errorf("update order: %w", err)
	}

	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderUpdated, nil); err != nil {
		logger.Warn("failed to emit order updated event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_order", "order",
			&orderID, "user", req.UpdatedBy, nil, nil, changes)
	}

	return order, nil
}

func (s *orderService) DeleteOrder(ctx context.Context, companyID, orderID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteOrder"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	// Only draft orders without invoices/returns can be hard deleted
	hasInvoices, err := s.orderRepo.HasInvoices(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	hasReturns, err := s.orderRepo.HasReturns(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}

	if order.Status == enums.OrderStatusDraft && !hasInvoices && !hasReturns {
		if err := s.orderRepo.Delete(ctx, tx, companyID, orderID); err != nil {
			return fmt.Errorf("delete order: %w", err)
		}
	} else {
		return fmt.Errorf("%w: cannot delete order with status %s or existing invoices/returns", salesErrors.ErrInvalidStatus, order.Status)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_order", "order",
			&orderID, "user", &deletedBy, nil, nil, nil)
	}

	logger.Info("order deleted", zap.String("order_number", order.OrderNumber))
	return nil
}

func (s *orderService) GetOrderByID(ctx context.Context, companyID, orderID uuid.UUID) (*models.Order, error) {
	return s.orderRepo.GetByID(ctx, nil, companyID, orderID)
}

func (s *orderService) GetOrderByNumber(ctx context.Context, companyID uuid.UUID, orderNumber string) (*models.Order, error) {
	return s.orderRepo.GetByNumber(ctx, nil, companyID, orderNumber)
}

func (s *orderService) ListOrders(ctx context.Context, filter OrderListFilter, p Pagination, srt Sort) ([]*models.Order, int64, error) {
	repoFilter := repository.OrderFilter{
		CompanyID:     filter.CompanyID,
		CustomerID:    filter.CustomerID,
		SalesRepID:    filter.SalesRepID,
		OrderDateFrom: filter.FromDate,
		OrderDateTo:   filter.ToDate,
		MinGrandTotal: filter.MinTotal,
		MaxGrandTotal: filter.MaxTotal,
	}
	if filter.Status != nil {
		repoFilter.Statuses = []enums.OrderStatus{*filter.Status}
	}
	return s.orderRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *orderService) SearchOrders(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Order, int64, error) {
	return s.orderRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *orderService) GetOrdersByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Order, int64, error) {
	return s.orderRepo.GetByCustomer(ctx, nil, companyID, customerID,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

// ----------------------------------------------------------------------------
// ORDER ITEM MANAGEMENT
// ----------------------------------------------------------------------------

func (s *orderService) AddItems(ctx context.Context, companyID, orderID uuid.UUID, items []*CreateOrderItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: cannot add items to order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	if err := s.addOrderItems(ctx, tx, order, items); err != nil {
		return err
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) ReplaceItems(ctx context.Context, companyID, orderID uuid.UUID, items []*CreateOrderItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: cannot replace items for order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	// Delete existing items
	if err := s.orderRepo.ReplaceItems(ctx, tx, companyID, orderID, nil); err != nil {
		return fmt.Errorf("clear items: %w", err)
	}

	if len(items) > 0 {
		if err := s.addOrderItems(ctx, tx, order, items); err != nil {
			return err
		}
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) RemoveItem(ctx context.Context, companyID, orderID, orderItemID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: cannot remove item from order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	if err := s.orderRepo.DeleteItem(ctx, tx, companyID, orderID, orderItemID); err != nil {
		return err
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) GetOrderItems(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.OrderItem, error) {
	return s.orderRepo.GetItems(ctx, nil, companyID, orderID)
}

// ----------------------------------------------------------------------------
// PRICING / DISCOUNTS
// ----------------------------------------------------------------------------

func (s *orderService) ApplyCoupon(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, updatedBy uuid.UUID) (*discount.Coupon, decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if order.CompanyID != companyID {
		return nil, decimal.Zero, salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return nil, decimal.Zero, fmt.Errorf("%w: cannot apply coupon to order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	// FIXED: removed tx argument
	coupon, discountAmount, err := s.discountEngine.ApplyCoupon(ctx, companyID, "order", orderID, couponCode, updatedBy)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return nil, decimal.Zero, err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return nil, decimal.Zero, err
	}

	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	return coupon, discountAmount, nil
}

func (s *orderService) RemoveCoupon(ctx context.Context, companyID, orderID uuid.UUID, couponCode string, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: cannot remove coupon from order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	// FIXED: removed tx argument
	if err := s.discountEngine.RemoveCoupon(ctx, companyID, "order", orderID, couponCode, updatedBy); err != nil {
		return err
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) ApplyBestDiscounts(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: cannot apply discounts to order with status %s", salesErrors.ErrInvalidStatus, order.Status)
	}

	// FIXED: removed tx argument
	_, err = s.discountEngine.ApplyBestDiscounts(ctx, companyID, "order", orderID, updatedBy)
	if err != nil {
		return err
	}

	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) RecalculateTotals(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.recalculateOrderTotals(ctx, tx, orderID); err != nil {
		return err
	}
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) GetOrderTotals(ctx context.Context, companyID, orderID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error) {
	return s.orderRepo.GetTotals(ctx, nil, companyID, orderID)
}

// ----------------------------------------------------------------------------
// STATUS TRANSITIONS
// ----------------------------------------------------------------------------

func (s *orderService) UpdateStatus(ctx context.Context, companyID, orderID uuid.UUID, status enums.OrderStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.validateStatusTransition(order.Status, status); err != nil {
		return err
	}

	if err := s.orderRepo.UpdateStatus(ctx, tx, companyID, orderID, status, &updatedBy); err != nil {
		return err
	}
	order.Status = status

	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderUpdated, nil); err != nil {
		s.logger.Warn("failed to emit order updated event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) ConfirmOrder(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusDraft {
		return fmt.Errorf("%w: only draft orders can be confirmed", salesErrors.ErrInvalidTransition)
	}

	active, err := s.customerSvc.IsCustomerActive(ctx, companyID, order.CustomerID)
	if err != nil {
		return err
	}
	if !active {
		return salesErrors.ErrCustomerInactive
	}
	items, err := s.orderRepo.GetItems(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	for _, it := range items {
		prod, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			return err
		}
		if !prod.IsActive {
			return fmt.Errorf("%w: product %s is inactive", salesErrors.ErrProductInactive, prod.SKU)
		}
	}

	if err := s.validatePricing(ctx, tx, companyID, orderID); err != nil {
		return err
	}

	canPurchase, err := s.customerSvc.CanCustomerPurchaseAmount(ctx, companyID, order.CustomerID, order.GrandTotal)
	if err != nil {
		return err
	}
	if !canPurchase {
		return fmt.Errorf("%w: customer credit limit exceeded or insufficient credit", salesErrors.ErrInvalidAmount)
	}

	now := time.Now()
	if err := s.orderRepo.Confirm(ctx, tx, companyID, orderID, now, &updatedBy); err != nil {
		return err
	}
	order.Status = enums.OrderStatusConfirmed
	order.ConfirmedAt = &now

	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderConfirmed, nil); err != nil {
		s.logger.Warn("failed to emit order confirmed event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *orderService) MarkProcessing(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID) error {
	return s.updateOrderStatus(ctx, companyID, orderID, enums.OrderStatusProcessing, &updatedBy, salesEvents.EventOrderProcessing)
}

func (s *orderService) MarkShipped(ctx context.Context, companyID, orderID uuid.UUID, shippedAt time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusProcessing {
		return fmt.Errorf("%w: order must be processing to mark shipped", salesErrors.ErrInvalidTransition)
	}
	if err := s.orderRepo.MarkShipped(ctx, tx, companyID, orderID, shippedAt, &updatedBy); err != nil {
		return err
	}
	order.Status = enums.OrderStatusShipped
	order.ShippedAt = &shippedAt
	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderShipped, nil); err != nil {
		s.logger.Warn("failed to emit order shipped event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *orderService) MarkDelivered(ctx context.Context, companyID, orderID uuid.UUID, deliveredAt time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status != enums.OrderStatusShipped {
		return fmt.Errorf("%w: order must be shipped to mark delivered", salesErrors.ErrInvalidTransition)
	}
	if err := s.orderRepo.MarkDelivered(ctx, tx, companyID, orderID, deliveredAt, &updatedBy); err != nil {
		return err
	}
	order.Status = enums.OrderStatusDelivered
	order.DeliveredAt = &deliveredAt
	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderDelivered, nil); err != nil {
		s.logger.Warn("failed to emit order delivered event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *orderService) CancelOrder(ctx context.Context, companyID, orderID uuid.UUID, reason string, cancelledBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if order.Status == enums.OrderStatusShipped || order.Status == enums.OrderStatusDelivered {
		return fmt.Errorf("%w: cannot cancel shipped or delivered order", salesErrors.ErrInvalidTransition)
	}
	if order.Status == enums.OrderStatusCancelled || order.Status == enums.OrderStatusRefunded {
		return fmt.Errorf("%w: order already cancelled or refunded", salesErrors.ErrInvalidTransition)
	}

	// Capture status before cancellation for the event
	oldStatus := order.Status

	now := time.Now()
	if err := s.orderRepo.Cancel(ctx, tx, companyID, orderID, reason, now, &cancelledBy); err != nil {
		return err
	}
	order.Status = enums.OrderStatusCancelled
	order.CancelledAt = &now
	order.CancellationReason = &reason

	// Build extra event fields for cancellation
	extra := map[string]interface{}{
		"status_before_cancel": oldStatus,
		"cancelled_by":         cancelledBy.String(),
	}
	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderCancelled, extra); err != nil {
		s.logger.Warn("failed to emit order cancelled event", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// SALES REP MANAGEMENT
// ----------------------------------------------------------------------------

func (s *orderService) AssignSalesRep(ctx context.Context, companyID, orderID, salesRepID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	order.SalesRepID = &salesRepID
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *orderService) RemoveSalesRep(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	order.SalesRepID = nil
	order.UpdatedBy = &updatedBy
	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// ORDER VALIDATION
// ----------------------------------------------------------------------------

func (s *orderService) ValidateOrder(ctx context.Context, order *models.Order, items []*models.OrderItem) error {
	if order.OrderNumber == "" {
		return fmt.Errorf("%w: order number required", salesErrors.ErrInvalidInput)
	}
	if order.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: order must contain at least one item", salesErrors.ErrInvalidInput)
	}
	for _, it := range items {
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}

func (s *orderService) ValidateOrderStatusTransition(ctx context.Context, currentStatus, nextStatus enums.OrderStatus) error {
	return s.validateStatusTransition(currentStatus, nextStatus)
}

func (s *orderService) ValidateOrderItems(ctx context.Context, companyID uuid.UUID, items []*CreateOrderItemRequest) error {
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

func (s *orderService) ValidatePricing(ctx context.Context, companyID, orderID uuid.UUID) error {
	subtotal, discountTotal, taxTotal, grandTotal, err := s.orderRepo.GetTotals(ctx, nil, companyID, orderID)
	if err != nil {
		return err
	}
	items, err := s.orderRepo.GetItems(ctx, nil, companyID, orderID)
	if err != nil {
		return err
	}
	var calcSubtotal, calcDiscount, calcTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		calcSubtotal = calcSubtotal.Add(lineSub)
		if it.DiscountAmount != nil {
			calcDiscount = calcDiscount.Add(*it.DiscountAmount)
		}
		if it.TaxAmount != nil {
			calcTax = calcTax.Add(*it.TaxAmount)
		}
	}
	calcGrand := calcSubtotal.Sub(calcDiscount).Add(calcTax)
	if !subtotal.Equal(calcSubtotal) || !discountTotal.Equal(calcDiscount) || !taxTotal.Equal(calcTax) || !grandTotal.Equal(calcGrand) {
		return fmt.Errorf("pricing validation failed: stored totals do not match line items")
	}
	return nil
}

// ----------------------------------------------------------------------------
// QUERY / ANALYTICS
// ----------------------------------------------------------------------------

func (s *orderService) GetPendingOrders(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error) {
	return s.orderRepo.GetPendingOrders(ctx, nil, companyID)
}

func (s *orderService) GetOrdersReadyForInvoicing(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error) {
	return s.orderRepo.GetOrdersReadyForInvoicing(ctx, nil, companyID)
}

func (s *orderService) GetOrderRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.orderRepo.GetOrderRevenue(ctx, nil, companyID, from, to)
}

func (s *orderService) GetAverageOrderValue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.orderRepo.GetAverageOrderValue(ctx, nil, companyID, from, to)
}

func (s *orderService) GetTopOrdersByValue(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Order, error) {
	return s.orderRepo.GetTopOrdersByValue(ctx, nil, companyID, limit, from, to)
}

// ----------------------------------------------------------------------------
// EXISTENCE / HELPERS
// ----------------------------------------------------------------------------

func (s *orderService) OrderExists(ctx context.Context, companyID, orderID uuid.UUID) (bool, error) {
	return s.orderRepo.Exists(ctx, nil, companyID, orderID)
}

func (s *orderService) OrderNumberExists(ctx context.Context, companyID uuid.UUID, orderNumber string) (bool, error) {
	return s.orderRepo.ExistsByNumber(ctx, nil, companyID, orderNumber)
}

func (s *orderService) HasInvoices(ctx context.Context, companyID, orderID uuid.UUID) (bool, error) {
	return s.orderRepo.HasInvoices(ctx, nil, companyID, orderID)
}

func (s *orderService) HasReturns(ctx context.Context, companyID, orderID uuid.UUID) (bool, error) {
	return s.orderRepo.HasReturns(ctx, nil, companyID, orderID)
}

// ----------------------------------------------------------------------------
// INTERNAL HELPERS
// ----------------------------------------------------------------------------

func (s *orderService) validateCreateOrderRequest(req *CreateOrderRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return fmt.Errorf("%w: at least one item required", salesErrors.ErrInvalidInput)
	}
	return s.ValidateOrderItems(context.Background(), req.CompanyID, req.Items)
}

func (s *orderService) addOrderItems(ctx context.Context, tx repository.DBTX, order *models.Order, items []*CreateOrderItemRequest) error {
	orderItems := make([]*models.OrderItem, 0, len(items))
	for _, it := range items {
		product, err := s.productRepo.GetByID(ctx, tx, order.CompanyID, it.ProductID)
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
		item := &models.OrderItem{
			OrderItemID:         uuid.New(),
			OrderID:             order.OrderID,
			ProductID:           product.ProductID,
			ProductNameSnapshot: product.Name,
			Quantity:            it.Quantity,
			UnitPrice:           unitPrice,
			DiscountAmount:      it.DiscountAmount,
			TaxAmount:           nil,
			Metadata:            it.Metadata,
		}
		orderItems = append(orderItems, item)
	}
	return s.orderRepo.AddItems(ctx, tx, order.CompanyID, order.OrderID, orderItems)
}

func (s *orderService) recalculateOrderTotals(ctx context.Context, tx repository.DBTX, orderID uuid.UUID) error {
	order, err := s.orderRepo.GetByID(ctx, tx, uuid.Nil, orderID)
	if err != nil {
		return err
	}
	items, err := s.orderRepo.GetItems(ctx, tx, order.CompanyID, orderID)
	if err != nil {
		return err
	}

	var subtotal, discountTotal, taxTotal decimal.Decimal
	for _, it := range items {
		lineSubtotal := it.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineSubtotal)
		if it.DiscountAmount != nil {
			discountTotal = discountTotal.Add(*it.DiscountAmount)
		}
		tax, err := s.pricingRepo.CalculateLineTax(ctx, tx, order.CompanyID, it.ProductID, lineSubtotal.Sub(*it.DiscountAmount))
		if err != nil {
			return fmt.Errorf("calculate line tax: %w", err)
		}
		it.TaxAmount = &tax
		taxTotal = taxTotal.Add(tax)

		updateQuery := `UPDATE sales.order_items SET tax_amount = $1 WHERE order_item_id = $2`
		if _, err := tx.ExecContext(ctx, updateQuery, tax, it.OrderItemID); err != nil {
			return fmt.Errorf("update item tax: %w", err)
		}
	}

	order.Subtotal = subtotal
	order.DiscountTotal = discountTotal
	order.TaxTotal = taxTotal
	order.GrandTotal = subtotal.Sub(discountTotal).Add(taxTotal)

	if err := s.orderRepo.Update(ctx, tx, order); err != nil {
		return fmt.Errorf("update order totals: %w", err)
	}

	// Store tax snapshots
	if err := s.taxSnapshotRepo.DeleteByEntity(ctx, tx, order.CompanyID, "order", order.OrderID); err != nil {
		s.logger.Warn("failed to delete old tax snapshots", zap.Error(err))
	}
	for _, it := range items {
		taxAmount := decimal.Zero
		if it.TaxAmount != nil {
			taxAmount = *it.TaxAmount
		}
		snapshot := &models.TaxSnapshot{
			TaxSnapshotID: uuid.New(),
			CompanyID:     order.CompanyID,
			EntityType:    "order",
			EntityID:      order.OrderID,
			LineID:        &it.OrderItemID,
			TaxableAmount: it.UnitPrice.Mul(it.Quantity).Sub(*it.DiscountAmount),
			TaxAmount:     taxAmount,
		}
		if err := s.taxSnapshotRepo.Create(ctx, tx, snapshot); err != nil {
			s.logger.Warn("failed to store tax snapshot", zap.Error(err))
		}
	}
	return nil
}

func (s *orderService) updateOrderStatus(ctx context.Context, companyID, orderID uuid.UUID, newStatus enums.OrderStatus, updatedBy *uuid.UUID, eventType string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return err
	}
	if order.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.validateStatusTransition(order.Status, newStatus); err != nil {
		return err
	}
	if err := s.orderRepo.UpdateStatus(ctx, tx, companyID, orderID, newStatus, updatedBy); err != nil {
		return err
	}
	order.Status = newStatus
	if err := s.emitOrderEvent(ctx, tx, order, eventType, nil); err != nil {
		s.logger.Warn("failed to emit event", zap.String("event", eventType), zap.Error(err))
	}
	return tx.Commit()
}

func (s *orderService) validateStatusTransition(current, next enums.OrderStatus) error {
	transitions := map[enums.OrderStatus][]enums.OrderStatus{
		enums.OrderStatusDraft:      {enums.OrderStatusConfirmed, enums.OrderStatusCancelled},
		enums.OrderStatusConfirmed:  {enums.OrderStatusProcessing, enums.OrderStatusCancelled},
		enums.OrderStatusProcessing: {enums.OrderStatusShipped, enums.OrderStatusCancelled},
		enums.OrderStatusShipped:    {enums.OrderStatusDelivered, enums.OrderStatusRefunded},
		enums.OrderStatusDelivered:  {enums.OrderStatusRefunded},
		enums.OrderStatusCancelled:  {},
		enums.OrderStatusRefunded:   {},
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

func (s *orderService) generateOrderNumber(tx repository.DBTX, companyID uuid.UUID) (string, error) {
	prefix := companyID.String()[:8]
	timestamp := time.Now().UnixMilli()
	orderNumber := fmt.Sprintf("ORD-%s-%d", prefix, timestamp)
	exists, err := s.orderRepo.ExistsByNumber(context.Background(), tx, companyID, orderNumber)
	if err != nil {
		return "", err
	}
	if exists {
		return fmt.Sprintf("ORD-%s-%d-1", prefix, timestamp), nil
	}
	return orderNumber, nil
}

// emitOrderEvent now builds the complete payload with all required fields for analytics.
// Extra fields can be passed via the extra map (e.g., for cancellations).
func (s *orderService) emitOrderEvent(ctx context.Context, tx repository.DBTX, order *models.Order, eventType string, extra map[string]interface{}) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}

	// Fetch order items
	items, err := s.orderRepo.GetItems(ctx, tx, order.CompanyID, order.OrderID)
	if err != nil {
		return fmt.Errorf("get order items for event: %w", err)
	}

	// Build order item payloads with OrderItemID
	orderItems := make([]salesEvents.OrderItemPayload, 0, len(items))
	for _, it := range items {
		discountStr := ""
		if it.DiscountAmount != nil {
			discountStr = it.DiscountAmount.String()
		}
		taxStr := ""
		if it.TaxAmount != nil {
			taxStr = it.TaxAmount.String()
		}
		orderItems = append(orderItems, salesEvents.OrderItemPayload{
			OrderItemID:   it.OrderItemID.String(),
			ProductID:     it.ProductID.String(),
			Quantity:      it.Quantity.String(),
			UnitPrice:     it.UnitPrice.String(),
			DiscountTotal: discountStr,
			TaxTotal:      taxStr,
		})
	}

	// Extract shipping region from shipping_address JSONB (if present)
	shippingRegion := ""
	if order.ShippingAddress != nil {
		if region, ok := order.ShippingAddress["region"].(string); ok {
			shippingRegion = region
		} else if country, ok := order.ShippingAddress["country"].(string); ok {
			shippingRegion = country
		}
	}

	// Convert SalesRepID pointer to string
	salesRepIDStr := ""
	if order.SalesRepID != nil {
		salesRepIDStr = order.SalesRepID.String()
	}

	// Build base payload
	payload := salesEvents.OrderPayload{
		OrderID:            order.OrderID.String(),
		CompanyID:          order.CompanyID.String(),
		CustomerID:         order.CustomerID.String(),
		OrderNumber:        order.OrderNumber,
		Status:             order.Status.String(),
		GrandTotal:         order.GrandTotal.String(),
		OrderDate:          order.OrderDate.Format(time.RFC3339),
		Items:              orderItems,
		SalesRepID:         salesRepIDStr,
		Carrier:            "", // TODO: populate from shipping service
		TrackingNumber:     "", // TODO: populate from shipping service
		ShippingRegion:     shippingRegion,
		CancellationReason: "",
		CancelledBy:        "",
		StatusBeforeCancel: "",
	}

	// Override with extra fields for cancellation events
	if extra != nil {
		if reason, ok := extra["cancellation_reason"].(string); ok {
			payload.CancellationReason = reason
		}
		if cancelledBy, ok := extra["cancelled_by"].(string); ok {
			payload.CancelledBy = cancelledBy
		}
		if statusBefore, ok := extra["status_before_cancel"].(enums.OrderStatus); ok {
			payload.StatusBeforeCancel = statusBefore.String()
		}
	} else if eventType == salesEvents.EventOrderCancelled && order.CancellationReason != nil {
		payload.CancellationReason = *order.CancellationReason
		// cancelled_by is not stored in the order model, so it must come from extra
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "order",
		AggregateID:   order.OrderID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *orderService) validatePricing(ctx context.Context, tx repository.DBTX, companyID, orderID uuid.UUID) error {
	return s.ValidatePricing(ctx, companyID, orderID)
}

// ----------------------------------------------------------------------------
// CreateDraftOrder
// ----------------------------------------------------------------------------

func (s *orderService) CreateDraftOrder(ctx context.Context, req *CreateOrderRequest) (*models.Order, error) {
	logger := s.logger.With(zap.String("method", "CreateDraftOrder"))

	if err := s.validateCreateOrderRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Generate order number if not provided
	orderNumber := req.OrderNumber
	if orderNumber == "" {
		orderNumber, err = s.generateOrderNumber(tx, req.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("generate order number: %w", err)
		}
	}

	// Check uniqueness
	exists, err := s.orderRepo.ExistsByNumber(ctx, tx, req.CompanyID, orderNumber)
	if err != nil {
		return nil, fmt.Errorf("check order number: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: order number %s already exists", salesErrors.ErrDuplicate, orderNumber)
	}

	if req.ExternalRef != nil && *req.ExternalRef != "" {
		exists, err = s.orderRepo.ExistsByExternalRef(ctx, tx, req.CompanyID, *req.ExternalRef)
		if err != nil {
			return nil, fmt.Errorf("check external ref: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: external reference %s already used", salesErrors.ErrDuplicate, *req.ExternalRef)
		}
	}

	orderDate := req.OrderDate
	if orderDate.IsZero() {
		orderDate = time.Now().Truncate(24 * time.Hour)
	}

	order := &models.Order{
		OrderID:         uuid.New(),
		CompanyID:       req.CompanyID,
		CustomerID:      req.CustomerID,
		OrderNumber:     orderNumber,
		ExternalRef:     req.ExternalRef,
		OrderDate:       orderDate,
		Status:          enums.OrderStatusDraft,
		Currency:        req.Currency,
		Notes:           req.Notes,
		ShippingAddress: req.ShippingAddress,
		BillingAddress:  req.BillingAddress,
		SalesRepID:      req.SalesRepID,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
		Subtotal:        decimal.Zero,
		DiscountTotal:   decimal.Zero,
		TaxTotal:        decimal.Zero,
	}

	if err := s.orderRepo.Create(ctx, tx, order, nil); err != nil {
		return nil, fmt.Errorf("create order: %w", err)
	}

	// Add items
	if len(req.Items) > 0 {
		if err := s.addOrderItems(ctx, tx, order, req.Items); err != nil {
			return nil, err
		}
	}

	// Recalculate totals (will also apply discounts if coupons given)
	if err := s.recalculateOrderTotals(ctx, tx, order.OrderID); err != nil {
		return nil, fmt.Errorf("recalculate totals: %w", err)
	}

	// Apply coupons if provided
	appliedBy := uuid.Nil
	if req.CreatedBy != nil {
		appliedBy = *req.CreatedBy
	}
	for _, code := range req.CouponCodes {
		// FIXED: removed tx argument
		if _, _, err := s.discountEngine.ApplyCoupon(ctx, req.CompanyID, "order", order.OrderID, code, appliedBy); err != nil {
			logger.Warn("failed to apply coupon", zap.String("code", code), zap.Error(err))
		}
	}

	// Recalc again after coupons
	if err := s.recalculateOrderTotals(ctx, tx, order.OrderID); err != nil {
		return nil, fmt.Errorf("recalculate totals after coupons: %w", err)
	}

	// Emit event
	if err := s.emitOrderEvent(ctx, tx, order, salesEvents.EventOrderCreated, nil); err != nil {
		logger.Warn("failed to emit order created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Fetch final order with items
	finalOrder, err := s.orderRepo.GetByID(ctx, nil, req.CompanyID, order.OrderID)
	if err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_order", "order",
			&order.OrderID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"order_number": order.OrderNumber,
			})
	}

	return finalOrder, nil
}

// ----------------------------------------------------------------------------
// PreviewPricing (correct implementation)
// ----------------------------------------------------------------------------

func (s *orderService) PreviewPricing(ctx context.Context, req *OrderPricingPreviewRequest) (*OrderPricingPreviewResult, error) {
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}
	// Build product IDs and lines
	var productIDs []uuid.UUID
	var lines []PricingLineInput
	for _, it := range req.Items {
		productIDs = append(productIDs, it.ProductID)
		unitPrice := decimal.Zero
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		} else {
			// Fetch product price
			price, err := s.pricingRepo.GetProductBasePrice(ctx, nil, req.CompanyID, it.ProductID)
			if err != nil {
				return nil, err
			}
			unitPrice = price
		}
		lines = append(lines, PricingLineInput{
			ProductID: it.ProductID,
			Quantity:  it.Quantity,
			UnitPrice: &unitPrice,
		})
	}

	// Calculate total
	var subtotal decimal.Decimal
	for _, line := range lines {
		price := decimal.Zero
		if line.UnitPrice != nil {
			price = *line.UnitPrice
		}
		subtotal = subtotal.Add(price.Mul(line.Quantity))
	}

	// Get applicable coupons and promotions
	_, err := s.discountEngine.GetApplicableCoupons(ctx, req.CompanyID, req.CustomerID, productIDs, subtotal, at)
	if err != nil {
		return nil, err
	}
	_, err = s.discountEngine.GetApplicablePromotions(ctx, req.CompanyID, req.CustomerID, productIDs, subtotal, at)
	if err != nil {
		return nil, err
	}

	// Calculate best combination
	best, err := s.discountEngine.GetBestDiscountCombination(ctx, &BestDiscountCombinationRequest{
		CompanyID:         req.CompanyID,
		CustomerID:        req.CustomerID,
		ProductIDs:        productIDs,
		OrderAmount:       subtotal,
		At:                at,
		IncludeCoupons:    true,
		IncludePromotions: true,
		IncludeAutomatic:  false,
		MaxCombinations:   3,
	})
	if err != nil {
		return nil, err
	}

	// Estimate tax (simplified)
	taxTotal, err := s.pricingRepo.CalculateTaxAmount(ctx, nil, req.CompanyID, "order", uuid.Nil, subtotal.Sub(best.DiscountTotal))
	if err != nil {
		taxTotal = decimal.Zero
	}
	grandTotal := subtotal.Sub(best.DiscountTotal).Add(taxTotal)

	return &OrderPricingPreviewResult{
		Subtotal:          subtotal,
		DiscountTotal:     best.DiscountTotal,
		TaxTotal:          taxTotal,
		GrandTotal:        grandTotal,
		AppliedCoupons:    best.AppliedCoupons,
		AppliedPromotions: best.AppliedPromotions,
	}, nil
}
