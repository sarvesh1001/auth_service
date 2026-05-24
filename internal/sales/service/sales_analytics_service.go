// file: internal/sales/service/sales_analytics_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/models/sales_analytics"
	"auth-service/internal/sales/repository"
)

// SalesAnalyticsService defines the methods to process sales events.
type SalesAnalyticsService interface {
	ProcessSalesEvent(ctx context.Context, eventType string, payload []byte) error
}

type salesAnalyticsService struct {
	analyticsRepo  repository.AnalyticsRepository
	orderRepo      repository.OrderRepository
	invoiceRepo    repository.InvoiceRepository
	commissionRepo repository.SalesRepCommissionRepository
	returnRepo     repository.ReturnRepository
	productRepo    repository.ProductRepository
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

// NewSalesAnalyticsService creates a new instance.
func NewSalesAnalyticsService(
	analyticsRepo repository.AnalyticsRepository,
	orderRepo repository.OrderRepository,
	invoiceRepo repository.InvoiceRepository,
	commissionRepo repository.SalesRepCommissionRepository,
	returnRepo repository.ReturnRepository,
	productRepo repository.ProductRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SalesAnalyticsService {
	return &salesAnalyticsService{
		analyticsRepo:  analyticsRepo,
		orderRepo:      orderRepo,
		invoiceRepo:    invoiceRepo,
		commissionRepo: commissionRepo,
		returnRepo:     returnRepo,
		productRepo:    productRepo,
		pgClient:       pgClient,
		logger:         logger.Named("sales_analytics_service"),
	}
}

// ProcessSalesEvent dispatches events to the appropriate handler.
func (s *salesAnalyticsService) ProcessSalesEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	// Order events
	case salesEvents.EventOrderCreated:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderCreated(ctx, order)

	case salesEvents.EventOrderConfirmed:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderConfirmed(ctx, order)

	case salesEvents.EventOrderProcessing:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderProcessing(ctx, order)
	case salesEvents.EventAutomaticDiscountApplied:
		var autoPayload struct {
			CompanyID      string `json:"company_id"`
			AutoDiscountID string `json:"auto_discount_id"`
			Amount         string `json:"amount"`
			OrderTotal     string `json:"order_total"`
			EntityID       string `json:"entity_id"`
			CustomerID     string `json:"customer_id"`
			AppliedAt      string `json:"applied_at"`
		}
		if err := json.Unmarshal(payload, &autoPayload); err != nil {
			return fmt.Errorf("unmarshal automatic discount applied payload: %w", err)
		}
		return s.onAutomaticDiscountApplied(ctx, autoPayload)

	case salesEvents.EventStackingRuleUsed:
		var stackingPayload struct {
			CompanyID        string `json:"company_id"`
			RuleID           string `json:"rule_id"`
			CombinedDiscount string `json:"combined_discount"`
			Date             string `json:"date"`
		}
		if err := json.Unmarshal(payload, &stackingPayload); err != nil {
			return fmt.Errorf("unmarshal stacking rule usage payload: %w", err)
		}
		return s.onStackingRuleUsed(ctx, stackingPayload)
	case salesEvents.EventCouponApplied:
		var cp salesEvents.CouponAppliedPayload
		if err := json.Unmarshal(payload, &cp); err != nil {
			return fmt.Errorf("unmarshal coupon applied payload: %w", err)
		}
		return s.onCouponApplied(ctx, cp)

	case salesEvents.EventOrderShipped:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderShipped(ctx, order)

	case salesEvents.EventOrderDelivered:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderDelivered(ctx, order)

	case salesEvents.EventOrderCancelled:
		var order salesEvents.OrderPayload
		if err := json.Unmarshal(payload, &order); err != nil {
			return fmt.Errorf("unmarshal order payload: %w", err)
		}
		return s.onOrderCancelled(ctx, order)

	// Payment & return events
	case salesEvents.EventPaymentCompleted:
		var pay salesEvents.PaymentPayload
		if err := json.Unmarshal(payload, &pay); err != nil {
			return fmt.Errorf("unmarshal payment payload: %w", err)
		}
		return s.onPaymentCompleted(ctx, pay)

	case salesEvents.EventPaymentRefunded, salesEvents.EventPaymentPartiallyRefunded:
		var pay salesEvents.PaymentPayload
		if err := json.Unmarshal(payload, &pay); err != nil {
			return fmt.Errorf("unmarshal payment payload: %w", err)
		}
		return s.onPaymentRefunded(ctx, pay, eventType == salesEvents.EventPaymentRefunded)

	case salesEvents.EventReturnCreated:
		var ret salesEvents.ReturnPayload
		if err := json.Unmarshal(payload, &ret); err != nil {
			return fmt.Errorf("unmarshal return payload: %w", err)
		}
		return s.onReturnCreated(ctx, ret)

	case salesEvents.EventReturnApproved:
		var ret salesEvents.ReturnPayload
		if err := json.Unmarshal(payload, &ret); err != nil {
			return fmt.Errorf("unmarshal return payload: %w", err)
		}
		return s.onReturnApproved(ctx, ret)

	case salesEvents.EventReturnRejected:
		var ret salesEvents.ReturnPayload
		if err := json.Unmarshal(payload, &ret); err != nil {
			return fmt.Errorf("unmarshal return payload: %w", err)
		}
		return s.onReturnRejected(ctx, ret)

	case salesEvents.EventReturnCompleted:
		var ret salesEvents.ReturnPayload
		if err := json.Unmarshal(payload, &ret); err != nil {
			return fmt.Errorf("unmarshal return payload: %w", err)
		}
		return s.onReturnCompleted(ctx, ret)

	// Invoice events
	case salesEvents.EventInvoiceCreated:
		var inv salesEvents.InvoicePayload
		if err := json.Unmarshal(payload, &inv); err != nil {
			return fmt.Errorf("unmarshal invoice payload: %w", err)
		}
		return s.onInvoiceCreated(ctx, inv)

	case salesEvents.EventInvoiceIssued:
		var inv salesEvents.InvoicePayload
		if err := json.Unmarshal(payload, &inv); err != nil {
			return fmt.Errorf("unmarshal invoice payload: %w", err)
		}
		return s.onInvoiceIssued(ctx, inv)

	case salesEvents.EventInvoicePaid:
		var pay salesEvents.PaymentPayload
		if err := json.Unmarshal(payload, &pay); err != nil {
			return fmt.Errorf("unmarshal payment payload: %w", err)
		}
		return s.onInvoicePaid(ctx, pay)

	case salesEvents.EventInvoiceOverdue:
		var inv salesEvents.InvoicePayload
		if err := json.Unmarshal(payload, &inv); err != nil {
			return fmt.Errorf("unmarshal invoice payload: %w", err)
		}
		return s.onInvoiceOverdue(ctx, inv)

	case salesEvents.EventInvoiceCancelled:
		var inv salesEvents.InvoicePayload
		if err := json.Unmarshal(payload, &inv); err != nil {
			return fmt.Errorf("unmarshal invoice payload: %w", err)
		}
		return s.onInvoiceCancelled(ctx, inv)

	case salesEvents.EventInvoiceCredited:
		var inv salesEvents.InvoicePayload
		if err := json.Unmarshal(payload, &inv); err != nil {
			return fmt.Errorf("unmarshal invoice payload: %w", err)
		}
		return s.onInvoiceCredited(ctx, inv)

	// Quote events
	case salesEvents.EventQuoteCreated:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteCreated(ctx, quote)

	case salesEvents.EventQuoteSent:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteStatusChanged(ctx, quote, enums.QuoteStatusSent, enums.QuoteStatusDraft)
	case salesEvents.EventPromotionApplied:
		var promoPayload struct {
			CompanyID      string `json:"company_id"`
			PromotionID    string `json:"promotion_id"`
			EntityType     string `json:"entity_type"`
			EntityID       string `json:"entity_id"`
			DiscountAmount string `json:"discount_amount"`
			AppliedAt      string `json:"applied_at"`
		}
		if err := json.Unmarshal(payload, &promoPayload); err != nil {
			return fmt.Errorf("unmarshal promotion applied payload: %w", err)
		}
		return s.onPromotionApplied(ctx, promoPayload)
	case salesEvents.EventQuoteAccepted:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteStatusChanged(ctx, quote, enums.QuoteStatusAccepted, enums.QuoteStatusSent)

	case salesEvents.EventQuoteRejected:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteStatusChanged(ctx, quote, enums.QuoteStatusRejected, enums.QuoteStatusSent)

	case salesEvents.EventQuoteExpired:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteStatusChanged(ctx, quote, enums.QuoteStatusExpired, enums.QuoteStatusSent)

	case salesEvents.EventQuoteConverted:
		var quote salesEvents.QuotePayload
		if err := json.Unmarshal(payload, &quote); err != nil {
			return fmt.Errorf("unmarshal quote payload: %w", err)
		}
		return s.onQuoteConverted(ctx, quote)

	default:
		s.logger.Debug("ignored sales event", zap.String("event_type", eventType))
		return nil
	}
}

// ----------------------------------------------------------------------------
// Order status handlers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) onOrderCreated(ctx context.Context, order salesEvents.OrderPayload) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusDraft,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert order status history: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderConfirmed(ctx context.Context, order salesEvents.OrderPayload) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(order.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	orderDate, err := time.Parse(time.RFC3339, order.OrderDate)
	if err != nil {
		return fmt.Errorf("invalid order_date: %w", err)
	}
	grandTotal, err := decimal.NewFromString(order.GrandTotal)
	if err != nil {
		return fmt.Errorf("invalid grand_total: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close draft status
	if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, enums.OrderStatusDraft, now); err != nil {
		s.logger.Warn("failed to close draft status history", zap.Error(err))
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusConfirmed,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert confirmed status history: %w", err)
	}

	// Daily aggregates
	if err := s.analyticsRepo.IncrementDailyOrders(ctx, tx, companyID, orderDate, 1); err != nil {
		return err
	}
	if err := s.analyticsRepo.AddDailyRevenue(ctx, tx, companyID, orderDate, grandTotal); err != nil {
		return err
	}
	if err := s.analyticsRepo.IncrementUniqueCustomers(ctx, tx, companyID, orderDate, customerID); err != nil {
		s.logger.Warn("failed to increment unique customers", zap.Error(err))
	}

	// Customer metrics
	existing, _ := s.analyticsRepo.GetCustomerMetrics(ctx, tx, companyID, customerID)
	firstOrderDate := orderDate
	if existing != nil && existing.FirstOrderDate != nil {
		firstOrderDate = *existing.FirstOrderDate
	}
	metric := &sales_analytics.CustomerMetric{
		CustomerID:     customerID,
		CompanyID:      companyID,
		FirstOrderDate: &firstOrderDate,
		LastOrderDate:  &orderDate,
		TotalOrders:    1,
		TotalSpent:     grandTotal,
	}
	if err := s.analyticsRepo.UpdateCustomerMetrics(ctx, tx, metric); err != nil {
		return err
	}

	// Product sales and order item analytics
	for _, item := range order.Items {
		productID, err := uuid.Parse(item.ProductID)
		if err != nil {
			s.logger.Warn("invalid product_id", zap.String("product_id", item.ProductID), zap.Error(err))
			continue
		}
		quantity, err := decimal.NewFromString(item.Quantity)
		if err != nil {
			s.logger.Warn("invalid quantity", zap.String("quantity", item.Quantity), zap.Error(err))
			continue
		}
		unitPrice, err := decimal.NewFromString(item.UnitPrice)
		if err != nil {
			s.logger.Warn("invalid unit_price", zap.String("unit_price", item.UnitPrice), zap.Error(err))
			continue
		}
		discount, err := decimal.NewFromString(item.DiscountTotal)
		if err != nil {
			discount = decimal.Zero
		}
		tax, err := decimal.NewFromString(item.TaxTotal)
		if err != nil {
			tax = decimal.Zero
		}
		revenue := quantity.Mul(unitPrice)
		lineAmount := revenue.Sub(discount).Add(tax)

		if err := s.analyticsRepo.AddProductSales(ctx, tx, companyID, productID, orderDate, quantity, revenue, discount); err != nil {
			s.logger.Error("failed to add product sales", zap.Error(err))
		}
		orderItemID := uuid.Nil
		if item.OrderItemID != "" {
			orderItemID, _ = uuid.Parse(item.OrderItemID)
		}
		analyticsItem := &sales_analytics.OrderItemAnalytics{
			OrderItemID:     orderItemID,
			OrderID:         orderID,
			CompanyID:       companyID,
			ProductID:       productID,
			Quantity:        quantity,
			UnitPrice:       unitPrice,
			DiscountAmount:  discount,
			TaxAmount:       tax,
			TotalLineAmount: lineAmount,
			CogsPerUnit:     nil,
			OrderDate:       orderDate,
		}
		if err := s.analyticsRepo.UpsertOrderItemAnalytics(ctx, tx, analyticsItem); err != nil {
			s.logger.Error("failed to upsert order item analytics", zap.Error(err))
		}
	}

	// Sales rep performance
	if order.SalesRepID != "" {
		salesRepID, err := uuid.Parse(order.SalesRepID)
		if err == nil {
			commissionRate, err := s.getCommissionRate(ctx, tx, companyID, salesRepID, orderDate)
			if err != nil {
				s.logger.Warn("failed to get commission rate, using 0", zap.Error(err))
				commissionRate = decimal.Zero
			}
			commission := grandTotal.Mul(commissionRate).Div(decimal.NewFromInt(100))
			if err := s.analyticsRepo.IncrementSalesRepPerformance(ctx, tx, companyID, salesRepID, orderDate, grandTotal, commission); err != nil {
				s.logger.Error("failed to update sales rep performance", zap.Error(err))
			}
		} else {
			s.logger.Warn("invalid sales_rep_id in order payload", zap.String("sales_rep_id", order.SalesRepID))
		}
	}

	// Hourly sales
	hourBucket := time.Date(orderDate.Year(), orderDate.Month(), orderDate.Day(), orderDate.Hour(), 0, 0, 0, orderDate.Location())
	if err := s.analyticsRepo.IncrementOrderHourlySales(ctx, tx, companyID, hourBucket, grandTotal, customerID); err != nil {
		s.logger.Warn("failed to increment hourly sales", zap.Error(err))
	}

	// Fulfillment metrics
	fulfillMetrics := &sales_analytics.FulfillmentMetrics{
		OrderID:     orderID,
		CompanyID:   companyID,
		ConfirmedAt: &now,
	}
	if err := s.analyticsRepo.UpsertFulfillmentMetrics(ctx, tx, fulfillMetrics); err != nil {
		s.logger.Warn("failed to upsert fulfillment metrics", zap.Error(err))
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderProcessing(ctx context.Context, order salesEvents.OrderPayload) error {
	return s.updateOrderStatus(ctx, order, enums.OrderStatusProcessing, enums.OrderStatusConfirmed)
}

func (s *salesAnalyticsService) onOrderShipped(ctx context.Context, order salesEvents.OrderPayload) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, enums.OrderStatusProcessing, now); err != nil {
		s.logger.Warn("failed to close processing status", zap.Error(err))
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusShipped,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert shipped status: %w", err)
	}

	carrier := order.Carrier
	tracking := order.TrackingNumber
	region := order.ShippingRegion
	if err := s.analyticsRepo.UpdateFulfillmentShipping(ctx, tx, orderID, now, &carrier, &tracking, &region); err != nil {
		s.logger.Warn("failed to update fulfillment shipping", zap.Error(err))
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderDelivered(ctx context.Context, order salesEvents.OrderPayload) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, enums.OrderStatusShipped, now); err != nil {
		s.logger.Warn("failed to close shipped status", zap.Error(err))
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusDelivered,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert delivered status: %w", err)
	}
	if err := s.analyticsRepo.UpdateFulfillmentDelivery(ctx, tx, orderID, now); err != nil {
		s.logger.Warn("failed to update fulfillment delivery", zap.Error(err))
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderCancelled(ctx context.Context, order salesEvents.OrderPayload) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()
	statusBefore := enums.OrderStatus(order.StatusBeforeCancel)
	grandTotal, _ := decimal.NewFromString(order.GrandTotal)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if statusBefore != "" {
		if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, statusBefore, now); err != nil {
			s.logger.Warn("failed to close previous status", zap.Error(err))
		}
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusCancelled,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert cancelled status: %w", err)
	}
	cancelReason := &sales_analytics.OrderCancellationReason{
		OrderID:                 orderID,
		CompanyID:               companyID,
		CancellationReason:      order.CancellationReason,
		CancelledAt:             now,
		OrderStatusBeforeCancel: statusBefore,
		OrderTotalBeforeCancel:  grandTotal,
	}
	if order.CancelledBy != "" {
		cancelledBy, _ := uuid.Parse(order.CancelledBy)
		cancelReason.CancelledBy = &cancelledBy
	}
	if err := s.analyticsRepo.InsertOrderCancellationReason(ctx, tx, cancelReason); err != nil {
		s.logger.Error("failed to insert cancellation reason", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Order helpers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) updateOrderStatus(ctx context.Context, order salesEvents.OrderPayload, newStatus, previousStatus enums.OrderStatus) error {
	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, previousStatus, now); err != nil {
		s.logger.Warn("failed to close previous status", zap.String("status", string(previousStatus)), zap.Error(err))
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    newStatus,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert %s status: %w", newStatus, err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) getCommissionRate(ctx context.Context, tx repository.DBTX, companyID, salesRepID uuid.UUID, at time.Time) (decimal.Decimal, error) {
	rule, err := s.commissionRepo.GetApplicableCommission(ctx, tx, companyID, salesRepID, nil, at)
	if err != nil {
		return decimal.Zero, err
	}
	return rule.CommissionRate, nil
}

// ----------------------------------------------------------------------------
// Payment & Return handlers
// ----------------------------------------------------------------------------

// onPaymentCompleted now also updates payment method daily breakdown.
func (s *salesAnalyticsService) onPaymentCompleted(ctx context.Context, pay salesEvents.PaymentPayload) error {
	companyID, err := uuid.Parse(pay.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	paymentDate, err := time.Parse(time.RFC3339, pay.PaymentDate)
	if err != nil {
		return fmt.Errorf("invalid payment_date: %w", err)
	}
	amount, err := decimal.NewFromString(pay.Amount)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	paymentMethod, err := parsePaymentMethod(pay.PaymentMethod)
	if err != nil {
		s.logger.Warn("invalid payment_method in event, skipping method breakdown", zap.String("method", pay.PaymentMethod), zap.Error(err))
		paymentMethod = enums.PaymentMethodOther // fallback
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Update daily total payments (existing)
	if err := s.analyticsRepo.AddDailyPayments(ctx, tx, companyID, paymentDate, amount); err != nil {
		return err
	}
	// Update payment method daily breakdown (new)
	if err := s.analyticsRepo.IncrementPaymentMethodDaily(ctx, tx, companyID, paymentDate, paymentMethod, amount); err != nil {
		s.logger.Error("failed to update payment method daily", zap.Error(err))
		// non‑fatal
	}
	return tx.Commit()
}

// onPaymentRefunded handles both full and partial refund events.
// Also inserts refund_fact if the refund is linked to a return.
func (s *salesAnalyticsService) onPaymentRefunded(ctx context.Context, pay salesEvents.PaymentPayload, isFullRefund bool) error {
	companyID, err := uuid.Parse(pay.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	// Refund date – use payment date (or we could use created_at from the event)
	refundDate, err := time.Parse(time.RFC3339, pay.PaymentDate)
	if err != nil {
		refundDate = time.Now()
	}
	refundAmount, err := decimal.NewFromString(pay.Amount)
	if err != nil {
		return fmt.Errorf("invalid refund amount: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Increment refund metrics
	if err := s.analyticsRepo.IncrementRefundMetrics(ctx, tx, companyID, refundDate, refundAmount, isFullRefund); err != nil {
		return fmt.Errorf("failed to update refund metrics: %w", err)
	}

	// Find if this refund is associated with a return
	// The event payload does not contain return_id, so we query payment_refunds table.
	// We need the refund_id – the event payload does not contain it either.
	// For a robust solution the event should be extended with refund_id and return_id.
	// Here we assume the refund event includes a "refund_id" field; if not, we skip.
	if pay.RefundID != "" {
		refundID, err := uuid.Parse(pay.RefundID)
		if err == nil {
			var returnID uuid.UUID
			query := `SELECT return_id FROM sales.payment_refunds WHERE refund_id = $1 AND company_id = $2`
			err = tx.QueryRowContext(ctx, query, refundID, companyID).Scan(&returnID)
			if err == nil && returnID != uuid.Nil {
				// Get refund amount and date (already have)
				refundMethod, _ := parsePaymentMethod(pay.PaymentMethod)
				status := "completed"
				if !isFullRefund {
					status = "partial"
				}
				// Original payment ID from the event
				paymentID, _ := uuid.Parse(pay.PaymentID)
				fact := &sales_analytics.RefundFact{
					CompanyID:    companyID,
					RefundID:     refundID,
					ReturnID:     returnID,
					PaymentID:    paymentID,
					Amount:       refundAmount,
					RefundDate:   refundDate,
					RefundMethod: &refundMethod,
					Status:       &status,
				}
				if err := s.analyticsRepo.InsertRefundFact(ctx, tx, fact); err != nil {
					s.logger.Error("failed to insert refund fact", zap.Error(err))
				}
			}
		}
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Return Analytics Handlers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) onReturnCreated(ctx context.Context, payload salesEvents.ReturnPayload) error {
	returnID, err := uuid.Parse(payload.ReturnID)
	if err != nil {
		return fmt.Errorf("invalid return_id: %w", err)
	}
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(payload.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	returnDate, err := time.Parse(time.RFC3339, payload.ReturnDate)
	if err != nil {
		return fmt.Errorf("invalid return_date: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Daily return metrics – increment requests
	if err := s.analyticsRepo.IncrementDailyReturnRequests(ctx, tx, companyID, returnDate); err != nil {
		return fmt.Errorf("increment return requests: %w", err)
	}

	// 2. Unique customer per day
	if err := s.analyticsRepo.IncrementDailyReturnUniqueCustomer(ctx, tx, companyID, returnDate, customerID); err != nil {
		s.logger.Warn("failed to increment unique customer for return", zap.Error(err))
	}

	// 3. Insert processing time for 'pending' status
	pendingFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusPending,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, pendingFact); err != nil {
		return fmt.Errorf("insert pending processing time: %w", err)
	}

	// 4. Fetch return items with reasons (from database, because event may not contain reasons)
	items, err := s.returnRepo.GetItems(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return items: %w", err)
	}

	// 5. Record reason facts and product category aggregations
	for _, it := range items {
		// Reason fact
		reasonFact := &sales_analytics.ReturnReasonFact{
			CompanyID:        companyID,
			ReturnID:         returnID,
			ReturnItemID:     it.ReturnItemID,
			ReasonCode:       nil, // could be derived from it.Reason or a code mapping
			ReasonText:       it.Reason,
			ProductID:        &it.ProductID,
			QuantityReturned: it.Quantity,
			RefundAmount:     it.RefundAmount,
			ReturnDate:       returnDate,
		}
		if err := s.analyticsRepo.InsertReturnReasonFact(ctx, tx, reasonFact); err != nil {
			s.logger.Error("failed to insert return reason fact", zap.Error(err))
		}

		// Product category fact – get product details
		_, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			s.logger.Warn("product not found for category aggregation", zap.String("product_id", it.ProductID.String()), zap.Error(err))
			continue
		}
		// Determine if this is the first return for this return_id (unique return per category)
		// We'll treat each return as one “unique return” per category. For simplicity, we increment unique_returns by 1
		// if this category hasn't been seen for this return. We can track in memory or use a more complex query,
		// but to keep the example simple we just call IncrementReturnProductCategory with isUniqueReturn = true
		// for the first product in the return (or we could count later). Here we'll call once per return item
		// but set unique_returns = 0 for subsequent items. To avoid overcounting, we'll only mark the first item as unique.
		// A simpler approach: leave unique_returns as 0 and rely on daily return metrics for count of returns.
		// We'll set isUniqueReturn = false to avoid overcounting.
		var categoryID *uuid.UUID
		var categoryName *string
		// If your Product model has CategoryID/CategoryName, use them; otherwise skip.
		// For demonstration, we pass nil – you can extend later.
		if err := s.analyticsRepo.IncrementReturnProductCategory(ctx, tx, companyID, categoryID, categoryName, returnDate, it.Quantity, it.RefundAmount, false); err != nil {
			s.logger.Error("failed to increment return product category", zap.Error(err))
		}
	}

	return tx.Commit()
}

func (s *salesAnalyticsService) onReturnApproved(ctx context.Context, payload salesEvents.ReturnPayload) error {
	returnID, err := uuid.Parse(payload.ReturnID)
	if err != nil {
		return fmt.Errorf("invalid return_id: %w", err)
	}
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	approvalDate := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close pending status
	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusPending, approvalDate); err != nil {
		s.logger.Warn("failed to close pending processing time", zap.Error(err))
	}
	// Insert approved status
	approvedFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusApproved,
		EnteredAt: approvalDate,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, approvedFact); err != nil {
		return fmt.Errorf("insert approved processing time: %w", err)
	}

	// Update daily metrics – approvals
	// Use the return date from the return (need to fetch it)
	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return for approval date: %w", err)
	}
	if err := s.analyticsRepo.IncrementDailyReturnApprovals(ctx, tx, companyID, ret.ReturnDate); err != nil {
		return fmt.Errorf("increment daily return approvals: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onReturnRejected(ctx context.Context, payload salesEvents.ReturnPayload) error {
	returnID, err := uuid.Parse(payload.ReturnID)
	if err != nil {
		return fmt.Errorf("invalid return_id: %w", err)
	}
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	rejectionDate := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close pending status
	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusPending, rejectionDate); err != nil {
		s.logger.Warn("failed to close pending processing time", zap.Error(err))
	}
	// Optionally insert rejected status (not required for duration calculation)
	// Update daily metrics – rejections
	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return for rejection date: %w", err)
	}
	if err := s.analyticsRepo.IncrementDailyReturnRejections(ctx, tx, companyID, ret.ReturnDate); err != nil {
		return fmt.Errorf("increment daily return rejections: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onReturnCompleted(ctx context.Context, payload salesEvents.ReturnPayload) error {
	returnID, err := uuid.Parse(payload.ReturnID)
	if err != nil {
		return fmt.Errorf("invalid return_id: %w", err)
	}
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	completionDate := time.Now()
	totalRefund, err := decimal.NewFromString(payload.TotalRefund)
	if err != nil {
		return fmt.Errorf("invalid total_refund: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close approved status (if any)
	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusApproved, completionDate); err != nil {
		s.logger.Warn("failed to close approved processing time", zap.Error(err))
	}
	// Insert completed status
	completedFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusCompleted,
		EnteredAt: completionDate,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, completedFact); err != nil {
		return fmt.Errorf("insert completed processing time: %w", err)
	}

	// Get return details (return date, credit note amount)
	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return for completion: %w", err)
	}
	var creditNoteAmount decimal.Decimal
	if ret.CreditNoteID != nil && *ret.CreditNoteID != uuid.Nil {
		creditNote, err := s.invoiceRepo.GetByID(ctx, tx, companyID, *ret.CreditNoteID)
		if err == nil && creditNote != nil && creditNote.GrandTotal.LessThan(decimal.Zero) {
			creditNoteAmount = creditNote.GrandTotal.Neg()
		}
	}

	// Update daily return metrics – completions
	if err := s.analyticsRepo.IncrementDailyReturnCompletions(ctx, tx, companyID, ret.ReturnDate, totalRefund, creditNoteAmount); err != nil {
		return fmt.Errorf("increment daily return completions: %w", err)
	}

	// Adjust revenue and product returns
	if err := s.analyticsRepo.AddDailyRevenue(ctx, tx, companyID, ret.ReturnDate, totalRefund.Neg()); err != nil {
		return err
	}
	if ret.OrderID != uuid.Nil {
		order, _ := s.orderRepo.GetByID(ctx, tx, companyID, ret.OrderID)
		if order != nil {
			if err := s.updateCustomerSpent(ctx, tx, companyID, order.CustomerID, totalRefund.Neg()); err != nil {
				s.logger.Warn("failed to adjust customer spent after return", zap.Error(err))
			}
		}
	} else if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
		invoice, _ := s.invoiceRepo.GetByID(ctx, tx, companyID, *ret.InvoiceID)
		if invoice != nil {
			if err := s.updateCustomerSpent(ctx, tx, companyID, invoice.CustomerID, totalRefund.Neg()); err != nil {
				s.logger.Warn("failed to adjust customer spent after return", zap.Error(err))
			}
		}
	}
	// Update product returns fact
	items, err := s.returnRepo.GetItems(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return items for completion: %w", err)
	}
	for _, it := range items {
		if err := s.analyticsRepo.AddProductSales(ctx, tx, companyID, it.ProductID, ret.ReturnDate, it.Quantity.Neg(), it.RefundAmount.Neg(), decimal.Zero); err != nil {
			s.logger.Error("failed to adjust product sales for return", zap.Error(err))
		}
		if err := s.analyticsRepo.AddProductReturns(ctx, tx, companyID, it.ProductID, ret.ReturnDate, it.Quantity, it.RefundAmount); err != nil {
			s.logger.Error("failed to add product returns fact", zap.Error(err))
		}
	}

	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Invoice Analytics Handlers
// ----------------------------------------------------------------------------

// onInvoiceCreated inserts the initial draft status into invoice_status_history.
func (s *salesAnalyticsService) onInvoiceCreated(ctx context.Context, inv salesEvents.InvoicePayload) error {
	invoiceID, err := uuid.Parse(inv.InvoiceID)
	if err != nil {
		return fmt.Errorf("invalid invoice_id: %w", err)
	}
	companyID, err := uuid.Parse(inv.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusDraft,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert invoice status history: %w", err)
	}
	return tx.Commit()
}

// onInvoiceIssued closes draft, inserts issued, captures item analytics, updates daily metrics,
// and refreshes aging snapshot.
func (s *salesAnalyticsService) onInvoiceIssued(ctx context.Context, inv salesEvents.InvoicePayload) error {
	invoiceID, err := uuid.Parse(inv.InvoiceID)
	if err != nil {
		return fmt.Errorf("invalid invoice_id: %w", err)
	}
	companyID, err := uuid.Parse(inv.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	invoiceDate, err := time.Parse(time.RFC3339, inv.InvoiceDate)
	if err != nil {
		return fmt.Errorf("invalid invoice_date: %w", err)
	}
	grandTotal, err := decimal.NewFromString(inv.GrandTotal)
	if err != nil {
		return fmt.Errorf("invalid grand_total: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close draft status
	if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, enums.InvoiceStatusDraft, now); err != nil {
		s.logger.Warn("failed to close draft invoice status", zap.Error(err))
	}
	// Insert issued status
	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusIssued,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert issued status: %w", err)
	}

	// Daily metrics
	if err := s.analyticsRepo.IncrementDailyInvoiceIssued(ctx, tx, companyID, invoiceDate, grandTotal); err != nil {
		return err
	}

	// Invoice item analytics
	items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, invoiceID)
	if err != nil {
		s.logger.Warn("failed to fetch invoice items for analytics", zap.Error(err))
	} else {
		for _, it := range items {
			productID := uuid.Nil
			if it.ProductID != nil {
				productID = *it.ProductID
			}
			discount := decimal.Zero
			if it.DiscountAmount != nil {
				discount = *it.DiscountAmount
			}
			tax := decimal.Zero
			if it.TaxAmount != nil {
				tax = *it.TaxAmount
			}
			lineTotal := it.UnitPrice.Mul(it.Quantity).Sub(discount).Add(tax)
			analyticsItem := &sales_analytics.InvoiceItemAnalytics{
				InvoiceItemID:   it.InvoiceItemID,
				InvoiceID:       invoiceID,
				CompanyID:       companyID,
				ProductID:       productID,
				Quantity:        it.Quantity,
				UnitPrice:       it.UnitPrice,
				DiscountAmount:  discount,
				TaxAmount:       tax,
				TotalLineAmount: lineTotal,
				InvoiceDate:     invoiceDate,
			}
			if err := s.analyticsRepo.UpsertInvoiceItemAnalytics(ctx, tx, analyticsItem); err != nil {
				s.logger.Error("failed to upsert invoice item analytics", zap.Error(err))
			}
		}
	}

	// Refresh aging snapshot as of today
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, now); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after issuance", zap.Error(err))
	}

	// Payment term analytics (using event payload, not invoice model)
	if inv.PaymentTermID != "" {
		termID, err := uuid.Parse(inv.PaymentTermID)
		if err == nil {
			eligible := inv.EarlyDiscountPercent != "" && inv.EarlyDiscountDays > 0
			if err := s.analyticsRepo.RecordPaymentTermInvoice(ctx, tx, companyID, termID, invoiceDate, grandTotal, eligible); err != nil {
				s.logger.Warn("failed to record payment term invoice", zap.Error(err))
			}
		}
	}
	return tx.Commit()
}

// onInvoicePaid processes payment allocations: closes previous status, inserts paid,
// updates daily metrics, records early discount if taken, refreshes aging.
func (s *salesAnalyticsService) onInvoicePaid(ctx context.Context, pay salesEvents.PaymentPayload) error {
	if len(pay.Allocations) == 0 {
		return nil
	}
	companyID, err := uuid.Parse(pay.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	paymentDate, err := time.Parse(time.RFC3339, pay.PaymentDate)
	if err != nil {
		return fmt.Errorf("invalid payment_date: %w", err)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, alloc := range pay.Allocations {
		invoiceID, err := uuid.Parse(alloc.InvoiceID)
		if err != nil {
			s.logger.Warn("invalid invoice_id in allocation", zap.Error(err))
			continue
		}
		// Fetch invoice details to get invoice_date, due_date, early discount info
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
		if err != nil {
			s.logger.Error("failed to fetch invoice for payment", zap.Error(err))
			continue
		}

		// Close previous status (issued or overdue) and insert paid
		previousStatus := invoice.Status
		if previousStatus != enums.InvoiceStatusIssued && previousStatus != enums.InvoiceStatusOverdue {
			s.logger.Warn("invoice paid but status not issued/overdue", zap.String("status", string(previousStatus)))
		}
		if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, previousStatus, paymentDate); err != nil {
			s.logger.Warn("failed to close previous invoice status", zap.Error(err))
		}
		history := &sales_analytics.InvoiceStatusHistory{
			InvoiceID: invoiceID,
			CompanyID: companyID,
			Status:    enums.InvoiceStatusPaid,
			EnteredAt: paymentDate,
		}
		if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
			s.logger.Error("failed to insert paid status", zap.Error(err))
			continue
		}

		// Days to pay
		daysToPay := int(paymentDate.Sub(invoice.InvoiceDate).Hours() / 24)

		// Update daily metrics: total_paid_value, total_invoices_paid, avg_days_to_payment
		amount, _ := decimal.NewFromString(alloc.Amount)
		if err := s.analyticsRepo.IncrementDailyInvoicePaid(ctx, tx, companyID, paymentDate, amount, &daysToPay); err != nil {
			s.logger.Error("failed to update daily paid metrics", zap.Error(err))
		}

		// Early discount taken?
		if alloc.IsEarlyDiscount && alloc.DiscountAmount != "" {
			discountAmt, _ := decimal.NewFromString(alloc.DiscountAmount)
			if err := s.analyticsRepo.RecordEarlyDiscount(ctx, tx, companyID, paymentDate, discountAmt); err != nil {
				s.logger.Error("failed to record early discount", zap.Error(err))
			}
		}
	}

	// Refresh aging snapshot after payments
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, paymentDate); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after payment", zap.Error(err))
	}
	return tx.Commit()
}

// onInvoiceOverdue handles EventInvoiceOverdue: close issued status, insert overdue,
// update daily metrics, refresh aging.
func (s *salesAnalyticsService) onInvoiceOverdue(ctx context.Context, inv salesEvents.InvoicePayload) error {
	invoiceID, err := uuid.Parse(inv.InvoiceID)
	if err != nil {
		return fmt.Errorf("invalid invoice_id: %w", err)
	}
	companyID, err := uuid.Parse(inv.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	overdueDate := time.Now()
	grandTotal, _ := decimal.NewFromString(inv.GrandTotal)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close the issued status (if any)
	if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, enums.InvoiceStatusIssued, overdueDate); err != nil {
		s.logger.Warn("failed to close issued status for overdue", zap.Error(err))
	}
	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusOverdue,
		EnteredAt: overdueDate,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert overdue status: %w", err)
	}

	// Update daily metrics: total_invoices_overdue, total_overdue_value
	if err := s.analyticsRepo.IncrementDailyInvoiceOverdue(ctx, tx, companyID, overdueDate, grandTotal); err != nil {
		return err
	}
	// Refresh aging snapshot
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, overdueDate); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after overdue", zap.Error(err))
	}
	return tx.Commit()
}

// onInvoiceCancelled handles cancellation events: close previous status, insert cancelled,
// update daily metrics, refresh aging.
func (s *salesAnalyticsService) onInvoiceCancelled(ctx context.Context, inv salesEvents.InvoicePayload) error {
	invoiceID, err := uuid.Parse(inv.InvoiceID)
	if err != nil {
		return fmt.Errorf("invalid invoice_id: %w", err)
	}
	companyID, err := uuid.Parse(inv.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	cancelledAt := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get current status before closing
	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		s.logger.Warn("failed to fetch invoice for cancellation", zap.Error(err))
	} else {
		if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, invoice.Status, cancelledAt); err != nil {
			s.logger.Warn("failed to close previous status for cancellation", zap.Error(err))
		}
	}
	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusCancelled,
		EnteredAt: cancelledAt,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert cancelled status: %w", err)
	}
	// Daily metrics: total_invoices_cancelled
	if err := s.analyticsRepo.IncrementDailyInvoiceCancelled(ctx, tx, companyID, cancelledAt); err != nil {
		return err
	}
	// Refresh aging snapshot (cancelled invoices no longer count as outstanding)
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, cancelledAt); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after cancellation", zap.Error(err))
	}
	return tx.Commit()
}

// onInvoiceCredited handles credit notes: close previous status, insert credited,
// refresh aging (credited invoices are considered fulfilled), and insert credit_note_fact if linked to a return.
func (s *salesAnalyticsService) onInvoiceCredited(ctx context.Context, inv salesEvents.InvoicePayload) error {
	invoiceID, err := uuid.Parse(inv.InvoiceID)
	if err != nil {
		return fmt.Errorf("invalid invoice_id: %w", err)
	}
	companyID, err := uuid.Parse(inv.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	creditedAt := time.Now()
	grandTotal, _ := decimal.NewFromString(inv.GrandTotal)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err == nil {
		if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, invoice.Status, creditedAt); err != nil {
			s.logger.Warn("failed to close previous status for credit", zap.Error(err))
		}
	}
	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusCredited,
		EnteredAt: creditedAt,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert credited status: %w", err)
	}
	// Refresh aging snapshot
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, creditedAt); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after credit", zap.Error(err))
	}

	// Check if this invoice is a credit note linked to a return
	var returnID *uuid.UUID
	query := `SELECT return_id FROM sales.returns WHERE credit_note_id = $1 AND company_id = $2`
	err = tx.QueryRowContext(ctx, query, invoiceID, companyID).Scan(&returnID)
	if err == nil && returnID != nil {
		// Insert into credit_note_fact
		fact := &sales_analytics.CreditNoteFact{
			CompanyID:     companyID,
			CreditNoteID:  invoiceID,
			ReturnID:      returnID,
			IssuedDate:    invoice.InvoiceDate, // or creditedAt
			IssuedAmount:  grandTotal.Abs(),
			AppliedAmount: decimal.Zero,
			Status:        "issued",
		}
		if err := s.analyticsRepo.InsertCreditNoteFact(ctx, tx, fact); err != nil {
			s.logger.Error("failed to insert credit note fact", zap.Error(err))
		}
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Quote Analytics Handlers
// ----------------------------------------------------------------------------

// onQuoteCreated inserts the initial draft status and updates daily quote creation metrics.
func (s *salesAnalyticsService) onQuoteCreated(ctx context.Context, quote salesEvents.QuotePayload) error {
	quoteID, err := uuid.Parse(quote.QuoteID)
	if err != nil {
		return fmt.Errorf("invalid quote_id: %w", err)
	}
	companyID, err := uuid.Parse(quote.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	quoteDate := time.Now()
	if quote.QuoteDate != "" {
		if parsed, err := time.Parse(time.RFC3339, quote.QuoteDate); err == nil {
			quoteDate = parsed
		}
	}
	grandTotal, err := decimal.NewFromString(quote.GrandTotal)
	if err != nil {
		return fmt.Errorf("invalid grand_total: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Insert draft status history
	history := &sales_analytics.QuoteStatusHistory{
		QuoteID:   quoteID,
		CompanyID: companyID,
		Status:    enums.QuoteStatusDraft,
		EnteredAt: time.Now(),
	}
	if err := s.analyticsRepo.InsertQuoteStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert quote status history: %w", err)
	}

	// Increment daily aggregates
	if err := s.analyticsRepo.IncrementDailyQuoteCreated(ctx, tx, companyID, quoteDate, grandTotal); err != nil {
		return err
	}

	// Quote item analytics (if items are present)
	if quote.Items != nil && len(quote.Items) > 0 {
		for _, item := range quote.Items {
			productID, err := uuid.Parse(item.ProductID)
			if err != nil {
				s.logger.Warn("invalid product_id in quote item", zap.String("product_id", item.ProductID), zap.Error(err))
				continue
			}
			quantity, err := decimal.NewFromString(item.Quantity)
			if err != nil {
				s.logger.Warn("invalid quantity in quote item", zap.Error(err))
				continue
			}
			unitPrice, err := decimal.NewFromString(item.UnitPrice)
			if err != nil {
				s.logger.Warn("invalid unit_price in quote item", zap.Error(err))
				continue
			}
			discount, _ := decimal.NewFromString(item.DiscountTotal)
			tax, _ := decimal.NewFromString(item.TaxTotal)

			analyticsItem := &sales_analytics.QuoteItemAnalytics{
				QuoteItemID:     uuid.Nil,
				QuoteID:         quoteID,
				CompanyID:       companyID,
				ProductID:       productID,
				Quantity:        quantity,
				UnitPrice:       unitPrice,
				DiscountAmount:  discount,
				TaxAmount:       tax,
				TotalLineAmount: unitPrice.Mul(quantity).Sub(discount).Add(tax),
				QuoteDate:       quoteDate,
			}
			if item.QuoteItemID != "" {
				if id, err := uuid.Parse(item.QuoteItemID); err == nil {
					analyticsItem.QuoteItemID = id
				}
			}
			if err := s.analyticsRepo.UpsertQuoteItemAnalytics(ctx, tx, analyticsItem); err != nil {
				s.logger.Error("failed to upsert quote item analytics", zap.Error(err))
			}
		}
	}
	return tx.Commit()
}

// onQuoteStatusChanged handles status transitions (sent, accepted, rejected, expired).
func (s *salesAnalyticsService) onQuoteStatusChanged(ctx context.Context, quote salesEvents.QuotePayload, newStatus, previousStatus enums.QuoteStatus) error {
	quoteID, err := uuid.Parse(quote.QuoteID)
	if err != nil {
		return fmt.Errorf("invalid quote_id: %w", err)
	}
	companyID, err := uuid.Parse(quote.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	now := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close the previous status
	if err := s.analyticsRepo.CloseQuoteStatusHistory(ctx, tx, quoteID, previousStatus, now); err != nil {
		s.logger.Warn("failed to close previous quote status", zap.String("previous", string(previousStatus)), zap.Error(err))
	}
	// Insert new status
	history := &sales_analytics.QuoteStatusHistory{
		QuoteID:   quoteID,
		CompanyID: companyID,
		Status:    newStatus,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertQuoteStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert quote status history: %w", err)
	}
	return tx.Commit()
}

// onQuoteConverted records the conversion fact and updates daily conversion metrics.
func (s *salesAnalyticsService) onQuoteConverted(ctx context.Context, quote salesEvents.QuotePayload) error {
	quoteID, err := uuid.Parse(quote.QuoteID)
	if err != nil {
		return fmt.Errorf("invalid quote_id: %w", err)
	}
	companyID, err := uuid.Parse(quote.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(quote.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	convertedAt := time.Now()
	quoteValue, err := decimal.NewFromString(quote.GrandTotal)
	if err != nil {
		return fmt.Errorf("invalid grand_total: %w", err)
	}

	// Order ID from conversion (must be present in payload)
	if quote.ConvertedOrderID == "" {
		s.logger.Warn("quote converted event missing converted_order_id", zap.String("quote_id", quote.QuoteID))
		return nil
	}
	orderID, err := uuid.Parse(quote.ConvertedOrderID)
	if err != nil {
		return fmt.Errorf("invalid converted_order_id: %w", err)
	}

	// Parse quote creation date for conversion time
	var quoteCreatedAt time.Time
	if quote.QuoteDate != "" {
		quoteCreatedAt, _ = time.Parse(time.RFC3339, quote.QuoteDate)
	} else {
		quoteCreatedAt = convertedAt
	}
	conversionSeconds := int(convertedAt.Sub(quoteCreatedAt).Seconds())

	var expiryDays *int
	if quote.ExpiryDate != "" {
		expiry, err := time.Parse(time.RFC3339, quote.ExpiryDate)
		if err == nil {
			days := int(expiry.Sub(quoteCreatedAt).Hours() / 24)
			expiryDays = &days
		}
	}

	// Order value - assume equal to quote value at conversion
	orderValue := quoteValue

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close the 'accepted' status (previous status) before inserting 'converted'
	if err := s.analyticsRepo.CloseQuoteStatusHistory(ctx, tx, quoteID, enums.QuoteStatusAccepted, convertedAt); err != nil {
		s.logger.Warn("failed to close accepted status", zap.Error(err))
	}
	// Insert converted status
	history := &sales_analytics.QuoteStatusHistory{
		QuoteID:   quoteID,
		CompanyID: companyID,
		Status:    enums.QuoteStatusConverted,
		EnteredAt: convertedAt,
	}
	if err := s.analyticsRepo.InsertQuoteStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert converted status: %w", err)
	}

	// Insert conversion fact
	fact := &sales_analytics.QuoteConversionFact{
		QuoteID:                quoteID,
		OrderID:                orderID,
		CompanyID:              companyID,
		CustomerID:             customerID,
		QuoteValueAtConversion: quoteValue,
		OrderValueAtConversion: orderValue,
		ConversionTimeSeconds:  conversionSeconds,
		QuoteExpiryDays:        expiryDays,
		UsedCouponIDs:          nil,
		SalesRepID:             nil,
		ConvertedAt:            convertedAt,
	}
	if err := s.analyticsRepo.InsertQuoteConversionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert quote conversion fact: %w", err)
	}

	// Update daily conversion metrics
	if err := s.analyticsRepo.IncrementDailyQuoteConverted(ctx, tx, companyID, convertedAt, orderValue); err != nil {
		return err
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// parsePaymentMethod converts a string from the event payload to a PaymentMethod enum.
func parsePaymentMethod(methodStr string) (enums.PaymentMethod, error) {
	switch methodStr {
	case "cash":
		return enums.PaymentMethodCash, nil
	case "card":
		return enums.PaymentMethodCard, nil
	case "bank_transfer":
		return enums.PaymentMethodBankTransfer, nil
	case "digital_wallet":
		return enums.PaymentMethodDigitalWallet, nil
	case "coupon":
		return enums.PaymentMethodCoupon, nil
	default:
		return enums.PaymentMethodOther, nil
	}
}

// updateCustomerSpent adjusts customer metrics after a return (existing helper)
func (s *salesAnalyticsService) updateCustomerSpent(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID, delta decimal.Decimal) error {
	query := `
        UPDATE sales_analytics.customer_metrics
        SET total_spent = total_spent + $3,
            lifetime_value = lifetime_value + $3,
            average_order_value = CASE WHEN total_orders > 0 THEN (total_spent + $3) / total_orders ELSE 0 END,
            updated_at = NOW()
        WHERE company_id = $1 AND customer_id = $2
    `
	_, err := tx.ExecContext(ctx, query, companyID, customerID, delta)
	return err
}

// onAutomaticDiscountApplied updates automatic_discount_metrics table.
func (s *salesAnalyticsService) onAutomaticDiscountApplied(ctx context.Context, payload struct {
	CompanyID      string `json:"company_id"`
	AutoDiscountID string `json:"auto_discount_id"`
	Amount         string `json:"amount"`
	OrderTotal     string `json:"order_total"`
	EntityID       string `json:"entity_id"`
	CustomerID     string `json:"customer_id"`
	AppliedAt      string `json:"applied_at"`
}) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	autoDiscountID, err := uuid.Parse(payload.AutoDiscountID)
	if err != nil {
		return fmt.Errorf("invalid auto_discount_id: %w", err)
	}
	customerID, err := uuid.Parse(payload.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	discountAmount, err := decimal.NewFromString(payload.Amount)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	orderTotal, err := decimal.NewFromString(payload.OrderTotal)
	if err != nil {
		return fmt.Errorf("invalid order_total: %w", err)
	}

	var date time.Time
	if payload.AppliedAt != "" {
		date, err = time.Parse(time.RFC3339, payload.AppliedAt)
		if err != nil {
			date = time.Now()
		}
	} else {
		date = time.Now()
	}
	date = date.Truncate(24 * time.Hour) // use only date part

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.IncrementAutomaticDiscountMetrics(ctx, tx, companyID, autoDiscountID, date, discountAmount, orderTotal, customerID); err != nil {
		return fmt.Errorf("update automatic discount metrics: %w", err)
	}
	return tx.Commit()
}

// onStackingRuleUsed updates discount_stacking_usage table.
func (s *salesAnalyticsService) onStackingRuleUsed(ctx context.Context, payload struct {
	CompanyID        string `json:"company_id"`
	RuleID           string `json:"rule_id"`
	CombinedDiscount string `json:"combined_discount"`
	Date             string `json:"date"`
}) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	ruleID, err := uuid.Parse(payload.RuleID)
	if err != nil {
		return fmt.Errorf("invalid rule_id: %w", err)
	}
	combinedDiscount, err := decimal.NewFromString(payload.CombinedDiscount)
	if err != nil {
		return fmt.Errorf("invalid combined_discount: %w", err)
	}

	var date time.Time
	if payload.Date != "" {
		date, err = time.Parse(time.RFC3339, payload.Date)
		if err != nil {
			date = time.Now()
		}
	} else {
		date = time.Now()
	}
	date = date.Truncate(24 * time.Hour)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.IncrementStackingRuleUsage(ctx, tx, companyID, ruleID, date, combinedDiscount); err != nil {
		return fmt.Errorf("update stacking rule usage: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onCouponApplied(ctx context.Context, payload salesEvents.CouponAppliedPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	couponID, err := uuid.Parse(payload.CouponID)
	if err != nil {
		return fmt.Errorf("invalid coupon_id: %w", err)
	}
	entityID, err := uuid.Parse(payload.EntityID)
	if err != nil {
		return fmt.Errorf("invalid entity_id: %w", err)
	}
	discountAmount, err := decimal.NewFromString(payload.DiscountAmount)
	if err != nil {
		return fmt.Errorf("invalid discount_amount: %w", err)
	}
	orderSubtotal, err := decimal.NewFromString(payload.OrderSubtotal)
	if err != nil {
		return fmt.Errorf("invalid order_subtotal: %w", err)
	}
	usedAt, err := time.Parse(time.RFC3339, payload.UsedAt)
	if err != nil {
		return fmt.Errorf("invalid used_at: %w", err)
	}

	var customerID *uuid.UUID
	if payload.CustomerID != nil && *payload.CustomerID != "" {
		id, err := uuid.Parse(*payload.CustomerID)
		if err != nil {
			return fmt.Errorf("invalid customer_id: %w", err)
		}
		customerID = &id
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Insert usage fact (idempotent thanks to unique constraint)
	fact := &sales_analytics.CouponUsageFact{
		CompanyID:      companyID,
		CouponID:       couponID,
		EntityType:     payload.EntityType,
		EntityID:       entityID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		OrderSubtotal:  &orderSubtotal,
		UsedAt:         usedAt,
	}
	if err := s.analyticsRepo.RecordCouponUsageFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("record coupon usage fact: %w", err)
	}

	// 2. Update daily metrics (includes unique customer tracking)
	date := usedAt.Truncate(24 * time.Hour)
	if customerID != nil {
		if err := s.analyticsRepo.IncrementCouponDailyMetrics(ctx, tx, companyID, couponID, date, discountAmount, orderSubtotal, *customerID); err != nil {
			return fmt.Errorf("increment daily coupon metrics: %w", err)
		}
	} else {
		// No customer – update without touching unique_customers
		if err := s.incrementDailyCouponMetricsWithoutCustomer(ctx, tx, companyID, couponID, date, discountAmount, orderSubtotal); err != nil {
			return fmt.Errorf("increment daily coupon metrics (no customer): %w", err)
		}
	}

	// 3. Update lifetime performance summary (handles unique customers via bridge)
	if err := s.analyticsRepo.UpdateCouponPerformanceSummary(ctx, tx, companyID, couponID, discountAmount, customerID, usedAt); err != nil {
		return fmt.Errorf("update coupon performance summary: %w", err)
	}

	// 4. Update per-customer usage
	if customerID != nil {
		if err := s.analyticsRepo.UpdateCustomerCouponUsage(ctx, tx, companyID, couponID, *customerID, discountAmount, usedAt); err != nil {
			return fmt.Errorf("update customer coupon usage: %w", err)
		}
	}

	return tx.Commit()
}

// Helper for the rare case when customerID is nil (e.g., anonymous orders)
func (s *salesAnalyticsService) incrementDailyCouponMetricsWithoutCustomer(
	ctx context.Context, tx repository.DBTX,
	companyID, couponID uuid.UUID,
	date time.Time,
	discountAmount, orderSubtotal decimal.Decimal,
) error {
	query := `
        INSERT INTO sales_analytics.daily_coupon_metrics
            (company_id, coupon_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
        VALUES ($1, $2, $3, 1, $4, $5, 0, NOW())
        ON CONFLICT (company_id, coupon_id, date) DO UPDATE SET
            times_applied = daily_coupon_metrics.times_applied + 1,
            total_discount_amount = daily_coupon_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
            total_order_value = daily_coupon_metrics.total_order_value + EXCLUDED.total_order_value,
            updated_at = NOW()
    `
	_, err := tx.ExecContext(ctx, query, companyID, couponID, date, discountAmount, orderSubtotal)
	return err
}

// onPromotionApplied processes promotion application events and updates promotion analytics tables.
func (s *salesAnalyticsService) onPromotionApplied(ctx context.Context, payload struct {
	CompanyID      string `json:"company_id"`
	PromotionID    string `json:"promotion_id"`
	EntityType     string `json:"entity_type"`
	EntityID       string `json:"entity_id"`
	DiscountAmount string `json:"discount_amount"`
	AppliedAt      string `json:"applied_at"`
}) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	promotionID, err := uuid.Parse(payload.PromotionID)
	if err != nil {
		return fmt.Errorf("invalid promotion_id: %w", err)
	}
	entityID, err := uuid.Parse(payload.EntityID)
	if err != nil {
		return fmt.Errorf("invalid entity_id: %w", err)
	}
	discountAmount, err := decimal.NewFromString(payload.DiscountAmount)
	if err != nil {
		return fmt.Errorf("invalid discount_amount: %w", err)
	}
	appliedAt, err := time.Parse(time.RFC3339, payload.AppliedAt)
	if err != nil {
		appliedAt = time.Now()
	}
	date := appliedAt.Truncate(24 * time.Hour)

	// Determine customer ID from the order/invoice if needed
	var customerID *uuid.UUID
	var orderSubtotal *decimal.Decimal

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch customer ID and order subtotal based on entity type
	switch payload.EntityType {
	case "order":
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return fmt.Errorf("get order for promotion usage: %w", err)
		}
		customerID = &order.CustomerID
		orderSubtotal = &order.Subtotal
	case "invoice":
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return fmt.Errorf("get invoice for promotion usage: %w", err)
		}
		customerID = &invoice.CustomerID
		orderSubtotal = &invoice.Subtotal
	default:
		s.logger.Warn("unknown entity type for promotion usage", zap.String("entity_type", payload.EntityType))
		// Proceed without customer info (just log)
	}

	// 1. Record usage fact (idempotent)
	fact := &sales_analytics.PromotionUsageFact{
		CompanyID:      companyID,
		PromotionID:    promotionID,
		EntityType:     payload.EntityType,
		EntityID:       entityID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		OrderSubtotal:  orderSubtotal,
		UsedAt:         appliedAt,
	}
	if err := s.analyticsRepo.RecordPromotionUsageFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("record promotion usage fact: %w", err)
	}

	// 2. Update daily metrics (including unique customers)
	if customerID != nil && orderSubtotal != nil {
		if err := s.analyticsRepo.IncrementPromotionDailyMetrics(ctx, tx, companyID, promotionID, date, discountAmount, *orderSubtotal, *customerID); err != nil {
			return fmt.Errorf("increment promotion daily metrics: %w", err)
		}
	} else {
		// No customer – still update daily metrics but with unique_customers unchanged
		query := `
            INSERT INTO sales_analytics.daily_promotion_metrics
                (company_id, promotion_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
            VALUES ($1, $2, $3, 1, $4, $5, 0, NOW())
            ON CONFLICT (company_id, promotion_id, date) DO UPDATE SET
                times_applied = daily_promotion_metrics.times_applied + 1,
                total_discount_amount = daily_promotion_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
                total_order_value = daily_promotion_metrics.total_order_value + EXCLUDED.total_order_value,
                updated_at = NOW()
        `
		if _, err := tx.ExecContext(ctx, query, companyID, promotionID, date, discountAmount, orderSubtotal); err != nil {
			return fmt.Errorf("update daily promotion metrics (no customer): %w", err)
		}
	}

	// 3. Update overall promotion performance summary
	if err := s.analyticsRepo.UpdatePromotionPerformanceSummary(ctx, tx, companyID, promotionID, discountAmount, customerID, appliedAt); err != nil {
		return fmt.Errorf("update promotion performance summary: %w", err)
	}

	// 4. Update per-customer usage (if customer exists)
	if customerID != nil {
		if err := s.analyticsRepo.UpdateCustomerPromotionUsage(ctx, tx, companyID, promotionID, *customerID, discountAmount, appliedAt); err != nil {
			return fmt.Errorf("update customer promotion usage: %w", err)
		}
	}

	return tx.Commit()
}
