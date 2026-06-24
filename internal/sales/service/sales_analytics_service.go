// file: internal/sales/service/sales_analytics_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/client"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/models/sales_analytics"
	"auth-service/internal/sales/repository"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
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
	case salesEvents.EventPaymentAllocated:
		var pay salesEvents.PaymentPayload
		if err := json.Unmarshal(payload, &pay); err != nil {
			return fmt.Errorf("unmarshal payment allocated payload: %w", err)
		}
		return s.onPaymentAllocated(ctx, pay)
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

	// Sales target events
	case salesEvents.EventSalesTargetSet, salesEvents.EventSalesTargetUpdated:
		var target salesEvents.SalesTargetPayload
		if err := json.Unmarshal(payload, &target); err != nil {
			return fmt.Errorf("unmarshal sales target payload: %w", err)
		}
		return s.onSalesTargetSet(ctx, target)

	case salesEvents.EventSalesTargetDeleted:
		var target salesEvents.SalesTargetPayload
		if err := json.Unmarshal(payload, &target); err != nil {
			return fmt.Errorf("unmarshal sales target payload: %w", err)
		}
		return s.onSalesTargetDeleted(ctx, target)

	// Commission events
	case salesEvents.EventCommissionCreated:
		var commissionPayload salesEvents.CommissionPayload
		if err := json.Unmarshal(payload, &commissionPayload); err != nil {
			return fmt.Errorf("unmarshal commission created payload: %w", err)
		}
		return s.onCommissionCreated(ctx, commissionPayload)

	case salesEvents.EventCommissionApproved:
		var statusPayload salesEvents.CommissionStatusPayload
		if err := json.Unmarshal(payload, &statusPayload); err != nil {
			return fmt.Errorf("unmarshal commission approved payload: %w", err)
		}
		return s.onCommissionStatusChanged(ctx, statusPayload, enums.CommissionStatusApproved)

	case salesEvents.EventCommissionPaid:
		var statusPayload salesEvents.CommissionStatusPayload
		if err := json.Unmarshal(payload, &statusPayload); err != nil {
			return fmt.Errorf("unmarshal commission paid payload: %w", err)
		}
		return s.onCommissionStatusChanged(ctx, statusPayload, enums.CommissionStatusPaid)

	case salesEvents.EventCommissionRejected:
		var statusPayload salesEvents.CommissionStatusPayload
		if err := json.Unmarshal(payload, &statusPayload); err != nil {
			return fmt.Errorf("unmarshal commission rejected payload: %w", err)
		}
		return s.onCommissionStatusChanged(ctx, statusPayload, enums.CommissionStatusRejected)

	case salesEvents.EventCommissionUpdated:
		s.logger.Debug("commission updated event received", zap.String("payload", string(payload)))
		return nil

	case salesEvents.EventCommissionPlanAssigned:
		var assignmentPayload salesEvents.CommissionAssignmentPayload
		if err := json.Unmarshal(payload, &assignmentPayload); err != nil {
			return fmt.Errorf("unmarshal commission assignment payload: %w", err)
		}
		return s.onCommissionPlanAssigned(ctx, assignmentPayload)

	case salesEvents.EventCommissionPlanRemoved:
		var removalPayload salesEvents.CommissionAssignmentPayload
		if err := json.Unmarshal(payload, &removalPayload); err != nil {
			return fmt.Errorf("unmarshal commission removal payload: %w", err)
		}
		return s.onCommissionPlanRemoved(ctx, removalPayload)

	// Credit events (new)
	case salesEvents.EventCustomerCreditLimitChanged:
		return s.onCreditLimitChanged(ctx, payload)
	case salesEvents.EventOrderCreditHeld:
		return s.onOrderCreditHeld(ctx, payload)
	case salesEvents.EventOrderCreditReleased:
		return s.onOrderCreditReleased(ctx, payload)
	case salesEvents.EventCreditCheckFailed:
		return s.onCreditCheckFailed(ctx, payload)

	// Sales rep events (optional, just log)
	case salesEvents.EventSalesRepCreated,
		salesEvents.EventSalesRepActivated,
		salesEvents.EventSalesRepDeactivated,
		salesEvents.EventSalesRepDeleted,
		salesEvents.EventSalesRepAssigned,
		salesEvents.EventSalesRepUnassigned:
		s.logger.Info("sales rep event received", zap.String("event_type", eventType))
		return nil

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
	logger := s.logger.With(
		zap.String("method", "onOrderConfirmed"),
		zap.String("order_id", order.OrderID),
		zap.String("company_id", order.CompanyID),
	)
	logger.Info("processing order confirmed event")

	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		logger.Error("invalid order_id", zap.Error(err))
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		logger.Error("invalid company_id", zap.Error(err))
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(order.CustomerID)
	if err != nil {
		logger.Error("invalid customer_id", zap.Error(err))
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	orderDate, err := time.Parse(time.RFC3339, order.OrderDate)
	if err != nil {
		logger.Error("invalid order_date", zap.Error(err))
		return fmt.Errorf("invalid order_date: %w", err)
	}
	grandTotal, err := decimal.NewFromString(order.GrandTotal)
	if err != nil {
		logger.Error("invalid grand_total", zap.Error(err))
		return fmt.Errorf("invalid grand_total: %w", err)
	}
	logger.Info("parsed order data",
		zap.String("grand_total", grandTotal.String()),
		zap.String("order_date", orderDate.Format("2006-01-02")),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin tx", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Increment daily orders
	if err := s.analyticsRepo.IncrementDailyOrders(ctx, tx, companyID, orderDate, 1); err != nil {
		logger.Error("failed to increment daily orders", zap.Error(err))
		return err
	}
	logger.Info("daily orders incremented", zap.String("date", orderDate.Format("2006-01-02")))

	// Add daily revenue
	if err := s.analyticsRepo.AddDailyRevenue(ctx, tx, companyID, orderDate, grandTotal); err != nil {
		logger.Error("failed to add daily revenue", zap.Error(err))
		return err
	}
	logger.Info("daily revenue added", zap.String("amount", grandTotal.String()))

	// Unique customers
	if err := s.analyticsRepo.IncrementUniqueCustomers(ctx, tx, companyID, orderDate, customerID); err != nil {
		logger.Warn("failed to increment unique customers", zap.Error(err))
	} else {
		logger.Info("unique customer incremented", zap.String("customer_id", customerID.String()))
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
		logger.Warn("failed to update customer metrics", zap.Error(err))
	} else {
		logger.Info("customer metrics updated")
	}

	// Product sales facts
	for _, item := range order.Items {
		productID, err := uuid.Parse(item.ProductID)
		if err != nil {
			logger.Warn("invalid product_id in item", zap.String("product_id", item.ProductID), zap.Error(err))
			continue
		}
		quantity, err := decimal.NewFromString(item.Quantity)
		if err != nil {
			logger.Warn("invalid quantity", zap.String("quantity", item.Quantity), zap.Error(err))
			continue
		}
		unitPrice, err := decimal.NewFromString(item.UnitPrice)
		if err != nil {
			logger.Warn("invalid unit_price", zap.String("unit_price", item.UnitPrice), zap.Error(err))
			continue
		}
		discount, _ := decimal.NewFromString(item.DiscountTotal)
		tax, _ := decimal.NewFromString(item.TaxTotal)
		revenue := quantity.Mul(unitPrice)
		lineAmount := revenue.Sub(discount).Add(tax)

		if err := s.analyticsRepo.AddProductSales(ctx, tx, companyID, productID, orderDate, quantity, revenue, discount); err != nil {
			logger.Error("failed to add product sales", zap.String("product_id", productID.String()), zap.Error(err))
		} else {
			logger.Debug("product sales incremented", zap.String("product_id", productID.String()), zap.String("quantity", quantity.String()), zap.String("revenue", revenue.String()))
		}

		// Insert order item analytics
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
			logger.Error("failed to upsert order item analytics", zap.String("order_item_id", orderItemID.String()), zap.Error(err))
		}
	}

	// Sales rep performance
	if order.SalesRepID != "" {
		salesRepID, err := uuid.Parse(order.SalesRepID)
		if err == nil {
			commissionRate, err := s.getCommissionRate(ctx, tx, companyID, salesRepID, orderDate)
			if err != nil {
				logger.Warn("failed to get commission rate, using 0", zap.Error(err))
				commissionRate = decimal.Zero
			}
			commission := grandTotal.Mul(commissionRate).Div(decimal.NewFromInt(100))
			if err := s.analyticsRepo.IncrementSalesRepPerformance(ctx, tx, companyID, salesRepID, orderDate, grandTotal, commission); err != nil {
				logger.Error("failed to update sales rep performance", zap.Error(err))
			} else {
				logger.Info("sales rep performance updated", zap.String("sales_rep_id", salesRepID.String()))
			}
			if err := s.updateTargetAchievement(ctx, tx, companyID, salesRepID, orderDate, grandTotal); err != nil {
				logger.Warn("failed to update target achievement", zap.Error(err))
			}
			if err := s.recordCommissionFact(ctx, tx, companyID, salesRepID, orderID, grandTotal, commissionRate, commission, orderDate); err != nil {
				logger.Warn("failed to record commission fact", zap.Error(err))
			}
		} else {
			logger.Warn("invalid sales_rep_id in order payload", zap.String("sales_rep_id", order.SalesRepID))
		}
	}

	// Hourly sales
	hourBucket := time.Date(orderDate.Year(), orderDate.Month(), orderDate.Day(), orderDate.Hour(), 0, 0, 0, orderDate.Location())
	if err := s.analyticsRepo.IncrementOrderHourlySales(ctx, tx, companyID, hourBucket, grandTotal, customerID); err != nil {
		logger.Warn("failed to increment hourly sales", zap.Error(err))
	} else {
		logger.Info("hourly sales incremented", zap.String("hour", hourBucket.Format("2006-01-02 15:00")))
	}

	// Fulfillment metrics
	now := time.Now()
	fulfillMetrics := &sales_analytics.FulfillmentMetrics{
		OrderID:     orderID,
		CompanyID:   companyID,
		ConfirmedAt: &now,
	}
	if err := s.analyticsRepo.UpsertFulfillmentMetrics(ctx, tx, fulfillMetrics); err != nil {
		logger.Warn("failed to upsert fulfillment metrics", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit tx", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("order confirmed event processed successfully")
	return nil
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
	logger := s.logger.With(
		zap.String("method", "onOrderCancelled"),
		zap.String("order_id", order.OrderID),
		zap.String("company_id", order.CompanyID),
		zap.String("status_before_cancel", order.StatusBeforeCancel),
	)
	logger.Info("processing order cancelled event")

	orderID, err := uuid.Parse(order.OrderID)
	if err != nil {
		logger.Error("invalid order_id", zap.Error(err))
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(order.CompanyID)
	if err != nil {
		logger.Error("invalid company_id", zap.Error(err))
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(order.CustomerID)
	if err != nil {
		logger.Error("invalid customer_id", zap.Error(err))
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	orderDate, err := time.Parse(time.RFC3339, order.OrderDate)
	if err != nil {
		logger.Error("invalid order_date", zap.Error(err))
		return fmt.Errorf("invalid order_date: %w", err)
	}
	grandTotal, err := decimal.NewFromString(order.GrandTotal)
	if err != nil {
		logger.Error("invalid grand_total", zap.Error(err))
		return fmt.Errorf("invalid grand_total: %w", err)
	}

	statusBefore := enums.OrderStatus(order.StatusBeforeCancel)
	shouldRevert := statusBefore != enums.OrderStatusDraft && statusBefore != ""
	logger.Info("cancellation revert decision", zap.Bool("should_revert", shouldRevert), zap.String("status_before", string(statusBefore)))

	now := time.Now()
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin tx", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Close previous status and record cancelled status
	if statusBefore != "" {
		if err := s.analyticsRepo.CloseOrderStatusHistory(ctx, tx, orderID, statusBefore, now); err != nil {
			logger.Warn("failed to close previous status", zap.String("status", string(statusBefore)), zap.Error(err))
		} else {
			logger.Info("closed previous status history", zap.String("status", string(statusBefore)))
		}
	}
	history := &sales_analytics.OrderStatusHistory{
		OrderID:   orderID,
		CompanyID: companyID,
		Status:    enums.OrderStatusCancelled,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertOrderStatusHistory(ctx, tx, history); err != nil {
		logger.Error("failed to insert cancelled status", zap.Error(err))
		return err
	}
	logger.Info("inserted cancelled status history")

	// Record cancellation reason
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
		logger.Error("failed to insert cancellation reason", zap.Error(err))
	} else {
		logger.Info("cancellation reason recorded")
	}

	if !shouldRevert {
		logger.Info("order was draft or unknown status, no revenue revert needed")
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		return nil
	}

	// --- REVERT COUNTERS ---
	// Decrement daily orders
	if err := s.analyticsRepo.IncrementDailyOrders(ctx, tx, companyID, orderDate, -1); err != nil {
		logger.Error("failed to decrement daily orders", zap.Error(err))
		return err
	}
	logger.Info("daily orders decremented", zap.String("date", orderDate.Format("2006-01-02")))

	// Decrement daily revenue
	if err := s.analyticsRepo.AddDailyRevenue(ctx, tx, companyID, orderDate, grandTotal.Neg()); err != nil {
		logger.Error("failed to decrement daily revenue", zap.Error(err))
		return err
	}
	logger.Info("daily revenue decremented", zap.String("amount", grandTotal.Neg().String()))

	// Unique customers - check if any other orders remain for this customer on the same date
	var otherOrders int
	query := `
		SELECT COUNT(*) FROM sales.orders
		WHERE company_id = $1 AND customer_id = $2 AND order_date = $3
		  AND status NOT IN ('cancelled', 'refunded')
		  AND order_id != $4
	`
	err = tx.QueryRowContext(ctx, query, companyID, customerID, orderDate, orderID).Scan(&otherOrders)
	if err != nil {
		logger.Warn("failed to check other orders for unique customer", zap.Error(err))
	} else {
		if otherOrders == 0 {
			if err := s.analyticsRepo.RemoveUniqueCustomer(ctx, tx, companyID, orderDate, customerID); err != nil {
				logger.Warn("failed to remove unique customer", zap.Error(err))
			} else {
				logger.Info("unique customer removed (no other orders for customer on this date)")
			}
		} else {
			logger.Info("unique customer not removed, other orders exist", zap.Int("other_orders", otherOrders))
		}
	}

	// Update customer metrics (negative)
	metric := &sales_analytics.CustomerMetric{
		CustomerID:    customerID,
		CompanyID:     companyID,
		TotalOrders:   -1,
		TotalSpent:    grandTotal.Neg(),
		LifetimeValue: grandTotal.Neg(),
	}
	if err := s.analyticsRepo.UpdateCustomerMetrics(ctx, tx, metric); err != nil {
		logger.Warn("failed to update customer metrics", zap.Error(err))
	} else {
		logger.Info("customer metrics decremented")
	}

	// Product sales facts (negative)
	for _, item := range order.Items {
		productID, err := uuid.Parse(item.ProductID)
		if err != nil {
			logger.Warn("invalid product_id in order items", zap.String("product_id", item.ProductID), zap.Error(err))
			continue
		}
		quantity, err := decimal.NewFromString(item.Quantity)
		if err != nil {
			logger.Warn("invalid quantity", zap.String("quantity", item.Quantity), zap.Error(err))
			continue
		}
		unitPrice, err := decimal.NewFromString(item.UnitPrice)
		if err != nil {
			logger.Warn("invalid unit_price", zap.String("unit_price", item.UnitPrice), zap.Error(err))
			continue
		}
		discount, _ := decimal.NewFromString(item.DiscountTotal)
		revenue := quantity.Mul(unitPrice)

		if err := s.analyticsRepo.AddProductSales(ctx, tx, companyID, productID, orderDate, quantity.Neg(), revenue.Neg(), discount.Neg()); err != nil {
			logger.Error("failed to revert product sales", zap.String("product_id", productID.String()), zap.Error(err))
		} else {
			logger.Debug("product sales reverted", zap.String("product_id", productID.String()), zap.String("quantity", quantity.Neg().String()))
		}
	}

	// Sales rep performance (negative)
	salesRepID := uuid.Nil
	if order.SalesRepID != "" {
		salesRepID, _ = uuid.Parse(order.SalesRepID)
	}
	if salesRepID != uuid.Nil {
		if err := s.analyticsRepo.DecrementSalesRepPerformance(ctx, tx, companyID, salesRepID, orderDate, grandTotal); err != nil {
			logger.Warn("failed to decrement sales rep performance", zap.Error(err))
		} else {
			logger.Info("sales rep performance decremented", zap.String("sales_rep_id", salesRepID.String()))
		}
		if err := s.analyticsRepo.UpdateSalesRepTargetAchievement(ctx, tx, companyID, salesRepID, orderDate, orderDate, grandTotal.Neg()); err != nil {
			logger.Warn("failed to decrement target achievement", zap.Error(err))
		}
	}

	// Hourly sales (negative)
	hourBucket := time.Date(orderDate.Year(), orderDate.Month(), orderDate.Day(), orderDate.Hour(), 0, 0, 0, orderDate.Location())
	if err := s.analyticsRepo.DecrementOrderHourlySales(ctx, tx, companyID, hourBucket, grandTotal); err != nil {
		logger.Warn("failed to decrement hourly sales", zap.Error(err))
	} else {
		logger.Info("hourly sales decremented", zap.String("hour", hourBucket.Format("2006-01-02 15:00")))
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit tx", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("order cancelled event processed with full revert")
	return nil
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
		paymentMethod = enums.PaymentMethodOther
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.AddDailyPayments(ctx, tx, companyID, paymentDate, amount); err != nil {
		return err
	}
	if err := s.analyticsRepo.IncrementPaymentMethodDaily(ctx, tx, companyID, paymentDate, paymentMethod, amount); err != nil {
		s.logger.Error("failed to update payment method daily", zap.Error(err))
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onPaymentRefunded(ctx context.Context, pay salesEvents.PaymentPayload, isFullRefund bool) error {
	companyID, err := uuid.Parse(pay.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
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

	if err := s.analyticsRepo.IncrementRefundMetrics(ctx, tx, companyID, refundDate, refundAmount, isFullRefund); err != nil {
		return fmt.Errorf("failed to update refund metrics: %w", err)
	}

	if pay.RefundID != "" {
		refundID, err := uuid.Parse(pay.RefundID)
		if err == nil {
			var returnID uuid.UUID
			query := `SELECT return_id FROM sales.payment_refunds WHERE refund_id = $1 AND company_id = $2`
			err = tx.QueryRowContext(ctx, query, refundID, companyID).Scan(&returnID)
			if err == nil && returnID != uuid.Nil {
				refundMethod, _ := parsePaymentMethod(pay.PaymentMethod)
				status := "completed"
				if !isFullRefund {
					status = "partial"
				}
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

	if err := s.analyticsRepo.IncrementDailyReturnRequests(ctx, tx, companyID, returnDate); err != nil {
		return fmt.Errorf("increment return requests: %w", err)
	}
	if err := s.analyticsRepo.IncrementDailyReturnUniqueCustomer(ctx, tx, companyID, returnDate, customerID); err != nil {
		s.logger.Warn("failed to increment unique customer for return", zap.Error(err))
	}

	pendingFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusPending,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, pendingFact); err != nil {
		return fmt.Errorf("insert pending processing time: %w", err)
	}

	items, err := s.returnRepo.GetItems(ctx, tx, companyID, returnID)
	if err != nil {
		return fmt.Errorf("get return items: %w", err)
	}

	for _, it := range items {
		reasonFact := &sales_analytics.ReturnReasonFact{
			CompanyID:        companyID,
			ReturnID:         returnID,
			ReturnItemID:     it.ReturnItemID,
			ReasonCode:       nil,
			ReasonText:       it.Reason,
			ProductID:        &it.ProductID,
			QuantityReturned: it.Quantity,
			RefundAmount:     it.RefundAmount,
			ReturnDate:       returnDate,
		}
		if err := s.analyticsRepo.InsertReturnReasonFact(ctx, tx, reasonFact); err != nil {
			s.logger.Error("failed to insert return reason fact", zap.Error(err))
		}

		_, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			s.logger.Warn("product not found for category aggregation", zap.String("product_id", it.ProductID.String()), zap.Error(err))
			continue
		}
		var categoryID *uuid.UUID
		var categoryName *string
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

	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusPending, approvalDate); err != nil {
		s.logger.Warn("failed to close pending processing time", zap.Error(err))
	}
	approvedFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusApproved,
		EnteredAt: approvalDate,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, approvedFact); err != nil {
		return fmt.Errorf("insert approved processing time: %w", err)
	}

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

	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusPending, rejectionDate); err != nil {
		s.logger.Warn("failed to close pending processing time", zap.Error(err))
	}
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

	if err := s.analyticsRepo.CloseReturnProcessingTime(ctx, tx, returnID, enums.ReturnStatusApproved, completionDate); err != nil {
		s.logger.Warn("failed to close approved processing time", zap.Error(err))
	}
	completedFact := &sales_analytics.ReturnProcessingTimeFact{
		CompanyID: companyID,
		ReturnID:  returnID,
		Status:    enums.ReturnStatusCompleted,
		EnteredAt: completionDate,
	}
	if err := s.analyticsRepo.InsertReturnProcessingTime(ctx, tx, completedFact); err != nil {
		return fmt.Errorf("insert completed processing time: %w", err)
	}

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

	if err := s.analyticsRepo.IncrementDailyReturnCompletions(ctx, tx, companyID, ret.ReturnDate, totalRefund, creditNoteAmount); err != nil {
		return fmt.Errorf("increment daily return completions: %w", err)
	}
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

	if err := s.analyticsRepo.CloseInvoiceStatusHistory(ctx, tx, invoiceID, enums.InvoiceStatusDraft, now); err != nil {
		s.logger.Warn("failed to close draft invoice status", zap.Error(err))
	}
	history := &sales_analytics.InvoiceStatusHistory{
		InvoiceID: invoiceID,
		CompanyID: companyID,
		Status:    enums.InvoiceStatusIssued,
		EnteredAt: now,
	}
	if err := s.analyticsRepo.InsertInvoiceStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert issued status: %w", err)
	}
	if err := s.analyticsRepo.IncrementDailyInvoiceIssued(ctx, tx, companyID, invoiceDate, grandTotal); err != nil {
		return err
	}

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

	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, now); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after issuance", zap.Error(err))
	}
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
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
		if err != nil {
			s.logger.Error("failed to fetch invoice for payment", zap.Error(err))
			continue
		}

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

		daysToPay := int(paymentDate.Sub(invoice.InvoiceDate).Hours() / 24)
		amount, _ := decimal.NewFromString(alloc.Amount)
		if err := s.analyticsRepo.IncrementDailyInvoicePaid(ctx, tx, companyID, paymentDate, amount, &daysToPay); err != nil {
			s.logger.Error("failed to update daily paid metrics", zap.Error(err))
		}
		if alloc.IsEarlyDiscount && alloc.DiscountAmount != "" {
			discountAmt, _ := decimal.NewFromString(alloc.DiscountAmount)
			if err := s.analyticsRepo.RecordEarlyDiscount(ctx, tx, companyID, paymentDate, discountAmt); err != nil {
				s.logger.Error("failed to record early discount", zap.Error(err))
			}
		}
	}
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, paymentDate); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after payment", zap.Error(err))
	}
	return tx.Commit()
}

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
	if err := s.analyticsRepo.IncrementDailyInvoiceOverdue(ctx, tx, companyID, overdueDate, grandTotal); err != nil {
		return err
	}
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, overdueDate); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after overdue", zap.Error(err))
	}
	return tx.Commit()
}

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
	if err := s.analyticsRepo.IncrementDailyInvoiceCancelled(ctx, tx, companyID, cancelledAt); err != nil {
		return err
	}
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, cancelledAt); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after cancellation", zap.Error(err))
	}
	return tx.Commit()
}

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
	if err := s.analyticsRepo.RefreshInvoiceAgingSnapshot(ctx, tx, companyID, creditedAt); err != nil {
		s.logger.Warn("failed to refresh aging snapshot after credit", zap.Error(err))
	}

	var returnID *uuid.UUID
	query := `SELECT return_id FROM sales.returns WHERE credit_note_id = $1 AND company_id = $2`
	err = tx.QueryRowContext(ctx, query, invoiceID, companyID).Scan(&returnID)
	if err == nil && returnID != nil {
		fact := &sales_analytics.CreditNoteFact{
			CompanyID:     companyID,
			CreditNoteID:  invoiceID,
			ReturnID:      returnID,
			IssuedDate:    invoice.InvoiceDate,
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

	history := &sales_analytics.QuoteStatusHistory{
		QuoteID:   quoteID,
		CompanyID: companyID,
		Status:    enums.QuoteStatusDraft,
		EnteredAt: time.Now(),
	}
	if err := s.analyticsRepo.InsertQuoteStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert quote status history: %w", err)
	}
	if err := s.analyticsRepo.IncrementDailyQuoteCreated(ctx, tx, companyID, quoteDate, grandTotal); err != nil {
		return err
	}

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

	if err := s.analyticsRepo.CloseQuoteStatusHistory(ctx, tx, quoteID, previousStatus, now); err != nil {
		s.logger.Warn("failed to close previous quote status", zap.String("previous", string(previousStatus)), zap.Error(err))
	}
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

	if quote.ConvertedOrderID == "" {
		s.logger.Warn("quote converted event missing converted_order_id", zap.String("quote_id", quote.QuoteID))
		return nil
	}
	orderID, err := uuid.Parse(quote.ConvertedOrderID)
	if err != nil {
		return fmt.Errorf("invalid converted_order_id: %w", err)
	}

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
	orderValue := quoteValue

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseQuoteStatusHistory(ctx, tx, quoteID, enums.QuoteStatusAccepted, convertedAt); err != nil {
		s.logger.Warn("failed to close accepted status", zap.Error(err))
	}
	history := &sales_analytics.QuoteStatusHistory{
		QuoteID:   quoteID,
		CompanyID: companyID,
		Status:    enums.QuoteStatusConverted,
		EnteredAt: convertedAt,
	}
	if err := s.analyticsRepo.InsertQuoteStatusHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("insert converted status: %w", err)
	}

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
	if err := s.analyticsRepo.IncrementDailyQuoteConverted(ctx, tx, companyID, convertedAt, orderValue); err != nil {
		return err
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Sales Target Handlers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) onSalesTargetSet(ctx context.Context, payload salesEvents.SalesTargetPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	salesRepID, err := uuid.Parse(payload.SalesRepID)
	if err != nil {
		return fmt.Errorf("invalid sales_rep_id: %w", err)
	}
	periodStart, err := time.Parse(time.RFC3339, payload.PeriodStart)
	if err != nil {
		return fmt.Errorf("invalid period_start: %w", err)
	}
	periodEnd, err := time.Parse(time.RFC3339, payload.PeriodEnd)
	if err != nil {
		return fmt.Errorf("invalid period_end: %w", err)
	}
	targetAmount, err := decimal.NewFromString(payload.TargetAmount)
	if err != nil {
		return fmt.Errorf("invalid target_amount: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	achievement := &sales_analytics.SalesRepTargetAchievement{
		CompanyID:     companyID,
		SalesRepID:    salesRepID,
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		TargetAmount:  targetAmount,
		ActualRevenue: decimal.Zero,
		Currency:      payload.Currency,
	}
	if err := s.analyticsRepo.UpsertSalesRepTargetAchievement(ctx, tx, achievement); err != nil {
		return fmt.Errorf("upsert target achievement: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onSalesTargetDeleted(ctx context.Context, payload salesEvents.SalesTargetPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	salesRepID, err := uuid.Parse(payload.SalesRepID)
	if err != nil {
		return fmt.Errorf("invalid sales_rep_id: %w", err)
	}
	periodStart, err := time.Parse(time.RFC3339, payload.PeriodStart)
	if err != nil {
		return fmt.Errorf("invalid period_start: %w", err)
	}
	periodEnd, err := time.Parse(time.RFC3339, payload.PeriodEnd)
	if err != nil {
		return fmt.Errorf("invalid period_end: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	updateQuery := `
		UPDATE sales_analytics.sales_rep_target_achievement
		SET target_amount = 0, updated_at = NOW()
		WHERE company_id = $1 AND sales_rep_id = $2 AND period_start = $3 AND period_end = $4
	`
	_, err = tx.ExecContext(ctx, updateQuery, companyID, salesRepID, periodStart, periodEnd)
	if err != nil {
		return fmt.Errorf("delete target achievement (set 0): %w", err)
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Sales Rep Target & Commission Helpers (called from onOrderConfirmed)
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) updateTargetAchievement(ctx context.Context, tx repository.DBTX, companyID, salesRepID uuid.UUID, orderDate time.Time, revenue decimal.Decimal) error {
	query := `
		SELECT period_start, period_end
		FROM sales.sales_targets
		WHERE company_id = $1 AND sales_rep_id = $2
		  AND period_start <= $3 AND period_end >= $3
	`
	var periodStart, periodEnd time.Time
	err := tx.QueryRowContext(ctx, query, companyID, salesRepID, orderDate).Scan(&periodStart, &periodEnd)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("find target period: %w", err)
	}

	if err := s.analyticsRepo.UpdateSalesRepTargetAchievement(ctx, tx, companyID, salesRepID, periodStart, periodEnd, revenue); err != nil {
		return fmt.Errorf("update target achievement: %w", err)
	}
	return nil
}

func (s *salesAnalyticsService) recordCommissionFact(ctx context.Context, tx repository.DBTX, companyID, salesRepID, orderID uuid.UUID, orderTotal, commissionRate, commissionAmount decimal.Decimal, earnedAt time.Time) error {
	fact := &sales_analytics.SalesRepCommissionFact{
		CompanyID:        companyID,
		SalesRepID:       salesRepID,
		EntityType:       "order",
		EntityID:         orderID,
		CommissionBase:   orderTotal,
		CommissionRate:   commissionRate,
		CommissionAmount: commissionAmount,
		EarnedAt:         earnedAt,
		PaidAt:           nil,
	}
	if err := s.analyticsRepo.UpsertSalesRepCommissionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("upsert commission fact: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Commission Event Handlers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) onCommissionCreated(ctx context.Context, payload salesEvents.CommissionPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	salesRepID, err := uuid.Parse(payload.SalesRepID)
	if err != nil {
		return fmt.Errorf("invalid sales_rep_id: %w", err)
	}
	commissionID, err := uuid.Parse(payload.CommissionID)
	if err != nil {
		return fmt.Errorf("invalid commission_id: %w", err)
	}
	referenceID, err := uuid.Parse(payload.ReferenceID)
	if err != nil {
		return fmt.Errorf("invalid reference_id: %w", err)
	}
	earnedAt, err := time.Parse(time.RFC3339, payload.EarnedAt)
	if err != nil {
		return fmt.Errorf("invalid earned_at: %w", err)
	}
	commissionBase, err := decimal.NewFromString(payload.CommissionBase)
	if err != nil {
		return fmt.Errorf("invalid commission_base: %w", err)
	}
	commissionRate, err := decimal.NewFromString(payload.CommissionRate)
	if err != nil {
		return fmt.Errorf("invalid commission_rate: %w", err)
	}
	commissionAmount, err := decimal.NewFromString(payload.CommissionAmount)
	if err != nil {
		return fmt.Errorf("invalid commission_amount: %w", err)
	}

	var planID *uuid.UUID
	if payload.PlanID != "" {
		if id, err := uuid.Parse(payload.PlanID); err == nil {
			planID = &id
		}
	}
	var ruleID *uuid.UUID
	if payload.RuleID != "" {
		if id, err := uuid.Parse(payload.RuleID); err == nil {
			ruleID = &id
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fact := &sales_analytics.SalesRepCommissionFact{
		CompanyID:        companyID,
		SalesRepID:       salesRepID,
		EntityType:       payload.ReferenceType,
		EntityID:         referenceID,
		CommissionBase:   commissionBase,
		CommissionRate:   commissionRate,
		CommissionAmount: commissionAmount,
		EarnedAt:         earnedAt,
		PaidAt:           nil,
		PlanID:           planID,
		RuleID:           ruleID,
	}
	if err := s.analyticsRepo.UpsertSalesRepCommissionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("upsert commission fact: %w", err)
	}

	if planID != nil {
		date := earnedAt.Truncate(24 * time.Hour)
		if err := s.analyticsRepo.IncrementCommissionPlanDaily(ctx, tx, companyID, *planID, date,
			commissionAmount, decimal.Zero, commissionRate, salesRepID); err != nil {
			s.logger.Warn("failed to increment commission plan daily", zap.Error(err))
		}
	}

	if ruleID != nil && planID != nil {
		date := earnedAt.Truncate(24 * time.Hour)
		if err := s.analyticsRepo.IncrementCommissionRuleFact(ctx, tx, companyID, *ruleID, *planID, date,
			commissionBase, commissionAmount, commissionRate); err != nil {
			s.logger.Warn("failed to increment commission rule fact", zap.Error(err))
		}
	}

	lifecycle := &sales_analytics.CommissionLifecycle{
		CommissionID:  commissionID,
		CompanyID:     companyID,
		SalesRepID:    salesRepID,
		ReferenceType: payload.ReferenceType,
		ReferenceID:   referenceID,
		EarnedAt:      earnedAt,
		CurrentStatus: payload.Status,
	}
	if err := s.analyticsRepo.InsertCommissionLifecycle(ctx, tx, lifecycle); err != nil {
		return fmt.Errorf("insert commission lifecycle: %w", err)
	}

	return tx.Commit()
}

func (s *salesAnalyticsService) onCommissionStatusChanged(ctx context.Context, payload salesEvents.CommissionStatusPayload, newStatus enums.CommissionStatus) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	commissionID, err := uuid.Parse(payload.CommissionID)
	if err != nil {
		return fmt.Errorf("invalid commission_id: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339, payload.UpdatedAt)
	if err != nil {
		updatedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var planID *uuid.UUID
	var commissionAmount decimal.Decimal
	var earnedAt time.Time
	if newStatus == enums.CommissionStatusPaid {
		var planIDStr *string
		var amountStr string
		var earnedAtStr time.Time
		query := `SELECT plan_id, commission_amount, earned_at FROM sales_analytics.commission_lifecycle WHERE commission_id = $1 AND company_id = $2`
		err := tx.QueryRowContext(ctx, query, commissionID, companyID).Scan(&planIDStr, &amountStr, &earnedAtStr)
		if err == nil && planIDStr != nil {
			if id, err := uuid.Parse(*planIDStr); err == nil {
				planID = &id
			}
			commissionAmount, _ = decimal.NewFromString(amountStr)
			earnedAt = earnedAtStr
		}
	}

	var approvedAt, paidAt, rejectedAt *time.Time
	switch newStatus {
	case enums.CommissionStatusApproved:
		approvedAt = &updatedAt
	case enums.CommissionStatusPaid:
		paidAt = &updatedAt
	case enums.CommissionStatusRejected:
		rejectedAt = &updatedAt
	}
	if err := s.analyticsRepo.UpdateCommissionLifecycle(ctx, tx, commissionID, string(newStatus), approvedAt, paidAt, rejectedAt); err != nil {
		return fmt.Errorf("update commission lifecycle: %w", err)
	}

	if newStatus == enums.CommissionStatusPaid && planID != nil {
		date := earnedAt.Truncate(24 * time.Hour)
		if err := s.analyticsRepo.IncrementCommissionPlanDaily(ctx, tx, companyID, *planID, date,
			decimal.Zero, commissionAmount, decimal.Zero, uuid.Nil); err != nil {
			s.logger.Warn("failed to increment paid amount in commission plan daily", zap.Error(err))
		}
	}

	return tx.Commit()
}

func (s *salesAnalyticsService) onCommissionPlanAssigned(ctx context.Context, payload salesEvents.CommissionAssignmentPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	salesRepID, err := uuid.Parse(payload.SalesRepID)
	if err != nil {
		return fmt.Errorf("invalid sales_rep_id: %w", err)
	}
	planID, err := uuid.Parse(payload.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	effectiveFrom, err := time.Parse(time.RFC3339, payload.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("invalid effective_from: %w", err)
	}
	var assignedBy *uuid.UUID
	if payload.AssignedBy != "" {
		if id, err := uuid.Parse(payload.AssignedBy); err == nil {
			assignedBy = &id
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	assignment := &sales_analytics.CommissionAssignmentFact{
		CompanyID:  companyID,
		SalesRepID: salesRepID,
		PlanID:     planID,
		AssignedAt: effectiveFrom,
		AssignedBy: assignedBy,
	}
	if err := s.analyticsRepo.InsertCommissionAssignmentFact(ctx, tx, assignment); err != nil {
		return fmt.Errorf("insert commission assignment fact: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onCommissionPlanRemoved(ctx context.Context, payload salesEvents.CommissionAssignmentPayload) error {
	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	salesRepID, err := uuid.Parse(payload.SalesRepID)
	if err != nil {
		return fmt.Errorf("invalid sales_rep_id: %w", err)
	}
	planID, err := uuid.Parse(payload.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	removedAt, err := time.Parse(time.RFC3339, payload.RemovedAt)
	if err != nil {
		removedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseCommissionAssignmentFact(ctx, tx, companyID, salesRepID, planID, removedAt); err != nil {
		return fmt.Errorf("close commission assignment fact: %w", err)
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Promotion and Discount Handlers
// ----------------------------------------------------------------------------

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
	date = date.Truncate(24 * time.Hour)

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

	date := usedAt.Truncate(24 * time.Hour)
	if customerID != nil {
		if err := s.analyticsRepo.IncrementCouponDailyMetrics(ctx, tx, companyID, couponID, date, discountAmount, orderSubtotal, *customerID); err != nil {
			return fmt.Errorf("increment daily coupon metrics: %w", err)
		}
	} else {
		if err := s.incrementDailyCouponMetricsWithoutCustomer(ctx, tx, companyID, couponID, date, discountAmount, orderSubtotal); err != nil {
			return fmt.Errorf("increment daily coupon metrics (no customer): %w", err)
		}
	}

	if err := s.analyticsRepo.UpdateCouponPerformanceSummary(ctx, tx, companyID, couponID, discountAmount, customerID, usedAt); err != nil {
		return fmt.Errorf("update coupon performance summary: %w", err)
	}
	if customerID != nil {
		if err := s.analyticsRepo.UpdateCustomerCouponUsage(ctx, tx, companyID, couponID, *customerID, discountAmount, usedAt); err != nil {
			return fmt.Errorf("update customer coupon usage: %w", err)
		}
	}
	return tx.Commit()
}

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

	var customerID *uuid.UUID
	var orderSubtotal *decimal.Decimal

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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
	}

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

	if customerID != nil && orderSubtotal != nil {
		if err := s.analyticsRepo.IncrementPromotionDailyMetrics(ctx, tx, companyID, promotionID, date, discountAmount, *orderSubtotal, *customerID); err != nil {
			return fmt.Errorf("increment promotion daily metrics: %w", err)
		}
	} else {
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

	if err := s.analyticsRepo.UpdatePromotionPerformanceSummary(ctx, tx, companyID, promotionID, discountAmount, customerID, appliedAt); err != nil {
		return fmt.Errorf("update promotion performance summary: %w", err)
	}
	if customerID != nil {
		if err := s.analyticsRepo.UpdateCustomerPromotionUsage(ctx, tx, companyID, promotionID, *customerID, discountAmount, appliedAt); err != nil {
			return fmt.Errorf("update customer promotion usage: %w", err)
		}
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Credit Event Handlers
// ----------------------------------------------------------------------------

func (s *salesAnalyticsService) onCreditLimitChanged(ctx context.Context, payload []byte) error {
	var data struct {
		CustomerID    string `json:"customer_id"`
		CompanyID     string `json:"company_id"`
		PreviousLimit string `json:"previous_limit"`
		NewLimit      string `json:"new_limit"`
		UpdatedBy     string `json:"updated_by"`
		UpdatedAt     string `json:"updated_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal credit limit changed payload: %w", err)
	}

	companyID, err := uuid.Parse(data.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(data.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	prevLimit, err := decimal.NewFromString(data.PreviousLimit)
	if err != nil {
		return fmt.Errorf("invalid previous_limit: %w", err)
	}
	newLimit, err := decimal.NewFromString(data.NewLimit)
	if err != nil {
		return fmt.Errorf("invalid new_limit: %w", err)
	}
	changedAt, err := time.Parse(time.RFC3339, data.UpdatedAt)
	if err != nil {
		changedAt = time.Now()
	}
	var changedBy *uuid.UUID
	if data.UpdatedBy != "" {
		if id, err := uuid.Parse(data.UpdatedBy); err == nil {
			changedBy = &id
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fact := &sales_analytics.CreditLimitChangeFact{
		CompanyID:     companyID,
		CustomerID:    customerID,
		PreviousLimit: prevLimit,
		NewLimit:      newLimit,
		ChangeReason:  nil,
		ChangedBy:     changedBy,
		ChangedAt:     changedAt,
	}
	if err := s.analyticsRepo.InsertCreditLimitChangeFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert credit limit change fact: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderCreditHeld(ctx context.Context, payload []byte) error {
	var data struct {
		OrderID    string `json:"order_id"`
		CompanyID  string `json:"company_id"`
		CustomerID string `json:"customer_id"`
		Reason     string `json:"reason"`
		HeldBy     string `json:"held_by"`
		HeldAt     string `json:"held_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal order credit held payload: %w", err)
	}

	orderID, err := uuid.Parse(data.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	companyID, err := uuid.Parse(data.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(data.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	heldAt, err := time.Parse(time.RFC3339, data.HeldAt)
	if err != nil {
		heldAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	holdFact := &sales_analytics.CreditHoldFact{
		OrderID:       orderID,
		CompanyID:     companyID,
		CustomerID:    customerID,
		HoldStartedAt: heldAt,
		Reason:        &data.Reason,
	}
	if err := s.analyticsRepo.InsertCreditHoldFact(ctx, tx, holdFact); err != nil {
		return fmt.Errorf("insert credit hold fact: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onOrderCreditReleased(ctx context.Context, payload []byte) error {
	var data struct {
		OrderID    string `json:"order_id"`
		CompanyID  string `json:"company_id"`
		CustomerID string `json:"customer_id"`
		Reason     string `json:"reason"`
		ReleasedBy string `json:"released_by"`
		ReleasedAt string `json:"released_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal order credit released payload: %w", err)
	}

	orderID, err := uuid.Parse(data.OrderID)
	if err != nil {
		return fmt.Errorf("invalid order_id: %w", err)
	}
	releasedAt, err := time.Parse(time.RFC3339, data.ReleasedAt)
	if err != nil {
		releasedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.analyticsRepo.CloseCreditHoldFact(ctx, tx, orderID, releasedAt); err != nil {
		return fmt.Errorf("close credit hold fact: %w", err)
	}
	return tx.Commit()
}

func (s *salesAnalyticsService) onCreditCheckFailed(ctx context.Context, payload []byte) error {
	var data struct {
		CheckID            string `json:"check_id"`
		CompanyID          string `json:"company_id"`
		CustomerID         string `json:"customer_id"`
		CheckType          string `json:"check_type"`
		RequestedAmount    string `json:"requested_amount"`
		CurrentLimit       string `json:"current_limit"`
		CurrentOutstanding string `json:"current_outstanding"`
		AvailableCredit    string `json:"available_credit"`
		Reason             string `json:"reason"`
		CheckedAt          string `json:"checked_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal credit check failed payload: %w", err)
	}

	companyID, err := uuid.Parse(data.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	customerID, err := uuid.Parse(data.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	var checkID *uuid.UUID
	if data.CheckID != "" {
		if id, err := uuid.Parse(data.CheckID); err == nil {
			checkID = &id
		}
	}
	requestedAmount, err := decimal.NewFromString(data.RequestedAmount)
	if err != nil {
		return fmt.Errorf("invalid requested_amount: %w", err)
	}
	currentLimit, err := decimal.NewFromString(data.CurrentLimit)
	if err != nil {
		return fmt.Errorf("invalid current_limit: %w", err)
	}
	currentOutstanding, err := decimal.NewFromString(data.CurrentOutstanding)
	if err != nil {
		return fmt.Errorf("invalid current_outstanding: %w", err)
	}
	availableCredit, err := decimal.NewFromString(data.AvailableCredit)
	if err != nil {
		return fmt.Errorf("invalid available_credit: %w", err)
	}
	checkedAt, err := time.Parse(time.RFC3339, data.CheckedAt)
	if err != nil {
		checkedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fact := &sales_analytics.CreditCheckFact{
		CompanyID:          companyID,
		CustomerID:         customerID,
		CheckID:            checkID,
		CheckType:          data.CheckType,
		Result:             "denied",
		RequestedAmount:    requestedAmount,
		CurrentLimit:       currentLimit,
		CurrentOutstanding: currentOutstanding,
		AvailableCredit:    availableCredit,
		Reason:             &data.Reason,
		CheckedAt:          checkedAt,
	}
	if err := s.analyticsRepo.InsertCreditCheckFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert credit check fact: %w", err)
	}

	// Update daily credit metrics
	utilizationPct := decimal.Zero
	if currentLimit.GreaterThan(decimal.Zero) {
		utilizationPct = currentOutstanding.Div(currentLimit).Mul(decimal.NewFromInt(100))
	}
	if err := s.analyticsRepo.IncrementDailyCreditMetrics(ctx, tx, companyID, checkedAt.Truncate(24*time.Hour),
		false, requestedAmount, data.CheckType, availableCredit, utilizationPct); err != nil {
		s.logger.Warn("failed to increment daily credit metrics", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

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

// onPaymentAllocated processes payment allocation events for analytics.
// It records the allocation amount and timing, which can be used to measure
// how quickly payments are applied to invoices after creation.
func (s *salesAnalyticsService) onPaymentAllocated(ctx context.Context, pay salesEvents.PaymentPayload) error {
	if len(pay.Allocations) == 0 {
		return nil
	}

	companyID, err := uuid.Parse(pay.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}

	paymentID, err := uuid.Parse(pay.PaymentID)
	if err != nil {
		return fmt.Errorf("invalid payment_id: %w", err)
	}

	paymentDate, err := time.Parse(time.RFC3339, pay.PaymentDate)
	if err != nil {
		paymentDate = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// For each allocation, record the allocation fact.
	for _, alloc := range pay.Allocations {
		invoiceID, err := uuid.Parse(alloc.InvoiceID)
		if err != nil {
			s.logger.Warn("invalid invoice_id in allocation", zap.String("invoice_id", alloc.InvoiceID), zap.Error(err))
			continue
		}

		amount, err := decimal.NewFromString(alloc.Amount)
		if err != nil {
			s.logger.Warn("invalid amount in allocation", zap.String("amount", alloc.Amount), zap.Error(err))
			continue
		}

		// Check if this invoice already has an allocation from this payment
		// (idempotency is handled by the event source, but we can upsert)
		fact := &sales_analytics.PaymentAllocationFact{
			CompanyID:       companyID,
			PaymentID:       paymentID,
			InvoiceID:       invoiceID,
			AllocatedAmount: amount,
			AllocatedAt:     time.Now(), // or use event timestamp? PaymentPayload doesn't have one.
		}
		// The PaymentPayload doesn't contain the allocation timestamp,
		// so we use current time. Alternatively, you could add an `allocated_at` field to the event.
		if err := s.analyticsRepo.UpsertPaymentAllocationFact(ctx, tx, fact); err != nil {
			s.logger.Error("failed to upsert payment allocation fact", zap.Error(err))
			continue
		}

		// Optionally, update daily metrics: total allocated amount per day.
		date := paymentDate.Truncate(24 * time.Hour)
		if err := s.analyticsRepo.IncrementDailyAllocatedAmount(ctx, tx, companyID, date, amount); err != nil {
			s.logger.Warn("failed to increment daily allocated amount", zap.Error(err))
		}
	}

	return tx.Commit()
}
