// file: internal/sales/repository/analytics_repository.go
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

	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/models/sales_analytics"
)

// AnalyticsRepository defines all methods for updating analytics aggregates
// including the new order service tables.
type AnalyticsRepository interface {
	// ==================== Existing methods (unchanged) ====================
	// DailySales
	UpsertDailySales(ctx context.Context, db DBTX, daily *sales_analytics.DailySales) error
	IncrementDailyOrders(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, delta int) error
	AddDailyRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	AddDailyPayments(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	AddDailyDiscounts(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	AddDailyTax(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	IncrementUniqueCustomers(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error
	UpsertPaymentMethodDaily(ctx context.Context, db DBTX, record *sales_analytics.PaymentMethodDaily) error
	IncrementPaymentMethodDaily(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, method enums.PaymentMethod, amount decimal.Decimal) error
	// UpsertPaymentAllocationFact inserts or updates a record of payment allocation to an invoice.
	UpsertPaymentAllocationFact(ctx context.Context, tx DBTX, fact *sales_analytics.PaymentAllocationFact) error

	// IncrementDailyAllocatedAmount updates the total amount allocated on a given day.
	IncrementDailyAllocatedAmount(ctx context.Context, tx DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	UpsertRefundMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.RefundMetrics) error
	IncrementRefundMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal, isFullRefund bool) error
	// Coupon analytics
	RecordCouponUsageFact(ctx context.Context, db DBTX, fact *sales_analytics.CouponUsageFact) error
	IncrementCouponDailyMetrics(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, date time.Time, discountAmount, orderSubtotal decimal.Decimal, customerID uuid.UUID) error
	UpdateCouponPerformanceSummary(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, discountAmount decimal.Decimal, customerID *uuid.UUID, usedAt time.Time) error
	UpdateCustomerCouponUsage(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	RefreshPaymentAgingSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error
	// Promotion analytics
	RecordPromotionUsageFact(ctx context.Context, db DBTX, fact *sales_analytics.PromotionUsageFact) error
	IncrementPromotionDailyMetrics(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, date time.Time, discountAmount, orderSubtotal decimal.Decimal, customerID uuid.UUID) error
	UpdatePromotionPerformanceSummary(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, discountAmount decimal.Decimal, customerID *uuid.UUID, usedAt time.Time) error
	UpdateCustomerPromotionUsage(ctx context.Context, db DBTX, companyID, promotionID, customerID uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	UpdateCollectionEfficiency(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, dso, collectionRate *decimal.Decimal, receivables, collected decimal.Decimal) error
	// AutomaticDiscountMetrics
	IncrementAutomaticDiscountMetrics(ctx context.Context, db DBTX, companyID, autoDiscountID uuid.UUID, date time.Time, discountAmount, orderAmount decimal.Decimal, customerID uuid.UUID) error

	// StackingRuleUsage
	IncrementStackingRuleUsage(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID, date time.Time, combinedDiscount decimal.Decimal) error

	// DailyUniqueCustomers
	AddUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) (bool, error)
	RemoveUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error
	IsUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) (bool, error)

	// CustomerMetrics
	UpdateCustomerMetrics(ctx context.Context, db DBTX, metric *sales_analytics.CustomerMetric) error
	GetCustomerMetrics(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*sales_analytics.CustomerMetric, error)

	// ProductSalesFact
	UpsertProductSales(ctx context.Context, db DBTX, fact *sales_analytics.ProductSalesFact) error
	AddProductSales(ctx context.Context, db DBTX, companyID, productID uuid.UUID, date time.Time, quantity, revenue, discount decimal.Decimal) error

	// ProductReturnsFact
	UpsertProductReturns(ctx context.Context, db DBTX, fact *sales_analytics.ProductReturnsFact) error
	AddProductReturns(ctx context.Context, db DBTX, companyID, productID uuid.UUID, date time.Time, quantity, refundAmount decimal.Decimal) error

	// PaymentTermPerformance
	UpdatePaymentTermPerformance(ctx context.Context, db DBTX, companyID, termID uuid.UUID, date time.Time, metrics PaymentTermPerformanceUpdate) error
	GetPaymentTermPerformance(ctx context.Context, db DBTX, companyID, termID uuid.UUID, from, to time.Time) ([]*sales_analytics.PaymentTermPerformance, error)
	RecordPaymentTermInvoice(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceDate time.Time, invoiceAmount decimal.Decimal, eligibleForEarlyDisc bool) error
	RecordPaymentTermPayment(ctx context.Context, db DBTX, companyID, termID uuid.UUID, paymentDate time.Time, paidOnTime, paidLate, tookEarlyDiscount bool, earlyDiscountAmount decimal.Decimal, daysToPay int) error

	// ==================== New methods for order analytics ====================

	// OrderStatusHistory
	InsertOrderStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.OrderStatusHistory) error
	CloseOrderStatusHistory(ctx context.Context, db DBTX, orderID uuid.UUID, status enums.OrderStatus, exitedAt time.Time) error
	GetOrderStatusHistory(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*sales_analytics.OrderStatusHistory, error)

	// OrderItemAnalytics
	UpsertOrderItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.OrderItemAnalytics) error
	GetOrderItemAnalyticsByOrder(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*sales_analytics.OrderItemAnalytics, error)

	// SalesRepPerformance
	UpsertSalesRepPerformance(ctx context.Context, db DBTX, perf *sales_analytics.SalesRepPerformance) error
	IncrementSalesRepPerformance(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, date time.Time, orderTotal decimal.Decimal, commission decimal.Decimal) error

	// OrderCancellationReasons
	InsertOrderCancellationReason(ctx context.Context, db DBTX, reason *sales_analytics.OrderCancellationReason) error
	GetCancellationReasons(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*sales_analytics.OrderCancellationReason, error)

	// FulfillmentMetrics
	UpsertFulfillmentMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.FulfillmentMetrics) error
	UpdateFulfillmentShipping(ctx context.Context, db DBTX, orderID uuid.UUID, shippedAt time.Time, carrier, trackingNumber *string, shippingRegion *string) error
	UpdateFulfillmentDelivery(ctx context.Context, db DBTX, orderID uuid.UUID, deliveredAt time.Time) error
	// ==================== New methods for quote analytics ====================

	// DailyQuoteMetrics
	UpsertDailyQuoteMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyQuoteMetrics) error
	IncrementDailyQuoteCreated(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, quoteValue decimal.Decimal) error
	IncrementDailyQuoteConverted(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, convertedValue decimal.Decimal) error

	// QuoteStatusHistory
	InsertQuoteStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.QuoteStatusHistory) error
	CloseQuoteStatusHistory(ctx context.Context, db DBTX, quoteID uuid.UUID, status enums.QuoteStatus, exitedAt time.Time) error
	GetQuoteStatusHistory(ctx context.Context, db DBTX, quoteID uuid.UUID) ([]*sales_analytics.QuoteStatusHistory, error)
	// ==================== New methods for invoice analytics ====================

	// InvoiceStatusHistory
	InsertInvoiceStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.InvoiceStatusHistory) error
	CloseInvoiceStatusHistory(ctx context.Context, db DBTX, invoiceID uuid.UUID, status enums.InvoiceStatus, exitedAt time.Time) error
	GetInvoiceStatusHistory(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*sales_analytics.InvoiceStatusHistory, error)

	// InvoiceItemAnalytics
	UpsertInvoiceItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.InvoiceItemAnalytics) error
	GetInvoiceItemAnalyticsByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*sales_analytics.InvoiceItemAnalytics, error)

	// DailyInvoiceMetrics
	UpsertDailyInvoiceMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyInvoiceMetrics) error
	IncrementDailyInvoiceIssued(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	IncrementDailyInvoicePaid(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal, daysToPay *int) error
	IncrementDailyInvoiceOverdue(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	IncrementDailyInvoiceCancelled(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error
	RecordEarlyDiscount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, discountAmount decimal.Decimal) error

	// InvoiceAgingSnapshot
	UpsertInvoiceAgingSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.InvoiceAgingSnapshot) error
	RefreshInvoiceAgingSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error
	// QuoteConversionFact
	InsertQuoteConversionFact(ctx context.Context, db DBTX, fact *sales_analytics.QuoteConversionFact) error
	// ==================== New methods for return analytics ====================

	// QuoteItemAnalytics
	UpsertQuoteItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.QuoteItemAnalytics) error
	GetQuoteItemAnalyticsByQuote(ctx context.Context, db DBTX, quoteID uuid.UUID) ([]*sales_analytics.QuoteItemAnalytics, error)
	// OrderHourlySales
	// ==================== New methods for return analytics ====================

	// DailyReturnMetrics
	UpsertDailyReturnMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyReturnMetrics) error
	IncrementDailyReturnRequests(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error
	IncrementDailyReturnApprovals(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error
	IncrementDailyReturnCompletions(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, refundAmount, creditNoteAmount decimal.Decimal) error
	IncrementDailyReturnRejections(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error
	AddDailyRefundAmount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	AddDailyCreditNoteAmount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error
	IncrementDailyReturnUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error

	// ReturnReasonFact
	InsertReturnReasonFact(ctx context.Context, db DBTX, fact *sales_analytics.ReturnReasonFact) error

	// ReturnProcessingTimeFact
	InsertReturnProcessingTime(ctx context.Context, db DBTX, fact *sales_analytics.ReturnProcessingTimeFact) error
	CloseReturnProcessingTime(ctx context.Context, db DBTX, returnID uuid.UUID, status enums.ReturnStatus, exitedAt time.Time) error

	// CreditNoteFact
	InsertCreditNoteFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditNoteFact) error
	UpdateCreditNoteAppliedAmount(ctx context.Context, db DBTX, creditNoteID uuid.UUID, appliedAmount decimal.Decimal, appliedToInvoiceID *uuid.UUID, appliedDate *time.Time, status string) error
	// Sales rep target achievement
	UpsertSalesRepTargetAchievement(ctx context.Context, db DBTX, achievement *sales_analytics.SalesRepTargetAchievement) error
	UpdateSalesRepTargetAchievement(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time, actualRevenue decimal.Decimal) error
	GetSalesRepTargetAchievement(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*sales_analytics.SalesRepTargetAchievement, error)

	// Sales rep commission fact
	UpsertSalesRepCommissionFact(ctx context.Context, db DBTX, fact *sales_analytics.SalesRepCommissionFact) error
	GetSalesRepCommissionFacts(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, from, to *time.Time) ([]*sales_analytics.SalesRepCommissionFact, error)
	MarkCommissionPaid(ctx context.Context, db DBTX, companyID, factID uuid.UUID, paidAt time.Time) error

	// Sales rep leaderboard snapshot
	UpsertSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.SalesRepLeaderboardSnapshot) error
	RefreshSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate, periodStart, periodEnd time.Time) error
	GetSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) ([]*sales_analytics.SalesRepLeaderboardSnapshot, error)
	// RefundFact
	InsertRefundFact(ctx context.Context, db DBTX, fact *sales_analytics.RefundFact) error
	// CommissionPlanDaily
	UpsertCommissionPlanDaily(ctx context.Context, db DBTX, daily *sales_analytics.CommissionPlanDaily) error
	IncrementCommissionPlanDaily(ctx context.Context, db DBTX, companyID, planID uuid.UUID, date time.Time, earnedAmount, paidAmount decimal.Decimal, rate decimal.Decimal, salesRepID uuid.UUID) error

	// CommissionRuleFact
	UpsertCommissionRuleFact(ctx context.Context, db DBTX, fact *sales_analytics.CommissionRuleFact) error
	IncrementCommissionRuleFact(ctx context.Context, db DBTX, companyID, ruleID, planID uuid.UUID, date time.Time, commissionBase, commissionAmount decimal.Decimal, rate decimal.Decimal) error

	// CommissionAssignmentFact
	InsertCommissionAssignmentFact(ctx context.Context, db DBTX, fact *sales_analytics.CommissionAssignmentFact) error
	CloseCommissionAssignmentFact(ctx context.Context, db DBTX, companyID, salesRepID, planID uuid.UUID, removedAt time.Time) error

	// CommissionLifecycle
	InsertCommissionLifecycle(ctx context.Context, db DBTX, lifecycle *sales_analytics.CommissionLifecycle) error
	UpdateCommissionLifecycle(ctx context.Context, db DBTX, commissionID uuid.UUID, status string, approvedAt, paidAt, rejectedAt *time.Time) error
	// CreditCheckFact
	InsertCreditCheckFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditCheckFact) error

	// DailyCreditMetrics
	UpsertDailyCreditMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyCreditMetrics) error
	IncrementDailyCreditMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, passed bool, requestedAmount decimal.Decimal, checkType string, availableCredit decimal.Decimal, utilizationPct decimal.Decimal) error

	// CreditHoldFact
	InsertCreditHoldFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditHoldFact) error
	CloseCreditHoldFact(ctx context.Context, db DBTX, orderID uuid.UUID, holdEndedAt time.Time) error

	// CreditLimitChangeFact
	InsertCreditLimitChangeFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditLimitChangeFact) error

	// CustomerCreditDailySnapshot
	UpsertCustomerCreditDailySnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.CustomerCreditDailySnapshot) error
	RefreshCustomerCreditDailySnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error

	// CurrentCustomerCredit (materialized view)
	RefreshCurrentCustomerCredit(ctx context.Context, db DBTX) error
	// CommissionForecastSnapshot
	UpsertCommissionForecastSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.CommissionForecastSnapshot) error
	RefreshCommissionForecastSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error
	// ReturnProductCategoryFact
	UpsertReturnProductCategoryFact(ctx context.Context, db DBTX, fact *sales_analytics.ReturnProductCategoryFact) error
	IncrementReturnProductCategory(ctx context.Context, db DBTX, companyID uuid.UUID, categoryID *uuid.UUID, categoryName *string, returnDate time.Time, quantity decimal.Decimal, refundAmount decimal.Decimal, isUniqueReturn bool) error
	IncrementOrderHourlySales(ctx context.Context, db DBTX, companyID uuid.UUID, hourBucket time.Time, orderTotal decimal.Decimal, customerID uuid.UUID) error
	GetOrderHourlySales(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*sales_analytics.OrderHourlySales, error)
}

// PaymentTermPerformanceUpdate remains unchanged.
type PaymentTermPerformanceUpdate struct {
	InvoiceAmount        decimal.Decimal
	PaidOnTime           bool
	PaidLate             bool
	EligibleForEarlyDisc bool
	TookEarlyDiscount    bool
	EarlyDiscountAmount  decimal.Decimal
	DaysToPay            *int
}

type analyticsRepository struct {
	logger *zap.Logger
}

func NewAnalyticsRepository(logger *zap.Logger) AnalyticsRepository {
	return &analyticsRepository{
		logger: logger.Named("sales_analytics_repo"),
	}
}

// -------------------- Daily Sales (unchanged) --------------------
func (r *analyticsRepository) UpsertDailySales(ctx context.Context, db DBTX, daily *sales_analytics.DailySales) error {
	query := `
        INSERT INTO sales_analytics.daily_sales
            (company_id, date, total_orders, total_invoices, total_revenue, total_discounts, total_tax, total_payments, unique_customers, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_orders = EXCLUDED.total_orders,
            total_invoices = EXCLUDED.total_invoices,
            total_revenue = EXCLUDED.total_revenue,
            total_discounts = EXCLUDED.total_discounts,
            total_tax = EXCLUDED.total_tax,
            total_payments = EXCLUDED.total_payments,
            unique_customers = EXCLUDED.unique_customers,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		daily.CompanyID, daily.Date,
		daily.TotalOrders, daily.TotalInvoices, daily.TotalRevenue, daily.TotalDiscounts,
		daily.TotalTax, daily.TotalPayments, daily.UniqueCustomers,
	)
	if err != nil {
		return fmt.Errorf("upsert daily sales: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyOrders(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, delta int) error {
	query := `
        INSERT INTO sales_analytics.daily_sales (company_id, date, total_orders, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE
        SET total_orders = daily_sales.total_orders + EXCLUDED.total_orders,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, delta)
	if err != nil {
		return fmt.Errorf("increment daily orders: %w", err)
	}
	return nil
}

func (r *analyticsRepository) AddDailyRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_sales (company_id, date, total_revenue, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE
        SET total_revenue = daily_sales.total_revenue + EXCLUDED.total_revenue,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	return err
}

func (r *analyticsRepository) AddDailyPayments(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_sales (company_id, date, total_payments, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE
        SET total_payments = daily_sales.total_payments + EXCLUDED.total_payments,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	return err
}

func (r *analyticsRepository) AddDailyDiscounts(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_sales (company_id, date, total_discounts, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE
        SET total_discounts = daily_sales.total_discounts + EXCLUDED.total_discounts,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	return err
}

func (r *analyticsRepository) AddDailyTax(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_sales (company_id, date, total_tax, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE
        SET total_tax = daily_sales.total_tax + EXCLUDED.total_tax,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	return err
}

func (r *analyticsRepository) IncrementUniqueCustomers(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error {
	query := `
        WITH inserted AS (
            INSERT INTO sales_analytics.daily_unique_customers (company_id, date, customer_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (company_id, date, customer_id) DO NOTHING
            RETURNING 1
        )
        UPDATE sales_analytics.daily_sales
        SET unique_customers = unique_customers + (SELECT COUNT(*) FROM inserted),
            updated_at = NOW()
        WHERE company_id = $1 AND date = $2
    `
	_, err := db.ExecContext(ctx, query, companyID, date, customerID)
	if err != nil {
		return fmt.Errorf("increment unique customers: %w", err)
	}
	return nil
}

// -------------------- Daily Unique Customers --------------------
func (r *analyticsRepository) AddUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) (bool, error) {
	query := `
        INSERT INTO sales_analytics.daily_unique_customers (company_id, date, customer_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (company_id, date, customer_id) DO NOTHING
        RETURNING 1
    `
	var ignored int
	err := db.QueryRowContext(ctx, query, companyID, date, customerID).Scan(&ignored)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("add unique customer: %w", err)
	}
	return true, nil
}

func (r *analyticsRepository) RemoveUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error {
	query := `DELETE FROM sales_analytics.daily_unique_customers WHERE company_id=$1 AND date=$2 AND customer_id=$3`
	_, err := db.ExecContext(ctx, query, companyID, date, customerID)
	if err != nil {
		return fmt.Errorf("remove unique customer: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IsUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales_analytics.daily_unique_customers WHERE company_id=$1 AND date=$2 AND customer_id=$3)`
	err := db.QueryRowContext(ctx, query, companyID, date, customerID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("is unique customer: %w", err)
	}
	return exists, nil
}

// -------------------- Customer Metrics --------------------
func (r *analyticsRepository) UpdateCustomerMetrics(ctx context.Context, db DBTX, metric *sales_analytics.CustomerMetric) error {
	query := `
        INSERT INTO sales_analytics.customer_metrics
            (customer_id, company_id, first_order_date, last_order_date, total_orders, total_invoices,
             total_spent, total_payments, average_order_value, lifetime_value, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        ON CONFLICT (customer_id) DO UPDATE SET
            first_order_date = COALESCE(customer_metrics.first_order_date, EXCLUDED.first_order_date),
            last_order_date = EXCLUDED.last_order_date,
            total_orders = customer_metrics.total_orders + EXCLUDED.total_orders,
            total_invoices = customer_metrics.total_invoices + EXCLUDED.total_invoices,
            total_spent = customer_metrics.total_spent + EXCLUDED.total_spent,
            total_payments = customer_metrics.total_payments + EXCLUDED.total_payments,
            average_order_value = CASE WHEN (customer_metrics.total_orders + EXCLUDED.total_orders) > 0
                                       THEN (customer_metrics.total_spent + EXCLUDED.total_spent) / (customer_metrics.total_orders + EXCLUDED.total_orders)
                                       ELSE 0 END,
            lifetime_value = customer_metrics.lifetime_value + EXCLUDED.lifetime_value,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		metric.CustomerID, metric.CompanyID,
		metric.FirstOrderDate, metric.LastOrderDate,
		metric.TotalOrders, metric.TotalInvoices,
		metric.TotalSpent, metric.TotalPayments,
		metric.AverageOrderValue, metric.LifetimeValue,
	)
	if err != nil {
		return fmt.Errorf("update customer metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetCustomerMetrics(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*sales_analytics.CustomerMetric, error) {
	query := `
        SELECT customer_id, company_id, first_order_date, last_order_date,
               total_orders, total_invoices, total_spent, total_payments,
               average_order_value, lifetime_value, updated_at
        FROM sales_analytics.customer_metrics
        WHERE company_id = $1 AND customer_id = $2
    `
	var m sales_analytics.CustomerMetric
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(
		&m.CustomerID, &m.CompanyID, &m.FirstOrderDate, &m.LastOrderDate,
		&m.TotalOrders, &m.TotalInvoices, &m.TotalSpent, &m.TotalPayments,
		&m.AverageOrderValue, &m.LifetimeValue, &m.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get customer metrics: %w", err)
	}
	return &m, nil
}

// -------------------- Product Sales Fact --------------------
func (r *analyticsRepository) UpsertProductSales(ctx context.Context, db DBTX, fact *sales_analytics.ProductSalesFact) error {
	query := `
        INSERT INTO sales_analytics.product_sales_fact
            (company_id, product_id, date, quantity_sold, revenue, discount_applied, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (company_id, product_id, date) DO UPDATE SET
            quantity_sold = EXCLUDED.quantity_sold,
            revenue = EXCLUDED.revenue,
            discount_applied = EXCLUDED.discount_applied,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.ProductID, fact.Date,
		fact.QuantitySold, fact.Revenue, fact.DiscountApplied,
	)
	if err != nil {
		return fmt.Errorf("upsert product sales: %w", err)
	}
	return nil
}

func (r *analyticsRepository) AddProductSales(ctx context.Context, db DBTX, companyID, productID uuid.UUID, date time.Time, quantity, revenue, discount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.product_sales_fact
            (company_id, product_id, date, quantity_sold, revenue, discount_applied, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (company_id, product_id, date) DO UPDATE SET
            quantity_sold = product_sales_fact.quantity_sold + EXCLUDED.quantity_sold,
            revenue = product_sales_fact.revenue + EXCLUDED.revenue,
            discount_applied = product_sales_fact.discount_applied + EXCLUDED.discount_applied,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, productID, date, quantity, revenue, discount)
	if err != nil {
		return fmt.Errorf("add product sales: %w", err)
	}
	return nil
}

// -------------------- Product Returns Fact --------------------
func (r *analyticsRepository) UpsertProductReturns(ctx context.Context, db DBTX, fact *sales_analytics.ProductReturnsFact) error {
	query := `
        INSERT INTO sales_analytics.product_returns_fact
            (company_id, product_id, date, quantity_returned, refund_amount, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (company_id, product_id, date) DO UPDATE SET
            quantity_returned = EXCLUDED.quantity_returned,
            refund_amount = EXCLUDED.refund_amount,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.ProductID, fact.Date,
		fact.QuantityReturned, fact.RefundAmount,
	)
	if err != nil {
		return fmt.Errorf("upsert product returns: %w", err)
	}
	return nil
}

func (r *analyticsRepository) AddProductReturns(ctx context.Context, db DBTX, companyID, productID uuid.UUID, date time.Time, quantity, refundAmount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.product_returns_fact
            (company_id, product_id, date, quantity_returned, refund_amount, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (company_id, product_id, date) DO UPDATE SET
            quantity_returned = product_returns_fact.quantity_returned + EXCLUDED.quantity_returned,
            refund_amount = product_returns_fact.refund_amount + EXCLUDED.refund_amount,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, productID, date, quantity, refundAmount)
	if err != nil {
		return fmt.Errorf("add product returns: %w", err)
	}
	return nil
}

// -------------------- PaymentTermPerformance --------------------
func (r *analyticsRepository) UpdatePaymentTermPerformance(ctx context.Context, db DBTX, companyID, termID uuid.UUID, date time.Time, metrics PaymentTermPerformanceUpdate) error {
	// Compute the average days to pay incrementally using a weighted average approach.
	// We'll store the new average as:
	// new_avg = (old_avg * old_total_invoices + days_to_pay) / (old_total_invoices + 1)
	// For the first invoice, days_to_pay may be nil (not paid yet).
	query := `
        INSERT INTO sales_analytics.payment_term_performance
            (company_id, payment_term_id, date,
             total_invoices, total_invoice_amount,
             paid_on_time_count, paid_late_count,
             early_discount_eligible_count, early_discount_taken_count,
             early_discount_amount, average_days_to_pay,
             updated_at)
        VALUES ($1, $2, $3,
                1, $4,
                $5, $6,
                $7, $8,
                $9, $10,
                NOW())
        ON CONFLICT (company_id, payment_term_id, date) DO UPDATE SET
            total_invoices = payment_term_performance.total_invoices + 1,
            total_invoice_amount = payment_term_performance.total_invoice_amount + EXCLUDED.total_invoice_amount,
            paid_on_time_count = payment_term_performance.paid_on_time_count + EXCLUDED.paid_on_time_count,
            paid_late_count = payment_term_performance.paid_late_count + EXCLUDED.paid_late_count,
            early_discount_eligible_count = payment_term_performance.early_discount_eligible_count + EXCLUDED.early_discount_eligible_count,
            early_discount_taken_count = payment_term_performance.early_discount_taken_count + EXCLUDED.early_discount_taken_count,
            early_discount_amount = payment_term_performance.early_discount_amount + EXCLUDED.early_discount_amount,
            average_days_to_pay = CASE
                WHEN EXCLUDED.average_days_to_pay IS NOT NULL THEN
                    (COALESCE(payment_term_performance.average_days_to_pay, 0) * payment_term_performance.total_invoices + EXCLUDED.average_days_to_pay) / (payment_term_performance.total_invoices + 1)
                ELSE
                    payment_term_performance.average_days_to_pay
            END,
            updated_at = NOW()
    `
	var avgDaysToPay interface{}
	if metrics.DaysToPay != nil {
		avgDaysToPay = *metrics.DaysToPay
	} else {
		avgDaysToPay = nil
	}

	_, err := db.ExecContext(ctx, query,
		companyID, termID, date,
		metrics.InvoiceAmount,
		boolToInt(metrics.PaidOnTime),
		boolToInt(metrics.PaidLate),
		boolToInt(metrics.EligibleForEarlyDisc),
		boolToInt(metrics.TookEarlyDiscount),
		metrics.EarlyDiscountAmount,
		avgDaysToPay,
	)
	if err != nil {
		return fmt.Errorf("update payment term performance: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetPaymentTermPerformance(ctx context.Context, db DBTX, companyID, termID uuid.UUID, from, to time.Time) ([]*sales_analytics.PaymentTermPerformance, error) {
	query := `
        SELECT id, company_id, payment_term_id, date,
               total_invoices, total_invoice_amount,
               paid_on_time_count, paid_late_count,
               early_discount_eligible_count, early_discount_taken_count,
               early_discount_amount, average_days_to_pay, updated_at
        FROM sales_analytics.payment_term_performance
        WHERE company_id = $1 AND payment_term_id = $2 AND date BETWEEN $3 AND $4
        ORDER BY date ASC
    `
	rows, err := db.QueryContext(ctx, query, companyID, termID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get payment term performance: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.PaymentTermPerformance
	for rows.Next() {
		var p sales_analytics.PaymentTermPerformance
		err := rows.Scan(
			&p.ID, &p.CompanyID, &p.PaymentTermID, &p.Date,
			&p.TotalInvoices, &p.TotalInvoiceAmount,
			&p.PaidOnTimeCount, &p.PaidLateCount,
			&p.EarlyDiscountEligibleCount, &p.EarlyDiscountTakenCount,
			&p.EarlyDiscountAmount, &p.AverageDaysToPay, &p.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan payment term performance: %w", err)
		}
		result = append(result, &p)
	}
	return result, rows.Err()
}

// Helper function
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// RecordPaymentTermInvoice inserts or updates the row for the invoice date,
// incrementing total_invoices and total_invoice_amount.
func (r *analyticsRepository) RecordPaymentTermInvoice(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceDate time.Time, invoiceAmount decimal.Decimal, eligibleForEarlyDisc bool) error {
	query := `
        INSERT INTO sales_analytics.payment_term_performance
            (company_id, payment_term_id, date,
             total_invoices, total_invoice_amount,
             early_discount_eligible_count, updated_at)
        VALUES ($1, $2, $3, 1, $4, $5, NOW())
        ON CONFLICT (company_id, payment_term_id, date) DO UPDATE SET
            total_invoices = payment_term_performance.total_invoices + 1,
            total_invoice_amount = payment_term_performance.total_invoice_amount + EXCLUDED.total_invoice_amount,
            early_discount_eligible_count = payment_term_performance.early_discount_eligible_count + EXCLUDED.early_discount_eligible_count,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, termID, invoiceDate, invoiceAmount, boolToInt(eligibleForEarlyDisc))
	return err
}

// RecordPaymentTermPayment updates the row for the payment date.
// It does NOT increment invoice counts – only payment metrics.
func (r *analyticsRepository) RecordPaymentTermPayment(ctx context.Context, db DBTX, companyID, termID uuid.UUID, paymentDate time.Time, paidOnTime, paidLate, tookEarlyDiscount bool, earlyDiscountAmount decimal.Decimal, daysToPay int) error {
	query := `
        INSERT INTO sales_analytics.payment_term_performance
            (company_id, payment_term_id, date,
             paid_on_time_count, paid_late_count,
             early_discount_taken_count, early_discount_amount,
             average_days_to_pay, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (company_id, payment_term_id, date) DO UPDATE SET
            paid_on_time_count = payment_term_performance.paid_on_time_count + EXCLUDED.paid_on_time_count,
            paid_late_count = payment_term_performance.paid_late_count + EXCLUDED.paid_late_count,
            early_discount_taken_count = payment_term_performance.early_discount_taken_count + EXCLUDED.early_discount_taken_count,
            early_discount_amount = payment_term_performance.early_discount_amount + EXCLUDED.early_discount_amount,
            average_days_to_pay = (COALESCE(payment_term_performance.average_days_to_pay, 0) * payment_term_performance.paid_on_time_count + EXCLUDED.average_days_to_pay) / (payment_term_performance.paid_on_time_count + 1),
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		companyID, termID, paymentDate,
		boolToInt(paidOnTime), boolToInt(paidLate),
		boolToInt(tookEarlyDiscount), earlyDiscountAmount,
		daysToPay,
	)
	return err
}

// -------------------- OrderStatusHistory --------------------
func (r *analyticsRepository) InsertOrderStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.OrderStatusHistory) error {
	query := `
		INSERT INTO sales_analytics.order_status_history
			(order_id, company_id, status, entered_at, exited_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		history.OrderID, history.CompanyID, history.Status,
		history.EnteredAt, history.ExitedAt,
	)
	if err != nil {
		return fmt.Errorf("insert order status history: %w", err)
	}
	return nil
}

func (r *analyticsRepository) CloseOrderStatusHistory(ctx context.Context, db DBTX, orderID uuid.UUID, status enums.OrderStatus, exitedAt time.Time) error {
	query := `
		UPDATE sales_analytics.order_status_history
		SET exited_at = $3
		WHERE order_id = $1 AND status = $2 AND exited_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, orderID, status, exitedAt)
	if err != nil {
		return fmt.Errorf("close order status history: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no open status history found to close", zap.String("order_id", orderID.String()), zap.String("status", string(status)))
	}
	return nil
}

func (r *analyticsRepository) GetOrderStatusHistory(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*sales_analytics.OrderStatusHistory, error) {
	query := `
		SELECT history_id, order_id, company_id, status, entered_at, exited_at, duration_seconds, created_at
		FROM sales_analytics.order_status_history
		WHERE order_id = $1
		ORDER BY entered_at ASC
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get order status history: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.OrderStatusHistory
	for rows.Next() {
		var h sales_analytics.OrderStatusHistory
		err := rows.Scan(
			&h.HistoryID, &h.OrderID, &h.CompanyID, &h.Status,
			&h.EnteredAt, &h.ExitedAt, &h.DurationSeconds, &h.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan order status history: %w", err)
		}
		result = append(result, &h)
	}
	return result, rows.Err()
}

// -------------------- OrderItemAnalytics --------------------
func (r *analyticsRepository) UpsertOrderItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.OrderItemAnalytics) error {
	query := `
		INSERT INTO sales_analytics.order_item_analytics
			(order_item_id, order_id, company_id, product_id, quantity, unit_price,
			 discount_amount, tax_amount, total_line_amount, cogs_per_unit, order_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (order_item_id) DO UPDATE SET
			quantity = EXCLUDED.quantity,
			unit_price = EXCLUDED.unit_price,
			discount_amount = EXCLUDED.discount_amount,
			tax_amount = EXCLUDED.tax_amount,
			total_line_amount = EXCLUDED.total_line_amount,
			cogs_per_unit = EXCLUDED.cogs_per_unit,
			order_date = EXCLUDED.order_date,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		item.OrderItemID, item.OrderID, item.CompanyID, item.ProductID,
		item.Quantity, item.UnitPrice, item.DiscountAmount, item.TaxAmount,
		item.TotalLineAmount, item.CogsPerUnit, item.OrderDate,
	)
	if err != nil {
		return fmt.Errorf("upsert order item analytics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetOrderItemAnalyticsByOrder(ctx context.Context, db DBTX, orderID uuid.UUID) ([]*sales_analytics.OrderItemAnalytics, error) {
	query := `
		SELECT id, order_item_id, order_id, company_id, product_id,
		       quantity, unit_price, discount_amount, tax_amount,
		       total_line_amount, cogs_per_unit, profit, order_date, created_at
		FROM sales_analytics.order_item_analytics
		WHERE order_id = $1
		ORDER BY id
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get order item analytics: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.OrderItemAnalytics
	for rows.Next() {
		var a sales_analytics.OrderItemAnalytics
		err := rows.Scan(
			&a.ID, &a.OrderItemID, &a.OrderID, &a.CompanyID, &a.ProductID,
			&a.Quantity, &a.UnitPrice, &a.DiscountAmount, &a.TaxAmount,
			&a.TotalLineAmount, &a.CogsPerUnit, &a.Profit, &a.OrderDate, &a.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan order item analytics: %w", err)
		}
		result = append(result, &a)
	}
	return result, rows.Err()
}

// -------------------- SalesRepPerformance --------------------
func (r *analyticsRepository) UpsertSalesRepPerformance(ctx context.Context, db DBTX, perf *sales_analytics.SalesRepPerformance) error {
	query := `
		INSERT INTO sales_analytics.sales_rep_performance
			(company_id, sales_rep_id, date, total_orders, total_revenue,
			 average_order_value, total_commission, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, sales_rep_id, date) DO UPDATE SET
			total_orders = EXCLUDED.total_orders,
			total_revenue = EXCLUDED.total_revenue,
			average_order_value = CASE WHEN EXCLUDED.total_orders > 0
			                           THEN EXCLUDED.total_revenue / EXCLUDED.total_orders
			                           ELSE 0 END,
			total_commission = EXCLUDED.total_commission,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		perf.CompanyID, perf.SalesRepID, perf.Date,
		perf.TotalOrders, perf.TotalRevenue, perf.AverageOrderValue, perf.TotalCommission,
	)
	if err != nil {
		return fmt.Errorf("upsert sales rep performance: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementSalesRepPerformance(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, date time.Time, orderTotal, commission decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.sales_rep_performance
			(company_id, sales_rep_id, date, total_orders, total_revenue, total_commission, updated_at)
		VALUES ($1, $2, $3, 1, $4, $5, NOW())
		ON CONFLICT (company_id, sales_rep_id, date) DO UPDATE SET
			total_orders = sales_rep_performance.total_orders + 1,
			total_revenue = sales_rep_performance.total_revenue + EXCLUDED.total_revenue,
			total_commission = sales_rep_performance.total_commission + EXCLUDED.total_commission,
			average_order_value = (sales_rep_performance.total_revenue + EXCLUDED.total_revenue) / (sales_rep_performance.total_orders + 1),
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, salesRepID, date, orderTotal, commission)
	if err != nil {
		return fmt.Errorf("increment sales rep performance: %w", err)
	}
	return nil
}

// -------------------- OrderCancellationReasons --------------------
func (r *analyticsRepository) InsertOrderCancellationReason(ctx context.Context, db DBTX, reason *sales_analytics.OrderCancellationReason) error {
	query := `
		INSERT INTO sales_analytics.order_cancellation_reasons
			(order_id, company_id, cancellation_reason, cancelled_by, cancelled_at,
			 order_status_before_cancel, order_total_before_cancel)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := db.ExecContext(ctx, query,
		reason.OrderID, reason.CompanyID, reason.CancellationReason,
		reason.CancelledBy, reason.CancelledAt,
		reason.OrderStatusBeforeCancel, reason.OrderTotalBeforeCancel,
	)
	if err != nil {
		return fmt.Errorf("insert order cancellation reason: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetCancellationReasons(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*sales_analytics.OrderCancellationReason, error) {
	query := `
		SELECT id, order_id, company_id, cancellation_reason, cancelled_by,
		       cancelled_at, order_status_before_cancel, order_total_before_cancel
		FROM sales_analytics.order_cancellation_reasons
		WHERE company_id = $1 AND cancelled_at BETWEEN $2 AND $3
		ORDER BY cancelled_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get cancellation reasons: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.OrderCancellationReason
	for rows.Next() {
		var c sales_analytics.OrderCancellationReason
		err := rows.Scan(
			&c.ID, &c.OrderID, &c.CompanyID, &c.CancellationReason,
			&c.CancelledBy, &c.CancelledAt, &c.OrderStatusBeforeCancel, &c.OrderTotalBeforeCancel,
		)
		if err != nil {
			return nil, fmt.Errorf("scan cancellation reason: %w", err)
		}
		result = append(result, &c)
	}
	return result, rows.Err()
}

// -------------------- FulfillmentMetrics --------------------
func (r *analyticsRepository) UpsertFulfillmentMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.FulfillmentMetrics) error {
	query := `
		INSERT INTO sales_analytics.fulfillment_metrics
			(order_id, company_id, confirmed_at, shipped_at, delivered_at,
			 carrier, tracking_number, shipping_address_region, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (order_id) DO UPDATE SET
			confirmed_at = COALESCE(EXCLUDED.confirmed_at, fulfillment_metrics.confirmed_at),
			shipped_at = COALESCE(EXCLUDED.shipped_at, fulfillment_metrics.shipped_at),
			delivered_at = COALESCE(EXCLUDED.delivered_at, fulfillment_metrics.delivered_at),
			carrier = COALESCE(EXCLUDED.carrier, fulfillment_metrics.carrier),
			tracking_number = COALESCE(EXCLUDED.tracking_number, fulfillment_metrics.tracking_number),
			shipping_address_region = COALESCE(EXCLUDED.shipping_address_region, fulfillment_metrics.shipping_address_region),
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		metrics.OrderID, metrics.CompanyID,
		metrics.ConfirmedAt, metrics.ShippedAt, metrics.DeliveredAt,
		metrics.Carrier, metrics.TrackingNumber, metrics.ShippingAddressRegion,
	)
	if err != nil {
		return fmt.Errorf("upsert fulfillment metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateFulfillmentShipping(ctx context.Context, db DBTX, orderID uuid.UUID, shippedAt time.Time, carrier, trackingNumber *string, shippingRegion *string) error {
	query := `
		UPDATE sales_analytics.fulfillment_metrics
		SET shipped_at = $2,
		    carrier = COALESCE($3, carrier),
		    tracking_number = COALESCE($4, tracking_number),
		    shipping_address_region = COALESCE($5, shipping_address_region),
		    created_at = NOW()
		WHERE order_id = $1
	`
	_, err := db.ExecContext(ctx, query, orderID, shippedAt, carrier, trackingNumber, shippingRegion)
	if err != nil {
		return fmt.Errorf("update fulfillment shipping: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateFulfillmentDelivery(ctx context.Context, db DBTX, orderID uuid.UUID, deliveredAt time.Time) error {
	query := `
		UPDATE sales_analytics.fulfillment_metrics
		SET delivered_at = $2, created_at = NOW()
		WHERE order_id = $1
	`
	_, err := db.ExecContext(ctx, query, orderID, deliveredAt)
	if err != nil {
		return fmt.Errorf("update fulfillment delivery: %w", err)
	}
	return nil
}

// -------------------- OrderHourlySales --------------------
func (r *analyticsRepository) IncrementOrderHourlySales(ctx context.Context, db DBTX, companyID uuid.UUID, hourBucket time.Time, orderTotal decimal.Decimal, customerID uuid.UUID) error {
	// Step 1: increment total_orders and total_revenue
	upsertQuery := `
		INSERT INTO sales_analytics.order_hourly_sales
			(company_id, hour_bucket, total_orders, total_revenue, updated_at)
		VALUES ($1, $2, 1, $3, NOW())
		ON CONFLICT (company_id, hour_bucket) DO UPDATE SET
			total_orders = order_hourly_sales.total_orders + 1,
			total_revenue = order_hourly_sales.total_revenue + EXCLUDED.total_revenue,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, upsertQuery, companyID, hourBucket, orderTotal)
	if err != nil {
		return fmt.Errorf("increment hourly sales (orders/revenue): %w", err)
	}

	// Step 2: update unique customers using a separate table or a subquery.
	// We'll reuse daily_unique_customers but with hour_bucket? Simpler: use a separate hourly_unique_customers table.
	// To avoid complexity, we'll implement unique customers per hour using an auxiliary table.
	// If you don't want that, skip this part.
	// For now, we'll implement a simple version that does NOT deduplicate customers per hour.
	// Alternatively, you can ignore unique_customers for hourly and rely on daily.
	// The following is a placeholder – you can extend later.
	// To keep it simple, we leave unique_customers as 0 and provide a separate method to recalc if needed.
	// But since the table has a unique_customers column, we'll try to maintain it.
	// A robust solution requires an hourly_unique_customers bridge table.
	// I'll implement the bridge table approach.
	// However, to avoid creating extra table now, we'll set unique_customers to 0 and note that it's not maintained.
	// Better: we can increment unique_customers only if this customer hasn't placed an order in the same hour.
	// Without an hourly bridge table, we cannot know. So we'll skip unique_customers for hourly.
	// The column will remain 0. If you need it, create sales_analytics.hourly_unique_customers similarly.
	r.logger.Warn("unique_customers in order_hourly_sales not implemented – requires hourly bridge table")
	return nil
}

func (r *analyticsRepository) GetOrderHourlySales(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*sales_analytics.OrderHourlySales, error) {
	query := `
		SELECT id, company_id, hour_bucket, total_orders, total_revenue, unique_customers, updated_at
		FROM sales_analytics.order_hourly_sales
		WHERE company_id = $1 AND hour_bucket BETWEEN $2 AND $3
		ORDER BY hour_bucket ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get order hourly sales: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.OrderHourlySales
	for rows.Next() {
		var h sales_analytics.OrderHourlySales
		err := rows.Scan(
			&h.ID, &h.CompanyID, &h.HourBucket,
			&h.TotalOrders, &h.TotalRevenue, &h.UniqueCustomers, &h.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan order hourly sales: %w", err)
		}
		result = append(result, &h)
	}
	return result, rows.Err()
}

// -------------------- Daily Quote Metrics --------------------
func (r *analyticsRepository) UpsertDailyQuoteMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyQuoteMetrics) error {
	query := `
        INSERT INTO sales_analytics.daily_quote_metrics
            (company_id, date, total_quotes_created, total_quote_value,
             total_quotes_converted, converted_value, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_quotes_created = EXCLUDED.total_quotes_created,
            total_quote_value = EXCLUDED.total_quote_value,
            total_quotes_converted = EXCLUDED.total_quotes_converted,
            converted_value = EXCLUDED.converted_value,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		metrics.CompanyID, metrics.Date,
		metrics.TotalQuotesCreated, metrics.TotalQuoteValue,
		metrics.TotalQuotesConverted, metrics.ConvertedValue,
	)
	if err != nil {
		return fmt.Errorf("upsert daily quote metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyQuoteCreated(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, quoteValue decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_quote_metrics
            (company_id, date, total_quotes_created, total_quote_value, updated_at)
        VALUES ($1, $2, 1, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_quotes_created = daily_quote_metrics.total_quotes_created + 1,
            total_quote_value = daily_quote_metrics.total_quote_value + EXCLUDED.total_quote_value,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, quoteValue)
	if err != nil {
		return fmt.Errorf("increment daily quote created: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyQuoteConverted(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, convertedValue decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_quote_metrics
            (company_id, date, total_quotes_converted, converted_value, updated_at)
        VALUES ($1, $2, 1, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_quotes_converted = daily_quote_metrics.total_quotes_converted + 1,
            converted_value = daily_quote_metrics.converted_value + EXCLUDED.converted_value,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, convertedValue)
	if err != nil {
		return fmt.Errorf("increment daily quote converted: %w", err)
	}
	return nil
}

// -------------------- Quote Status History --------------------
func (r *analyticsRepository) InsertQuoteStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.QuoteStatusHistory) error {
	query := `
        INSERT INTO sales_analytics.quote_status_history
            (quote_id, company_id, status, entered_at, exited_at, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
    `
	_, err := db.ExecContext(ctx, query,
		history.QuoteID, history.CompanyID, history.Status,
		history.EnteredAt, history.ExitedAt,
	)
	if err != nil {
		return fmt.Errorf("insert quote status history: %w", err)
	}
	return nil
}

func (r *analyticsRepository) CloseQuoteStatusHistory(ctx context.Context, db DBTX, quoteID uuid.UUID, status enums.QuoteStatus, exitedAt time.Time) error {
	query := `
        UPDATE sales_analytics.quote_status_history
        SET exited_at = $3
        WHERE quote_id = $1 AND status = $2 AND exited_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, quoteID, status, exitedAt)
	if err != nil {
		return fmt.Errorf("close quote status history: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no open quote status history found to close", zap.String("quote_id", quoteID.String()), zap.String("status", string(status)))
	}
	return nil
}

func (r *analyticsRepository) GetQuoteStatusHistory(ctx context.Context, db DBTX, quoteID uuid.UUID) ([]*sales_analytics.QuoteStatusHistory, error) {
	query := `
        SELECT history_id, quote_id, company_id, status, entered_at, exited_at, duration_seconds, created_at
        FROM sales_analytics.quote_status_history
        WHERE quote_id = $1
        ORDER BY entered_at ASC
    `
	rows, err := db.QueryContext(ctx, query, quoteID)
	if err != nil {
		return nil, fmt.Errorf("get quote status history: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.QuoteStatusHistory
	for rows.Next() {
		var h sales_analytics.QuoteStatusHistory
		err := rows.Scan(
			&h.HistoryID, &h.QuoteID, &h.CompanyID, &h.Status,
			&h.EnteredAt, &h.ExitedAt, &h.DurationSeconds, &h.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan quote status history: %w", err)
		}
		result = append(result, &h)
	}
	return result, rows.Err()
}

// -------------------- Quote Conversion Fact --------------------
func (r *analyticsRepository) InsertQuoteConversionFact(ctx context.Context, db DBTX, fact *sales_analytics.QuoteConversionFact) error {
	query := `
        INSERT INTO sales_analytics.quote_conversion_facts
            (quote_id, order_id, company_id, customer_id,
             quote_value_at_conversion, order_value_at_conversion,
             conversion_time_seconds, quote_expiry_days, used_coupon_ids,
             sales_rep_id, converted_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        ON CONFLICT (quote_id, order_id) DO NOTHING
    `
	_, err := db.ExecContext(ctx, query,
		fact.QuoteID, fact.OrderID, fact.CompanyID, fact.CustomerID,
		fact.QuoteValueAtConversion, fact.OrderValueAtConversion,
		fact.ConversionTimeSeconds, fact.QuoteExpiryDays, fact.UsedCouponIDs,
		fact.SalesRepID, fact.ConvertedAt,
	)
	if err != nil {
		return fmt.Errorf("insert quote conversion fact: %w", err)
	}
	return nil
}

// -------------------- Quote Item Analytics --------------------
func (r *analyticsRepository) UpsertQuoteItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.QuoteItemAnalytics) error {
	query := `
        INSERT INTO sales_analytics.quote_item_analytics
            (quote_item_id, quote_id, company_id, product_id,
             quantity, unit_price, discount_amount, tax_amount,
             total_line_amount, quote_date, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        ON CONFLICT (quote_item_id) DO UPDATE SET
            quantity = EXCLUDED.quantity,
            unit_price = EXCLUDED.unit_price,
            discount_amount = EXCLUDED.discount_amount,
            tax_amount = EXCLUDED.tax_amount,
            total_line_amount = EXCLUDED.total_line_amount,
            quote_date = EXCLUDED.quote_date,
            created_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		item.QuoteItemID, item.QuoteID, item.CompanyID, item.ProductID,
		item.Quantity, item.UnitPrice, item.DiscountAmount, item.TaxAmount,
		item.TotalLineAmount, item.QuoteDate,
	)
	if err != nil {
		return fmt.Errorf("upsert quote item analytics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetQuoteItemAnalyticsByQuote(ctx context.Context, db DBTX, quoteID uuid.UUID) ([]*sales_analytics.QuoteItemAnalytics, error) {
	query := `
        SELECT id, quote_item_id, quote_id, company_id, product_id,
               quantity, unit_price, discount_amount, tax_amount,
               total_line_amount, quote_date, created_at
        FROM sales_analytics.quote_item_analytics
        WHERE quote_id = $1
        ORDER BY id
    `
	rows, err := db.QueryContext(ctx, query, quoteID)
	if err != nil {
		return nil, fmt.Errorf("get quote item analytics: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.QuoteItemAnalytics
	for rows.Next() {
		var a sales_analytics.QuoteItemAnalytics
		err := rows.Scan(
			&a.ID, &a.QuoteItemID, &a.QuoteID, &a.CompanyID, &a.ProductID,
			&a.Quantity, &a.UnitPrice, &a.DiscountAmount, &a.TaxAmount,
			&a.TotalLineAmount, &a.QuoteDate, &a.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan quote item analytics: %w", err)
		}
		result = append(result, &a)
	}
	return result, rows.Err()
}
func (r *analyticsRepository) InsertInvoiceStatusHistory(ctx context.Context, db DBTX, history *sales_analytics.InvoiceStatusHistory) error {
	query := `
		INSERT INTO sales_analytics.invoice_status_history
			(invoice_id, company_id, status, entered_at, exited_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		history.InvoiceID, history.CompanyID, history.Status,
		history.EnteredAt, history.ExitedAt,
	)
	if err != nil {
		return fmt.Errorf("insert invoice status history: %w", err)
	}
	return nil
}

func (r *analyticsRepository) CloseInvoiceStatusHistory(ctx context.Context, db DBTX, invoiceID uuid.UUID, status enums.InvoiceStatus, exitedAt time.Time) error {
	query := `
		UPDATE sales_analytics.invoice_status_history
		SET exited_at = $3
		WHERE invoice_id = $1 AND status = $2 AND exited_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, invoiceID, status, exitedAt)
	if err != nil {
		return fmt.Errorf("close invoice status history: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no open invoice status history found to close", zap.String("invoice_id", invoiceID.String()), zap.String("status", string(status)))
	}
	return nil
}

func (r *analyticsRepository) GetInvoiceStatusHistory(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*sales_analytics.InvoiceStatusHistory, error) {
	query := `
		SELECT history_id, invoice_id, company_id, status, entered_at, exited_at, duration_seconds, created_at
		FROM sales_analytics.invoice_status_history
		WHERE invoice_id = $1
		ORDER BY entered_at ASC
	`
	rows, err := db.QueryContext(ctx, query, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get invoice status history: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.InvoiceStatusHistory
	for rows.Next() {
		var h sales_analytics.InvoiceStatusHistory
		err := rows.Scan(
			&h.HistoryID, &h.InvoiceID, &h.CompanyID, &h.Status,
			&h.EnteredAt, &h.ExitedAt, &h.DurationSeconds, &h.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan invoice status history: %w", err)
		}
		result = append(result, &h)
	}
	return result, rows.Err()
}
func (r *analyticsRepository) UpsertInvoiceItemAnalytics(ctx context.Context, db DBTX, item *sales_analytics.InvoiceItemAnalytics) error {
	query := `
		INSERT INTO sales_analytics.invoice_item_analytics
			(invoice_item_id, invoice_id, company_id, product_id,
			 quantity, unit_price, discount_amount, tax_amount,
			 total_line_amount, invoice_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (invoice_item_id) DO UPDATE SET
			quantity = EXCLUDED.quantity,
			unit_price = EXCLUDED.unit_price,
			discount_amount = EXCLUDED.discount_amount,
			tax_amount = EXCLUDED.tax_amount,
			total_line_amount = EXCLUDED.total_line_amount,
			invoice_date = EXCLUDED.invoice_date,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		item.InvoiceItemID, item.InvoiceID, item.CompanyID, item.ProductID,
		item.Quantity, item.UnitPrice, item.DiscountAmount, item.TaxAmount,
		item.TotalLineAmount, item.InvoiceDate,
	)
	if err != nil {
		return fmt.Errorf("upsert invoice item analytics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetInvoiceItemAnalyticsByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*sales_analytics.InvoiceItemAnalytics, error) {
	query := `
		SELECT id, invoice_item_id, invoice_id, company_id, product_id,
		       quantity, unit_price, discount_amount, tax_amount,
		       total_line_amount, invoice_date, created_at
		FROM sales_analytics.invoice_item_analytics
		WHERE invoice_id = $1
		ORDER BY id
	`
	rows, err := db.QueryContext(ctx, query, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get invoice item analytics: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.InvoiceItemAnalytics
	for rows.Next() {
		var a sales_analytics.InvoiceItemAnalytics
		err := rows.Scan(
			&a.ID, &a.InvoiceItemID, &a.InvoiceID, &a.CompanyID, &a.ProductID,
			&a.Quantity, &a.UnitPrice, &a.DiscountAmount, &a.TaxAmount,
			&a.TotalLineAmount, &a.InvoiceDate, &a.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan invoice item analytics: %w", err)
		}
		result = append(result, &a)
	}
	return result, rows.Err()
}

func (r *analyticsRepository) UpsertDailyInvoiceMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyInvoiceMetrics) error {
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date,
			 total_invoices_issued, total_invoices_paid, total_invoices_overdue, total_invoices_cancelled,
			 total_invoice_value_issued, total_paid_value, total_overdue_value,
			 early_discount_taken_count, early_discount_amount, avg_days_to_payment,
			 updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_invoices_issued = EXCLUDED.total_invoices_issued,
			total_invoices_paid = EXCLUDED.total_invoices_paid,
			total_invoices_overdue = EXCLUDED.total_invoices_overdue,
			total_invoices_cancelled = EXCLUDED.total_invoices_cancelled,
			total_invoice_value_issued = EXCLUDED.total_invoice_value_issued,
			total_paid_value = EXCLUDED.total_paid_value,
			total_overdue_value = EXCLUDED.total_overdue_value,
			early_discount_taken_count = EXCLUDED.early_discount_taken_count,
			early_discount_amount = EXCLUDED.early_discount_amount,
			avg_days_to_payment = EXCLUDED.avg_days_to_payment,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		metrics.CompanyID, metrics.Date,
		metrics.TotalInvoicesIssued, metrics.TotalInvoicesPaid, metrics.TotalInvoicesOverdue, metrics.TotalInvoicesCancelled,
		metrics.TotalInvoiceValueIssued, metrics.TotalPaidValue, metrics.TotalOverdueValue,
		metrics.EarlyDiscountTakenCount, metrics.EarlyDiscountAmount, metrics.AvgDaysToPayment,
	)
	if err != nil {
		return fmt.Errorf("upsert daily invoice metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyInvoiceIssued(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date, total_invoices_issued, total_invoice_value_issued, updated_at)
		VALUES ($1, $2, 1, $3, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_invoices_issued = daily_invoice_metrics.total_invoices_issued + 1,
			total_invoice_value_issued = daily_invoice_metrics.total_invoice_value_issued + EXCLUDED.total_invoice_value_issued,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	if err != nil {
		return fmt.Errorf("increment daily invoice issued: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyInvoicePaid(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal, daysToPay *int) error {
	// First, insert/update the paid counts and amount
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date, total_invoices_paid, total_paid_value, avg_days_to_payment, updated_at)
		VALUES ($1, $2, 1, $3, $4, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_invoices_paid = daily_invoice_metrics.total_invoices_paid + 1,
			total_paid_value = daily_invoice_metrics.total_paid_value + EXCLUDED.total_paid_value,
			avg_days_to_payment = (COALESCE(daily_invoice_metrics.avg_days_to_payment, 0) * (daily_invoice_metrics.total_invoices_paid) + COALESCE(EXCLUDED.avg_days_to_payment, 0)) / (daily_invoice_metrics.total_invoices_paid + 1),
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, amount, daysToPay)
	if err != nil {
		return fmt.Errorf("increment daily invoice paid: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyInvoiceOverdue(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date, total_invoices_overdue, total_overdue_value, updated_at)
		VALUES ($1, $2, 1, $3, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_invoices_overdue = daily_invoice_metrics.total_invoices_overdue + 1,
			total_overdue_value = daily_invoice_metrics.total_overdue_value + EXCLUDED.total_overdue_value,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	if err != nil {
		return fmt.Errorf("increment daily invoice overdue: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyInvoiceCancelled(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error {
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date, total_invoices_cancelled, updated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_invoices_cancelled = daily_invoice_metrics.total_invoices_cancelled + 1,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date)
	if err != nil {
		return fmt.Errorf("increment daily invoice cancelled: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RecordEarlyDiscount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, discountAmount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_invoice_metrics
			(company_id, date, early_discount_taken_count, early_discount_amount, updated_at)
		VALUES ($1, $2, 1, $3, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			early_discount_taken_count = daily_invoice_metrics.early_discount_taken_count + 1,
			early_discount_amount = daily_invoice_metrics.early_discount_amount + EXCLUDED.early_discount_amount,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, discountAmount)
	if err != nil {
		return fmt.Errorf("record early discount: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpsertInvoiceAgingSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.InvoiceAgingSnapshot) error {
	query := `
		INSERT INTO sales_analytics.invoice_aging_snapshot
			(company_id, snapshot_date,
			 bucket_0_30_days, bucket_31_60_days, bucket_61_90_days, bucket_over_90_days,
			 total_outstanding, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, snapshot_date) DO UPDATE SET
			bucket_0_30_days = EXCLUDED.bucket_0_30_days,
			bucket_31_60_days = EXCLUDED.bucket_31_60_days,
			bucket_61_90_days = EXCLUDED.bucket_61_90_days,
			bucket_over_90_days = EXCLUDED.bucket_over_90_days,
			total_outstanding = EXCLUDED.total_outstanding,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		snapshot.CompanyID, snapshot.SnapshotDate,
		snapshot.Bucket0_30Days, snapshot.Bucket31_60Days, snapshot.Bucket61_90Days, snapshot.BucketOver90Days,
		snapshot.TotalOutstanding,
	)
	if err != nil {
		return fmt.Errorf("upsert invoice aging snapshot: %w", err)
	}
	return nil
}

// RefreshInvoiceAgingSnapshot computes the aging buckets from unpaid invoices as of snapshotDate.
func (r *analyticsRepository) RefreshInvoiceAgingSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error {
	// This query calculates outstanding amounts per aging bucket based on due_date.
	// Invoices with status = 'issued' or 'overdue' and amount_due > 0 are considered.
	query := `
		WITH aging AS (
			SELECT
				SUM(CASE WHEN due_date - $2 <= 30 THEN amount_due ELSE 0 END) AS bucket_0_30,
				SUM(CASE WHEN due_date - $2 BETWEEN 31 AND 60 THEN amount_due ELSE 0 END) AS bucket_31_60,
				SUM(CASE WHEN due_date - $2 BETWEEN 61 AND 90 THEN amount_due ELSE 0 END) AS bucket_61_90,
				SUM(CASE WHEN due_date - $2 > 90 THEN amount_due ELSE 0 END) AS bucket_over_90,
				SUM(amount_due) AS total
			FROM sales.invoices
			WHERE company_id = $1
			  AND status IN ('issued', 'overdue')
			  AND amount_due > 0
		)
		INSERT INTO sales_analytics.invoice_aging_snapshot
			(company_id, snapshot_date,
			 bucket_0_30_days, bucket_31_60_days, bucket_61_90_days, bucket_over_90_days,
			 total_outstanding, created_at)
		SELECT $1, $2,
		       COALESCE(bucket_0_30, 0),
		       COALESCE(bucket_31_60, 0),
		       COALESCE(bucket_61_90, 0),
		       COALESCE(bucket_over_90, 0),
		       COALESCE(total, 0),
		       NOW()
		FROM aging
		ON CONFLICT (company_id, snapshot_date) DO UPDATE SET
			bucket_0_30_days = EXCLUDED.bucket_0_30_days,
			bucket_31_60_days = EXCLUDED.bucket_31_60_days,
			bucket_61_90_days = EXCLUDED.bucket_61_90_days,
			bucket_over_90_days = EXCLUDED.bucket_over_90_days,
			total_outstanding = EXCLUDED.total_outstanding,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		return fmt.Errorf("refresh invoice aging snapshot: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Payment Method Daily
// --------------------------------------------------------------------------

func (r *analyticsRepository) UpsertPaymentMethodDaily(ctx context.Context, db DBTX, record *sales_analytics.PaymentMethodDaily) error {
	query := `
        INSERT INTO sales_analytics.payment_method_daily (
            company_id, date, payment_method, payment_count, total_amount, updated_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (company_id, date, payment_method) DO UPDATE SET
            payment_count = EXCLUDED.payment_count,
            total_amount = EXCLUDED.total_amount,
            updated_at = NOW()
        RETURNING id
    `
	err := db.QueryRowContext(ctx, query,
		record.CompanyID,
		record.Date,
		record.PaymentMethod,
		record.PaymentCount,
		record.TotalAmount,
	).Scan(&record.ID)
	if err != nil {
		return fmt.Errorf("upsert payment method daily: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementPaymentMethodDaily(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, method enums.PaymentMethod, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.payment_method_daily (company_id, date, payment_method, payment_count, total_amount, updated_at)
        VALUES ($1, $2, $3, 1, $4, NOW())
        ON CONFLICT (company_id, date, payment_method) DO UPDATE SET
            payment_count = payment_method_daily.payment_count + 1,
            total_amount = payment_method_daily.total_amount + EXCLUDED.total_amount,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, method, amount)
	if err != nil {
		return fmt.Errorf("increment payment method daily: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Refund Metrics
// --------------------------------------------------------------------------

func (r *analyticsRepository) UpsertRefundMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.RefundMetrics) error {
	query := `
        INSERT INTO sales_analytics.refund_metrics (
            company_id, date, refund_count, total_refund_amount,
            partial_refund_count, full_refund_count, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            refund_count = EXCLUDED.refund_count,
            total_refund_amount = EXCLUDED.total_refund_amount,
            partial_refund_count = EXCLUDED.partial_refund_count,
            full_refund_count = EXCLUDED.full_refund_count,
            updated_at = NOW()
        RETURNING id
    `
	err := db.QueryRowContext(ctx, query,
		metrics.CompanyID,
		metrics.Date,
		metrics.RefundCount,
		metrics.TotalRefundAmount,
		metrics.PartialRefundCount,
		metrics.FullRefundCount,
	).Scan(&metrics.ID)
	if err != nil {
		return fmt.Errorf("upsert refund metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementRefundMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal, isFullRefund bool) error {
	partialInc := 0
	fullInc := 0
	if isFullRefund {
		fullInc = 1
	} else {
		partialInc = 1
	}

	query := `
        INSERT INTO sales_analytics.refund_metrics (company_id, date, refund_count, total_refund_amount, partial_refund_count, full_refund_count, updated_at)
        VALUES ($1, $2, 1, $3, $4, $5, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            refund_count = refund_metrics.refund_count + 1,
            total_refund_amount = refund_metrics.total_refund_amount + EXCLUDED.total_refund_amount,
            partial_refund_count = refund_metrics.partial_refund_count + EXCLUDED.partial_refund_count,
            full_refund_count = refund_metrics.full_refund_count + EXCLUDED.full_refund_count,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, date, amount, partialInc, fullInc)
	if err != nil {
		return fmt.Errorf("increment refund metrics: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Payment Aging Snapshot
// --------------------------------------------------------------------------

func (r *analyticsRepository) RefreshPaymentAgingSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error {
	// Compute aging buckets for completed payments that are not fully allocated
	query := `
        WITH unallocated_payments AS (
            SELECT 
                p.payment_id,
                p.payment_date,
                p.amount,
                COALESCE(SUM(pa.amount), 0) as allocated_amount,
                p.amount - COALESCE(SUM(pa.amount), 0) as unallocated_amount
            FROM sales.payments p
            LEFT JOIN sales.payment_allocations pa ON p.payment_id = pa.payment_id
            WHERE p.company_id = $1
              AND p.status = 'completed'
            GROUP BY p.payment_id, p.payment_date, p.amount
            HAVING p.amount - COALESCE(SUM(pa.amount), 0) > 0
        ),
        aged AS (
            SELECT
                SUM(CASE WHEN payment_date >= $2 - INTERVAL '30 days' THEN unallocated_amount ELSE 0 END) as bucket0_30,
                SUM(CASE WHEN payment_date < $2 - INTERVAL '30 days' AND payment_date >= $2 - INTERVAL '60 days' THEN unallocated_amount ELSE 0 END) as bucket31_60,
                SUM(CASE WHEN payment_date < $2 - INTERVAL '60 days' AND payment_date >= $2 - INTERVAL '90 days' THEN unallocated_amount ELSE 0 END) as bucket61_90,
                SUM(CASE WHEN payment_date < $2 - INTERVAL '90 days' THEN unallocated_amount ELSE 0 END) as bucket_over90,
                SUM(unallocated_amount) as total_unallocated
            FROM unallocated_payments
        )
        INSERT INTO sales_analytics.payment_aging_snapshot (
            company_id, snapshot_date,
            bucket_0_30_days, bucket_31_60_days, bucket_61_90_days, bucket_over_90_days,
            total_unallocated, created_at
        )
        SELECT $1, $2,
               COALESCE(bucket0_30, 0),
               COALESCE(bucket31_60, 0),
               COALESCE(bucket61_90, 0),
               COALESCE(bucket_over90, 0),
               COALESCE(total_unallocated, 0),
               NOW()
        FROM aged
        ON CONFLICT (company_id, snapshot_date) DO UPDATE SET
            bucket_0_30_days = EXCLUDED.bucket_0_30_days,
            bucket_31_60_days = EXCLUDED.bucket_31_60_days,
            bucket_61_90_days = EXCLUDED.bucket_61_90_days,
            bucket_over_90_days = EXCLUDED.bucket_over_90_days,
            total_unallocated = EXCLUDED.total_unallocated,
            created_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		return fmt.Errorf("refresh payment aging snapshot: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Collection Efficiency
// --------------------------------------------------------------------------

func (r *analyticsRepository) UpdateCollectionEfficiency(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, dso, collectionRate *decimal.Decimal, receivables, collected decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.collection_efficiency (
            company_id, date, days_sales_outstanding, collection_rate,
            total_receivables, collected_amount, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            days_sales_outstanding = EXCLUDED.days_sales_outstanding,
            collection_rate = EXCLUDED.collection_rate,
            total_receivables = EXCLUDED.total_receivables,
            collected_amount = EXCLUDED.collected_amount,
            updated_at = NOW()
    `
	var dsoValue, rateValue interface{}
	if dso != nil {
		dsoValue = *dso
	} else {
		dsoValue = nil
	}
	if collectionRate != nil {
		rateValue = *collectionRate
	} else {
		rateValue = nil
	}
	_, err := db.ExecContext(ctx, query, companyID, date, dsoValue, rateValue, receivables, collected)
	if err != nil {
		return fmt.Errorf("update collection efficiency: %w", err)
	}
	return nil
}

// -------------------- Automatic Discount Metrics --------------------
func (r *analyticsRepository) IncrementAutomaticDiscountMetrics(ctx context.Context, db DBTX, companyID, autoDiscountID uuid.UUID, date time.Time, discountAmount, orderAmount decimal.Decimal, customerID uuid.UUID) error {
	// Step 1: Insert into bridge table to track unique customer for this discount on this day.
	// If the row already exists, do nothing.
	bridgeQuery := `
		INSERT INTO sales_analytics.auto_discount_unique_customers
			(company_id, auto_discount_id, date, customer_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, auto_discount_id, date, customer_id) DO NOTHING
	`
	result, err := db.ExecContext(ctx, bridgeQuery, companyID, autoDiscountID, date, customerID)
	if err != nil {
		return fmt.Errorf("insert into auto_discount_unique_customers: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	isNewUnique := rowsAffected > 0

	// Step 2: Update the main metrics table.
	// If this is a new unique customer, increment unique_customers by 1.
	var mainQuery string
	if isNewUnique {
		mainQuery = `
			INSERT INTO sales_analytics.automatic_discount_metrics
				(company_id, auto_discount_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 1, NOW())
			ON CONFLICT (company_id, auto_discount_id, date) DO UPDATE SET
				times_applied = automatic_discount_metrics.times_applied + 1,
				total_discount_amount = automatic_discount_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = automatic_discount_metrics.total_order_value + EXCLUDED.total_order_value,
				unique_customers = automatic_discount_metrics.unique_customers + 1,
				updated_at = NOW()
		`
	} else {
		mainQuery = `
			INSERT INTO sales_analytics.automatic_discount_metrics
				(company_id, auto_discount_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 0, NOW())
			ON CONFLICT (company_id, auto_discount_id, date) DO UPDATE SET
				times_applied = automatic_discount_metrics.times_applied + 1,
				total_discount_amount = automatic_discount_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = automatic_discount_metrics.total_order_value + EXCLUDED.total_order_value,
				updated_at = NOW()
		`
	}

	_, err = db.ExecContext(ctx, mainQuery, companyID, autoDiscountID, date, discountAmount, orderAmount)
	if err != nil {
		return fmt.Errorf("update automatic discount metrics: %w", err)
	}
	return nil
}

// -------------------- Stacking Rule Usage --------------------
func (r *analyticsRepository) IncrementStackingRuleUsage(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID, date time.Time, combinedDiscount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.discount_stacking_usage
            (company_id, rule_id, date, times_used, total_combined_discount, updated_at)
        VALUES ($1, $2, $3, 1, $4, NOW())
        ON CONFLICT (company_id, rule_id, date) DO UPDATE SET
            times_used = discount_stacking_usage.times_used + 1,
            total_combined_discount = discount_stacking_usage.total_combined_discount + EXCLUDED.total_combined_discount,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, ruleID, date, combinedDiscount)
	if err != nil {
		return fmt.Errorf("increment stacking rule usage: %w", err)
	}
	return nil
}

// RecordCouponUsageFact inserts a row into coupon_usage_fact.
// It does not update aggregated tables – call IncrementCouponDailyMetrics separately.
func (r *analyticsRepository) RecordCouponUsageFact(ctx context.Context, db DBTX, fact *sales_analytics.CouponUsageFact) error {
	query := `
		INSERT INTO sales_analytics.coupon_usage_fact
			(company_id, coupon_id, entity_type, entity_id, customer_id,
			 discount_amount, order_subtotal, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (company_id, coupon_id, entity_type, entity_id) DO NOTHING
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.CouponID, fact.EntityType, fact.EntityID, fact.CustomerID,
		fact.DiscountAmount, fact.OrderSubtotal, fact.UsedAt,
	)
	if err != nil {
		return fmt.Errorf("record coupon usage fact: %w", err)
	}
	return nil
}

// IncrementCouponDailyMetrics updates daily_coupon_metrics and unique customer tracking.
// It mirrors the logic used for automatic discounts.
func (r *analyticsRepository) IncrementCouponDailyMetrics(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, date time.Time, discountAmount, orderSubtotal decimal.Decimal, customerID uuid.UUID) error {
	// 1. Insert into daily unique customer bridge table (if not already present)
	bridgeQuery := `
		INSERT INTO sales_analytics.daily_coupon_unique_customers
			(company_id, coupon_id, date, customer_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, coupon_id, date, customer_id) DO NOTHING
	`
	result, err := db.ExecContext(ctx, bridgeQuery, companyID, couponID, date, customerID)
	if err != nil {
		return fmt.Errorf("insert into daily_coupon_unique_customers: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	isNewUnique := rowsAffected > 0

	// 2. Update daily_coupon_metrics
	var mainQuery string
	if isNewUnique {
		mainQuery = `
			INSERT INTO sales_analytics.daily_coupon_metrics
				(company_id, coupon_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 1, NOW())
			ON CONFLICT (company_id, coupon_id, date) DO UPDATE SET
				times_applied = daily_coupon_metrics.times_applied + 1,
				total_discount_amount = daily_coupon_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = daily_coupon_metrics.total_order_value + EXCLUDED.total_order_value,
				unique_customers = daily_coupon_metrics.unique_customers + 1,
				updated_at = NOW()
		`
	} else {
		mainQuery = `
			INSERT INTO sales_analytics.daily_coupon_metrics
				(company_id, coupon_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 0, NOW())
			ON CONFLICT (company_id, coupon_id, date) DO UPDATE SET
				times_applied = daily_coupon_metrics.times_applied + 1,
				total_discount_amount = daily_coupon_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = daily_coupon_metrics.total_order_value + EXCLUDED.total_order_value,
				updated_at = NOW()
		`
	}
	_, err = db.ExecContext(ctx, mainQuery, companyID, couponID, date, discountAmount, orderSubtotal)
	if err != nil {
		return fmt.Errorf("update daily coupon metrics: %w", err)
	}
	return nil
}

// UpdateCouponPerformanceSummary updates the lifetime summary for a coupon.
// It increments total_times_used, total_discount_given, updates avg_discount_per_use and last_used_at.
// It also manages the coupon_unique_customers bridge table (for unique customers over coupon lifetime).
func (r *analyticsRepository) UpdateCouponPerformanceSummary(ctx context.Context, db DBTX, companyID, couponID uuid.UUID, discountAmount decimal.Decimal, customerID *uuid.UUID, usedAt time.Time) error {
	// 1. Track unique customer for this coupon over its lifetime (if customerID provided)
	if customerID != nil {
		bridgeQuery := `
			INSERT INTO sales_analytics.coupon_unique_customers
				(company_id, coupon_id, customer_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (company_id, coupon_id, customer_id) DO NOTHING
		`
		_, err := db.ExecContext(ctx, bridgeQuery, companyID, couponID, *customerID)
		if err != nil {
			r.logger.Warn("failed to insert coupon_unique_customer", zap.Error(err))
			// Continue – do not fail the whole operation
		}
	}

	// 2. Update the performance summary using a CTE to compute new average
	query := `
		WITH old AS (
			SELECT total_times_used, total_discount_given, unique_customers
			FROM sales_analytics.coupon_performance_summary
			WHERE coupon_id = $2 AND company_id = $1
		)
		INSERT INTO sales_analytics.coupon_performance_summary
			(coupon_id, company_id, total_times_used, total_discount_given, avg_discount_per_use, unique_customers, last_used_at, updated_at)
		VALUES ($2, $1, 1, $3, $3, 1, $4, NOW())
		ON CONFLICT (coupon_id) DO UPDATE SET
			total_times_used = coupon_performance_summary.total_times_used + 1,
			total_discount_given = coupon_performance_summary.total_discount_given + EXCLUDED.total_discount_given,
			avg_discount_per_use = (coupon_performance_summary.total_discount_given + EXCLUDED.total_discount_given) / (coupon_performance_summary.total_times_used + 1),
			unique_customers = (SELECT COUNT(*) FROM sales_analytics.coupon_unique_customers WHERE coupon_id = $2),
			last_used_at = EXCLUDED.last_used_at,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, couponID, discountAmount, usedAt)
	if err != nil {
		return fmt.Errorf("update coupon performance summary: %w", err)
	}
	return nil
}

// UpdateCustomerCouponUsage updates the per-customer usage of a coupon.
func (r *analyticsRepository) UpdateCustomerCouponUsage(ctx context.Context, db DBTX, companyID, couponID, customerID uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	query := `
		INSERT INTO sales_analytics.customer_coupon_usage
			(company_id, coupon_id, customer_id, usage_count, total_discount, first_used_at, last_used_at)
		VALUES ($1, $2, $3, 1, $4, $5, $5)
		ON CONFLICT (company_id, coupon_id, customer_id) DO UPDATE SET
			usage_count = customer_coupon_usage.usage_count + 1,
			total_discount = customer_coupon_usage.total_discount + EXCLUDED.total_discount,
			last_used_at = EXCLUDED.last_used_at,
			first_used_at = COALESCE(customer_coupon_usage.first_used_at, EXCLUDED.first_used_at)
	`
	_, err := db.ExecContext(ctx, query, companyID, couponID, customerID, discountAmount, usedAt)
	if err != nil {
		return fmt.Errorf("update customer coupon usage: %w", err)
	}
	return nil
}

// RecordPromotionUsageFact inserts a row into promotion_usage_fact.
// It does not update aggregated tables – call IncrementPromotionDailyMetrics separately.
func (r *analyticsRepository) RecordPromotionUsageFact(ctx context.Context, db DBTX, fact *sales_analytics.PromotionUsageFact) error {
	query := `
		INSERT INTO sales_analytics.promotion_usage_fact
			(company_id, promotion_id, entity_type, entity_id, customer_id,
			 discount_amount, order_subtotal, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (company_id, promotion_id, entity_type, entity_id) DO NOTHING
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.PromotionID, fact.EntityType, fact.EntityID, fact.CustomerID,
		fact.DiscountAmount, fact.OrderSubtotal, fact.UsedAt,
	)
	if err != nil {
		return fmt.Errorf("record promotion usage fact: %w", err)
	}
	return nil
}

// IncrementPromotionDailyMetrics updates daily_promotion_metrics and unique customer tracking.
func (r *analyticsRepository) IncrementPromotionDailyMetrics(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, date time.Time, discountAmount, orderSubtotal decimal.Decimal, customerID uuid.UUID) error {
	// 1. Insert into daily unique customer bridge table (if not already present)
	bridgeQuery := `
		INSERT INTO sales_analytics.daily_promotion_unique_customers
			(company_id, promotion_id, date, customer_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, promotion_id, date, customer_id) DO NOTHING
	`
	result, err := db.ExecContext(ctx, bridgeQuery, companyID, promotionID, date, customerID)
	if err != nil {
		return fmt.Errorf("insert into daily_promotion_unique_customers: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	isNewUnique := rowsAffected > 0

	// 2. Update daily_promotion_metrics
	var mainQuery string
	if isNewUnique {
		mainQuery = `
			INSERT INTO sales_analytics.daily_promotion_metrics
				(company_id, promotion_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 1, NOW())
			ON CONFLICT (company_id, promotion_id, date) DO UPDATE SET
				times_applied = daily_promotion_metrics.times_applied + 1,
				total_discount_amount = daily_promotion_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = daily_promotion_metrics.total_order_value + EXCLUDED.total_order_value,
				unique_customers = daily_promotion_metrics.unique_customers + 1,
				updated_at = NOW()
		`
	} else {
		mainQuery = `
			INSERT INTO sales_analytics.daily_promotion_metrics
				(company_id, promotion_id, date, times_applied, total_discount_amount, total_order_value, unique_customers, updated_at)
			VALUES ($1, $2, $3, 1, $4, $5, 0, NOW())
			ON CONFLICT (company_id, promotion_id, date) DO UPDATE SET
				times_applied = daily_promotion_metrics.times_applied + 1,
				total_discount_amount = daily_promotion_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
				total_order_value = daily_promotion_metrics.total_order_value + EXCLUDED.total_order_value,
				updated_at = NOW()
		`
	}
	_, err = db.ExecContext(ctx, mainQuery, companyID, promotionID, date, discountAmount, orderSubtotal)
	if err != nil {
		return fmt.Errorf("update daily promotion metrics: %w", err)
	}
	return nil
}

// UpdatePromotionPerformanceSummary updates the lifetime summary for a promotion.
func (r *analyticsRepository) UpdatePromotionPerformanceSummary(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, discountAmount decimal.Decimal, customerID *uuid.UUID, usedAt time.Time) error {
	// 1. Track unique customer for this promotion over its lifetime (if customerID provided)
	if customerID != nil {
		bridgeQuery := `
			INSERT INTO sales_analytics.promotion_unique_customers
				(company_id, promotion_id, customer_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (company_id, promotion_id, customer_id) DO NOTHING
		`
		_, err := db.ExecContext(ctx, bridgeQuery, companyID, promotionID, *customerID)
		if err != nil {
			r.logger.Warn("failed to insert promotion_unique_customer", zap.Error(err))
			// Continue – do not fail the whole operation
		}
	}

	// 2. Update the performance summary using a CTE to compute new average
	query := `
		WITH old AS (
			SELECT total_times_used, total_discount_given, unique_customers
			FROM sales_analytics.promotion_performance_summary
			WHERE promotion_id = $2 AND company_id = $1
		)
		INSERT INTO sales_analytics.promotion_performance_summary
			(promotion_id, company_id, total_times_used, total_discount_given, avg_discount_per_use, unique_customers, last_used_at, updated_at)
		VALUES ($2, $1, 1, $3, $3, 1, $4, NOW())
		ON CONFLICT (promotion_id) DO UPDATE SET
			total_times_used = promotion_performance_summary.total_times_used + 1,
			total_discount_given = promotion_performance_summary.total_discount_given + EXCLUDED.total_discount_given,
			avg_discount_per_use = (promotion_performance_summary.total_discount_given + EXCLUDED.total_discount_given) / (promotion_performance_summary.total_times_used + 1),
			unique_customers = (SELECT COUNT(*) FROM sales_analytics.promotion_unique_customers WHERE promotion_id = $2),
			last_used_at = EXCLUDED.last_used_at,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, promotionID, discountAmount, usedAt)
	if err != nil {
		return fmt.Errorf("update promotion performance summary: %w", err)
	}
	return nil
}

// UpdateCustomerPromotionUsage updates the per-customer usage of a promotion.
func (r *analyticsRepository) UpdateCustomerPromotionUsage(ctx context.Context, db DBTX, companyID, promotionID, customerID uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	query := `
		INSERT INTO sales_analytics.customer_promotion_usage
			(company_id, promotion_id, customer_id, usage_count, total_discount, first_used_at, last_used_at)
		VALUES ($1, $2, $3, 1, $4, $5, $5)
		ON CONFLICT (company_id, promotion_id, customer_id) DO UPDATE SET
			usage_count = customer_promotion_usage.usage_count + 1,
			total_discount = customer_promotion_usage.total_discount + EXCLUDED.total_discount,
			last_used_at = EXCLUDED.last_used_at,
			first_used_at = COALESCE(customer_promotion_usage.first_used_at, EXCLUDED.first_used_at)
	`
	_, err := db.ExecContext(ctx, query, companyID, promotionID, customerID, discountAmount, usedAt)
	if err != nil {
		return fmt.Errorf("update customer promotion usage: %w", err)
	}
	return nil
}

// -------------------- Daily Return Metrics --------------------

func (r *analyticsRepository) UpsertDailyReturnMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyReturnMetrics) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_returns_requested, total_returns_approved,
			 total_returns_completed, total_returns_rejected,
			 total_refund_amount, total_credit_note_amount,
			 unique_customers, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_returns_requested = EXCLUDED.total_returns_requested,
			total_returns_approved = EXCLUDED.total_returns_approved,
			total_returns_completed = EXCLUDED.total_returns_completed,
			total_returns_rejected = EXCLUDED.total_returns_rejected,
			total_refund_amount = EXCLUDED.total_refund_amount,
			total_credit_note_amount = EXCLUDED.total_credit_note_amount,
			unique_customers = EXCLUDED.unique_customers,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		metrics.CompanyID, metrics.Date,
		metrics.TotalReturnsRequested, metrics.TotalReturnsApproved,
		metrics.TotalReturnsCompleted, metrics.TotalReturnsRejected,
		metrics.TotalRefundAmount, metrics.TotalCreditNoteAmount,
		metrics.UniqueCustomers,
	)
	if err != nil {
		return fmt.Errorf("upsert daily return metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyReturnRequests(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_returns_requested, updated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_returns_requested = daily_return_metrics.total_returns_requested + 1,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date)
	if err != nil {
		return fmt.Errorf("increment daily return requests: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyReturnApprovals(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_returns_approved, updated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_returns_approved = daily_return_metrics.total_returns_approved + 1,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date)
	if err != nil {
		return fmt.Errorf("increment daily return approvals: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyReturnCompletions(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, refundAmount, creditNoteAmount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_returns_completed, total_refund_amount, total_credit_note_amount, updated_at)
		VALUES ($1, $2, 1, $3, $4, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_returns_completed = daily_return_metrics.total_returns_completed + 1,
			total_refund_amount = daily_return_metrics.total_refund_amount + EXCLUDED.total_refund_amount,
			total_credit_note_amount = daily_return_metrics.total_credit_note_amount + EXCLUDED.total_credit_note_amount,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, refundAmount, creditNoteAmount)
	if err != nil {
		return fmt.Errorf("increment daily return completions: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyReturnRejections(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_returns_rejected, updated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_returns_rejected = daily_return_metrics.total_returns_rejected + 1,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date)
	if err != nil {
		return fmt.Errorf("increment daily return rejections: %w", err)
	}
	return nil
}

func (r *analyticsRepository) AddDailyRefundAmount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_refund_amount, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_refund_amount = daily_return_metrics.total_refund_amount + EXCLUDED.total_refund_amount,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	if err != nil {
		return fmt.Errorf("add daily refund amount: %w", err)
	}
	return nil
}

func (r *analyticsRepository) AddDailyCreditNoteAmount(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.daily_return_metrics
			(company_id, date, total_credit_note_amount, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			total_credit_note_amount = daily_return_metrics.total_credit_note_amount + EXCLUDED.total_credit_note_amount,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, date, amount)
	if err != nil {
		return fmt.Errorf("add daily credit note amount: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementDailyReturnUniqueCustomer(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, customerID uuid.UUID) error {
	// Insert into bridge table
	bridgeQuery := `
		INSERT INTO sales_analytics.daily_return_unique_customers (company_id, date, customer_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (company_id, date, customer_id) DO NOTHING
	`
	result, err := db.ExecContext(ctx, bridgeQuery, companyID, date, customerID)
	if err != nil {
		return fmt.Errorf("insert daily return unique customer: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Already counted
		return nil
	}

	// Increment unique_customers in daily_return_metrics
	updateQuery := `
		INSERT INTO sales_analytics.daily_return_metrics (company_id, date, unique_customers, updated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			unique_customers = daily_return_metrics.unique_customers + 1,
			updated_at = NOW()
	`
	_, err = db.ExecContext(ctx, updateQuery, companyID, date)
	if err != nil {
		return fmt.Errorf("increment daily return unique customers count: %w", err)
	}
	return nil
}

// -------------------- Return Reason Fact --------------------

func (r *analyticsRepository) InsertReturnReasonFact(ctx context.Context, db DBTX, fact *sales_analytics.ReturnReasonFact) error {
	query := `
		INSERT INTO sales_analytics.return_reason_fact
			(company_id, return_id, return_item_id, reason_code, reason_text,
			 product_id, quantity_returned, refund_amount, return_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.ReturnID, fact.ReturnItemID,
		fact.ReasonCode, fact.ReasonText, fact.ProductID,
		fact.QuantityReturned, fact.RefundAmount, fact.ReturnDate,
	)
	if err != nil {
		return fmt.Errorf("insert return reason fact: %w", err)
	}
	return nil
}

// -------------------- Return Processing Time Fact --------------------

func (r *analyticsRepository) InsertReturnProcessingTime(ctx context.Context, db DBTX, fact *sales_analytics.ReturnProcessingTimeFact) error {
	query := `
		INSERT INTO sales_analytics.return_processing_time_fact
			(company_id, return_id, status, entered_at, exited_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.ReturnID, fact.Status,
		fact.EnteredAt, fact.ExitedAt,
	)
	if err != nil {
		return fmt.Errorf("insert return processing time: %w", err)
	}
	return nil
}

func (r *analyticsRepository) CloseReturnProcessingTime(ctx context.Context, db DBTX, returnID uuid.UUID, status enums.ReturnStatus, exitedAt time.Time) error {
	query := `
		UPDATE sales_analytics.return_processing_time_fact
		SET exited_at = $3
		WHERE return_id = $1 AND status = $2 AND exited_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, status, exitedAt)
	if err != nil {
		return fmt.Errorf("close return processing time: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no open return processing time found to close",
			zap.String("return_id", returnID.String()),
			zap.String("status", string(status)))
	}
	return nil
}

// -------------------- Credit Note Fact --------------------

func (r *analyticsRepository) InsertCreditNoteFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditNoteFact) error {
	query := `
		INSERT INTO sales_analytics.credit_note_fact
			(company_id, credit_note_id, return_id, issued_date, issued_amount,
			 applied_amount, applied_to_invoice_id, applied_date, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.CreditNoteID, fact.ReturnID,
		fact.IssuedDate, fact.IssuedAmount, fact.AppliedAmount,
		fact.AppliedToInvoiceID, fact.AppliedDate, fact.Status,
	)
	if err != nil {
		return fmt.Errorf("insert credit note fact: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateCreditNoteAppliedAmount(ctx context.Context, db DBTX, creditNoteID uuid.UUID, appliedAmount decimal.Decimal, appliedToInvoiceID *uuid.UUID, appliedDate *time.Time, status string) error {
	query := `
		UPDATE sales_analytics.credit_note_fact
		SET applied_amount = $2,
		    applied_to_invoice_id = COALESCE($3, applied_to_invoice_id),
		    applied_date = COALESCE($4, applied_date),
		    status = $5,
		    created_at = NOW()
		WHERE credit_note_id = $1
	`
	_, err := db.ExecContext(ctx, query, creditNoteID, appliedAmount, appliedToInvoiceID, appliedDate, status)
	if err != nil {
		return fmt.Errorf("update credit note applied amount: %w", err)
	}
	return nil
}

// -------------------- Refund Fact --------------------

func (r *analyticsRepository) InsertRefundFact(ctx context.Context, db DBTX, fact *sales_analytics.RefundFact) error {
	query := `
		INSERT INTO sales_analytics.refund_fact
			(company_id, refund_id, return_id, payment_id, amount, refund_date,
			 refund_method, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.RefundID, fact.ReturnID, fact.PaymentID,
		fact.Amount, fact.RefundDate, fact.RefundMethod, fact.Status,
	)
	if err != nil {
		return fmt.Errorf("insert refund fact: %w", err)
	}
	return nil
}

// -------------------- Return Product Category Fact --------------------

func (r *analyticsRepository) UpsertReturnProductCategoryFact(ctx context.Context, db DBTX, fact *sales_analytics.ReturnProductCategoryFact) error {
	query := `
		INSERT INTO sales_analytics.return_product_category_fact
			(company_id, category_id, category_name, return_date,
			 quantity_returned, refund_amount, unique_returns, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, category_id, return_date) DO UPDATE SET
			quantity_returned = return_product_category_fact.quantity_returned + EXCLUDED.quantity_returned,
			refund_amount = return_product_category_fact.refund_amount + EXCLUDED.refund_amount,
			unique_returns = return_product_category_fact.unique_returns + EXCLUDED.unique_returns,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.CategoryID, fact.CategoryName,
		fact.ReturnDate, fact.QuantityReturned, fact.RefundAmount,
		fact.UniqueReturns,
	)
	if err != nil {
		return fmt.Errorf("upsert return product category fact: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementReturnProductCategory(ctx context.Context, db DBTX, companyID uuid.UUID, categoryID *uuid.UUID, categoryName *string, returnDate time.Time, quantity decimal.Decimal, refundAmount decimal.Decimal, isUniqueReturn bool) error {
	uniqueInc := 0
	if isUniqueReturn {
		uniqueInc = 1
	}
	query := `
		INSERT INTO sales_analytics.return_product_category_fact
			(company_id, category_id, category_name, return_date,
			 quantity_returned, refund_amount, unique_returns, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, category_id, return_date) DO UPDATE SET
			quantity_returned = return_product_category_fact.quantity_returned + EXCLUDED.quantity_returned,
			refund_amount = return_product_category_fact.refund_amount + EXCLUDED.refund_amount,
			unique_returns = return_product_category_fact.unique_returns + EXCLUDED.unique_returns,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		companyID, categoryID, categoryName, returnDate,
		quantity, refundAmount, uniqueInc,
	)
	if err != nil {
		return fmt.Errorf("increment return product category: %w", err)
	}
	return nil
}

// -------------------- Sales Rep Target Achievement --------------------

func (r *analyticsRepository) UpsertSalesRepTargetAchievement(ctx context.Context, db DBTX, achievement *sales_analytics.SalesRepTargetAchievement) error {
	query := `
        INSERT INTO sales_analytics.sales_rep_target_achievement
            (company_id, sales_rep_id, period_start, period_end,
             target_amount, actual_revenue, currency, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (company_id, sales_rep_id, period_start, period_end) DO UPDATE SET
            target_amount = EXCLUDED.target_amount,
            actual_revenue = EXCLUDED.actual_revenue,
            currency = EXCLUDED.currency,
            updated_at = NOW()
        RETURNING id
    `
	var id int64
	err := db.QueryRowContext(ctx, query,
		achievement.CompanyID,
		achievement.SalesRepID,
		achievement.PeriodStart,
		achievement.PeriodEnd,
		achievement.TargetAmount,
		achievement.ActualRevenue,
		achievement.Currency,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("upsert sales rep target achievement: %w", err)
	}
	achievement.ID = id
	return nil
}

func (r *analyticsRepository) UpdateSalesRepTargetAchievement(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time, actualRevenue decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.sales_rep_target_achievement
            (company_id, sales_rep_id, period_start, period_end, target_amount, actual_revenue, updated_at)
        SELECT $1, $2, $3, $4, target_amount, $5, NOW()
        FROM sales_analytics.sales_rep_target_achievement
        WHERE company_id = $1 AND sales_rep_id = $2 AND period_start = $3 AND period_end = $4
        ON CONFLICT (company_id, sales_rep_id, period_start, period_end) DO UPDATE SET
            actual_revenue = EXCLUDED.actual_revenue,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, salesRepID, periodStart, periodEnd, actualRevenue)
	if err != nil {
		return fmt.Errorf("update sales rep target achievement: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetSalesRepTargetAchievement(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*sales_analytics.SalesRepTargetAchievement, error) {
	query := `
        SELECT id, company_id, sales_rep_id, period_start, period_end,
               target_amount, actual_revenue, achievement_pct, currency,
               created_at, updated_at
        FROM sales_analytics.sales_rep_target_achievement
        WHERE company_id = $1 AND sales_rep_id = $2 AND period_start = $3 AND period_end = $4
    `
	var a sales_analytics.SalesRepTargetAchievement
	err := db.QueryRowContext(ctx, query, companyID, salesRepID, periodStart, periodEnd).Scan(
		&a.ID, &a.CompanyID, &a.SalesRepID, &a.PeriodStart, &a.PeriodEnd,
		&a.TargetAmount, &a.ActualRevenue, &a.AchievementPct, &a.Currency,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // not found is not an error
		}
		return nil, fmt.Errorf("get sales rep target achievement: %w", err)
	}
	return &a, nil
}

// -------------------- Sales Rep Commission Fact --------------------

func (r *analyticsRepository) UpsertSalesRepCommissionFact(ctx context.Context, db DBTX, fact *sales_analytics.SalesRepCommissionFact) error {
	query := `
        INSERT INTO sales_analytics.sales_rep_commission_fact
            (company_id, sales_rep_id, entity_type, entity_id,
             commission_base, commission_rate, commission_amount,
             earned_at, paid_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (company_id, entity_type, entity_id) DO UPDATE SET
            commission_base = EXCLUDED.commission_base,
            commission_rate = EXCLUDED.commission_rate,
            commission_amount = EXCLUDED.commission_amount,
            earned_at = EXCLUDED.earned_at,
            paid_at = EXCLUDED.paid_at,
            created_at = NOW()
        RETURNING id
    `
	var id int64
	err := db.QueryRowContext(ctx, query,
		fact.CompanyID, fact.SalesRepID, fact.EntityType, fact.EntityID,
		fact.CommissionBase, fact.CommissionRate, fact.CommissionAmount,
		fact.EarnedAt, fact.PaidAt,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("upsert sales rep commission fact: %w", err)
	}
	fact.ID = id
	return nil
}

func (r *analyticsRepository) GetSalesRepCommissionFacts(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, from, to *time.Time) ([]*sales_analytics.SalesRepCommissionFact, error) {
	var args []interface{}
	conditions := []string{"company_id = $1", "sales_rep_id = $2"}
	args = append(args, companyID, salesRepID)
	idx := 3
	if from != nil {
		conditions = append(conditions, fmt.Sprintf("earned_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conditions = append(conditions, fmt.Sprintf("earned_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	whereClause := strings.Join(conditions, " AND ")
	query := fmt.Sprintf(`
        SELECT id, company_id, sales_rep_id, entity_type, entity_id,
               commission_base, commission_rate, commission_amount,
               earned_at, paid_at, created_at
        FROM sales_analytics.sales_rep_commission_fact
        WHERE %s
        ORDER BY earned_at DESC
    `, whereClause)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get sales rep commission facts: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.SalesRepCommissionFact
	for rows.Next() {
		var f sales_analytics.SalesRepCommissionFact
		err := rows.Scan(
			&f.ID, &f.CompanyID, &f.SalesRepID, &f.EntityType, &f.EntityID,
			&f.CommissionBase, &f.CommissionRate, &f.CommissionAmount,
			&f.EarnedAt, &f.PaidAt, &f.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan commission fact: %w", err)
		}
		result = append(result, &f)
	}
	return result, rows.Err()
}

func (r *analyticsRepository) MarkCommissionPaid(ctx context.Context, db DBTX, companyID, factID uuid.UUID, paidAt time.Time) error {
	query := `
        UPDATE sales_analytics.sales_rep_commission_fact
        SET paid_at = $3
        WHERE company_id = $1 AND id = $2 AND paid_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, companyID, factID, paidAt)
	if err != nil {
		return fmt.Errorf("mark commission paid: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no unpaid commission fact found for id %s", factID)
	}
	return nil
}

// -------------------- Sales Rep Leaderboard Snapshot --------------------

func (r *analyticsRepository) UpsertSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.SalesRepLeaderboardSnapshot) error {
	query := `
        INSERT INTO sales_analytics.sales_rep_leaderboard_snapshot
            (company_id, snapshot_date, period_start, period_end,
             sales_rep_id, rank, revenue, orders_count, average_deal, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (company_id, snapshot_date, sales_rep_id) DO UPDATE SET
            period_start = EXCLUDED.period_start,
            period_end = EXCLUDED.period_end,
            rank = EXCLUDED.rank,
            revenue = EXCLUDED.revenue,
            orders_count = EXCLUDED.orders_count,
            average_deal = EXCLUDED.average_deal,
            created_at = NOW()
        RETURNING id
    `
	var id int64
	err := db.QueryRowContext(ctx, query,
		snapshot.CompanyID, snapshot.SnapshotDate, snapshot.PeriodStart, snapshot.PeriodEnd,
		snapshot.SalesRepID, snapshot.Rank, snapshot.Revenue, snapshot.OrdersCount, snapshot.AverageDeal,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("upsert sales rep leaderboard snapshot: %w", err)
	}
	snapshot.ID = id
	return nil
}

// RefreshSalesRepLeaderboardSnapshot computes the leaderboard for the given period and stores it as a snapshot.
func (r *analyticsRepository) RefreshSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate, periodStart, periodEnd time.Time) error {
	// Compute leaderboard from orders within the period
	query := `
        WITH leaderboard AS (
            SELECT
                o.sales_rep_id,
                COALESCE(SUM(o.grand_total), 0) as revenue,
                COUNT(o.order_id) as orders_count,
                COALESCE(AVG(o.grand_total), 0) as avg_deal,
                ROW_NUMBER() OVER (ORDER BY COALESCE(SUM(o.grand_total), 0) DESC) as rank
            FROM sales.sales_reps sr
            LEFT JOIN sales.orders o ON o.sales_rep_id = sr.sales_rep_id
                AND o.company_id = sr.company_id
                AND o.order_date BETWEEN $3 AND $4
                AND o.status IN ('confirmed', 'processing', 'shipped', 'delivered')
            WHERE sr.company_id = $1 AND sr.is_active = true
            GROUP BY o.sales_rep_id
        )
        INSERT INTO sales_analytics.sales_rep_leaderboard_snapshot
            (company_id, snapshot_date, period_start, period_end,
             sales_rep_id, rank, revenue, orders_count, average_deal, created_at)
        SELECT $1, $2, $3, $4,
               sales_rep_id, rank, revenue, orders_count, avg_deal, NOW()
        FROM leaderboard
        WHERE sales_rep_id IS NOT NULL
        ON CONFLICT (company_id, snapshot_date, sales_rep_id) DO UPDATE SET
            period_start = EXCLUDED.period_start,
            period_end = EXCLUDED.period_end,
            rank = EXCLUDED.rank,
            revenue = EXCLUDED.revenue,
            orders_count = EXCLUDED.orders_count,
            average_deal = EXCLUDED.average_deal,
            created_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate, periodStart, periodEnd)
	if err != nil {
		return fmt.Errorf("refresh sales rep leaderboard snapshot: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetSalesRepLeaderboardSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) ([]*sales_analytics.SalesRepLeaderboardSnapshot, error) {
	query := `
        SELECT id, company_id, snapshot_date, period_start, period_end,
               sales_rep_id, rank, revenue, orders_count, average_deal, created_at
        FROM sales_analytics.sales_rep_leaderboard_snapshot
        WHERE company_id = $1 AND snapshot_date = $2
        ORDER BY rank ASC
    `
	rows, err := db.QueryContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		return nil, fmt.Errorf("get sales rep leaderboard snapshot: %w", err)
	}
	defer rows.Close()

	var result []*sales_analytics.SalesRepLeaderboardSnapshot
	for rows.Next() {
		var s sales_analytics.SalesRepLeaderboardSnapshot
		err := rows.Scan(
			&s.ID, &s.CompanyID, &s.SnapshotDate, &s.PeriodStart, &s.PeriodEnd,
			&s.SalesRepID, &s.Rank, &s.Revenue, &s.OrdersCount, &s.AverageDeal, &s.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan leaderboard snapshot: %w", err)
		}
		result = append(result, &s)
	}
	return result, rows.Err()
}

// -------------------- Commission Plan Daily --------------------
func (r *analyticsRepository) UpsertCommissionPlanDaily(ctx context.Context, db DBTX, daily *sales_analytics.CommissionPlanDaily) error {
	query := `
		INSERT INTO sales_analytics.commission_plan_daily
			(company_id, plan_id, date,
			 total_commissions_earned, total_commissions_paid,
			 commission_count, average_rate, unique_sales_reps, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (company_id, plan_id, date) DO UPDATE SET
			total_commissions_earned = EXCLUDED.total_commissions_earned,
			total_commissions_paid = EXCLUDED.total_commissions_paid,
			commission_count = EXCLUDED.commission_count,
			average_rate = EXCLUDED.average_rate,
			unique_sales_reps = EXCLUDED.unique_sales_reps,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		daily.CompanyID, daily.PlanID, daily.Date,
		daily.TotalCommissionsEarned, daily.TotalCommissionsPaid,
		daily.CommissionCount, daily.AverageRate, daily.UniqueSalesReps,
	)
	if err != nil {
		return fmt.Errorf("upsert commission plan daily: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementCommissionPlanDaily(ctx context.Context, db DBTX, companyID, planID uuid.UUID, date time.Time, earnedAmount, paidAmount decimal.Decimal, rate decimal.Decimal, salesRepID uuid.UUID) error {
	// Check if this sales rep is already counted for this plan on this day
	// Requires the bridge table sales_analytics.commission_plan_unique_reps
	bridgeQuery := `
		INSERT INTO sales_analytics.commission_plan_unique_reps (company_id, plan_id, date, sales_rep_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, plan_id, date, sales_rep_id) DO NOTHING
		RETURNING 1
	`
	var inserted int
	err := db.QueryRowContext(ctx, bridgeQuery, companyID, planID, date, salesRepID).Scan(&inserted)
	isNewRep := err == nil // if no error, a row was inserted -> new unique rep

	var updateQuery string
	if isNewRep {
		updateQuery = `
			INSERT INTO sales_analytics.commission_plan_daily
				(company_id, plan_id, date,
				 total_commissions_earned, total_commissions_paid,
				 commission_count, average_rate, unique_sales_reps, updated_at)
			VALUES ($1, $2, $3, $4, $5, 1, $6, 1, NOW())
			ON CONFLICT (company_id, plan_id, date) DO UPDATE SET
				total_commissions_earned = commission_plan_daily.total_commissions_earned + EXCLUDED.total_commissions_earned,
				total_commissions_paid = commission_plan_daily.total_commissions_paid + EXCLUDED.total_commissions_paid,
				commission_count = commission_plan_daily.commission_count + 1,
				average_rate = (commission_plan_daily.average_rate * commission_plan_daily.commission_count + EXCLUDED.average_rate) / (commission_plan_daily.commission_count + 1),
				unique_sales_reps = commission_plan_daily.unique_sales_reps + 1,
				updated_at = NOW()
		`
	} else {
		updateQuery = `
			INSERT INTO sales_analytics.commission_plan_daily
				(company_id, plan_id, date,
				 total_commissions_earned, total_commissions_paid,
				 commission_count, average_rate, unique_sales_reps, updated_at)
			VALUES ($1, $2, $3, $4, $5, 1, $6, 0, NOW())
			ON CONFLICT (company_id, plan_id, date) DO UPDATE SET
				total_commissions_earned = commission_plan_daily.total_commissions_earned + EXCLUDED.total_commissions_earned,
				total_commissions_paid = commission_plan_daily.total_commissions_paid + EXCLUDED.total_commissions_paid,
				commission_count = commission_plan_daily.commission_count + 1,
				average_rate = (commission_plan_daily.average_rate * commission_plan_daily.commission_count + EXCLUDED.average_rate) / (commission_plan_daily.commission_count + 1),
				updated_at = NOW()
		`
	}
	_, err = db.ExecContext(ctx, updateQuery, companyID, planID, date, earnedAmount, paidAmount, rate)
	if err != nil {
		return fmt.Errorf("increment commission plan daily: %w", err)
	}
	return nil
}

// -------------------- Commission Rule Fact --------------------
func (r *analyticsRepository) UpsertCommissionRuleFact(ctx context.Context, db DBTX, fact *sales_analytics.CommissionRuleFact) error {
	query := `
		INSERT INTO sales_analytics.commission_rule_fact
			(company_id, rule_id, plan_id, date,
			 times_applied, total_commission_base, total_commission_amount, avg_rate, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (company_id, rule_id, date) DO UPDATE SET
			times_applied = EXCLUDED.times_applied,
			total_commission_base = EXCLUDED.total_commission_base,
			total_commission_amount = EXCLUDED.total_commission_amount,
			avg_rate = EXCLUDED.avg_rate,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.RuleID, fact.PlanID, fact.Date,
		fact.TimesApplied, fact.TotalCommissionBase, fact.TotalCommissionAmount, fact.AvgRate,
	)
	if err != nil {
		return fmt.Errorf("upsert commission rule fact: %w", err)
	}
	return nil
}

func (r *analyticsRepository) IncrementCommissionRuleFact(ctx context.Context, db DBTX, companyID, ruleID, planID uuid.UUID, date time.Time, commissionBase, commissionAmount decimal.Decimal, rate decimal.Decimal) error {
	query := `
		INSERT INTO sales_analytics.commission_rule_fact
			(company_id, rule_id, plan_id, date,
			 times_applied, total_commission_base, total_commission_amount, avg_rate, updated_at)
		VALUES ($1, $2, $3, $4, 1, $5, $6, $7, NOW())
		ON CONFLICT (company_id, rule_id, date) DO UPDATE SET
			times_applied = commission_rule_fact.times_applied + 1,
			total_commission_base = commission_rule_fact.total_commission_base + EXCLUDED.total_commission_base,
			total_commission_amount = commission_rule_fact.total_commission_amount + EXCLUDED.total_commission_amount,
			avg_rate = (commission_rule_fact.avg_rate * commission_rule_fact.times_applied + EXCLUDED.avg_rate) / (commission_rule_fact.times_applied + 1),
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, ruleID, planID, date, commissionBase, commissionAmount, rate)
	if err != nil {
		return fmt.Errorf("increment commission rule fact: %w", err)
	}
	return nil
}

// -------------------- Commission Assignment Fact --------------------
func (r *analyticsRepository) InsertCommissionAssignmentFact(ctx context.Context, db DBTX, fact *sales_analytics.CommissionAssignmentFact) error {
	query := `
		INSERT INTO sales_analytics.commission_assignment_fact
			(company_id, sales_rep_id, plan_id, assigned_at, removed_at, assigned_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.SalesRepID, fact.PlanID,
		fact.AssignedAt, fact.RemovedAt, fact.AssignedBy,
	)
	if err != nil {
		return fmt.Errorf("insert commission assignment fact: %w", err)
	}
	return nil
}

func (r *analyticsRepository) CloseCommissionAssignmentFact(ctx context.Context, db DBTX, companyID, salesRepID, planID uuid.UUID, removedAt time.Time) error {
	query := `
		UPDATE sales_analytics.commission_assignment_fact
		SET removed_at = $4
		WHERE company_id = $1 AND sales_rep_id = $2 AND plan_id = $3 AND removed_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, salesRepID, planID, removedAt)
	if err != nil {
		return fmt.Errorf("close commission assignment fact: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Not an error; assignment might have been never recorded or already closed
		return nil
	}
	return nil
}

// -------------------- Commission Lifecycle --------------------
func (r *analyticsRepository) InsertCommissionLifecycle(ctx context.Context, db DBTX, lifecycle *sales_analytics.CommissionLifecycle) error {
	query := `
		INSERT INTO sales_analytics.commission_lifecycle
			(commission_id, company_id, sales_rep_id, reference_type, reference_id,
			 earned_at, approved_at, paid_at, rejected_at, current_status, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		lifecycle.CommissionID, lifecycle.CompanyID, lifecycle.SalesRepID,
		lifecycle.ReferenceType, lifecycle.ReferenceID,
		lifecycle.EarnedAt, lifecycle.ApprovedAt, lifecycle.PaidAt, lifecycle.RejectedAt,
		lifecycle.CurrentStatus,
	)
	if err != nil {
		return fmt.Errorf("insert commission lifecycle: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateCommissionLifecycle(ctx context.Context, db DBTX, commissionID uuid.UUID, status string, approvedAt, paidAt, rejectedAt *time.Time) error {
	query := `
		UPDATE sales_analytics.commission_lifecycle
		SET current_status = $2,
		    approved_at = COALESCE($3, approved_at),
		    paid_at = COALESCE($4, paid_at),
		    rejected_at = COALESCE($5, rejected_at),
		    updated_at = NOW()
		WHERE commission_id = $1
	`
	_, err := db.ExecContext(ctx, query, commissionID, status, approvedAt, paidAt, rejectedAt)
	if err != nil {
		return fmt.Errorf("update commission lifecycle: %w", err)
	}
	return nil
}

// -------------------- Commission Forecast Snapshot --------------------
func (r *analyticsRepository) UpsertCommissionForecastSnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.CommissionForecastSnapshot) error {
	query := `
		INSERT INTO sales_analytics.commission_forecast_snapshot
			(company_id, snapshot_date, sales_rep_id,
			 expected_commission_from_open_orders, expected_commission_from_open_invoices,
			 total_expected_commission, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (company_id, snapshot_date, sales_rep_id) DO UPDATE SET
			expected_commission_from_open_orders = EXCLUDED.expected_commission_from_open_orders,
			expected_commission_from_open_invoices = EXCLUDED.expected_commission_from_open_invoices,
			total_expected_commission = EXCLUDED.total_expected_commission,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		snapshot.CompanyID, snapshot.SnapshotDate, snapshot.SalesRepID,
		snapshot.ExpectedCommissionFromOpenOrders, snapshot.ExpectedCommissionFromOpenInvoices,
		snapshot.TotalExpectedCommission,
	)
	if err != nil {
		return fmt.Errorf("upsert commission forecast snapshot: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshCommissionForecastSnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error {
	// Compute expected commissions from pending/approved sales_commissions
	query := `
		WITH pending_commissions AS (
			SELECT
				sales_rep_id,
				SUM(commission_amount) as pending_amount
			FROM sales.sales_commissions
			WHERE company_id = $1
			  AND status IN ('pending', 'approved')
			  AND earned_at <= $2
			GROUP BY sales_rep_id
		)
		INSERT INTO sales_analytics.commission_forecast_snapshot
			(company_id, snapshot_date, sales_rep_id,
			 expected_commission_from_open_orders, expected_commission_from_open_invoices,
			 total_expected_commission, created_at)
		SELECT
			$1, $2, sr.sales_rep_id,
			0, 0, COALESCE(pc.pending_amount, 0), NOW()
		FROM sales.sales_reps sr
		LEFT JOIN pending_commissions pc ON sr.sales_rep_id = pc.sales_rep_id
		WHERE sr.company_id = $1 AND sr.is_active = true
		ON CONFLICT (company_id, snapshot_date, sales_rep_id) DO UPDATE SET
			expected_commission_from_open_orders = 0,
			expected_commission_from_open_invoices = 0,
			total_expected_commission = EXCLUDED.total_expected_commission,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		return fmt.Errorf("refresh commission forecast snapshot: %w", err)
	}
	return nil
}
func (r *analyticsRepository) InsertCreditCheckFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditCheckFact) error {
	query := `
        INSERT INTO sales_analytics.credit_check_fact
            (company_id, customer_id, check_id, check_type, result,
             requested_amount, current_limit, current_outstanding, available_credit,
             reason, checked_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
    `
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.CustomerID, fact.CheckID, fact.CheckType, fact.Result,
		fact.RequestedAmount, fact.CurrentLimit, fact.CurrentOutstanding, fact.AvailableCredit,
		fact.Reason, fact.CheckedAt,
	)
	if err != nil {
		return fmt.Errorf("insert credit check fact: %w", err)
	}
	return nil
}
func (r *analyticsRepository) UpsertDailyCreditMetrics(ctx context.Context, db DBTX, metrics *sales_analytics.DailyCreditMetrics) error {
	query := `
        INSERT INTO sales_analytics.daily_credit_metrics
            (company_id, date, total_checks, checks_passed, checks_failed,
             total_order_value_checked, total_invoice_value_checked,
             avg_available_credit, avg_credit_utilization, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_checks = EXCLUDED.total_checks,
            checks_passed = EXCLUDED.checks_passed,
            checks_failed = EXCLUDED.checks_failed,
            total_order_value_checked = EXCLUDED.total_order_value_checked,
            total_invoice_value_checked = EXCLUDED.total_invoice_value_checked,
            avg_available_credit = EXCLUDED.avg_available_credit,
            avg_credit_utilization = EXCLUDED.avg_credit_utilization,
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		metrics.CompanyID, metrics.Date,
		metrics.TotalChecks, metrics.ChecksPassed, metrics.ChecksFailed,
		metrics.TotalOrderValueChecked, metrics.TotalInvoiceValueChecked,
		metrics.AvgAvailableCredit, metrics.AvgCreditUtilization,
	)
	if err != nil {
		return fmt.Errorf("upsert daily credit metrics: %w", err)
	}
	return nil
}
func (r *analyticsRepository) IncrementDailyCreditMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time, passed bool, requestedAmount decimal.Decimal, checkType string, availableCredit decimal.Decimal, utilizationPct decimal.Decimal) error {
	passedInc := 0
	failedInc := 0
	if passed {
		passedInc = 1
	} else {
		failedInc = 1
	}

	orderValueInc := decimal.Zero
	invoiceValueInc := decimal.Zero
	if checkType == "order_eligibility" {
		orderValueInc = requestedAmount
	} else if checkType == "invoice_eligibility" {
		invoiceValueInc = requestedAmount
	}

	query := `
        INSERT INTO sales_analytics.daily_credit_metrics
            (company_id, date, total_checks, checks_passed, checks_failed,
             total_order_value_checked, total_invoice_value_checked,
             avg_available_credit, avg_credit_utilization, updated_at)
        VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_checks = daily_credit_metrics.total_checks + 1,
            checks_passed = daily_credit_metrics.checks_passed + EXCLUDED.checks_passed,
            checks_failed = daily_credit_metrics.checks_failed + EXCLUDED.checks_failed,
            total_order_value_checked = daily_credit_metrics.total_order_value_checked + EXCLUDED.total_order_value_checked,
            total_invoice_value_checked = daily_credit_metrics.total_invoice_value_checked + EXCLUDED.total_invoice_value_checked,
            avg_available_credit = (daily_credit_metrics.avg_available_credit * daily_credit_metrics.total_checks + EXCLUDED.avg_available_credit) / (daily_credit_metrics.total_checks + 1),
            avg_credit_utilization = (daily_credit_metrics.avg_credit_utilization * daily_credit_metrics.total_checks + EXCLUDED.avg_credit_utilization) / (daily_credit_metrics.total_checks + 1),
            updated_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		companyID, date,
		passedInc, failedInc,
		orderValueInc, invoiceValueInc,
		availableCredit, utilizationPct,
	)
	if err != nil {
		return fmt.Errorf("increment daily credit metrics: %w", err)
	}
	return nil
}
func (r *analyticsRepository) InsertCreditHoldFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditHoldFact) error {
	query := `
        INSERT INTO sales_analytics.credit_hold_fact
            (order_id, company_id, customer_id, hold_started_at, hold_ended_at, reason, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (order_id, hold_started_at) DO NOTHING
    `
	_, err := db.ExecContext(ctx, query,
		fact.OrderID, fact.CompanyID, fact.CustomerID,
		fact.HoldStartedAt, fact.HoldEndedAt, fact.Reason,
	)
	if err != nil {
		return fmt.Errorf("insert credit hold fact: %w", err)
	}
	return nil
}
func (r *analyticsRepository) CloseCreditHoldFact(ctx context.Context, db DBTX, orderID uuid.UUID, holdEndedAt time.Time) error {
	query := `
        UPDATE sales_analytics.credit_hold_fact
        SET hold_ended_at = $2
        WHERE order_id = $1 AND hold_ended_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, orderID, holdEndedAt)
	if err != nil {
		return fmt.Errorf("close credit hold fact: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no open credit hold fact found to close", zap.String("order_id", orderID.String()))
	}
	return nil
}
func (r *analyticsRepository) InsertCreditLimitChangeFact(ctx context.Context, db DBTX, fact *sales_analytics.CreditLimitChangeFact) error {
	query := `
        INSERT INTO sales_analytics.credit_limit_change_fact
            (company_id, customer_id, previous_limit, new_limit, change_reason, changed_by, changed_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
    `
	_, err := db.ExecContext(ctx, query,
		fact.CompanyID, fact.CustomerID,
		fact.PreviousLimit, fact.NewLimit,
		fact.ChangeReason, fact.ChangedBy, fact.ChangedAt,
	)
	if err != nil {
		return fmt.Errorf("insert credit limit change fact: %w", err)
	}
	return nil
}
func (r *analyticsRepository) UpsertCustomerCreditDailySnapshot(ctx context.Context, db DBTX, snapshot *sales_analytics.CustomerCreditDailySnapshot) error {
	query := `
        INSERT INTO sales_analytics.customer_credit_daily_snapshot
            (company_id, customer_id, snapshot_date, credit_limit, outstanding_balance, available_credit, is_suspended, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (company_id, customer_id, snapshot_date) DO UPDATE SET
            credit_limit = EXCLUDED.credit_limit,
            outstanding_balance = EXCLUDED.outstanding_balance,
            available_credit = EXCLUDED.available_credit,
            is_suspended = EXCLUDED.is_suspended,
            created_at = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		snapshot.CompanyID, snapshot.CustomerID, snapshot.SnapshotDate,
		snapshot.CreditLimit, snapshot.OutstandingBalance, snapshot.AvailableCredit,
		snapshot.IsSuspended,
	)
	if err != nil {
		return fmt.Errorf("upsert customer credit daily snapshot: %w", err)
	}
	return nil
}
func (r *analyticsRepository) RefreshCustomerCreditDailySnapshot(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error {
	query := `
        WITH current_credits AS (
            SELECT
                c.customer_id,
                COALESCE(c.credit_limit, 0) AS credit_limit,
                COALESCE(SUM(i.amount_due), 0) AS outstanding_balance,
                COALESCE(c.credit_limit, 0) - COALESCE(SUM(i.amount_due), 0) AS available_credit,
                EXISTS (
                    SELECT 1 FROM sales.credit_check_history h
                    WHERE h.customer_id = c.customer_id
                      AND h.action_type = 'suspend'
                      AND h.created_at > COALESCE(
                          (SELECT MAX(created_at) FROM sales.credit_check_history
                           WHERE customer_id = c.customer_id AND action_type = 'restore'),
                          '0001-01-01'
                      )
                ) AS is_suspended
            FROM sales.customers c
            LEFT JOIN sales.invoices i ON i.customer_id = c.customer_id
                AND i.status NOT IN ('paid', 'cancelled')
            WHERE c.company_id = $1
            GROUP BY c.customer_id, c.credit_limit
        )
        INSERT INTO sales_analytics.customer_credit_daily_snapshot
            (company_id, customer_id, snapshot_date, credit_limit, outstanding_balance, available_credit, is_suspended, created_at)
        SELECT
            $1, customer_id, $2,
            credit_limit, outstanding_balance, available_credit, is_suspended, NOW()
        FROM current_credits
        ON CONFLICT (company_id, customer_id, snapshot_date) DO UPDATE SET
            credit_limit = EXCLUDED.credit_limit,
            outstanding_balance = EXCLUDED.outstanding_balance,
            available_credit = EXCLUDED.available_credit,
            is_suspended = EXCLUDED.is_suspended,
            created_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		return fmt.Errorf("refresh customer credit daily snapshot: %w", err)
	}
	return nil
}
func (r *analyticsRepository) RefreshCurrentCustomerCredit(ctx context.Context, db DBTX) error {
	query := `REFRESH MATERIALIZED VIEW CONCURRENTLY sales_analytics.current_customer_credit`
	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("refresh current customer credit materialized view: %w", err)
	}
	return nil
}

// UpsertPaymentAllocationFact inserts or updates a payment allocation fact.
func (r *analyticsRepository) UpsertPaymentAllocationFact(ctx context.Context, tx DBTX, fact *sales_analytics.PaymentAllocationFact) error {
	query := `
        INSERT INTO sales_analytics.payment_allocation_fact
            (company_id, payment_id, invoice_id, allocated_amount, allocated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (payment_id, invoice_id) DO UPDATE SET
            allocated_amount = EXCLUDED.allocated_amount,
            allocated_at = EXCLUDED.allocated_at
    `
	_, err := tx.ExecContext(ctx, query,
		fact.CompanyID,
		fact.PaymentID,
		fact.InvoiceID,
		fact.AllocatedAmount,
		fact.AllocatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert payment allocation fact: %w", err)
	}
	return nil
}

// IncrementDailyAllocatedAmount adds the given amount to the total allocated for the date.
func (r *analyticsRepository) IncrementDailyAllocatedAmount(ctx context.Context, tx DBTX, companyID uuid.UUID, date time.Time, amount decimal.Decimal) error {
	query := `
        INSERT INTO sales_analytics.daily_allocated_amount (company_id, date, total_allocated, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, date) DO UPDATE SET
            total_allocated = daily_allocated_amount.total_allocated + EXCLUDED.total_allocated,
            updated_at = NOW()
    `
	_, err := tx.ExecContext(ctx, query, companyID, date, amount)
	if err != nil {
		return fmt.Errorf("increment daily allocated amount: %w", err)
	}
	return nil
}
