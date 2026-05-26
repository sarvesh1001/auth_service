package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/sales_analytics"
	"auth-service/internal/sales/repository"
)

// SalesQueryService defines all read‑only query methods for sales analytics.
type SalesQueryService interface {
	GetSalesDashboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*SalesDashboardSummary, error)
	GetTodaySalesSummary(ctx context.Context, companyID uuid.UUID) (*TodaySalesSummary, error)
	GetRealtimeSalesSnapshot(ctx context.Context, companyID uuid.UUID) (*RealtimeSalesSnapshot, error)
	GetRevenueSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*RevenueSummary, error)
	GetRevenueTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*RevenueTrendPoint, error)
	GetRevenueByCustomer(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*CustomerRevenueSummary, error)
	GetRevenueByProduct(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*ProductRevenueSummary, error)
	GetRevenueByCategory(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*CategoryRevenueSummary, error)
	GetRevenueBySalesRep(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*SalesRepRevenueSummary, error)
	GetRevenueByPaymentMethod(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*PaymentMethodRevenueSummary, error)
	GetNetRevenueAfterReturns(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopCustomers(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*TopCustomerRow, error)
	GetCustomerSalesSummary(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, from, to *time.Time) (*CustomerSalesSummary, error)
	GetCustomerLifetimeValue(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID) (decimal.Decimal, error)
	GetCustomersWithOutstandingBalance(ctx context.Context, companyID uuid.UUID) ([]*CustomerOutstandingBalanceRow, error)
	GetCustomersWithOverdueInvoices(ctx context.Context, companyID uuid.UUID) ([]*CustomerOverdueSummary, error)
	GetInactiveCustomers(ctx context.Context, companyID uuid.UUID, since time.Time) ([]*models.Customer, error)
	GetNewCustomers(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.Customer, error)
	GetOrderSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*OrderSummary, error)
	GetOrdersByStatus(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*OrderStatusSummary, error)
	GetTopOrdersByValue(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Order, error)
	GetAverageOrderValueTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*AverageOrderValuePoint, error)
	GetOrderConversionFunnel(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*OrderConversionFunnel, error)
	GetQuoteSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*QuoteSummary, error)
	GetQuoteConversionMetrics(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*QuoteConversionMetrics, error)
	GetQuotesExpiringSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Quote, error)
	GetInvoiceSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*InvoiceSummary, error)
	GetOutstandingReceivablesSummary(ctx context.Context, companyID uuid.UUID) (*OutstandingReceivablesSummary, error)
	GetOverdueInvoices(ctx context.Context, companyID uuid.UUID, at time.Time, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	GetOverdueInvoiceAging(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*InvoiceAgingBucket, error)
	GetInvoicesDueSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Invoice, error)
	GetInvoiceCollectionTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*CollectionTrendPoint, error)
	GetAverageCollectionDays(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetPaymentSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*PaymentSummary, error)
	GetPaymentMethodBreakdown(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*PaymentMethodBreakdownRow, error)
	GetFailedPaymentAnalytics(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*FailedPaymentAnalytics, error)
	GetRefundSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*RefundSummary, error)
	GetTopSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*TopSellingProductRow, error)
	GetLeastSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*LeastSellingProductRow, error)
	GetProductSalesTrend(ctx context.Context, companyID uuid.UUID, productID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*ProductSalesTrendPoint, error)
	GetProductsNeverSold(ctx context.Context, companyID uuid.UUID) ([]*models.Product, error)
	GetMostReturnedProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*MostReturnedProductRow, error)
	GetReturnSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*ReturnSummary, error)
	GetReturnRateTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*ReturnRateTrendPoint, error)
	GetRefundLiabilitySummary(ctx context.Context, companyID uuid.UUID) (*RefundLiabilitySummary, error)
	GetDiscountSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*DiscountSummary, error)
	GetCouponPerformance(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*CouponPerformanceRow, error)
	GetPromotionPerformance(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*PromotionPerformanceRow, error)
	GetDiscountImpactOnRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*DiscountRevenueImpact, error)
	GetTaxSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*TaxSummary, error)
	GetTaxBreakdownByRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*TaxRateBreakdownRow, error)
	GetTaxBreakdownByJurisdiction(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*JurisdictionTaxBreakdownRow, error)
	GetTaxBreakdownByProduct(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*ProductTaxBreakdownRow, error)
	GetCollectedTaxTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*CollectedTaxTrendPoint, error)
	GetTaxAuditReport(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*TaxAuditReportRow, error)
	GetSalesRepPerformance(ctx context.Context, companyID uuid.UUID, salesRepID uuid.UUID, from, to *time.Time) (*SalesRepPerformanceSummary, error)
	GetSalesLeaderboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*SalesLeaderboardRow, error)
	GetCommissionSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*CommissionSummary, error)
	GetCreditRiskSummary(ctx context.Context, companyID uuid.UUID) (*CreditRiskSummary, error)
	GetCustomersNearCreditLimit(ctx context.Context, companyID uuid.UUID, thresholdPercent decimal.Decimal) ([]*CustomerCreditUtilizationRow, error)
	GetCustomersExceedingCreditLimit(ctx context.Context, companyID uuid.UUID) ([]*CustomerCreditExposureRow, error)
	GetOrdersOnCreditHold(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error)
	GetSalesReport(ctx context.Context, req *SalesReportRequest) (*SalesReportResult, error)
	GetTaxReport(ctx context.Context, req *TaxReportRequest) (*TaxReportResult, error)
	GetReceivablesReport(ctx context.Context, req *ReceivablesReportRequest) (*ReceivablesReportResult, error)
	GetCustomerStatement(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, from, to *time.Time) (*CustomerStatementResult, error)
	GetSalesAuditTrail(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*SalesAuditEntry, error)
}

type salesQueryService struct {
	analyticsRepo     repository.AnalyticsRepository
	orderRepo         repository.OrderRepository
	invoiceRepo       repository.InvoiceRepository
	paymentRepo       repository.PaymentRepository
	returnRepo        repository.ReturnRepository
	customerRepo      repository.CustomerRepository
	productRepo       repository.ProductRepository
	salesRepRepo      repository.SalesRepRepository
	quoteRepo         repository.QuoteRepository
	discountUsageRepo repository.DiscountUsageRepository
	taxSnapshotRepo   repository.TaxSnapshotRepository
	creditNoteRepo    repository.CreditNoteRepository
	pgClient          *client.PostgresClient
	logger            *zap.Logger
}

// NewSalesQueryService creates a new instance of SalesQueryService.
func NewSalesQueryService(
	analyticsRepo repository.AnalyticsRepository,
	orderRepo repository.OrderRepository,
	invoiceRepo repository.InvoiceRepository,
	paymentRepo repository.PaymentRepository,
	returnRepo repository.ReturnRepository,
	customerRepo repository.CustomerRepository,
	productRepo repository.ProductRepository,
	salesRepRepo repository.SalesRepRepository,
	quoteRepo repository.QuoteRepository,
	discountUsageRepo repository.DiscountUsageRepository,
	taxSnapshotRepo repository.TaxSnapshotRepository,
	creditNoteRepo repository.CreditNoteRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SalesQueryService {
	return &salesQueryService{
		analyticsRepo:     analyticsRepo,
		orderRepo:         orderRepo,
		invoiceRepo:       invoiceRepo,
		paymentRepo:       paymentRepo,
		returnRepo:        returnRepo,
		customerRepo:      customerRepo,
		productRepo:       productRepo,
		salesRepRepo:      salesRepRepo,
		quoteRepo:         quoteRepo,
		discountUsageRepo: discountUsageRepo,
		taxSnapshotRepo:   taxSnapshotRepo,
		creditNoteRepo:    creditNoteRepo,
		pgClient:          pgClient,
		logger:            logger.Named("sales_query_service"),
	}
}

func (s *salesQueryService) normalizeDateRange(from, to *time.Time) (time.Time, time.Time) {
	start := time.Now().AddDate(-1, 0, 0)
	if from != nil {
		start = *from
	}
	end := time.Now()
	if to != nil {
		end = *to
	}
	return start, end
}

func (s *salesQueryService) truncateByGranularity(t time.Time, g AnalyticsGranularity) time.Time {
	switch g {
	case GranularityDaily:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	case GranularityWeekly:
		weekday := int(t.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		return t.AddDate(0, 0, -weekday+1).Truncate(24 * time.Hour)
	case GranularityMonthly:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
	case GranularityYearly:
		return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, t.Location())
	default:
		return t.Truncate(24 * time.Hour)
	}
}

// GetSalesDashboard returns high-level sales KPIs for a date range.
func (s *salesQueryService) GetSalesDashboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*SalesDashboardSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT total_revenue, total_orders, total_discounts, total_tax
		 FROM sales_analytics.daily_sales
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var totalRevenue, totalDiscounts, totalTax decimal.Decimal
	var totalOrders int
	for rows.Next() {
		var rev, disc, tax decimal.Decimal
		var ord int
		if err := rows.Scan(&rev, &ord, &disc, &tax); err != nil {
			return nil, err
		}
		totalRevenue = totalRevenue.Add(rev)
		totalOrders += ord
		totalDiscounts = totalDiscounts.Add(disc)
		totalTax = totalTax.Add(tax)
	}

	var uniqueCustomers int
	err = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(DISTINCT customer_id) FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&uniqueCustomers)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Warn("failed to count unique customers", zap.Error(err))
	}

	aov := decimal.Zero
	if totalOrders > 0 {
		aov = totalRevenue.Div(decimal.NewFromInt(int64(totalOrders)))
	}

	var outstanding decimal.Decimal
	err = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_due),0) FROM sales.invoices
		 WHERE company_id=$1 AND status NOT IN ('paid','cancelled')`,
		companyID).Scan(&outstanding)
	if err != nil {
		s.logger.Warn("failed to get outstanding receivables", zap.Error(err))
	}

	topProducts, _ := s.GetTopSellingProducts(ctx, companyID, 1, &start, &end)
	var topProd *TopSellingProductRow
	if len(topProducts) > 0 {
		topProd = topProducts[0]
	}

	return &SalesDashboardSummary{
		Revenue:                totalRevenue,
		Orders:                 totalOrders,
		AverageOrderValue:      aov,
		ConversionRate:         decimal.Zero,
		OutstandingReceivables: outstanding,
		TopSellingProduct:      topProd,
		TotalDiscounts:         totalDiscounts,
		TotalTax:               totalTax,
		UniqueCustomers:        uniqueCustomers,
		PeriodStart:            start,
		PeriodEnd:              end,
	}, nil
}

// GetTodaySalesSummary returns summary for the current calendar day.
func (s *salesQueryService) GetTodaySalesSummary(ctx context.Context, companyID uuid.UUID) (*TodaySalesSummary, error) {
	today := time.Now().Truncate(24 * time.Hour)
	var daily sales_analytics.DailySales
	err := s.pgClient.QueryRow(ctx,
		`SELECT total_revenue, total_orders, unique_customers
		 FROM sales_analytics.daily_sales
		 WHERE company_id=$1 AND date=$2`,
		companyID, today).Scan(&daily.TotalRevenue, &daily.TotalOrders, &daily.UniqueCustomers)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	summary := &TodaySalesSummary{
		Date:            today,
		Revenue:         daily.TotalRevenue,
		OrdersCount:     daily.TotalOrders,
		UniqueCustomers: daily.UniqueCustomers,
	}
	if daily.TotalOrders > 0 {
		summary.AverageOrderValue = daily.TotalRevenue.Div(decimal.NewFromInt(int64(daily.TotalOrders)))
	}

	var invCount int
	var invValue decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(grand_total),0)
		 FROM sales.invoices
		 WHERE company_id=$1 AND invoice_date=$2 AND status='issued'`,
		companyID, today).Scan(&invCount, &invValue)
	summary.InvoicesIssuedCount = invCount
	summary.InvoicesIssuedValue = invValue

	var payCount int
	var payValue decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(amount),0)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date=$2 AND status='completed'`,
		companyID, today).Scan(&payCount, &payValue)
	summary.PaymentsReceivedCount = payCount
	summary.PaymentsReceivedValue = payValue

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.name, SUM(oi.quantity * oi.unit_price) as rev
		 FROM sales.order_items oi
		 JOIN sales.orders o ON o.order_id = oi.order_id
		 JOIN sales.products p ON p.product_id = oi.product_id
		 WHERE o.company_id=$1 AND o.order_date=$2 AND o.status NOT IN ('cancelled')
		 GROUP BY p.product_id, p.name
		 ORDER BY rev DESC LIMIT 1`,
		companyID, today)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			var name string
			var rev decimal.Decimal
			rows.Scan(&name, &rev)
			summary.TopSellingProductName = name
			summary.TopSellingProductRevenue = rev
		}
	}
	return summary, nil
}

// GetRealtimeSalesSnapshot returns current sales activity metrics.
func (s *salesQueryService) GetRealtimeSalesSnapshot(ctx context.Context, companyID uuid.UUID) (*RealtimeSalesSnapshot, error) {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	today := now.Truncate(24 * time.Hour)

	snapshot := &RealtimeSalesSnapshot{}
	var rev decimal.Decimal
	var orders int

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0), COUNT(*)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date >= $2 AND order_date < $3 AND status NOT IN ('cancelled')`,
		companyID, oneHourAgo, now).Scan(&rev, &orders)
	snapshot.LastHourRevenue = rev
	snapshot.LastHourOrders = orders

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0), COUNT(*)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date >= $2 AND status NOT IN ('cancelled')`,
		companyID, today).Scan(&rev, &orders)
	snapshot.TodayRevenue = rev
	snapshot.TodayOrders = orders

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND status IN ('draft','confirmed')`,
		companyID).Scan(&snapshot.PendingOrders)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(amount_due),0)
		 FROM sales.invoices
		 WHERE company_id=$1 AND due_date < $2 AND status NOT IN ('paid','cancelled')`,
		companyID, now).Scan(&snapshot.OverdueInvoicesCount, &snapshot.OverdueInvoicesValue)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.quotes WHERE company_id=$1 AND status IN ('draft','sent')`,
		companyID).Scan(&snapshot.ActiveQuotesCount)

	return snapshot, nil
}

// GetRevenueSummary returns aggregated revenue metrics.
func (s *salesQueryService) GetRevenueSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*RevenueSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	var totalRevenue decimal.Decimal
	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled','refunded')`,
		companyID, start, end).Scan(&totalRevenue)
	if err != nil {
		return nil, err
	}

	var collected decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3 AND status='completed'`,
		companyID, start, end).Scan(&collected)

	var refunded decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0)
		 FROM sales.payment_refunds
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3 AND status='completed'`,
		companyID, start, end).Scan(&refunded)

	return &RevenueSummary{
		TotalRevenue:      totalRevenue,
		RevenueFromOrders: totalRevenue,
		CollectedRevenue:  collected,
		RefundedAmount:    refunded,
		NetRevenue:        collected.Sub(refunded),
		PeriodStart:       start,
		PeriodEnd:         end,
	}, nil
}

// GetRevenueTrend returns revenue over time, optionally aggregated.
func (s *salesQueryService) GetRevenueTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*RevenueTrendPoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT date, total_revenue
		 FROM sales_analytics.daily_sales
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3
		 ORDER BY date`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []*RevenueTrendPoint
	for rows.Next() {
		var date time.Time
		var rev decimal.Decimal
		if err := rows.Scan(&date, &rev); err != nil {
			return nil, err
		}
		points = append(points, &RevenueTrendPoint{Date: date, Revenue: rev})
	}

	if granularity != GranularityDaily {
		aggMap := make(map[string]*RevenueTrendPoint)
		for _, p := range points {
			key := s.truncateByGranularity(p.Date, granularity)
			keyStr := key.Format("2006-01-02")
			if existing, ok := aggMap[keyStr]; ok {
				existing.Revenue = existing.Revenue.Add(p.Revenue)
			} else {
				aggMap[keyStr] = &RevenueTrendPoint{Date: key, Revenue: p.Revenue}
			}
		}
		points = make([]*RevenueTrendPoint, 0, len(aggMap))
		for _, v := range aggMap {
			points = append(points, v)
		}
	}
	return points, nil
}

// GetRevenueByCustomer returns top customers by revenue.
func (s *salesQueryService) GetRevenueByCustomer(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*CustomerRevenueSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT c.customer_id, c.name, COALESCE(SUM(o.grand_total),0) as revenue, COUNT(o.order_id) as order_count
		 FROM sales.customers c
		 LEFT JOIN sales.orders o ON o.customer_id = c.customer_id AND o.company_id=c.company_id
		  AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled','refunded')
		 WHERE c.company_id=$1
		 GROUP BY c.customer_id, c.name
		 ORDER BY revenue DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CustomerRevenueSummary
	for rows.Next() {
		var custID uuid.UUID
		var name string
		var rev decimal.Decimal
		var orderCount int
		if err := rows.Scan(&custID, &name, &rev, &orderCount); err != nil {
			return nil, err
		}
		avgVal := decimal.Zero
		if orderCount > 0 {
			avgVal = rev.Div(decimal.NewFromInt(int64(orderCount)))
		}
		result = append(result, &CustomerRevenueSummary{
			CustomerID:   custID,
			CustomerName: name,
			TotalRevenue: rev,
			OrderCount:   orderCount,
			AverageValue: avgVal,
		})
	}
	return result, nil
}

// GetRevenueByProduct returns top products by revenue.
func (s *salesQueryService) GetRevenueByProduct(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*ProductRevenueSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.name, p.sku,
			SUM(oi.quantity) as qty,
			SUM(oi.quantity * oi.unit_price) as revenue
		 FROM sales.order_items oi
		 JOIN sales.orders o ON o.order_id = oi.order_id
		 JOIN sales.products p ON p.product_id = oi.product_id
		 WHERE o.company_id=$1 AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 GROUP BY p.product_id, p.name, p.sku
		 ORDER BY revenue DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ProductRevenueSummary
	for rows.Next() {
		var pid uuid.UUID
		var name, sku string
		var qty, rev decimal.Decimal
		if err := rows.Scan(&pid, &name, &sku, &qty, &rev); err != nil {
			return nil, err
		}
		result = append(result, &ProductRevenueSummary{
			ProductID:    pid,
			ProductName:  name,
			SKU:          sku,
			QuantitySold: qty,
			Revenue:      rev,
		})
	}
	return result, nil
}

// GetRevenueByCategory is a stub – implement if category data is available.
func (s *salesQueryService) GetRevenueByCategory(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*CategoryRevenueSummary, error) {
	return []*CategoryRevenueSummary{}, nil
}

// GetRevenueBySalesRep returns revenue attributed to sales representatives.
func (s *salesQueryService) GetRevenueBySalesRep(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*SalesRepRevenueSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT sr.sales_rep_id, sr.name,
			COALESCE(SUM(o.grand_total),0) as revenue,
			COUNT(o.order_id) as orders
		 FROM sales.sales_reps sr
		 LEFT JOIN sales.orders o ON o.sales_rep_id = sr.sales_rep_id AND o.company_id=sr.company_id
		  AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 WHERE sr.company_id=$1
		 GROUP BY sr.sales_rep_id, sr.name
		 ORDER BY revenue DESC`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*SalesRepRevenueSummary
	for rows.Next() {
		var id uuid.UUID
		var name string
		var rev decimal.Decimal
		var orders int
		if err := rows.Scan(&id, &name, &rev, &orders); err != nil {
			return nil, err
		}
		result = append(result, &SalesRepRevenueSummary{
			SalesRepID:   id,
			SalesRepName: name,
			Revenue:      rev,
			OrdersCount:  orders,
		})
	}
	return result, nil
}

// GetRevenueByPaymentMethod returns revenue split by payment method.
func (s *salesQueryService) GetRevenueByPaymentMethod(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*PaymentMethodRevenueSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT payment_method, COUNT(*), COALESCE(SUM(amount),0)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3 AND status='completed'
		 GROUP BY payment_method`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*PaymentMethodRevenueSummary
	for rows.Next() {
		var method string
		var count int
		var amount decimal.Decimal
		if err := rows.Scan(&method, &count, &amount); err != nil {
			return nil, err
		}
		result = append(result, &PaymentMethodRevenueSummary{
			PaymentMethod: method,
			TotalAmount:   amount,
			Count:         count,
		})
	}
	return result, nil
}

// GetNetRevenueAfterReturns returns revenue after accounting for returns.
func (s *salesQueryService) GetNetRevenueAfterReturns(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	start, end := s.normalizeDateRange(from, to)

	var revenue decimal.Decimal
	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(o.grand_total),0) - COALESCE(SUM(r.total_refund),0)
		 FROM sales.orders o
		 LEFT JOIN sales.returns r ON r.order_id = o.order_id AND r.status='completed'
		 WHERE o.company_id=$1 AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&revenue)
	return revenue, err
}

// GetTopCustomers returns customers with highest spending.
func (s *salesQueryService) GetTopCustomers(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*TopCustomerRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT c.customer_id, c.name, COALESCE(SUM(o.grand_total),0) as spent,
			COUNT(o.order_id) as orders, MAX(o.order_date) as last_order
		 FROM sales.customers c
		 LEFT JOIN sales.orders o ON o.customer_id = c.customer_id AND o.company_id=c.company_id
		  AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 WHERE c.company_id=$1
		 GROUP BY c.customer_id, c.name
		 ORDER BY spent DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*TopCustomerRow
	for rows.Next() {
		var id uuid.UUID
		var name string
		var spent decimal.Decimal
		var orders int
		var lastOrder sql.NullTime
		if err := rows.Scan(&id, &name, &spent, &orders, &lastOrder); err != nil {
			return nil, err
		}
		row := &TopCustomerRow{
			CustomerID:   id,
			CustomerName: name,
			TotalSpent:   spent,
			OrderCount:   orders,
		}
		if lastOrder.Valid {
			row.LastOrder = lastOrder.Time
		}
		result = append(result, row)
	}
	return result, nil
}

// GetCustomerSalesSummary returns detailed sales metrics for a single customer.
func (s *salesQueryService) GetCustomerSalesSummary(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, from, to *time.Time) (*CustomerSalesSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &CustomerSalesSummary{CustomerID: customerID}

	err := s.pgClient.QueryRow(ctx,
		`SELECT name FROM sales.customers WHERE customer_id=$1 AND company_id=$2`,
		customerID, companyID).Scan(&summary.CustomerName)
	if err != nil {
		return nil, err
	}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE customer_id=$1 AND company_id=$2 AND order_date BETWEEN $3 AND $4 AND status NOT IN ('cancelled')`,
		customerID, companyID, start, end).Scan(&summary.TotalOrders, &summary.TotalRevenue)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM sales.invoices
		 WHERE customer_id=$1 AND company_id=$2 AND invoice_date BETWEEN $3 AND $4 AND status NOT IN ('cancelled')`,
		customerID, companyID, start, end).Scan(&summary.TotalInvoices)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0)
		 FROM sales.payments p
		 JOIN sales.payment_allocations pa ON pa.payment_id = p.payment_id
		 JOIN sales.invoices i ON i.invoice_id = pa.invoice_id
		 WHERE i.customer_id=$1 AND i.company_id=$2 AND p.payment_date BETWEEN $3 AND $4 AND p.status='completed'`,
		customerID, companyID, start, end).Scan(&summary.TotalPayments)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_due),0)
		 FROM sales.invoices
		 WHERE customer_id=$1 AND company_id=$2 AND status NOT IN ('paid','cancelled')`,
		customerID, companyID).Scan(&summary.OutstandingBalance)

	if summary.TotalOrders > 0 {
		summary.AverageOrderValue = summary.TotalRevenue.Div(decimal.NewFromInt(int64(summary.TotalOrders)))
	}
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE customer_id=$1 AND company_id=$2 AND status NOT IN ('cancelled')`,
		customerID, companyID).Scan(&summary.LifetimeValue)

	var first, last sql.NullTime
	_ = s.pgClient.QueryRow(ctx,
		`SELECT MIN(order_date), MAX(order_date)
		 FROM sales.orders
		 WHERE customer_id=$1 AND company_id=$2 AND status NOT IN ('cancelled')`,
		customerID, companyID).Scan(&first, &last)
	if first.Valid {
		summary.FirstOrderDate = &first.Time
	}
	if last.Valid {
		summary.LastOrderDate = &last.Time
	}
	return summary, nil
}

// GetCustomerLifetimeValue returns total lifetime spend of a customer.
func (s *salesQueryService) GetCustomerLifetimeValue(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID) (decimal.Decimal, error) {
	var ltv decimal.Decimal
	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE customer_id=$1 AND company_id=$2 AND status NOT IN ('cancelled')`,
		customerID, companyID).Scan(&ltv)
	return ltv, err
}

// GetCustomersWithOutstandingBalance returns customers with unpaid invoices.
func (s *salesQueryService) GetCustomersWithOutstandingBalance(ctx context.Context, companyID uuid.UUID) ([]*CustomerOutstandingBalanceRow, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT c.customer_id, c.name, COALESCE(SUM(i.amount_due),0) as outstanding,
			COALESCE(SUM(CASE WHEN i.due_date < NOW() THEN i.amount_due ELSE 0 END),0) as overdue
		 FROM sales.customers c
		 LEFT JOIN sales.invoices i ON i.customer_id = c.customer_id AND i.company_id=c.company_id AND i.status NOT IN ('paid','cancelled')
		 WHERE c.company_id=$1
		 GROUP BY c.customer_id, c.name
		 HAVING COALESCE(SUM(i.amount_due),0) > 0`,
		companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CustomerOutstandingBalanceRow
	for rows.Next() {
		var id uuid.UUID
		var name string
		var outstanding, overdue decimal.Decimal
		if err := rows.Scan(&id, &name, &outstanding, &overdue); err != nil {
			return nil, err
		}
		result = append(result, &CustomerOutstandingBalanceRow{
			CustomerID:        id,
			CustomerName:      name,
			OutstandingAmount: outstanding,
			OverdueAmount:     overdue,
		})
	}
	return result, nil
}

// GetCustomersWithOverdueInvoices returns customers with overdue invoices.
func (s *salesQueryService) GetCustomersWithOverdueInvoices(ctx context.Context, companyID uuid.UUID) ([]*CustomerOverdueSummary, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT c.customer_id, c.name, SUM(i.amount_due) as overdue_amount,
			EXTRACT(DAY FROM (NOW() - i.due_date)) as days_overdue
		 FROM sales.customers c
		 JOIN sales.invoices i ON i.customer_id = c.customer_id AND i.company_id=c.company_id
		 WHERE i.due_date < NOW() AND i.status NOT IN ('paid','cancelled') AND c.company_id=$1
		 GROUP BY c.customer_id, c.name, i.due_date`,
		companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CustomerOverdueSummary
	for rows.Next() {
		var id uuid.UUID
		var name string
		var amount decimal.Decimal
		var days int
		if err := rows.Scan(&id, &name, &amount, &days); err != nil {
			return nil, err
		}
		result = append(result, &CustomerOverdueSummary{
			CustomerID:    id,
			CustomerName:  name,
			OverdueAmount: amount,
			OverdueDays:   days,
		})
	}
	return result, nil
}

// GetInactiveCustomers returns active customers with no activity since the given time.
func (s *salesQueryService) GetInactiveCustomers(ctx context.Context, companyID uuid.UUID, since time.Time) ([]*models.Customer, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT customer_id, company_id, customer_code, name, is_active
		 FROM sales.customers
		 WHERE company_id=$1 AND updated_at < $2 AND is_active = true`,
		companyID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var customers []*models.Customer
	for rows.Next() {
		var c models.Customer
		if err := rows.Scan(&c.CustomerID, &c.CompanyID, &c.CustomerCode, &c.Name, &c.IsActive); err != nil {
			return nil, err
		}
		customers = append(customers, &c)
	}
	return customers, nil
}

// GetNewCustomers returns customers created in the given date range.
func (s *salesQueryService) GetNewCustomers(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.Customer, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT customer_id, company_id, customer_code, name, is_active, created_at
		 FROM sales.customers
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var customers []*models.Customer
	for rows.Next() {
		var c models.Customer
		if err := rows.Scan(&c.CustomerID, &c.CompanyID, &c.CustomerCode, &c.Name, &c.IsActive, &c.CreatedAt); err != nil {
			return nil, err
		}
		customers = append(customers, &c)
	}
	return customers, nil
}

// GetOrderSummary returns aggregated order statistics.
func (s *salesQueryService) GetOrderSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*OrderSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &OrderSummary{PeriodStart: start, PeriodEnd: end}

	err := s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&summary.TotalOrders, &summary.TotalRevenue)
	if err != nil {
		return nil, err
	}
	if summary.TotalOrders > 0 {
		summary.AverageOrderValue = summary.TotalRevenue.Div(decimal.NewFromInt(int64(summary.TotalOrders)))
	}

	var completed, cancelled, refunded, pending int
	_ = s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(CASE WHEN status='delivered' THEN 1 END),
			COUNT(CASE WHEN status='cancelled' THEN 1 END),
			COUNT(CASE WHEN status='refunded' THEN 1 END),
			COUNT(CASE WHEN status IN ('draft','confirmed','processing') THEN 1 END)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&completed, &cancelled, &refunded, &pending)
	summary.CompletedOrders = completed
	summary.CancelledOrders = cancelled
	summary.RefundedOrders = refunded
	summary.PendingOrders = pending

	return summary, nil
}

// GetOrdersByStatus returns order counts and values grouped by status.
func (s *salesQueryService) GetOrdersByStatus(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*OrderStatusSummary, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT status, COUNT(*) as cnt, COALESCE(SUM(grand_total),0) as val
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3
		 GROUP BY status`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*OrderStatusSummary
	for rows.Next() {
		var status string
		var cnt int
		var val decimal.Decimal
		if err := rows.Scan(&status, &cnt, &val); err != nil {
			return nil, err
		}
		result = append(result, &OrderStatusSummary{Status: status, Count: cnt, Value: val})
	}
	return result, nil
}

// GetTopOrdersByValue returns the highest‑value orders.
func (s *salesQueryService) GetTopOrdersByValue(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Order, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT order_id, company_id, customer_id, order_number, order_date, status, grand_total
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')
		 ORDER BY grand_total DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orders []*models.Order
	for rows.Next() {
		var o models.Order
		if err := rows.Scan(&o.OrderID, &o.CompanyID, &o.CustomerID, &o.OrderNumber, &o.OrderDate, &o.Status, &o.GrandTotal); err != nil {
			return nil, err
		}
		orders = append(orders, &o)
	}
	return orders, nil
}

// GetAverageOrderValueTrend returns average order value over time.
func (s *salesQueryService) GetAverageOrderValueTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*AverageOrderValuePoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT date, total_revenue, total_orders
		 FROM sales_analytics.daily_sales
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupMap := make(map[string]struct {
		revenue decimal.Decimal
		orders  int
	})
	for rows.Next() {
		var date time.Time
		var rev decimal.Decimal
		var orders int
		if err := rows.Scan(&date, &rev, &orders); err != nil {
			return nil, err
		}
		key := s.truncateByGranularity(date, granularity)
		keyStr := key.Format("2006-01-02")
		if val, ok := groupMap[keyStr]; ok {
			val.revenue = val.revenue.Add(rev)
			val.orders += orders
			groupMap[keyStr] = val
		} else {
			groupMap[keyStr] = struct {
				revenue decimal.Decimal
				orders  int
			}{revenue: rev, orders: orders}
		}
	}

	var points []*AverageOrderValuePoint
	for keyStr, val := range groupMap {
		date, _ := time.Parse("2006-01-02", keyStr)
		aov := decimal.Zero
		if val.orders > 0 {
			aov = val.revenue.Div(decimal.NewFromInt(int64(val.orders)))
		}
		points = append(points, &AverageOrderValuePoint{Date: date, AOV: aov})
	}
	return points, nil
}

// GetOrderConversionFunnel returns conversion rates from quote to order.
func (s *salesQueryService) GetOrderConversionFunnel(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*OrderConversionFunnel, error) {
	start, end := s.normalizeDateRange(from, to)
	funnel := &OrderConversionFunnel{}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.quotes WHERE company_id=$1 AND quote_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&funnel.QuotesCreated)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&funnel.OrdersCreated)

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status='delivered'`,
		companyID, start, end).Scan(&funnel.OrdersCompleted)

	if funnel.QuotesCreated > 0 {
		funnel.ConversionRate = decimal.NewFromInt(int64(funnel.OrdersCreated)).
			Div(decimal.NewFromInt(int64(funnel.QuotesCreated))).
			Mul(decimal.NewFromInt(100))
	}
	return funnel, nil
}

// GetQuoteSummary returns aggregated quote metrics.
func (s *salesQueryService) GetQuoteSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*QuoteSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &QuoteSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(grand_total),0),
			COUNT(CASE WHEN status='converted' THEN 1 END),
			COALESCE(SUM(CASE WHEN status='converted' THEN grand_total ELSE 0 END),0),
			COUNT(CASE WHEN status='expired' THEN 1 END)
		 FROM sales.quotes
		 WHERE company_id=$1 AND quote_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(
		&summary.TotalQuotes, &summary.TotalValue,
		&summary.ConvertedQuotes, &summary.ConvertedValue,
		&summary.ExpiredQuotes)
	if err != nil {
		return nil, err
	}

	var avgDays sql.NullFloat64
	_ = s.pgClient.QueryRow(ctx,
		`SELECT AVG(EXTRACT(DAY FROM (converted_at - quote_date)))
		 FROM sales.quotes
		 WHERE company_id=$1 AND quote_date BETWEEN $2 AND $3 AND status='converted' AND converted_at IS NOT NULL`,
		companyID, start, end).Scan(&avgDays)
	if avgDays.Valid {
		summary.AverageConversionTimeDays = decimal.NewFromFloat(avgDays.Float64)
	}
	return summary, nil
}

// GetQuoteConversionMetrics returns detailed quote conversion analysis.
func (s *salesQueryService) GetQuoteConversionMetrics(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*QuoteConversionMetrics, error) {
	start, end := s.normalizeDateRange(from, to)
	metrics := &QuoteConversionMetrics{}

	var convRate decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(AVG(conversion_rate),0)
		 FROM sales_analytics.daily_quote_metrics
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&convRate)
	metrics.ConversionRate = convRate

	var avgDays decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(AVG(conversion_time_seconds),0)/86400
		 FROM sales_analytics.quote_conversion_facts
		 WHERE company_id=$1 AND converted_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&avgDays)
	metrics.AverageConversionDays = avgDays

	_ = s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(CASE WHEN used_coupon_ids IS NOT NULL AND jsonb_array_length(used_coupon_ids) > 0 THEN 1 END),
			COUNT(CASE WHEN (used_coupon_ids IS NULL OR jsonb_array_length(used_coupon_ids)=0) THEN 1 END)
		 FROM sales_analytics.quote_conversion_facts
		 WHERE company_id=$1 AND converted_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&metrics.QuotesWithCoupon, &metrics.QuotesWithoutCoupon)
	return metrics, nil
}

// GetQuotesExpiringSoon returns quotes that expire before the given time.
func (s *salesQueryService) GetQuotesExpiringSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Quote, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT quote_id, company_id, customer_id, quote_number, revision, quote_date, expiry_date, status, grand_total
		 FROM sales.quotes
		 WHERE company_id=$1 AND expiry_date < $2 AND status NOT IN ('converted','expired')`,
		companyID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var quotes []*models.Quote
	for rows.Next() {
		var q models.Quote
		if err := rows.Scan(&q.QuoteID, &q.CompanyID, &q.CustomerID, &q.QuoteNumber, &q.Revision, &q.QuoteDate, &q.ExpiryDate, &q.Status, &q.GrandTotal); err != nil {
			return nil, err
		}
		quotes = append(quotes, &q)
	}
	return quotes, nil
}

// GetInvoiceSummary returns aggregated invoice metrics.
func (s *salesQueryService) GetInvoiceSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*InvoiceSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &InvoiceSummary{PeriodStart: start, PeriodEnd: end}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(*), COALESCE(SUM(grand_total),0),
			COUNT(CASE WHEN status='paid' THEN 1 END), COALESCE(SUM(CASE WHEN status='paid' THEN grand_total ELSE 0 END),0),
			COUNT(CASE WHEN status='overdue' THEN 1 END), COALESCE(SUM(CASE WHEN status='overdue' THEN amount_due ELSE 0 END),0),
			COUNT(CASE WHEN status='cancelled' THEN 1 END)
		 FROM sales.invoices
		 WHERE company_id=$1 AND invoice_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(
		&summary.TotalIssued, &summary.TotalIssuedValue,
		&summary.TotalPaid, &summary.TotalPaidValue,
		&summary.TotalOverdue, &summary.TotalOverdueValue,
		&summary.TotalCancelled)
	if err != nil {
		return nil, err
	}
	return summary, nil
}

// GetOutstandingReceivablesSummary returns aging buckets of receivables.
func (s *salesQueryService) GetOutstandingReceivablesSummary(ctx context.Context, companyID uuid.UUID) (*OutstandingReceivablesSummary, error) {
	now := time.Now()
	summary := &OutstandingReceivablesSummary{}
	var current, b30, b60, b90, over, total decimal.Decimal

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COALESCE(SUM(amount_due) FILTER (WHERE due_date >= $1),0) as current,
			COALESCE(SUM(amount_due) FILTER (WHERE due_date < $1 AND due_date >= $1 - interval '30 days'),0) as b30,
			COALESCE(SUM(amount_due) FILTER (WHERE due_date < $1 - interval '30 days' AND due_date >= $1 - interval '60 days'),0) as b60,
			COALESCE(SUM(amount_due) FILTER (WHERE due_date < $1 - interval '60 days' AND due_date >= $1 - interval '90 days'),0) as b90,
			COALESCE(SUM(amount_due) FILTER (WHERE due_date < $1 - interval '90 days'),0) as over,
			COALESCE(SUM(amount_due),0) as total
		 FROM sales.invoices
		 WHERE company_id=$2 AND status NOT IN ('paid','cancelled')`,
		now, companyID).Scan(&current, &b30, &b60, &b90, &over, &total)
	if err != nil {
		return nil, err
	}
	summary.CurrentReceivables = current
	summary.Overdue30Days = b30
	summary.Overdue60Days = b60
	summary.Overdue90Days = b90
	summary.OverdueOver90Days = over
	summary.TotalReceivables = total
	summary.OverdueReceivables = b30.Add(b60).Add(b90).Add(over)
	return summary, nil
}

// GetOverdueInvoices returns invoices overdue at a given time.
func (s *salesQueryService) GetOverdueInvoices(ctx context.Context, companyID uuid.UUID, at time.Time, p Pagination, srt Sort) ([]*models.Invoice, int64, error) {
	// Use direct SQL because the repository filter does not support DueDateBefore
	offset := p.Offset
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	order := "invoice_date ASC"
	if srt.Field != "" {
		order = srt.Field + " " + srt.Direction
	}
	query := `
		SELECT invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate, subtotal, discount_total,
			tax_total, grand_total, amount_paid, amount_due, notes, is_locked, sales_rep_id,
			payment_term_name, payment_due_days, early_discount_percent, early_discount_days,
			created_at, updated_at, created_by, updated_by
		FROM sales.invoices
		WHERE company_id=$1 AND due_date < $2 AND status NOT IN ('paid','cancelled')
		ORDER BY ` + order + `
		LIMIT $3 OFFSET $4
	`
	rows, err := s.pgClient.Query(ctx, query, companyID, at, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var invoices []*models.Invoice
	for rows.Next() {
		var inv models.Invoice
		if err := rows.Scan(
			&inv.InvoiceID, &inv.CompanyID, &inv.OrderID, &inv.CustomerID, &inv.InvoiceNumber, &inv.ExternalRef,
			&inv.InvoiceDate, &inv.DueDate, &inv.Status, &inv.Currency, &inv.ExchangeRate, &inv.Subtotal,
			&inv.DiscountTotal, &inv.TaxTotal, &inv.GrandTotal, &inv.AmountPaid, &inv.AmountDue, &inv.Notes,
			&inv.IsLocked, &inv.SalesRepID, &inv.PaymentTermName, &inv.PaymentDueDays,
			&inv.EarlyDiscountPercent, &inv.EarlyDiscountDays,
			&inv.CreatedAt, &inv.UpdatedAt, &inv.CreatedBy, &inv.UpdatedBy,
		); err != nil {
			return nil, 0, err
		}
		invoices = append(invoices, &inv)
	}

	var total int64
	err = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.invoices WHERE company_id=$1 AND due_date < $2 AND status NOT IN ('paid','cancelled')`,
		companyID, at).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	return invoices, total, nil
}

// GetOverdueInvoiceAging returns aging buckets for overdue invoices.
func (s *salesQueryService) GetOverdueInvoiceAging(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*InvoiceAgingBucket, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT
			CASE
				WHEN due_date >= $1 - interval '30 days' THEN '0-30 days'
				WHEN due_date >= $1 - interval '60 days' THEN '31-60 days'
				WHEN due_date >= $1 - interval '90 days' THEN '61-90 days'
				ELSE '90+ days'
			END as bucket,
			COUNT(*),
			COALESCE(SUM(amount_due),0)
		 FROM sales.invoices
		 WHERE company_id=$2 AND due_date < $1 AND status NOT IN ('paid','cancelled')
		 GROUP BY bucket`,
		at, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []*InvoiceAgingBucket
	for rows.Next() {
		var name string
		var cnt int
		var amt decimal.Decimal
		if err := rows.Scan(&name, &cnt, &amt); err != nil {
			return nil, err
		}
		buckets = append(buckets, &InvoiceAgingBucket{BucketName: name, Amount: amt, Count: cnt})
	}
	return buckets, nil
}

// GetInvoicesDueSoon returns invoices with due date before the given time.
func (s *salesQueryService) GetInvoicesDueSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Invoice, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT invoice_id, company_id, customer_id, invoice_number, invoice_date, due_date, status, grand_total, amount_due
		 FROM sales.invoices
		 WHERE company_id=$1 AND due_date <= $2 AND due_date >= NOW() AND status NOT IN ('paid','cancelled')`,
		companyID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invoices []*models.Invoice
	for rows.Next() {
		var inv models.Invoice
		if err := rows.Scan(&inv.InvoiceID, &inv.CompanyID, &inv.CustomerID, &inv.InvoiceNumber, &inv.InvoiceDate, &inv.DueDate, &inv.Status, &inv.GrandTotal, &inv.AmountDue); err != nil {
			return nil, err
		}
		invoices = append(invoices, &inv)
	}
	return invoices, nil
}

// GetInvoiceCollectionTrend returns collection efficiency over time.
func (s *salesQueryService) GetInvoiceCollectionTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*CollectionTrendPoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT date, collected_amount, total_receivables, collection_rate
		 FROM sales_analytics.collection_efficiency
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []*CollectionTrendPoint
	for rows.Next() {
		var date time.Time
		var collected, receivables, rate decimal.Decimal
		if err := rows.Scan(&date, &collected, &receivables, &rate); err != nil {
			return nil, err
		}
		points = append(points, &CollectionTrendPoint{
			Date:           date,
			Collected:      collected,
			Outstanding:    receivables,
			CollectionRate: rate,
		})
	}
	return points, nil
}

// GetAverageCollectionDays returns average days to payment for invoices.
func (s *salesQueryService) GetAverageCollectionDays(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	start, end := s.normalizeDateRange(from, to)
	var avgDays decimal.Decimal
	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(AVG(EXTRACT(DAY FROM (paid_at - invoice_date))),0)
		 FROM sales.invoices
		 WHERE company_id=$1 AND status='paid' AND paid_at IS NOT NULL AND invoice_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&avgDays)
	return avgDays, err
}

// GetPaymentSummary returns aggregated payment metrics.
func (s *salesQueryService) GetPaymentSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*PaymentSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &PaymentSummary{PeriodStart: start, PeriodEnd: end}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(*), COALESCE(SUM(amount),0),
			COUNT(CASE WHEN status='failed' THEN 1 END)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&summary.PaymentCount, &summary.TotalPayments, &summary.FailedPayments)
	if err != nil {
		return nil, err
	}
	if summary.PaymentCount > 0 {
		summary.AveragePayment = summary.TotalPayments.Div(decimal.NewFromInt(int64(summary.PaymentCount)))
	}

	var refunds decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0)
		 FROM sales.payment_refunds
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3 AND status='completed'`,
		companyID, start, end).Scan(&refunds)
	summary.TotalRefunds = refunds
	summary.NetCollections = summary.TotalPayments.Sub(refunds)
	return summary, nil
}

// GetPaymentMethodBreakdown returns payment amounts grouped by method.
func (s *salesQueryService) GetPaymentMethodBreakdown(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*PaymentMethodBreakdownRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT payment_method, COUNT(*), COALESCE(SUM(amount),0)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3 AND status='completed'
		 GROUP BY payment_method`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*PaymentMethodBreakdownRow
	var total decimal.Decimal
	var rowsData []*PaymentMethodBreakdownRow
	for rows.Next() {
		var method string
		var cnt int
		var amt decimal.Decimal
		if err := rows.Scan(&method, &cnt, &amt); err != nil {
			return nil, err
		}
		total = total.Add(amt)
		rowsData = append(rowsData, &PaymentMethodBreakdownRow{PaymentMethod: method, TotalAmount: amt, Count: cnt})
	}
	for _, r := range rowsData {
		if total.IsZero() {
			r.Percentage = decimal.Zero
		} else {
			r.Percentage = r.TotalAmount.Div(total).Mul(decimal.NewFromInt(100))
		}
		result = append(result, r)
	}
	return result, nil
}

// GetFailedPaymentAnalytics returns analysis of failed payments.
func (s *salesQueryService) GetFailedPaymentAnalytics(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*FailedPaymentAnalytics, error) {
	start, end := s.normalizeDateRange(from, to)
	analytics := &FailedPaymentAnalytics{
		ByReason: make(map[string]int),
		ByMethod: make(map[string]int),
	}

	rows, err := s.pgClient.Query(ctx,
		`SELECT failure_reason, payment_method
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3 AND status='failed'`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var reason sql.NullString
		var method string
		if err := rows.Scan(&reason, &method); err != nil {
			return nil, err
		}
		analytics.TotalFailed++
		if reason.Valid {
			analytics.ByReason[reason.String]++
		} else {
			analytics.ByReason["unknown"]++
		}
		analytics.ByMethod[method]++
	}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0)
		 FROM sales.payments
		 WHERE company_id=$1 AND payment_date BETWEEN $2 AND $3 AND status='failed'`,
		companyID, start, end).Scan(&analytics.TotalFailedAmount)
	return analytics, nil
}

// GetRefundSummary returns aggregated refund metrics.
func (s *salesQueryService) GetRefundSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*RefundSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &RefundSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(*), COALESCE(SUM(amount),0),
			COUNT(CASE WHEN amount = (SELECT amount FROM sales.payments WHERE payment_id = refunds.payment_id) THEN 1 END),
			COUNT(CASE WHEN amount < (SELECT amount FROM sales.payments WHERE payment_id = refunds.payment_id) THEN 1 END)
		 FROM sales.payment_refunds
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3 AND status='completed'`,
		companyID, start, end).Scan(&summary.RefundCount, &summary.TotalRefunds, &summary.FullRefunds, &summary.PartialRefunds)
	if err != nil {
		return nil, err
	}
	if summary.RefundCount > 0 {
		summary.AverageRefundAmount = summary.TotalRefunds.Div(decimal.NewFromInt(int64(summary.RefundCount)))
	}
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(total_amount),0)
		 FROM sales.credit_notes
		 WHERE company_id=$1 AND issued_at BETWEEN $2 AND $3 AND status='issued'`,
		companyID, start, end).Scan(&summary.CreditNotesIssued)
	return summary, nil
}

// GetTopSellingProducts returns products with highest revenue.
func (s *salesQueryService) GetTopSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*TopSellingProductRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.name, SUM(oi.quantity) as qty, SUM(oi.quantity * oi.unit_price) as rev
		 FROM sales.order_items oi
		 JOIN sales.orders o ON o.order_id = oi.order_id
		 JOIN sales.products p ON p.product_id = oi.product_id
		 WHERE o.company_id=$1 AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 GROUP BY p.product_id, p.name
		 ORDER BY rev DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*TopSellingProductRow
	for rows.Next() {
		var pid uuid.UUID
		var name string
		var qty, rev decimal.Decimal
		if err := rows.Scan(&pid, &name, &qty, &rev); err != nil {
			return nil, err
		}
		result = append(result, &TopSellingProductRow{
			ProductID:    pid,
			ProductName:  name,
			QuantitySold: qty,
			Revenue:      rev,
		})
	}
	return result, nil
}

// GetLeastSellingProducts returns products with lowest revenue.
func (s *salesQueryService) GetLeastSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*LeastSellingProductRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.name, COALESCE(SUM(oi.quantity),0) as qty, COALESCE(SUM(oi.quantity * oi.unit_price),0) as rev
		 FROM sales.products p
		 LEFT JOIN sales.order_items oi ON oi.product_id = p.product_id
		 LEFT JOIN sales.orders o ON o.order_id = oi.order_id AND o.company_id=p.company_id
		  AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 WHERE p.company_id=$1
		 GROUP BY p.product_id, p.name
		 ORDER BY rev ASC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*LeastSellingProductRow
	for rows.Next() {
		var pid uuid.UUID
		var name string
		var qty, rev decimal.Decimal
		if err := rows.Scan(&pid, &name, &qty, &rev); err != nil {
			return nil, err
		}
		result = append(result, &LeastSellingProductRow{
			ProductID:    pid,
			ProductName:  name,
			QuantitySold: qty,
			Revenue:      rev,
		})
	}
	return result, nil
}

// GetProductSalesTrend returns sales over time for a specific product.
func (s *salesQueryService) GetProductSalesTrend(ctx context.Context, companyID uuid.UUID, productID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*ProductSalesTrendPoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT date, quantity_sold, revenue
		 FROM sales_analytics.product_sales_fact
		 WHERE company_id=$1 AND product_id=$2 AND date BETWEEN $3 AND $4`,
		companyID, productID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []*ProductSalesTrendPoint
	for rows.Next() {
		var date time.Time
		var qty, rev decimal.Decimal
		if err := rows.Scan(&date, &qty, &rev); err != nil {
			return nil, err
		}
		points = append(points, &ProductSalesTrendPoint{Date: date, QuantitySold: qty, Revenue: rev})
	}

	if granularity != GranularityDaily {
		aggMap := make(map[string]*ProductSalesTrendPoint)
		for _, p := range points {
			key := s.truncateByGranularity(p.Date, granularity)
			keyStr := key.Format("2006-01-02")
			if existing, ok := aggMap[keyStr]; ok {
				existing.QuantitySold = existing.QuantitySold.Add(p.QuantitySold)
				existing.Revenue = existing.Revenue.Add(p.Revenue)
			} else {
				aggMap[keyStr] = &ProductSalesTrendPoint{Date: key, QuantitySold: p.QuantitySold, Revenue: p.Revenue}
			}
		}
		points = make([]*ProductSalesTrendPoint, 0, len(aggMap))
		for _, v := range aggMap {
			points = append(points, v)
		}
	}
	return points, nil
}

// GetProductsNeverSold returns products that have never been sold.
func (s *salesQueryService) GetProductsNeverSold(ctx context.Context, companyID uuid.UUID) ([]*models.Product, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.company_id, p.sku, p.name, p.unit_price, p.is_active
		 FROM sales.products p
		 LEFT JOIN sales.order_items oi ON oi.product_id = p.product_id
		 LEFT JOIN sales.orders o ON o.order_id = oi.order_id
		 WHERE p.company_id=$1 AND o.order_id IS NULL`,
		companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*models.Product
	for rows.Next() {
		var prod models.Product
		if err := rows.Scan(&prod.ProductID, &prod.CompanyID, &prod.SKU, &prod.Name, &prod.UnitPrice, &prod.IsActive); err != nil {
			return nil, err
		}
		products = append(products, &prod)
	}
	return products, nil
}

// GetMostReturnedProducts returns products with highest return counts.
func (s *salesQueryService) GetMostReturnedProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*MostReturnedProductRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.name, COUNT(ri.return_item_id) as return_count, COALESCE(SUM(ri.refund_amount),0) as refund_amt
		 FROM sales.return_items ri
		 JOIN sales.returns r ON r.return_id = ri.return_id
		 JOIN sales.products p ON p.product_id = ri.product_id
		 WHERE r.company_id=$1 AND r.return_date BETWEEN $2 AND $3 AND r.status='completed'
		 GROUP BY p.product_id, p.name
		 ORDER BY return_count DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*MostReturnedProductRow
	for rows.Next() {
		var pid uuid.UUID
		var name string
		var cnt int
		var amt decimal.Decimal
		if err := rows.Scan(&pid, &name, &cnt, &amt); err != nil {
			return nil, err
		}
		result = append(result, &MostReturnedProductRow{
			ProductID:    pid,
			ProductName:  name,
			ReturnCount:  cnt,
			ReturnAmount: amt,
		})
	}
	return result, nil
}

// GetReturnSummary returns aggregated return metrics.
func (s *salesQueryService) GetReturnSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*ReturnSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &ReturnSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COUNT(*),
			COUNT(CASE WHEN status='approved' THEN 1 END),
			COUNT(CASE WHEN status='completed' THEN 1 END),
			COUNT(CASE WHEN status='rejected' THEN 1 END),
			COALESCE(SUM(total_refund),0),
			COALESCE(SUM(CASE WHEN credit_note_id IS NOT NULL THEN total_refund ELSE 0 END),0)
		 FROM sales.returns
		 WHERE company_id=$1 AND return_date BETWEEN $2 AND $3`,
		companyID, start, end).Scan(
		&summary.TotalReturns,
		&summary.ApprovedReturns,
		&summary.CompletedReturns,
		&summary.RejectedReturns,
		&summary.TotalRefundAmount,
		&summary.TotalCreditNoteAmount)
	if err != nil {
		return nil, err
	}

	var totalOrders int
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&totalOrders)
	if totalOrders > 0 {
		summary.ReturnRate = decimal.NewFromInt(int64(summary.CompletedReturns)).
			Div(decimal.NewFromInt(int64(totalOrders))).
			Mul(decimal.NewFromInt(100))
	}
	return summary, nil
}

// GetReturnRateTrend returns return rate over time.
func (s *salesQueryService) GetReturnRateTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*ReturnRateTrendPoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT date, total_returns_completed,
			(SELECT COUNT(*) FROM sales.orders o WHERE o.company_id=$1 AND o.order_date = d.date AND o.status NOT IN ('cancelled')) as orders
		 FROM sales_analytics.daily_return_metrics d
		 WHERE d.company_id=$1 AND date BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []*ReturnRateTrendPoint
	for rows.Next() {
		var date time.Time
		var returns, orders int
		if err := rows.Scan(&date, &returns, &orders); err != nil {
			return nil, err
		}
		rate := decimal.Zero
		if orders > 0 {
			rate = decimal.NewFromInt(int64(returns)).Div(decimal.NewFromInt(int64(orders))).Mul(decimal.NewFromInt(100))
		}
		points = append(points, &ReturnRateTrendPoint{Date: date, ReturnRate: rate})
	}

	if granularity != GranularityDaily {
		agg := make(map[string]*ReturnRateTrendPoint)
		for _, p := range points {
			key := s.truncateByGranularity(p.Date, granularity)
			keyStr := key.Format("2006-01-02")
			if _, ok := agg[keyStr]; !ok {
				agg[keyStr] = p
			}
		}
		points = make([]*ReturnRateTrendPoint, 0, len(agg))
		for _, v := range agg {
			points = append(points, v)
		}
	}
	return points, nil
}

// GetRefundLiabilitySummary returns current refund and credit note obligations.
func (s *salesQueryService) GetRefundLiabilitySummary(ctx context.Context, companyID uuid.UUID) (*RefundLiabilitySummary, error) {
	summary := &RefundLiabilitySummary{}
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0) FROM sales.payment_refunds WHERE company_id=$1 AND status='pending'`,
		companyID).Scan(&summary.PendingRefunds)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0) FROM sales.payment_refunds WHERE company_id=$1 AND status='approved'`,
		companyID).Scan(&summary.ApprovedRefunds)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0) FROM sales.payment_refunds WHERE company_id=$1 AND status='completed'`,
		companyID).Scan(&summary.CompletedRefunds)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(remaining_amount),0) FROM sales.credit_notes WHERE company_id=$1 AND status IN ('issued','partially_used')`,
		companyID).Scan(&summary.OutstandingCreditNotes)
	summary.TotalLiability = summary.PendingRefunds.Add(summary.ApprovedRefunds).Add(summary.OutstandingCreditNotes)
	return summary, nil
}

// GetDiscountSummary returns aggregated discount usage.
func (s *salesQueryService) GetDiscountSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*DiscountSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &DiscountSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COALESCE(SUM(amount),0),
			COALESCE(SUM(CASE WHEN discount_type='coupon' THEN amount ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN discount_type='promotion' THEN amount ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN discount_type='auto' THEN amount ELSE 0 END),0)
		 FROM sales.discount_applications
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(
		&summary.TotalDiscountAmount,
		&summary.TotalCouponDiscount,
		&summary.TotalPromotionDiscount,
		&summary.TotalAutoDiscount)
	if err != nil {
		return nil, err
	}

	var avgRate decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(AVG(total_discounts / total_revenue),0)
		 FROM sales_analytics.daily_sales
		 WHERE company_id=$1 AND date BETWEEN $2 AND $3 AND total_revenue > 0`,
		companyID, start, end).Scan(&avgRate)
	summary.AverageDiscountRate = avgRate

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(DISTINCT discount_id)
		 FROM sales.discount_applications
		 WHERE company_id=$1 AND discount_type='coupon' AND created_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&summary.UniqueCouponsUsed)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(DISTINCT discount_id)
		 FROM sales.discount_applications
		 WHERE company_id=$1 AND discount_type='promotion' AND created_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&summary.UniquePromotionsUsed)
	return summary, nil
}

// GetCouponPerformance returns coupon performance metrics.
func (s *salesQueryService) GetCouponPerformance(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*CouponPerformanceRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT c.coupon_id, c.code, COUNT(*) as times_used, COALESCE(SUM(da.amount),0) as total_discount
		 FROM sales.discount_applications da
		 JOIN sales.coupons c ON c.coupon_id = da.discount_id
		 WHERE da.company_id=$1 AND da.discount_type='coupon' AND da.created_at BETWEEN $2 AND $3
		 GROUP BY c.coupon_id, c.code
		 ORDER BY total_discount DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CouponPerformanceRow
	for rows.Next() {
		var cid uuid.UUID
		var code string
		var used int
		var total decimal.Decimal
		if err := rows.Scan(&cid, &code, &used, &total); err != nil {
			return nil, err
		}
		avg := decimal.Zero
		if used > 0 {
			avg = total.Div(decimal.NewFromInt(int64(used)))
		}
		result = append(result, &CouponPerformanceRow{
			CouponID:        cid,
			CouponCode:      code,
			TimesUsed:       used,
			TotalDiscount:   total,
			AverageDiscount: avg,
		})
	}
	return result, nil
}

// GetPromotionPerformance returns promotion performance metrics.
func (s *salesQueryService) GetPromotionPerformance(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*PromotionPerformanceRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.promotion_id, p.name, COUNT(*) as times_used, COALESCE(SUM(da.amount),0) as total_discount
		 FROM sales.discount_applications da
		 JOIN sales.promotions p ON p.promotion_id = da.discount_id
		 WHERE da.company_id=$1 AND da.discount_type='promotion' AND da.created_at BETWEEN $2 AND $3
		 GROUP BY p.promotion_id, p.name
		 ORDER BY total_discount DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*PromotionPerformanceRow
	for rows.Next() {
		var pid uuid.UUID
		var name string
		var used int
		var total decimal.Decimal
		if err := rows.Scan(&pid, &name, &used, &total); err != nil {
			return nil, err
		}
		avg := decimal.Zero
		if used > 0 {
			avg = total.Div(decimal.NewFromInt(int64(used)))
		}
		result = append(result, &PromotionPerformanceRow{
			PromotionID:     pid,
			PromotionName:   name,
			TimesUsed:       used,
			TotalDiscount:   total,
			AverageDiscount: avg,
		})
	}
	return result, nil
}

// GetDiscountImpactOnRevenue calculates the effect of discounts on revenue.
func (s *salesQueryService) GetDiscountImpactOnRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*DiscountRevenueImpact, error) {
	start, end := s.normalizeDateRange(from, to)
	impact := &DiscountRevenueImpact{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(grand_total),0), COALESCE(SUM(discount_total),0)
		 FROM sales.orders
		 WHERE company_id=$1 AND order_date BETWEEN $2 AND $3 AND status NOT IN ('cancelled')`,
		companyID, start, end).Scan(&impact.GrossRevenue, &impact.DiscountAmount)
	if err != nil {
		return nil, err
	}
	impact.NetRevenue = impact.GrossRevenue.Sub(impact.DiscountAmount)
	if !impact.GrossRevenue.IsZero() {
		impact.DiscountPercentage = impact.DiscountAmount.Div(impact.GrossRevenue).Mul(decimal.NewFromInt(100))
	}
	return impact, nil
}

// GetTaxSummary returns aggregated tax amounts.
func (s *salesQueryService) GetTaxSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*TaxSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &TaxSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(taxable_amount),0), COALESCE(SUM(tax_amount),0)
		 FROM sales.tax_snapshots
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(&summary.TotalTaxableAmount, &summary.TotalTaxAmount)
	if err != nil {
		return nil, err
	}
	if !summary.TotalTaxableAmount.IsZero() {
		summary.EffectiveTaxRate = summary.TotalTaxAmount.Div(summary.TotalTaxableAmount).Mul(decimal.NewFromInt(100))
	}
	return summary, nil
}

// GetTaxBreakdownByRate returns tax collected per tax rate.
func (s *salesQueryService) GetTaxBreakdownByRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*TaxRateBreakdownRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT COALESCE(tax_name, 'Unknown'), COALESCE(tax_percentage,0), SUM(taxable_amount), SUM(tax_amount)
		 FROM sales.tax_snapshots
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3
		 GROUP BY tax_name, tax_percentage`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*TaxRateBreakdownRow
	for rows.Next() {
		var name string
		var pct, taxable, tax decimal.Decimal
		if err := rows.Scan(&name, &pct, &taxable, &tax); err != nil {
			return nil, err
		}
		result = append(result, &TaxRateBreakdownRow{
			TaxRateName:   name,
			TaxPercentage: pct,
			TaxableAmount: taxable,
			TaxAmount:     tax,
		})
	}
	return result, nil
}

// GetTaxBreakdownByJurisdiction is a stub – implement if jurisdiction data available.
func (s *salesQueryService) GetTaxBreakdownByJurisdiction(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*JurisdictionTaxBreakdownRow, error) {
	return []*JurisdictionTaxBreakdownRow{}, nil
}

// GetTaxBreakdownByProduct returns tax collected per product.
func (s *salesQueryService) GetTaxBreakdownByProduct(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*ProductTaxBreakdownRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT p.product_id, p.name, SUM(ts.taxable_amount), SUM(ts.tax_amount)
		 FROM sales.tax_snapshots ts
		 JOIN sales.invoice_items ii ON ii.invoice_item_id = ts.line_id
		 JOIN sales.products p ON p.product_id = ii.product_id
		 WHERE ts.company_id=$1 AND ts.created_at BETWEEN $2 AND $3 AND ts.entity_type='invoice_item'
		 GROUP BY p.product_id, p.name
		 ORDER BY SUM(ts.tax_amount) DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ProductTaxBreakdownRow
	for rows.Next() {
		var pid uuid.UUID
		var name string
		var taxable, tax decimal.Decimal
		if err := rows.Scan(&pid, &name, &taxable, &tax); err != nil {
			return nil, err
		}
		result = append(result, &ProductTaxBreakdownRow{
			ProductID:     pid,
			ProductName:   name,
			TaxableAmount: taxable,
			TaxAmount:     tax,
		})
	}
	return result, nil
}

// GetCollectedTaxTrend returns tax collected over time.
func (s *salesQueryService) GetCollectedTaxTrend(ctx context.Context, companyID uuid.UUID, granularity AnalyticsGranularity, from, to *time.Time) ([]*CollectedTaxTrendPoint, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT DATE(created_at) as date, SUM(tax_amount) as tax
		 FROM sales.tax_snapshots
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3
		 GROUP BY DATE(created_at)`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []*CollectedTaxTrendPoint
	for rows.Next() {
		var date time.Time
		var tax decimal.Decimal
		if err := rows.Scan(&date, &tax); err != nil {
			return nil, err
		}
		points = append(points, &CollectedTaxTrendPoint{Date: date, TaxCollected: tax})
	}
	return points, nil
}

// GetTaxAuditReport returns detailed tax audit rows.
func (s *salesQueryService) GetTaxAuditReport(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*TaxAuditReportRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT entity_type, entity_id, taxable_amount, tax_amount, COALESCE(tax_percentage,0) as rate, created_at
		 FROM sales.tax_snapshots
		 WHERE company_id=$1 AND created_at BETWEEN $2 AND $3`,
		companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*TaxAuditReportRow
	for rows.Next() {
		var etype string
		var eid uuid.UUID
		var taxable, tax, rate decimal.Decimal
		var createdAt time.Time
		if err := rows.Scan(&etype, &eid, &taxable, &tax, &rate, &createdAt); err != nil {
			return nil, err
		}
		result = append(result, &TaxAuditReportRow{
			EntityType:    etype,
			EntityID:      eid,
			TaxableAmount: taxable,
			TaxAmount:     tax,
			TaxRate:       rate,
			CreatedAt:     createdAt,
		})
	}
	return result, nil
}

// GetSalesRepPerformance returns performance summary for a sales rep.
func (s *salesQueryService) GetSalesRepPerformance(ctx context.Context, companyID uuid.UUID, salesRepID uuid.UUID, from, to *time.Time) (*SalesRepPerformanceSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &SalesRepPerformanceSummary{SalesRepID: salesRepID}

	err := s.pgClient.QueryRow(ctx,
		`SELECT name FROM sales.sales_reps WHERE sales_rep_id=$1 AND company_id=$2`,
		salesRepID, companyID).Scan(&summary.Name)
	if err != nil {
		return nil, err
	}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(grand_total),0)
		 FROM sales.orders
		 WHERE sales_rep_id=$1 AND company_id=$2 AND order_date BETWEEN $3 AND $4 AND status NOT IN ('cancelled')`,
		salesRepID, companyID, start, end).Scan(&summary.TotalOrders, &summary.TotalRevenue)
	if summary.TotalOrders > 0 {
		summary.AverageOrderValue = summary.TotalRevenue.Div(decimal.NewFromInt(int64(summary.TotalOrders)))
	}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(commission_amount),0)
		 FROM sales.sales_commissions
		 WHERE sales_rep_id=$1 AND company_id=$2 AND earned_at BETWEEN $3 AND $4 AND status='paid'`,
		salesRepID, companyID, start, end).Scan(&summary.TotalCommission)

	var targetAmt decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT target_amount FROM sales.sales_targets
		 WHERE sales_rep_id=$1 AND company_id=$2 AND period_start <= $4 AND period_end >= $3`,
		salesRepID, companyID, start, end).Scan(&targetAmt)
	summary.TargetAmount = targetAmt
	if !targetAmt.IsZero() {
		summary.AchievementPercent = summary.TotalRevenue.Div(targetAmt).Mul(decimal.NewFromInt(100))
	}
	return summary, nil
}

// GetSalesLeaderboard returns ranking of sales reps by revenue.
func (s *salesQueryService) GetSalesLeaderboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time, limit int) ([]*SalesLeaderboardRow, error) {
	start, end := s.normalizeDateRange(from, to)

	rows, err := s.pgClient.Query(ctx,
		`SELECT sr.sales_rep_id, sr.name, COALESCE(SUM(o.grand_total),0) as revenue, COUNT(o.order_id) as orders, COALESCE(SUM(sc.commission_amount),0) as commission
		 FROM sales.sales_reps sr
		 LEFT JOIN sales.orders o ON o.sales_rep_id = sr.sales_rep_id AND o.company_id=sr.company_id
		  AND o.order_date BETWEEN $2 AND $3 AND o.status NOT IN ('cancelled')
		 LEFT JOIN sales.sales_commissions sc ON sc.sales_rep_id = sr.sales_rep_id AND sc.company_id=sr.company_id
		  AND sc.earned_at BETWEEN $2 AND $3 AND sc.status='paid'
		 WHERE sr.company_id=$1
		 GROUP BY sr.sales_rep_id, sr.name
		 ORDER BY revenue DESC
		 LIMIT $4`,
		companyID, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*SalesLeaderboardRow
	rank := 1
	for rows.Next() {
		var id uuid.UUID
		var name string
		var rev, comm decimal.Decimal
		var orders int
		if err := rows.Scan(&id, &name, &rev, &orders, &comm); err != nil {
			return nil, err
		}
		result = append(result, &SalesLeaderboardRow{
			Rank:        rank,
			SalesRepID:  id,
			Name:        name,
			Revenue:     rev,
			OrdersCount: orders,
			Commission:  comm,
		})
		rank++
	}
	return result, nil
}

// GetCommissionSummary returns aggregated commission metrics.
func (s *salesQueryService) GetCommissionSummary(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (*CommissionSummary, error) {
	start, end := s.normalizeDateRange(from, to)
	summary := &CommissionSummary{PeriodStart: start, PeriodEnd: end}

	err := s.pgClient.QueryRow(ctx,
		`SELECT
			COALESCE(SUM(commission_amount),0),
			COALESCE(SUM(CASE WHEN status='paid' THEN commission_amount ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN status='pending' THEN commission_amount ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN status='approved' THEN commission_amount ELSE 0 END),0),
			COALESCE(AVG(commission_rate),0)
		 FROM sales.sales_commissions
		 WHERE company_id=$1 AND earned_at BETWEEN $2 AND $3`,
		companyID, start, end).Scan(
		&summary.TotalEarned,
		&summary.TotalPaid,
		&summary.TotalPending,
		&summary.TotalApproved,
		&summary.AverageCommissionRate)
	if err != nil {
		return nil, err
	}
	return summary, nil
}

// GetCreditRiskSummary returns company‑wide credit risk metrics.
func (s *salesQueryService) GetCreditRiskSummary(ctx context.Context, companyID uuid.UUID) (*CreditRiskSummary, error) {
	summary := &CreditRiskSummary{}

	err := s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(credit_limit),0), COALESCE(SUM(outstanding_balance),0)
		 FROM sales_analytics.current_customer_credit
		 WHERE company_id=$1`,
		companyID).Scan(&summary.TotalCreditLimit, &summary.TotalOutstanding)
	if err != nil {
		return nil, err
	}
	summary.TotalAvailableCredit = summary.TotalCreditLimit.Sub(summary.TotalOutstanding)
	if !summary.TotalCreditLimit.IsZero() {
		summary.AverageUtilization = summary.TotalOutstanding.Div(summary.TotalCreditLimit).Mul(decimal.NewFromInt(100))
	}

	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales_analytics.current_customer_credit WHERE company_id=$1 AND outstanding_balance > credit_limit`,
		companyID).Scan(&summary.CustomersExceedingLimit)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales_analytics.current_customer_credit WHERE company_id=$1 AND (outstanding_balance / credit_limit) >= 0.9 AND credit_limit > 0`,
		companyID).Scan(&summary.CustomersNearLimit)
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND credit_hold=true`,
		companyID).Scan(&summary.OrdersOnCreditHold)
	return summary, nil
}

// GetCustomersNearCreditLimit returns customers whose credit utilisation exceeds threshold.
func (s *salesQueryService) GetCustomersNearCreditLimit(ctx context.Context, companyID uuid.UUID, thresholdPercent decimal.Decimal) ([]*CustomerCreditUtilizationRow, error) {
	threshold := thresholdPercent.Div(decimal.NewFromInt(100))

	rows, err := s.pgClient.Query(ctx,
		`SELECT customer_id, credit_limit, outstanding_balance, (outstanding_balance / credit_limit) as util
		 FROM sales_analytics.current_customer_credit
		 WHERE company_id=$1 AND credit_limit > 0 AND (outstanding_balance / credit_limit) >= $2`,
		companyID, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CustomerCreditUtilizationRow
	for rows.Next() {
		var cid uuid.UUID
		var limit, outstanding, util decimal.Decimal
		if err := rows.Scan(&cid, &limit, &outstanding, &util); err != nil {
			return nil, err
		}
		var name string
		_ = s.pgClient.QueryRow(ctx, `SELECT name FROM sales.customers WHERE customer_id=$1`, cid).Scan(&name)
		result = append(result, &CustomerCreditUtilizationRow{
			CustomerID:     cid,
			CustomerName:   name,
			CreditLimit:    limit,
			Outstanding:    outstanding,
			UtilizationPct: util.Mul(decimal.NewFromInt(100)),
		})
	}
	return result, nil
}

// GetCustomersExceedingCreditLimit returns customers who exceeded their credit limit.
func (s *salesQueryService) GetCustomersExceedingCreditLimit(ctx context.Context, companyID uuid.UUID) ([]*CustomerCreditExposureRow, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT customer_id, credit_limit, outstanding_balance, (outstanding_balance - credit_limit) as exceed
		 FROM sales_analytics.current_customer_credit
		 WHERE company_id=$1 AND outstanding_balance > credit_limit`,
		companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CustomerCreditExposureRow
	for rows.Next() {
		var cid uuid.UUID
		var limit, outstanding, exceed decimal.Decimal
		if err := rows.Scan(&cid, &limit, &outstanding, &exceed); err != nil {
			return nil, err
		}
		var name string
		_ = s.pgClient.QueryRow(ctx, `SELECT name FROM sales.customers WHERE customer_id=$1`, cid).Scan(&name)
		result = append(result, &CustomerCreditExposureRow{
			CustomerID:   cid,
			CustomerName: name,
			CreditLimit:  limit,
			Outstanding:  outstanding,
			ExceedAmount: exceed,
		})
	}
	return result, nil
}

// GetOrdersOnCreditHold returns orders currently on credit hold.
func (s *salesQueryService) GetOrdersOnCreditHold(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error) {
	rows, err := s.pgClient.Query(ctx,
		`SELECT order_id, company_id, customer_id, order_number, order_date, status, grand_total, credit_hold, credit_status
		 FROM sales.orders
		 WHERE company_id=$1 AND credit_hold=true`,
		companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orders []*models.Order
	for rows.Next() {
		var o models.Order
		if err := rows.Scan(&o.OrderID, &o.CompanyID, &o.CustomerID, &o.OrderNumber, &o.OrderDate, &o.Status, &o.GrandTotal, &o.CreditHold, &o.CreditStatus); err != nil {
			return nil, err
		}
		orders = append(orders, &o)
	}
	return orders, nil
}

// GetSalesReport returns a comprehensive sales report.
func (s *salesQueryService) GetSalesReport(ctx context.Context, req *SalesReportRequest) (*SalesReportResult, error) {
	result := &SalesReportResult{}
	summary, err := s.GetSalesDashboard(ctx, req.CompanyID, req.From, req.To)
	if err != nil {
		return nil, err
	}
	result.Summary = summary

	trend, err := s.GetRevenueTrend(ctx, req.CompanyID, req.Granularity, req.From, req.To)
	if err != nil {
		return nil, err
	}
	result.Trend = trend

	if req.IncludeDetails {
		topCust, _ := s.GetTopCustomers(ctx, req.CompanyID, 10, req.From, req.To)
		result.TopCustomers = topCust
		topProd, _ := s.GetTopSellingProducts(ctx, req.CompanyID, 10, req.From, req.To)
		result.TopProducts = topProd
	}
	return result, nil
}

// GetTaxReport returns a detailed tax report.
func (s *salesQueryService) GetTaxReport(ctx context.Context, req *TaxReportRequest) (*TaxReportResult, error) {
	result := &TaxReportResult{}
	summary, err := s.GetTaxSummary(ctx, req.CompanyID, req.From, req.To)
	if err != nil {
		return nil, err
	}
	result.Summary = summary

	byRate, err := s.GetTaxBreakdownByRate(ctx, req.CompanyID, req.From, req.To)
	if err != nil {
		return nil, err
	}
	result.ByRate = byRate

	trend, err := s.GetCollectedTaxTrend(ctx, req.CompanyID, req.Granularity, req.From, req.To)
	if err != nil {
		return nil, err
	}
	result.Trend = trend
	return result, nil
}

// GetReceivablesReport returns outstanding receivables analysis.
func (s *salesQueryService) GetReceivablesReport(ctx context.Context, req *ReceivablesReportRequest) (*ReceivablesReportResult, error) {
	result := &ReceivablesReportResult{}
	summary, err := s.GetOutstandingReceivablesSummary(ctx, req.CompanyID)
	if err != nil {
		return nil, err
	}
	result.TotalOutstanding = summary.TotalReceivables

	buckets, err := s.GetOverdueInvoiceAging(ctx, req.CompanyID, req.AsOf)
	if err != nil {
		return nil, err
	}
	result.AgingBuckets = buckets

	customers, err := s.GetCustomersWithOutstandingBalance(ctx, req.CompanyID)
	if err != nil {
		return nil, err
	}
	result.ByCustomer = customers
	return result, nil
}

// GetCustomerStatement returns a statement of invoices, payments, and credit notes for a customer.
func (s *salesQueryService) GetCustomerStatement(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, from, to *time.Time) (*CustomerStatementResult, error) {
	start, end := s.normalizeDateRange(from, to)
	statement := &CustomerStatementResult{
		CustomerID:  customerID,
		PeriodStart: start,
		PeriodEnd:   end,
	}
	err := s.pgClient.QueryRow(ctx, `SELECT name FROM sales.customers WHERE customer_id=$1 AND company_id=$2`, customerID, companyID).Scan(&statement.CustomerName)
	if err != nil {
		return nil, err
	}

	var opening decimal.Decimal
	_ = s.pgClient.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_due),0)
		 FROM sales.invoices
		 WHERE customer_id=$1 AND company_id=$2 AND invoice_date < $3 AND status NOT IN ('paid','cancelled')`,
		customerID, companyID, start).Scan(&opening)
	statement.OpeningBalance = opening

	// Invoices in period
	invoices, _, err := s.invoiceRepo.List(ctx, nil, repository.InvoiceFilter{
		CompanyID:       companyID,
		CustomerID:      &customerID,
		InvoiceDateFrom: &start,
		InvoiceDateTo:   &end,
	}, repository.Pagination{Limit: 1000, Offset: 0}, repository.Sort{Field: "invoice_date", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	statement.Invoices = invoices

	// Payments in period – use direct SQL because PaymentFilter doesn't have CustomerID
	paymentRows, err := s.pgClient.Query(ctx,
		`SELECT p.payment_id, p.company_id, p.payment_number, p.external_ref, p.payment_date, p.amount,
			p.payment_method, p.status, p.exchange_rate, p.reference, p.gateway_response, p.failure_reason,
			p.completed_at, p.refunded_amount, p.created_at, p.updated_at, p.created_by, p.updated_by
		 FROM sales.payments p
		 JOIN sales.payment_allocations pa ON pa.payment_id = p.payment_id
		 JOIN sales.invoices i ON i.invoice_id = pa.invoice_id
		 WHERE i.customer_id=$1 AND i.company_id=$2 AND p.payment_date BETWEEN $3 AND $4 AND p.status='completed'
		 GROUP BY p.payment_id
		 ORDER BY p.payment_date ASC`,
		customerID, companyID, start, end)
	if err != nil {
		return nil, err
	}
	defer paymentRows.Close()
	var payments []*models.Payment
	for paymentRows.Next() {
		var pmt models.Payment
		if err := paymentRows.Scan(
			&pmt.PaymentID, &pmt.CompanyID, &pmt.PaymentNumber, &pmt.ExternalRef, &pmt.PaymentDate, &pmt.Amount,
			&pmt.PaymentMethod, &pmt.Status, &pmt.ExchangeRate, &pmt.Reference, &pmt.GatewayResponse, &pmt.FailureReason,
			&pmt.CompletedAt, &pmt.RefundedAmount, &pmt.CreatedAt, &pmt.UpdatedAt, &pmt.CreatedBy, &pmt.UpdatedBy,
		); err != nil {
			return nil, err
		}
		payments = append(payments, &pmt)
	}
	statement.Payments = payments

	// Credit notes in period – use direct SQL because CreditNoteFilter doesn't have IssueDateFrom/To
	cnRows, err := s.pgClient.Query(ctx,
		`SELECT credit_note_id, company_id, customer_id, credit_note_number, invoice_id, return_id,
			issue_date, status, currency, subtotal, tax_total, total_amount, amount_applied, remaining_amount,
			reason, notes, issued_at, voided_at, void_reason, created_at, updated_at, created_by, updated_by
		 FROM sales.credit_notes
		 WHERE company_id=$1 AND customer_id=$2 AND issue_date BETWEEN $3 AND $4`,
		companyID, customerID, start, end)
	if err != nil {
		return nil, err
	}
	defer cnRows.Close()
	var creditNotes []*models.CreditNote
	for cnRows.Next() {
		var cn models.CreditNote
		if err := cnRows.Scan(
			&cn.CreditNoteID, &cn.CompanyID, &cn.CustomerID, &cn.CreditNoteNumber, &cn.InvoiceID, &cn.ReturnID,
			&cn.IssueDate, &cn.Status, &cn.Currency, &cn.Subtotal, &cn.TaxTotal, &cn.TotalAmount, &cn.AmountApplied, &cn.RemainingAmount,
			&cn.Reason, &cn.Notes, &cn.IssuedAt, &cn.VoidedAt, &cn.VoidReason, &cn.CreatedAt, &cn.UpdatedAt, &cn.CreatedBy, &cn.UpdatedBy,
		); err != nil {
			return nil, err
		}
		creditNotes = append(creditNotes, &cn)
	}
	statement.CreditNotes = creditNotes

	closing := opening
	for _, inv := range invoices {
		closing = closing.Add(inv.AmountDue)
	}
	for _, pmt := range payments {
		closing = closing.Sub(pmt.Amount)
	}
	statement.ClosingBalance = closing
	return statement, nil
}

// GetSalesAuditTrail returns audit trail entries (stub).
func (s *salesQueryService) GetSalesAuditTrail(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*SalesAuditEntry, error) {
	return []*SalesAuditEntry{}, nil
}
