package handler

import (
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/service"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

type ReportHandler struct {
	queryService service.SalesQueryService
	*BaseHandler
}

func NewReportHandler(queryService service.SalesQueryService, logger *zap.Logger) *ReportHandler {
	return &ReportHandler{
		queryService: queryService,
		BaseHandler:  &BaseHandler{logger: logger.Named("report_handler")},
	}
}
func (h *ReportHandler) GetSalesDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	dashboard, err := h.queryService.GetSalesDashboard(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get sales dashboard", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    dashboard,
	})
}
func (h *ReportHandler) GetTodaySalesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	summary, err := h.queryService.GetTodaySalesSummary(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get today sales summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetRealtimeSalesSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	snapshot, err := h.queryService.GetRealtimeSalesSnapshot(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get realtime sales snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    snapshot,
	})
}
func (h *ReportHandler) GetRevenueSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetRevenueSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetRevenueTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	allowed := map[string]bool{
		"daily":   true,
		"weekly":  true,
		"monthly": true,
		"yearly":  true,
	}
	if granularityStr != "" && !allowed[granularityStr] {
		h.respondWithError(w, http.StatusBadRequest,
			"invalid granularity (allowed: daily, weekly, monthly, yearly)")
		return
	}
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetRevenueTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if trend == nil {
		trend = []*service.RevenueTrendPoint{}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetRevenueByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	revenues, err := h.queryService.GetRevenueByCustomer(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get revenue by customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    revenues,
	})
}
func (h *ReportHandler) GetRevenueByProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	revenues, err := h.queryService.GetRevenueByProduct(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get revenue by product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    revenues,
	})
}
func (h *ReportHandler) GetRevenueByCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summaries, err := h.queryService.GetRevenueByCategory(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue by category", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}
func (h *ReportHandler) GetRevenueBySalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summaries, err := h.queryService.GetRevenueBySalesRep(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue by sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}
func (h *ReportHandler) GetRevenueByPaymentMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summaries, err := h.queryService.GetRevenueByPaymentMethod(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue by payment method", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}
func (h *ReportHandler) GetNetRevenueAfterReturns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	netRevenue, err := h.queryService.GetNetRevenueAfterReturns(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get net revenue after returns", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    netRevenue.String(),
	})
}
func (h *ReportHandler) GetTopCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	customers, err := h.queryService.GetTopCustomers(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top customers", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetCustomerSalesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := h.parseUUIDParam(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetCustomerSalesSummary(ctx, companyID, customerID, from, to)
	if err != nil {
		h.logger.Error("failed to get customer sales summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetCustomerLifetimeValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := h.parseUUIDParam(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	ltv, err := h.queryService.GetCustomerLifetimeValue(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer lifetime value", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ltv.String(),
	})
}
func (h *ReportHandler) GetCustomersWithOutstandingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	customers, err := h.queryService.GetCustomersWithOutstandingBalance(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get customers with outstanding balance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetCustomersWithOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	customers, err := h.queryService.GetCustomersWithOverdueInvoices(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get customers with overdue invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetInactiveCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "since parameter is required")
		return
	}
	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid since format (RFC3339)")
		return
	}
	customers, err := h.queryService.GetInactiveCustomers(ctx, companyID, since)
	if err != nil {
		h.logger.Error("failed to get inactive customers", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetNewCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	customers, err := h.queryService.GetNewCustomers(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get new customers", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if customers == nil {
		customers = []*models.Customer{}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetOrderSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetOrderSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get order summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetOrdersByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summaries, err := h.queryService.GetOrdersByStatus(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get orders by status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}
func (h *ReportHandler) GetTopOrdersByValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	orders, err := h.queryService.GetTopOrdersByValue(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top orders by value", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orders,
	})
}
func (h *ReportHandler) GetAverageOrderValueTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "daily":
		granularity = service.GranularityDaily
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetAverageOrderValueTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get average order value trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetOrderConversionFunnel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	funnel, err := h.queryService.GetOrderConversionFunnel(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get order conversion funnel", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    funnel,
	})
}
func (h *ReportHandler) GetQuoteSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetQuoteSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get quote summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetQuoteConversionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	metrics, err := h.queryService.GetQuoteConversionMetrics(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get quote conversion metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}
func (h *ReportHandler) GetQuotesExpiringSoon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before format (RFC3339)")
		return
	}
	quotes, err := h.queryService.GetQuotesExpiringSoon(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get quotes expiring soon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    quotes,
	})
}
func (h *ReportHandler) GetInvoiceSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetInvoiceSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get invoice summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetOutstandingReceivablesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	summary, err := h.queryService.GetOutstandingReceivablesSummary(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get outstanding receivables summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "at parameter is required")
		return
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at format (RFC3339)")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "due_date"
	}
	if sort.Direction == "" {
		sort.Direction = "ASC"
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	invoices, total, err := h.queryService.GetOverdueInvoices(ctx, companyID, at, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get overdue invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoices": invoices,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		},
	})
}
func (h *ReportHandler) GetOverdueInvoiceAging(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "at parameter is required")
		return
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at format (RFC3339)")
		return
	}
	buckets, err := h.queryService.GetOverdueInvoiceAging(ctx, companyID, at)
	if err != nil {
		h.logger.Error("failed to get overdue invoice aging", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    buckets,
	})
}
func (h *ReportHandler) GetInvoicesDueSoon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before format (RFC3339)")
		return
	}
	invoices, err := h.queryService.GetInvoicesDueSoon(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get invoices due soon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoices,
	})
}
func (h *ReportHandler) GetInvoiceCollectionTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "daily":
		granularity = service.GranularityDaily
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetInvoiceCollectionTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get invoice collection trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetAverageCollectionDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	days, err := h.queryService.GetAverageCollectionDays(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get average collection days", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    days.String(),
	})
}
func (h *ReportHandler) GetPaymentSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetPaymentSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get payment summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetPaymentMethodBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	breakdown, err := h.queryService.GetPaymentMethodBreakdown(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get payment method breakdown", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    breakdown,
	})
}
func (h *ReportHandler) GetFailedPaymentAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	analytics, err := h.queryService.GetFailedPaymentAnalytics(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get failed payment analytics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    analytics,
	})
}
func (h *ReportHandler) GetRefundSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetRefundSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get refund summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetTopSellingProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	products, err := h.queryService.GetTopSellingProducts(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top selling products", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    products,
	})
}
func (h *ReportHandler) GetLeastSellingProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	products, err := h.queryService.GetLeastSellingProducts(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get least selling products", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    products,
	})
}
func (h *ReportHandler) GetProductSalesTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	productID, err := h.parseUUIDParam(r, "product_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "daily":
		granularity = service.GranularityDaily
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetProductSalesTrend(ctx, companyID, productID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get product sales trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetProductsNeverSold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	products, err := h.queryService.GetProductsNeverSold(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get products never sold", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    products,
	})
}
func (h *ReportHandler) GetMostReturnedProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	products, err := h.queryService.GetMostReturnedProducts(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get most returned products", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    products,
	})
}
func (h *ReportHandler) GetReturnSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetReturnSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get return summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetReturnRateTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "daily":
		granularity = service.GranularityDaily
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetReturnRateTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get return rate trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetRefundLiabilitySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	summary, err := h.queryService.GetRefundLiabilitySummary(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get refund liability summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetDiscountSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetDiscountSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get discount summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetCouponPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	performance, err := h.queryService.GetCouponPerformance(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get coupon performance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    performance,
	})
}
func (h *ReportHandler) GetPromotionPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	performance, err := h.queryService.GetPromotionPerformance(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get promotion performance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    performance,
	})
}
func (h *ReportHandler) GetDiscountImpactOnRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	impact, err := h.queryService.GetDiscountImpactOnRevenue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get discount impact on revenue", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    impact,
	})
}
func (h *ReportHandler) GetTaxSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetTaxSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get tax summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetTaxBreakdownByRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	breakdown, err := h.queryService.GetTaxBreakdownByRate(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get tax breakdown by rate", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    breakdown,
	})
}
func (h *ReportHandler) GetTaxBreakdownByJurisdiction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	breakdown, err := h.queryService.GetTaxBreakdownByJurisdiction(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get tax breakdown by jurisdiction", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    breakdown,
	})
}
func (h *ReportHandler) GetTaxBreakdownByProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	breakdown, err := h.queryService.GetTaxBreakdownByProduct(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get tax breakdown by product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    breakdown,
	})
}
func (h *ReportHandler) GetCollectedTaxTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "daily":
		granularity = service.GranularityDaily
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	trend, err := h.queryService.GetCollectedTaxTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get collected tax trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}
func (h *ReportHandler) GetTaxAuditReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	report, err := h.queryService.GetTaxAuditReport(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get tax audit report", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    report,
	})
}
func (h *ReportHandler) GetSalesRepPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	salesRepID, err := h.parseUUIDParam(r, "sales_rep_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	performance, err := h.queryService.GetSalesRepPerformance(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get sales rep performance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    performance,
	})
}
func (h *ReportHandler) GetSalesLeaderboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	leaderboard, err := h.queryService.GetSalesLeaderboard(ctx, companyID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get sales leaderboard", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaderboard,
	})
}
func (h *ReportHandler) GetCommissionSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	summary, err := h.queryService.GetCommissionSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get commission summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetCreditRiskSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	summary, err := h.queryService.GetCreditRiskSummary(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get credit risk summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}
func (h *ReportHandler) GetCustomersNearCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	thresholdStr := r.URL.Query().Get("threshold_percent")
	if thresholdStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "threshold_percent parameter is required")
		return
	}
	threshold, err := decimal.NewFromString(thresholdStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid threshold_percent")
		return
	}
	if threshold.GreaterThan(decimal.NewFromInt(100)) {
		h.respondWithError(w, http.StatusBadRequest, "threshold_percent cannot exceed 100")
		return
	}
	customers, err := h.queryService.GetCustomersNearCreditLimit(ctx, companyID, threshold)
	if err != nil {
		h.logger.Error("failed to get customers near credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetCustomersExceedingCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	customers, err := h.queryService.GetCustomersExceedingCreditLimit(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get customers exceeding credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}
func (h *ReportHandler) GetOrdersOnCreditHold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	orders, err := h.queryService.GetOrdersOnCreditHold(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get orders on credit hold", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orders,
	})
}
func (h *ReportHandler) GetSalesReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	includeDetails, _ := strconv.ParseBool(r.URL.Query().Get("include_details"))
	req := service.SalesReportRequest{
		CompanyID:      companyID,
		From:           from,
		To:             to,
		Granularity:    granularity,
		IncludeDetails: includeDetails,
	}
	report, err := h.queryService.GetSalesReport(ctx, &req)
	if err != nil {
		h.logger.Error("failed to get sales report", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    report,
	})
}
func (h *ReportHandler) GetTaxReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	granularityStr := r.URL.Query().Get("granularity")
	var granularity service.AnalyticsGranularity
	switch granularityStr {
	case "weekly":
		granularity = service.GranularityWeekly
	case "monthly":
		granularity = service.GranularityMonthly
	case "yearly":
		granularity = service.GranularityYearly
	default:
		granularity = service.GranularityDaily
	}
	req := service.TaxReportRequest{
		CompanyID:   companyID,
		From:        from,
		To:          to,
		Granularity: granularity,
	}
	report, err := h.queryService.GetTaxReport(ctx, &req)
	if err != nil {
		h.logger.Error("failed to get tax report", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    report,
	})
}
func (h *ReportHandler) GetReceivablesReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	asOfStr := r.URL.Query().Get("as_of")
	if asOfStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "as_of parameter is required")
		return
	}
	asOf, err := time.Parse(time.RFC3339, asOfStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid as_of format (RFC3339)")
		return
	}
	req := service.ReceivablesReportRequest{
		CompanyID: companyID,
		AsOf:      asOf,
	}
	report, err := h.queryService.GetReceivablesReport(ctx, &req)
	if err != nil {
		h.logger.Error("failed to get receivables report", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    report,
	})
}
func (h *ReportHandler) GetCustomerStatement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := h.parseUUIDParam(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	from := h.parseTimeQuery(r, "from")
	to := h.parseTimeQuery(r, "to")
	statement, err := h.queryService.GetCustomerStatement(ctx, companyID, customerID, from, to)
	if err != nil {
		h.logger.Error("failed to get customer statement", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    statement,
	})
}
func (h *ReportHandler) GetSalesAuditTrail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	entityType := r.URL.Query().Get("entity_type")
	if entityType == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type parameter is required")
		return
	}
	entityIDStr := r.URL.Query().Get("entity_id")
	if entityIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_id parameter is required")
		return
	}
	entityID, err := uuid.Parse(entityIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	audit, err := h.queryService.GetSalesAuditTrail(ctx, companyID, entityType, entityID)
	if err != nil {
		h.logger.Error("failed to get sales audit trail", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    audit,
	})
}
func (h *ReportHandler) GetCustomerOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := h.parseUUIDParam(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "at parameter is required")
		return
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at format (RFC3339)")
		return
	}
	invoices, err := h.queryService.GetCustomerOverdueInvoices(ctx, companyID, customerID, at)
	if err != nil {
		h.logger.Error("failed to get customer overdue invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if invoices == nil {
		invoices = []*models.Invoice{}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoices,
	})
}
