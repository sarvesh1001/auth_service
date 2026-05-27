// file: internal/sales/handler/report_handler.go

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/service"
)

// ReportHandler handles read‑only analytics and report requests.
type ReportHandler struct {
	queryService service.SalesQueryService
	logger       *zap.Logger
}

// NewReportHandler creates a new ReportHandler.
func NewReportHandler(queryService service.SalesQueryService, logger *zap.Logger) *ReportHandler {
	return &ReportHandler{
		queryService: queryService,
		logger:       logger.Named("report_handler"),
	}
}

// ---------- Helper Functions ----------

func (h *ReportHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *ReportHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: integrate with real permission system
	return true
}

func (h *ReportHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, errors.New("missing parameter")
	}
	return uuid.Parse(idStr)
}

func (h *ReportHandler) parseTimeQuery(r *http.Request, paramName string) *time.Time {
	if s := r.URL.Query().Get(paramName); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return &t
		}
	}
	return nil
}

func (h *ReportHandler) parseDecimalQuery(r *http.Request, paramName string) *decimal.Decimal {
	if s := r.URL.Query().Get(paramName); s != "" {
		if d, err := decimal.NewFromString(s); err == nil {
			return &d
		}
	}
	return nil
}

func (h *ReportHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReportHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *ReportHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, salesErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Handler Methods ----------

// GetSalesDashboard godoc
// @Summary Get sales dashboard summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.SalesDashboardSummary
// @Router /reports/sales-dashboard [get]
func (h *ReportHandler) GetSalesDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTodaySalesSummary godoc
// @Summary Get today's sales summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {object} service.TodaySalesSummary
// @Router /reports/today-sales-summary [get]
func (h *ReportHandler) GetTodaySalesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRealtimeSalesSnapshot godoc
// @Summary Get realtime sales snapshot
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {object} service.RealtimeSalesSnapshot
// @Router /reports/realtime-snapshot [get]
func (h *ReportHandler) GetRealtimeSalesSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueSummary godoc
// @Summary Get revenue summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.RevenueSummary
// @Router /reports/revenue-summary [get]
func (h *ReportHandler) GetRevenueSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueTrend godoc
// @Summary Get revenue trend over time
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.RevenueTrendPoint
// @Router /reports/revenue-trend [get]
func (h *ReportHandler) GetRevenueTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

	trend, err := h.queryService.GetRevenueTrend(ctx, companyID, granularity, from, to)
	if err != nil {
		h.logger.Error("failed to get revenue trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}

// GetRevenueByCustomer godoc
// @Summary Get revenue breakdown by customer
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Max number of customers" default(20)
// @Success 200 {array} service.CustomerRevenueSummary
// @Router /reports/revenue-by-customer [get]
func (h *ReportHandler) GetRevenueByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueByProduct godoc
// @Summary Get revenue breakdown by product
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Max number of products" default(20)
// @Success 200 {array} service.ProductRevenueSummary
// @Router /reports/revenue-by-product [get]
func (h *ReportHandler) GetRevenueByProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueByCategory godoc
// @Summary Get revenue breakdown by product category
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.CategoryRevenueSummary
// @Router /reports/revenue-by-category [get]
func (h *ReportHandler) GetRevenueByCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueBySalesRep godoc
// @Summary Get revenue breakdown by sales representative
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.SalesRepRevenueSummary
// @Router /reports/revenue-by-sales-rep [get]
func (h *ReportHandler) GetRevenueBySalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRevenueByPaymentMethod godoc
// @Summary Get revenue breakdown by payment method
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.PaymentMethodRevenueSummary
// @Router /reports/revenue-by-payment-method [get]
func (h *ReportHandler) GetRevenueByPaymentMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetNetRevenueAfterReturns godoc
// @Summary Get net revenue after returns
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} decimal.Decimal
// @Router /reports/net-revenue-after-returns [get]
func (h *ReportHandler) GetNetRevenueAfterReturns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTopCustomers godoc
// @Summary Get top customers by revenue
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param limit query int false "Max number of customers" default(10)
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.TopCustomerRow
// @Router /reports/top-customers [get]
func (h *ReportHandler) GetTopCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCustomerSalesSummary godoc
// @Summary Get detailed sales summary for a specific customer
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param customer_id path string true "Customer ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.CustomerSalesSummary
// @Router /reports/customers/{customer_id}/sales-summary [get]
func (h *ReportHandler) GetCustomerSalesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	customerID, err := h.parseUUIDParam(r, "customer_id")
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

// GetCustomerLifetimeValue godoc
// @Summary Get customer lifetime value (LTV)
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param customer_id path string true "Customer ID"
// @Success 200 {object} decimal.Decimal
// @Router /reports/customers/{customer_id}/lifetime-value [get]
func (h *ReportHandler) GetCustomerLifetimeValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	customerID, err := h.parseUUIDParam(r, "customer_id")
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

// GetCustomersWithOutstandingBalance godoc
// @Summary Get customers with outstanding balance
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {array} service.CustomerOutstandingBalanceRow
// @Router /reports/customers/outstanding-balance [get]
func (h *ReportHandler) GetCustomersWithOutstandingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCustomersWithOverdueInvoices godoc
// @Summary Get customers with overdue invoices
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {array} service.CustomerOverdueSummary
// @Router /reports/customers/overdue-invoices [get]
func (h *ReportHandler) GetCustomersWithOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetInactiveCustomers godoc
// @Summary Get customers inactive since a given date
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param since query string true "Since date (RFC3339)"
// @Success 200 {array} models.Customer
// @Router /reports/customers/inactive [get]
func (h *ReportHandler) GetInactiveCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetNewCustomers godoc
// @Summary Get new customers in a date range
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} models.Customer
// @Router /reports/customers/new [get]
func (h *ReportHandler) GetNewCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}

// GetOrderSummary godoc
// @Summary Get order summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.OrderSummary
// @Router /reports/order-summary [get]
func (h *ReportHandler) GetOrderSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOrdersByStatus godoc
// @Summary Get order counts and totals grouped by status
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.OrderStatusSummary
// @Router /reports/orders-by-status [get]
func (h *ReportHandler) GetOrdersByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTopOrdersByValue godoc
// @Summary Get top orders by value
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param limit query int false "Number of orders" default(10)
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} models.Order
// @Router /reports/top-orders [get]
func (h *ReportHandler) GetTopOrdersByValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetAverageOrderValueTrend godoc
// @Summary Get average order value trend over time
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.AverageOrderValuePoint
// @Router /reports/average-order-value-trend [get]
func (h *ReportHandler) GetAverageOrderValueTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOrderConversionFunnel godoc
// @Summary Get order conversion funnel (quote → order)
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.OrderConversionFunnel
// @Router /reports/order-conversion-funnel [get]
func (h *ReportHandler) GetOrderConversionFunnel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetQuoteSummary godoc
// @Summary Get quote summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.QuoteSummary
// @Router /reports/quote-summary [get]
func (h *ReportHandler) GetQuoteSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetQuoteConversionMetrics godoc
// @Summary Get quote conversion metrics
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.QuoteConversionMetrics
// @Router /reports/quote-conversion-metrics [get]
func (h *ReportHandler) GetQuoteConversionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetQuotesExpiringSoon godoc
// @Summary Get quotes expiring before a given date
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param before query string true "Expiry cutoff date (RFC3339)"
// @Success 200 {array} models.Quote
// @Router /reports/quotes-expiring-soon [get]
func (h *ReportHandler) GetQuotesExpiringSoon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetInvoiceSummary godoc
// @Summary Get invoice summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.InvoiceSummary
// @Router /reports/invoice-summary [get]
func (h *ReportHandler) GetInvoiceSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOutstandingReceivablesSummary godoc
// @Summary Get outstanding receivables summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {object} service.OutstandingReceivablesSummary
// @Router /reports/outstanding-receivables [get]
func (h *ReportHandler) GetOutstandingReceivablesSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOverdueInvoices godoc
// @Summary Get overdue invoices as of a given date
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param at query string true "As of date (RFC3339)"
// @Param limit query int false "Page size" default(20)
// @Param offset query int false "Page offset" default(0)
// @Param sort_field query string false "Sort field (e.g. due_date)"
// @Param sort_dir query string false "Sort direction (ASC/DESC)"
// @Success 200 {object} PaginatedInvoicesResponse
// @Router /reports/overdue-invoices [get]
func (h *ReportHandler) GetOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOverdueInvoiceAging godoc
// @Summary Get overdue invoice aging buckets
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param at query string true "As of date (RFC3339)"
// @Success 200 {array} service.InvoiceAgingBucket
// @Router /reports/overdue-invoice-aging [get]
func (h *ReportHandler) GetOverdueInvoiceAging(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetInvoicesDueSoon godoc
// @Summary Get invoices due before a given date
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param before query string true "Due before date (RFC3339)"
// @Success 200 {array} models.Invoice
// @Router /reports/invoices-due-soon [get]
func (h *ReportHandler) GetInvoicesDueSoon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetInvoiceCollectionTrend godoc
// @Summary Get invoice collection trend over time
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.CollectionTrendPoint
// @Router /reports/invoice-collection-trend [get]
func (h *ReportHandler) GetInvoiceCollectionTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetAverageCollectionDays godoc
// @Summary Get average collection days (DSO)
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} decimal.Decimal
// @Router /reports/average-collection-days [get]
func (h *ReportHandler) GetAverageCollectionDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetPaymentSummary godoc
// @Summary Get payment summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.PaymentSummary
// @Router /reports/payment-summary [get]
func (h *ReportHandler) GetPaymentSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetPaymentMethodBreakdown godoc
// @Summary Get payment method breakdown
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.PaymentMethodBreakdownRow
// @Router /reports/payment-method-breakdown [get]
func (h *ReportHandler) GetPaymentMethodBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetFailedPaymentAnalytics godoc
// @Summary Get failed payment analytics
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.FailedPaymentAnalytics
// @Router /reports/failed-payment-analytics [get]
func (h *ReportHandler) GetFailedPaymentAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRefundSummary godoc
// @Summary Get refund summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.RefundSummary
// @Router /reports/refund-summary [get]
func (h *ReportHandler) GetRefundSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTopSellingProducts godoc
// @Summary Get top selling products by revenue
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param limit query int false "Max number of products" default(10)
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.TopSellingProductRow
// @Router /reports/top-selling-products [get]
func (h *ReportHandler) GetTopSellingProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetLeastSellingProducts godoc
// @Summary Get least selling products by revenue
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param limit query int false "Max number of products" default(10)
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.LeastSellingProductRow
// @Router /reports/least-selling-products [get]
func (h *ReportHandler) GetLeastSellingProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetProductSalesTrend godoc
// @Summary Get sales trend for a specific product
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param product_id path string true "Product ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.ProductSalesTrendPoint
// @Router /reports/products/{product_id}/sales-trend [get]
func (h *ReportHandler) GetProductSalesTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetProductsNeverSold godoc
// @Summary Get products that have never been sold
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {array} models.Product
// @Router /reports/products-never-sold [get]
func (h *ReportHandler) GetProductsNeverSold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetMostReturnedProducts godoc
// @Summary Get most returned products
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param limit query int false "Max number of products" default(10)
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.MostReturnedProductRow
// @Router /reports/most-returned-products [get]
func (h *ReportHandler) GetMostReturnedProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetReturnSummary godoc
// @Summary Get return summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.ReturnSummary
// @Router /reports/return-summary [get]
func (h *ReportHandler) GetReturnSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetReturnRateTrend godoc
// @Summary Get return rate trend over time
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.ReturnRateTrendPoint
// @Router /reports/return-rate-trend [get]
func (h *ReportHandler) GetReturnRateTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetRefundLiabilitySummary godoc
// @Summary Get refund liability summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {object} service.RefundLiabilitySummary
// @Router /reports/refund-liability-summary [get]
func (h *ReportHandler) GetRefundLiabilitySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetDiscountSummary godoc
// @Summary Get discount summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.DiscountSummary
// @Router /reports/discount-summary [get]
func (h *ReportHandler) GetDiscountSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCouponPerformance godoc
// @Summary Get coupon performance metrics
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Max number of coupons" default(20)
// @Success 200 {array} service.CouponPerformanceRow
// @Router /reports/coupon-performance [get]
func (h *ReportHandler) GetCouponPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetPromotionPerformance godoc
// @Summary Get promotion performance metrics
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Max number of promotions" default(20)
// @Success 200 {array} service.PromotionPerformanceRow
// @Router /reports/promotion-performance [get]
func (h *ReportHandler) GetPromotionPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetDiscountImpactOnRevenue godoc
// @Summary Get discount impact on revenue
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.DiscountRevenueImpact
// @Router /reports/discount-impact-on-revenue [get]
func (h *ReportHandler) GetDiscountImpactOnRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxSummary godoc
// @Summary Get tax summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.TaxSummary
// @Router /reports/tax-summary [get]
func (h *ReportHandler) GetTaxSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxBreakdownByRate godoc
// @Summary Get tax breakdown by tax rate
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.TaxRateBreakdownRow
// @Router /reports/tax-breakdown-by-rate [get]
func (h *ReportHandler) GetTaxBreakdownByRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxBreakdownByJurisdiction godoc
// @Summary Get tax breakdown by jurisdiction
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.JurisdictionTaxBreakdownRow
// @Router /reports/tax-breakdown-by-jurisdiction [get]
func (h *ReportHandler) GetTaxBreakdownByJurisdiction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxBreakdownByProduct godoc
// @Summary Get tax breakdown by product
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Max number of products" default(20)
// @Success 200 {array} service.ProductTaxBreakdownRow
// @Router /reports/tax-breakdown-by-product [get]
func (h *ReportHandler) GetTaxBreakdownByProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCollectedTaxTrend godoc
// @Summary Get collected tax trend over time
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param granularity query string true "daily|weekly|monthly|yearly"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.CollectedTaxTrendPoint
// @Router /reports/collected-tax-trend [get]
func (h *ReportHandler) GetCollectedTaxTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxAuditReport godoc
// @Summary Get tax audit report
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {array} service.TaxAuditReportRow
// @Router /reports/tax-audit-report [get]
func (h *ReportHandler) GetTaxAuditReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetSalesRepPerformance godoc
// @Summary Get performance summary for a specific sales representative
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param sales_rep_id path string true "Sales rep ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.SalesRepPerformanceSummary
// @Router /reports/sales-reps/{sales_rep_id}/performance [get]
func (h *ReportHandler) GetSalesRepPerformance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetSalesLeaderboard godoc
// @Summary Get sales leaderboard
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param limit query int false "Number of top reps" default(10)
// @Success 200 {array} service.SalesLeaderboardRow
// @Router /reports/sales-leaderboard [get]
func (h *ReportHandler) GetSalesLeaderboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCommissionSummary godoc
// @Summary Get commission summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.CommissionSummary
// @Router /reports/commission-summary [get]
func (h *ReportHandler) GetCommissionSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCreditRiskSummary godoc
// @Summary Get credit risk summary
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {object} service.CreditRiskSummary
// @Router /reports/credit-risk-summary [get]
func (h *ReportHandler) GetCreditRiskSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCustomersNearCreditLimit godoc
// @Summary Get customers near their credit limit
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param threshold_percent query string true "Threshold percentage (e.g., 80 for 80%)"
// @Success 200 {array} service.CustomerCreditUtilizationRow
// @Router /reports/customers-near-credit-limit [get]
func (h *ReportHandler) GetCustomersNearCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCustomersExceedingCreditLimit godoc
// @Summary Get customers exceeding their credit limit
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {array} service.CustomerCreditExposureRow
// @Router /reports/customers-exceeding-credit-limit [get]
func (h *ReportHandler) GetCustomersExceedingCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetOrdersOnCreditHold godoc
// @Summary Get orders currently on credit hold
// @Tags reports
// @Param company_id query string true "Company ID"
// @Success 200 {array} models.Order
// @Router /reports/orders-on-credit-hold [get]
func (h *ReportHandler) GetOrdersOnCreditHold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetSalesReport godoc
// @Summary Get comprehensive sales report
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param granularity query string false "daily|weekly|monthly|yearly"
// @Param include_details query bool false "Include detailed lines"
// @Success 200 {object} service.SalesReportResult
// @Router /reports/sales-report [get]
func (h *ReportHandler) GetSalesReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetTaxReport godoc
// @Summary Get tax report
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param granularity query string false "daily|weekly|monthly|yearly"
// @Success 200 {object} service.TaxReportResult
// @Router /reports/tax-report [get]
func (h *ReportHandler) GetTaxReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetReceivablesReport godoc
// @Summary Get receivables report
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param as_of query string true "Date as of (RFC3339)"
// @Success 200 {object} service.ReceivablesReportResult
// @Router /reports/receivables-report [get]
func (h *ReportHandler) GetReceivablesReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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

// GetCustomerStatement godoc
// @Summary Get customer statement for a period
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param customer_id path string true "Customer ID"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Success 200 {object} service.CustomerStatementResult
// @Router /reports/customers/{customer_id}/statement [get]
func (h *ReportHandler) GetCustomerStatement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	customerID, err := h.parseUUIDParam(r, "customer_id")
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

// GetSalesAuditTrail godoc
// @Summary Get audit trail for a sales entity
// @Tags reports
// @Param company_id query string true "Company ID"
// @Param entity_type query string true "Type of entity (order, invoice, quote, etc.)"
// @Param entity_id query string true "ID of the entity"
// @Success 200 {array} service.SalesAuditEntry
// @Router /reports/sales-audit-trail [get]
func (h *ReportHandler) GetSalesAuditTrail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseUUIDParam(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
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
