package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

// AnalyticsHandler provides HTTP endpoints for accounting analytics data.
type AnalyticsHandler struct {
	accountingSvc     service.AccountingAnalyticsService
	taxSvc            service.TaxAnalyticsService
	complianceSvc     service.ComplianceAnalyticsService
	reconciliationSvc service.ReconciliationAnalyticsService
	logger            *zap.Logger
}

// NewAnalyticsHandler creates a new handler instance.
func NewAnalyticsHandler(
	accountingSvc service.AccountingAnalyticsService,
	taxSvc service.TaxAnalyticsService,
	complianceSvc service.ComplianceAnalyticsService,
	reconciliationSvc service.ReconciliationAnalyticsService,
	logger *zap.Logger,
) *AnalyticsHandler {
	return &AnalyticsHandler{
		accountingSvc:     accountingSvc,
		taxSvc:            taxSvc,
		complianceSvc:     complianceSvc,
		reconciliationSvc: reconciliationSvc,
		logger:            logger.Named("analytics_handler"),
	}
}

// ----------------------------------------------------------------------------
// Daily Account Summaries
// ----------------------------------------------------------------------------

// ListDailySummaries returns daily aggregated debit/credit totals per account.
// Query parameters:
//   - account_id (optional) – filter by a specific account
//   - from, to (optional, YYYY-MM-DD) – date range
//   - limit, offset – pagination
//   - sort_field, sort_order – sorting
func (h *AnalyticsHandler) ListDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.DailySummaryFilter{}
	if accountIDStr := query.Get("account_id"); accountIDStr != "" {
		aid, err := uuid.Parse(accountIDStr)
		if err == nil {
			filter.AccountID = &aid
		}
	}
	if fromStr := query.Get("from"); fromStr != "" {
		from, err := time.Parse("2006-01-02", fromStr)
		if err == nil {
			filter.FromDate = &from
		}
	}
	if toStr := query.Get("to"); toStr != "" {
		to, err := time.Parse("2006-01-02", toStr)
		if err == nil {
			filter.ToDate = &to
		}
	}

	pagination := parsePaginationFromQuery(query)
	sort := parseSortFromQuery(query)

	summaries, err := h.accountingSvc.ListDailySummaries(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list daily summaries", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  summaries,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

// GetDailySummary returns a single daily summary by ID.
func (h *AnalyticsHandler) GetDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaryID, err := uuid.Parse(chi.URLParam(r, "summaryID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid summary ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summary, err := h.accountingSvc.GetDailySummary(ctx, companyID, summaryID)
	if err != nil {
		h.logger.Error("failed to get daily summary", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "summary not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ----------------------------------------------------------------------------
// Account Snapshots (balances over time)
// ----------------------------------------------------------------------------

// ListSnapshots returns account balance snapshots, optionally filtered by account, date, fiscal year, period.
func (h *AnalyticsHandler) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.SnapshotFilter{}
	if accountIDStr := query.Get("account_id"); accountIDStr != "" {
		aid, _ := uuid.Parse(accountIDStr)
		filter.AccountID = &aid
	}
	if snapshotDateStr := query.Get("snapshot_date"); snapshotDateStr != "" {
		sd, _ := time.Parse("2006-01-02", snapshotDateStr)
		filter.SnapshotDate = &sd
	}
	if fromStr := query.Get("from"); fromStr != "" {
		from, _ := time.Parse("2006-01-02", fromStr)
		filter.FromDate = &from
	}
	if toStr := query.Get("to"); toStr != "" {
		to, _ := time.Parse("2006-01-02", toStr)
		filter.ToDate = &to
	}
	if fiscalYearStr := query.Get("fiscal_year"); fiscalYearStr != "" {
		fy, _ := strconv.Atoi(fiscalYearStr)
		filter.FiscalYear = &fy
	}
	if periodStr := query.Get("period"); periodStr != "" {
		p, _ := strconv.Atoi(periodStr)
		filter.Period = &p
	}

	pagination := parsePaginationFromQuery(query)
	sort := parseSortFromQuery(query)

	snapshots, err := h.accountingSvc.ListSnapshots(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list snapshots", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve snapshots")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    snapshots,
	})
}

// GetSnapshot returns a single snapshot by ID.
func (h *AnalyticsHandler) GetSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	snapshotID, err := uuid.Parse(chi.URLParam(r, "snapshotID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid snapshot ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	snapshot, err := h.accountingSvc.GetSnapshot(ctx, companyID, snapshotID)
	if err != nil {
		h.logger.Error("failed to get snapshot", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "snapshot not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    snapshot,
	})
}

// ----------------------------------------------------------------------------
// Journal Metrics
// ----------------------------------------------------------------------------

// ListJournalMetrics returns aggregated journal metrics (volume, total amount) per journal type and date.
func (h *AnalyticsHandler) ListJournalMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.JournalMetricFilter{}
	if journalType := query.Get("journal_type"); journalType != "" {
		filter.JournalType = &journalType
	}
	if fromStr := query.Get("from"); fromStr != "" {
		from, _ := time.Parse("2006-01-02", fromStr)
		filter.FromDate = &from
	}
	if toStr := query.Get("to"); toStr != "" {
		to, _ := time.Parse("2006-01-02", toStr)
		filter.ToDate = &to
	}

	pagination := parsePaginationFromQuery(query)
	sort := parseSortFromQuery(query)

	metrics, err := h.accountingSvc.ListJournalMetrics(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list journal metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetJournalMetric returns a single journal metric by ID.
func (h *AnalyticsHandler) GetJournalMetric(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metricID, err := uuid.Parse(chi.URLParam(r, "metricID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid metric ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metric, err := h.accountingSvc.GetJournalMetric(ctx, companyID, metricID)
	if err != nil {
		h.logger.Error("failed to get journal metric", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "metric not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metric,
	})
}

// ----------------------------------------------------------------------------
// Cashflow
// ----------------------------------------------------------------------------

// ListCashflows returns cashflow records per day (inflow, outflow, net).
func (h *AnalyticsHandler) ListCashflows(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.CashflowFilter{}
	if fromStr := query.Get("from"); fromStr != "" {
		from, _ := time.Parse("2006-01-02", fromStr)
		filter.FromDate = &from
	}
	if toStr := query.Get("to"); toStr != "" {
		to, _ := time.Parse("2006-01-02", toStr)
		filter.ToDate = &to
	}

	pagination := parsePaginationFromQuery(query)
	sort := parseSortFromQuery(query)

	cashflows, err := h.accountingSvc.ListCashflows(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list cashflows", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve cashflows")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    cashflows,
	})
}

// GetCashflow returns a single cashflow record by ID.
func (h *AnalyticsHandler) GetCashflow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	cashflowID, err := uuid.Parse(chi.URLParam(r, "cashflowID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cashflow ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	cashflow, err := h.accountingSvc.GetCashflow(ctx, companyID, cashflowID)
	if err != nil {
		h.logger.Error("failed to get cashflow", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "cashflow not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    cashflow,
	})
}

// ----------------------------------------------------------------------------
// Tax Summaries (via TaxAnalyticsService)
// ----------------------------------------------------------------------------

// ListTaxSummaries returns aggregated tax liabilities per period / tax rate.
func (h *AnalyticsHandler) ListTaxSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.TaxSummaryFilter{}
	if taxRateIDStr := query.Get("tax_rate_id"); taxRateIDStr != "" {
		rid, _ := uuid.Parse(taxRateIDStr)
		filter.TaxRateID = &rid
	}
	if fromStr := query.Get("from"); fromStr != "" {
		from, _ := time.Parse("2006-01-02", fromStr)
		filter.FromDate = &from
	}
	if toStr := query.Get("to"); toStr != "" {
		to, _ := time.Parse("2006-01-02", toStr)
		filter.ToDate = &to
	}

	pagination := parsePaginationFromQuery(query)
	sort := parseSortFromQuery(query)

	summaries, err := h.taxSvc.ListTaxSummaries(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list tax summaries", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetTaxSummary returns a single tax summary by ID.
func (h *AnalyticsHandler) GetTaxSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaryID, err := uuid.Parse(chi.URLParam(r, "summaryID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax summary ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summary, err := h.taxSvc.GetTaxSummary(ctx, companyID, summaryID)
	if err != nil {
		h.logger.Error("failed to get tax summary", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "tax summary not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ----------------------------------------------------------------------------
// Reconciliation Daily Stats
// ----------------------------------------------------------------------------

// ListReconciliationDailyStats returns daily reconciliation performance metrics.
func (h *AnalyticsHandler) ListReconciliationDailyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	fromStr := query.Get("from")
	toStr := query.Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format (use YYYY-MM-DD)")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format (use YYYY-MM-DD)")
		return
	}

	stats, err := h.reconciliationSvc.ListReconciliationDailyStats(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to list reconciliation daily stats", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve reconciliation stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// GetReconciliationDailyStats returns a single day's stats for a specific reconciliation type.
func (h *AnalyticsHandler) GetReconciliationDailyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	reconciliationType := chi.URLParam(r, "reconciliationType")
	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stats, err := h.reconciliationSvc.GetReconciliationDailyStats(ctx, companyID, reconciliationType, date)
	if err != nil {
		h.logger.Error("failed to get reconciliation daily stats", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, "stats not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// ----------------------------------------------------------------------------
// Reconciliation Difference Trends
// ----------------------------------------------------------------------------

// ListReconciliationDiffTrends returns aggregated unresolved differences by issue type over time.
func (h *AnalyticsHandler) ListReconciliationDiffTrends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromURL(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "analytics:reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	fromStr := query.Get("from")
	toStr := query.Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format")
		return
	}

	trends, err := h.reconciliationSvc.ListReconciliationDiffTrends(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to list reconciliation diff trends", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve diff trends")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trends,
	})
}

// ----------------------------------------------------------------------------
// Helper functions (reused from other handlers)
// ----------------------------------------------------------------------------

// parseCompanyIDFromURL extracts companyID from URL path parameter.
func parseCompanyIDFromURL(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	return uuid.Parse(companyIDStr)
}

// parsePaginationFromQuery reads limit/offset from query string.
func parsePaginationFromQuery(query map[string][]string) repository.Pagination {
	limit := 20
	if l, err := strconv.Atoi(getQueryParam(query, "limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(getQueryParam(query, "offset")); err == nil && o >= 0 {
		offset = o
	}
	return repository.Pagination{Limit: limit, Offset: offset}
}

// parseSortFromQuery reads sort_field and sort_order from query string.
func parseSortFromQuery(query map[string][]string) repository.Sort {
	field := getQueryParam(query, "sort_field")
	if field == "" {
		field = "date"
	}
	direction := getQueryParam(query, "sort_order")
	if direction == "" {
		direction = "desc"
	}
	return repository.Sort{Field: field, Direction: direction}
}

// getQueryParam is a helper to get first value of a query parameter.

// hasPermission is a placeholder – implement your real permission check.
func (h *AnalyticsHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: integrate with your auth middleware or RBAC service.
	return true
}

// respondWithJSON writes a JSON response.
func (h *AnalyticsHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError writes an error response.
func (h *AnalyticsHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
