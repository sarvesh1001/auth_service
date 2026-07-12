// handler/analytics_handler.go

package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// AnalyticsHandler handles HTTP requests for analytics data.
type AnalyticsHandler struct {
	analyticsService service.AnalyticsQueryService
	*BaseHandler
}

// NewAnalyticsHandler creates a new instance.
func NewAnalyticsHandler(analyticsService service.AnalyticsQueryService, logger *zap.Logger) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: analyticsService,
		BaseHandler:      &BaseHandler{logger: logger.Named("analytics_handler")},
	}
}

// GetDashboard returns a comprehensive dashboard summary.
func (h *AnalyticsHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	dashboard, err := h.analyticsService.GetDashboard(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get dashboard", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    dashboard,
	})
}

// GetSubscriptionMetrics returns counts by subscription status.
func (h *AnalyticsHandler) GetSubscriptionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetSubscriptionMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get subscription metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetRevenueMetrics returns revenue aggregates.
func (h *AnalyticsHandler) GetRevenueMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetRevenueMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get revenue metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetMRR returns the Monthly Recurring Revenue as a string.
func (h *AnalyticsHandler) GetMRR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	mrr, err := h.analyticsService.GetMRR(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get MRR", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"mrr": mrr},
	})
}

// GetARR returns the Annual Recurring Revenue as a string.
func (h *AnalyticsHandler) GetARR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	arr, err := h.analyticsService.GetARR(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get ARR", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"arr": arr},
	})
}

// GetChurnMetrics returns churn statistics for a date range.
func (h *AnalyticsHandler) GetChurnMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetChurnMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get churn metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetTrialMetrics returns trial conversion and expiration data.
func (h *AnalyticsHandler) GetTrialMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetTrialMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get trial metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetTopPlans returns the most popular plans.
func (h *AnalyticsHandler) GetTopPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, err := h.parseIntParam(r, "limit", 5, 100)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	plans, err := h.analyticsService.GetTopPlans(ctx, filter, limit)
	if err != nil {
		h.logger.Error("failed to get top plans", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    plans,
	})
}

// GetTopAddons returns the most used add-ons.
func (h *AnalyticsHandler) GetTopAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, err := h.parseIntParam(r, "limit", 5, 100)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addons, err := h.analyticsService.GetTopAddons(ctx, filter, limit)
	if err != nil {
		h.logger.Error("failed to get top addons", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    addons,
	})
}

// GetTopCustomers returns customers with the highest spend.
func (h *AnalyticsHandler) GetTopCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, err := h.parseIntParam(r, "limit", 5, 100)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	customers, err := h.analyticsService.GetTopCustomers(ctx, filter, limit)
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

// GetUsageMetrics returns usage aggregations.
func (h *AnalyticsHandler) GetUsageMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetUsageMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get usage metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetTopFeatures returns features with the highest usage.
func (h *AnalyticsHandler) GetTopFeatures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, err := h.parseIntParam(r, "limit", 5, 100)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	features, err := h.analyticsService.GetTopFeatures(ctx, filter, limit)
	if err != nil {
		h.logger.Error("failed to get top features", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    features,
	})
}

// GetRenewalMetrics returns renewal counts.
func (h *AnalyticsHandler) GetRenewalMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetRenewalMetrics(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get renewal metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetUpcomingRenewals returns subscriptions that will renew within the next N days.
func (h *AnalyticsHandler) GetUpcomingRenewals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	days, err := h.parseIntParam(r, "days", 7, 365)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	renewals, err := h.analyticsService.GetUpcomingRenewals(ctx, filter, days)
	if err != nil {
		h.logger.Error("failed to get upcoming renewals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    renewals,
	})
}

// GetPlanChangeMetrics returns aggregate plan change statistics for a given plan.
func (h *AnalyticsHandler) GetPlanChangeMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	planID := r.URL.Query().Get("plan_id")
	if planID == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_id is required")
		return
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	metrics, err := h.analyticsService.GetPlanChangeMetrics(ctx, filter, planID)
	if err != nil {
		h.logger.Error("failed to get plan change metrics", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// GetPlanChangeTrend returns plan change trends over time.
func (h *AnalyticsHandler) GetPlanChangeTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	planID := r.URL.Query().Get("plan_id")
	if planID == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_id is required")
		return
	}

	groupByStr := r.URL.Query().Get("group_by")
	groupBy := repository.AnalyticsGroupByDay // default
	switch groupByStr {
	case "day":
		groupBy = repository.AnalyticsGroupByDay
	case "week":
		groupBy = repository.AnalyticsGroupByWeek
	case "month":
		groupBy = repository.AnalyticsGroupByMonth
	case "year":
		groupBy = repository.AnalyticsGroupByYear
	default:
		// keep default
	}

	filter, err := h.buildFilter(r, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	trend, err := h.analyticsService.GetPlanChangeTrend(ctx, filter, planID, groupBy)
	if err != nil {
		h.logger.Error("failed to get plan change trend", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

// buildFilter constructs an AnalyticsFilter from query parameters.
func (h *AnalyticsHandler) buildFilter(r *http.Request, companyID uuid.UUID) (repository.AnalyticsFilter, error) {
	filter := repository.AnalyticsFilter{
		CompanyID: companyID,
		// IncludeDeleted: false by default; can be overridden via query param.
	}

	// Parse start_date and end_date (format: 2006-01-02)
	if startStr := r.URL.Query().Get("start_date"); startStr != "" {
		start, err := time.Parse("2006-01-02", startStr)
		if err != nil {
			return filter, err
		}
		filter.StartDate = &start
	}
	if endStr := r.URL.Query().Get("end_date"); endStr != "" {
		end, err := time.Parse("2006-01-02", endStr)
		if err != nil {
			return filter, err
		}
		// Optionally set to end of day for inclusive queries.
		// The repository uses <= for end date, so we can just pass the date.
		// To be safe, we add 23h59m59s to include the entire day.
		end = end.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		filter.EndDate = &end
	}

	// Optional plan_id, customer_id, subscription_id
	if planIDStr := r.URL.Query().Get("plan_id"); planIDStr != "" {
		if planID, err := uuid.Parse(planIDStr); err == nil {
			filter.PlanID = &planID
		}
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		if custID, err := uuid.Parse(customerIDStr); err == nil {
			filter.CustomerID = &custID
		}
	}
	if subIDStr := r.URL.Query().Get("subscription_id"); subIDStr != "" {
		if subID, err := uuid.Parse(subIDStr); err == nil {
			filter.SubscriptionID = &subID
		}
	}

	// Include deleted? (default false)
	if includeDeleted := r.URL.Query().Get("include_deleted"); includeDeleted != "" {
		if val, err := strconv.ParseBool(includeDeleted); err == nil {
			filter.IncludeDeleted = val
		}
	}

	return filter, nil
}

// parseIntParam parses an integer query parameter with default and max.
func (h *AnalyticsHandler) parseIntParam(r *http.Request, key string, defaultVal, maxVal int) (int, error) {
	valStr := r.URL.Query().Get(key)
	if valStr == "" {
		return defaultVal, nil
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return 0, err
	}
	if val < 1 {
		val = defaultVal
	}
	if val > maxVal {
		val = maxVal
	}
	return val, nil
}
