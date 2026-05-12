package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

// AnalyticsHandler handles HTTP requests for inventory analytics.
type AnalyticsHandler struct {
	analyticsService service.AnalyticsQueryService
	logger           *zap.Logger
}

// NewAnalyticsHandler creates a new AnalyticsHandler.
func NewAnalyticsHandler(analyticsService service.AnalyticsQueryService, logger *zap.Logger) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: analyticsService,
		logger:           logger.Named("analytics_handler"),
	}
}

// GetDailySnapshots GET /api/v1/companies/{companyId}/analytics/snapshots
func (h *AnalyticsHandler) GetDailySnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	filter, err := parseSnapshotFilter(r.URL.Query(), companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pagination, sort := parsePaginationAndSort(r.URL.Query(), "snapshot_date", "desc")

	snapshots, err := h.analyticsService.GetSnapshotRange(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get daily snapshots", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve snapshots")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      snapshots,
			"total":      len(snapshots),
			"limit":      pagination.Limit,
			"offset":     pagination.Offset,
			"sort_field": sort.Field,
			"sort_order": sort.Direction,
		},
	})
}

// GetTurnoverMetrics GET /api/v1/companies/{companyId}/analytics/turnover
func (h *AnalyticsHandler) GetTurnoverMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	filter, err := parseTurnoverFilter(r.URL.Query(), companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pagination, sort := parsePaginationAndSort(r.URL.Query(), "year_month", "desc")

	metrics, err := h.analyticsService.GetTurnoverMetrics(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get turnover metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve turnover metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      metrics,
			"total":      len(metrics),
			"limit":      pagination.Limit,
			"offset":     pagination.Offset,
			"sort_field": sort.Field,
			"sort_order": sort.Direction,
		},
	})
}

// GetABCClassifications GET /api/v1/companies/{companyId}/analytics/abc
func (h *AnalyticsHandler) GetABCClassifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	filter, err := parseABCFilter(r.URL.Query(), companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pagination, sort := parsePaginationAndSort(r.URL.Query(), "classification_date", "desc")

	classifications, err := h.analyticsService.GetABCClassification(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get ABC classifications", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve ABC classifications")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      classifications,
			"total":      len(classifications),
			"limit":      pagination.Limit,
			"offset":     pagination.Offset,
			"sort_field": sort.Field,
			"sort_order": sort.Direction,
		},
	})
}

// GetInventoryAging GET /api/v1/companies/{companyId}/analytics/aging
func (h *AnalyticsHandler) GetInventoryAging(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	filter, err := parseAgingFilter(r.URL.Query(), companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pagination, sort := parsePaginationAndSort(r.URL.Query(), "snapshot_date", "desc")

	aging, err := h.analyticsService.GetInventoryAging(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get inventory aging", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve inventory aging")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      aging,
			"total":      len(aging),
			"limit":      pagination.Limit,
			"offset":     pagination.Offset,
			"sort_field": sort.Field,
			"sort_order": sort.Direction,
		},
	})
}

// GetDemandHistory GET /api/v1/companies/{companyId}/analytics/demand
func (h *AnalyticsHandler) GetDemandHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	filter, err := parseDemandFilter(r.URL.Query(), companyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pagination, sort := parsePaginationAndSort(r.URL.Query(), "demand_date", "desc")

	demand, err := h.analyticsService.GetDemandHistory(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get demand history", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve demand history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      demand,
			"total":      len(demand),
			"limit":      pagination.Limit,
			"offset":     pagination.Offset,
			"sort_field": sort.Field,
			"sort_order": sort.Direction,
		},
	})
}

// GetMovementDailySummary GET /api/v1/companies/{companyId}/analytics/movement-summary
func (h *AnalyticsHandler) GetMovementDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "analytics:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	fromDate, toDate, warehouseID, itemID, err := parseMovementSummaryParams(r.URL.Query())
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaries, err := h.analyticsService.GetMovementSummary(ctx, companyID, fromDate, toDate, warehouseID, itemID)
	if err != nil {
		h.logger.Error("failed to get movement summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve movement summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ---------- Helper functions ----------

func parseCompanyIDFromRequest(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		companyIDStr = chi.URLParam(r, "companyId")
	}
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *AnalyticsHandler) checkPermission(ctx context.Context, companyID uuid.UUID, permission string) error {
	// Stub: implement real permission check using your auth system.
	return nil
}

func parseSnapshotFilter(query map[string][]string, companyID uuid.UUID) (repository.SnapshotFilter, error) {
	filter := repository.SnapshotFilter{CompanyID: companyID}
	if fromDateStr := getQueryParam(query, "from_date"); fromDateStr != "" {
		t, err := time.Parse("2006-01-02", fromDateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid from_date: %w", err)
		}
		filter.DateFrom = &t
	}
	if toDateStr := getQueryParam(query, "to_date"); toDateStr != "" {
		t, err := time.Parse("2006-01-02", toDateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid to_date: %w", err)
		}
		filter.DateTo = &t
	}
	if warehouseIDStr := getQueryParam(query, "warehouse_id"); warehouseIDStr != "" {
		id, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid warehouse_id: %w", err)
		}
		filter.WarehouseID = &id
	}
	if itemIDStr := getQueryParam(query, "item_id"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid item_id: %w", err)
		}
		filter.ItemID = &id
	}
	return filter, nil
}

func parseTurnoverFilter(query map[string][]string, companyID uuid.UUID) (repository.TurnoverFilter, error) {
	filter := repository.TurnoverFilter{CompanyID: companyID}
	if fromMonthStr := getQueryParam(query, "from_month"); fromMonthStr != "" {
		t, err := time.Parse("2006-01-02", fromMonthStr)
		if err != nil {
			return filter, fmt.Errorf("invalid from_month: %w", err)
		}
		filter.YearMonthFrom = &t
	}
	if toMonthStr := getQueryParam(query, "to_month"); toMonthStr != "" {
		t, err := time.Parse("2006-01-02", toMonthStr)
		if err != nil {
			return filter, fmt.Errorf("invalid to_month: %w", err)
		}
		filter.YearMonthTo = &t
	}
	if warehouseIDStr := getQueryParam(query, "warehouse_id"); warehouseIDStr != "" {
		id, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid warehouse_id: %w", err)
		}
		filter.WarehouseID = &id
	}
	if itemIDStr := getQueryParam(query, "item_id"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid item_id: %w", err)
		}
		filter.ItemID = &id
	}
	return filter, nil
}

func parseABCFilter(query map[string][]string, companyID uuid.UUID) (repository.ABCFilter, error) {
	filter := repository.ABCFilter{CompanyID: companyID}
	if dateStr := getQueryParam(query, "classification_date"); dateStr != "" {
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid classification_date: %w", err)
		}
		filter.Date = &t
	}
	if abcClass := getQueryParam(query, "abc_class"); abcClass != "" {
		filter.Class = abcClass
	}
	if itemIDStr := getQueryParam(query, "item_id"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid item_id: %w", err)
		}
		filter.ItemID = &id
	}
	return filter, nil
}

func parseAgingFilter(query map[string][]string, companyID uuid.UUID) (repository.AgingFilter, error) {
	filter := repository.AgingFilter{CompanyID: companyID}
	if snapshotDateStr := getQueryParam(query, "snapshot_date"); snapshotDateStr != "" {
		t, err := time.Parse("2006-01-02", snapshotDateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid snapshot_date: %w", err)
		}
		filter.SnapshotDate = &t
	}
	if warehouseIDStr := getQueryParam(query, "warehouse_id"); warehouseIDStr != "" {
		id, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid warehouse_id: %w", err)
		}
		filter.WarehouseID = &id
	}
	if itemIDStr := getQueryParam(query, "item_id"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid item_id: %w", err)
		}
		filter.ItemID = &id
	}
	if agingBucket := getQueryParam(query, "aging_bucket"); agingBucket != "" {
		filter.AgingBucket = agingBucket
	}
	return filter, nil
}

func parseDemandFilter(query map[string][]string, companyID uuid.UUID) (repository.DemandFilter, error) {
	filter := repository.DemandFilter{CompanyID: companyID}
	if fromDateStr := getQueryParam(query, "from_date"); fromDateStr != "" {
		t, err := time.Parse("2006-01-02", fromDateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid from_date: %w", err)
		}
		filter.DateFrom = &t
	}
	if toDateStr := getQueryParam(query, "to_date"); toDateStr != "" {
		t, err := time.Parse("2006-01-02", toDateStr)
		if err != nil {
			return filter, fmt.Errorf("invalid to_date: %w", err)
		}
		filter.DateTo = &t
	}
	if warehouseIDStr := getQueryParam(query, "warehouse_id"); warehouseIDStr != "" {
		id, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid warehouse_id: %w", err)
		}
		filter.WarehouseID = &id
	}
	if itemIDStr := getQueryParam(query, "item_id"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err != nil {
			return filter, fmt.Errorf("invalid item_id: %w", err)
		}
		filter.ItemID = &id
	}
	return filter, nil
}

func parseMovementSummaryParams(query map[string][]string) (from, to time.Time, warehouseID, itemID *uuid.UUID, err error) {
	fromStr := getQueryParam(query, "from_date")
	toStr := getQueryParam(query, "to_date")
	if fromStr == "" || toStr == "" {
		return from, to, nil, nil, fmt.Errorf("from_date and to_date are required")
	}
	from, err = time.Parse("2006-01-02", fromStr)
	if err != nil {
		return from, to, nil, nil, fmt.Errorf("invalid from_date: %w", err)
	}
	to, err = time.Parse("2006-01-02", toStr)
	if err != nil {
		return from, to, nil, nil, fmt.Errorf("invalid to_date: %w", err)
	}
	if whStr := getQueryParam(query, "warehouse_id"); whStr != "" {
		id, err := uuid.Parse(whStr)
		if err != nil {
			return from, to, nil, nil, fmt.Errorf("invalid warehouse_id: %w", err)
		}
		warehouseID = &id
	}
	if itemStr := getQueryParam(query, "item_id"); itemStr != "" {
		id, err := uuid.Parse(itemStr)
		if err != nil {
			return from, to, nil, nil, fmt.Errorf("invalid item_id: %w", err)
		}
		itemID = &id
	}
	return from, to, warehouseID, itemID, nil
}

func parsePaginationAndSort(query map[string][]string, defaultSortField, defaultSortOrder string) (repository.Pagination, repository.Sort) {
	limit := 20
	if limitStr := getQueryParam(query, "limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := getQueryParam(query, "offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	sortField := getQueryParam(query, "sort_field")
	if sortField == "" {
		sortField = defaultSortField
	}
	sortOrder := getQueryParam(query, "sort_order")
	if sortOrder == "" {
		sortOrder = defaultSortOrder
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}
	return repository.Pagination{Limit: limit, Offset: offset}, repository.Sort{Field: sortField, Direction: sortOrder}
}

func getQueryParam(query map[string][]string, key string) string {
	if vals, ok := query[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (h *AnalyticsHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *AnalyticsHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
