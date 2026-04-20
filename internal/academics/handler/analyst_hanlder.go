package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AnalyticsHandler handles HTTP requests for analytics metrics.
type AnalyticsHandler struct {
	analyticsService service.AnalyticsService
	logger           *zap.Logger
}

// NewAnalyticsHandler creates a new AnalyticsHandler.
func NewAnalyticsHandler(analyticsService service.AnalyticsService, logger *zap.Logger) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: analyticsService,
		logger:           logger.Named("analytics_handler"),
	}
}

// ---------------------------------------------------------------------
// Academic Year Metrics
// ---------------------------------------------------------------------

// GetAcademicYearMetrics returns metrics for a specific academic year.
// GET /api/v1/companies/{companyID}/analytics/academic-years/{academicYearID}/metrics
func (h *AnalyticsHandler) GetAcademicYearMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetAcademicYearMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get academic year metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListAcademicYearMetrics returns paginated academic year metrics.
// GET /api/v1/companies/{companyID}/analytics/academic-years/metrics
func (h *AnalyticsHandler) ListAcademicYearMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListAcademicYearMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list academic year metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshAcademicYearMetrics triggers a full refresh of metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/academic-years/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshAcademicYearMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshAcademicYearMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh academic year metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "metrics refreshed successfully",
	})
}

// RefreshAllAcademicYearMetrics triggers a full refresh for all academic years.
// POST /api/v1/companies/{companyID}/analytics/academic-years/refresh-all
func (h *AnalyticsHandler) RefreshAllAcademicYearMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshAllAcademicYearMetrics(ctx); err != nil {
		h.logger.Error("failed to refresh all academic year metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "all metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Exam Metrics
// ---------------------------------------------------------------------

// GetExamMetrics returns exam metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/exams/{academicYearID}/metrics
func (h *AnalyticsHandler) GetExamMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetExamMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get exam metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListExamMetrics returns paginated exam metrics.
// GET /api/v1/companies/{companyID}/analytics/exams/metrics
func (h *AnalyticsHandler) ListExamMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListExamMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list exam metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ---------------------------------------------------------------------
// Fee Metrics
// ---------------------------------------------------------------------

// GetFeeMetrics returns fee metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/fees/{academicYearID}/metrics
func (h *AnalyticsHandler) GetFeeMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetFeeMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get fee metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListFeeMetrics returns paginated fee metrics.
// GET /api/v1/companies/{companyID}/analytics/fees/metrics
func (h *AnalyticsHandler) ListFeeMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListFeeMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list fee metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ---------------------------------------------------------------------
// Grading Metrics
// ---------------------------------------------------------------------

// GetGradingMetrics returns grading metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/grading/{academicYearID}/metrics
func (h *AnalyticsHandler) GetGradingMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetGradingMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get grading metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListGradingMetrics returns paginated grading metrics.
// GET /api/v1/companies/{companyID}/analytics/grading/metrics
func (h *AnalyticsHandler) ListGradingMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListGradingMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list grading metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ---------------------------------------------------------------------
// Guardian Metrics
// ---------------------------------------------------------------------

// GetGuardianMetrics returns guardian metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/guardians/{academicYearID}/metrics
func (h *AnalyticsHandler) GetGuardianMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetGuardianMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get guardian metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListGuardianMetrics returns paginated guardian metrics.
// GET /api/v1/companies/{companyID}/analytics/guardians/metrics
func (h *AnalyticsHandler) ListGuardianMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListGuardianMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list guardian metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ---------------------------------------------------------------------
// Library Metrics
// ---------------------------------------------------------------------

// GetLibraryMetrics returns library metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/library/{academicYearID}/metrics
func (h *AnalyticsHandler) GetLibraryMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetLibraryMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get library metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListLibraryMetrics returns paginated library metrics.
// GET /api/v1/companies/{companyID}/analytics/library/metrics
func (h *AnalyticsHandler) ListLibraryMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListLibraryMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list library metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ---------------------------------------------------------------------
// Room Metrics
// ---------------------------------------------------------------------

// GetRoomMetrics returns room metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/rooms/{academicYearID}/metrics
func (h *AnalyticsHandler) GetRoomMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetRoomMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get room metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListRoomMetrics returns paginated room metrics.
// GET /api/v1/companies/{companyID}/analytics/rooms/metrics
func (h *AnalyticsHandler) ListRoomMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListRoomMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list room metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshRoomMetrics triggers a full refresh of room metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/rooms/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshRoomMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshRoomMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh room metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "room metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Section Metrics
// ---------------------------------------------------------------------

// GetSectionMetrics returns section metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/sections/{academicYearID}/metrics
func (h *AnalyticsHandler) GetSectionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetSectionMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get section metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListSectionMetrics returns paginated section metrics.
// GET /api/v1/companies/{companyID}/analytics/sections/metrics
func (h *AnalyticsHandler) ListSectionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListSectionMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list section metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshSectionMetrics triggers a full refresh of section metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/sections/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshSectionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshSectionMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh section metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "section metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Student Metrics
// ---------------------------------------------------------------------

// GetStudentMetrics returns student metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/students/{academicYearID}/metrics
func (h *AnalyticsHandler) GetStudentMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetStudentMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get student metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListStudentMetrics returns paginated student metrics.
// GET /api/v1/companies/{companyID}/analytics/students/metrics
func (h *AnalyticsHandler) ListStudentMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListStudentMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list student metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshStudentMetrics triggers a full refresh of student metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/students/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshStudentMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshStudentMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh student metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "student metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Subject Metrics
// ---------------------------------------------------------------------

// GetSubjectMetrics returns subject metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/subjects/{academicYearID}/metrics
func (h *AnalyticsHandler) GetSubjectMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetSubjectMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get subject metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListSubjectMetrics returns paginated subject metrics.
// GET /api/v1/companies/{companyID}/analytics/subjects/metrics
func (h *AnalyticsHandler) ListSubjectMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListSubjectMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list subject metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshSubjectMetrics triggers a full refresh of subject metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/subjects/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshSubjectMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshSubjectMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh subject metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "subject metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Submission Metrics
// ---------------------------------------------------------------------

// GetSubmissionMetrics returns submission metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/submissions/{academicYearID}/metrics
func (h *AnalyticsHandler) GetSubmissionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetSubmissionMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get submission metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListSubmissionMetrics returns paginated submission metrics.
// GET /api/v1/companies/{companyID}/analytics/submissions/metrics
func (h *AnalyticsHandler) ListSubmissionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListSubmissionMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list submission metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshSubmissionMetrics triggers a full refresh of submission metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/submissions/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshSubmissionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshSubmissionMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh submission metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "submission metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Teacher Metrics
// ---------------------------------------------------------------------

// GetTeacherMetrics returns teacher metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/teachers/{academicYearID}/metrics
func (h *AnalyticsHandler) GetTeacherMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetTeacherMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get teacher metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListTeacherMetrics returns paginated teacher metrics.
// GET /api/v1/companies/{companyID}/analytics/teachers/metrics
func (h *AnalyticsHandler) ListTeacherMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListTeacherMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list teacher metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshTeacherMetrics triggers a full refresh of teacher metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/teachers/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshTeacherMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshTeacherMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh teacher metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "teacher metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Timetable Metrics
// ---------------------------------------------------------------------

// GetTimetableMetrics returns timetable metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/timetables/{academicYearID}/metrics
func (h *AnalyticsHandler) GetTimetableMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetTimetableMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get timetable metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListTimetableMetrics returns paginated timetable metrics.
// GET /api/v1/companies/{companyID}/analytics/timetables/metrics
func (h *AnalyticsHandler) ListTimetableMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListTimetableMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list timetable metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshTimetableMetrics triggers a full refresh of timetable metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/timetables/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshTimetableMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshTimetableMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh timetable metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "timetable metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Transport Metrics
// ---------------------------------------------------------------------

// GetTransportMetrics returns transport metrics for an academic year.
// GET /api/v1/companies/{companyID}/analytics/transport/{academicYearID}/metrics
func (h *AnalyticsHandler) GetTransportMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetTransportMetrics(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get transport metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListTransportMetrics returns paginated transport metrics.
// GET /api/v1/companies/{companyID}/analytics/transport/metrics
func (h *AnalyticsHandler) ListTransportMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	metrics, err := h.analyticsService.ListTransportMetrics(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list transport metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metrics,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshTransportMetrics triggers a full refresh of transport metrics for an academic year.
// POST /api/v1/companies/{companyID}/analytics/transport/{academicYearID}/refresh
func (h *AnalyticsHandler) RefreshTransportMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshTransportMetrics(ctx, academicYearID); err != nil {
		h.logger.Error("failed to refresh transport metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "transport metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------

func parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	return uuid.Parse(companyIDStr)
}

func parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	val := chi.URLParam(r, paramName)
	return uuid.Parse(val)
}

func parsePagination(r *http.Request) (limit, offset int) {
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit == 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offsetStr := r.URL.Query().Get("offset")
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	return
}

func (h *AnalyticsHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check based on user roles.
	return true
}

func (h *AnalyticsHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AnalyticsHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ---------------------------------------------------------------------
// Student Session Summary
// ---------------------------------------------------------------------

// GetStudentSessionSummary returns session attendance summary for a student.
// GET /api/v1/companies/{companyID}/academics/analytics/students/{studentID}/session-summary
func (h *AnalyticsHandler) GetStudentSessionSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDParam(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	var termID *uuid.UUID
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		if id, err := uuid.Parse(termIDStr); err == nil {
			termID = &id
		}
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summary, err := h.analyticsService.GetStudentSessionSummary(ctx, studentID, academicYearID, termID)
	if err != nil {
		h.logger.Error("failed to get student session summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve summary")
		return
	}
	if summary == nil {
		h.respondWithError(w, http.StatusNotFound, "summary not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ListStudentSessionSummaries returns paginated student session summaries.
// GET /api/v1/companies/{companyID}/academics/analytics/students/session-summaries
func (h *AnalyticsHandler) ListStudentSessionSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	// You can add query filters here if needed
	filter := service.StudentSessionSummaryFilter{
		StudentID:      nil,
		AcademicYearID: nil,
		TermID:         nil,
	}
	pag := repository.Pagination{Limit: limit, Offset: offset}
	sort := repository.Sort{Field: "last_updated", Direction: "DESC"}

	summaries, err := h.analyticsService.ListStudentSessionSummaries(ctx, filter, pag, sort)
	if err != nil {
		h.logger.Error("failed to list student session summaries", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries": summaries,
			"limit":     limit,
			"offset":    offset,
		},
	})
}

// RefreshStudentSessionSummary triggers a full refresh of a student's session summary.
// POST /api/v1/companies/{companyID}/academics/analytics/students/{studentID}/academic-years/{academicYearID}/session-summary/refresh
func (h *AnalyticsHandler) RefreshStudentSessionSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDParam(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	var termID *uuid.UUID
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		if id, err := uuid.Parse(termIDStr); err == nil {
			termID = &id
		}
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshStudentSessionSummary(ctx, studentID, academicYearID, termID); err != nil {
		h.logger.Error("failed to refresh student session summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "student session summary refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Section Session Metrics
// ---------------------------------------------------------------------

// GetSectionSessionMetrics returns metrics for a section on a specific date.
// GET /api/v1/companies/{companyID}/academics/analytics/sections/{sectionID}/session-metrics?date=YYYY-MM-DD
func (h *AnalyticsHandler) GetSectionSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionID, err := parseUUIDParam(r, "sectionID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing date parameter")
		return
	}
	sessionDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetSectionSessionMetrics(ctx, sectionID, sessionDate)
	if err != nil {
		h.logger.Error("failed to get section session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListSectionSessionMetrics returns paginated section session metrics.
// GET /api/v1/companies/{companyID}/academics/analytics/sections/session-metrics
func (h *AnalyticsHandler) ListSectionSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	// Optional filters from query parameters
	filter := service.SectionSessionMetricsFilter{
		SectionID: nil,
		FromDate:  nil,
		ToDate:    nil,
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if id, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &id
		}
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		if t, err := time.Parse("2006-01-02", fromStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		if t, err := time.Parse("2006-01-02", toStr); err == nil {
			filter.ToDate = &t
		}
	}

	pag := repository.Pagination{Limit: limit, Offset: offset}
	sort := repository.Sort{Field: "session_date", Direction: "DESC"}

	metricsList, err := h.analyticsService.ListSectionSessionMetrics(ctx, filter, pag, sort)
	if err != nil {
		h.logger.Error("failed to list section session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metricsList,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshSectionSessionMetrics triggers a full refresh for a section on a given date.
// POST /api/v1/companies/{companyID}/academics/analytics/sections/{sectionID}/session-metrics/refresh?date=YYYY-MM-DD
func (h *AnalyticsHandler) RefreshSectionSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionID, err := parseUUIDParam(r, "sectionID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing date parameter")
		return
	}
	sessionDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshSectionSessionMetrics(ctx, sectionID, sessionDate); err != nil {
		h.logger.Error("failed to refresh section session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "section session metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Teacher Session Metrics
// ---------------------------------------------------------------------

// GetTeacherSessionMetrics returns session metrics for a teacher.
// GET /api/v1/companies/{companyID}/academics/analytics/teachers/{teacherID}/academic-years/{academicYearID}/session-metrics
func (h *AnalyticsHandler) GetTeacherSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	teacherID, err := parseUUIDParam(r, "teacherID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid teacher ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetTeacherSessionMetrics(ctx, teacherID, academicYearID)
	if err != nil {
		h.logger.Error("failed to get teacher session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListTeacherSessionMetrics returns paginated teacher session metrics.
// GET /api/v1/companies/{companyID}/academics/analytics/teachers/session-metrics
func (h *AnalyticsHandler) ListTeacherSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	filter := service.TeacherSessionMetricsFilter{
		TeacherID:      nil,
		AcademicYearID: nil,
	}
	if teacherIDStr := r.URL.Query().Get("teacher_id"); teacherIDStr != "" {
		if id, err := uuid.Parse(teacherIDStr); err == nil {
			filter.TeacherID = &id
		}
	}
	if ayIDStr := r.URL.Query().Get("academic_year_id"); ayIDStr != "" {
		if id, err := uuid.Parse(ayIDStr); err == nil {
			filter.AcademicYearID = &id
		}
	}

	pag := repository.Pagination{Limit: limit, Offset: offset}
	sort := repository.Sort{Field: "last_updated", Direction: "DESC"}

	metricsList, err := h.analyticsService.ListTeacherSessionMetrics(ctx, filter, pag, sort)
	if err != nil {
		h.logger.Error("failed to list teacher session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metricsList,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshTeacherSessionMetrics triggers a full refresh for a teacher.
// POST /api/v1/companies/{companyID}/academics/analytics/teachers/{teacherID}/academic-years/{academicYearID}/session-metrics/refresh
func (h *AnalyticsHandler) RefreshTeacherSessionMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	teacherID, err := parseUUIDParam(r, "teacherID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid teacher ID")
		return
	}

	academicYearID, err := parseUUIDParam(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshTeacherSessionMetrics(ctx, teacherID, academicYearID); err != nil {
		h.logger.Error("failed to refresh teacher session metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "teacher session metrics refreshed successfully",
	})
}

// ---------------------------------------------------------------------
// Biometric Usage Metrics
// ---------------------------------------------------------------------

// GetBiometricUsageMetrics returns metrics for a biometric device on a specific date.
// GET /api/v1/companies/{companyID}/academics/analytics/biometric-usage?device_id=xxx&date=YYYY-MM-DD
func (h *AnalyticsHandler) GetBiometricUsageMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing device_id parameter")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing date parameter")
		return
	}
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	metrics, err := h.analyticsService.GetBiometricUsageMetrics(ctx, deviceID, date)
	if err != nil {
		h.logger.Error("failed to get biometric usage metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve metrics")
		return
	}
	if metrics == nil {
		h.respondWithError(w, http.StatusNotFound, "metrics not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}

// ListBiometricUsageMetrics returns paginated biometric usage metrics.
// GET /api/v1/companies/{companyID}/academics/analytics/biometric-usage/list
func (h *AnalyticsHandler) ListBiometricUsageMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := parsePagination(r)
	filter := service.BiometricUsageMetricsFilter{
		DeviceID:  nil,
		CompanyID: &companyID,
		FromDate:  nil,
		ToDate:    nil,
	}
	if deviceID := r.URL.Query().Get("device_id"); deviceID != "" {
		filter.DeviceID = &deviceID
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		if t, err := time.Parse("2006-01-02", fromStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		if t, err := time.Parse("2006-01-02", toStr); err == nil {
			filter.ToDate = &t
		}
	}

	pag := repository.Pagination{Limit: limit, Offset: offset}
	sort := repository.Sort{Field: "date", Direction: "DESC"}

	metricsList, err := h.analyticsService.ListBiometricUsageMetrics(ctx, filter, pag, sort)
	if err != nil {
		h.logger.Error("failed to list biometric usage metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"metrics": metricsList,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// RefreshBiometricUsageMetrics triggers a full refresh for a device on a given date.
// POST /api/v1/companies/{companyID}/academics/analytics/biometric-usage/refresh?device_id=xxx&date=YYYY-MM-DD
func (h *AnalyticsHandler) RefreshBiometricUsageMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing device_id parameter")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing date parameter")
		return
	}
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "analytics:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.analyticsService.RefreshBiometricUsageMetrics(ctx, deviceID, date); err != nil {
		h.logger.Error("failed to refresh biometric usage metrics", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to refresh metrics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "biometric usage metrics refreshed successfully",
	})
}
