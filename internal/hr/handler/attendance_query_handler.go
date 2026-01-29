package handler

import (
	"auth-service/internal/hr/service"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AttendanceQueryHandler handles attendance query operations
type AttendanceQueryHandler struct {
	queryService service.AttendanceQueryService
	logger       *zap.Logger
}

// NewAttendanceQueryHandler creates a new query handler
func NewAttendanceQueryHandler(
	queryService service.AttendanceQueryService,
	logger *zap.Logger,
) *AttendanceQueryHandler {
	return &AttendanceQueryHandler{
		queryService: queryService,
		logger:       logger,
	}
}

// GetEvent handles retrieving a specific attendance event
func (h *AttendanceQueryHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	eventIDStr := chi.URLParam(r, "eventID")
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid event ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:event:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	event, err := h.queryService.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		h.logger.Error("Failed to get attendance event",
			zap.String("event_id", eventID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve event")
		return
	}

	if event == nil {
		h.respondWithError(w, http.StatusNotFound, "event not found")
		return
	}

	// Check if event belongs to user's company
	if event.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "access denied")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// SearchEvents handles searching for attendance events
func (h *AttendanceQueryHandler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:event:search") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Parse dates
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format, use YYYY-MM-DD")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format, use YYYY-MM-DD")
			return
		}
	} else {
		endDate = time.Now()
	}

	// Validate date range
	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date cannot be after end_date")
		return
	}

	// Parse filters
	filters := service.AttendanceSearchFilters{
		CompanyID: companyID,
		StartDate: startDate,
		EndDate:   endDate,
	}

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
			return
		}
		filters.UserID = &userID
	}

	if eventType := r.URL.Query().Get("event_type"); eventType != "" {
		filters.EventType = &eventType
	}

	if sourceType := r.URL.Query().Get("source_type"); sourceType != "" {
		filters.SourceType = &sourceType
	}

	if departmentIDStr := r.URL.Query().Get("department_id"); departmentIDStr != "" {
		departmentID, err := uuid.Parse(departmentIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid department_id")
			return
		}
		filters.DepartmentID = &departmentID
	}

	if shiftIDStr := r.URL.Query().Get("shift_id"); shiftIDStr != "" {
		shiftID, err := uuid.Parse(shiftIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid shift_id")
			return
		}
		filters.ShiftID = &shiftID
	}

	// Search events
	events, total, err := h.queryService.SearchAttendanceEventsTyped(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search attendance events",
			zap.String("company_id", companyID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search events")
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"events": events,
		},
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total":        total,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"filters":      filters,
		},
	})
}

// GetDailySummary handles retrieving daily summary for a user
func (h *AttendanceQueryHandler) GetDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
		return
	}

	// Check permission (users can view their own, managers can view their team)
	if !h.canViewUserAttendance(ctx, companyID, userID) {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summary, err := h.queryService.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		h.logger.Error("Failed to get daily summary",
			zap.String("user_id", userID.String()),
			zap.Time("date", date),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve daily summary")
		return
	}

	if summary == nil {
		h.respondWithError(w, http.StatusNotFound, "daily summary not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// GetUserSummaries handles retrieving summaries for a user over a date range
func (h *AttendanceQueryHandler) GetUserSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// Parse dates
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format, use YYYY-MM-DD")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format, use YYYY-MM-DD")
			return
		}
	} else {
		endDate = time.Now()
	}

	// Validate date range
	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date cannot be after end_date")
		return
	}

	// Check permission
	if !h.canViewUserAttendance(ctx, companyID, userID) {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summaries, err := h.queryService.GetAttendanceDailySummariesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get user summaries",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries":  summaries,
			"user_id":    userID,
			"start_date": startDate,
			"end_date":   endDate,
			"total":      len(summaries),
		},
	})
}

// GetCompanyStats handles retrieving company-wide attendance statistics
func (h *AttendanceQueryHandler) GetCompanyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:stats:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse dates
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format, use YYYY-MM-DD")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format, use YYYY-MM-DD")
			return
		}
	} else {
		endDate = time.Now()
	}

	// Validate date range
	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date cannot be after end_date")
		return
	}

	stats, err := h.queryService.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get company stats",
			zap.String("company_id", companyID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// GetUserStats handles retrieving user attendance statistics
func (h *AttendanceQueryHandler) GetUserStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// Parse dates
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format, use YYYY-MM-DD")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format, use YYYY-MM-DD")
			return
		}
	} else {
		endDate = time.Now()
	}

	// Validate date range
	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date cannot be after end_date")
		return
	}

	// Check permission
	if !h.canViewUserAttendance(ctx, companyID, userID) {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stats, err := h.queryService.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get user stats",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve user statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// GenerateReport handles generating attendance reports
func (h *AttendanceQueryHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:report:generate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse dates
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "csv"
	}

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format, use YYYY-MM-DD")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format, use YYYY-MM-DD")
			return
		}
	} else {
		endDate = time.Now()
	}

	// Validate date range
	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date cannot be after end_date")
		return
	}

	// Generate report
	reportData, contentType, err := h.queryService.GenerateAttendanceReport(ctx, companyID, reportType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to generate report",
			zap.String("company_id", companyID.String()),
			zap.String("report_type", reportType),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate report")
		return
	}

	// Set response headers for file download
	filename := fmt.Sprintf("attendance_report_%s_%s_to_%s.%s",
		companyID.String(),
		startDate.Format("20060102"),
		endDate.Format("20060102"),
		reportType)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(reportData)))
	w.Write(reportData)
}

// ListEventTypes handles listing all valid event types
func (h *AttendanceQueryHandler) ListEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:metadata:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	activeOnly := true
	if r.URL.Query().Get("include_inactive") == "true" {
		activeOnly = false
	}

	eventTypes, err := h.queryService.ListAttendanceEventTypes(ctx, activeOnly)
	if err != nil {
		h.logger.Error("Failed to list event types",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list event types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"event_types": eventTypes,
			"total":       len(eventTypes),
			"active_only": activeOnly,
		},
	})
}

// ListSourceTypes handles listing all valid source types
func (h *AttendanceQueryHandler) ListSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:metadata:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sourceTypes, err := h.queryService.ListAttendanceSourceTypes(ctx)
	if err != nil {
		h.logger.Error("Failed to list source types",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list source types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"source_types": sourceTypes,
			"total":        len(sourceTypes),
		},
	})
}

// Helper function to extract company ID from request

func (h *AttendanceQueryHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission checking
	return true
}

func (h *AttendanceQueryHandler) canViewUserAttendance(ctx interface{}, companyID, userID uuid.UUID) bool {
	// TODO: Implement actual permission checking
	return true
}

func (h *AttendanceQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AttendanceQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
