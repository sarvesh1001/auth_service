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

type AttendanceQueryHandler struct {
	queryService service.AttendanceQueryService
	logger       *zap.Logger
}

func NewAttendanceQueryHandler(
	queryService service.AttendanceQueryService,
	logger *zap.Logger,
) *AttendanceQueryHandler {
	return &AttendanceQueryHandler{
		queryService: queryService,
		logger:       logger,
	}
}

// =====================================================
// Events
// =====================================================

func (h *AttendanceQueryHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	eventIDStr := chi.URLParam(r, "eventID")
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid event ID")
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

	if event.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "access denied")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

func (h *AttendanceQueryHandler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filters := service.AttendanceSearchFilters{
		CompanyID: companyID,
		StartDate: startDate,
		EndDate:   endDate,
	}

	if v := r.URL.Query().Get("user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
			return
		}
		filters.UserID = &id
	}

	if v := r.URL.Query().Get("event_type"); v != "" {
		switch v {
		case "check_in":
			filters.EventTypes = []string{"check_in", "manual_check_in"}
		case "check_out":
			filters.EventTypes = []string{"check_out", "manual_check_out"}
		default:
			filters.EventTypes = []string{v}
		}
	}

	if v := r.URL.Query().Get("source_type"); v != "" {
		filters.SourceType = &v
	}

	if v := r.URL.Query().Get("department_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid department_id")
			return
		}
		filters.DepartmentID = &id
	}

	if v := r.URL.Query().Get("shift_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid shift_id")
			return
		}
		filters.ShiftID = &id
	}

	events, total, err := h.queryService.SearchAttendanceEventsTyped(
		ctx,
		companyID,
		filters,
		page,
		pageSize,
	)
	if err != nil {
		h.logger.Error("Failed to search attendance events",
			zap.String("company_id", companyID.String()),
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
			"page":       page,
			"page_size":  pageSize,
			"total":      total,
			"totalPages": totalPages,
			"has_next":   page < totalPages,
			"has_prev":   page > 1,
			"date_range": map[string]time.Time{"start": startDate, "end": endDate},
		},
	})
}

// =====================================================
// Summaries
// =====================================================

func (h *AttendanceQueryHandler) GetDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	date, err := time.Parse("2006-01-02", chi.URLParam(r, "date"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
		return
	}

	summary, err := h.queryService.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		h.logger.Error("Failed to get daily summary",
			zap.String("user_id", userID.String()),
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

func (h *AttendanceQueryHandler) GetUserSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaries, err := h.queryService.GetAttendanceDailySummariesByUser(
		ctx,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("Failed to get user summaries",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries": summaries,
			"total":     len(summaries),
		},
	})
}

// =====================================================
// Stats & Metadata
// =====================================================

func (h *AttendanceQueryHandler) GetCompanyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	stats, err := h.queryService.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get company stats",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func (h *AttendanceQueryHandler) GetUserStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	stats, err := h.queryService.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get user stats",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve user statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// =====================================================
// Reports & Metadata
// =====================================================

func (h *AttendanceQueryHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "csv"
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	data, contentType, err := h.queryService.GenerateAttendanceReport(
		ctx,
		companyID,
		reportType,
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("Failed to generate report",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate report")
		return
	}

	filename := fmt.Sprintf(
		"attendance_report_%s_%s_to_%s.%s",
		companyID.String(),
		startDate.Format("20060102"),
		endDate.Format("20060102"),
		reportType,
	)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (h *AttendanceQueryHandler) ListEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	activeOnly := r.URL.Query().Get("include_inactive") != "true"

	types, err := h.queryService.ListAttendanceEventTypes(ctx, activeOnly)
	if err != nil {
		h.logger.Error("Failed to list event types", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list event types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    types,
	})
}

func (h *AttendanceQueryHandler) ListSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	types, err := h.queryService.ListAttendanceSourceTypes(ctx)
	if err != nil {
		h.logger.Error("Failed to list source types", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list source types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    types,
	})
}

// =====================================================
// Helpers
// =====================================================

func parseDateRange(r *http.Request) (time.Time, time.Time, error) {
	startStr := r.URL.Query().Get("start_date")
	endStr := r.URL.Query().Get("end_date")

	start := time.Now().AddDate(0, 0, -30)
	end := time.Now()

	var err error
	if startStr != "" {
		start, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date format, use YYYY-MM-DD")
		}
	}

	if endStr != "" {
		end, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date format, use YYYY-MM-DD")
		}
	}

	if start.After(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_date cannot be after end_date")
	}

	return start, end, nil
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
