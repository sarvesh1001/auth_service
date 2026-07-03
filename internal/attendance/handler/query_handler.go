package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/query"
)

// AttendanceQueryHandler handles attendance queries.
type AttendanceQueryHandler struct {
	queryService query.QueryService
	logger       *zap.Logger
}

// NewAttendanceQueryHandler creates a new handler.
func NewAttendanceQueryHandler(
	queryService query.QueryService,
	logger *zap.Logger,
) *AttendanceQueryHandler {
	return &AttendanceQueryHandler{
		queryService: queryService,
		logger:       logger,
	}
}

// ---- Events ----

// GetEvent returns a single attendance event by ID.
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

	event, err := h.queryService.GetEventByID(ctx, eventID)
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

// SearchEvents searches attendance events with filters and pagination.
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

	filter := query.EventFilter{
		CompanyID: companyID,
		StartDate: startDate,
		EndDate:   endDate,
		Page:      page,
		PageSize:  pageSize,
	}

	if v := r.URL.Query().Get("subject_type"); v != "" {
		filter.SubjectType = &v
	}
	if v := r.URL.Query().Get("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
			return
		}
		filter.SubjectID = &id
	}
	if v := r.URL.Query().Get("event_type"); v != "" {
		switch v {
		case "check_in":
			filter.EventTypes = []string{"check_in", "manual_check_in"}
		case "check_out":
			filter.EventTypes = []string{"check_out", "manual_check_out"}
		default:
			filter.EventTypes = []string{v}
		}
	}
	if v := r.URL.Query().Get("source_type"); v != "" {
		filter.SourceType = &v
	}
	if v := r.URL.Query().Get("device_id"); v != "" {
		filter.DeviceID = &v
	}

	events, total, err := h.queryService.ListEvents(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to search attendance events",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search events")
		return
	}

	totalPages := (int(total) + pageSize - 1) / pageSize
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

// ---- Summaries ----

// GetDailySummary returns the attendance summary for a specific user and date.
func (h *AttendanceQueryHandler) GetDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	subjectType := chi.URLParam(r, "subjectType")
	if subjectType == "" {
		subjectType = "employee" // default for backward compatibility
	}

	date, err := time.Parse("2006-01-02", chi.URLParam(r, "date"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
		return
	}

	summary, err := h.queryService.GetDailySummary(ctx, companyID, subjectID, subjectType, date)
	if err != nil {
		h.logger.Error("Failed to get daily summary",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
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

// GetSubjectSummaries returns all daily summaries for a subject over a date range.
func (h *AttendanceQueryHandler) GetSubjectSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	subjectType := chi.URLParam(r, "subjectType")
	if subjectType == "" {
		subjectType = "employee"
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaries, err := h.queryService.ListDailySummaries(ctx, companyID, subjectID, subjectType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get subject summaries",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
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

// ---- Stats ----

// GetCompanyStats returns aggregated attendance statistics for a company.
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

	stats, err := h.queryService.GetCompanyStats(ctx, companyID, startDate, endDate)
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

// GetSubjectStats returns attendance statistics for a single subject.
func (h *AttendanceQueryHandler) GetSubjectStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	subjectType := chi.URLParam(r, "subjectType")
	if subjectType == "" {
		subjectType = "employee"
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	stats, err := h.queryService.GetSubjectStats(ctx, companyID, subjectID, subjectType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get subject stats",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve subject statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// ---- Metadata ----

// ListEventTypes returns the available attendance event types.
func (h *AttendanceQueryHandler) ListEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	activeOnly := r.URL.Query().Get("include_inactive") != "true"

	types, err := h.queryService.ListEventTypes(ctx, activeOnly)
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

// ListSourceTypes returns the available attendance source types.
func (h *AttendanceQueryHandler) ListSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	types, err := h.queryService.ListSourceTypes(ctx)
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

// ---- NEW: Session Summary Endpoints ----

// GetSessionSummary returns a session summary for a specific session and subject.
func (h *AttendanceQueryHandler) GetSessionSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	subjectType := r.URL.Query().Get("subject_type")
	if subjectType == "" {
		h.respondWithError(w, http.StatusBadRequest, "subject_type is required")
		return
	}
	subjectID, err := uuid.Parse(r.URL.Query().Get("subject_id"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
		return
	}

	summary, err := h.queryService.GetSessionSummary(ctx, sessionID, subjectID, subjectType)
	if err != nil {
		h.logger.Error("Failed to get session summary",
			zap.String("session_id", sessionID.String()),
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve session summary")
		return
	}
	if summary == nil {
		h.respondWithError(w, http.StatusNotFound, "session summary not found")
		return
	}
	if summary.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "access denied")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ListSessionSummaries returns paginated session summaries with filters.
func (h *AttendanceQueryHandler) ListSessionSummaries(w http.ResponseWriter, r *http.Request) {
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

	filter := repository.SessionSummaryFilter{}
	filter.CompanyID = &companyID

	if v := r.URL.Query().Get("subject_type"); v != "" {
		filter.SubjectType = &v
	}
	if v := r.URL.Query().Get("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
			return
		}
		filter.SubjectID = &id
	}
	if v := r.URL.Query().Get("session_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid session_id")
			return
		}
		filter.SessionID = &id
	}
	if v := r.URL.Query().Get("session_date"); v != "" {
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid session_date, use YYYY-MM-DD")
			return
		}
		filter.SessionDate = &d
	}
	if v := r.URL.Query().Get("status"); v != "" {
		filter.Status = &v
	}

	summaries, total, err := h.queryService.ListSessionSummaries(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list session summaries",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list session summaries")
		return
	}

	totalPages := (int(total) + pageSize - 1) / pageSize
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
		"meta": map[string]interface{}{
			"page":       page,
			"page_size":  pageSize,
			"total":      total,
			"totalPages": totalPages,
			"has_next":   page < totalPages,
			"has_prev":   page > 1,
		},
	})
}

// ---- NEW: Exemption Query Endpoints ----

// GetExemptionsForSubject returns active exemptions for a subject on a specific date.
func (h *AttendanceQueryHandler) GetExemptionsForSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}
	subjectType := chi.URLParam(r, "subjectType")
	if subjectType == "" {
		h.respondWithError(w, http.StatusBadRequest, "subject_type is required")
		return
	}
	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date, use YYYY-MM-DD")
		return
	}

	exemptions, err := h.queryService.GetExemptionsForSubject(ctx, companyID, subjectID, subjectType, date)
	if err != nil {
		h.logger.Error("Failed to get exemptions",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve exemptions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exemptions,
	})
}

// ListExemptions returns paginated exemptions with filters.
func (h *AttendanceQueryHandler) ListExemptions(w http.ResponseWriter, r *http.Request) {
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

	filter := repository.ExemptionFilter{}
	filter.CompanyID = &companyID

	if v := r.URL.Query().Get("subject_type"); v != "" {
		filter.SubjectType = &v
	}
	if v := r.URL.Query().Get("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
			return
		}
		filter.SubjectID = &id
	}
	if v := r.URL.Query().Get("from_date"); v != "" {
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from_date, use YYYY-MM-DD")
			return
		}
		filter.FromDate = &d
	}
	if v := r.URL.Query().Get("to_date"); v != "" {
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to_date, use YYYY-MM-DD")
			return
		}
		filter.ToDate = &d
	}

	exemptions, total, err := h.queryService.ListExemptions(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list exemptions",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exemptions")
		return
	}

	totalPages := (int(total) + pageSize - 1) / pageSize
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exemptions,
		"meta": map[string]interface{}{
			"page":       page,
			"page_size":  pageSize,
			"total":      total,
			"totalPages": totalPages,
			"has_next":   page < totalPages,
			"has_prev":   page > 1,
		},
	})
}

// ---- Helpers ----

func (h *AttendanceQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
