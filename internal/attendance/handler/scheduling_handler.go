package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/scheduling"
	"auth-service/internal/locationctx"
)

type SchedulingHandler struct {
	schedulingService      scheduling.SchedulingService
	schedulingQueryService scheduling.SchedulingQueryService
	logger                 *zap.Logger
}

func NewSchedulingHandler(
	schedulingService scheduling.SchedulingService,
	schedulingQueryService scheduling.SchedulingQueryService,
	logger *zap.Logger,
) *SchedulingHandler {
	return &SchedulingHandler{
		schedulingService:      schedulingService,
		schedulingQueryService: schedulingQueryService,
		logger:                 logger,
	}
}

// =============================================================================
// Time normalization helpers
// =============================================================================

func normalizeBusinessDateFromString(dateStr, tz string) (time.Time, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}
	d, err := time.ParseInLocation("2006-01-02", dateStr, loc)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc), nil
}

func normalizeBusinessDate(t time.Time, tz string) (time.Time, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}
	local := t.In(loc)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc), nil
}

func parseDateFlexible(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unparseable date: %q", s)
}

// getUserTimezone — previously derived per-user tz from a materialized
// schedule_instances row. With instances gone, we fall back to the
// company's default timezone. Callers that need finer granularity should
// pass an explicit `timezone` in the request body/query.
func (h *SchedulingHandler) getUserTimezone(ctx context.Context, userID uuid.UUID) string {
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		return "UTC"
	}
	tz, err := h.schedulingQueryService.ResolveCompanyTimezone(ctx, companyID)
	if err != nil || tz == "" {
		return "UTC"
	}
	return tz
}

func (h *SchedulingHandler) getCompanyDefaultTimezone(ctx context.Context, companyID uuid.UUID) string {
	tz, err := h.schedulingQueryService.ResolveCompanyTimezone(ctx, companyID)
	if err != nil || tz == "" {
		return "UTC"
	}
	return tz
}

func (h *SchedulingHandler) pathCompanyMatchesContext(
	w http.ResponseWriter,
	r *http.Request,
) (uuid.UUID, bool) {
	ctx := r.Context()
	pathCompany, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return uuid.Nil, false
	}
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return uuid.Nil, false
	}
	if !assertPathCompany(w, ctxCompany, pathCompany, h.logger) {
		return uuid.Nil, false
	}
	return pathCompany, true
}

// =============================================================================
// Work calendars
// =============================================================================

type CreateWorkCalendarRequest struct {
	Name        string               `json:"name"`
	Year        int                  `json:"year"`
	LocationID  *uuid.UUID           `json:"location_id,omitempty"`
	WorkingDays []int                `json:"working_days"`
	Holidays    []scheduling.Holiday `json:"holidays,omitempty"`
	IsActive    bool                 `json:"is_active"`
}

func holidaysToMap(holidays []scheduling.Holiday) map[string]interface{} {
	out := make(map[string]interface{}, len(holidays))
	for _, h := range holidays {
		out[h.Date] = map[string]interface{}{
			"date": h.Date,
			"name": h.Name,
		}
	}
	return out
}

func (h *SchedulingHandler) CreateWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req CreateWorkCalendarRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("work calendar decode failed", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	targetLocationID, err := resolveTargetLocation(ctx, req.LocationID)
	if err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	calendar := &models.WorkCalendar{
		CompanyID:   companyID,
		LocationID:  targetLocationID,
		Year:        req.Year,
		Name:        req.Name,
		WorkingDays: req.WorkingDays,
		Holidays:    holidaysToMap(req.Holidays),
		IsActive:    req.IsActive,
	}

	result, err := h.schedulingService.CreateWorkCalendar(ctx, calendar, actorType, actorID, nil)
	if err != nil {
		h.logger.Warn("work calendar create failed",
			zap.String("company_id", companyID.String()),
			zap.Any("location_id", targetLocationID),
			zap.String("name", req.Name),
			zap.Int("year", req.Year),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarID, err := uuid.Parse(chi.URLParam(r, "calendarID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}
	result, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil || result == nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}
	locCtx, ctxErr := locationctx.FromContext(ctx)
	if ctxErr == nil && locCtx.Mode != locationctx.ScopeAll {
		if result.LocationID != nil && (locCtx.LocationID == nil || *result.LocationID != *locCtx.LocationID) {
			h.respondWithError(w, http.StatusForbidden, "calendar is outside your access scope")
			return
		}
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) UpdateWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarID, err := uuid.Parse(chi.URLParam(r, "calendarID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil || existing == nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}
	if err := assertCanTouchLocation(ctx, existing.LocationID); err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	var update scheduling.WorkCalendarUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	result, err := h.schedulingService.UpdateWorkCalendar(ctx, calendarID, update, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) DeleteWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarID, err := uuid.Parse(chi.URLParam(r, "calendarID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil || existing == nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}
	if err := assertCanTouchLocation(ctx, existing.LocationID); err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	if err := h.schedulingService.DeleteWorkCalendar(ctx, calendarID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Work calendar deleted successfully"})
}

func (h *SchedulingHandler) ListWorkCalendars(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}
	locFilter := locationctx.Filter(ctx)
	result, err := h.schedulingQueryService.GetWorkCalendarsByCompany(ctx, companyID, locFilter)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetCalendarAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarID, err := uuid.Parse(chi.URLParam(r, "calendarID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil || calendar == nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}

	locCtx, ctxErr := locationctx.FromContext(ctx)
	if ctxErr == nil && locCtx.Mode != locationctx.ScopeAll {
		if calendar.LocationID != nil && (locCtx.LocationID == nil || *calendar.LocationID != *locCtx.LocationID) {
			h.respondWithError(w, http.StatusForbidden, "calendar is outside your access scope")
			return
		}
	}

	tz := ""
	if calendar.LocationID != nil {
		if t, err := h.schedulingQueryService.ResolveLocationTimezone(ctx, calendar.CompanyID, *calendar.LocationID); err == nil && t != "" {
			tz = t
		}
	} else if ctxErr == nil && locCtx.LocationID != nil {
		if t, err := h.schedulingQueryService.ResolveLocationTimezone(ctx, calendar.CompanyID, *locCtx.LocationID); err == nil && t != "" {
			tz = t
		}
	}
	if tz == "" {
		tz = h.getCompanyDefaultTimezone(ctx, calendar.CompanyID)
	}
	startDate, err := normalizeBusinessDateFromString(startDateStr, tz)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
		return
	}
	endDate, err := normalizeBusinessDateFromString(endDateStr, tz)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
		return
	}
	result, err := h.schedulingQueryService.GetWorkCalendarAvailability(ctx, calendarID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// =============================================================================
// Schedule templates
// =============================================================================

func (h *SchedulingHandler) CreateScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var template models.ScheduleTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	targetLocationID, err := resolveTargetLocation(ctx, template.LocationID)
	if err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	template.CompanyID = companyID
	template.LocationID = targetLocationID

	result, err := h.schedulingService.CreateScheduleTemplate(ctx, &template, actorType, actorID, nil)
	if err != nil {
		h.logger.Warn("schedule template create failed",
			zap.String("company_id", companyID.String()),
			zap.Any("location_id", targetLocationID),
			zap.String("name", template.Name),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateID, err := uuid.Parse(chi.URLParam(r, "templateID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}
	result, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
	if err != nil || result == nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule template not found")
		return
	}
	locCtx, ctxErr := locationctx.FromContext(ctx)
	if ctxErr == nil && locCtx.Mode != locationctx.ScopeAll {
		if result.LocationID != nil && (locCtx.LocationID == nil || *result.LocationID != *locCtx.LocationID) {
			h.respondWithError(w, http.StatusForbidden, "template is outside your access scope")
			return
		}
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) UpdateScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateID, err := uuid.Parse(chi.URLParam(r, "templateID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
	if err != nil || existing == nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule template not found")
		return
	}
	if err := assertCanTouchLocation(ctx, existing.LocationID); err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	var update scheduling.ScheduleTemplateUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	result, err := h.schedulingService.UpdateScheduleTemplate(ctx, templateID, update, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) DeleteScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateID, err := uuid.Parse(chi.URLParam(r, "templateID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
	if err != nil || existing == nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule template not found")
		return
	}
	if err := assertCanTouchLocation(ctx, existing.LocationID); err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	if err := h.schedulingService.DeleteScheduleTemplate(ctx, templateID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Schedule template deleted successfully"})
}

func (h *SchedulingHandler) ListScheduleTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	locFilter := locationctx.Filter(ctx)
	result, err := h.schedulingQueryService.GetScheduleTemplatesByCompany(ctx, companyID, locFilter, activeOnly)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// =============================================================================
// Schedule preview
// =============================================================================

// PreviewUserSchedule returns the derived schedule for a user over a date
// range. It writes nothing. The response is the same shape the punch path
// produces, so the frontend can render it directly.
//
// Query params:
//
//	from  YYYY-MM-DD  (required)
//	to    YYYY-MM-DD  (required)
func (h *SchedulingHandler) PreviewUserSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to are required")
		return
	}

	tz := h.getUserTimezone(ctx, userID)

	from, err := normalizeBusinessDateFromString(fromStr, tz)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid from date. Use YYYY-MM-DD")
		return
	}
	to, err := normalizeBusinessDateFromString(toStr, tz)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid to date. Use YYYY-MM-DD")
		return
	}
	if to.Before(from) {
		h.respondWithError(w, http.StatusBadRequest, "to must be on or after from")
		return
	}

	days, err := h.schedulingQueryService.PreviewSchedule(ctx, companyID, userID, from, to)
	if err != nil {
		h.logger.Warn("preview schedule failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.String("from", fromStr),
			zap.String("to", toStr),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, days)
}

// =============================================================================
// Schedule overrides
// =============================================================================

type CreateScheduleOverrideRequest struct {
	UserID        uuid.UUID `json:"user_id"`
	OverrideDate  string    `json:"override_date"`
	OverrideType  string    `json:"override_type"`
	Reason        *string   `json:"reason,omitempty"`
	ExpectedStart *string   `json:"expected_start,omitempty"` // "09:00:00"
	ExpectedEnd   *string   `json:"expected_end,omitempty"`   // "19:00:00"
}

func (h *SchedulingHandler) CreateScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req CreateScheduleOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if req.OverrideType == "" {
		h.respondWithError(w, http.StatusBadRequest, "override_type is required")
		return
	}
	userTimezone := h.getUserTimezone(ctx, req.UserID)
	overrideDate, err := normalizeBusinessDateFromString(req.OverrideDate, userTimezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "override_date must be in YYYY-MM-DD format")
		return
	}
	existing, _ := h.schedulingQueryService.GetScheduleOverrideByUserDate(ctx, req.UserID, overrideDate)
	if existing != nil {
		h.respondWithError(w, http.StatusConflict, "Schedule override already exists for this date")
		return
	}
	override := &models.ScheduleOverride{
		OverrideID:    uuid.New(),
		CompanyID:     companyID,
		UserID:        req.UserID,
		OverrideDate:  overrideDate,
		OverrideType:  req.OverrideType,
		ExpectedStart: req.ExpectedStart,
		ExpectedEnd:   req.ExpectedEnd,
		Reason:        req.Reason,
		CreatedBy:     &actorID,
		CreatedAt:     time.Now(),
	}
	result, err := h.schedulingService.CreateScheduleOverride(ctx, companyID, override, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetScheduleOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}
	userIDStr := r.URL.Query().Get("user_id")
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	overrideType := r.URL.Query().Get("override_type")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	timezone := "UTC"
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err == nil {
			timezone = h.getUserTimezone(ctx, userID)
		} else {
			timezone = h.getCompanyDefaultTimezone(ctx, companyID)
		}
	} else {
		timezone = h.getCompanyDefaultTimezone(ctx, companyID)
	}
	startDate, err := normalizeBusinessDateFromString(startDateStr, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
		return
	}
	endDate, err := normalizeBusinessDateFromString(endDateStr, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
		return
	}
	var overrideTypePtr *string
	if overrideType != "" {
		overrideTypePtr = &overrideType
	}
	var result []*models.ScheduleOverride
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleOverridesByUser(ctx, userID, startDate, endDate, overrideTypePtr)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		result, err = h.schedulingQueryService.GetScheduleOverridesByCompany(ctx, companyID, startDate, endDate, overrideTypePtr)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetScheduleOverrideByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideID, err := uuid.Parse(chi.URLParam(r, "overrideID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}
	result, err := h.schedulingQueryService.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil || result == nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule override not found")
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) UpdateScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideID, err := uuid.Parse(chi.URLParam(r, "overrideID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var update scheduling.ScheduleOverrideUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if update.OverrideType != nil && *update.OverrideType != "" {
		valid := map[string]bool{
			"off":              true,
			"force_work":       true,
			"holiday_override": true,
			"custom_hours":     true,
		}
		if !valid[*update.OverrideType] {
			h.respondWithError(w, http.StatusBadRequest,
				"Invalid override_type. Must be one of: off, force_work, holiday_override, custom_hours")
			return
		}
	}
	result, err := h.schedulingService.UpdateScheduleOverride(ctx, overrideID, update, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) DeleteScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideID, err := uuid.Parse(chi.URLParam(r, "overrideID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := h.schedulingService.DeleteScheduleOverride(ctx, overrideID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Schedule override deleted successfully"})
}

// =============================================================================
// Work centers
// =============================================================================

func (h *SchedulingHandler) GetWorkCenter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}
	workCenterCode := chi.URLParam(r, "workCenterCode")
	result, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil || result == nil {
		h.respondWithError(w, http.StatusNotFound, "Work center not found")
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) ListWorkCenters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	result, err := h.schedulingQueryService.GetWorkCentersByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetWorkCenterShifts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, ok := h.pathCompanyMatchesContext(w, r)
	if !ok {
		return
	}

	workCenterCode := chi.URLParam(r, "workCenterCode")
	if workCenterCode == "" {
		workCenterCode = r.URL.Query().Get("work_center_code")
	}
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "work_center_code is required")
		return
	}

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr != "" {
		wc, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, companyID, workCenterCode)
		if err != nil || wc == nil {
			h.respondWithError(w, http.StatusBadRequest, "Work center not found")
			return
		}
		date, err = normalizeBusinessDateFromString(dateStr, wc.Timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	} else {
		date = time.Now()
	}

	result, err := h.schedulingQueryService.GetWorkCenterShifts(ctx, companyID, workCenterCode, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// =============================================================================
// Work center shift mappings
// =============================================================================

type CreateWorkCenterShiftMappingRequest struct {
	WorkCenterCode string    `json:"work_center_code"`
	ShiftID        uuid.UUID `json:"shift_id"`
	EffectiveFrom  string    `json:"effective_from"`
	EffectiveTo    *string   `json:"effective_to,omitempty"`
	IsActive       *bool     `json:"is_active,omitempty"`
}

func (h *SchedulingHandler) CreateWorkCenterShiftMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req CreateWorkCenterShiftMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("wc shift mapping decode failed", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.WorkCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "work_center_code is required")
		return
	}
	if req.ShiftID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "shift_id is required")
		return
	}
	if req.EffectiveFrom == "" {
		h.respondWithError(w, http.StatusBadRequest, "effective_from is required")
		return
	}

	effectiveFrom, err := parseDateFlexible(req.EffectiveFrom)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest,
			"effective_from must be YYYY-MM-DD or RFC3339")
		return
	}

	var effectiveTo *time.Time
	if req.EffectiveTo != nil && *req.EffectiveTo != "" {
		t, err := parseDateFlexible(*req.EffectiveTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest,
				"effective_to must be YYYY-MM-DD or RFC3339")
			return
		}
		effectiveTo = &t
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	mapping := &models.WorkCenterShift{
		MappingID:      uuid.New(),
		CompanyID:      companyID,
		WorkCenterCode: req.WorkCenterCode,
		ShiftID:        req.ShiftID,
		EffectiveFrom:  effectiveFrom,
		EffectiveTo:    effectiveTo,
		IsActive:       isActive,
	}

	if err := h.schedulingService.CreateWorkCenterShiftMapping(ctx, companyID, mapping, actorType, actorID, nil); err != nil {
		h.logger.Warn("wc shift mapping create failed",
			zap.String("company_id", companyID.String()),
			zap.String("work_center", req.WorkCenterCode),
			zap.String("shift_id", req.ShiftID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]string{
		"message": "Work center shift mapping created successfully",
	})
}

func (h *SchedulingHandler) UpdateWorkCenterShiftMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		WorkCenterCode string  `json:"work_center_code"`
		ShiftID        *string `json:"shift_id,omitempty"`
		EffectiveTo    *string `json:"effective_to,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("wc shift mapping update decode failed", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.WorkCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "work_center_code is required")
		return
	}

	update := scheduling.WorkCenterShiftUpdate{}

	if req.ShiftID != nil && *req.ShiftID != "" {
		id, err := uuid.Parse(*req.ShiftID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid shift_id")
			return
		}
		update.ShiftID = &id
	}

	if req.EffectiveTo != nil && *req.EffectiveTo != "" {
		t, err := parseDateFlexible(*req.EffectiveTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest,
				"effective_to must be YYYY-MM-DD or RFC3339")
			return
		}
		update.EffectiveTo = &t
	}

	if err := h.schedulingService.UpdateWorkCenterShiftMappingByKey(
		ctx, companyID, req.WorkCenterCode, update, actorType, actorID, nil,
	); err != nil {
		h.logger.Warn("wc shift mapping update failed",
			zap.String("work_center", req.WorkCenterCode),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Work center shift mapping updated successfully",
	})
}

// =============================================================================
// Position-based resolution views
// =============================================================================

func (h *SchedulingHandler) GetUserScheduledPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr != "" {
		timezone := h.getUserTimezone(ctx, userID)
		date, err = normalizeBusinessDateFromString(dateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	} else {
		date = time.Now()
	}
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	resolved, err := h.schedulingService.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]interface{}{
		"user_id":          userID,
		"date":             date.Format("2006-01-02"),
		"position_id":      resolved.PositionID,
		"position_title":   resolved.PositionTitle,
		"work_center_code": resolved.WorkCenterCode,
		"work_center_name": resolved.WorkCenterName,
	}
	h.respondWithJSON(w, http.StatusOK, response)
}

func (h *SchedulingHandler) GetUserCurrentAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr != "" {
		timezone := h.getUserTimezone(ctx, userID)
		date, err = normalizeBusinessDateFromString(dateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	} else {
		date = time.Now()
	}
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	resolved, err := h.schedulingService.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":          userID,
		"date":             date.Format("2006-01-02"),
		"work_center_code": resolved.WorkCenterCode,
		"work_center_name": resolved.WorkCenterName,
		"position_id":      resolved.PositionID,
		"position_title":   resolved.PositionTitle,
	})
}

// =============================================================================
// Holidays
// =============================================================================

func (h *SchedulingHandler) AddHolidayToCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := h.pathCompanyMatchesContext(w, r); !ok {
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		CalendarID uuid.UUID `json:"calendar_id"`
		Date       string    `json:"date"`
		Name       string    `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.CalendarID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "calendar_id is required")
		return
	}
	if req.Date == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}

	existing, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, req.CalendarID)
	if err != nil || existing == nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}
	if err := assertCanTouchLocation(ctx, existing.LocationID); err != nil {
		writeLocationResolutionError(w, h.logger, err)
		return
	}

	if err := h.schedulingService.AddHolidayToCalendar(ctx, req.CalendarID, req.Date, req.Name, actorType, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Holiday added to calendar successfully"})
}

// =============================================================================
// Availability
// =============================================================================

func (h *SchedulingHandler) CheckScheduleAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDParam := r.URL.Query().Get("user_id")
	if userIDParam == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id parameter is required")
		return
	}
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user_id format")
		return
	}
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Company ID not found in context")
		return
	}
	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}
	timezone := r.URL.Query().Get("timezone")
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, userID)
	}
	date, err := normalizeBusinessDateFromString(dateStr, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
		return
	}
	times, err := h.schedulingService.CheckScheduleAvailability(ctx, companyID, userID, date, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":        userID,
		"date":           dateStr,
		"timezone":       timezone,
		"schedule_times": times,
	})
}

// =============================================================================
// Health
// =============================================================================

func (h *SchedulingHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.schedulingQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"status": "healthy", "service": "scheduling"})
}

// =============================================================================
// Response helpers
// =============================================================================

func (h *SchedulingHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *SchedulingHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
