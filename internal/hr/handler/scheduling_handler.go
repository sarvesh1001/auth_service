package handler

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/service"
	"auth-service/internal/middleware"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type SchedulingHandler struct {
	schedulingService      service.SchedulingService
	schedulingQueryService service.SchedulingQueryService
	logger                 *zap.Logger
}

func NewSchedulingHandler(
	schedulingService service.SchedulingService,
	schedulingQueryService service.SchedulingQueryService,
	logger *zap.Logger,
) *SchedulingHandler {
	return &SchedulingHandler{
		schedulingService:      schedulingService,
		schedulingQueryService: schedulingQueryService,
		logger:                 logger,
	}
}

// Helper function to normalize business dates
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

// Helper to normalize existing time.Time to business date in specific timezone
func normalizeBusinessDate(t time.Time, tz string) (time.Time, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}
	local := t.In(loc) // FIX: Convert to target timezone first
	return time.Date(
		local.Year(), local.Month(), local.Day(),
		0, 0, 0, 0,
		loc,
	), nil
}

// Helper to get user's timezone from their current assignment
func (h *SchedulingHandler) getUserTimezone(ctx context.Context, userID uuid.UUID) string {
	assignment, err := h.schedulingQueryService.GetUserCurrentScheduleAssignment(ctx, userID, time.Now())
	if err != nil {
		return "UTC"
	}

	template, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, assignment.ScheduleTemplateID)
	if err != nil {
		return "UTC"
	}

	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		return "UTC"
	}

	return calendar.Timezone
}

// Helper to get company's default calendar timezone
func (h *SchedulingHandler) getCompanyDefaultTimezone(ctx context.Context, companyID uuid.UUID) string {
	calendars, err := h.schedulingQueryService.GetWorkCalendarsByCompany(ctx, companyID)
	if err != nil || len(calendars) == 0 {
		return "UTC"
	}

	// TODO: Implement proper default calendar logic
	// For now, use the first calendar as default
	return calendars[0].Timezone
}

func (h *SchedulingHandler) CreateWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var calendar scheduling.WorkCalendar
	if err := json.NewDecoder(r.Body).Decode(&calendar); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	calendar.CompanyID = companyID
	result, err := h.schedulingService.CreateWorkCalendar(ctx, &calendar, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}

	result, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) ListWorkCalendars(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	result, err := h.schedulingQueryService.GetWorkCalendarsByCompany(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetCalendarAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
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

	// Get calendar to get timezone
	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}

	// Normalize dates using calendar timezone
	startDate, err := normalizeBusinessDateFromString(startDateStr, calendar.Timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
		return
	}

	endDate, err := normalizeBusinessDateFromString(endDateStr, calendar.Timezone)
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

func (h *SchedulingHandler) CreateScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var template scheduling.ScheduleTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	template.CompanyID = companyID
	result, err := h.schedulingService.CreateScheduleTemplate(ctx, &template, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateIDStr := chi.URLParam(r, "templateID")
	templateID, err := uuid.Parse(templateIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}

	result, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule template not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) ListScheduleTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	result, err := h.schedulingQueryService.GetScheduleTemplatesByCompany(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) AssignUserToTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var assignment scheduling.UserScheduleAssignment
	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	err = h.schedulingService.AssignUserToTemplate(ctx, companyID, &assignment, actorType, actorID, nil)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "already has an active assignment") {
			h.respondWithError(w, http.StatusConflict, err.Error())
		} else if strings.Contains(err.Error(), "user ID is required") ||
			strings.Contains(err.Error(), "schedule template ID is required") ||
			strings.Contains(err.Error(), "user not found") ||
			strings.Contains(err.Error(), "does not belong to this company") {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]string{
		"message": "User assigned to schedule template successfully",
	})
}

func (h *SchedulingHandler) GetUserCurrentAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	var date time.Time

	// Get user's timezone using helper
	userTimezone := h.getUserTimezone(ctx, userID)

	if dateStr != "" {
		date, err = normalizeBusinessDateFromString(dateStr, userTimezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	} else {
		// Normalize current time to user's timezone
		date, err = normalizeBusinessDate(time.Now(), userTimezone)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "Failed to normalize date")
			return
		}
	}

	result, err := h.schedulingQueryService.GetUserCurrentScheduleAssignment(ctx, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "No schedule assignment found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

type CreateScheduleInstanceRequest struct {
	UserID        uuid.UUID  `json:"user_id"`
	ScheduleDate  string     `json:"schedule_date"` // YYYY-MM-DD
	ExpectedStart *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time `json:"expected_end,omitempty"`
}

func (h *SchedulingHandler) CreateScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req CreateScheduleInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Get user's current assignment to determine calendar timezone
	assignment, err := h.schedulingQueryService.GetUserCurrentScheduleAssignment(ctx, req.UserID, time.Now())
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "User has no active schedule assignment")
		return
	}

	// Get template and calendar for timezone
	template, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, assignment.ScheduleTemplateID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Schedule template not found")
		return
	}

	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Work calendar not found")
		return
	}

	// Normalize business date using calendar timezone
	businessDate, err := normalizeBusinessDateFromString(req.ScheduleDate, calendar.Timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid schedule date format")
		return
	}

	instance := &scheduling.ScheduleInstance{
		CompanyID:     companyID,
		UserID:        req.UserID,
		ScheduleDate:  businessDate,
		ExpectedStart: req.ExpectedStart,
		ExpectedEnd:   req.ExpectedEnd,
		Timezone:      calendar.Timezone,
		Metadata:      scheduling.InstanceMetadata{},
	}

	result, err := h.schedulingService.CreateScheduleInstance(ctx, instance, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceIDStr := chi.URLParam(r, "instanceID")
	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid instance ID")
		return
	}

	result, err := h.schedulingQueryService.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule instance not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) ListScheduleInstances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userIDStr := r.URL.Query().Get("user_id")
	templateIDStr := r.URL.Query().Get("template_id")
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// For date normalization, we need a timezone
	// For user-specific queries, use user's calendar timezone
	// For template queries, use template's calendar timezone
	// For company queries, use company's default timezone
	timezone := "UTC"

	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		// Use helper to get user's timezone
		timezone = h.getUserTimezone(ctx, userID)
	} else if templateIDStr != "" {
		templateID, err := uuid.Parse(templateIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
			return
		}
		// Get template's calendar timezone
		template, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
		if err == nil && template != nil {
			calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, template.CalendarID)
			if err == nil && calendar != nil {
				timezone = calendar.Timezone
			}
		}
	} else {
		// For company queries, use company's default timezone
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

	var result []*scheduling.ScheduleInstance
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByUser(ctx, userID, startDate, endDate)
	} else if templateIDStr != "" {
		templateID, err := uuid.Parse(templateIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByTemplate(ctx, templateID, startDate, endDate)
	} else {
		result, err = h.schedulingQueryService.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
	}

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GenerateScheduleForUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	type GenerateScheduleRequest struct {
		StartDate       string `json:"start_date"`
		EndDate         string `json:"end_date"`
		Timezone        string `json:"timezone"`
		IncludeHolidays bool   `json:"include_holidays"`
		Overwrite       bool   `json:"overwrite"`
		BatchSize       int    `json:"batch_size"`
	}

	var req GenerateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.StartDate == "" || req.EndDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// If timezone not provided, get from user's calendar using helper
	if req.Timezone == "" {
		req.Timezone = h.getUserTimezone(ctx, userID)
	}

	startDate, err := normalizeBusinessDateFromString(req.StartDate, req.Timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
		return
	}

	endDate, err := normalizeBusinessDateFromString(req.EndDate, req.Timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
		return
	}

	if startDate.After(endDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date must be before or equal to end_date")
		return
	}

	if req.BatchSize <= 0 {
		req.BatchSize = 100
	}

	config := service.ScheduleGenerationConfig{
		StartDate:       startDate,
		EndDate:         endDate,
		Timezone:        req.Timezone,
		IncludeHolidays: req.IncludeHolidays,
		Overwrite:       req.Overwrite,
		BatchSize:       req.BatchSize,
	}

	result, err := h.schedulingService.GenerateScheduleForUser(ctx, userID, config, actorType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":   "Schedule generated successfully",
		"instances": len(result),
		"data":      result,
	})
}

func (h *SchedulingHandler) GetScheduleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time

	// FIX: Use company's default calendar timezone instead of hardcoded UTC
	timezone := h.getCompanyDefaultTimezone(ctx, companyID)

	if startDateStr != "" {
		startDate, err = normalizeBusinessDateFromString(startDateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, -1, 0)
		startDate, err = normalizeBusinessDate(startDate, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "Failed to normalize start date")
			return
		}
	}

	if endDateStr != "" {
		endDate, err = normalizeBusinessDateFromString(endDateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
			return
		}
	} else {
		endDate = time.Now()
		endDate, err = normalizeBusinessDate(endDate, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "Failed to normalize end date")
			return
		}
	}

	result, err := h.schedulingQueryService.GetScheduleStats(
		ctx,
		companyID,
		startDate,
		endDate,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetScheduleCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// FIX: Use company's default calendar timezone instead of hardcoded UTC
	timezone := h.getCompanyDefaultTimezone(ctx, companyID)

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

	result, err := h.schedulingQueryService.GetScheduleCoverage(ctx, companyID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

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

	dateStr := r.URL.Query().Get("date")
	timezone := r.URL.Query().Get("timezone")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}

	// If timezone not provided, get from user's calendar using helper
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, userID)
	}

	date, err := normalizeBusinessDateFromString(dateStr, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
		return
	}

	result, err := h.schedulingService.CheckScheduleAvailability(ctx, userID, date, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":        userID,
		"date":           dateStr,
		"timezone":       timezone,
		"schedule_times": result,
	})
}

func (h *SchedulingHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.schedulingQueryService.HealthCheck(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "scheduling",
	})
}

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

func (h *SchedulingHandler) CreateOffEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var createReq scheduling.OffEntitlementCreate
	if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	entitlement := &scheduling.UserOffEntitlement{
		EntitlementID:    uuid.New(),
		CompanyID:        companyID,
		UserID:           createReq.UserID,
		PeriodType:       createReq.PeriodType,
		OffCount:         createReq.OffCount,
		RequiresApproval: createReq.RequiresApproval,
		EffectiveFrom:    createReq.EffectiveFrom,
		EffectiveTo:      createReq.EffectiveTo,
		CreatedAt:        time.Now().UTC(),
	}

	result, err := h.schedulingService.CreateOffEntitlement(ctx, companyID, entitlement, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetOffEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	activeOnly := r.URL.Query().Get("active_only") != "false"
	result, err := h.schedulingQueryService.GetOffEntitlementsByUser(ctx, userID, activeOnly)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) CreateOffRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var createReq scheduling.OffRequestCreate
	if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	request := &scheduling.OffRequest{
		OffRequestID: uuid.New(),
		CompanyID:    companyID,
		UserID:       createReq.UserID,
		RequestDates: createReq.RequestDates,
		Status:       "pending",
		RequestedBy:  createReq.RequestedBy,
		CreatedAt:    time.Now().UTC(),
	}

	if createReq.Status != nil {
		request.Status = *createReq.Status
	}

	result, err := h.schedulingService.CreateOffRequest(ctx, companyID, request, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetOffRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userIDStr := r.URL.Query().Get("user_id")
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	status := r.URL.Query().Get("status")

	var startDate, endDate time.Time
	if startDateStr != "" && endDateStr != "" {
		// For off requests, we use UTC for date normalization
		startDate, err = normalizeBusinessDateFromString(startDateStr, "UTC")
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
			return
		}
		endDate, err = normalizeBusinessDateFromString(endDateStr, "UTC")
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
			return
		}
	}

	var result []*scheduling.OffRequest
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetOffRequestsByUser(ctx, userID, startDate, endDate, &status)
	} else {
		result, err = h.schedulingQueryService.GetOffRequestsByCompany(ctx, companyID, startDate, endDate, &status)
	}

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) ApproveOffRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.ApproveOffRequest(ctx, requestID, actorID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Off request approved successfully",
	})
}

func (h *SchedulingHandler) RejectOffRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.RejectOffRequest(ctx, requestID, actorID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Off request rejected successfully",
	})
}

type ScheduleOverrideCreate struct {
	UserID       uuid.UUID `json:"user_id"`
	OverrideDate string    `json:"override_date"` // YYYY-MM-DD
	OverrideType string    `json:"override_type"`
	Reason       string    `json:"reason,omitempty"`
	// CreatedBy is ignored - always use actorID for security
}

func (h *SchedulingHandler) CreateScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var createReq ScheduleOverrideCreate
	if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Get user's calendar timezone for date normalization using helper
	userTimezone := h.getUserTimezone(ctx, createReq.UserID)

	// Normalize override date using calendar timezone
	overrideDate, err := normalizeBusinessDateFromString(createReq.OverrideDate, userTimezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override date format")
		return
	}

	// Create a pointer to the reason string if it's not empty
	var reasonPtr *string
	if createReq.Reason != "" {
		reasonPtr = &createReq.Reason
	}

	// Create a pointer to actorID for CreatedBy field
	createdByPtr := &actorID

	override := &scheduling.ScheduleOverride{
		OverrideID:   uuid.New(),
		CompanyID:    companyID,
		UserID:       createReq.UserID,
		OverrideDate: overrideDate,
		OverrideType: createReq.OverrideType,
		Reason:       reasonPtr,
		CreatedBy:    createdByPtr,
		CreatedAt:    time.Now().UTC(),
	}

	result, err := h.schedulingService.CreateScheduleOverride(ctx, companyID, override, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetScheduleOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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

	// Determine timezone for normalization
	timezone := "UTC"
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err == nil {
			timezone = h.getUserTimezone(ctx, userID)
		}
	} else {
		// For company-wide queries, use company's default timezone
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

	var result []*scheduling.ScheduleOverride
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleOverridesByUser(ctx, userID, startDate, endDate, &overrideType)
	} else {
		result, err = h.schedulingQueryService.GetScheduleOverridesByCompany(ctx, companyID, startDate, endDate, &overrideType)
	}

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) RequestTimeOff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req struct {
		Dates  []string `json:"dates"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(req.Dates) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "At least one date is required")
		return
	}

	result, err := h.schedulingService.RequestTimeOff(ctx, companyID, userID, req.Dates, req.Reason, actorType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) GetUserTimeOffSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// Get user's calendar timezone for date normalization using helper
	userTimezone := h.getUserTimezone(ctx, userID)

	startDate, err := normalizeBusinessDateFromString(startDateStr, userTimezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
		return
	}

	endDate, err := normalizeBusinessDateFromString(endDateStr, userTimezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
		return
	}

	result, err := h.schedulingQueryService.GetUserTimeOffSummary(ctx, userID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) CheckDateAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserIDFromContext(ctx)

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date parameter is required")
		return
	}

	// Get user's calendar timezone for date normalization using helper
	userTimezone := h.getUserTimezone(ctx, userID)

	date, err := normalizeBusinessDateFromString(dateStr, userTimezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}

	result, err := h.schedulingQueryService.CheckDateAvailability(ctx, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

type DeclareHolidayRequest struct {
	CalendarID uuid.UUID `json:"calendar_id"`
	Date       string    `json:"date"`
	Name       string    `json:"name"`
}

func (h *SchedulingHandler) DeclareHoliday(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req DeclareHolidayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Get calendar to get timezone for date normalization
	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, req.CalendarID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Calendar not found")
		return
	}

	holidayDate, err := normalizeBusinessDateFromString(req.Date, calendar.Timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format (YYYY-MM-DD)")
		return
	}

	err = h.schedulingService.AddHolidayToCalendar(
		ctx,
		req.CalendarID,
		req.Date,
		req.Name,
		actorType,
		actorID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = h.schedulingService.ProcessHolidayForDate(
		ctx,
		companyID,
		holidayDate,
		actorType,
		actorID,
	)
	if err != nil {
		h.logger.Warn("Holiday declared but failed to cancel schedules", zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Holiday declared and schedules updated",
	})
}
