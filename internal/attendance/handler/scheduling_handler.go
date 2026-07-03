// internal/attendance/handler/scheduling_handler.go
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/scheduling"
)

// SchedulingHandler handles all scheduling-related HTTP endpoints.
type SchedulingHandler struct {
	schedulingService      scheduling.SchedulingService
	schedulingQueryService scheduling.SchedulingQueryService
	logger                 *zap.Logger
}

// NewSchedulingHandler creates a new scheduling handler.
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

// ---- Helper functions ----

// normalizeBusinessDateFromString parses a date string in the given timezone and returns a normalized date (midnight).
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

// normalizeBusinessDate normalizes a time to midnight in the given timezone.
func normalizeBusinessDate(t time.Time, tz string) (time.Time, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}
	local := t.In(loc)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc), nil
}

// getUserTimezone attempts to resolve a user's timezone from their schedule.
func (h *SchedulingHandler) getUserTimezone(ctx context.Context, userID uuid.UUID) string {
	// Try to get timezone from today's schedule instance.
	today := time.Now().UTC().Truncate(24 * time.Hour)
	instances, err := h.schedulingQueryService.GetScheduleInstancesByUser(ctx, userID, today, today)
	if err == nil && len(instances) > 0 && instances[0].Timezone != "" {
		return instances[0].Timezone
	}
	// Fallback to UTC
	return "UTC"
}

// getCompanyDefaultTimezone returns the timezone of the first work calendar for the company.
func (h *SchedulingHandler) getCompanyDefaultTimezone(ctx context.Context, companyID uuid.UUID) string {
	calendars, err := h.schedulingQueryService.GetWorkCalendarsByCompany(ctx, companyID)
	if err != nil || len(calendars) == 0 {
		return "UTC"
	}
	return calendars[0].Timezone
}

// ---- Work Calendar Handlers ----

// CreateWorkCalendar creates a new work calendar.
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

	var calendar models.WorkCalendar
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

// GetWorkCalendar returns a work calendar by ID.
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

// UpdateWorkCalendar updates an existing work calendar.
func (h *SchedulingHandler) UpdateWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
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

// DeleteWorkCalendar deletes a work calendar.
func (h *SchedulingHandler) DeleteWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
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

	if err := h.schedulingService.DeleteWorkCalendar(ctx, calendarID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Work calendar deleted successfully"})
}

// ListWorkCalendars lists all work calendars for a company.
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

// GetCalendarAvailability returns working days and holidays for a calendar.
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
	calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Work calendar not found")
		return
	}
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

// ---- Schedule Template Handlers ----

// CreateScheduleTemplate creates a new schedule template.
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
	template.CompanyID = companyID

	result, err := h.schedulingService.CreateScheduleTemplate(ctx, &template, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

// GetScheduleTemplate returns a schedule template by ID.
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

// UpdateScheduleTemplate updates an existing schedule template.
func (h *SchedulingHandler) UpdateScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateIDStr := chi.URLParam(r, "templateID")
	templateID, err := uuid.Parse(templateIDStr)
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

// DeleteScheduleTemplate deletes a schedule template.
func (h *SchedulingHandler) DeleteScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateIDStr := chi.URLParam(r, "templateID")
	templateID, err := uuid.Parse(templateIDStr)
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

	if err := h.schedulingService.DeleteScheduleTemplate(ctx, templateID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Schedule template deleted successfully"})
}

// ListScheduleTemplates lists all schedule templates for a company.
func (h *SchedulingHandler) ListScheduleTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	result, err := h.schedulingQueryService.GetScheduleTemplatesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// ---- Schedule Instance Handlers ----

type CreateScheduleInstanceRequest struct {
	UserID             uuid.UUID                `json:"user_id"`
	ScheduleDate       string                   `json:"schedule_date"`
	ScheduleTemplateID uuid.UUID                `json:"schedule_template_id"`
	Timezone           string                   `json:"timezone,omitempty"`
	Metadata           *models.InstanceMetadata `json:"metadata,omitempty"`
}

// CreateScheduleInstance manually creates a schedule instance.
func (h *SchedulingHandler) CreateScheduleInstance(w http.ResponseWriter, r *http.Request) {
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

	var req CreateScheduleInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.ScheduleTemplateID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "schedule_template_id is required for manual schedule creation")
		return
	}
	timezone := req.Timezone
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, req.UserID)
	}
	businessDate, err := normalizeBusinessDateFromString(req.ScheduleDate, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid schedule_date")
		return
	}
	instance := &models.ScheduleInstance{
		CompanyID:          companyID,
		UserID:             req.UserID,
		ScheduleDate:       businessDate,
		ScheduleTemplateID: req.ScheduleTemplateID,
		Timezone:           timezone,
		Metadata:           models.InstanceMetadata{},
	}
	if req.Metadata != nil {
		instance.Metadata = *req.Metadata
	}
	result, err := h.schedulingService.CreateScheduleInstance(ctx, instance, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

// CreateScheduleInstanceFromPosition creates a schedule instance based on position resolution.
func (h *SchedulingHandler) CreateScheduleInstanceFromPosition(w http.ResponseWriter, r *http.Request) {
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
		UserID   string `json:"user_id"`
		Date     string `json:"date"`
		Timezone string `json:"timezone,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.UserID == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	if req.Date == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}
	timezone := req.Timezone
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, userID)
	}
	date, err := normalizeBusinessDateFromString(req.Date, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}
	result, err := h.schedulingService.CreateScheduleInstanceFromPosition(ctx, companyID, userID, date, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

// GetScheduleInstance returns a schedule instance by ID.
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

// UpdateScheduleInstance updates a schedule instance (metadata only).
func (h *SchedulingHandler) UpdateScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceIDStr := chi.URLParam(r, "instanceID")
	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid instance ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var update scheduling.ScheduleInstanceUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	result, err := h.schedulingService.UpdateScheduleInstance(ctx, instanceID, update, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// DeleteScheduleInstance deletes a schedule instance.
func (h *SchedulingHandler) DeleteScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceIDStr := chi.URLParam(r, "instanceID")
	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid instance ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := h.schedulingService.DeleteScheduleInstance(ctx, instanceID, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Schedule instance deleted successfully"})
}

// ListScheduleInstances lists schedule instances with various filters.
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
	positionIDStr := r.URL.Query().Get("position_id")
	workCenterCode := r.URL.Query().Get("work_center_code")
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// Determine timezone for date parsing
	timezone := "UTC"
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err == nil {
			timezone = h.getUserTimezone(ctx, userID)
		}
	} else if templateIDStr != "" {
		templateID, err := uuid.Parse(templateIDStr)
		if err == nil {
			tmpl, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
			if err == nil && tmpl != nil {
				cal, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, tmpl.CalendarID)
				if err == nil && cal != nil {
					timezone = cal.Timezone
				}
			}
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

	var result []*models.ScheduleInstance
	switch {
	case userIDStr != "":
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByUser(ctx, userID, startDate, endDate)
	case templateIDStr != "":
		templateID, err := uuid.Parse(templateIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByTemplate(ctx, templateID, startDate, endDate)
	case positionIDStr != "":
		positionID, err := uuid.Parse(positionIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid position ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByPosition(ctx, positionID, startDate, endDate)
	case workCenterCode != "":
		result, err = h.schedulingQueryService.GetScheduleInstancesByWorkCenter(ctx, companyID, workCenterCode, startDate, endDate)
	default:
		result, err = h.schedulingQueryService.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
	}
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// ---- Schedule Generation Handlers ----

type GenerateScheduleRequest struct {
	StartDate       string `json:"start_date"`
	EndDate         string `json:"end_date"`
	Timezone        string `json:"timezone"`
	IncludeHolidays bool   `json:"include_holidays"`
	Overwrite       bool   `json:"overwrite"`
	BatchSize       int    `json:"batch_size"`
}

// GenerateScheduleForUser generates schedule instances for a specific user.
// GenerateScheduleForUser generates schedule instances for a specific user.
func (h *SchedulingHandler) GenerateScheduleForUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	// Get company ID from context
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

	var req GenerateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.StartDate == "" || req.EndDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
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

	config := scheduling.ScheduleGenerationConfig{
		StartDate:       startDate,
		EndDate:         endDate,
		Timezone:        req.Timezone,
		IncludeHolidays: req.IncludeHolidays,
		Overwrite:       req.Overwrite,
		BatchSize:       req.BatchSize,
	}
	// Pass companyID to service
	result, err := h.schedulingService.GenerateScheduleForUser(ctx, companyID, userID, config, actorType, actorID)
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

// GenerateScheduleForCompany generates schedule instances for all employees in a company.
func (h *SchedulingHandler) GenerateScheduleForCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
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
	if req.Timezone == "" {
		req.Timezone = h.getCompanyDefaultTimezone(ctx, companyID)
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
	config := scheduling.ScheduleGenerationConfig{
		StartDate:       startDate,
		EndDate:         endDate,
		Timezone:        req.Timezone,
		IncludeHolidays: req.IncludeHolidays,
		Overwrite:       req.Overwrite,
		BatchSize:       req.BatchSize,
	}
	result, err := h.schedulingService.GenerateScheduleForCompany(ctx, companyID, config, actorType, actorID)
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

// ---- Schedule Override Handlers ----

type CreateScheduleOverrideRequest struct {
	UserID       uuid.UUID `json:"user_id"`
	OverrideDate string    `json:"override_date"`
	OverrideType string    `json:"override_type"`
	Reason       *string   `json:"reason,omitempty"`
}

// CreateScheduleOverride creates a schedule override for a user.
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
	// Check if override already exists
	existing, _ := h.schedulingQueryService.GetScheduleOverrideByUserDate(ctx, req.UserID, overrideDate)
	if existing != nil {
		h.respondWithError(w, http.StatusConflict, "Schedule override already exists for this date")
		return
	}
	override := &models.ScheduleOverride{
		OverrideID:   uuid.New(),
		CompanyID:    companyID,
		UserID:       req.UserID,
		OverrideDate: overrideDate,
		OverrideType: req.OverrideType,
		Reason:       req.Reason,
		CreatedBy:    &actorID,
		CreatedAt:    time.Now(),
	}
	result, err := h.schedulingService.CreateScheduleOverride(ctx, companyID, override, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, result)
}

// GetScheduleOverrides returns schedule overrides for a user or company.
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
	// Determine timezone
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
	} else {
		result, err = h.schedulingQueryService.GetScheduleOverridesByCompany(ctx, companyID, startDate, endDate, overrideTypePtr)
	}
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// GetScheduleOverrideByID returns a specific override.
func (h *SchedulingHandler) GetScheduleOverrideByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideIDStr := chi.URLParam(r, "overrideID")
	overrideID, err := uuid.Parse(overrideIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}
	result, err := h.schedulingQueryService.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Schedule override not found")
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// UpdateScheduleOverride updates an existing override.
func (h *SchedulingHandler) UpdateScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideIDStr := chi.URLParam(r, "overrideID")
	overrideID, err := uuid.Parse(overrideIDStr)
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
	// Validate override type if provided
	if update.OverrideType != nil && *update.OverrideType != "" {
		valid := map[string]bool{"off": true, "force_work": true, "holiday_override": true}
		if !valid[*update.OverrideType] {
			h.respondWithError(w, http.StatusBadRequest, "Invalid override_type. Must be one of: off, force_work, holiday_override")
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

// DeleteScheduleOverride deletes an override.
func (h *SchedulingHandler) DeleteScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideIDStr := chi.URLParam(r, "overrideID")
	overrideID, err := uuid.Parse(overrideIDStr)
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

// ---- Work Center Handlers ----

// GetWorkCenter returns a work center by code.
func (h *SchedulingHandler) GetWorkCenter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	workCenterCode := chi.URLParam(r, "workCenterCode")
	result, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Work center not found")
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// ListWorkCenters lists work centers for a company.
func (h *SchedulingHandler) ListWorkCenters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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

// GetWorkCenterShifts returns the active shift mapping for a work center.
func (h *SchedulingHandler) GetWorkCenterShifts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	workCenterCode := r.URL.Query().Get("work_center_code")
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

// ---- Work Center Shift Mapping Handlers ----

// CreateWorkCenterShiftMapping creates a new work center shift mapping.
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

	var mapping models.WorkCenterShift
	if err := json.NewDecoder(r.Body).Decode(&mapping); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	mapping.CompanyID = companyID
	if err := h.schedulingService.CreateWorkCenterShiftMapping(ctx, companyID, &mapping, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]string{"message": "Work center shift mapping created successfully"})
}

// UpdateWorkCenterShiftMapping updates an existing work center shift mapping by key.
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
		WorkCenterCode string    `json:"work_center_code"`
		EffectiveTo    time.Time `json:"effective_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.WorkCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "work_center_code is required")
		return
	}
	update := scheduling.WorkCenterShiftUpdate{
		EffectiveTo: &req.EffectiveTo,
	}
	if err := h.schedulingService.UpdateWorkCenterShiftMappingByKey(ctx, companyID, req.WorkCenterCode, update, actorType, actorID, nil); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Work center shift mapping updated successfully"})
}

// ---- Position & Assignment Handlers ----

// GetUserScheduledPosition returns the position a user is scheduled for on a date.
func (h *SchedulingHandler) GetUserScheduledPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
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

// GetUserCurrentAssignment returns the user's current work center assignment.
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

// ---- Holiday Handlers ----

// AddHolidayToCalendar adds a holiday to an existing calendar.
func (h *SchedulingHandler) AddHolidayToCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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
	if err := h.schedulingService.AddHolidayToCalendar(ctx, req.CalendarID, req.Date, req.Name, actorType, actorID); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Holiday added to calendar successfully"})
}

// ProcessHolidayForDate processes a holiday for a specific date (cancels schedules).
func (h *SchedulingHandler) ProcessHolidayForDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType := getSessionTypeFromContext(ctx)
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		Date string `json:"date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	date, err := time.Parse("2006-01-02", req.Date)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}
	if err := h.schedulingService.ProcessHolidayForDate(ctx, companyID, date, actorType, actorID); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Holiday processed successfully"})
}

// ---- Stats & Query Handlers ----

// GetScheduleStats returns aggregated scheduling statistics.
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
	timezone := h.getCompanyDefaultTimezone(ctx, companyID)

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = normalizeBusinessDateFromString(startDateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
			return
		}
	} else {
		startDate, _ = normalizeBusinessDate(time.Now().AddDate(0, -1, 0), timezone)
	}
	if endDateStr != "" {
		endDate, err = normalizeBusinessDateFromString(endDateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
			return
		}
	} else {
		endDate, _ = normalizeBusinessDate(time.Now(), timezone)
	}
	result, err := h.schedulingQueryService.GetScheduleStats(ctx, companyID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, result)
}

// CheckScheduleAvailability returns the expected start/end times for a user on a date.
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

// ValidateScheduleConflict checks if a proposed time range conflicts with existing schedules.
func (h *SchedulingHandler) ValidateScheduleConflict(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id parameter is required")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user_id format")
		return
	}
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")
	if startTimeStr == "" || endTimeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_time and end_time are required")
		return
	}
	timezone := r.URL.Query().Get("timezone")
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, userID)
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid timezone")
		return
	}
	startTime, err := time.ParseInLocation("2006-01-02T15:04:05", startTimeStr, loc)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_time format")
		return
	}
	endTime, err := time.ParseInLocation("2006-01-02T15:04:05", endTimeStr, loc)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_time format")
		return
	}
	excludeInstanceIDStr := r.URL.Query().Get("exclude_instance_id")
	var excludeInstanceID *uuid.UUID
	if excludeInstanceIDStr != "" {
		id, err := uuid.Parse(excludeInstanceIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid exclude_instance_id format")
			return
		}
		excludeInstanceID = &id
	}
	hasConflict, err := h.schedulingService.ValidateScheduleConflict(ctx, userID, startTime, endTime, excludeInstanceID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"has_conflict": hasConflict})
}

// ---- Health Check ----

// HealthCheck returns the health status of the scheduling service.
func (h *SchedulingHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.schedulingQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"status": "healthy", "service": "scheduling"})
}

// ---- Response Helpers ----

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
