package handler

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/service"
	"auth-service/internal/middleware"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

// Helper functions
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
	return time.Date(
		local.Year(), local.Month(), local.Day(),
		0, 0, 0, 0,
		loc,
	), nil
}

func (h *SchedulingHandler) getUserTimezone(ctx context.Context, userID uuid.UUID) string {
	// Try to get from schedule instance first
	instance, err := h.schedulingQueryService.GetScheduleInstanceByUserDate(ctx, userID, time.Now())
	if err == nil && instance != nil {
		return instance.Timezone
	}

	// Fallback to work center timezone
	employee, err := h.schedulingQueryService.GetCompanyEmployeeByUserID(ctx, userID)
	if err == nil && employee != nil && employee.PositionID != nil {
		position, err := h.schedulingQueryService.GetPositionByID(ctx, *employee.PositionID)
		if err == nil && position != nil && position.WorkCenterCode != nil {
			workCenter, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, position.CompanyID, *position.WorkCenterCode)
			if err == nil {
				return workCenter.Timezone
			}
		}
	}

	// Default to UTC
	return "UTC"
}

func (h *SchedulingHandler) getCompanyDefaultTimezone(ctx context.Context, companyID uuid.UUID) string {
	calendars, err := h.schedulingQueryService.GetWorkCalendarsByCompany(ctx, companyID)
	if err != nil || len(calendars) == 0 {
		return "UTC"
	}
	return calendars[0].Timezone
}

// getCompanyIDFromContext helper function
func getCompanyIDFromContext(ctx context.Context) (uuid.UUID, error) {
	rawCompanyID := ctx.Value("company_id")
	if rawCompanyID == nil {
		return uuid.Nil, errors.New("company_id not found in context")
	}

	switch v := rawCompanyID.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, errors.New("invalid company_id type in context")
	}
}

// Work Calendar Handlers
func (h *SchedulingHandler) CreateWorkCalendar(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var calendar scheduling.WorkCalendar
	if err := json.NewDecoder(r.Body).Decode(&calendar); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 🔒 ENFORCE SERVER OWNERSHIP
	calendar.CompanyID = companyID // enforce company

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

func (h *SchedulingHandler) UpdateWorkCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var update service.WorkCalendarUpdate
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
	calendarIDStr := chi.URLParam(r, "calendarID")
	calendarID, err := uuid.Parse(calendarIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid calendar ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.DeleteWorkCalendar(ctx, calendarID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Work calendar deleted successfully",
	})
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

// Schedule Template Handlers
func (h *SchedulingHandler) CreateScheduleTemplate(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var template scheduling.ScheduleTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 🔒 ENFORCE SERVER OWNERSHIP
	template.CompanyID = companyID // enforce company

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

func (h *SchedulingHandler) UpdateScheduleTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templateIDStr := chi.URLParam(r, "templateID")
	templateID, err := uuid.Parse(templateIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var update service.ScheduleTemplateUpdate
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
	templateIDStr := chi.URLParam(r, "templateID")
	templateID, err := uuid.Parse(templateIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.DeleteScheduleTemplate(ctx, templateID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Schedule template deleted successfully",
	})
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

// Schedule Instance Handlers
// CreateScheduleInstanceRequest
// Used ONLY for manual schedule creation
type CreateScheduleInstanceRequest struct {
	UserID             uuid.UUID                    `json:"user_id"`
	ScheduleDate       string                       `json:"schedule_date"` // YYYY-MM-DD
	ScheduleTemplateID uuid.UUID                    `json:"schedule_template_id"`
	Timezone           string                       `json:"timezone,omitempty"`
	Metadata           *scheduling.InstanceMetadata `json:"metadata,omitempty"`
}

func (h *SchedulingHandler) CreateScheduleInstance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req CreateScheduleInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 🔒 Enforce template requirement (manual means explicit)
	if req.ScheduleTemplateID == uuid.Nil {
		h.respondWithError(
			w,
			http.StatusBadRequest,
			"schedule_template_id is required for manual schedule creation",
		)
		return
	}

	// Resolve timezone
	timezone := req.Timezone
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, req.UserID)
	}

	// Normalize business date
	businessDate, err := normalizeBusinessDateFromString(
		req.ScheduleDate,
		timezone,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid schedule_date")
		return
	}

	// Build instance (times resolved in service from template)
	instance := &scheduling.ScheduleInstance{
		CompanyID:          companyID, // from context
		UserID:             req.UserID,
		ScheduleDate:       businessDate,
		ScheduleTemplateID: req.ScheduleTemplateID,
		Timezone:           timezone,
		Metadata:           scheduling.InstanceMetadata{},
	}

	if req.Metadata != nil {
		instance.Metadata = *req.Metadata
	}

	result, err := h.schedulingService.CreateScheduleInstance(
		ctx,
		instance,
		actorType,
		actorID,
		nil,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *SchedulingHandler) CreateScheduleInstanceFromPosition(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// 2. Actor info (from session / token)
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	// 3. Request payload
	var req struct {
		UserID   string `json:"user_id"`
		Date     string `json:"date"`
		Timezone string `json:"timezone,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 4. Validate user_id
	if req.UserID == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// 5. Validate date
	if req.Date == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}

	// 6. Resolve timezone
	timezone := req.Timezone
	if timezone == "" {
		timezone = h.getUserTimezone(ctx, userID)
	}

	// 7. Normalize business date
	date, err := normalizeBusinessDateFromString(req.Date, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}

	// 8. Call service
	result, err := h.schedulingService.CreateScheduleInstanceFromPosition(
		ctx,
		companyID, // from context
		userID,
		date,
		actorType,
		actorID,
		nil, // optional metadata
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 9. Success response
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

func (h *SchedulingHandler) UpdateScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceIDStr := chi.URLParam(r, "instanceID")
	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid instance ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var update service.ScheduleInstanceUpdate
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

func (h *SchedulingHandler) DeleteScheduleInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceIDStr := chi.URLParam(r, "instanceID")
	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid instance ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.DeleteScheduleInstance(ctx, instanceID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Schedule instance deleted successfully",
	})
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
	positionIDStr := r.URL.Query().Get("position_id")
	workCenterCode := r.URL.Query().Get("work_center_code")
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	timezone := "UTC"
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		timezone = h.getUserTimezone(ctx, userID)
	} else if templateIDStr != "" {
		templateID, err := uuid.Parse(templateIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid template ID")
			return
		}
		template, err := h.schedulingQueryService.GetScheduleTemplateByID(ctx, templateID)
		if err == nil && template != nil {
			calendar, err := h.schedulingQueryService.GetWorkCalendarByID(ctx, template.CalendarID)
			if err == nil && calendar != nil {
				timezone = calendar.Timezone
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
	} else if positionIDStr != "" {
		positionID, err := uuid.Parse(positionIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid position ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleInstancesByPosition(ctx, positionID, startDate, endDate)
	} else if workCenterCode != "" {
		result, err = h.schedulingQueryService.GetScheduleInstancesByWorkCenter(ctx, companyID, workCenterCode, startDate, endDate)
	} else {
		result, err = h.schedulingQueryService.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
	}

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) SearchScheduleInstances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var filters service.ScheduleSearchFilters
	if err := json.NewDecoder(r.Body).Decode(&filters); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// ✅ ENFORCE company scope from context
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Company ID not found in context")
		return
	}
	filters.CompanyID = &companyID

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	result, total, err := h.schedulingQueryService.SearchScheduleInstances(ctx, filters, page, pageSize)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"instances":   result,
		"total_count": total,
		"page":        page,
		"page_size":   pageSize,
	})
}

// Schedule Generation Handlers
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

func (h *SchedulingHandler) GenerateScheduleForCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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

	config := service.ScheduleGenerationConfig{
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

// Position-Based Scheduling Handlers
func (h *SchedulingHandler) ResolveUserDay(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	userIDStr := chi.URLParam(r, "userID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		dateStr = time.Now().Format("2006-01-02")
	}

	timezone := h.getUserTimezone(ctx, userID)
	date, err := normalizeBusinessDateFromString(dateStr, timezone)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}

	result, err := h.schedulingService.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

type CreateScheduleOverrideRequest struct {
	UserID       uuid.UUID `json:"user_id"`
	OverrideDate string    `json:"override_date"` // YYYY-MM-DD
	OverrideType string    `json:"override_type"` // off | force_work | holiday_override
	Reason       *string   `json:"reason,omitempty"`
}

// Schedule Override Handlers
func (h *SchedulingHandler) CreateScheduleOverride(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

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

	// Get user's timezone
	userTimezone := h.getUserTimezone(ctx, req.UserID)

	// Parse date in user's timezone
	overrideDate, err := normalizeBusinessDateFromString(req.OverrideDate, userTimezone)
	if err != nil {
		h.respondWithError(
			w,
			http.StatusBadRequest,
			"override_date must be in YYYY-MM-DD format",
		)
		return
	}

	// Check if override already exists for this user and date
	existingOverride, err := h.schedulingQueryService.GetScheduleOverrideByUserDate(
		ctx, req.UserID, overrideDate)
	if err == nil && existingOverride != nil {
		h.respondWithError(
			w,
			http.StatusConflict,
			"Schedule override already exists for this date",
		)
		return
	}

	// Create override with all required fields
	now := time.Now()
	override := &scheduling.ScheduleOverride{
		OverrideID:   uuid.New(),
		CompanyID:    companyID,
		UserID:       req.UserID,
		OverrideDate: overrideDate,
		OverrideType: req.OverrideType,
		Reason:       req.Reason,
		CreatedBy:    &actorID,
		CreatedAt:    now,
	}

	result, err := h.schedulingService.CreateScheduleOverride(
		ctx,
		companyID,
		override,
		actorType,
		actorID,
		nil,
	)
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

	// Get appropriate timezone
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

	// Parse dates in the correct timezone
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

	// Log for debugging
	h.logger.Debug("Getting schedule overrides",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userIDStr),
		zap.String("start_date", startDateStr),
		zap.String("end_date", endDateStr),
		zap.String("timezone", timezone),
		zap.String("override_type", overrideType),
	)

	var result []*scheduling.ScheduleOverride
	var overrideTypePtr *string
	if overrideType != "" {
		overrideTypePtr = &overrideType
	}

	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		result, err = h.schedulingQueryService.GetScheduleOverridesByUser(
			ctx, userID, startDate, endDate, overrideTypePtr)
	} else {
		result, err = h.schedulingQueryService.GetScheduleOverridesByCompany(
			ctx, companyID, startDate, endDate, overrideTypePtr)
	}

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Work Center Handlers
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

// Work Center Shift Mapping Handlers
func (h *SchedulingHandler) CreateWorkCenterShiftMapping(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var mapping scheduling.WorkCenterShiftMapping
	if err := json.NewDecoder(r.Body).Decode(&mapping); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 🔒 ENFORCE SERVER OWNERSHIP
	mapping.CompanyID = companyID // enforce company

	err = h.schedulingService.CreateWorkCenterShiftMapping(ctx, companyID, &mapping, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]string{
		"message": "Work center shift mapping created successfully",
	})
}

func (h *SchedulingHandler) UpdateWorkCenterShiftMapping(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req struct {
		WorkCenterCode string    `json:"work_center_code"`
		EffectiveTo    time.Time `json:"effective_to"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.WorkCenterCode == "" {
		h.respondWithError(
			w,
			http.StatusBadRequest,
			"work_center_code is required",
		)
		return
	}

	update := scheduling.WorkCenterShiftMappingUpdate{
		EffectiveTo: &req.EffectiveTo,
	}

	err = h.schedulingService.UpdateWorkCenterShiftMappingByKey(
		ctx,
		companyID,
		req.WorkCenterCode,
		update,
		actorType,
		actorID,
		nil,
	)

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Work center shift mapping updated successfully",
	})
}

func (h *SchedulingHandler) GetWorkCenterShifts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1️⃣ Company ID (path param)
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// 2️⃣ Work center code (QUERY param — IMPORTANT FIX)
	workCenterCode := r.URL.Query().Get("work_center_code")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "work_center_code is required")
		return
	}

	// 3️⃣ Date (optional query param)
	dateStr := r.URL.Query().Get("date")

	var date time.Time

	if dateStr != "" {
		// 4️⃣ Fetch work center to get timezone
		workCenter, err := h.schedulingQueryService.
			GetWorkCenterByCode(ctx, companyID, workCenterCode)
		if err != nil || workCenter == nil {
			h.respondWithError(w, http.StatusBadRequest, "Work center not found")
			return
		}

		// 5️⃣ Normalize business date using WC timezone
		date, err = normalizeBusinessDateFromString(
			dateStr,
			workCenter.Timezone,
		)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format (expected YYYY-MM-DD)")
			return
		}
	} else {
		// Default to today (UTC-safe fallback)
		date = time.Now()
	}

	// 6️⃣ Fetch shifts
	result, err := h.schedulingQueryService.
		GetWorkCenterShifts(ctx, companyID, workCenterCode, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 7️⃣ Respond
	h.respondWithJSON(w, http.StatusOK, result)
}

// User Work Center Assignment Handlers
func (h *SchedulingHandler) AssignUserToWorkCenter(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var assignment scheduling.UserWorkCenterAssignment
	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 🔒 ENFORCE SERVER OWNERSHIP
	assignment.CompanyID = companyID // enforce company

	err = h.schedulingService.AssignUserToWorkCenter(ctx, companyID, &assignment, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]string{
		"message": "User assigned to work center successfully",
	})
}

func (h *SchedulingHandler) EndUserWorkCenterAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid assignment ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req struct {
		EndDate time.Time `json:"end_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	err = h.schedulingService.EndUserWorkCenterAssignment(ctx, assignmentID, req.EndDate, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "User work center assignment ended successfully",
	})
}

// Position Handlers
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

	result, err := h.schedulingQueryService.GetUserScheduledPosition(ctx, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Holiday Handlers
func (h *SchedulingHandler) AddHolidayToCalendar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req struct {
		CalendarID uuid.UUID `json:"calendar_id"`
		Date       string    `json:"date"`
		Name       string    `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	err = h.schedulingService.AddHolidayToCalendar(ctx, req.CalendarID, req.Date, req.Name, actorType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Holiday added to calendar successfully",
	})
}

// Query and Stats Handlers
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

	result, err := h.schedulingQueryService.GetScheduleStats(ctx, companyID, startDate, endDate)
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

func (h *SchedulingHandler) GetUserScheduleSummary(w http.ResponseWriter, r *http.Request) {
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

	result, err := h.schedulingQueryService.GetUserScheduleSummary(ctx, userID, startDate, endDate)
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

	// ✅ Get company ID from context
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

	// ✅ Validate employee exists
	employee, err := h.schedulingQueryService.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil {
		h.respondWithError(
			w,
			http.StatusNotFound,
			fmt.Sprintf("User %s is not an employee in this company", userID.String()),
		)
		return
	}

	// ✅ Validate employee belongs to this company
	if employee.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "User does not belong to the specified company")
		return
	}

	// ✅ PASS companyID INTO SERVICE
	result, err := h.schedulingService.CheckScheduleAvailability(
		ctx,
		companyID,
		userID,
		date,
		timezone,
	)
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

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"has_conflict": hasConflict,
	})
}

// Bulk Operations
func (h *SchedulingHandler) BulkCreateScheduleInstances(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var instances []*scheduling.ScheduleInstance
	if err := json.NewDecoder(r.Body).Decode(&instances); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(instances) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "No instances provided")
		return
	}

	// Set company ID for all instances (from context)
	for _, instance := range instances {
		instance.CompanyID = companyID
	}

	err = h.schedulingService.BulkCreateScheduleInstances(ctx, instances, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":        "Schedule instances created successfully",
		"instance_count": len(instances),
	})
}

// Work Center Schedule Handlers
func (h *SchedulingHandler) GetWorkCenterSchedule(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	workCenterCode := chi.URLParam(r, "workCenterCode")

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}

	workCenter, err := h.schedulingQueryService.
		GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil || workCenter == nil {
		h.respondWithError(w, http.StatusBadRequest, "Work center not found")
		return
	}

	date, err := normalizeBusinessDateFromString(
		dateStr,
		workCenter.Timezone,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
		return
	}

	result, err := h.schedulingQueryService.
		GetWorkCenterSchedule(ctx, companyID, workCenterCode, date)

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetWorkCenterSchedulesByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr != "" {
		timezone := h.getCompanyDefaultTimezone(ctx, companyID)
		date, err = normalizeBusinessDateFromString(dateStr, timezone)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	} else {
		date = time.Now()
	}

	result, err := h.schedulingQueryService.GetWorkCenterSchedulesByCompany(ctx, companyID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Position Schedule Handlers
func (h *SchedulingHandler) GetPositionScheduleSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid position ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// Get position to determine timezone
	position, err := h.schedulingQueryService.GetPositionByID(ctx, positionID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Position not found")
		return
	}

	timezone := "UTC"
	if position.WorkCenterCode != nil {
		workCenter, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, position.CompanyID, *position.WorkCenterCode)
		if err == nil {
			timezone = workCenter.Timezone
		}
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

	result, err := h.schedulingQueryService.GetPositionScheduleSummary(ctx, positionID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) GetPositionSchedulesByCompany(w http.ResponseWriter, r *http.Request) {
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

	result, err := h.schedulingQueryService.GetPositionSchedulesByCompany(ctx, companyID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Health Check
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

// Helper response methods
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

// Add these methods to the SchedulingHandler struct in handler.go

func (h *SchedulingHandler) ProcessHolidayForDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

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

	err = h.schedulingService.ProcessHolidayForDate(ctx, companyID, date, actorType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Holiday processed successfully",
	})
}

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

func (h *SchedulingHandler) UpdateScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideIDStr := chi.URLParam(r, "overrideID")
	overrideID, err := uuid.Parse(overrideIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var update scheduling.ScheduleOverrideUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate override type
	if update.OverrideType != nil && *update.OverrideType != "" {
		validTypes := map[string]bool{
			"off": true, "force_work": true, "holiday_override": true,
		}
		if !validTypes[*update.OverrideType] {
			h.respondWithError(
				w,
				http.StatusBadRequest,
				"Invalid override_type. Must be one of: off, force_work, holiday_override",
			)
			return
		}
	}

	result, err := h.schedulingService.UpdateScheduleOverride(
		ctx, overrideID, update, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *SchedulingHandler) DeleteScheduleOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	overrideIDStr := chi.URLParam(r, "overrideID")
	overrideID, err := uuid.Parse(overrideIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid override ID")
		return
	}

	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	err = h.schedulingService.DeleteScheduleOverride(ctx, overrideID, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Schedule override deleted successfully",
	})
}

func (h *SchedulingHandler) GetScheduleInstancesByPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid position ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	// Get timezone from position or company
	position, err := h.schedulingQueryService.GetPositionByID(ctx, positionID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Position not found")
		return
	}

	timezone := "UTC"
	if position.WorkCenterCode != nil {
		workCenter, err := h.schedulingQueryService.GetWorkCenterByCode(ctx, position.CompanyID, *position.WorkCenterCode)
		if err == nil {
			timezone = workCenter.Timezone
		}
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

	result, err := h.schedulingQueryService.GetScheduleInstancesByPosition(ctx, positionID, startDate, endDate)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
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

	result, err := h.schedulingQueryService.GetUserCurrentScheduleAssignment(ctx, userID, date)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}
