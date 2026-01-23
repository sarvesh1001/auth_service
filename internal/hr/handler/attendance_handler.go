package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceHandler struct {
	attendanceService service.AttendanceService
	queryService      service.AttendanceQueryService
	logger            *zap.Logger
}

func NewAttendanceHandler(
	attendanceService service.AttendanceService,
	queryService service.AttendanceQueryService,
	logger *zap.Logger,
) *AttendanceHandler {
	return &AttendanceHandler{
		attendanceService: attendanceService,
		queryService:      queryService,
		logger:            logger,
	}
}

func (h *AttendanceHandler) CreateAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		UserID     uuid.UUID                `json:"user_id"`
		CompanyID  uuid.UUID                `json:"company_id"`
		EventType  string                   `json:"event_type"`
		EventTime  time.Time                `json:"event_time"`
		SourceType string                   `json:"source_type"`
		SourceID   *uuid.UUID               `json:"source_id"`
		DeviceID   *string                  `json:"device_id"`
		IPAddress  *string                  `json:"ip_address"`
		Metadata   attendance.EventMetadata `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	eventTime := req.EventTime
	if eventTime.Location() == time.Local {
		eventTime = eventTime.UTC()
	}

	event := &attendance.AttendanceEvent{
		CompanyID:  req.CompanyID,
		UserID:     req.UserID,
		EventType:  req.EventType,
		EventTime:  eventTime,
		SourceType: req.SourceType,
		SourceID:   req.SourceID,
		DeviceID:   req.DeviceID,
		IPAddress:  req.IPAddress,
		Metadata:   req.Metadata,
	}

	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
		ctx,
		event,
		actorType,
		actorID,
		nil,
	)

	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "not allowed") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdEvent,
	})
}

func (h *AttendanceHandler) CreateBulkAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		Events []*attendance.AttendanceEvent `json:"events" validate:"required,min=1"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Events) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "No events provided")
		return
	}

	if len(req.Events) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, "Cannot process more than 1000 events at once")
		return
	}

	err = h.attendanceService.CreateBulkAttendanceEvents(
		ctx, req.Events, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to create bulk attendance events",
			util.Int("event_count", len(req.Events)),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create bulk events")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Created %d attendance events", len(req.Events)),
	})
}

func (h *AttendanceHandler) GetAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	eventIDStr := chi.URLParam(r, "eventID")
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid event ID format")
		return
	}

	event, err := h.queryService.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		h.logger.Error("Failed to get attendance event",
			util.String("event_id", eventID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance event")
		return
	}

	if event == nil {
		h.respondWithError(w, http.StatusNotFound, "Attendance event not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

func (h *AttendanceHandler) GetAttendanceEventsByUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		endDate = time.Now().UTC()
		startDate = endDate.AddDate(0, 0, -30)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format")
			return
		}
	}

	endDate = endDate.Add(36 * time.Hour)

	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit <= 0 || limit > 1000 {
		limit = 100
	}

	events, err := h.queryService.GetAttendanceEventsByUser(
		ctx,
		userID,
		startDate,
		endDate,
		limit,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"events": events,
			"count":  len(events),
		},
	})
}

func (h *AttendanceHandler) GetAttendanceEventsByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		endDate = time.Now().UTC()
		startDate = endDate.AddDate(0, 0, -7)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format")
			return
		}
	}

	endDate = endDate.Add(36 * time.Hour)

	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	events, total, err := h.queryService.GetAttendanceEventsByCompany(
		ctx,
		companyID,
		startDate,
		endDate,
		page,
		pageSize,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"events": events,
			"total":  total,
		},
	})
}

func (h *AttendanceHandler) SearchAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	companyIDStr := query.Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var filters service.AttendanceSearchFilters
	filters.CompanyID = companyID

	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	filters.StartDate, err = time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_date")
		return
	}

	filters.EndDate, err = time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_date")
		return
	}
	filters.EndDate = filters.EndDate.Add(36 * time.Hour)

	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	events, total, err := h.queryService.SearchAttendanceEventsTyped(
		ctx,
		companyID,
		filters,
		page,
		pageSize,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"events": events,
			"total":  total,
		},
	})
}

func (h *AttendanceHandler) ProcessSAPAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SapEvent   service.SAPAttendanceEvent `json:"sap_event" validate:"required"`
		CompanyID  uuid.UUID                  `json:"company_id" validate:"required"`
		SourceType string                     `json:"source_type"`
		SourceID   *uuid.UUID                 `json:"source_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SourceType == "" {
		req.SourceType = "sap"
	}

	event, err := h.attendanceService.ProcessSAPAttendanceEvent(
		ctx, &req.SapEvent, req.CompanyID, req.SourceType, req.SourceID)
	if err != nil {
		h.logger.Error("Failed to process SAP attendance event",
			util.String("company_id", req.CompanyID.String()),
			util.String("employee_id", req.SapEvent.EmployeeID),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "not found") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

func (h *AttendanceHandler) SyncFactoryAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.FactoryAttendanceData
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr != "" {
		companyID, err := uuid.Parse(companyIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
			return
		}
		req.CompanyID = companyID
	}

	err := h.attendanceService.SyncFactoryAttendance(ctx, &req, req.CompanyID)
	if err != nil {
		h.logger.Error("Failed to sync factory attendance",
			util.String("company_id", req.CompanyID.String()),
			util.String("work_center", req.WorkCenterCode),
			util.Int("event_count", len(req.Events)),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to sync factory attendance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Synced %d factory attendance events", len(req.Events)),
	})
}

func (h *AttendanceHandler) CreateAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var policy attendance.AttendancePolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	createdPolicy, err := h.attendanceService.CreateAttendancePolicy(
		ctx, &policy, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to create attendance policy",
			util.String("company_id", policy.CompanyID.String()),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdPolicy,
	})
}

func (h *AttendanceHandler) GetAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	policy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance policy")
		return
	}

	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "Attendance policy not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}

func (h *AttendanceHandler) GetAttendancePoliciesByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	query := r.URL.Query()
	activeOnly := query.Get("active_only") == "true"

	policies, err := h.queryService.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.logger.Error("Failed to get attendance policies",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance policies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"policies": policies,
			"count":    len(policies),
		},
	})
}

func (h *AttendanceHandler) UpdateAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, _, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	existingPolicy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get existing policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get policy")
		return
	}

	if existingPolicy == nil {
		h.respondWithError(w, http.StatusNotFound, "Attendance policy not found")
		return
	}

	var updates struct {
		DepartmentID *uuid.UUID              `json:"department_id"`
		PolicyCode   *string                 `json:"policy_code"`
		PolicyType   *string                 `json:"policy_type"`
		Rules        *attendance.PolicyRules `json:"rules"`
		IsActive     *bool                   `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if updates.DepartmentID != nil {
		existingPolicy.DepartmentID = updates.DepartmentID
	}
	if updates.PolicyCode != nil {
		existingPolicy.PolicyCode = *updates.PolicyCode
	}
	if updates.PolicyType != nil {
		existingPolicy.PolicyType = *updates.PolicyType
	}
	if updates.Rules != nil {
		existingPolicy.Rules = *updates.Rules
	}
	if updates.IsActive != nil {
		existingPolicy.IsActive = *updates.IsActive
	}

	err = h.attendanceService.UpdateAttendancePolicy(ctx, existingPolicy)
	if err != nil {
		h.logger.Error("Failed to update attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	updatedPolicy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get updated policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    updatedPolicy,
	})
}

func (h *AttendanceHandler) DeleteAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	err = h.attendanceService.DeleteAttendancePolicy(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to delete attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance policy deleted successfully",
	})
}

func (h *AttendanceHandler) AssignUserAttendancePolicy(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		UserID        uuid.UUID  `json:"user_id" validate:"required"`
		PolicyID      uuid.UUID  `json:"policy_id" validate:"required"`
		EffectiveFrom time.Time  `json:"effective_from"`
		EffectiveTo   *time.Time `json:"effective_to"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	if req.PolicyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "policy_id is required")
		return
	}

	if req.EffectiveFrom.IsZero() {
		req.EffectiveFrom = time.Now().UTC()
	}

	userPolicy := &attendance.UserAttendancePolicy{
		UserID:        req.UserID,
		PolicyID:      req.PolicyID,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		AssignedBy:    &actorID,
	}

	err = h.attendanceService.AssignUserAttendancePolicy(
		ctx,
		userPolicy,
		actorType,
		actorID,
		nil,
	)
	if err != nil {
		h.logger.Error(
			"Failed to assign user attendance policy",
			util.String("user_id", req.UserID.String()),
			util.String("policy_id", req.PolicyID.String()),
			util.ErrorField(err),
		)
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "not active") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance policy assigned to user successfully",
	})
}

func (h *AttendanceHandler) GetCompanyAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	rules, err := h.attendanceService.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get company attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceHandler) UpdateCompanyAttendanceRules(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	var rules attendance.CompanyAttendanceRules
	rules.CompanyID = companyID
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.attendanceService.UpdateCompanyAttendanceRules(
		ctx,
		&rules,
		actorID,
	); err != nil {
		h.logger.Error(
			"Failed to update company attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Company attendance rules updated successfully",
	})
}

func (h *AttendanceHandler) GetDepartmentAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
		return
	}

	rules, err := h.attendanceService.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
	if err != nil {
		h.logger.Error("Failed to get department attendance rules",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get department attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceHandler) UpdateDepartmentAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
		return
	}

	var rules attendance.DepartmentAttendanceRules
	rules.CompanyID = companyID
	rules.DepartmentID = departmentID
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.attendanceService.UpsertDepartmentAttendanceRules(ctx, &rules)
	if err != nil {
		h.logger.Error("Failed to update department attendance rules",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update department attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Department attendance rules updated successfully",
	})
}

func (h *AttendanceHandler) GetUserAttendanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	profile, err := h.attendanceService.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get user attendance profile",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get user attendance profile")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profile,
	})
}

func (h *AttendanceHandler) UpdateUserAttendanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	var profile attendance.UserAttendanceProfile
	profile.UserID = userID
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromContext(ctx)
	if err != nil {
		if profile.CompanyID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, "Company ID is required")
			return
		}
	} else {
		profile.CompanyID = companyID
	}

	err = h.attendanceService.UpsertUserAttendanceProfile(ctx, &profile)
	if err != nil {
		h.logger.Error("Failed to update user attendance profile",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update user attendance profile")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User attendance profile updated successfully",
	})
}

func (h *AttendanceHandler) ResolveAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	companyIDStr := query.Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	var userID uuid.UUID
	if userIDStr := query.Get("user_id"); userIDStr != "" {
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
			return
		}
	}

	var departmentID uuid.UUID
	if deptIDStr := query.Get("department_id"); deptIDStr != "" {
		departmentID, err = uuid.Parse(deptIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
			return
		}
	}

	rules, err := h.attendanceService.ResolveAttendanceRules(ctx, userID, companyID, departmentID)
	if err != nil {
		h.logger.Error("Failed to resolve attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to resolve attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceHandler) GetAttendanceDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	dateStr := query.Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now().UTC()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
			return
		}
	}

	summary, err := h.queryService.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		h.logger.Error("Failed to get attendance daily summary",
			util.String("user_id", userID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

func (h *AttendanceHandler) GetAttendanceDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		now := time.Now().UTC()
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate = startDate.AddDate(0, 1, -1)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	summaries, err := h.queryService.GetAttendanceDailySummariesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get attendance daily summaries",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries": summaries,
			"count":     len(summaries),
			"period": map[string]interface{}{
				"start_date": startDate.Format("2006-01-02"),
				"end_date":   endDate.Format("2006-01-02"),
			},
		},
	})
}

func (h *AttendanceHandler) GenerateDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		CompanyID uuid.UUID `json:"company_id" validate:"required"`
		UserID    uuid.UUID `json:"user_id" validate:"required"`
		Date      time.Time `json:"date" validate:"required"`
		Timezone  string    `json:"timezone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	summary, err := h.attendanceService.GenerateDailySummary(ctx, req.CompanyID, req.UserID, req.Date, req.Timezone)
	if err != nil {
		h.logger.Error("Failed to generate daily summary",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.UserID.String()),
			util.String("date", req.Date.Format("2006-01-02")),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to generate daily summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

func (h *AttendanceHandler) GenerateBulkDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		CompanyID uuid.UUID `json:"company_id" validate:"required"`
		Timezone  string    `json:"timezone"`
		StartDate time.Time `json:"start_date" validate:"required"`
		EndDate   time.Time `json:"end_date" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	summaries, err := h.attendanceService.GenerateBulkDailySummaries(ctx, req.CompanyID, req.Timezone, req.StartDate, req.EndDate)
	if err != nil {
		h.logger.Error("Failed to generate bulk daily summaries",
			util.String("company_id", req.CompanyID.String()),
			util.Time("start_date", req.StartDate),
			util.Time("end_date", req.EndDate),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to generate bulk daily summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries": summaries,
			"count":     len(summaries),
			"period": map[string]interface{}{
				"start_date": req.StartDate.Format("2006-01-02"),
				"end_date":   req.EndDate.Format("2006-01-02"),
			},
		},
	})
}

func (h *AttendanceHandler) AssignRFIDToEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		CompanyID uuid.UUID `json:"company_id" validate:"required"`
		UserID    uuid.UUID `json:"user_id" validate:"required"`
		RFIDTag   string    `json:"rfid_tag" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.attendanceService.AssignRFIDToEmployee(ctx, req.CompanyID, req.UserID, req.RFIDTag, actorID)
	if err != nil {
		h.logger.Error("Failed to assign RFID to employee",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.UserID.String()),
			util.String("rfid_tag", req.RFIDTag),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already assigned") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "RFID assigned to employee successfully",
	})
}

func (h *AttendanceHandler) GetEmployeeByRFID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rfidTag := chi.URLParam(r, "rfidTag")
	if rfidTag == "" {
		h.respondWithError(w, http.StatusBadRequest, "RFID tag is required")
		return
	}

	query := r.URL.Query()
	companyIDStr := query.Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	mapping, err := h.attendanceService.GetEmployeeByRFID(ctx, rfidTag, companyID)
	if err != nil {
		h.logger.Error("Failed to get employee by RFID",
			util.String("rfid_tag", rfidTag),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get employee by RFID")
		return
	}

	if mapping == nil {
		h.respondWithError(w, http.StatusNotFound, "Employee not found for RFID tag")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
	})
}

func (h *AttendanceHandler) UnassignRFID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	rfidIDStr := chi.URLParam(r, "rfidID")
	rfidID, err := uuid.Parse(rfidIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid RFID ID format")
		return
	}

	err = h.attendanceService.UnassignRFID(ctx, rfidID, actorID)
	if err != nil {
		h.logger.Error("Failed to unassign RFID",
			util.String("rfid_id", rfidID.String()),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "RFID unassigned successfully",
	})
}

func (h *AttendanceHandler) GetAttendanceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		now := time.Now().UTC()
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate = startDate.AddDate(0, 1, -1)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	stats, err := h.attendanceService.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get attendance stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func (h *AttendanceHandler) GetUserAttendanceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		now := time.Now().UTC()
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate = startDate.AddDate(0, 1, -1)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	stats, err := h.attendanceService.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get user attendance stats",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get user attendance stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func (h *AttendanceHandler) GetAttendanceEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == "true"

	eventTypes, err := h.queryService.ListAttendanceEventTypes(ctx, activeOnly)
	if err != nil {
		h.logger.Error("Failed to get attendance event types",
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance event types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"event_types": eventTypes,
			"count":       len(eventTypes),
		},
	})
}

func (h *AttendanceHandler) GetAttendanceSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sourceTypes, err := h.queryService.ListAttendanceSourceTypes(ctx)
	if err != nil {
		h.logger.Error("Failed to get attendance source types",
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance source types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"source_types": sourceTypes,
			"count":        len(sourceTypes),
		},
	})
}

func (h *AttendanceHandler) GenerateAttendanceReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	companyIDStr := query.Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	reportType := strings.ToLower(query.Get("type"))
	if reportType == "" {
		reportType = "csv"
	}
	if reportType != "csv" && reportType != "json" {
		h.respondWithError(w, http.StatusBadRequest, "Unsupported report type. Use 'csv' or 'json'")
		return
	}

	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
		return
	}
	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
		return
	}

	data, contentType, err := h.queryService.GenerateAttendanceReport(ctx, companyID, reportType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to generate attendance report",
			util.String("company_id", companyID.String()),
			util.String("report_type", reportType),
			util.ErrorField(err))
		if strings.Contains(err.Error(), "date range cannot exceed") {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "Failed to generate attendance report")
		}
		return
	}

	filename := fmt.Sprintf("attendance-report_%s_%s_%s.%s",
		companyID.String(),
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
		reportType,
	)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if _, err := w.Write(data); err != nil {
		h.logger.Error("Failed to write report data",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
	}
}

func (h *AttendanceHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.attendanceService.HealthCheck(ctx)
	if err != nil {
		h.logger.Error("Attendance health check failed", util.ErrorField(err))
		h.respondWithJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"success": false,
			"status":  "unhealthy",
			"service": "attendance",
			"error":   err.Error(),
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"status":  "healthy",
		"service": "attendance",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *AttendanceHandler) CheckDateAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	dateStr := query.Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date parameter is required")
		return
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
		return
	}

	result, err := h.attendanceService.CheckDateAvailability(ctx, userID, date)
	if err != nil {
		h.logger.Error("Failed to check date availability",
			util.String("user_id", userID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to check date availability")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *AttendanceHandler) GetAttendanceDailySummariesByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	query := r.URL.Query()
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		now := time.Now().UTC()
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate = startDate.AddDate(0, 1, -1)
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	summaries, total, err := h.attendanceService.GetAttendanceDailySummariesByCompany(
		ctx, companyID, startDate, endDate, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get attendance daily summaries by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get attendance daily summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"summaries": summaries,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
			"period": map[string]interface{}{
				"start_date": startDate.Format("2006-01-02"),
				"end_date":   endDate.Format("2006-01-02"),
			},
		},
	})
}

func (h *AttendanceHandler) CompleteSAPAttendanceFlow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SapEvent  service.SAPAttendanceEvent `json:"sap_event" validate:"required"`
		CompanyID uuid.UUID                  `json:"company_id" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err := h.attendanceService.CompleteSAPAttendanceFlow(ctx, &req.SapEvent, req.CompanyID)
	if err != nil {
		h.logger.Error("Failed to complete SAP attendance flow",
			util.String("company_id", req.CompanyID.String()),
			util.String("employee_id", req.SapEvent.EmployeeID),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "not found") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "SAP attendance flow completed successfully",
	})
}

func (h *AttendanceHandler) GetUserCurrentAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	query := r.URL.Query()
	dateStr := query.Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now().UTC()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
			return
		}
	}

	policy, err := h.queryService.GetUserCurrentAttendancePolicy(ctx, userID, date)
	if err != nil {
		h.logger.Error("Failed to get user current attendance policy",
			util.String("user_id", userID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get user attendance policy")
		return
	}

	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "No active attendance policy found for user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}

func (h *AttendanceHandler) StreamAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	companyIDStr := query.Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	format := strings.ToLower(query.Get("format"))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		h.respondWithError(w, http.StatusBadRequest, "Unsupported format. Use 'csv' or 'jsonl'")
		return
	}

	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
		return
	}
	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")

	err = h.queryService.StreamAttendanceEvents(ctx, companyID, startDate, endDate, w, format)
	if err != nil {
		h.logger.Error("Failed to stream attendance events",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to stream attendance events")
		return
	}
}

func (h *AttendanceHandler) ValidateEventAgainstRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Event *attendance.AttendanceEvent         `json:"event" validate:"required"`
		Rules *attendance.ResolvedAttendanceRules `json:"rules" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err := h.attendanceService.ValidateEventAgainstRules(ctx, req.Event, req.Rules)
	if err != nil {
		h.logger.Error("Event validation against rules failed",
			util.String("user_id", req.Event.UserID.String()),
			util.String("event_type", req.Event.EventType),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Event is valid against the rules",
	})
}

func (h *AttendanceHandler) CorrectAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Company context required")
		return
	}

	var req struct {
		UserID    uuid.UUID                `json:"user_id" validate:"required"`
		EventType string                   `json:"event_type" validate:"required"`
		EventTime time.Time                `json:"event_time" validate:"required"`
		Reason    string                   `json:"reason" validate:"required"`
		Metadata  attendance.EventMetadata `json:"metadata,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "Reason is required for correction")
		return
	}

	if req.EventTime.After(time.Now().UTC()) {
		h.respondWithError(w, http.StatusBadRequest, "Cannot correct future events")
		return
	}

	if time.Since(req.EventTime) > 30*24*time.Hour {
		h.respondWithError(w, http.StatusBadRequest, "Cannot correct events older than 30 days")
		return
	}

	now := time.Now().UTC()
	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            req.UserID,
		EventType:         req.EventType,
		EventTime:         req.EventTime,
		SourceType:        "correction",
		Metadata:          req.Metadata,
		CreatedAt:         now,
		CreatedBy:         &actorID,
	}

	if event.Metadata.Reason == nil {
		event.Metadata.Reason = &req.Reason
	}

	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
		ctx,
		event,
		actorType,
		actorID,
		map[string]interface{}{
			"correction":   true,
			"reason":       req.Reason,
			"corrected_by": actorID.String(),
			"corrected_at": now,
		},
	)

	if err != nil {
		h.logger.Error(
			"Failed to create correction attendance event",
			util.String("user_id", req.UserID.String()),
			util.String("event_type", req.EventType),
			util.String("reason", req.Reason),
			util.ErrorField(err),
		)
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "duplicate") {
			status = http.StatusConflict
			h.respondWithError(w, status, "A correction for this event already exists")
			return
		} else if strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "not allowed") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdEvent,
		"correction_info": map[string]interface{}{
			"reason":       req.Reason,
			"corrected_by": actorID.String(),
			"corrected_at": now,
			"is_duplicate": createdEvent.AttendanceEventID != event.AttendanceEventID,
		},
	})
}

func (h *AttendanceHandler) PunchAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Company context required")
		return
	}

	var req struct {
		EventType  string                   `json:"event_type" validate:"required"`
		SourceType string                   `json:"source_type" validate:"required"`
		Metadata   attendance.EventMetadata `json:"metadata,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	now := time.Now().UTC()
	clientIP := h.getClientIP(r)
	deviceID := r.Header.Get("X-Device-ID")
	userID := actorID

	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            userID,
		EventType:         req.EventType,
		EventTime:         now,
		SourceType:        req.SourceType,
		DeviceID:          &deviceID,
		IPAddress:         &clientIP,
		Metadata:          req.Metadata,
		CreatedAt:         now,
		CreatedBy:         &actorID,
	}

	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
		ctx, event, actorType, actorID, map[string]interface{}{
			"auto_derived": true,
			"source":       "real_time_punch",
			"device_id":    deviceID,
			"ip_address":   clientIP,
		})

	if err != nil {
		h.logger.Error("Failed to create punch attendance event",
			util.String("user_id", userID.String()),
			util.String("event_type", req.EventType),
			util.ErrorField(err))
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "duplicate") {
			status = http.StatusConflict
			h.respondWithError(w, status, "A similar punch was recently recorded")
			return
		} else if strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "not allowed") {
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    createdEvent,
		"auto_derived": map[string]interface{}{
			"event_time": now,
			"ip_address": clientIP,
			"device_id":  deviceID,
		},
	}

	if createdEvent.AttendanceEventID != event.AttendanceEventID {
		response["warning"] = "Duplicate punch prevented - returned existing record"
		response["is_duplicate"] = true
		response["original_event_id"] = createdEvent.AttendanceEventID
	}

	h.respondWithJSON(w, http.StatusCreated, response)
}

func (h *AttendanceHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

func (h *AttendanceHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"message": message,
		"code":    status,
	})
}

func (h *AttendanceHandler) getActorFromContext(
	ctx context.Context,
) (string, uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return "", uuid.Nil, fmt.Errorf("user not authenticated")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("invalid user_id in context")
	}
	userType, ok := ctx.Value("user_type").(string)
	if !ok || userType == "" {
		userType = "user"
	}
	return userType, userID, nil
}

func (h *AttendanceHandler) getCompanyIDFromContext(ctx context.Context) (uuid.UUID, error) {
	v := ctx.Value("company_id")
	if v == nil {
		return uuid.Nil, fmt.Errorf("company ID not found in context")
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id, nil
	case string:
		if id == "" {
			return uuid.Nil, fmt.Errorf("company ID empty in context")
		}
		return uuid.Parse(id)
	default:
		return uuid.Nil, fmt.Errorf("invalid company ID type in context")
	}
}

func (h *AttendanceHandler) getPointerValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (h *AttendanceHandler) getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Helper function for admin access (you need to implement this based on your auth system)
func RequireAdmin(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, fmt.Errorf("user not authenticated")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user_id in context")
	}

	// Check if user has admin role (implement based on your auth system)
	userRole, ok := ctx.Value("user_role").(string)
	if !ok || userRole != "admin" {
		return uuid.Nil, fmt.Errorf("admin access required")
	}

	return userID, nil
}
