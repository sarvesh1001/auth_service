// internal/hr/handler/attendance/attendance_handler.go
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

// AttendanceHandler handles HTTP requests for attendance operations
type AttendanceHandler struct {
	attendanceService service.AttendanceService
	queryService      service.AttendanceQueryService
	logger            *zap.Logger
}

// NewAttendanceHandler creates a new attendance handler
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

// ============================================================================
// ATTENDANCE EVENTS
// ============================================================================

// CreateAttendanceEvent handles POST /api/attendance/events
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

	// ✅ NORMALIZE EVENT TIME
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

// CreateBulkAttendanceEvents handles POST /api/attendance/events/bulk
func (h *AttendanceHandler) CreateBulkAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
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

	// Limit bulk operations
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

// GetAttendanceEvent handles GET /api/attendance/events/{eventID}
func (h *AttendanceHandler) GetAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse event ID from URL
	eventIDStr := chi.URLParam(r, "eventID")
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid event ID format")
		return
	}

	// Get attendance event
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

// GetAttendanceEventsByUser handles GET /api/attendance/users/{userID}/events
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

	// ✅ EXTEND WINDOW FOR NIGHT SHIFTS
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

// GetAttendanceEventsByCompany handles GET /api/attendance/companies/{companyID}/events
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

	// ✅ EXTEND WINDOW
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

	// ✅ EXTEND WINDOW
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

// ============================================================================
// SAP INTEGRATION
// ============================================================================

// ProcessSAPAttendanceEvent handles POST /api/attendance/sap/events
func (h *AttendanceHandler) ProcessSAPAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
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

	// Process SAP event
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

// SyncFactoryAttendance handles POST /api/attendance/factory/sync
func (h *AttendanceHandler) SyncFactoryAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req service.FactoryAttendanceData

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate company ID from URL if provided
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr != "" {
		companyID, err := uuid.Parse(companyIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
			return
		}
		req.CompanyID = companyID
	}

	// Sync factory attendance
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

// ============================================================================
// ATTENDANCE POLICIES
// ============================================================================

// CreateAttendancePolicy handles POST /api/attendance/policies
func (h *AttendanceHandler) CreateAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var policy attendance.AttendancePolicy

	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Create attendance policy
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

// GetAttendancePolicy handles GET /api/attendance/policies/{policyID}
func (h *AttendanceHandler) GetAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse policy ID from URL
	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	// Get attendance policy
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

// GetAttendancePoliciesByCompany handles GET /api/attendance/companies/{companyID}/policies
func (h *AttendanceHandler) GetAttendancePoliciesByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == "true"

	// Get attendance policies
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

// UpdateAttendancePolicy handles PUT /api/attendance/policies/{policyID}
func (h *AttendanceHandler) UpdateAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	_, _, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse policy ID from URL
	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	// Get existing policy
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

	// Parse request body
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

	// Apply updates
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

	// Update policy
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

	// Get updated policy
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

// DeleteAttendancePolicy handles DELETE /api/attendance/policies/{policyID}
func (h *AttendanceHandler) DeleteAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse policy ID from URL
	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID format")
		return
	}

	// Delete attendance policy
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

// AssignUserAttendancePolicy handles POST /api/attendance/users/{userID}/policies
func (h *AttendanceHandler) AssignUserAttendancePolicy(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ------------------------------------------------------------
	// Get actor information from context
	// ------------------------------------------------------------
	actorType, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// ------------------------------------------------------------
	// Parse request body
	// ------------------------------------------------------------
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

	// ------------------------------------------------------------
	// Basic validation
	// ------------------------------------------------------------
	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	if req.PolicyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "policy_id is required")
		return
	}

	// ------------------------------------------------------------
	// Default effective_from
	// ------------------------------------------------------------
	if req.EffectiveFrom.IsZero() {
		req.EffectiveFrom = time.Now().UTC()
	}

	// ------------------------------------------------------------
	// Build domain model
	// ------------------------------------------------------------
	userPolicy := &attendance.UserAttendancePolicy{
		UserID:        req.UserID,
		PolicyID:      req.PolicyID,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		AssignedBy:    &actorID,
	}

	// ------------------------------------------------------------
	// Assign policy
	// ------------------------------------------------------------
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

	// ------------------------------------------------------------
	// Success response
	// ------------------------------------------------------------
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance policy assigned to user successfully",
	})
}

// ============================================================================
// ATTENDANCE RULES
// ============================================================================

// GetCompanyAttendanceRules handles GET /api/attendance/companies/{companyID}/rules
func (h *AttendanceHandler) GetCompanyAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Get company attendance rules
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

// UpdateCompanyAttendanceRules handles PUT /api/attendance/companies/{companyID}/rules
func (h *AttendanceHandler) UpdateCompanyAttendanceRules(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ✅ Admin-only guard
	adminID, err := RequireAdmin(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Admin access required")
		return
	}

	// Parse company ID
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse request body
	var rules attendance.CompanyAttendanceRules
	rules.CompanyID = companyID

	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update rules
	if err := h.attendanceService.UpdateCompanyAttendanceRules(
		ctx,
		&rules,
		adminID, // ✅ explicit admin actor
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

// GetDepartmentAttendanceRules handles GET /api/attendance/departments/{departmentID}/rules
func (h *AttendanceHandler) GetDepartmentAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse department ID from URL
	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
		return
	}

	// Get department attendance rules
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

// UpdateDepartmentAttendanceRules handles PUT /api/attendance/departments/{departmentID}/rules
func (h *AttendanceHandler) UpdateDepartmentAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse department ID from URL
	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
		return
	}

	// Parse request body
	var rules attendance.DepartmentAttendanceRules
	rules.CompanyID = companyID
	rules.DepartmentID = departmentID

	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update department attendance rules
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

// GetUserAttendanceProfile handles GET /api/attendance/users/{userID}/profile
func (h *AttendanceHandler) GetUserAttendanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Get user attendance profile
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

// UpdateUserAttendanceProfile handles PUT /api/attendance/users/{userID}/profile
func (h *AttendanceHandler) UpdateUserAttendanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Parse request body
	var profile attendance.UserAttendanceProfile
	profile.UserID = userID

	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get company ID from context or request
	companyID, err := h.getCompanyIDFromContext(ctx)
	if err != nil {
		// Try to get from request body
		if profile.CompanyID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, "Company ID is required")
			return
		}
	} else {
		profile.CompanyID = companyID
	}

	// Update user attendance profile
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

// ResolveAttendanceRules handles GET /api/attendance/rules/resolve
func (h *AttendanceHandler) ResolveAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()

	// Parse company ID
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

	// Parse user ID (optional)
	var userID uuid.UUID
	if userIDStr := query.Get("user_id"); userIDStr != "" {
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
			return
		}
	}

	// Parse department ID (optional)
	var departmentID uuid.UUID
	if deptIDStr := query.Get("department_id"); deptIDStr != "" {
		departmentID, err = uuid.Parse(deptIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid department ID format")
			return
		}
	}

	// Resolve attendance rules
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

// ============================================================================
// DAILY SUMMARIES
// ============================================================================

// GetAttendanceDailySummary handles GET /api/attendance/users/{userID}/summary
func (h *AttendanceHandler) GetAttendanceDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Parse date from query parameters
	query := r.URL.Query()
	dateStr := query.Get("date")

	var date time.Time
	if dateStr == "" {
		// Default to today
		date = time.Now().UTC()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
			return
		}
	}

	// Get attendance daily summary
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

// GetAttendanceDailySummaries handles GET /api/attendance/users/{userID}/summaries
func (h *AttendanceHandler) GetAttendanceDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Parse dates
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		// Default to current month
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

	// Get attendance daily summaries
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

// GenerateDailySummary handles POST /api/attendance/summaries/generate
func (h *AttendanceHandler) GenerateDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
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

	// Generate daily summary
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

// GenerateBulkDailySummaries handles POST /api/attendance/summaries/bulk-generate
func (h *AttendanceHandler) GenerateBulkDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
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

	// Generate bulk daily summaries
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

// ============================================================================
// RFID MANAGEMENT
// ============================================================================

// AssignRFIDToEmployee handles POST /api/attendance/rfid/assign
func (h *AttendanceHandler) AssignRFIDToEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var req struct {
		CompanyID uuid.UUID `json:"company_id" validate:"required"`
		UserID    uuid.UUID `json:"user_id" validate:"required"`
		RFIDTag   string    `json:"rfid_tag" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Assign RFID to employee
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

// GetEmployeeByRFID handles GET /api/attendance/rfid/{rfidTag}
func (h *AttendanceHandler) GetEmployeeByRFID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse RFID tag from URL
	rfidTag := chi.URLParam(r, "rfidTag")
	if rfidTag == "" {
		h.respondWithError(w, http.StatusBadRequest, "RFID tag is required")
		return
	}

	// Parse company ID from query parameters
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

	// Get employee by RFID
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

// UnassignRFID handles POST /api/attendance/rfid/{rfidID}/unassign
func (h *AttendanceHandler) UnassignRFID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse RFID ID from URL
	rfidIDStr := chi.URLParam(r, "rfidID")
	rfidID, err := uuid.Parse(rfidIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid RFID ID format")
		return
	}

	// Unassign RFID
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

// ============================================================================
// WORK CENTER MANAGEMENT
// ============================================================================

// MapWorkCenterToShift handles POST /api/attendance/work-centers/map
func (h *AttendanceHandler) MapWorkCenterToShift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor information from context
	_, actorID, err := h.getActorFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var req struct {
		CompanyID      uuid.UUID  `json:"company_id" validate:"required"`
		WorkCenterCode string     `json:"work_center_code" validate:"required"`
		ShiftID        uuid.UUID  `json:"shift_id" validate:"required"`
		EffectiveFrom  time.Time  `json:"effective_from"`
		EffectiveTo    *time.Time `json:"effective_to"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Map work center to shift
	err = h.attendanceService.MapWorkCenterToShift(
		ctx, req.CompanyID, req.WorkCenterCode, req.ShiftID, req.EffectiveFrom, req.EffectiveTo, actorID)
	if err != nil {
		h.logger.Error("Failed to map work center to shift",
			util.String("company_id", req.CompanyID.String()),
			util.String("work_center_code", req.WorkCenterCode),
			util.String("shift_id", req.ShiftID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to map work center to shift")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Work center mapped to shift successfully",
	})
}

// GetShiftForWorkCenter handles GET /api/attendance/work-centers/{workCenterCode}/shift
func (h *AttendanceHandler) GetShiftForWorkCenter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse work center code from URL
	workCenterCode := chi.URLParam(r, "workCenterCode")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}

	// Parse company ID from query parameters
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

	// Get shift for work center
	mapping, err := h.attendanceService.GetShiftForWorkCenter(ctx, workCenterCode, companyID)
	if err != nil {
		h.logger.Error("Failed to get shift for work center",
			util.String("work_center_code", workCenterCode),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get shift for work center")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
	})
}

// ============================================================================
// ATTENDANCE ANALYTICS
// ============================================================================

// GetAttendanceStats handles GET /api/attendance/companies/{companyID}/stats
func (h *AttendanceHandler) GetAttendanceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Parse dates
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		// Default to current month
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

	// Get attendance stats
	stats, err := h.queryService.GetAttendanceSummaryStats(ctx, companyID, startDate, endDate)
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

// GetUserAttendanceStats handles GET /api/attendance/users/{userID}/stats
func (h *AttendanceHandler) GetUserAttendanceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Parse dates
	startDateStr := query.Get("start_date")
	endDateStr := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		// Default to current month
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

	// Get user attendance stats
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

// ============================================================================
// EVENT & SOURCE TYPES
// ============================================================================

// GetAttendanceEventTypes handles GET /api/attendance/event-types
func (h *AttendanceHandler) GetAttendanceEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == "true"

	// Get attendance event types
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

// GetAttendanceSourceTypes handles GET /api/attendance/source-types
func (h *AttendanceHandler) GetAttendanceSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get attendance source types
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

// ============================================================================
// SAP BUSINESS RULES
// ============================================================================

// ============================================================================
// REPORTS
// ============================================================================

// GenerateAttendanceReport handles GET /api/attendance/reports
func (h *AttendanceHandler) GenerateAttendanceReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()

	// Parse company ID
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

	// Parse report type
	reportType := strings.ToLower(query.Get("type"))
	if reportType == "" {
		reportType = "csv"
	}

	if reportType != "csv" && reportType != "json" {
		h.respondWithError(w, http.StatusBadRequest, "Unsupported report type. Use 'csv' or 'json'")
		return
	}

	// Parse dates
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

	// Generate attendance report
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

	// Generate filename
	filename := fmt.Sprintf("attendance-report_%s_%s_%s.%s",
		companyID.String(),
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
		reportType,
	)

	// Set response headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write data
	if _, err := w.Write(data); err != nil {
		h.logger.Error("Failed to write report data",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
	}
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

// HealthCheck handles GET /api/attendance/health
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

// ============================================================================
// HELPER METHODS
// ============================================================================

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

// func (h *AttendanceHandler) PunchAttendance(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	// Get user and company from context (set by middleware)
// 	actorType, actorID, err := h.getActorFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
// 		return
// 	}

// 	companyID, err := h.getCompanyIDFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Company context required")
// 		return
// 	}

// 	var req struct {
// 		EventType  string                   `json:"event_type" validate:"required"`
// 		SourceType string                   `json:"source_type" validate:"required"`
// 		Metadata   attendance.EventMetadata `json:"metadata,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
// 		return
// 	}

// 	// Auto-derive all data - client cannot send these
// 	now := time.Now().UTC()
// 	clientIP := h.getClientIP(r)
// 	deviceID := r.Header.Get("X-Device-ID")
// 	userID := actorID // User punches for themselves

// 	event := &attendance.AttendanceEvent{
// 		AttendanceEventID: uuid.New(),
// 		CompanyID:         companyID,
// 		UserID:            userID,
// 		EventType:         req.EventType,
// 		EventTime:         now, // Server time, not client time
// 		SourceType:        req.SourceType,
// 		DeviceID:          &deviceID,
// 		IPAddress:         &clientIP,
// 		Metadata:          req.Metadata,
// 		CreatedAt:         now,
// 		CreatedBy:         &actorID,
// 	}

// 	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
// 		ctx, event, actorType, actorID, map[string]interface{}{
// 			"auto_derived": true,
// 			"source":       "real_time_punch",
// 		})

// 	if err != nil {
// 		h.logger.Error("Failed to create punch attendance event",
// 			util.String("user_id", userID.String()),
// 			util.String("event_type", req.EventType),
// 			util.ErrorField(err))

// 		status := http.StatusInternalServerError
// 		if strings.Contains(err.Error(), "invalid") ||
// 			strings.Contains(err.Error(), "required") ||
// 			strings.Contains(err.Error(), "not allowed") {
// 			status = http.StatusBadRequest
// 		}
// 		h.respondWithError(w, status, err.Error())
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
// 		"success": true,
// 		"data":    createdEvent,
// 		"auto_derived": map[string]interface{}{
// 			"event_time": now,
// 			"ip_address": clientIP,
// 			"device_id":  deviceID,
// 		},
// 	})
// }

// func (h *AttendanceHandler) CorrectAttendance(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	// Get actor info
// 	actorType, actorID, err := h.getActorFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
// 		return
// 	}

// 	companyID, err := h.getCompanyIDFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Company context required")
// 		return
// 	}

// 	var req struct {
// 		UserID     uuid.UUID                `json:"user_id" validate:"required"`
// 		EventType  string                   `json:"event_type" validate:"required"`
// 		EventTime  time.Time                `json:"event_time" validate:"required"`
// 		SourceType string                   `json:"source_type"`
// 		Reason     string                   `json:"reason" validate:"required"`
// 		DeviceID   *string                  `json:"device_id,omitempty"`
// 		IPAddress  *string                  `json:"ip_address,omitempty"`
// 		Metadata   attendance.EventMetadata `json:"metadata,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
// 		return
// 	}

// 	// Validate required fields
// 	if req.Reason == "" {
// 		h.respondWithError(w, http.StatusBadRequest, "Reason is required for correction")
// 		return
// 	}

// 	if req.EventTime.After(time.Now().UTC()) {
// 		h.respondWithError(w, http.StatusBadRequest, "Cannot correct future events")
// 		return
// 	}

// 	// Use provided source type or default
// 	sourceType := req.SourceType
// 	if sourceType == "" {
// 		sourceType = "correction"
// 	}

// 	now := time.Now().UTC()
// 	event := &attendance.AttendanceEvent{
// 		AttendanceEventID: uuid.New(),
// 		CompanyID:         companyID,
// 		UserID:            req.UserID,
// 		EventType:         req.EventType,
// 		EventTime:         req.EventTime,
// 		SourceType:        sourceType,
// 		DeviceID:          req.DeviceID,
// 		IPAddress:         req.IPAddress,
// 		Metadata:          req.Metadata,
// 		CreatedAt:         now,
// 		CreatedBy:         &actorID,
// 	}

// 	// Add reason to metadata if not already present
// 	if event.Metadata.Reason == nil {
// 		event.Metadata.Reason = &req.Reason
// 	}

// 	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
// 		ctx, event, actorType, actorID, map[string]interface{}{
// 			"correction":   true,
// 			"reason":       req.Reason,
// 			"corrected_by": actorID.String(),
// 			"corrected_at": now,
// 		})

// 	if err != nil {
// 		h.logger.Error("Failed to create correction attendance event",
// 			util.String("user_id", req.UserID.String()),
// 			util.String("event_type", req.EventType),
// 			util.String("reason", req.Reason),
// 			util.ErrorField(err))

// 		status := http.StatusInternalServerError
// 		if strings.Contains(err.Error(), "invalid") ||
// 			strings.Contains(err.Error(), "required") ||
// 			strings.Contains(err.Error(), "not allowed") {
// 			status = http.StatusBadRequest
// 		}
// 		h.respondWithError(w, status, err.Error())
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
// 		"success": true,
// 		"data":    createdEvent,
// 		"correction_info": map[string]interface{}{
// 			"reason":       req.Reason,
// 			"corrected_by": actorID.String(),
// 			"corrected_at": now,
// 		},
// 	})
// }

// ====================================
// HELPER FUNCTIONS
// ====================================

// getClientIP extracts client IP address from request
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

// func (h *AttendanceHandler) CorrectAttendance(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	actorType, actorID, err := h.getActorFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
// 		return
// 	}

// 	companyID, err := h.getCompanyIDFromContext(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Company context required")
// 		return
// 	}

// 	var req struct {
// 		UserID    uuid.UUID                `json:"user_id" validate:"required"`
// 		EventType string                   `json:"event_type" validate:"required"`
// 		EventTime time.Time                `json:"event_time" validate:"required"`
// 		Reason    string                   `json:"reason" validate:"required"`
// 		Metadata  attendance.EventMetadata `json:"metadata,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
// 		return
// 	}

// 	if req.Reason == "" {
// 		h.respondWithError(w, http.StatusBadRequest, "Reason is required for correction")
// 		return
// 	}

// 	if req.EventTime.After(time.Now().UTC()) {
// 		h.respondWithError(w, http.StatusBadRequest, "Cannot correct future events")
// 		return
// 	}

// 	now := time.Now().UTC()

// 	// 🔒 FORCE correction source type (client never sends it)
// 	event := &attendance.AttendanceEvent{
// 		AttendanceEventID: uuid.New(),
// 		CompanyID:         companyID,
// 		UserID:            req.UserID,
// 		EventType:         req.EventType,
// 		EventTime:         req.EventTime,
// 		SourceType:        "correction", // ✅ HARD-SET
// 		Metadata:          req.Metadata,
// 		CreatedAt:         now,
// 		CreatedBy:         &actorID,
// 	}

// 	// Always store reason in metadata
// 	if event.Metadata.Reason == nil {
// 		event.Metadata.Reason = &req.Reason
// 	}

// 	createdEvent, err := h.attendanceService.CreateAttendanceEvent(
// 		ctx,
// 		event,
// 		actorType,
// 		actorID,
// 		map[string]interface{}{
// 			"correction":   true,
// 			"reason":       req.Reason,
// 			"corrected_by": actorID.String(),
// 			"corrected_at": now,
// 		},
// 	)

// 	if err != nil {
// 		h.logger.Error(
// 			"Failed to create correction attendance event",
// 			util.String("user_id", req.UserID.String()),
// 			util.String("event_type", req.EventType),
// 			util.String("reason", req.Reason),
// 			util.ErrorField(err),
// 		)

// 		status := http.StatusInternalServerError
// 		if strings.Contains(err.Error(), "invalid") ||
// 			strings.Contains(err.Error(), "required") ||
// 			strings.Contains(err.Error(), "not allowed") {
// 			status = http.StatusBadRequest
// 		}

// 		h.respondWithError(w, status, err.Error())
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
// 		"success": true,
// 		"data":    createdEvent,
// 		"correction_info": map[string]interface{}{
// 			"reason":       req.Reason,
// 			"corrected_by": actorID.String(),
// 			"corrected_at": now,
// 		},
// 	})
// }

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

	// Validate required fields
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "Reason is required for correction")
		return
	}

	if req.EventTime.After(time.Now().UTC()) {
		h.respondWithError(w, http.StatusBadRequest, "Cannot correct future events")
		return
	}

	// Check if correction is too old (e.g., more than 30 days)
	if time.Since(req.EventTime) > 30*24*time.Hour {
		h.respondWithError(w, http.StatusBadRequest, "Cannot correct events older than 30 days")
		return
	}

	// Create correction event
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

	// Set correction reason in metadata
	if event.Metadata.Reason == nil {
		event.Metadata.Reason = &req.Reason
	}

	// Create the correction event
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

	// Get current time
	now := time.Now().UTC()
	clientIP := h.getClientIP(r)
	deviceID := r.Header.Get("X-Device-ID")
	userID := actorID

	// Create punch event
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

	// Create the attendance event with duplicate protection
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

	// Add duplicate warning if event was actually a duplicate
	if createdEvent.AttendanceEventID != event.AttendanceEventID {
		response["warning"] = "Duplicate punch prevented - returned existing record"
		response["is_duplicate"] = true
		response["original_event_id"] = createdEvent.AttendanceEventID
	}

	h.respondWithJSON(w, http.StatusCreated, response)
}
