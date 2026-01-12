package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
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
// REQUEST/ RESPONSE STRUCTURES
// ============================================================================

type CreateAttendanceEventRequest struct {
	UserID     uuid.UUID                `json:"user_id"`
	EventType  string                   `json:"event_type"`
	EventTime  time.Time                `json:"event_time"`
	SourceType string                   `json:"source_type"`
	SourceID   *uuid.UUID               `json:"source_id,omitempty"`
	DeviceID   *string                  `json:"device_id,omitempty"`
	IPAddress  *string                  `json:"ip_address,omitempty"`
	Metadata   attendance.EventMetadata `json:"metadata,omitempty"`
}

type CreateAttendancePolicyRequest struct {
	PolicyCode   string                 `json:"policy_code"`
	PolicyType   string                 `json:"policy_type"`
	DepartmentID *uuid.UUID             `json:"department_id,omitempty"`
	Rules        attendance.PolicyRules `json:"rules"`
	IsActive     bool                   `json:"is_active"`
}

type AssignUserPolicyRequest struct {
	UserID        uuid.UUID  `json:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

type GenerateSummaryRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Date     time.Time `json:"date"`
	Timezone string    `json:"timezone"`
}

type GenerateBulkSummaryRequest struct {
	Timezone     string      `json:"timezone"`
	StartDate    time.Time   `json:"start_date"`
	EndDate      time.Time   `json:"end_date"`
	UserIDs      []uuid.UUID `json:"user_ids,omitempty"`
	DepartmentID *uuid.UUID  `json:"department_id,omitempty"`
}

type SAPEventRequest struct {
	EmployeeID      string    `json:"employee_id"`
	RFIDTag         *string   `json:"rfid_tag,omitempty"`
	EventDateTime   time.Time `json:"event_datetime"`
	EventType       string    `json:"event_type"`
	LocationCode    *string   `json:"location_code,omitempty"`
	MachineID       *string   `json:"machine_id,omitempty"`
	WorkCenter      string    `json:"work_center"`
	SAPTransaction  string    `json:"sap_transaction"`
	RawData         string    `json:"raw_data"`
	ExternalEventID string    `json:"external_event_id"`
	CostCenter      *string   `json:"cost_center,omitempty"`
	FactoryZone     *string   `json:"factory_zone,omitempty"`
	Remarks         *string   `json:"remarks,omitempty"`
}

type FactoryDataRequest struct {
	DeviceID        string    `json:"device_id"`
	EmployeeRFID    string    `json:"employee_rfid"`
	EventTimestamp  time.Time `json:"event_timestamp"`
	GateNumber      string    `json:"gate_number"`
	Direction       string    `json:"direction"`
	Temperature     float64   `json:"temperature,omitempty"`
	MaskDetected    bool      `json:"mask_detected,omitempty"`
	HelmetDetected  bool      `json:"helmet_detected,omitempty"`
	BiometricMatch  bool      `json:"biometric_match,omitempty"`
	FactoryZone     string    `json:"factory_zone"`
	ExternalEventID string    `json:"external_event_id"`
}

type AssignRFIDRequest struct {
	UserID     uuid.UUID `json:"user_id"`
	RFIDTag    string    `json:"rfid_tag"`
	AssignedBy uuid.UUID `json:"assigned_by"`
}

type WorkCenterShiftRequest struct {
	WorkCenterCode string     `json:"work_center_code"`
	ShiftID        uuid.UUID  `json:"shift_id"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	CreatedBy      uuid.UUID  `json:"created_by"`
}

type SearchEventsRequest struct {
	UserID           *uuid.UUID  `json:"user_id,omitempty"`
	UserIDs          []uuid.UUID `json:"user_ids,omitempty"`
	EventType        *string     `json:"event_type,omitempty"`
	EventTypes       []string    `json:"event_types,omitempty"`
	SourceType       *string     `json:"source_type,omitempty"`
	SourceTypes      []string    `json:"source_types,omitempty"`
	StartDate        *time.Time  `json:"start_date,omitempty"`
	EndDate          *time.Time  `json:"end_date,omitempty"`
	DeviceID         *string     `json:"device_id,omitempty"`
	MinWorkedMinutes *int        `json:"min_worked_minutes,omitempty"`
	MaxWorkedMinutes *int        `json:"max_worked_minutes,omitempty"`
	Status           *string     `json:"status,omitempty"`
	Statuses         []string    `json:"statuses,omitempty"`
	Page             int         `json:"page" validate:"min=1"`
	PageSize         int         `json:"page_size" validate:"min=1,max=1000"`
}

type ReportRequest struct {
	ReportType string    `json:"report_type"`
	StartDate  time.Time `json:"start_date"`
	EndDate    time.Time `json:"end_date"`
	Format     string    `json:"format,omitempty"`
}

type StreamRequest struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Format    string    `json:"format" validate:"required,oneof=csv jsonl"`
}

// ============================================================================
// EVENT MANAGEMENT HANDLERS
// ============================================================================

// CreateAttendanceEvent handles creating a new attendance event
func (h *AttendanceHandler) CreateAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID := h.extractActorInfo(ctx)

	var req CreateAttendanceEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            req.UserID,
		EventType:         req.EventType,
		EventTime:         req.EventTime,
		SourceType:        req.SourceType,
		SourceID:          req.SourceID,
		DeviceID:          req.DeviceID,
		IPAddress:         req.IPAddress,
		Metadata:          req.Metadata,
		CreatedAt:         time.Now().UTC(),
		CreatedBy:         &actorID,
	}

	metadata := map[string]interface{}{
		"http_request": true,
		"user_agent":   r.UserAgent(),
		"ip_address":   r.RemoteAddr,
	}

	createdEvent, err := h.attendanceService.CreateAttendanceEvent(ctx, event, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to create attendance event",
			util.String("company_id", companyID.String()),
			util.String("user_id", req.UserID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create attendance event")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, createdEvent)
}

// CreateBulkAttendanceEvents handles creating multiple attendance events
func (h *AttendanceHandler) CreateBulkAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID := h.extractActorInfo(ctx)

	var events []*CreateAttendanceEventRequest
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	attendanceEvents := make([]*attendance.AttendanceEvent, len(events))
	for i, req := range events {
		attendanceEvents[i] = &attendance.AttendanceEvent{
			AttendanceEventID: uuid.New(),
			CompanyID:         companyID,
			UserID:            req.UserID,
			EventType:         req.EventType,
			EventTime:         req.EventTime,
			SourceType:        req.SourceType,
			SourceID:          req.SourceID,
			DeviceID:          req.DeviceID,
			IPAddress:         req.IPAddress,
			Metadata:          req.Metadata,
			CreatedAt:         time.Now().UTC(),
			CreatedBy:         &actorID,
		}
	}

	metadata := map[string]interface{}{
		"http_request": true,
		"user_agent":   r.UserAgent(),
		"ip_address":   r.RemoteAddr,
		"batch_size":   len(events),
	}

	err = h.attendanceService.CreateBulkAttendanceEvents(ctx, attendanceEvents, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to create bulk attendance events",
			util.String("company_id", companyID.String()),
			util.Int("event_count", len(events)),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create bulk attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":      "Attendance events created successfully",
		"events_count": len(events),
	})
}

// GetAttendanceEventByID handles retrieving an attendance event by ID
func (h *AttendanceHandler) GetAttendanceEventByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eventIDStr := chi.URLParam(r, "eventID")
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid event ID")
		return
	}

	event, err := h.queryService.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Attendance event not found")
			return
		}
		h.logger.Error("Failed to get attendance event",
			util.String("event_id", eventIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance event")
		return
	}

	h.respondWithJSON(w, http.StatusOK, event)
}

// GetAttendanceEventsByUser handles retrieving attendance events for a specific user
func (h *AttendanceHandler) GetAttendanceEventsByUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	startDate, endDate, err := h.parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	events, err := h.queryService.GetAttendanceEventsByUser(ctx, userID, startDate, endDate, limit)
	if err != nil {
		h.logger.Error("Failed to get attendance events by user",
			util.String("user_id", userIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, events)
}

// GetAttendanceEventsByCompany handles retrieving attendance events for a company
func (h *AttendanceHandler) GetAttendanceEventsByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	startDate, endDate, err := h.parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	page, pageSize := h.parsePagination(r)

	events, totalCount, err := h.queryService.GetAttendanceEventsByCompany(ctx, companyID, startDate, endDate, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get attendance events by company",
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"events":      events,
		"total_count": totalCount,
		"page":        page,
		"page_size":   pageSize,
	})
}

// SearchAttendanceEvents handles searching attendance events with filters
func (h *AttendanceHandler) SearchAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req SearchEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Page == 0 {
		req.Page = 1
	}
	if req.PageSize == 0 {
		req.PageSize = 100
	}

	filters := service.AttendanceSearchFilters{
		UserID:           req.UserID,
		UserIDs:          req.UserIDs,
		EventType:        req.EventType,
		EventTypes:       req.EventTypes,
		SourceType:       req.SourceType,
		SourceTypes:      req.SourceTypes,
		StartDate:        req.StartDate,
		EndDate:          req.EndDate,
		DeviceID:         req.DeviceID,
		MinWorkedMinutes: req.MinWorkedMinutes,
		MaxWorkedMinutes: req.MaxWorkedMinutes,
		Status:           req.Status,
		Statuses:         req.Statuses,
	}

	events, totalCount, err := h.queryService.SearchAttendanceEventsTyped(ctx, companyID, filters, req.Page, req.PageSize)
	if err != nil {
		h.logger.Error("Failed to search attendance events",
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search attendance events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"events":      events,
		"total_count": totalCount,
		"page":        req.Page,
		"page_size":   req.PageSize,
	})
}

// ============================================================================
// POLICY MANAGEMENT HANDLERS
// ============================================================================

// CreateAttendancePolicy handles creating a new attendance policy
func (h *AttendanceHandler) CreateAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID := h.extractActorInfo(ctx)

	var req CreateAttendancePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	policy := &attendance.AttendancePolicy{
		PolicyID:     uuid.New(),
		CompanyID:    companyID,
		DepartmentID: req.DepartmentID,
		PolicyCode:   req.PolicyCode,
		PolicyType:   req.PolicyType,
		Rules:        req.Rules,
		IsActive:     req.IsActive,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	metadata := map[string]interface{}{
		"http_request": true,
		"user_agent":   r.UserAgent(),
	}

	createdPolicy, err := h.attendanceService.CreateAttendancePolicy(ctx, policy, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to create attendance policy",
			util.String("company_id", companyID.String()),
			util.String("policy_code", req.PolicyCode),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create attendance policy")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, createdPolicy)
}

// GetAttendancePolicyByID handles retrieving an attendance policy by ID
func (h *AttendanceHandler) GetAttendancePolicyByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID")
		return
	}

	policy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Attendance policy not found")
			return
		}
		h.logger.Error("Failed to get attendance policy",
			util.String("policy_id", policyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, policy)
}

// GetAttendancePoliciesByCompany handles retrieving all attendance policies for a company
func (h *AttendanceHandler) GetAttendancePoliciesByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	activeOnly := r.URL.Query().Get("active_only") == "true"

	policies, err := h.queryService.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.logger.Error("Failed to get attendance policies",
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance policies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, policies)
}

// AssignUserAttendancePolicy handles assigning an attendance policy to a user
func (h *AttendanceHandler) AssignUserAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID := h.extractActorInfo(ctx)

	var req AssignUserPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userPolicy := &attendance.UserAttendancePolicy{
		UserID:        req.UserID,
		PolicyID:      req.PolicyID,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		AssignedBy:    &actorID,
		CreatedAt:     time.Now().UTC(),
	}

	metadata := map[string]interface{}{
		"http_request": true,
	}

	err = h.attendanceService.AssignUserAttendancePolicy(ctx, userPolicy, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to assign user attendance policy",
			util.String("company_id", companyID.String()),
			util.String("user_id", req.UserID.String()),
			util.String("policy_id", req.PolicyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to assign attendance policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Attendance policy assigned successfully",
	})
}

// GetUserCurrentAttendancePolicy handles retrieving the current attendance policy for a user
func (h *AttendanceHandler) GetUserCurrentAttendancePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	date := time.Now().UTC()
	if dateStr := r.URL.Query().Get("date"); dateStr != "" {
		if d, err := time.Parse("2006-01-02", dateStr); err == nil {
			date = d
		}
	}

	policy, err := h.queryService.GetUserCurrentAttendancePolicy(ctx, userID, date)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Attendance policy not found for user")
			return
		}
		h.logger.Error("Failed to get user current attendance policy",
			util.String("user_id", userIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, policy)
}

// ============================================================================
// DAILY SUMMARY HANDLERS
// ============================================================================

// GenerateDailySummary handles generating daily attendance summary for a user
func (h *AttendanceHandler) GenerateDailySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req GenerateSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	summary, err := h.attendanceService.GenerateDailySummary(ctx, companyID, req.UserID, req.Date, req.Timezone)
	if err != nil {
		h.logger.Error("Failed to generate daily summary",
			util.String("company_id", companyID.String()),
			util.String("user_id", req.UserID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to generate daily summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, summary)
}

// GenerateBulkDailySummaries handles generating daily summaries for multiple users/dates
func (h *AttendanceHandler) GenerateBulkDailySummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req GenerateBulkSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	summaries, err := h.attendanceService.GenerateBulkDailySummaries(ctx, companyID, req.Timezone, req.StartDate, req.EndDate)
	if err != nil {
		h.logger.Error("Failed to generate bulk daily summaries",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to generate bulk daily summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, summaries)
}

// GetAttendanceDailySummaryByUserDate handles retrieving daily summary for a user on a specific date
func (h *AttendanceHandler) GetAttendanceDailySummaryByUserDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		dateStr = time.Now().Format("2006-01-02")
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format, use YYYY-MM-DD")
		return
	}

	summary, err := h.queryService.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Daily summary not found")
			return
		}
		h.logger.Error("Failed to get daily summary",
			util.String("user_id", userIDStr),
			util.String("date", dateStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve daily summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, summary)
}

// GetAttendanceDailySummariesByUser handles retrieving daily summaries for a user within a date range
func (h *AttendanceHandler) GetAttendanceDailySummariesByUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	startDate, endDate, err := h.parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	summaries, err := h.queryService.GetAttendanceDailySummariesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get daily summaries by user",
			util.String("user_id", userIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve daily summaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, summaries)
}

// GetAttendanceSummaryStats handles retrieving attendance statistics
func (h *AttendanceHandler) GetAttendanceSummaryStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	startDate, endDate, err := h.parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	stats, err := h.queryService.GetAttendanceSummaryStats(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get attendance summary stats",
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, stats)
}

// ============================================================================
// SAP & FACTORY INTEGRATION HANDLERS
// ============================================================================

// ProcessSAPAttendanceEvent handles processing SAP attendance events
func (h *AttendanceHandler) ProcessSAPAttendanceEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req SAPEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	sapEvent := &service.SAPAttendanceEvent{
		EmployeeID:      req.EmployeeID,
		RFIDTag:         req.RFIDTag,
		EventDateTime:   req.EventDateTime,
		EventType:       req.EventType,
		LocationCode:    req.LocationCode,
		MachineID:       req.MachineID,
		WorkCenter:      req.WorkCenter,
		SAPTransaction:  req.SAPTransaction,
		RawData:         req.RawData,
		ExternalEventID: req.ExternalEventID,
		CostCenter:      req.CostCenter,
		FactoryZone:     req.FactoryZone,
		Remarks:         req.Remarks,
	}

	sourceType := "SAP"
	sourceID := uuid.New()

	event, err := h.attendanceService.ProcessSAPAttendanceEvent(ctx, sapEvent, companyID, sourceType, &sourceID)
	if err != nil {
		h.logger.Error("Failed to process SAP attendance event",
			util.String("company_id", companyID.String()),
			util.String("employee_id", req.EmployeeID),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to process SAP attendance event")
		return
	}

	h.respondWithJSON(w, http.StatusOK, event)
}

// SyncFactoryAttendance handles processing factory IoT attendance data
func (h *AttendanceHandler) SyncFactoryAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req FactoryDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	factoryData := &service.FactoryAttendanceData{
		DeviceID:        req.DeviceID,
		EmployeeRFID:    req.EmployeeRFID,
		EventTimestamp:  req.EventTimestamp,
		GateNumber:      req.GateNumber,
		Direction:       req.Direction,
		Temperature:     req.Temperature,
		MaskDetected:    req.MaskDetected,
		HelmetDetected:  req.HelmetDetected,
		BiometricMatch:  req.BiometricMatch,
		FactoryZone:     req.FactoryZone,
		ExternalEventID: req.ExternalEventID,
	}

	err = h.attendanceService.SyncFactoryAttendance(ctx, factoryData, companyID)
	if err != nil {
		h.logger.Error("Failed to sync factory attendance",
			util.String("company_id", companyID.String()),
			util.String("rfid", req.EmployeeRFID),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to sync factory attendance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Factory attendance synced successfully",
	})
}

// ============================================================================
// RFID MANAGEMENT HANDLERS
// ============================================================================

// AssignRFIDToEmployee handles assigning RFID to an employee
func (h *AttendanceHandler) AssignRFIDToEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req AssignRFIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.attendanceService.AssignRFIDToEmployee(ctx, companyID, req.UserID, req.RFIDTag, req.AssignedBy)
	if err != nil {
		h.logger.Error("Failed to assign RFID to employee",
			util.String("company_id", companyID.String()),
			util.String("user_id", req.UserID.String()),
			util.String("rfid", req.RFIDTag),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to assign RFID")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "RFID assigned successfully",
	})
}

// GetEmployeeByRFID handles retrieving employee information by RFID
func (h *AttendanceHandler) GetEmployeeByRFID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	rfidTag := r.URL.Query().Get("rfid_tag")
	if rfidTag == "" {
		h.respondWithError(w, http.StatusBadRequest, "RFID tag is required")
		return
	}

	mapping, err := h.attendanceService.GetEmployeeByRFID(ctx, rfidTag, companyID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee not found for RFID")
			return
		}
		h.logger.Error("Failed to get employee by RFID",
			util.String("company_id", companyID.String()),
			util.String("rfid", rfidTag),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee information")
		return
	}

	h.respondWithJSON(w, http.StatusOK, mapping)
}

// ============================================================================
// WORK CENTER MANAGEMENT HANDLERS
// ============================================================================

// MapWorkCenterToShift handles mapping a work center to a shift
func (h *AttendanceHandler) MapWorkCenterToShift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req WorkCenterShiftRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.attendanceService.MapWorkCenterToShift(ctx, companyID, req.WorkCenterCode, req.ShiftID, req.EffectiveFrom, req.EffectiveTo, req.CreatedBy)
	if err != nil {
		h.logger.Error("Failed to map work center to shift",
			util.String("company_id", companyID.String()),
			util.String("work_center", req.WorkCenterCode),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to map work center to shift")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Work center mapped to shift successfully",
	})
}

// GetShiftForWorkCenter handles retrieving shift information for a work center
func (h *AttendanceHandler) GetShiftForWorkCenter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	workCenterCode := r.URL.Query().Get("work_center_code")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}

	wcShift, err := h.attendanceService.GetShiftForWorkCenter(ctx, workCenterCode, companyID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Shift mapping not found for work center")
			return
		}
		h.logger.Error("Failed to get shift for work center",
			util.String("company_id", companyID.String()),
			util.String("work_center", workCenterCode),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve shift information")
		return
	}

	h.respondWithJSON(w, http.StatusOK, wcShift)
}

// ============================================================================
// REPORTS HANDLERS
// ============================================================================

// GenerateAttendanceReport handles generating attendance reports
func (h *AttendanceHandler) GenerateAttendanceReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	data, contentType, err := h.queryService.GenerateAttendanceReport(ctx, companyID, req.ReportType, req.StartDate, req.EndDate)
	if err != nil {
		h.logger.Error("Failed to generate attendance report",
			util.String("company_id", companyID.String()),
			util.String("report_type", req.ReportType),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to generate attendance report")
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=attendance_report_%s_%s.%s",
		req.ReportType, time.Now().Format("20060102"), strings.Split(contentType, "/")[1]))
	w.Write(data)
}

// StreamAttendanceEvents handles streaming attendance events in various formats
func (h *AttendanceHandler) StreamAttendanceEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req StreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	if req.Format == "csv" {
		w.Header().Set("Content-Disposition", "attachment; filename=attendance_events.csv")
	} else {
		w.Header().Set("Content-Type", "application/jsonlines")
		w.Header().Set("Content-Disposition", "attachment; filename=attendance_events.jsonl")
	}

	err = h.queryService.StreamAttendanceEvents(ctx, companyID, req.StartDate, req.EndDate, w, req.Format)
	if err != nil {
		h.logger.Error("Failed to stream attendance events",
			util.String("company_id", companyID.String()),
			util.String("format", req.Format),
			util.ErrorField(err))
		// Can't send error response after starting stream
		return
	}
}

// ============================================================================
// SAP BUSINESS RULES HANDLERS
// ============================================================================

// GetSAPBusinessRules handles retrieving SAP business rules
func (h *AttendanceHandler) GetSAPBusinessRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	rules, err := h.attendanceService.GetSAPBusinessRules(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get SAP business rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve SAP business rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, rules)
}

// UpdateSAPBusinessRules handles updating SAP business rules
func (h *AttendanceHandler) UpdateSAPBusinessRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userID := h.extractUserID(ctx)
	if userID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var rules attendance.SAPBusinessRules
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.attendanceService.UpdateSAPBusinessRules(ctx, companyID, &rules, userID)
	if err != nil {
		h.logger.Error("Failed to update SAP business rules",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update SAP business rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "SAP business rules updated successfully",
	})
}

// ============================================================================
// HEALTH CHECK HANDLER
// ============================================================================

// HealthCheck handles attendance service health check
func (h *AttendanceHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.attendanceService.HealthCheck(ctx); err != nil {
		h.logger.Error("Attendance service health check failed", util.ErrorField(err))
		h.respondWithError(w, http.StatusServiceUnavailable, "Attendance service is unhealthy")
		return
	}

	if err := h.queryService.HealthCheck(ctx); err != nil {
		h.logger.Error("Attendance query service health check failed", util.ErrorField(err))
		h.respondWithError(w, http.StatusServiceUnavailable, "Attendance query service is unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"service": "attendance",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// HELPER METHODS
// ============================================================================
func (h *AttendanceHandler) parseDateRange(r *http.Request) (time.Time, time.Time, error) {
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	if startDateStr == "" || endDateStr == "" {
		end := time.Now().UTC()
		start := end.AddDate(0, 0, -7)
		return start, end, nil
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date format, use YYYY-MM-DD")
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date format, use YYYY-MM-DD")
	}

	if startDate.After(endDate) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_date cannot be after end_date")
	}

	// Optional safety limit
	if endDate.Sub(startDate).Hours() > 24*366 {
		return time.Time{}, time.Time{}, fmt.Errorf("date range cannot exceed 366 days")
	}

	return startDate, endDate, nil
}

func (h *AttendanceHandler) parsePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := 100

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 1000 {
			pageSize = ps
		}
	}

	return page, pageSize
}

func (h *AttendanceHandler) extractActorInfo(ctx context.Context) (string, uuid.UUID) {
	actorType, _ := ctx.Value("session_type").(string)
	userIDStr, _ := ctx.Value("user_id").(string)

	var actorID uuid.UUID
	if userIDStr != "" {
		actorID, _ = uuid.Parse(userIDStr)
	}

	return actorType, actorID
}

func (h *AttendanceHandler) extractUserID(ctx context.Context) uuid.UUID {
	userIDStr, _ := ctx.Value("user_id").(string)
	if userIDStr == "" {
		return uuid.Nil
	}
	userID, _ := uuid.Parse(userIDStr)
	return userID
}

func (h *AttendanceHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

func (h *AttendanceHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
	})
}

// ============================================================================
// ATTENDANCE EVENT TYPE HANDLERS
// ============================================================================

// GetAttendanceEventType handles retrieving a specific attendance event type
func (h *AttendanceHandler) GetAttendanceEventType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eventType := chi.URLParam(r, "eventType")

	if eventType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Event type is required")
		return
	}

	eventTypeObj, err := h.attendanceService.GetAttendanceEventType(ctx, eventType)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Attendance event type not found")
			return
		}
		h.logger.Error("Failed to get attendance event type",
			util.String("event_type", eventType),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance event type")
		return
	}

	h.respondWithJSON(w, http.StatusOK, eventTypeObj)
}

// ListAttendanceEventTypes handles listing all attendance event types
func (h *AttendanceHandler) ListAttendanceEventTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	activeOnly := r.URL.Query().Get("active_only") == "true"

	eventTypes, err := h.attendanceService.ListAttendanceEventTypes(ctx, activeOnly)
	if err != nil {
		h.logger.Error("Failed to list attendance event types",
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance event types")
		return
	}

	// Group by category for better frontend consumption
	groupedResponse := h.groupEventTypesByCategory(eventTypes)

	h.respondWithJSON(w, http.StatusOK, groupedResponse)
}

// ============================================================================
// ATTENDANCE SOURCE TYPE HANDLERS
// ============================================================================

// GetAttendanceSourceType handles retrieving a specific attendance source type
func (h *AttendanceHandler) GetAttendanceSourceType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sourceType := chi.URLParam(r, "sourceType")

	if sourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Source type is required")
		return
	}

	sourceTypeObj, err := h.attendanceService.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Attendance source type not found")
			return
		}
		h.logger.Error("Failed to get attendance source type",
			util.String("source_type", sourceType),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance source type")
		return
	}

	h.respondWithJSON(w, http.StatusOK, sourceTypeObj)
}

// ListAttendanceSourceTypes handles listing all attendance source types
func (h *AttendanceHandler) ListAttendanceSourceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sourceTypes, err := h.attendanceService.ListAttendanceSourceTypes(ctx)
	if err != nil {
		h.logger.Error("Failed to list attendance source types",
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve attendance source types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, sourceTypes)
}

// ============================================================================
// COMPANY ATTENDANCE RULES HANDLERS
// ============================================================================

// GetCompanyAttendanceRules handles retrieving company attendance rules
func (h *AttendanceHandler) GetCompanyAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	rules, err := h.attendanceService.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get company attendance rules",
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve company attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, rules)
}

// UpdateCompanyAttendanceRules handles updating company attendance rules
func (h *AttendanceHandler) UpdateCompanyAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Extract user ID from context (assumes authentication middleware)
	userID := h.extractUserID(ctx)
	if userID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var rules attendance.CompanyAttendanceRules
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Ensure company ID matches URL parameter
	rules.CompanyID = companyID

	err = h.attendanceService.UpdateCompanyAttendanceRules(ctx, &rules, userID)
	if err != nil {
		h.logger.Error("Failed to update company attendance rules",
			util.String("company_id", companyIDStr),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update company attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Company attendance rules updated successfully",
		"rules":   rules,
	})
}

// ============================================================================
// DEPARTMENT ATTENDANCE RULES HANDLERS
// ============================================================================

// GetDepartmentAttendanceRules handles retrieving department attendance rules
func (h *AttendanceHandler) GetDepartmentAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID")
		return
	}

	rules, err := h.attendanceService.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
	if err != nil {
		h.logger.Error("Failed to get department attendance rules",
			util.String("company_id", companyIDStr),
			util.String("department_id", departmentIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve department attendance rules")
		return
	}

	// Return null if no rules found (caller can decide how to handle)
	if rules == nil {
		h.respondWithJSON(w, http.StatusOK, nil)
		return
	}

	h.respondWithJSON(w, http.StatusOK, rules)
}

// ============================================================================
// USER ATTENDANCE PROFILE HANDLERS
// ============================================================================

// GetUserAttendanceProfile handles retrieving user attendance profile
func (h *AttendanceHandler) GetUserAttendanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	profile, err := h.attendanceService.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get user attendance profile",
			util.String("user_id", userIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve user attendance profile")
		return
	}

	// Return null if no profile found (caller can decide how to handle)
	if profile == nil {
		h.respondWithJSON(w, http.StatusOK, nil)
		return
	}

	h.respondWithJSON(w, http.StatusOK, profile)
}

// ============================================================================
// RULE RESOLUTION HANDLER
// ============================================================================

// ResolveAttendanceRules handles resolving attendance rules for a user
func (h *AttendanceHandler) ResolveAttendanceRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract parameters from query string
	userIDStr := r.URL.Query().Get("user_id")
	companyIDStr := r.URL.Query().Get("company_id")
	departmentIDStr := r.URL.Query().Get("department_id")

	if userIDStr == "" || companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "User ID and Company ID are required")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var departmentID uuid.UUID
	if departmentIDStr != "" {
		departmentID, err = uuid.Parse(departmentIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid department ID")
			return
		}
	}

	rules, err := h.attendanceService.ResolveAttendanceRules(ctx, userID, companyID, departmentID)
	if err != nil {
		h.logger.Error("Failed to resolve attendance rules",
			util.String("user_id", userIDStr),
			util.String("company_id", companyIDStr),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to resolve attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, rules)
}

// handler/attendance.go - Add these structs
type ValidateEventTypeRequest struct {
	EventType string `json:"event_type"`
}

type ValidateSourceTypeRequest struct {
	SourceType string     `json:"source_type"`
	SourceID   *uuid.UUID `json:"source_id,omitempty"`
}

// Fix ValidateAttendanceEventType handler
func (h *AttendanceHandler) ValidateAttendanceEventType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ValidateEventTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.EventType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Event type is required")
		return
	}

	err := h.attendanceService.ValidateAttendanceEventType(ctx, req.EventType)
	if err != nil {
		h.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"valid":   false,
			"message": err.Error(),
		})
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Event type is valid",
	})
}

// Fix ValidateAttendanceSourceType handler similarly

// ValidateAttendanceSourceType handles validating an attendance source type
// ValidateAttendanceSourceType handles validating an attendance source type
func (h *AttendanceHandler) ValidateAttendanceSourceType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ValidateSourceTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Source type is required")
		return
	}

	err := h.attendanceService.ValidateAttendanceSourceType(ctx, req.SourceType, req.SourceID)
	if err != nil {
		h.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Source type is valid",
	})
}

// ============================================================================
// HELPER METHODS
// ============================================================================

// groupEventTypesByCategory groups event types by category for better frontend consumption
func (h *AttendanceHandler) groupEventTypesByCategory(eventTypes []*attendance.AttendanceEventType) map[string]interface{} {
	grouped := make(map[string][]*attendance.AttendanceEventType)
	categoryOrder := []string{"check_in_out", "breaks", "overtime", "leave", "safety", "status", "class"}

	// Define category order (you can customize this)
	for _, eventType := range eventTypes {
		grouped[eventType.Category] = append(grouped[eventType.Category], eventType)
	}

	// Sort categories by predefined order
	sortedCategories := make([]string, 0, len(grouped))
	for _, cat := range categoryOrder {
		if _, exists := grouped[cat]; exists {
			sortedCategories = append(sortedCategories, cat)
		}
	}

	// Add any remaining categories not in predefined order
	for cat := range grouped {
		found := false
		for _, sortedCat := range sortedCategories {
			if sortedCat == cat {
				found = true
				break
			}
		}
		if !found {
			sortedCategories = append(sortedCategories, cat)
		}
	}

	result := map[string]interface{}{
		"categories": sortedCategories,
		"events":     grouped,
	}

	return result
}

// handler/attendance.go - Add these structs
type CreateDepartmentRulesRequest struct {
	DepartmentID       uuid.UUID `json:"department_id"`
	AllowedSourceTypes []string  `json:"allowed_source_types"`
	AllowedEventTypes  []string  `json:"allowed_event_types"`
	RequireLocation    bool      `json:"require_location"`
	RequireDevice      bool      `json:"require_device"`
}

type CreateUserProfileRequest struct {
	UserID              uuid.UUID `json:"user_id"`
	OverrideSourceTypes []string  `json:"override_source_types,omitempty"`
	OverrideEventTypes  []string  `json:"override_event_types,omitempty"`
}

// handler/attendance.go - Add these handler methods
func (h *AttendanceHandler) CreateOrUpdateDepartmentRules(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// 1️⃣ Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// 2️⃣ Decode request body
	var req CreateDepartmentRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.DepartmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "department_id is required")
		return
	}

	// 3️⃣ Build domain model
	rules := &attendance.DepartmentAttendanceRules{
		RuleID:             uuid.New(),
		CompanyID:          companyID,
		DepartmentID:       req.DepartmentID,
		AllowedSourceTypes: req.AllowedSourceTypes,
		AllowedEventTypes:  req.AllowedEventTypes,
		RequireLocation:    req.RequireLocation,
		RequireDevice:      req.RequireDevice,
		CreatedAt:          time.Now().UTC(),
	}

	// 4️⃣ Call SERVICE (NOT repo)
	if err := h.attendanceService.UpsertDepartmentAttendanceRules(ctx, rules); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 5️⃣ Success response
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Department attendance rules updated successfully",
		"rules":   rules,
	})
}
func (h *AttendanceHandler) CreateOrUpdateUserProfile(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// 1️⃣ Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// 2️⃣ Decode request body
	var req CreateUserProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	// 3️⃣ Build domain model
	profile := &attendance.UserAttendanceProfile{
		UserID:              req.UserID,
		CompanyID:           companyID,
		OverrideSourceTypes: req.OverrideSourceTypes,
		OverrideEventTypes:  req.OverrideEventTypes,
		CreatedAt:           time.Now().UTC(),
	}

	// 4️⃣ Call SERVICE (NOT repo)
	if err := h.attendanceService.UpsertUserAttendanceProfile(ctx, profile); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 5️⃣ Success response
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "User attendance profile updated successfully",
		"profile": profile,
	})
}

// handler/attendance.go - Add this struct and handler method

type CompleteSAPFlowRequest struct {
	EmployeeID      string    `json:"employee_id"`
	RFIDTag         *string   `json:"rfid_tag,omitempty"`
	EventDateTime   time.Time `json:"event_datetime"`
	EventType       string    `json:"event_type"`
	WorkCenter      string    `json:"work_center"`
	SAPTransaction  string    `json:"sap_transaction"`
	ExternalEventID string    `json:"external_event_id"`
	CostCenter      *string   `json:"cost_center,omitempty"`
}

func (h *AttendanceHandler) CompleteSAPAttendanceFlow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req CompleteSAPFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	sapEvent := &service.SAPAttendanceEvent{
		EmployeeID:      req.EmployeeID,
		RFIDTag:         req.RFIDTag,
		EventDateTime:   req.EventDateTime,
		EventType:       req.EventType,
		WorkCenter:      req.WorkCenter,
		SAPTransaction:  req.SAPTransaction,
		ExternalEventID: req.ExternalEventID,
		CostCenter:      req.CostCenter,
	}

	// First, we need to get the service to call the complete flow
	// Since we don't have this method in the service interface yet,
	// let's call the existing ProcessSAPAttendanceEvent instead
	sourceType := "sap"
	sourceID := uuid.New()

	_, err = h.attendanceService.ProcessSAPAttendanceEvent(ctx, sapEvent, companyID, sourceType, &sourceID)
	if err != nil {
		h.logger.Error("Failed to process SAP attendance flow",
			util.String("company_id", companyID.String()),
			util.String("employee_id", req.EmployeeID),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to process SAP attendance flow")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "SAP attendance flow completed successfully",
	})
}
