package handler

import (
	"auth-service/internal/hr/models/leave"
	"auth-service/internal/hr/service"
	"auth-service/internal/middleware"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeaveHandler struct {
	leaveService      service.LeaveService
	leaveQueryService service.LeaveQueryService
	logger            *zap.Logger
}

func NewLeaveHandler(
	leaveService service.LeaveService,
	leaveQueryService service.LeaveQueryService,
	logger *zap.Logger,
) *LeaveHandler {
	return &LeaveHandler{
		leaveService:      leaveService,
		leaveQueryService: leaveQueryService,
		logger:            logger,
	}
}

// Leave Type Management
func (h *LeaveHandler) CreateLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var leaveType leave.LeaveType
	if err := json.NewDecoder(r.Body).Decode(&leaveType); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	leaveType.CompanyID = companyID
	result, err := h.leaveService.CreateLeaveType(ctx, &leaveType, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *LeaveHandler) GetLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	leaveTypeIDStr := chi.URLParam(r, "leaveTypeID")

	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid leave type ID")
		return
	}

	result, err := h.leaveQueryService.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Leave type not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *LeaveHandler) ListLeaveTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	includeInactive := r.URL.Query().Get("include_inactive") == "true"

	result, err := h.leaveQueryService.ListLeaveTypesByCompany(ctx, companyID, includeInactive)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Leave Policy Management
func (h *LeaveHandler) CreateLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var policy leave.LeavePolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	policy.CompanyID = companyID
	result, err := h.leaveService.CreateLeavePolicy(ctx, &policy, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *LeaveHandler) GetLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyIDStr := chi.URLParam(r, "policyID")

	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid policy ID")
		return
	}

	result, err := h.leaveQueryService.GetLeavePolicyByID(ctx, policyID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Leave policy not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Leave Request Management
func (h *LeaveHandler) CreateLeaveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType := middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var req leave.LeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	req.CompanyID = companyID
	// For employee self-request, use current user ID
	if actorType == "employee" {
		req.UserID = actorID
	}

	result, err := h.leaveService.CreateLeaveRequest(ctx, &req, actorType, actorID, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, result)
}

func (h *LeaveHandler) GetLeaveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestIDStr := chi.URLParam(r, "requestID")

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request ID")
		return
	}

	result, err := h.leaveQueryService.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Leave request not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

func (h *LeaveHandler) ListLeaveRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := r.URL.Query().Get("user_id")
	leaveTypeIDStr := r.URL.Query().Get("leave_type_id")
	status := r.URL.Query().Get("status")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filters := make(map[string]interface{})
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err == nil {
			filters["user_id"] = userID
		}
	}

	if leaveTypeIDStr != "" {
		leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
		if err == nil {
			filters["leave_type_id"] = leaveTypeID
		}
	}

	if status != "" {
		filters["status"] = status
	}

	result, total, err := h.leaveQueryService.ListLeaveRequestsByCompany(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"data":        result,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + pageSize - 1) / pageSize,
	})
}

// Leave Approval Management
func (h *LeaveHandler) ApproveLeaveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestIDStr := chi.URLParam(r, "requestID")
	_ = middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var requestBody struct {
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request ID")
		return
	}

	err = h.leaveService.ApproveLeaveRequest(ctx, requestID, actorID, requestBody.Reason, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Leave request approved successfully",
	})
}

func (h *LeaveHandler) RejectLeaveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestIDStr := chi.URLParam(r, "requestID")
	_ = middleware.GetSessionTypeFromContext(ctx)
	actorID := middleware.GetUserIDFromContext(ctx)

	var requestBody struct {
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request ID")
		return
	}

	err = h.leaveService.RejectLeaveRequest(ctx, requestID, actorID, requestBody.Reason, nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Leave request rejected successfully",
	})
}

// Leave Balance
func (h *LeaveHandler) GetLeaveBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserIDFromContext(ctx)

	leaveTypeIDStr := r.URL.Query().Get("leave_type_id")
	if leaveTypeIDStr == "" {
		// Get all leave balances for user
		result, err := h.leaveQueryService.GetLeaveBalancesByUser(ctx, userID, time.Now())
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		h.respondWithJSON(w, http.StatusOK, result)
		return
	}

	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid leave type ID")
		return
	}

	result, err := h.leaveQueryService.GetCurrentLeaveBalance(ctx, userID, leaveTypeID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Leave Stats and Reports
func (h *LeaveHandler) GetLeaveStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIX: get company ID from URL (NOT context)
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time

	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start date format")
			return
		}
	} else {
		startDate = time.Now().AddDate(0, -12, 0)
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end date format")
			return
		}
	} else {
		endDate = time.Now()
	}

	result, err := h.leaveQueryService.GetLeaveSummaryStats(
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

func (h *LeaveHandler) GetEmployeeLeaveSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	yearStr := r.URL.Query().Get("year")
	year := time.Now().Year()
	if yearStr != "" {
		year, err = strconv.Atoi(yearStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid year")
			return
		}
	}

	result, err := h.leaveQueryService.GetEmployeeLeaveSummary(ctx, userID, year)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// Health Check
func (h *LeaveHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.leaveQueryService.HealthCheck(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "leave",
	})
}

// Helper methods
func (h *LeaveHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *LeaveHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
