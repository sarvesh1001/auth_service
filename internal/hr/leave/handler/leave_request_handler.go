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

	"auth-service/internal/attendance/service/scheduling" // ✅ Unified scheduling service
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/service"
)

type LeaveRequestHandler struct {
	requestService    service.LeaveRequestService
	queryService      service.LeaveQueryService
	schedulingService scheduling.SchedulingService
	logger            *zap.Logger
}

func NewLeaveRequestHandler(
	requestService service.LeaveRequestService,
	queryService service.LeaveQueryService,
	schedulingService scheduling.SchedulingService,
	logger *zap.Logger,
) *LeaveRequestHandler {
	return &LeaveRequestHandler{
		requestService:    requestService,
		queryService:      queryService,
		schedulingService: schedulingService,
		logger:            logger,
	}
}

// ---- DTOs ----

type CreateLeaveRequest struct {
	UserID      uuid.UUID `json:"user_id"`
	LeaveTypeID uuid.UUID `json:"leave_type_id"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	TotalDays   int       `json:"total_days"`
}

type ApproveRejectRequest struct {
	ApprovedBy uuid.UUID `json:"approved_by"`
	Reason     string    `json:"reason,omitempty"`
}

// ---- Handlers ----

func (h *LeaveRequestHandler) RequestLeave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	requestedBy, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:request:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateLeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user ID is required")
		return
	}
	if req.LeaveTypeID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "leave type ID is required")
		return
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start and end dates are required")
		return
	}
	if req.EndDate.Before(req.StartDate) {
		h.respondWithError(w, http.StatusBadRequest, "end date must be after start date")
		return
	}
	if req.TotalDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "total days must be greater than 0")
		return
	}

	createReq := &models.LeaveRequestCreate{
		CompanyID:   companyID,
		UserID:      req.UserID,
		LeaveTypeID: req.LeaveTypeID,
		StartDate:   req.StartDate,
		EndDate:     req.EndDate,
		TotalDays:   req.TotalDays,
		RequestedBy: requestedBy,
	}

	leaveRequest, err := h.requestService.RequestLeave(ctx, createReq)
	if err != nil {
		h.logger.Error("Failed to create leave request",
			zap.String("user_id", req.UserID.String()),
			zap.String("leave_type_id", req.LeaveTypeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    leaveRequest,
		"message": "Leave request created successfully",
	})
}

func (h *LeaveRequestHandler) GetLeaveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	requests, err := h.queryService.GetUserLeaveHistory(ctx, userID,
		time.Now().AddDate(-1, 0, 0),
		time.Now().AddDate(1, 0, 0))
	if err != nil {
		h.logger.Error("Failed to get leave requests",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave request")
		return
	}

	var leaveRequest *models.LeaveRequest
	for _, req := range requests {
		if req.LeaveRequestID == requestID && req.CompanyID == companyID {
			leaveRequest = req
			break
		}
	}

	if leaveRequest == nil {
		h.respondWithError(w, http.StatusNotFound, "leave request not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaveRequest,
	})
}

func (h *LeaveRequestHandler) ListLeaveRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	status := r.URL.Query().Get("status")
	leaveTypeIDStr := r.URL.Query().Get("leave_type_id")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date format")
			return
		}
	} else {
		startDate = time.Now().AddDate(-1, 0, 0)
	}
	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date format")
			return
		}
	} else {
		endDate = time.Now().AddDate(1, 0, 0)
	}

	requests, err := h.queryService.GetUserLeaveHistory(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to list leave requests",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list leave requests")
		return
	}

	filteredRequests := make([]*models.LeaveRequest, 0)
	for _, req := range requests {
		if req.CompanyID != companyID {
			continue
		}
		if status != "" && req.Status != status {
			continue
		}
		if leaveTypeIDStr != "" {
			ltID, err := uuid.Parse(leaveTypeIDStr)
			if err == nil && req.LeaveTypeID != ltID {
				continue
			}
		}
		filteredRequests = append(filteredRequests, req)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"requests":    filteredRequests,
			"total_count": len(filteredRequests),
			"start_date":  startDate,
			"end_date":    endDate,
			"status":      status,
		},
	})
}

func (h *LeaveRequestHandler) ApproveLeave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	approvedBy, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:request:approve") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ApproveRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.ApprovedBy != uuid.Nil {
		approvedBy = req.ApprovedBy
	}

	leaveRequest, err := h.requestService.ApproveLeave(ctx, requestID, approvedBy)
	if err != nil {
		h.logger.Error("Failed to approve leave request",
			zap.String("leave_request_id", requestID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to approve leave request")
		return
	}

	// ✅ Apply scheduling overrides for approved leave
	leaveData := &scheduling.LeaveScheduleData{
		LeaveRequestID: leaveRequest.LeaveRequestID,
		UserID:         leaveRequest.UserID,
		CompanyID:      leaveRequest.CompanyID,
		StartDate:      leaveRequest.StartDate,
		EndDate:        leaveRequest.EndDate,
	}
	if err := h.schedulingService.ApplyApprovedLeave(ctx, leaveData, "user", approvedBy); err != nil {
		h.logger.Warn(
			"Leave approved but scheduling override failed",
			zap.String("leave_request_id", leaveRequest.LeaveRequestID.String()),
			zap.Error(err),
		)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaveRequest,
		"message": "Leave request approved successfully",
	})
}

func (h *LeaveRequestHandler) RejectLeave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	rejectedBy, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:request:reject") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ApproveRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.ApprovedBy != uuid.Nil {
		rejectedBy = req.ApprovedBy
	}

	leaveRequest, err := h.requestService.RejectLeave(ctx, requestID, rejectedBy, req.Reason)
	if err != nil {
		h.logger.Error("Failed to reject leave request",
			zap.String("leave_request_id", requestID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to reject leave request")
		return
	}

	// 🔁 Rollback scheduling overrides
	leaveData := &scheduling.LeaveScheduleData{
		LeaveRequestID: leaveRequest.LeaveRequestID,
		UserID:         leaveRequest.UserID,
		CompanyID:      leaveRequest.CompanyID,
		StartDate:      leaveRequest.StartDate,
		EndDate:        leaveRequest.EndDate,
	}
	if err := h.schedulingService.RollbackCancelledLeave(ctx, leaveData, "user", rejectedBy); err != nil {
		h.logger.Warn(
			"Leave rejected but scheduling rollback failed",
			zap.String("leave_request_id", leaveRequest.LeaveRequestID.String()),
			zap.Error(err),
		)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaveRequest,
		"message": "Leave request rejected successfully",
	})
}

func (h *LeaveRequestHandler) CancelLeave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	requestIDStr := chi.URLParam(r, "requestID")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	cancelledBy, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	leaveRequest, err := h.requestService.CancelLeave(ctx, requestID, cancelledBy)
	if err != nil {
		h.logger.Error("Failed to cancel leave request",
			zap.String("leave_request_id", requestID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to cancel leave request")
		return
	}

	// 🔁 Rollback scheduling overrides
	leaveData := &scheduling.LeaveScheduleData{
		LeaveRequestID: leaveRequest.LeaveRequestID,
		UserID:         leaveRequest.UserID,
		CompanyID:      leaveRequest.CompanyID,
		StartDate:      leaveRequest.StartDate,
		EndDate:        leaveRequest.EndDate,
	}
	if err := h.schedulingService.RollbackCancelledLeave(ctx, leaveData, "user", cancelledBy); err != nil {
		h.logger.Warn(
			"Leave cancelled but scheduling rollback failed",
			zap.String("leave_request_id", leaveRequest.LeaveRequestID.String()),
			zap.Error(err),
		)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaveRequest,
		"message": "Leave request cancelled successfully",
	})
}

func (h *LeaveRequestHandler) GetPendingRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	approverID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:request:approve") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	requests, err := h.requestService.GetPendingRequests(ctx, companyID, approverID)
	if err != nil {
		h.logger.Error("Failed to get pending leave requests",
			zap.String("company_id", companyID.String()),
			zap.String("approver_id", approverID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve pending requests")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"pending_requests": requests,
			"total_count":      len(requests),
			"company_id":       companyID,
			"approver_id":      approverID,
		},
	})
}

// ---- Helper methods ----

func (h *LeaveRequestHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission checking
	return true
}

func (h *LeaveRequestHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *LeaveRequestHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}
