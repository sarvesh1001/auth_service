package handler

import (
	"auth-service/internal/hr/leave/service"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeaveQueryHandler struct {
	queryService service.LeaveQueryService
	logger       *zap.Logger
}

func NewLeaveQueryHandler(
	queryService service.LeaveQueryService,
	logger *zap.Logger,
) *LeaveQueryHandler {
	return &LeaveQueryHandler{
		queryService: queryService,
		logger:       logger.Named("leave_query_handler"),
	}
}

type CheckAvailabilityRequest struct {
	LeaveTypeID uuid.UUID `json:"leave_type_id"`
	Days        int       `json:"days"`
	StartDate   time.Time `json:"start_date"`
}

// =====================================================
// LEAVE BALANCE (ALL TYPES)
// =====================================================
func (h *LeaveQueryHandler) GetLeaveBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	asOfDate := time.Now().UTC()
	if v := r.URL.Query().Get("as_of"); v != "" {
		asOfDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (YYYY-MM-DD)")
			return
		}
	}

	balances, err := h.queryService.GetLeaveBalance(
		ctx,
		companyID,
		userID,
		asOfDate,
	)
	if err != nil {
		h.logger.Error("failed to get leave balance",
			zap.String("user_id", userID.String()),
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"balances":    balances,
			"user_id":     userID,
			"company_id":  companyID,
			"as_of_date":  asOfDate,
			"total_types": len(balances),
		},
	})
}

// =====================================================
// LEAVE BALANCE (BY TYPE)
// =====================================================
func (h *LeaveQueryHandler) GetLeaveBalanceByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	leaveTypeID, err := uuid.Parse(chi.URLParam(r, "leaveTypeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	asOfDate := time.Now().UTC()
	if v := r.URL.Query().Get("as_of"); v != "" {
		asOfDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (YYYY-MM-DD)")
			return
		}
	}

	balance, err := h.queryService.GetLeaveBalanceByType(
		ctx,
		companyID,
		userID,
		leaveTypeID,
		asOfDate,
	)
	if err != nil {
		h.logger.Error("failed to get leave balance by type",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    balance,
	})
}

// =====================================================
// USER LEAVE STATUS
// =====================================================
func (h *LeaveQueryHandler) IsUserOnLeave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	date := time.Now().UTC()
	if v := r.URL.Query().Get("date"); v != "" {
		date, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format")
			return
		}
	}

	onLeave, leaveRequest, err := h.queryService.IsUserOnLeave(
		ctx,
		companyID,
		userID,
		date,
	)
	if err != nil {
		h.logger.Error("failed to check leave status", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check leave status")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_on_leave":   onLeave,
			"leave_request": leaveRequest,
			"user_id":       userID,
			"company_id":    companyID,
			"checked_at":    time.Now().UTC(),
		},
	})
}

// =====================================================
// USER LEAVE HISTORY
// =====================================================
func (h *LeaveQueryHandler) GetUserLeaveHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now().AddDate(1, 0, 0)

	if v := r.URL.Query().Get("start_date"); v != "" {
		startDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date")
			return
		}
	}

	if v := r.URL.Query().Get("end_date"); v != "" {
		endDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date")
			return
		}
	}

	history, err := h.queryService.GetUserLeaveHistory(
		ctx,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("failed to get leave history", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"history":     history,
			"user_id":     userID,
			"company_id":  companyID,
			"start_date":  startDate,
			"end_date":    endDate,
			"total_count": len(history),
		},
	})
}

// =====================================================
// LEAVE TRANSACTION HISTORY
// =====================================================
func (h *LeaveQueryHandler) GetLeaveTransactionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now().AddDate(1, 0, 0)

	if v := r.URL.Query().Get("start_date"); v != "" {
		startDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date")
			return
		}
	}

	if v := r.URL.Query().Get("end_date"); v != "" {
		endDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date")
			return
		}
	}

	transactions, err := h.queryService.GetLeaveTransactionHistory(
		ctx,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("failed to get transaction history", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transactions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transactions": transactions,
			"total_count":  len(transactions),
			"user_id":      userID,
			"company_id":   companyID,
		},
	})
}

// =====================================================
// LEAVE FORECAST
// =====================================================
func (h *LeaveQueryHandler) GetLeaveForecast(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	months := 12
	if v := r.URL.Query().Get("months"); v != "" {
		months, err = strconv.Atoi(v)
		if err != nil || months <= 0 {
			h.respondWithError(w, http.StatusBadRequest, "months must be positive")
			return
		}
	}

	forecast, err := h.queryService.GetLeaveForecast(ctx, userID, months)
	if err != nil {
		h.logger.Error("failed to get forecast", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate forecast")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    forecast,
	})
}

// =====================================================
// LEAVE UTILIZATION REPORT
// =====================================================
func (h *LeaveQueryHandler) GetLeaveUtilizationReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now()

	if v := r.URL.Query().Get("start_date"); v != "" {
		startDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date")
			return
		}
	}

	if v := r.URL.Query().Get("end_date"); v != "" {
		endDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date")
			return
		}
	}

	report, err := h.queryService.GetLeaveUtilizationReport(
		ctx,
		companyID,
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("failed to get utilization report", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate report")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    report,
	})
}

// =====================================================
// LEAVE AVAILABILITY
// =====================================================
func (h *LeaveQueryHandler) CheckLeaveAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.LeaveTypeID == uuid.Nil || req.Days <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "invalid request parameters")
		return
	}

	if req.StartDate.IsZero() {
		req.StartDate = time.Now().UTC()
	}

	ok, availableDays, err := h.queryService.CheckLeaveAvailability(
		ctx,
		companyID,
		userID,
		req.LeaveTypeID,
		req.Days,
		req.StartDate,
	)
	if err != nil {
		h.logger.Error("failed to check availability", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check availability")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_available":   ok,
			"available_days": availableDays,
		},
	})
}

// =====================================================
// HELPERS
// =====================================================
func (h *LeaveQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *LeaveQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
func (h *LeaveQueryHandler) GetLeaveBalanceForUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	asOfDate := time.Now().UTC()
	if v := r.URL.Query().Get("as_of"); v != "" {
		asOfDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (YYYY-MM-DD)")
			return
		}
	}

	balances, err := h.queryService.GetLeaveBalance(
		ctx,
		companyID,
		targetUserID,
		asOfDate,
	)
	if err != nil {
		h.logger.Error("failed to get leave balance for user",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch leave balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"user_id":    targetUserID,
			"company_id": companyID,
			"as_of":      asOfDate,
			"balances":   balances,
		},
	})
}
func (h *LeaveQueryHandler) GetLeaveBalanceForUserByType(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	leaveTypeID, err := uuid.Parse(chi.URLParam(r, "leaveTypeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	asOfDate := time.Now().UTC()
	if v := r.URL.Query().Get("as_of"); v != "" {
		asOfDate, err = time.Parse("2006-01-02", v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (YYYY-MM-DD)")
			return
		}
	}

	balance, err := h.queryService.GetLeaveBalanceByType(
		ctx,
		companyID,
		targetUserID,
		leaveTypeID,
		asOfDate,
	)
	if err != nil {
		h.logger.Error("failed to get leave balance by type for user",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch leave balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"user_id":       targetUserID,
			"company_id":    companyID,
			"leave_type_id": leaveTypeID,
			"as_of":         asOfDate,
			"balance":       balance,
		},
	})
}
