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
		logger:       logger,
	}
}

type CheckAvailabilityRequest struct {
	LeaveTypeID uuid.UUID `json:"leave_type_id"`
	Days        int       `json:"days"`
	StartDate   time.Time `json:"start_date"`
}

func (h *LeaveQueryHandler) GetLeaveBalance(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
	asOfStr := r.URL.Query().Get("as_of")
	var asOfDate time.Time
	if asOfStr != "" {
		asOfDate, err = time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
			return
		}
	} else {
		asOfDate = time.Now().UTC()
	}

	balances, err := h.queryService.GetLeaveBalance(ctx, userID, asOfDate)
	if err != nil {
		h.logger.Error("Failed to get leave balance",
			zap.String("user_id", userID.String()),
			zap.Time("as_of_date", asOfDate),
			zap.Error(err))
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

func (h *LeaveQueryHandler) GetLeaveBalanceByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	leaveTypeIDStr := chi.URLParam(r, "leaveTypeID")
	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	// Parse query parameters
	asOfStr := r.URL.Query().Get("as_of")
	var asOfDate time.Time
	if asOfStr != "" {
		asOfDate, err = time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
			return
		}
	} else {
		asOfDate = time.Now().UTC()
	}

	balance, err := h.queryService.GetLeaveBalanceByType(ctx, userID, leaveTypeID, asOfDate)
	if err != nil {
		h.logger.Error("Failed to get leave balance by type",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Time("as_of_date", asOfDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    balance,
	})
}

func (h *LeaveQueryHandler) IsUserOnLeave(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr != "" {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
			return
		}
	} else {
		date = time.Now().UTC()
	}

	onLeave, leaveRequest, err := h.queryService.IsUserOnLeave(ctx, companyID, userID, date)
	if err != nil {
		h.logger.Error("Failed to check if user is on leave",
			zap.String("user_id", userID.String()),
			zap.Time("date", date),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check leave status")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_on_leave":   onLeave,
			"leave_request": leaveRequest,
			"user_id":       userID,
			"date":          date,
			"company_id":    companyID,
			"checked_at":    time.Now().UTC(),
		},
	})
}

func (h *LeaveQueryHandler) GetUserLeaveHistory(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
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
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date format")
			return
		}
	} else {
		endDate = time.Now().AddDate(1, 0, 0) // Default: next year
	}

	history, err := h.queryService.GetUserLeaveHistory(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get user leave history",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave history")
		return
	}

	// Apply filters
	filteredHistory := make([]interface{}, 0)
	for _, record := range history {
		if record.CompanyID != companyID {
			continue
		}

		if status != "" && record.Status != status {
			continue
		}

		if leaveTypeIDStr != "" {
			leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
			if err == nil && record.LeaveTypeID != leaveTypeID {
				continue
			}
		}

		filteredHistory = append(filteredHistory, record)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"history":     filteredHistory,
			"total_count": len(filteredHistory),
			"user_id":     userID,
			"company_id":  companyID,
			"start_date":  startDate,
			"end_date":    endDate,
			"status":      status,
		},
	})
}

func (h *LeaveQueryHandler) GetLeaveTransactionHistory(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date format")
			return
		}
	} else {
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date format")
			return
		}
	} else {
		endDate = time.Now().AddDate(1, 0, 0) // Default: next year
	}

	transactions, err := h.queryService.GetLeaveTransactionHistory(ctx, userID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get leave transaction history",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transaction history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transactions": transactions,
			"total_count":  len(transactions),
			"user_id":      userID,
			"company_id":   companyID,
			"start_date":   startDate,
			"end_date":     endDate,
		},
	})
}

func (h *LeaveQueryHandler) GetLeaveForecast(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
	monthsStr := r.URL.Query().Get("months")
	months := 12 // Default: 12 months
	if monthsStr != "" {
		months, err = strconv.Atoi(monthsStr)
		if err != nil || months <= 0 {
			h.respondWithError(w, http.StatusBadRequest, "months must be a positive integer")
			return
		}
	}

	forecast, err := h.queryService.GetLeaveForecast(ctx, userID, months)
	if err != nil {
		h.logger.Error("Failed to get leave forecast",
			zap.String("user_id", userID.String()),
			zap.Int("months", months),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate leave forecast")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"forecast":     forecast,
			"user_id":      userID,
			"company_id":   companyID,
			"months":       months,
			"generated_at": time.Now().UTC(),
		},
	})
}

func (h *LeaveQueryHandler) GetLeaveUtilizationReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:report:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start date format")
			return
		}
	} else {
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}

	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end date format")
			return
		}
	} else {
		endDate = time.Now().AddDate(1, 0, 0) // Default: next year
	}

	report, err := h.queryService.GetLeaveUtilizationReport(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to get leave utilization report",
			zap.String("company_id", companyID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate utilization report")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"report":       report,
			"total_users":  len(report),
			"company_id":   companyID,
			"start_date":   startDate,
			"end_date":     endDate,
			"generated_at": time.Now().UTC(),
		},
	})
}

func (h *LeaveQueryHandler) CheckLeaveAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Parse query parameters or request body
	var req CheckAvailabilityRequest
	if r.Method == http.MethodGet {
		// Parse from query parameters
		leaveTypeIDStr := r.URL.Query().Get("leave_type_id")
		daysStr := r.URL.Query().Get("days")
		startDateStr := r.URL.Query().Get("start_date")

		if leaveTypeIDStr == "" {
			h.respondWithError(w, http.StatusBadRequest, "leave_type_id is required")
			return
		}

		req.LeaveTypeID, err = uuid.Parse(leaveTypeIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
			return
		}

		if daysStr == "" {
			h.respondWithError(w, http.StatusBadRequest, "days is required")
			return
		}

		req.Days, err = strconv.Atoi(daysStr)
		if err != nil || req.Days <= 0 {
			h.respondWithError(w, http.StatusBadRequest, "days must be a positive integer")
			return
		}

		if startDateStr != "" {
			req.StartDate, err = time.Parse("2006-01-02", startDateStr)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid start date format")
				return
			}
		} else {
			req.StartDate = time.Now().UTC()
		}
	} else {
		// Parse from request body for POST
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.LeaveTypeID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, "leave_type_id is required")
			return
		}

		if req.Days <= 0 {
			h.respondWithError(w, http.StatusBadRequest, "days must be greater than 0")
			return
		}

		if req.StartDate.IsZero() {
			req.StartDate = time.Now().UTC()
		}
	}

	available, availableDays, err := h.queryService.CheckLeaveAvailability(ctx, userID, req.LeaveTypeID, req.Days, req.StartDate)
	if err != nil {
		h.logger.Error("Failed to check leave availability",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", req.LeaveTypeID.String()),
			zap.Int("days", req.Days),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check leave availability")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_available":   available,
			"available_days": availableDays,
			"requested_days": req.Days,
			"user_id":        userID,
			"leave_type_id":  req.LeaveTypeID,
			"start_date":     req.StartDate,
			"checked_at":     time.Now().UTC(),
		},
	})
}

// Helper methods
func (h *LeaveQueryHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission checking
	return true
}

func (h *LeaveQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *LeaveQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
