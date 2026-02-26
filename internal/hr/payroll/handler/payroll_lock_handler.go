package handler

import (
	"context" // added missing import
	"encoding/json"
	"errors"
	"net/http"
	"strings" // for error message matching
	"time"

	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollLockHandler handles HTTP requests for payroll period locks.
type PayrollLockHandler struct {
	lockService service.PayrollLockService
	logger      *zap.Logger
}

// NewPayrollLockHandler creates a new PayrollLockHandler.
func NewPayrollLockHandler(
	lockService service.PayrollLockService,
	logger *zap.Logger,
) *PayrollLockHandler {
	return &PayrollLockHandler{
		lockService: lockService,
		logger:      logger,
	}
}

// createLockRequest defines the expected body for creating a lock.
type createLockRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Reason      string    `json:"reason"`
}

// CreateLock handles POST /companies/{companyID}/payroll/locks
func (h *PayrollLockHandler) CreateLock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	// Get actor ID from admin session
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Decode request body
	var req createLockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Basic validation
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "period_start and period_end are required")
		return
	}
	if req.PeriodEnd.Before(req.PeriodStart) {
		h.respondWithError(w, http.StatusBadRequest, "period_end cannot be before period_start")
		return
	}

	// Call service
	err = h.lockService.LockPeriod(ctx, companyID, req.PeriodStart, req.PeriodEnd, actorID, req.Reason)
	if err != nil {
		// Map service errors to HTTP status codes based on error message content
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already locked") {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "payroll period locked successfully",
	})
}

// DeleteLock handles DELETE /companies/{companyID}/payroll/locks?start=...&end=...
func (h *PayrollLockHandler) DeleteLock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	// Get actor ID
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	if startStr == "" || endStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "start and end query parameters are required")
		return
	}

	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start format, use RFC3339")
		return
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end format, use RFC3339")
		return
	}

	// Call service
	err = h.lockService.UnlockPeriod(ctx, companyID, start, end, actorID)
	if err != nil {
		// The service currently does not return a specific "not found" error,
		// so we always return 400 for any error.
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll period unlocked successfully",
	})
}

// ListLocks handles GET /companies/{companyID}/payroll/locks?from=...&to=...
func (h *PayrollLockHandler) ListLocks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	// Parse optional from/to
	var from, to time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from format, use RFC3339")
			return
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to format, use RFC3339")
			return
		}
	}

	// Call service
	locks, err := h.lockService.ListLocks(ctx, companyID, from, to)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    locks,
	})
}

// getAdminActor extracts actor UUID from context, replicating the logic from the reference handler.
func (h *PayrollLockHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in context")
	}

	return userID, nil
}

// respondWithJSON writes a JSON response with the given status and data.
func (h *PayrollLockHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondWithError writes a JSON error response.
func (h *PayrollLockHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
