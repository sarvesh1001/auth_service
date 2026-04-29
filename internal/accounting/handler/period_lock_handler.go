package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type PeriodLockHandler struct {
	periodLockService service.PeriodLockService
	logger            *zap.Logger
}

func NewPeriodLockHandler(pls service.PeriodLockService, logger *zap.Logger) *PeriodLockHandler {
	return &PeriodLockHandler{
		periodLockService: pls,
		logger:            logger.Named("period_lock_handler"),
	}
}

type lockPeriodRequest struct {
	Reason string `json:"reason"`
}

// LockPeriod POST /companies/{companyID}/periods/{fiscalYear}/{period}/lock
func (h *PeriodLockHandler) LockPeriod(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	fiscalYear, err := strconv.Atoi(chi.URLParam(r, "fiscalYear"))
	if err != nil || fiscalYear < 2000 {
		h.respondWithError(w, http.StatusBadRequest, "invalid fiscal year")
		return
	}

	period, err := strconv.Atoi(chi.URLParam(r, "period"))
	if err != nil || period < 1 || period > 12 {
		h.respondWithError(w, http.StatusBadRequest, "period must be between 1 and 12")
		return
	}

	userID, err := h.getUserID(r.Context())
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req lockPeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.periodLockService.LockPeriod(r.Context(), companyID, fiscalYear, period, &userID, req.Reason); err != nil {
		h.logger.Error("failed to lock period", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "period locked successfully",
	})
}

// UnlockPeriod DELETE /companies/{companyID}/periods/{fiscalYear}/{period}/lock
func (h *PeriodLockHandler) UnlockPeriod(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	fiscalYear, err := strconv.Atoi(chi.URLParam(r, "fiscalYear"))
	if err != nil || fiscalYear < 2000 {
		h.respondWithError(w, http.StatusBadRequest, "invalid fiscal year")
		return
	}

	period, err := strconv.Atoi(chi.URLParam(r, "period"))
	if err != nil || period < 1 || period > 12 {
		h.respondWithError(w, http.StatusBadRequest, "period must be between 1 and 12")
		return
	}

	userID, err := h.getUserID(r.Context())
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req lockPeriodRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // optional reason

	if err := h.periodLockService.UnlockPeriod(r.Context(), companyID, fiscalYear, period, &userID, req.Reason); err != nil {
		h.logger.Error("failed to unlock period", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "period unlocked successfully",
	})
}

// GetPeriodLock GET /companies/{companyID}/periods/{fiscalYear}/{period}/lock
func (h *PeriodLockHandler) GetPeriodLock(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	fiscalYear, err := strconv.Atoi(chi.URLParam(r, "fiscalYear"))
	if err != nil || fiscalYear < 2000 {
		h.respondWithError(w, http.StatusBadRequest, "invalid fiscal year")
		return
	}

	period, err := strconv.Atoi(chi.URLParam(r, "period"))
	if err != nil || period < 1 || period > 12 {
		h.respondWithError(w, http.StatusBadRequest, "period must be between 1 and 12")
		return
	}

	lock, err := h.periodLockService.GetPeriodLock(r.Context(), companyID, fiscalYear, period)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "lock not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    lock,
	})
}

// ListPeriodLocks GET /companies/{companyID}/periods/locks
func (h *PeriodLockHandler) ListPeriodLocks(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Parse query filters
	filter := repository.PeriodLockFilter{CompanyID: companyID}
	if fyStr := r.URL.Query().Get("fiscal_year"); fyStr != "" {
		fy, _ := strconv.Atoi(fyStr)
		filter.FiscalYear = &fy
	}
	if pStr := r.URL.Query().Get("period"); pStr != "" {
		p, _ := strconv.Atoi(pStr)
		filter.Period = &p
	}
	if lockedStr := r.URL.Query().Get("is_locked"); lockedStr != "" {
		locked := lockedStr == "true"
		filter.IsLocked = &locked
	}

	pagination := service.Pagination{
		Limit:  h.getIntQueryParam(r, "limit", 50),
		Offset: h.getIntQueryParam(r, "offset", 0),
	}
	sort := repository.Sort{
		Field:     r.URL.Query().Get("sort_by"),
		Direction: r.URL.Query().Get("sort_dir"),
	}

	locks, total, err := h.periodLockService.ListPeriodLocks(r.Context(), filter, pagination, sort)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to list locks")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  locks,
			"total":  total,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

// ========== Helper Methods ==========

func (h *PeriodLockHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PeriodLockHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *PeriodLockHandler) getUserID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *PeriodLockHandler) getIntQueryParam(r *http.Request, key string, defaultValue int) int {
	if val := r.URL.Query().Get(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i >= 0 {
			return i
		}
	}
	return defaultValue
}
