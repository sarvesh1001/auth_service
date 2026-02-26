package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/service"
)

// CompensationHandler handles HTTP requests for compensation related operations.
type CompensationHandler struct {
	compensationSvc service.CompensationService
	logger          *zap.Logger
}

// NewCompensationHandler creates a new CompensationHandler.
func NewCompensationHandler(compensationSvc service.CompensationService, logger *zap.Logger) *CompensationHandler {
	return &CompensationHandler{
		compensationSvc: compensationSvc,
		logger:          logger.Named("compensation_handler"),
	}
}

// ---------------------------------------------------------------------
// GET EMPLOYEE MONTHLY CTC
// ---------------------------------------------------------------------

type GetEmployeeSalaryResponse struct {
	MonthlyCTC float64 `json:"monthly_ctc"`
	AsOf       string  `json:"as_of"`
}

func (h *CompensationHandler) GetEmployeeSalary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	asOf := time.Now().UTC()
	if asOfStr := r.URL.Query().Get("as_of"); asOfStr != "" {
		parsed, err := time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid as_of format, use YYYY-MM-DD")
			return
		}
		asOf = parsed
	}

	ctc, err := h.compensationSvc.ResolveCTC(ctx, companyID, userID, asOf)
	if err != nil {
		h.logger.Error("failed to resolve CTC", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := GetEmployeeSalaryResponse{
		MonthlyCTC: ctc,
		AsOf:       asOf.Format("2006-01-02"),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// GET SALARY STRUCTURE SNAPSHOT
// ---------------------------------------------------------------------

func (h *CompensationHandler) GetSalarySnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	asOf := time.Now().UTC()
	if asOfStr := r.URL.Query().Get("as_of"); asOfStr != "" {
		parsed, err := time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid as_of format, use YYYY-MM-DD")
			return
		}
		asOf = parsed
	}

	snapshot, err := h.compensationSvc.ResolveSalaryStructure(ctx, companyID, userID, asOf)
	if err != nil {
		h.logger.Error("failed to resolve salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if snapshot == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nil,
			"message": "no active salary structure found",
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    snapshot,
	})
}

// ---------------------------------------------------------------------
// PREVIEW EARNINGS (Payroll Preview)
// ---------------------------------------------------------------------

type PreviewEarningsRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

func (h *CompensationHandler) PreviewEarnings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req PreviewEarningsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "period_start and period_end are required")
		return
	}

	if req.PeriodEnd.Before(req.PeriodStart) {
		h.respondWithError(w, http.StatusBadRequest, "period_end cannot be before period_start")
		return
	}

	totalDays := inclusiveDays(req.PeriodStart, req.PeriodEnd)

	earnings, err := h.compensationSvc.ResolveEarnings(
		ctx,
		companyID,
		userID,
		req.PeriodStart,
		req.PeriodEnd,
		totalDays,
	)
	if err != nil {
		h.logger.Error("failed to resolve earnings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    earnings,
	})
}

// ---------------------------------------------------------------------
// Helper: Inclusive Day Calculation (timezone-safe)
// ---------------------------------------------------------------------

func inclusiveDays(start, end time.Time) float64 {
	s := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	e := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	return float64(int(e.Sub(s).Hours()/24) + 1)
}

// ---------------------------------------------------------------------
// Response Helpers
// ---------------------------------------------------------------------

func (h *CompensationHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *CompensationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
