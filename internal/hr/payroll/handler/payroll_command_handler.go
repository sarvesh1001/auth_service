package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PayrollCommandHandler struct {
	engine service.PayrollEngineService
	logger *zap.Logger
}

func NewPayrollCommandHandler(
	engine service.PayrollEngineService,
	logger *zap.Logger,
) *PayrollCommandHandler {
	return &PayrollCommandHandler{
		engine: engine,
		logger: logger.Named("payroll_command_handler"),
	}
}

type createRunRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

type reprocessRequest struct {
	Force bool `json:"force"`
}

// CREATE RUN
// POST /companies/{companyID}/payroll/runs
func (h *PayrollCommandHandler) CreateRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, _ := uuid.Parse(r.Context().Value("user_id").(string))

	// Your engine expects (ctx, companyID, actorID)
	err = h.engine.InitializeRun(ctx, companyID, actorID)
	if err != nil {
		h.logger.Error("initialize run failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "payroll run initialized",
	})
}

// EXECUTE RUN
// POST /companies/{companyID}/payroll/runs/{runID}/execute
func (h *PayrollCommandHandler) ExecuteRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, _ := uuid.Parse(r.Context().Value("user_id").(string))

	if err := h.engine.ExecuteRun(ctx, runID, actorID); err != nil {
		h.logger.Error("execute run failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run execution started",
	})
}

// APPROVE RUN
// POST /companies/{companyID}/payroll/runs/{runID}/approve
func (h *PayrollCommandHandler) ApproveRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, _ := uuid.Parse(r.Context().Value("user_id").(string))

	if err := h.engine.ApproveRun(ctx, runID, actorID); err != nil {
		h.logger.Error("approve failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run approved",
	})
}

// CANCEL RUN
// POST /companies/{companyID}/payroll/runs/{runID}/cancel
func (h *PayrollCommandHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, _ := uuid.Parse(r.Context().Value("user_id").(string))

	if err := h.engine.CancelRun(ctx, runID, actorID); err != nil {
		h.logger.Error("cancel failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run cancelled",
	})
}

// REPROCESS EMPLOYEE
// POST /companies/{companyID}/payroll/runs/{runID}/employees/{userID}/reprocess
func (h *PayrollCommandHandler) ReprocessEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid user id")
		return
	}

	actorID, _ := uuid.Parse(r.Context().Value("user_id").(string))

	var req reprocessRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Your engine expects (ctx, runID, userID, actorID, force)
	if err := h.engine.ReprocessEmployee(ctx, runID, userID, actorID, req.Force); err != nil {
		h.logger.Error("reprocess failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "employee reprocessed",
	})
}

// RESPONSE HELPERS
func (h *PayrollCommandHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *PayrollCommandHandler) respondErr(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
