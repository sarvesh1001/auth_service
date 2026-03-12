package handler

import (
	"auth-service/internal/hr/payroll/service"
	"context"
	"encoding/json"
	"net/http"
	"time"

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

// Request/Response types
type createRunRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

type reprocessRequest struct {
	ReflectLatestAdjustments bool `json:"reflect_latest_adjustments"` // was "force"
}

type markPaidRequest struct {
	PaidAt time.Time `json:"paid_at"`
}

// ---------------------------------------------------------------------
// CREATE DRAFT RUN
// POST /companies/{companyID}/payroll/runs
func (h *PayrollCommandHandler) CreateRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid company id")
		return
	}

	var req createRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondErr(w, http.StatusBadRequest, "period_start and period_end are required")
		return
	}
	if req.PeriodEnd.Before(req.PeriodStart) {
		h.respondErr(w, http.StatusBadRequest, "period_end cannot be before period_start")
		return
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	run, err := h.engine.CreateRun(ctx, companyID, req.PeriodStart, req.PeriodEnd, actorID)
	if err != nil {
		h.logger.Error("create run failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, run)
}

// ---------------------------------------------------------------------
// INITIALIZE RUN (transition from draft to processing)
// POST /companies/{companyID}/payroll/runs/{runID}/initialize
func (h *PayrollCommandHandler) InitializeRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	if err := h.engine.InitializeRun(ctx, runID, actorID); err != nil {
		h.logger.Error("initialize run failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run initialized",
	})
}

// ---------------------------------------------------------------------
// EXECUTE RUN (asynchronous processing)
// POST /companies/{companyID}/payroll/runs/{runID}/execute
func (h *PayrollCommandHandler) ExecuteRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

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

// ---------------------------------------------------------------------
// APPROVE RUN
// POST /companies/{companyID}/payroll/runs/{runID}/approve
func (h *PayrollCommandHandler) ApproveRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

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

// ---------------------------------------------------------------------
// MARK RUN AS PAID
// POST /companies/{companyID}/payroll/runs/{runID}/mark-paid
func (h *PayrollCommandHandler) MarkRunAsPaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	var req markPaidRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PaidAt.IsZero() {
		req.PaidAt = time.Now().UTC() // default to now if not provided
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	if err := h.engine.MarkRunAsPaid(ctx, runID, actorID, req.PaidAt); err != nil {
		h.logger.Error("mark as paid failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run marked as paid",
	})
}

// ---------------------------------------------------------------------
// CANCEL RUN (only draft)
// DELETE /companies/{companyID}/payroll/runs/{runID}
func (h *PayrollCommandHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

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

// ---------------------------------------------------------------------
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

	actorID := getUserIDFromContext(r.Context())
	if actorID == uuid.Nil {
		h.respondErr(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	var req reprocessRequest
	// If body is empty, default to false
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.engine.ReprocessEmployee(ctx, runID, userID, actorID, req.ReflectLatestAdjustments); err != nil {
		h.logger.Error("reprocess failed", zap.Error(err))
		h.respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "employee reprocessed",
	})
}

// ---------------------------------------------------------------------
// GET RUN EXECUTION STATUS
// GET /companies/{companyID}/payroll/runs/{runID}/status
func (h *PayrollCommandHandler) GetRunExecutionStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondErr(w, http.StatusBadRequest, "invalid run id")
		return
	}

	status, err := h.engine.GetRunExecutionStatus(ctx, runID)
	if err != nil {
		h.logger.Error("get execution status failed", zap.Error(err))
		h.respondErr(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, status)
}

// ---------------------------------------------------------------------
// Helpers
func getUserIDFromContext(ctx context.Context) uuid.UUID {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil
	}
	switch v := val.(type) {
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return uuid.Nil
		}
		return id
	case uuid.UUID:
		return v
	default:
		return uuid.Nil
	}
}

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
