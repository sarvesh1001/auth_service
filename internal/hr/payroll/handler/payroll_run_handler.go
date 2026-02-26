package handler

import (
	"context" // added missing import
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollRunHandler handles HTTP requests for payroll run operations.
type PayrollRunHandler struct {
	engineService service.PayrollEngineService
	lockService   service.PayrollLockService
	logger        *zap.Logger
}

// NewPayrollRunHandler creates a new PayrollRunHandler.
func NewPayrollRunHandler(
	engineService service.PayrollEngineService,
	lockService service.PayrollLockService,
	logger *zap.Logger,
) *PayrollRunHandler {
	return &PayrollRunHandler{
		engineService: engineService,
		lockService:   lockService,
		logger:        logger.Named("payroll_run_handler"),
	}
}

// CreateRunRequest represents the request body for creating a payroll run.
type CreateRunRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

// CreateRunResponse represents the response after creating a payroll run.
type CreateRunResponse struct {
	RunID       uuid.UUID `json:"run_id"`
	CompanyID   uuid.UUID `json:"company_id"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// MarkRunAsPaidRequest represents the request body for marking a run as paid.
type MarkRunAsPaidRequest struct {
	PaidAt time.Time `json:"paid_at"`
}

// CreateRun handles POST /companies/{companyID}/payroll/runs
// TODO: This endpoint requires a CreateRun method on PayrollEngineService.
// Currently returns 501 Not Implemented as a placeholder.
func (h *PayrollRunHandler) CreateRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req CreateRunRequest
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

	run, err := h.engineService.CreateRun(
		ctx,
		companyID,
		req.PeriodStart,
		req.PeriodEnd,
		actorID,
	)
	if err != nil {
		h.logger.Error("failed to create payroll run", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := CreateRunResponse{
		RunID:       run.PayrollRunID,
		CompanyID:   run.CompanyID,
		PeriodStart: run.PeriodStart,
		PeriodEnd:   run.PeriodEnd,
		Status:      run.Status,
		CreatedAt:   run.CreatedAt,
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// InitializeRun handles POST /companies/{companyID}/payroll/runs/{runID}/initialize
func (h *PayrollRunHandler) InitializeRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and ignore companyID because the service method doesn't need it.
	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.engineService.InitializeRun(ctx, runID, actorID); err != nil {
		h.logger.Error("failed to initialize payroll run", zap.String("run_id", runID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run initialized",
	})
}

// ExecuteRun handles POST /companies/{companyID}/payroll/runs/{runID}/execute
func (h *PayrollRunHandler) ExecuteRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and ignore companyID because the service method doesn't need it.
	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.engineService.ExecuteRun(ctx, runID, actorID); err != nil {
		h.logger.Error("failed to execute payroll run", zap.String("run_id", runID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run execution completed",
	})
}

// ApproveRun handles POST /companies/{companyID}/payroll/runs/{runID}/approve
func (h *PayrollRunHandler) ApproveRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and ignore companyID because the service method doesn't need it.
	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.engineService.ApproveRun(ctx, runID, actorID); err != nil {
		h.logger.Error("failed to approve payroll run", zap.String("run_id", runID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run approved",
	})
}

// MarkRunAsPaid handles POST /companies/{companyID}/payroll/runs/{runID}/mark-paid
func (h *PayrollRunHandler) MarkRunAsPaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and ignore companyID because the service method doesn't need it.
	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req MarkRunAsPaidRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PaidAt.IsZero() {
		req.PaidAt = time.Now().UTC()
	}

	if err := h.engineService.MarkRunAsPaid(ctx, runID, actorID, req.PaidAt); err != nil {
		h.logger.Error("failed to mark payroll run as paid", zap.String("run_id", runID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run marked as paid",
	})
}

// CancelRun handles POST /companies/{companyID}/payroll/runs/{runID}/cancel
func (h *PayrollRunHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and ignore companyID because the service method doesn't need it.
	_, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.engineService.CancelRun(ctx, runID, actorID); err != nil {
		h.logger.Error("failed to cancel payroll run", zap.String("run_id", runID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payroll run cancelled",
	})
}

// getActorID extracts the actor UUID from the request context.
// It assumes that the auth middleware has set "session_type" and "user_id".
func (h *PayrollRunHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
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

// respondWithJSON writes a JSON response.
func (h *PayrollRunHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondWithError writes an error response in JSON format.
func (h *PayrollRunHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
