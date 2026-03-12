package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollRunHandler handles HTTP requests for payroll run and component operations.
type PayrollRunHandler struct {
	engineService service.PayrollEngineService
	queryService  service.PayrollQueryService
	jobRepo       repository.PayrollJobRepository
	logger        *zap.Logger
}

// NewPayrollRunHandler creates a new PayrollRunHandler.
func NewPayrollRunHandler(
	engineService service.PayrollEngineService,
	queryService service.PayrollQueryService,
	jobRepo repository.PayrollJobRepository,
	logger *zap.Logger,
) *PayrollRunHandler {
	return &PayrollRunHandler{
		engineService: engineService,
		queryService:  queryService,
		jobRepo:       jobRepo,
		logger:        logger.Named("payroll_run_handler"),
	}
}

// ==================== Request/Response Models ====================

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

// CreateComponentRequest represents request body for creating a payroll component.
type CreateComponentRequest struct {
	ComponentCode    string `json:"component_code"`
	ComponentType    string `json:"component_type"`
	Description      string `json:"description"`
	IsTaxable        bool   `json:"is_taxable"`
	ContributionSide string `json:"contribution_side"`
}

// UpdateComponentRequest represents request body for updating a component.
type UpdateComponentRequest struct {
	Description      string `json:"description"`
	IsTaxable        bool   `json:"is_taxable"`
	IsActive         bool   `json:"is_active"`
	ContributionSide string `json:"contribution_side"`
}

// ==================== Payroll Run Handlers ====================

// CreateRun handles POST /companies/{companyID}/payroll/runs
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

	run, err := h.engineService.CreateRun(ctx, companyID, req.PeriodStart, req.PeriodEnd, actorID)
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

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	// Verify that the run belongs to the company
	if _, err := h.queryService.GetRunSummary(ctx, companyID, runID); err != nil {
		h.respondWithError(w, http.StatusNotFound, "payroll run not found")
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

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	// Verify ownership
	if _, err := h.queryService.GetRunSummary(ctx, companyID, runID); err != nil {
		h.respondWithError(w, http.StatusNotFound, "payroll run not found")
		return
	}

	// ActorID is still validated but not used in job creation (could be stored for audit later)
	_, err = h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Create a background job instead of executing directly
	job, err := h.jobRepo.Create(ctx, &models.CreatePayrollJobInput{
		CompanyID:    companyID,
		PayrollRunID: runID,
		MaxAttempts:  3,
	})
	if err != nil {
		h.logger.Error("failed to create payroll job",
			zap.String("run_id", runID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to queue payroll run")
		return
	}

	// Return 202 Accepted with job info
	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
		"message": "payroll run queued for execution",
		"data": map[string]interface{}{
			"job_id": job.JobID,
			"status": job.Status,
		},
	})
}

// ApproveRun handles POST /companies/{companyID}/payroll/runs/{runID}/approve
func (h *PayrollRunHandler) ApproveRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	// Verify ownership
	if _, err := h.queryService.GetRunSummary(ctx, companyID, runID); err != nil {
		h.respondWithError(w, http.StatusNotFound, "payroll run not found")
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

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	// Verify ownership
	if _, err := h.queryService.GetRunSummary(ctx, companyID, runID); err != nil {
		h.respondWithError(w, http.StatusNotFound, "payroll run not found")
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

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	// Verify ownership
	if _, err := h.queryService.GetRunSummary(ctx, companyID, runID); err != nil {
		h.respondWithError(w, http.StatusNotFound, "payroll run not found")
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

// ==================== Payroll Component Handlers ====================

// CreateComponent handles POST /companies/{companyID}/payroll/components
func (h *PayrollRunHandler) CreateComponent(w http.ResponseWriter, r *http.Request) {
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

	var req CreateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.CreateComponentInput{
		CompanyID:        companyID,
		ComponentCode:    req.ComponentCode,
		ComponentType:    req.ComponentType,
		Description:      req.Description,
		IsTaxable:        req.IsTaxable,
		ContributionSide: req.ContributionSide,
	}

	component, err := h.engineService.CreateComponent(ctx, input, actorID)
	if err != nil {
		h.logger.Error("failed to create component", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    component,
	})
}

// UpdateComponent handles PUT /companies/{companyID}/payroll/components/{componentCode}
func (h *PayrollRunHandler) UpdateComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	componentCode := chi.URLParam(r, "componentCode")

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req UpdateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.UpdateComponentInput{
		CompanyID:        companyID,
		ComponentCode:    componentCode,
		Description:      req.Description,
		IsTaxable:        req.IsTaxable,
		IsActive:         req.IsActive,
		ContributionSide: req.ContributionSide,
	}

	component, err := h.engineService.UpdateComponent(ctx, input, actorID)
	if err != nil {
		h.logger.Error("failed to update component", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    component,
	})
}

// DeactivateComponent handles DELETE /companies/{companyID}/payroll/components/{componentCode}
func (h *PayrollRunHandler) DeactivateComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	componentCode := chi.URLParam(r, "componentCode")

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.engineService.DeactivateComponent(ctx, companyID, componentCode, actorID)
	if err != nil {
		h.logger.Error("failed to deactivate component", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "component deactivated",
	})
}

// ListComponents handles GET /companies/{companyID}/payroll/components
func (h *PayrollRunHandler) ListComponents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	components, err := h.engineService.ListComponents(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to list components", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    components,
	})
}

// ==================== Helper Methods ====================

// getActorID extracts the actor UUID from the request context.
// It assumes that the auth middleware has set "user_id".
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
