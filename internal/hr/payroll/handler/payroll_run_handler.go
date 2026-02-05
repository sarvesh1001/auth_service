package handler

import (
	"net/http"
	"strconv"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
	"auth-service/internal/util"

	"encoding/json"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PayrollRunHandler struct {
	runService service.PayrollRunService
	logger     *zap.Logger
}

func NewPayrollRunHandler(
	runService service.PayrollRunService,
	logger *zap.Logger,
) *PayrollRunHandler {
	return &PayrollRunHandler{
		runService: runService,
		logger:     logger,
	}
}

// CreatePayrollRunRequest represents request to create payroll run
type CreatePayrollRunRequest struct {
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

// CalculatePayrollRequest represents request to calculate payroll
type CalculatePayrollRequest struct {
	ActorID uuid.UUID `json:"actor_id"`
}

// ApprovePayrollRequest represents request to approve payroll
type ApprovePayrollRequest struct {
	ApprovedBy uuid.UUID `json:"approved_by"`
}

// PayPayrollRequest represents request to mark payroll as paid
type PayPayrollRequest struct {
	PaidBy uuid.UUID `json:"paid_by"`
}

func (h *PayrollRunHandler) CreatePayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req CreatePayrollRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate period
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "Period start and end are required")
		return
	}
	if req.PeriodStart.After(req.PeriodEnd) {
		h.respondWithError(w, http.StatusBadRequest, "Period start cannot be after period end")
		return
	}

	// Create payroll run
	run, err := h.runService.CreatePayrollRun(ctx, companyID, req.PeriodStart, req.PeriodEnd, req.CreatedBy)
	if err != nil {
		h.logger.Error("Failed to create payroll run",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create payroll run")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    run,
		"message": "Payroll run created successfully",
	})
}

func (h *PayrollRunHandler) CalculatePayroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	var req CalculatePayrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate actor
	if req.ActorID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Actor ID is required")
		return
	}

	// Calculate payroll
	if err := h.runService.CalculatePayroll(ctx, runID, req.ActorID); err != nil {
		h.logger.Error("Failed to calculate payroll",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))

		status := http.StatusInternalServerError
		if err.Error() == "payroll run must be in draft status" {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll calculation completed successfully",
	})
}

func (h *PayrollRunHandler) ApprovePayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	var req ApprovePayrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ApprovedBy == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Approved by is required")
		return
	}

	// Approve payroll run
	if err := h.runService.ApprovePayrollRun(ctx, runID, req.ApprovedBy); err != nil {
		h.logger.Error("Failed to approve payroll run",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))

		status := http.StatusInternalServerError
		if err.Error() == "payroll run must be in calculated status" {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll run approved successfully",
	})
}

func (h *PayrollRunHandler) PayPayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	var req PayPayrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PaidBy == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Paid by is required")
		return
	}

	// Mark payroll as paid
	if err := h.runService.PayPayrollRun(ctx, runID, req.PaidBy); err != nil {
		h.logger.Error("Failed to mark payroll as paid",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))

		status := http.StatusInternalServerError
		if err.Error() == "payroll run must be in approved status" {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll marked as paid successfully",
	})
}

func (h *PayrollRunHandler) GetPayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	// Get payroll run
	run, err := h.runService.GetPayrollRun(ctx, runID)
	if err != nil {
		h.logger.Error("Failed to get payroll run",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get payroll run")
		return
	}

	if run == nil {
		h.respondWithError(w, http.StatusNotFound, "Payroll run not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    run,
	})
}

func (h *PayrollRunHandler) ListPayrollRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Parse query parameters
	status := r.URL.Query().Get("status")
	page := parseInt(r.URL.Query().Get("page"), 1)
	pageSize := parseInt(r.URL.Query().Get("page_size"), 50)

	// Parse date filters
	var periodStart, periodEnd *time.Time
	if startStr := r.URL.Query().Get("period_start"); startStr != "" {
		if t, err := time.Parse("2006-01-02", startStr); err == nil {
			periodStart = &t
		}
	}
	if endStr := r.URL.Query().Get("period_end"); endStr != "" {
		if t, err := time.Parse("2006-01-02", endStr); err == nil {
			periodEnd = &t
		}
	}

	// Build filter
	filter := models.PayrollRunFilter{
		CompanyID:   companyID,
		Page:        page,
		PageSize:    pageSize,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}
	if status != "" {
		filter.Status = &status
	}

	// List payroll runs
	runs, total, err := h.runService.ListPayrollRuns(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list payroll runs",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list payroll runs")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"runs":      runs,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
			"has_more":  total > int64(page*pageSize),
		},
	})
}

func (h *PayrollRunHandler) GetRunSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	// Get run summary
	summary, err := h.runService.GetRunSummary(ctx, runID)
	if err != nil {
		h.logger.Error("Failed to get payroll run summary",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get payroll run summary")
		return
	}

	if summary == nil {
		h.respondWithError(w, http.StatusNotFound, "Payroll run summary not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

func (h *PayrollRunHandler) DeletePayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	// Delete payroll run
	if err := h.runService.DeletePayrollRun(ctx, runID); err != nil {
		h.logger.Error("Failed to delete payroll run",
			util.String("run_id", runID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))

		status := http.StatusInternalServerError
		if err.Error() == "can only delete draft payroll runs" {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll run deleted successfully",
	})
}

// Helper methods
func (h *PayrollRunHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *PayrollRunHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func parseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	result, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return result
}
