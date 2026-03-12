package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

// EmployeeFineHandler handles HTTP requests for employee fines.
type EmployeeFineHandler struct {
	fineService service.EmployeeFineService
	logger      *zap.Logger
}

// NewEmployeeFineHandler creates a new employee fine handler.
func NewEmployeeFineHandler(fineService service.EmployeeFineService, logger *zap.Logger) *EmployeeFineHandler {
	return &EmployeeFineHandler{
		fineService: fineService,
		logger:      logger,
	}
}

// ---------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------

type createFineRequest struct {
	UserID        string    `json:"user_id"`
	FineAmount    float64   `json:"fine_amount"`
	Reason        string    `json:"reason"`
	FineDate      time.Time `json:"fine_date"`
	ComponentCode *string   `json:"component_code,omitempty"` // added
	Category      *string   `json:"category,omitempty"`
	Reference     *string   `json:"reference,omitempty"`
}

type updateFineRequest struct {
	FineAmount    *float64   `json:"fine_amount,omitempty"`
	Reason        *string    `json:"reason,omitempty"`
	FineDate      *time.Time `json:"fine_date,omitempty"`
	ComponentCode *string    `json:"component_code,omitempty"` // added
}

type bulkCreateFinesRequest struct {
	UserIDs       []string  `json:"user_ids"`
	FineAmount    float64   `json:"fine_amount"`
	Reason        string    `json:"reason"`
	FineDate      time.Time `json:"fine_date"`
	ComponentCode *string   `json:"component_code,omitempty"` // added
}

type bulkDeleteUnprocessedRequest struct {
	FineIDs []string `json:"fine_ids"`
}

type markFineAsProcessedRequest struct {
	PayrollRunID string `json:"payroll_run_id"`
}

type lockFinesForPayrollRunRequest struct {
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
	PayrollRunID string    `json:"payroll_run_id"`
}

// ---------------------------------------------------------------------
// Create Fine (POST /companies/{companyID}/employees/fines)
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) CreateFine(w http.ResponseWriter, r *http.Request) {
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

	var req createFineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	input := service.CreateEmployeeFineInput{
		CompanyID:     companyID,
		UserID:        userID,
		FineAmount:    req.FineAmount,
		Reason:        req.Reason,
		FineDate:      req.FineDate,
		ComponentCode: req.ComponentCode, // added
		Category:      req.Category,
		Reference:     req.Reference,
		CreatedBy:     actorID,
	}

	fine, err := h.fineService.CreateFine(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    fine,
	})
}

// ---------------------------------------------------------------------
// Update Fine (PUT /companies/{companyID}/employees/fines/{fineID})
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) UpdateFine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	fineID, err := uuid.Parse(chi.URLParam(r, "fineID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fine id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateFineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FineAmount == nil && req.Reason == nil && req.FineDate == nil && req.ComponentCode == nil {
		h.respondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	input := service.UpdateEmployeeFineInput{
		FineID:        fineID,
		CompanyID:     companyID,
		FineAmount:    req.FineAmount,
		Reason:        req.Reason,
		FineDate:      req.FineDate,
		ComponentCode: req.ComponentCode, // added
		UpdatedBy:     actorID,
	}

	fine, err := h.fineService.UpdateFine(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fine,
	})
}

// ---------------------------------------------------------------------
// Delete Fine (DELETE /companies/{companyID}/employees/fines/{fineID})
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) DeleteFine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	fineID, err := uuid.Parse(chi.URLParam(r, "fineID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fine id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.fineService.DeleteFine(ctx, companyID, fineID, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "fine deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Bulk Create Fines (POST /companies/{companyID}/employees/fines/bulk)
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) BulkCreateFines(w http.ResponseWriter, r *http.Request) {
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

	var req bulkCreateFinesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.UserIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one user_id required")
		return
	}

	userIDs := make([]uuid.UUID, 0, len(req.UserIDs))
	for i, idStr := range req.UserIDs {
		uid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id at index "+strconv.Itoa(i))
			return
		}
		userIDs = append(userIDs, uid)
	}

	input := service.BulkCreateEmployeeFineInput{
		CompanyID:     companyID,
		UserIDs:       userIDs,
		FineAmount:    req.FineAmount,
		Reason:        req.Reason,
		FineDate:      req.FineDate,
		ComponentCode: req.ComponentCode, // added
		CreatedBy:     actorID,
	}

	fines, err := h.fineService.BulkCreateFines(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    fines,
	})
}

// ---------------------------------------------------------------------
// Bulk Delete Unprocessed Fines (DELETE /companies/{companyID}/employees/fines/bulk/unprocessed)
// Body contains fine_ids array.
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) BulkDeleteUnprocessed(w http.ResponseWriter, r *http.Request) {
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

	var req bulkDeleteUnprocessedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.FineIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "fine_ids array required")
		return
	}

	fineIDs := make([]uuid.UUID, 0, len(req.FineIDs))
	for i, idStr := range req.FineIDs {
		fid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid fine_id at index "+strconv.Itoa(i))
			return
		}
		fineIDs = append(fineIDs, fid)
	}

	err = h.fineService.BulkDeleteUnprocessed(ctx, companyID, fineIDs, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "fines deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Mark Fine as Processed (PUT /companies/{companyID}/employees/fines/{fineID}/process)
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) MarkFineAsProcessed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	fineID, err := uuid.Parse(chi.URLParam(r, "fineID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fine id")
		return
	}

	var req markFineAsProcessedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	payrollRunID, err := uuid.Parse(req.PayrollRunID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payroll_run_id")
		return
	}

	err = h.fineService.MarkFineAsProcessed(ctx, fineID, payrollRunID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "fine marked as processed",
	})
}

// ---------------------------------------------------------------------
// Lock Fines for Payroll Run (POST /companies/{companyID}/payroll-runs/fines/lock)
// This is typically used by payroll processing internally.
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) LockFinesForPayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	var req lockFinesForPayrollRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	payrollRunID, err := uuid.Parse(req.PayrollRunID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payroll_run_id")
		return
	}

	fines, err := h.fineService.LockFinesForPayrollRun(ctx, companyID, req.PeriodStart, req.PeriodEnd, payrollRunID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fines,
	})
}

// ---------------------------------------------------------------------
// Get Fine by ID (GET /companies/{companyID}/employees/fines/{fineID})
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) GetFineByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	fineID, err := uuid.Parse(chi.URLParam(r, "fineID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fine id")
		return
	}

	fine, err := h.fineService.GetFineByID(ctx, companyID, fineID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if fine == nil {
		h.respondWithError(w, http.StatusNotFound, "fine not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fine,
	})
}

// ---------------------------------------------------------------------
// List Fines (GET /companies/{companyID}/employees/fines)
// Supports filtering by user_id, is_processed, payroll_run_id, date range, pagination.
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) ListFines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	filter := models.EmployeeFineFilter{
		CompanyID: companyID,
	}

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err == nil {
			filter.UserID = &uid
		}
	}
	if isProcessedStr := r.URL.Query().Get("is_processed"); isProcessedStr != "" {
		isProcessed, err := strconv.ParseBool(isProcessedStr)
		if err == nil {
			filter.IsProcessed = &isProcessed
		}
	}
	if payrollRunIDStr := r.URL.Query().Get("payroll_run_id"); payrollRunIDStr != "" {
		pid, err := uuid.Parse(payrollRunIDStr)
		if err == nil {
			filter.PayrollRunID = &pid
		}
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		from, err := time.Parse("2006-01-02", fromStr)
		if err == nil {
			filter.FromDate = &from
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		to, err := time.Parse("2006-01-02", toStr)
		if err == nil {
			filter.ToDate = &to
		}
	}
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		page, err := strconv.Atoi(pageStr)
		if err == nil && page > 0 {
			filter.Page = page
		}
	}
	if sizeStr := r.URL.Query().Get("page_size"); sizeStr != "" {
		size, err := strconv.Atoi(sizeStr)
		if err == nil && size > 0 {
			filter.PageSize = size
		}
	}

	fines, total, err := h.fineService.ListFines(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list fines", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fines,
		"total":   total,
		"page":    filter.Page,
		"size":    filter.PageSize,
	})
}

// ---------------------------------------------------------------------
// Get Employee Unprocessed Fines (GET /companies/{companyID}/employees/{userID}/fines/unprocessed)
// Query params: from_date, to_date (YYYY-MM-DD)
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) GetEmployeeUnprocessedFines(w http.ResponseWriter, r *http.Request) {
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

	fromStr := r.URL.Query().Get("from_date")
	toStr := r.URL.Query().Get("to_date")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from_date and to_date query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from_date, expected YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to_date, expected YYYY-MM-DD")
		return
	}

	fines, err := h.fineService.GetEmployeeUnprocessedFines(ctx, companyID, userID, from, to)
	if err != nil {
		h.logger.Error("failed to get employee unprocessed fines", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fines,
	})
}

// ---------------------------------------------------------------------
// Get Fine Summary by Employee (GET /companies/{companyID}/employees/{userID}/fines/summary)
// Query params: from_date, to_date
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) GetFineSummaryByEmployee(w http.ResponseWriter, r *http.Request) {
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

	fromStr := r.URL.Query().Get("from_date")
	toStr := r.URL.Query().Get("to_date")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from_date and to_date query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from_date, expected YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to_date, expected YYYY-MM-DD")
		return
	}

	summary, err := h.fineService.GetFineSummaryByEmployee(ctx, companyID, userID, from, to)
	if err != nil {
		h.logger.Error("failed to get fine summary by employee", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ---------------------------------------------------------------------
// Get Company Fine Summary (GET /companies/{companyID}/fines/summary)
// Query params: from_date, to_date
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) GetCompanyFineSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	fromStr := r.URL.Query().Get("from_date")
	toStr := r.URL.Query().Get("to_date")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from_date and to_date query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from_date, expected YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to_date, expected YYYY-MM-DD")
		return
	}

	summary, err := h.fineService.GetCompanyFineSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get company fine summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ---------------------------------------------------------------------
// Helper: get actor ID from context
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	return uuid.Parse(userIDStr)
}

// ---------------------------------------------------------------------
// Standard JSON responses
// ---------------------------------------------------------------------

func (h *EmployeeFineHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *EmployeeFineHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
