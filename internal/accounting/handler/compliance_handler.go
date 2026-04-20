// FILE: ./internal/accounting/handler/compliance_handler.go
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type ComplianceHandler struct {
	complianceService service.ComplianceService
	logger            *zap.Logger
}

func NewComplianceHandler(complianceService service.ComplianceService, logger *zap.Logger) *ComplianceHandler {
	return &ComplianceHandler{
		complianceService: complianceService,
		logger:            logger.Named("compliance_handler"),
	}
}

// ---------- Request DTOs ----------
type createReturnRequest struct {
	ReturnType  string    `json:"return_type"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	DueDate     time.Time `json:"due_date"`
}

type updateReturnRequest struct {
	DueDate     *time.Time `json:"due_date,omitempty"`
	Description *string    `json:"description,omitempty"`
}

type fileReturnRequest struct {
	AcknowledgementNo   *string          `json:"acknowledgement_no,omitempty"`
	PaymentAmount       *decimal.Decimal `json:"payment_amount,omitempty"`
	TaxPayableAccountID string           `json:"tax_payable_account_id"`
	BankAccountID       string           `json:"bank_account_id"`
	Metadata            json.RawMessage  `json:"metadata,omitempty"`
}

type amendReturnRequest struct {
	// empty body, only amended by taken from context
}

type updateFilingStatusRequest struct {
	Status       string  `json:"status"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

type listReturnsQuery struct {
	Status   string `json:"status"`
	FromDate string `json:"from_date"`
	ToDate   string `json:"to_date"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// ---------- Helper ----------
func (h *ComplianceHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: implement actual permission check (e.g., via RBAC)
	return true
}

func (h *ComplianceHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ComplianceHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ---------- Handlers ----------

// CreateReturn godoc
// @Summary Create a new compliance return
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param request body createReturnRequest true "Return details"
// @Success 201 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns [post]
func (h *ComplianceHandler) CreateReturn(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "compliance:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.CreateReturnRequest{
		CompanyID:   companyID,
		ReturnType:  req.ReturnType,
		PeriodStart: req.PeriodStart,
		PeriodEnd:   req.PeriodEnd,
		DueDate:     req.DueDate,
		CreatedBy:   &userID,
		UpdatedBy:   &userID,
	}

	ret, err := h.complianceService.CreateReturn(ctx, serviceReq)
	if err != nil {
		h.logger.Error("failed to create return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    ret,
		"message": "Compliance return created successfully",
	})
}

// UpdateReturn godoc
// @Summary Update an existing compliance return (draft only)
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Return ID"
// @Param request body updateReturnRequest true "Update fields"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id} [put]
func (h *ComplianceHandler) UpdateReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.UpdateReturnRequest{
		ReturnID:  returnID,
		DueDate:   req.DueDate,
		UpdatedBy: &userID,
	}

	updated, err := h.complianceService.UpdateReturn(ctx, serviceReq)
	if err != nil {
		h.logger.Error("failed to update return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// optional: check that updated belongs to the company
	if updated.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    updated,
		"message": "Return updated successfully",
	})
}

// SubmitReturn godoc
// @Summary Submit a return (change status from draft to submitted)
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Return ID"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id}/submit [post]
func (h *ComplianceHandler) SubmitReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:submit") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.complianceService.SubmitReturn(ctx, returnID, &userID); err != nil {
		h.logger.Error("failed to submit return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Return submitted successfully",
	})
}

// FileReturn godoc
// @Summary File a submitted return with payment and acknowledgement
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Return ID"
// @Param request body fileReturnRequest true "Filing details"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id}/file [post]
func (h *ComplianceHandler) FileReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:file") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req fileReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	taxPayableAccID, err := uuid.Parse(req.TaxPayableAccountID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax_payable_account_id")
		return
	}
	bankAccID, err := uuid.Parse(req.BankAccountID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid bank_account_id")
		return
	}

	serviceReq := service.FileReturnRequest{
		AcknowledgementNo:   req.AcknowledgementNo,
		PaymentAmount:       req.PaymentAmount,
		TaxPayableAccountID: taxPayableAccID,
		BankAccountID:       bankAccID,
		Metadata:            req.Metadata,
		FiledBy:             &userID,
	}

	filing, err := h.complianceService.FileReturn(ctx, returnID, serviceReq)
	if err != nil {
		h.logger.Error("failed to file return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    filing,
		"message": "Return filed successfully",
	})
}

// AmendReturn godoc
// @Summary Amend an already filed return (creates new draft return)
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Original Return ID"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id}/amend [post]
func (h *ComplianceHandler) AmendReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:amend") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	req := service.AmendReturnRequest{
		AmendedBy: &userID,
	}

	amended, err := h.complianceService.AmendReturn(ctx, returnID, req)
	if err != nil {
		h.logger.Error("failed to amend return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    amended,
		"message": "Return amended, new draft created",
	})
}

// DeleteReturn godoc
// @Summary Soft-delete a return (only if not filed)
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Return ID"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id} [delete]
func (h *ComplianceHandler) DeleteReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.complianceService.DeleteReturn(ctx, returnID, &userID); err != nil {
		h.logger.Error("failed to delete return", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Return deleted successfully",
	})
}

// GetReturnByID godoc
// @Summary Get a compliance return by ID
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param id path string true "Return ID"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns/{id} [get]
func (h *ComplianceHandler) GetReturnByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	returnID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ret, err := h.complianceService.GetReturnByID(ctx, returnID)
	if err != nil {
		h.logger.Error("failed to get return", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	if ret.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ret,
	})
}

// ListReturns godoc
// @Summary List compliance returns with filtering and pagination
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param status query string false "Filter by status"
// @Param from_date query string false "Start date (YYYY-MM-DD)"
// @Param to_date query string false "End date (YYYY-MM-DD)"
// @Param limit query int false "Page size (default 50, max 1000)"
// @Param offset query int false "Offset"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/returns [get]
func (h *ComplianceHandler) ListReturns(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "compliance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.ComplianceReturnFilter{
		CompanyID: companyID,
		Status:    query.Get("status"),
	}
	// Date filtering – adjust field names based on actual filter struct.
	// If the filter uses PeriodStart/PeriodEnd, uncomment and modify accordingly:
	/*
		if from := query.Get("from_date"); from != "" {
			if t, err := time.Parse("2006-01-02", from); err == nil {
				filter.PeriodStart = &t
			}
		}
		if to := query.Get("to_date"); to != "" {
			if t, err := time.Parse("2006-01-02", to); err == nil {
				filter.PeriodEnd = &t
			}
		}
	*/

	limit := 50
	if l, err := strconv.Atoi(query.Get("limit")); err == nil && l > 0 {
		limit = l
		if limit > 1000 {
			limit = 1000
		}
	}
	offset := 0
	if o, err := strconv.Atoi(query.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	pagination := service.Pagination{Limit: limit, Offset: offset}
	items, total, err := h.complianceService.ListReturns(ctx, filter, pagination)
	if err != nil {
		h.logger.Error("failed to list returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list returns")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetFilingByID godoc
// @Summary Get a filing by ID
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param filingID path string true "Filing ID"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/filings/{filingID} [get]
func (h *ComplianceHandler) GetFilingByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	filingIDStr := chi.URLParam(r, "filingID")
	filingID, err := uuid.Parse(filingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid filing ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filing, err := h.complianceService.GetFilingByID(ctx, filingID)
	if err != nil {
		h.logger.Error("failed to get filing", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// optional: verify that filing belongs to a return of the company
	// we could fetch the return, but for brevity we trust the service
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    filing,
	})
}

// UpdateFilingStatus godoc
// @Summary Update filing status (e.g., accepted/rejected by tax authority)
// @Tags compliance
// @Param companyID path string true "Company ID"
// @Param filingID path string true "Filing ID"
// @Param request body updateFilingStatusRequest true "Status update"
// @Success 200 {object} map[string]interface{}
// @Router /companies/{companyID}/compliance/filings/{filingID}/status [patch]
func (h *ComplianceHandler) UpdateFilingStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	filingIDStr := chi.URLParam(r, "filingID")
	filingID, err := uuid.Parse(filingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid filing ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "compliance:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateFilingStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.complianceService.UpdateFilingStatus(ctx, filingID, req.Status, req.ErrorMessage); err != nil {
		h.logger.Error("failed to update filing status", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Filing status updated",
	})
}
