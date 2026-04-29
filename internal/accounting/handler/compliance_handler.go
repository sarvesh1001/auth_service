package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/shopspring/decimal"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/enums"
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

// ---------- Request DTOs (restored from original) ----------
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

type updateFilingStatusRequest struct {
	Status       string  `json:"status"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

// ---------- Helper: idempotency key from header ----------
func (h *ComplianceHandler) withIdempotencyKey(r *http.Request) context.Context {
	ctx := r.Context()
	key := r.Header.Get("Idempotency-Key")
	if key != "" {
		ctx = context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// ---------- Helper: timeout context ----------
func (h *ComplianceHandler) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}

// ---------- Response helpers (unchanged) ----------
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

// ---------- Stub permission (keep as is) ----------
func (h *ComplianceHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	return true
}

// ---------- CREATE RETURN ----------
func (h *ComplianceHandler) CreateReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

	// Validation
	if req.ReturnType == "" {
		h.respondWithError(w, http.StatusBadRequest, "return_type required")
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

	h.logger.Info("CreateReturn called",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)

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

// ---------- UPDATE RETURN ----------
func (h *ComplianceHandler) UpdateReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

// ---------- SUBMIT RETURN (with ownership check) ----------
func (h *ComplianceHandler) SubmitReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

	// Ownership check: fetch return first
	ret, err := h.complianceService.GetReturnByID(ctx, returnID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if ret.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
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

// ---------- FILE RETURN (with validation and ownership) ----------
func (h *ComplianceHandler) FileReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

	// Validate payment amount sign
	if req.PaymentAmount != nil && req.PaymentAmount.IsNegative() {
		h.respondWithError(w, http.StatusBadRequest, "payment_amount cannot be negative")
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

	// Ownership check
	ret, err := h.complianceService.GetReturnByID(ctx, returnID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if ret.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
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

// ---------- AMEND RETURN (with ownership check) ----------
func (h *ComplianceHandler) AmendReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

	// Ownership check
	ret, err := h.complianceService.GetReturnByID(ctx, returnID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if ret.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
		return
	}

	req := service.AmendReturnRequest{AmendedBy: &userID}
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

// ---------- DELETE RETURN (with ownership check) ----------
func (h *ComplianceHandler) DeleteReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	ctx = h.withIdempotencyKey(r)

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

	// Ownership check
	ret, err := h.complianceService.GetReturnByID(ctx, returnID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if ret.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "return does not belong to this company")
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

// ---------- GET RETURN BY ID ----------
func (h *ComplianceHandler) GetReturnByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()

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

// ---------- LIST RETURNS ----------
func (h *ComplianceHandler) ListReturns(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()

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

// ---------- GET FILING BY ID ----------
func (h *ComplianceHandler) GetFilingByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()

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

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    filing,
	})
}

// ---------- UPDATE FILING STATUS (FIXED) ----------
func (h *ComplianceHandler) UpdateFilingStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()

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

	// Convert string to enum and validate
	status := enums.ComplianceFilingStatus(req.Status)
	if status != enums.FilingStatusAccepted &&
		status != enums.FilingStatusRejected &&
		status != enums.FilingStatusPending {
		h.respondWithError(w, http.StatusBadRequest, "invalid filing status")
		return
	}

	if err := h.complianceService.UpdateFilingStatus(ctx, filingID, status, req.ErrorMessage); err != nil {
		h.logger.Error("failed to update filing status", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Filing status updated",
	})
}
