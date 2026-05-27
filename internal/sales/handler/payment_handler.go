package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

type PaymentHandler struct {
	paymentService service.PaymentService
	logger         *zap.Logger
}

func NewPaymentHandler(paymentService service.PaymentService, logger *zap.Logger) *PaymentHandler {
	return &PaymentHandler{
		paymentService: paymentService,
		logger:         logger.Named("payment_handler"),
	}
}

// ---------- Request/Response Types ----------

type createPaymentRequest struct {
	CompanyID       string        `json:"company_id"`
	PaymentNumber   string        `json:"payment_number,omitempty"`
	ExternalRef     *string       `json:"external_ref,omitempty"`
	PaymentDate     string        `json:"payment_date"`
	Amount          string        `json:"amount"`
	PaymentMethod   string        `json:"payment_method"`
	Reference       *string       `json:"reference,omitempty"`
	GatewayResponse *models.JSONB `json:"gateway_response,omitempty"`
}

type registerCashPaymentRequest struct {
	CompanyID   string                     `json:"company_id"`
	PaymentDate string                     `json:"payment_date"`
	Amount      string                     `json:"amount"`
	Reference   *string                    `json:"reference,omitempty"`
	Allocations []paymentAllocationRequest `json:"allocations,omitempty"`
}

type registerCardPaymentRequest struct {
	CompanyID   string                     `json:"company_id"`
	PaymentDate string                     `json:"payment_date"`
	Amount      string                     `json:"amount"`
	CardLast4   string                     `json:"card_last4"`
	CardBrand   string                     `json:"card_brand"`
	GatewayTxID string                     `json:"gateway_tx_id"`
	Reference   *string                    `json:"reference,omitempty"`
	Allocations []paymentAllocationRequest `json:"allocations,omitempty"`
}

type registerBankTransferPaymentRequest struct {
	CompanyID       string                     `json:"company_id"`
	PaymentDate     string                     `json:"payment_date"`
	Amount          string                     `json:"amount"`
	BankName        string                     `json:"bank_name"`
	ReferenceNumber string                     `json:"reference_number"`
	Allocations     []paymentAllocationRequest `json:"allocations,omitempty"`
}

type registerChequePaymentRequest struct {
	CompanyID    string                     `json:"company_id"`
	PaymentDate  string                     `json:"payment_date"`
	Amount       string                     `json:"amount"`
	ChequeNumber string                     `json:"cheque_number"`
	BankName     string                     `json:"bank_name"`
	Allocations  []paymentAllocationRequest `json:"allocations,omitempty"`
}

type registerWalletPaymentRequest struct {
	CompanyID      string                     `json:"company_id"`
	PaymentDate    string                     `json:"payment_date"`
	Amount         string                     `json:"amount"`
	WalletProvider string                     `json:"wallet_provider"`
	WalletTxID     string                     `json:"wallet_tx_id"`
	Allocations    []paymentAllocationRequest `json:"allocations,omitempty"`
}

type processGatewayPaymentRequest struct {
	CompanyID      string                     `json:"company_id"`
	GatewayName    string                     `json:"gateway_name"`
	GatewayToken   string                     `json:"gateway_token"`
	Amount         string                     `json:"amount"`
	PaymentMethod  string                     `json:"payment_method"`
	IdempotencyKey string                     `json:"idempotency_key"`
	Allocations    []paymentAllocationRequest `json:"allocations,omitempty"`
}

type processGatewayWebhookRequest struct {
	GatewayName string          `json:"gateway_name"`
	GatewayTxID string          `json:"gateway_tx_id"`
	Status      string          `json:"status"`
	RawPayload  json.RawMessage `json:"raw_payload"`
	Signature   string          `json:"signature"`
}

type paymentAllocationRequest struct {
	InvoiceID string `json:"invoice_id"`
	Amount    string `json:"amount"`
}

type updatePaymentRequest struct {
	ExternalRef     *string       `json:"external_ref,omitempty"`
	PaymentDate     *string       `json:"payment_date,omitempty"`
	Amount          *string       `json:"amount,omitempty"`
	PaymentMethod   *string       `json:"payment_method,omitempty"`
	Reference       *string       `json:"reference,omitempty"`
	GatewayResponse *models.JSONB `json:"gateway_response,omitempty"`
}

type paymentUpdateStatusRequest struct {
	Status string `json:"status"`
}

type markFailedRequest struct {
	Reason string `json:"reason"`
}

type cancelPaymentRequest struct {
	Reason string `json:"reason"`
}

type allocatePaymentRequest struct {
	InvoiceID string `json:"invoice_id"`
	Amount    string `json:"amount"`
}

type allocateMultipleRequest struct {
	Allocations []paymentAllocationRequest `json:"allocations"`
}

type createRefundRequest struct {
	Amount string `json:"amount"`
	Reason string `json:"reason"`
}

type processGatewayRefundRequest struct {
	Amount string `json:"amount"`
	Reason string `json:"reason"`
}

type paymentResponse struct {
	PaymentID       string        `json:"payment_id"`
	CompanyID       string        `json:"company_id"`
	PaymentNumber   string        `json:"payment_number"`
	ExternalRef     *string       `json:"external_ref,omitempty"`
	PaymentDate     string        `json:"payment_date"`
	Amount          string        `json:"amount"`
	PaymentMethod   string        `json:"payment_method"`
	Status          string        `json:"status"`
	ExchangeRate    *string       `json:"exchange_rate,omitempty"`
	Reference       *string       `json:"reference,omitempty"`
	GatewayResponse *models.JSONB `json:"gateway_response,omitempty"`
	FailureReason   *string       `json:"failure_reason,omitempty"`
	CompletedAt     *string       `json:"completed_at,omitempty"`
	RefundedAmount  string        `json:"refunded_amount"`
	CreatedAt       string        `json:"created_at"`
	UpdatedAt       string        `json:"updated_at"`
}

type paymentAllocationResponse struct {
	AllocationID string `json:"allocation_id"`
	PaymentID    string `json:"payment_id"`
	InvoiceID    string `json:"invoice_id"`
	Amount       string `json:"amount"`
	CreatedAt    string `json:"created_at"`
}

type refundResponse struct {
	RefundID    string  `json:"refund_id"`
	CompanyID   string  `json:"company_id"`
	PaymentID   string  `json:"payment_id"`
	ReturnID    *string `json:"return_id,omitempty"`
	Amount      string  `json:"amount"`
	Reason      string  `json:"reason"`
	GatewayRef  *string `json:"gateway_ref,omitempty"`
	Status      string  `json:"status"`
	CompletedAt *string `json:"completed_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

type listPaymentsResponse struct {
	Payments []paymentSummary `json:"payments"`
	Total    int64            `json:"total"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

type paymentSummary struct {
	PaymentID     string `json:"payment_id"`
	PaymentNumber string `json:"payment_number"`
	PaymentDate   string `json:"payment_date"`
	Amount        string `json:"amount"`
	PaymentMethod string `json:"payment_method"`
	Status        string `json:"status"`
}

type paymentsByMethodResponse struct {
	Method string `json:"method"`
	Total  string `json:"total"`
}

// ---------- Helper Functions ----------

func (h *PaymentHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *PaymentHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	return true // TODO: implement actual permission check
}

func parseUUIDParamPayment(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func (h *PaymentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PaymentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *PaymentHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, salesErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, salesErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidState):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidAmount):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrPaymentOverAlloc):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrOverRefund):
		return http.StatusConflict, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

func (h *PaymentHandler) toPaymentResponse(p *models.Payment) paymentResponse {
	resp := paymentResponse{
		PaymentID:       p.PaymentID.String(),
		CompanyID:       p.CompanyID.String(),
		PaymentNumber:   p.PaymentNumber,
		ExternalRef:     p.ExternalRef,
		PaymentDate:     p.PaymentDate.Format(time.RFC3339),
		Amount:          p.Amount.String(),
		PaymentMethod:   string(p.PaymentMethod),
		Status:          string(p.Status),
		Reference:       p.Reference,
		GatewayResponse: &p.GatewayResponse, // p.GatewayResponse is models.JSONB, we take pointer
		FailureReason:   p.FailureReason,
		RefundedAmount:  p.RefundedAmount.String(),
		CreatedAt:       p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       p.UpdatedAt.Format(time.RFC3339),
	}
	if p.ExchangeRate != nil {
		rateStr := p.ExchangeRate.String()
		resp.ExchangeRate = &rateStr
	}
	if p.CompletedAt != nil {
		completedStr := p.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &completedStr
	}
	return resp
}

func (h *PaymentHandler) toRefundResponse(r *models.PaymentRefund) refundResponse {
	resp := refundResponse{
		RefundID:   r.RefundID.String(),
		CompanyID:  r.CompanyID.String(),
		PaymentID:  r.PaymentID.String(),
		Amount:     r.Amount.String(),
		Reason:     r.Reason,
		GatewayRef: r.GatewayRef,
		Status:     r.Status,
		CreatedAt:  r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  r.UpdatedAt.Format(time.RFC3339),
	}
	if r.ReturnID != nil {
		retStr := r.ReturnID.String()
		resp.ReturnID = &retStr
	}
	if r.CompletedAt != nil {
		compStr := r.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &compStr
	}
	return resp
}

// ---------- Endpoint Implementations ----------

// POST /payments
func (h *PaymentHandler) CreatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" || req.PaymentMethod == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, amount, and payment_method are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date (use RFC3339)")
		return
	}

	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	method := enums.PaymentMethod(req.PaymentMethod)
	if !method.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_method")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey // service uses idempotency internally

	svcReq := &service.CreatePaymentRequest{
		CompanyID:       companyID,
		PaymentNumber:   req.PaymentNumber,
		ExternalRef:     req.ExternalRef,
		PaymentDate:     paymentDate,
		Amount:          amount,
		PaymentMethod:   method,
		Reference:       req.Reference,
		GatewayResponse: *req.GatewayResponse, // dereference because service expects models.JSONB
		CreatedBy:       &userID,
	}

	payment, err := h.paymentService.CreatePayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// PUT /payments/{id}
func (h *PaymentHandler) UpdatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updatePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.UpdatePaymentRequest{
		ExternalRef: req.ExternalRef,
		Reference:   req.Reference,
		UpdatedBy:   &userID,
	}
	// GatewayResponse: service expects models.JSONB (value), handler has *models.JSONB
	if req.GatewayResponse != nil {
		svcReq.GatewayResponse = *req.GatewayResponse
	}
	if req.PaymentDate != nil {
		t, err := time.Parse(time.RFC3339, *req.PaymentDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
			return
		}
		svcReq.PaymentDate = &t
	}
	if req.Amount != nil {
		amt, err := decimal.NewFromString(*req.Amount)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid amount")
			return
		}
		svcReq.Amount = &amt
	}
	if req.PaymentMethod != nil {
		method := enums.PaymentMethod(*req.PaymentMethod)
		if !method.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid payment_method")
			return
		}
		svcReq.PaymentMethod = &method
	}

	payment, err := h.paymentService.UpdatePayment(ctx, companyID, paymentID, svcReq)
	if err != nil {
		h.logger.Error("failed to update payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DELETE /payments/{id}
func (h *PaymentHandler) DeletePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.DeletePayment(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to delete payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment deleted successfully",
	})
}

// GET /payments/{id}
func (h *PaymentHandler) GetPaymentByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payment, err := h.paymentService.GetPaymentByID(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to get payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/by-number?number=...
func (h *PaymentHandler) GetPaymentByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentNumber := r.URL.Query().Get("number")
	if paymentNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payment, err := h.paymentService.GetPaymentByNumber(ctx, companyID, paymentNumber)
	if err != nil {
		h.logger.Error("failed to get payment by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/by-gateway-ref?ref=...
func (h *PaymentHandler) GetPaymentByGatewayReference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	gatewayRef := r.URL.Query().Get("ref")
	if gatewayRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "ref query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payment, err := h.paymentService.GetPaymentByGatewayReference(ctx, companyID, gatewayRef)
	if err != nil {
		h.logger.Error("failed to get payment by gateway reference", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments
func (h *PaymentHandler) ListPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.PaymentListFilter{CompanyID: companyID}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		s := enums.PaymentStatus(statusStr)
		filter.Status = &s
	}
	if methodStr := r.URL.Query().Get("method"); methodStr != "" {
		m := enums.PaymentMethod(methodStr)
		filter.PaymentMethod = &m
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			filter.FromDate = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			filter.ToDate = &t
		}
	}
	if minStr := r.URL.Query().Get("min_amount"); minStr != "" {
		amt, err := decimal.NewFromString(minStr)
		if err == nil {
			filter.MinAmount = &amt
		}
	}
	if maxStr := r.URL.Query().Get("max_amount"); maxStr != "" {
		amt, err := decimal.NewFromString(maxStr)
		if err == nil {
			filter.MaxAmount = &amt
		}
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "payment_date"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	payments, total, err := h.paymentService.ListPayments(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list payments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}

	resp := listPaymentsResponse{
		Payments: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/search
func (h *PaymentHandler) SearchPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	payments, total, err := h.paymentService.SearchPayments(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search payments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}
	resp := listPaymentsResponse{
		Payments: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments?customer_id=...
func (h *PaymentHandler) GetPaymentsByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	customerIDStr := r.URL.Query().Get("customer_id")
	if customerIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id query parameter is required")
		return
	}
	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "payment_date"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	payments, total, err := h.paymentService.GetPaymentsByCustomer(ctx, companyID, customerID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get payments by customer", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}
	resp := listPaymentsResponse{
		Payments: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments?invoice_id=...
func (h *PaymentHandler) GetPaymentsByInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	invoiceIDStr := r.URL.Query().Get("invoice_id")
	if invoiceIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "invoice_id query parameter is required")
		return
	}
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payments, err := h.paymentService.GetPaymentsByInvoice(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get payments by invoice", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// POST /payments/register/cash
func (h *PaymentHandler) RegisterCashPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req registerCashPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, and amount are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	svcReq := &service.RegisterCashPaymentRequest{
		CompanyID:   companyID,
		PaymentDate: paymentDate,
		Amount:      amount,
		Reference:   req.Reference,
		Allocations: allocations,
		CreatedBy:   userID,
	}

	payment, err := h.paymentService.RegisterCashPayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to register cash payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/register/card
func (h *PaymentHandler) RegisterCardPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req registerCardPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" || req.CardLast4 == "" || req.CardBrand == "" || req.GatewayTxID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, amount, card_last4, card_brand, gateway_tx_id are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	svcReq := &service.RegisterCardPaymentRequest{
		CompanyID:   companyID,
		PaymentDate: paymentDate,
		Amount:      amount,
		CardLast4:   req.CardLast4,
		CardBrand:   req.CardBrand,
		GatewayTxID: req.GatewayTxID,
		Allocations: allocations,
		CreatedBy:   userID,
	}

	payment, err := h.paymentService.RegisterCardPayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to register card payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/register/bank-transfer
// POST /payments/register/bank-transfer
func (h *PaymentHandler) RegisterBankTransferPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req registerBankTransferPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" || req.BankName == "" || req.ReferenceNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, amount, bank_name, reference_number are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	// BankName is *string in service request, req.BankName is string
	bankNameCopy := req.BankName
	svcReq := &service.RegisterBankTransferPaymentRequest{
		CompanyID:       companyID,
		PaymentDate:     paymentDate,
		Amount:          amount,
		BankName:        &bankNameCopy,
		ReferenceNumber: req.ReferenceNumber,
		Allocations:     allocations,
		CreatedBy:       userID,
	}

	payment, err := h.paymentService.RegisterBankTransferPayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to register bank transfer payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/register/cheque
func (h *PaymentHandler) RegisterChequePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req registerChequePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" || req.ChequeNumber == "" || req.BankName == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, amount, cheque_number, bank_name are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	// BankName is *string in service request, req.BankName is string
	bankNameCopy := req.BankName
	svcReq := &service.RegisterChequePaymentRequest{
		CompanyID:    companyID,
		PaymentDate:  paymentDate,
		Amount:       amount,
		ChequeNumber: req.ChequeNumber,
		BankName:     &bankNameCopy,
		Allocations:  allocations,
		CreatedBy:    userID,
	}

	payment, err := h.paymentService.RegisterChequePayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to register cheque payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/register/wallet
func (h *PaymentHandler) RegisterWalletPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req registerWalletPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.PaymentDate == "" || req.Amount == "" || req.WalletProvider == "" || req.WalletTxID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, payment_date, amount, wallet_provider, wallet_tx_id are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	svcReq := &service.RegisterWalletPaymentRequest{
		CompanyID:      companyID,
		PaymentDate:    paymentDate,
		Amount:         amount,
		WalletProvider: req.WalletProvider,
		WalletTxID:     req.WalletTxID,
		Allocations:    allocations,
		CreatedBy:      userID,
	}

	payment, err := h.paymentService.RegisterWalletPayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to register wallet payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/gateway
func (h *PaymentHandler) ProcessGatewayPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req processGatewayPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.GatewayName == "" || req.GatewayToken == "" || req.Amount == "" || req.PaymentMethod == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, gateway_name, gateway_token, amount, payment_method are required")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	method := enums.PaymentMethod(req.PaymentMethod)
	if !method.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_method")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" && req.IdempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header or body field is required")
		return
	}
	if idempotencyKey == "" {
		idempotencyKey = req.IdempotencyKey
	}

	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invID, _ := uuid.Parse(a.InvoiceID)
		amt, _ := decimal.NewFromString(a.Amount)
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invID, Amount: amt}
	}

	svcReq := &service.ProcessGatewayPaymentRequest{
		CompanyID:      companyID,
		GatewayName:    req.GatewayName,
		GatewayToken:   req.GatewayToken,
		Amount:         amount,
		PaymentMethod:  method,
		IdempotencyKey: idempotencyKey,
		Allocations:    allocations,
		CreatedBy:      userID,
	}

	payment, err := h.paymentService.ProcessGatewayPayment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to process gateway payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	location := fmt.Sprintf("/payments/%s", payment.PaymentID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/webhook
func (h *PaymentHandler) ProcessGatewayWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req processGatewayWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.GatewayName == "" || req.GatewayTxID == "" || req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "gateway_name, gateway_tx_id, status are required")
		return
	}

	// Validate signature – service will do it
	svcReq := &service.ProcessGatewayWebhookRequest{
		GatewayName: req.GatewayName,
		GatewayTxID: req.GatewayTxID,
		Status:      req.Status,
		RawPayload:  req.RawPayload,
		Signature:   req.Signature,
	}

	err := h.paymentService.ProcessGatewayWebhook(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to process gateway webhook", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to process webhook")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "webhook processed",
	})
}

// GET /payments/idempotent/{key}
func (h *PaymentHandler) GetPaymentByIdempotencyKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := chi.URLParam(r, "key")
	if key == "" {
		h.respondWithError(w, http.StatusBadRequest, "idempotency key is required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payment, err := h.paymentService.GetPaymentByIdempotencyKey(ctx, companyID, key)
	if err != nil {
		h.logger.Error("failed to get payment by idempotency key", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPaymentResponse(payment)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/{id}/allocate
func (h *PaymentHandler) AllocatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req allocatePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(req.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.AllocatePayment(ctx, companyID, paymentID, invoiceID, amount, userID)
	if err != nil {
		h.logger.Error("failed to allocate payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment allocated",
	})
}

// POST /payments/{id}/allocate-multiple
func (h *PaymentHandler) AllocatePaymentToInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req allocateMultipleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	allocations := make([]service.PaymentAllocationRequest, len(req.Allocations))
	for i, a := range req.Allocations {
		invoiceID, err := uuid.Parse(a.InvoiceID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id in allocation")
			return
		}
		amount, err := decimal.NewFromString(a.Amount)
		if err != nil || amount.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid amount in allocation")
			return
		}
		allocations[i] = service.PaymentAllocationRequest{InvoiceID: invoiceID, Amount: amount}
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.AllocatePaymentToInvoices(ctx, companyID, paymentID, allocations, userID)
	if err != nil {
		h.logger.Error("failed to allocate payment to multiple invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "allocations added",
	})
}

// POST /payments/{id}/auto-allocate
func (h *PaymentHandler) AutoAllocatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.AutoAllocatePayment(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to auto-allocate payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "auto-allocation completed",
	})
}

// DELETE /payments/{id}/allocations/{allocId}
func (h *PaymentHandler) RemoveAllocation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	allocationID, err := parseUUIDParamPayment(r, "allocId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid allocation ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.RemoveAllocation(ctx, companyID, paymentID, allocationID, userID)
	if err != nil {
		h.logger.Error("failed to remove allocation", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "allocation removed",
	})
}

// GET /payments/{id}/allocations
func (h *PaymentHandler) GetPaymentAllocations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	allocations, err := h.paymentService.GetPaymentAllocations(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to get payment allocations", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]paymentAllocationResponse, len(allocations))
	for i, a := range allocations {
		resp[i] = paymentAllocationResponse{
			AllocationID: a.AllocationID.String(),
			PaymentID:    a.PaymentID.String(),
			InvoiceID:    a.InvoiceID.String(),
			Amount:       a.Amount.String(),
			CreatedAt:    a.CreatedAt.Format(time.RFC3339),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/{id}/unallocated
func (h *PaymentHandler) GetUnallocatedAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.paymentService.GetUnallocatedAmount(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to get unallocated amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"unallocated_amount": amount.String()},
	})
}

// POST /payments/{id}/refunds
func (h *PaymentHandler) CreateRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.CreateRefundRequest{
		CompanyID:  companyID,
		PaymentID:  paymentID,
		Amount:     amount,
		Reason:     req.Reason,
		RefundedBy: userID,
	}
	refund, err := h.paymentService.CreateRefund(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRefundResponse(refund)
	location := fmt.Sprintf("/refunds/%s", refund.RefundID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/{id}/refund-full
func (h *PaymentHandler) RefundFullPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	refund, err := h.paymentService.RefundFullPayment(ctx, companyID, paymentID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to refund full payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRefundResponse(refund)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/{id}/refund-partial
func (h *PaymentHandler) RefundPartialPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Amount string `json:"amount"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	refund, err := h.paymentService.RefundPartialPayment(ctx, companyID, paymentID, amount, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to refund partial payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRefundResponse(refund)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /payments/{id}/gateway-refund
func (h *PaymentHandler) ProcessGatewayRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req processGatewayRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.ProcessGatewayRefundRequest{
		CompanyID:  companyID,
		PaymentID:  paymentID,
		Amount:     amount,
		Reason:     req.Reason,
		RefundedBy: userID,
	}

	refund, err := h.paymentService.ProcessGatewayRefund(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to process gateway refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRefundResponse(refund)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /refunds/{id}
func (h *PaymentHandler) GetRefundByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refundID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid refund ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	refund, err := h.paymentService.GetRefundByID(ctx, companyID, refundID)
	if err != nil {
		h.logger.Error("failed to get refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRefundResponse(refund)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/{id}/refunds
func (h *PaymentHandler) GetPaymentRefunds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	refunds, err := h.paymentService.GetPaymentRefunds(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to get payment refunds", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]refundResponse, len(refunds))
	for i, r := range refunds {
		resp[i] = h.toRefundResponse(r)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/{id}/refunded-amount
func (h *PaymentHandler) GetRefundedAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.paymentService.GetRefundedAmount(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to get refunded amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"refunded_amount": amount.String()},
	})
}

// PATCH /payments/{id}/status
func (h *PaymentHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req paymentUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status := enums.PaymentStatus(req.Status)
	if !status.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.UpdateStatus(ctx, companyID, paymentID, status, userID)
	if err != nil {
		h.logger.Error("failed to update payment status", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "status updated",
	})
}

// POST /payments/{id}/mark-pending
func (h *PaymentHandler) MarkPending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.MarkPending(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to mark payment pending", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment marked as pending",
	})
}

// POST /payments/{id}/mark-processing
func (h *PaymentHandler) MarkProcessing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.MarkProcessing(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to mark payment processing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment marked as processing",
	})
}

// POST /payments/{id}/mark-completed
func (h *PaymentHandler) MarkCompleted(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	completedAt := time.Now()
	err = h.paymentService.MarkCompleted(ctx, companyID, paymentID, completedAt, userID)
	if err != nil {
		h.logger.Error("failed to mark payment completed", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment marked as completed",
	})
}

// POST /payments/{id}/mark-failed
func (h *PaymentHandler) MarkFailed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req markFailedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.MarkFailed(ctx, companyID, paymentID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to mark payment failed", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment marked as failed",
	})
}

// POST /payments/{id}/cancel
func (h *PaymentHandler) CancelPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req cancelPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.CancelPayment(ctx, companyID, paymentID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to cancel payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment cancelled",
	})
}

// POST /payments/{id}/reconcile
func (h *PaymentHandler) ReconcilePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.ReconcilePayment(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to reconcile payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment reconciled",
	})
}

// POST /payments/{id}/unreconcile
func (h *PaymentHandler) UnreconcilePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.paymentService.UnreconcilePayment(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to unreconcile payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment unreconciled",
	})
}

// GET /payments/unreconciled
func (h *PaymentHandler) GetUnreconciledPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payments, err := h.paymentService.GetUnreconciledPayments(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get unreconciled payments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get unreconciled payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GET /payments/total-received
func (h *PaymentHandler) GetTotalPaymentsReceived(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	total, err := h.paymentService.GetTotalPaymentsReceived(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total payments received", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_received": total.String()},
	})
}

// GET /payments/total-refunded
func (h *PaymentHandler) GetTotalRefundedAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	total, err := h.paymentService.GetTotalRefundedAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total refunded amount", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_refunded": total.String()},
	})
}

// GET /payments/net-collections
func (h *PaymentHandler) GetNetCollections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	net, err := h.paymentService.GetNetCollections(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get net collections", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get net collections")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"net_collections": net.String()},
	})
}

// GET /payments/by-method
func (h *PaymentHandler) GetPaymentsByMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	byMethod, err := h.paymentService.GetPaymentsByMethod(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get payments by method", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get breakdown")
		return
	}

	resp := make([]paymentsByMethodResponse, 0, len(byMethod))
	for method, total := range byMethod {
		resp = append(resp, paymentsByMethodResponse{
			Method: string(method),
			Total:  total.String(),
		})
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /payments/failed
func (h *PaymentHandler) GetFailedPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	payments, err := h.paymentService.GetFailedPayments(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get failed payments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get failed payments")
		return
	}

	summaries := make([]paymentSummary, len(payments))
	for i, p := range payments {
		summaries[i] = paymentSummary{
			PaymentID:     p.PaymentID.String(),
			PaymentNumber: p.PaymentNumber,
			PaymentDate:   p.PaymentDate.Format(time.RFC3339),
			Amount:        p.Amount.String(),
			PaymentMethod: string(p.PaymentMethod),
			Status:        string(p.Status),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GET /payments/{id}/exists
func (h *PaymentHandler) PaymentExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.paymentService.PaymentExists(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to check payment existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// GET /payments/number-exists?number=...
func (h *PaymentHandler) PaymentNumberExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	number := r.URL.Query().Get("number")
	if number == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.paymentService.PaymentNumberExists(ctx, companyID, number)
	if err != nil {
		h.logger.Error("failed to check payment number existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// GET /payments/gateway-transaction-exists?id=...
func (h *PaymentHandler) GatewayTransactionExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	txID := r.URL.Query().Get("id")
	if txID == "" {
		h.respondWithError(w, http.StatusBadRequest, "id query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.paymentService.GatewayTransactionExists(ctx, companyID, txID)
	if err != nil {
		h.logger.Error("failed to check gateway transaction existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// GET /payments/{id}/has-refunds
func (h *PaymentHandler) HasRefunds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paymentID, err := parseUUIDParamPayment(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	has, err := h.paymentService.HasRefunds(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to check refunds", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"has_refunds": has},
	})
}
