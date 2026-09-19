// internal/handler/payment_handler.go
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/service"
)

// PaymentHandler handles payment-related endpoints.
type PaymentHandler struct {
	paymentService   *service.PaymentService
	idempotencyStore idempotency.Store
}

// NewPaymentHandler creates a new PaymentHandler.
func NewPaymentHandler(
	paymentService *service.PaymentService,
	idempotencyStore idempotency.Store,
) *PaymentHandler {
	return &PaymentHandler{
		paymentService:   paymentService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- Helpers ----------

// getIdempotencyKey extracts the idempotency key from request header.
func (h *PaymentHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to context.
func (h *PaymentHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// injectClientIP adds client IP to context.
func (h *PaymentHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// ---------- Payment CRUD ----------

// CreatePayment POST /api/v1/companies/{companyID}/payments
// Creates a manual payment record (for admin use or offline payments).
// If status is "success", it extends the company's subscription.
func (h *PaymentHandler) CreatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req struct {
		PlanID          *uuid.UUID      `json:"plan_id,omitempty"`
		Amount          float64         `json:"amount" validate:"required,gt=0"`
		Currency        string          `json:"currency"`
		PaymentDate     string          `json:"payment_date"` // RFC3339
		PaymentMethod   *string         `json:"payment_method,omitempty"`
		GatewayTxnID    *string         `json:"gateway_txn_id,omitempty"`
		GatewayResponse json.RawMessage `json:"gateway_response,omitempty"`
		Status          string          `json:"status"`
		Notes           *string         `json:"notes,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Amount <= 0 {
		respondError(w, http.StatusBadRequest, "Amount must be positive")
		return
	}
	if req.GatewayTxnID == nil || *req.GatewayTxnID == "" {
		respondError(w, http.StatusBadRequest, "gateway_txn_id is required for idempotency")
		return
	}
	if req.Status == "" {
		req.Status = models.PaymentStatusPending
	}
	// Validate status
	validStatuses := map[string]bool{
		models.PaymentStatusPending:  true,
		models.PaymentStatusSuccess:  true,
		models.PaymentStatusFailed:   true,
		models.PaymentStatusRefunded: true,
	}
	if !validStatuses[req.Status] {
		respondError(w, http.StatusBadRequest, "Invalid status. Allowed: pending, success, failed, refunded")
		return
	}

	now := time.Now().UTC()
	payment := &models.CompanyPayment{
		PaymentID:   uuid.New(),
		CompanyID:   companyID,
		PlanID:      req.PlanID,
		Amount:      req.Amount,
		Currency:    req.Currency,
		PaymentDate: now,
	}
	if req.PaymentDate != "" {
		if t, err := time.Parse(time.RFC3339, req.PaymentDate); err == nil {
			payment.PaymentDate = t
		} else {
			respondError(w, http.StatusBadRequest, "Invalid payment_date format (use RFC3339)")
			return
		}
	}
	payment.PaymentMethod = req.PaymentMethod
	payment.GatewayTxnID = req.GatewayTxnID
	payment.GatewayResponse = req.GatewayResponse
	payment.Status = req.Status
	payment.Notes = req.Notes
	payment.CreatedAt = now
	payment.UpdatedAt = now

	// Use RecordManualPayment which extends subscription if status == "success"
	if err := h.paymentService.RecordManualPayment(ctx, payment); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusCreated, successResponse(payment, "Payment record created"))
}

// GetPayment GET /api/v1/companies/{companyID}/payments/{paymentID}
func (h *PaymentHandler) GetPayment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	paymentIDStr := chi.URLParam(r, "paymentID")
	paymentID, err := uuid.Parse(paymentIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid payment ID")
		return
	}
	payment, err := h.paymentService.GetPaymentByID(ctx, paymentID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(payment, "Payment retrieved"))
}

// GetPaymentByGatewayTxn GET /api/v1/companies/{companyID}/payments/gateway/{gatewayTxnID}
func (h *PaymentHandler) GetPaymentByGatewayTxn(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	gatewayTxnID := chi.URLParam(r, "gatewayTxnID")
	if gatewayTxnID == "" {
		respondError(w, http.StatusBadRequest, "Gateway transaction ID is required")
		return
	}
	payment, err := h.paymentService.GetPaymentByGatewayTxnID(ctx, gatewayTxnID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	if payment == nil {
		respondError(w, http.StatusNotFound, "Payment not found for this gateway transaction ID")
		return
	}
	respondJSON(w, http.StatusOK, successResponse(payment, "Payment retrieved"))
}

// ListPayments GET /api/v1/companies/{companyID}/payments
func (h *PaymentHandler) ListPayments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit

	payments, total, err := h.paymentService.ListPaymentsForCompany(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"payments": payments,
		"total":    total,
		"page":     page,
		"limit":    limit,
	}, "Payments retrieved"))
}

// UpdatePaymentStatus PATCH /api/v1/companies/{companyID}/payments/{paymentID}/status
func (h *PaymentHandler) UpdatePaymentStatus(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	paymentIDStr := chi.URLParam(r, "paymentID")
	paymentID, err := uuid.Parse(paymentIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid payment ID")
		return
	}
	var req struct {
		Status string `json:"status" validate:"required,oneof=pending success failed refunded"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Status == "" {
		respondError(w, http.StatusBadRequest, "Status is required")
		return
	}
	if err := h.paymentService.UpdatePaymentStatus(ctx, paymentID, req.Status); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Payment status updated"))
}

// ---------- Webhook ----------

// ProcessPaymentWebhook POST /api/v1/webhooks/payment
// This endpoint is called by the payment gateway (Stripe/Razorpay) to notify of successful payments.
// It does not require authentication; signature verification should be done inside.
func (h *PaymentHandler) ProcessPaymentWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// Read raw body for signature verification (not implemented here, should be done in service/gateway)
	var req struct {
		GatewayTxnID    string          `json:"gateway_txn_id" validate:"required"`
		CompanyID       string          `json:"company_id" validate:"required"`
		PlanCode        string          `json:"plan_code" validate:"required"`
		Amount          float64         `json:"amount" validate:"required,gt=0"`
		Currency        string          `json:"currency"`
		GatewayResponse json.RawMessage `json:"gateway_response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company_id")
		return
	}
	if req.Currency == "" {
		req.Currency = "USD"
	}

	err = h.paymentService.ProcessPaymentWebhook(
		ctx,
		req.GatewayTxnID,
		companyID,
		req.PlanCode,
		req.Amount,
		req.Currency,
		req.GatewayResponse,
	)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Webhook processed successfully"))
}
