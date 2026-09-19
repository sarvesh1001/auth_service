// internal/handler/invoice_handler.go
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

// InvoiceHandler handles invoice-related endpoints.
type InvoiceHandler struct {
	invoiceService   *service.SubscriptionInvoiceService
	idempotencyStore idempotency.Store
}

// NewInvoiceHandler creates a new InvoiceHandler.
func NewInvoiceHandler(
	invoiceService *service.SubscriptionInvoiceService,
	idempotencyStore idempotency.Store,
) *InvoiceHandler {
	return &InvoiceHandler{
		invoiceService:   invoiceService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- Helpers ----------

// getIdempotencyKey extracts the idempotency key from request header.
func (h *InvoiceHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to context.
func (h *InvoiceHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// injectClientIP adds client IP to context.
func (h *InvoiceHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// ---------- Invoice CRUD ----------

// CreateInvoice POST /api/v1/companies/{companyID}/invoices
func (h *InvoiceHandler) CreateInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req struct {
		InvoiceDate   string  `json:"invoice_date"`
		DueDate       string  `json:"due_date"`
		Currency      string  `json:"currency"`
		Subtotal      float64 `json:"subtotal"`
		TaxTotal      float64 `json:"tax_total"`
		DiscountTotal float64 `json:"discount_total"`
		GrandTotal    float64 `json:"grand_total"`
		Status        string  `json:"status"`
		Notes         *string `json:"notes"`
		Items         []struct {
			Description string  `json:"description"`
			Quantity    float64 `json:"quantity"`
			UnitPrice   float64 `json:"unit_price"`
			TaxRate     float64 `json:"tax_rate"`
			TaxAmount   float64 `json:"tax_amount"`
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Items) == 0 {
		respondError(w, http.StatusBadRequest, "At least one invoice item is required")
		return
	}

	now := time.Now().UTC()
	invoice := &models.SubscriptionInvoice{
		InvoiceID:     uuid.New(),
		CompanyID:     companyID,
		Currency:      req.Currency,
		Subtotal:      req.Subtotal,
		TaxTotal:      req.TaxTotal,
		DiscountTotal: req.DiscountTotal,
		GrandTotal:    req.GrandTotal,
		Status:        req.Status,
		Notes:         req.Notes,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if req.InvoiceDate != "" {
		if t, err := time.Parse(time.RFC3339, req.InvoiceDate); err == nil {
			invoice.InvoiceDate = t
		} else {
			respondError(w, http.StatusBadRequest, "Invalid invoice_date format (use RFC3339)")
			return
		}
	} else {
		invoice.InvoiceDate = now
	}
	if req.DueDate != "" {
		if t, err := time.Parse(time.RFC3339, req.DueDate); err == nil {
			invoice.DueDate = t
		} else {
			respondError(w, http.StatusBadRequest, "Invalid due_date format (use RFC3339)")
			return
		}
	} else {
		invoice.DueDate = now.AddDate(0, 0, 7)
	}

	// Auto-compute totals if zero
	if invoice.GrandTotal == 0 {
		for _, item := range req.Items {
			invoice.Subtotal += item.Quantity * item.UnitPrice
			invoice.TaxTotal += item.TaxAmount
		}
		invoice.GrandTotal = invoice.Subtotal + invoice.TaxTotal - invoice.DiscountTotal
	}

	var items []*models.SubscriptionInvoiceItem
	for _, it := range req.Items {
		items = append(items, &models.SubscriptionInvoiceItem{
			ItemID:      uuid.New(),
			Description: it.Description,
			Quantity:    it.Quantity,
			UnitPrice:   it.UnitPrice,
			TaxRate:     it.TaxRate,
			TaxAmount:   it.TaxAmount,
			CreatedAt:   now,
		})
	}

	createdInvoice, err := h.invoiceService.CreateInvoice(ctx, invoice, items)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusCreated, successResponse(createdInvoice, "Invoice created"))
}

// GetInvoice GET /api/v1/companies/{companyID}/invoices/{invoiceID}
func (h *InvoiceHandler) GetInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid invoice ID")
		return
	}
	invoice, err := h.invoiceService.GetInvoiceByID(ctx, invoiceID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(invoice, "Invoice retrieved"))
}

// GetInvoiceByNumber GET /api/v1/companies/{companyID}/invoices/number/{invoiceNumber}
func (h *InvoiceHandler) GetInvoiceByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	invoiceNumber := chi.URLParam(r, "invoiceNumber")
	if invoiceNumber == "" {
		respondError(w, http.StatusBadRequest, "Invoice number is required")
		return
	}
	invoice, err := h.invoiceService.GetInvoiceByNumber(ctx, invoiceNumber)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(invoice, "Invoice retrieved"))
}

// ListInvoices GET /api/v1/companies/{companyID}/invoices
func (h *InvoiceHandler) ListInvoices(w http.ResponseWriter, r *http.Request) {
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

	invoices, total, err := h.invoiceService.ListInvoicesForCompany(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"invoices": invoices,
		"total":    total,
		"page":     page,
		"limit":    limit,
	}, "Invoices retrieved"))
}

// UpdateInvoice PUT /api/v1/companies/{companyID}/invoices/{invoiceID}
func (h *InvoiceHandler) UpdateInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid invoice ID")
		return
	}

	var req struct {
		InvoiceNumber string  `json:"invoice_number"`
		InvoiceDate   string  `json:"invoice_date"`
		DueDate       string  `json:"due_date"`
		Currency      string  `json:"currency"`
		Subtotal      float64 `json:"subtotal"`
		TaxTotal      float64 `json:"tax_total"`
		DiscountTotal float64 `json:"discount_total"`
		GrandTotal    float64 `json:"grand_total"`
		Status        string  `json:"status"`
		Notes         *string `json:"notes"`
		Items         []struct {
			Description string  `json:"description"`
			Quantity    float64 `json:"quantity"`
			UnitPrice   float64 `json:"unit_price"`
			TaxRate     float64 `json:"tax_rate"`
			TaxAmount   float64 `json:"tax_amount"`
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	updates := &models.SubscriptionInvoice{
		InvoiceNumber: req.InvoiceNumber,
		Currency:      req.Currency,
		Subtotal:      req.Subtotal,
		TaxTotal:      req.TaxTotal,
		DiscountTotal: req.DiscountTotal,
		GrandTotal:    req.GrandTotal,
		Status:        req.Status,
		Notes:         req.Notes,
	}
	if req.InvoiceDate != "" {
		if t, err := time.Parse(time.RFC3339, req.InvoiceDate); err == nil {
			updates.InvoiceDate = t
		} else {
			respondError(w, http.StatusBadRequest, "Invalid invoice_date format")
			return
		}
	}
	if req.DueDate != "" {
		if t, err := time.Parse(time.RFC3339, req.DueDate); err == nil {
			updates.DueDate = t
		} else {
			respondError(w, http.StatusBadRequest, "Invalid due_date format")
			return
		}
	}

	var items []*models.SubscriptionInvoiceItem
	if req.Items != nil {
		now := time.Now().UTC()
		for _, it := range req.Items {
			items = append(items, &models.SubscriptionInvoiceItem{
				Description: it.Description,
				Quantity:    it.Quantity,
				UnitPrice:   it.UnitPrice,
				TaxRate:     it.TaxRate,
				TaxAmount:   it.TaxAmount,
				CreatedAt:   now,
			})
		}
	}

	updated, err := h.invoiceService.UpdateInvoice(ctx, invoiceID, updates, items)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(updated, "Invoice updated"))
}

// UpdateInvoiceStatus PATCH /api/v1/companies/{companyID}/invoices/{invoiceID}/status
func (h *InvoiceHandler) UpdateInvoiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid invoice ID")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Status == "" {
		respondError(w, http.StatusBadRequest, "Status is required")
		return
	}
	if err := h.invoiceService.UpdateInvoiceStatus(ctx, invoiceID, req.Status); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Invoice status updated"))
}

// DeleteInvoice DELETE /api/v1/companies/{companyID}/invoices/{invoiceID}
func (h *InvoiceHandler) DeleteInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid invoice ID")
		return
	}
	if err := h.invoiceService.SoftDeleteInvoice(ctx, invoiceID); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Invoice deleted"))
}

// GetInvoiceItems GET /api/v1/companies/{companyID}/invoices/{invoiceID}/items
func (h *InvoiceHandler) GetInvoiceItems(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid invoice ID")
		return
	}
	items, err := h.invoiceService.GetInvoiceItems(ctx, invoiceID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(items, "Invoice items retrieved"))
}
