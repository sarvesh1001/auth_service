// file: internal/sales/handler/invoice_handler.go
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

// InvoiceHandler handles HTTP requests for invoice management.
type InvoiceHandler struct {
	invoiceService service.InvoiceService
	*BaseHandler
}

// NewInvoiceHandler creates a new InvoiceHandler.
func NewInvoiceHandler(invoiceService service.InvoiceService, logger *zap.Logger) *InvoiceHandler {
	return &InvoiceHandler{
		invoiceService: invoiceService,
		BaseHandler:    &BaseHandler{logger: logger.Named("commission_handler")},
	}
}

// ---------- Request/Response Types ----------

type createInvoiceRequest struct {
	CustomerID  string                     `json:"customer_id"`
	OrderID     *string                    `json:"order_id,omitempty"`
	InvoiceDate string                     `json:"invoice_date"`
	DueDate     string                     `json:"due_date"`
	Currency    string                     `json:"currency,omitempty"`
	Notes       *string                    `json:"notes,omitempty"`
	Items       []createInvoiceItemRequest `json:"items"`
}

type createInvoiceItemRequest struct {
	ProductID           *string      `json:"product_id,omitempty"`
	ProductNameSnapshot string       `json:"product_name_snapshot"`
	Quantity            string       `json:"quantity"`
	UnitPrice           string       `json:"unit_price"`
	Discount            *string      `json:"discount,omitempty"`
	Metadata            models.JSONB `json:"metadata,omitempty"`
}

// ---------- NEW: Partial invoicing request types ----------
type partialInvoiceItem struct {
	OrderItemID string `json:"order_item_id"`
	Quantity    string `json:"quantity"`
}

type createInvoiceFromOrderRequest struct {
	OrderID     string               `json:"order_id"`
	Items       []partialInvoiceItem `json:"items,omitempty"` // optional – if omitted, invoice all remaining
	InvoiceDate string               `json:"invoice_date,omitempty"`
	DueDate     string               `json:"due_date,omitempty"`
	Notes       *string              `json:"notes,omitempty"`
}

// -----------------------------------------------------------

type createInvoiceFromQuoteRequest struct {
	QuoteID     string  `json:"quote_id"`
	InvoiceDate string  `json:"invoice_date,omitempty"`
	DueDate     string  `json:"due_date,omitempty"`
	Notes       *string `json:"notes,omitempty"`
}

type invoiceResponse struct {
	InvoiceID            string  `json:"invoice_id"`
	CompanyID            string  `json:"company_id"`
	OrderID              *string `json:"order_id,omitempty"`
	CustomerID           string  `json:"customer_id"`
	InvoiceNumber        string  `json:"invoice_number"`
	ExternalRef          *string `json:"external_ref,omitempty"`
	InvoiceDate          string  `json:"invoice_date"`
	DueDate              string  `json:"due_date"`
	Status               string  `json:"status"`
	Currency             string  `json:"currency"`
	ExchangeRate         *string `json:"exchange_rate,omitempty"`
	Subtotal             string  `json:"subtotal"`
	DiscountTotal        string  `json:"discount_total"`
	TaxTotal             string  `json:"tax_total"`
	GrandTotal           string  `json:"grand_total"`
	AmountPaid           string  `json:"amount_paid"`
	AmountDue            string  `json:"amount_due"`
	Notes                *string `json:"notes,omitempty"`
	IsLocked             bool    `json:"is_locked"`
	IssuedAt             *string `json:"issued_at,omitempty"`
	PaidAt               *string `json:"paid_at,omitempty"`
	CancelledAt          *string `json:"cancelled_at,omitempty"`
	SalesRepID           *string `json:"sales_rep_id,omitempty"`
	PaymentTermName      *string `json:"payment_term_name,omitempty"`
	PaymentDueDays       *int    `json:"payment_due_days,omitempty"`
	EarlyDiscountPercent *string `json:"early_discount_percent,omitempty"`
	EarlyDiscountDays    *int    `json:"early_discount_days,omitempty"`
	CreatedAt            string  `json:"created_at"`
	UpdatedAt            string  `json:"updated_at"`
}

type updateInvoiceRequest struct {
	Notes *string `json:"notes,omitempty"`
}

type addInvoiceItemsRequest struct {
	Items []createInvoiceItemRequest `json:"items"`
}

type replaceInvoiceItemsRequest struct {
	Items []createInvoiceItemRequest `json:"items"`
}

type manualDiscountRequest struct {
	DiscountAmount string `json:"discount_amount"`
	Reason         string `json:"reason"`
}

type invoiceUpdateStatusRequest struct {
	Status string `json:"status"`
}

type markPaidRequest struct {
	PaidAt string `json:"paid_at,omitempty"`
}

type voidInvoiceRequest struct {
	Reason string `json:"reason"`
}

type registerPaymentRequest struct {
	PaymentID string `json:"payment_id"`
	Amount    string `json:"amount"`
}

type applyPaymentRequest struct {
	PaymentID string `json:"payment_id"`
	Amount    string `json:"amount"`
}

type updateDueDateRequest struct {
	DueDate string `json:"due_date"`
}

type invoiceItemResponse struct {
	InvoiceItemID       string        `json:"invoice_item_id"`
	InvoiceID           string        `json:"invoice_id"`
	ProductID           *string       `json:"product_id,omitempty"`
	ProductNameSnapshot string        `json:"product_name_snapshot"`
	Quantity            string        `json:"quantity"`
	UnitPrice           string        `json:"unit_price"`
	DiscountAmount      *string       `json:"discount_amount,omitempty"`
	TaxAmount           *string       `json:"tax_amount,omitempty"`
	TotalPrice          string        `json:"total_price"`
	Metadata            *models.JSONB `json:"metadata,omitempty"`
	CreatedAt           string        `json:"created_at"`
}

type listInvoicesResponse struct {
	Invoices []invoiceSummary `json:"invoices"`
	Total    int64            `json:"total"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

type invoiceSummary struct {
	InvoiceID     string `json:"invoice_id"`
	InvoiceNumber string `json:"invoice_number"`
	CustomerID    string `json:"customer_id"`
	Status        string `json:"status"`
	InvoiceDate   string `json:"invoice_date"`
	DueDate       string `json:"due_date"`
	GrandTotal    string `json:"grand_total"`
	AmountDue     string `json:"amount_due"`
}

type invoicePaymentResponse struct {
	PaymentID string `json:"payment_id"`
	Amount    string `json:"amount"`
	AppliedAt string `json:"applied_at"`
}

type invoiceTotalsResponse struct {
	Subtotal      string `json:"subtotal"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
	GrandTotal    string `json:"grand_total"`
	AmountPaid    string `json:"amount_paid"`
	AmountDue     string `json:"amount_due"`
}

// ---------- Helper Functions ----------

func (h *InvoiceHandler) toInvoiceResponse(inv *models.Invoice) invoiceResponse {
	resp := invoiceResponse{
		InvoiceID:     inv.InvoiceID.String(),
		CompanyID:     inv.CompanyID.String(),
		CustomerID:    inv.CustomerID.String(),
		InvoiceNumber: inv.InvoiceNumber,
		InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
		DueDate:       inv.DueDate.Format(time.RFC3339),
		Status:        string(inv.Status),
		Currency:      inv.Currency,
		Subtotal:      inv.Subtotal.String(),
		DiscountTotal: inv.DiscountTotal.String(),
		TaxTotal:      inv.TaxTotal.String(),
		GrandTotal:    inv.GrandTotal.String(),
		AmountPaid:    inv.AmountPaid.String(),
		AmountDue:     inv.AmountDue.String(),
		Notes:         inv.Notes,
		IsLocked:      inv.IsLocked,
		CreatedAt:     inv.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     inv.UpdatedAt.Format(time.RFC3339),
	}
	if inv.OrderID != nil {
		orderIDStr := inv.OrderID.String()
		resp.OrderID = &orderIDStr
	}
	if inv.ExternalRef != nil {
		resp.ExternalRef = inv.ExternalRef
	}
	if inv.ExchangeRate != nil {
		rateStr := inv.ExchangeRate.String()
		resp.ExchangeRate = &rateStr
	}
	if inv.IssuedAt != nil {
		issuedAtStr := inv.IssuedAt.Format(time.RFC3339)
		resp.IssuedAt = &issuedAtStr
	}
	if inv.PaidAt != nil {
		paidAtStr := inv.PaidAt.Format(time.RFC3339)
		resp.PaidAt = &paidAtStr
	}
	if inv.CancelledAt != nil {
		cancelledAtStr := inv.CancelledAt.Format(time.RFC3339)
		resp.CancelledAt = &cancelledAtStr
	}
	if inv.SalesRepID != nil {
		salesRepIDStr := inv.SalesRepID.String()
		resp.SalesRepID = &salesRepIDStr
	}
	if inv.PaymentTermName != nil {
		resp.PaymentTermName = inv.PaymentTermName
	}
	if inv.PaymentDueDays != nil {
		resp.PaymentDueDays = inv.PaymentDueDays
	}
	if inv.EarlyDiscountPercent != nil {
		discPctStr := inv.EarlyDiscountPercent.String()
		resp.EarlyDiscountPercent = &discPctStr
	}
	if inv.EarlyDiscountDays != nil {
		resp.EarlyDiscountDays = inv.EarlyDiscountDays
	}
	return resp
}

func (h *InvoiceHandler) toInvoiceItemResponse(item *models.InvoiceItem) invoiceItemResponse {
	resp := invoiceItemResponse{
		InvoiceItemID:       item.InvoiceItemID.String(),
		InvoiceID:           item.InvoiceID.String(),
		ProductNameSnapshot: item.ProductNameSnapshot,
		Quantity:            item.Quantity.String(),
		UnitPrice:           item.UnitPrice.String(),
		TotalPrice:          item.TotalPrice.String(),
		CreatedAt:           item.CreatedAt.Format(time.RFC3339),
	}
	if item.ProductID != nil {
		productIDStr := item.ProductID.String()
		resp.ProductID = &productIDStr
	}
	if item.DiscountAmount != nil {
		discStr := item.DiscountAmount.String()
		resp.DiscountAmount = &discStr
	}
	if item.TaxAmount != nil {
		taxStr := item.TaxAmount.String()
		resp.TaxAmount = &taxStr
	}
	if item.Metadata != nil {
		resp.Metadata = &item.Metadata
	}
	return resp
}

// ---------- Handler Methods ----------

// CreateDraftInvoice handles POST /invoices
func (h *InvoiceHandler) CreateDraftInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if req.CustomerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id is required")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	invoiceDate, err := time.Parse(time.RFC3339, req.InvoiceDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_date (use RFC3339)")
		return
	}
	dueDate, err := time.Parse(time.RFC3339, req.DueDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid due_date (use RFC3339)")
		return
	}
	currency := req.Currency
	if currency == "" {
		currency = "USD"
	}
	var orderID *uuid.UUID
	if req.OrderID != nil && *req.OrderID != "" {
		parsed, err := uuid.Parse(*req.OrderID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
			return
		}
		orderID = &parsed
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}
	items := make([]service.CreateInvoiceItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity for item")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price for item")
			return
		}
		var discount *decimal.Decimal
		if it.Discount != nil && *it.Discount != "" {
			d, err := decimal.NewFromString(*it.Discount)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid discount for item")
				return
			}
			discount = &d
		}
		var productID uuid.UUID
		if it.ProductID != nil && *it.ProductID != "" {
			parsed, err := uuid.Parse(*it.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id for item")
				return
			}
			productID = parsed
		}
		items[i] = service.CreateInvoiceItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &unitPrice,
			Discount:  discount,
			Metadata:  it.Metadata,
		}
	}

	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := service.CreateInvoiceRequest{
		CompanyID:   companyID,
		CustomerID:  customerID,
		OrderID:     orderID,
		InvoiceDate: invoiceDate,
		DueDate:     dueDate,
		Currency:    currency,
		Notes:       req.Notes,
		Items:       items,
	}

	invoice, err := h.invoiceService.CreateDraftInvoice(ctx, &svcReq)
	if err != nil {
		h.logger.Error("failed to create draft invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toInvoiceResponse(invoice)
	location := fmt.Sprintf("/invoices/%s", invoice.InvoiceID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CreateInvoiceFromOrder handles POST /invoices/from-order
// This is the method that now supports partial invoicing.
func (h *InvoiceHandler) CreateInvoiceFromOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get authenticated user ID
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Get company ID from header
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Decode request body
	var req createInvoiceFromOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.OrderID == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_id is required")
		return
	}
	orderID, err := uuid.Parse(req.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}

	// Parse partial invoicing items if present
	var partialItems []service.PartialInvoiceItemInput
	if len(req.Items) > 0 {
		partialItems = make([]service.PartialInvoiceItemInput, 0, len(req.Items))
		for _, it := range req.Items {
			orderItemID, err := uuid.Parse(it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			quantity, err := decimal.NewFromString(it.Quantity)
			if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
				return
			}
			partialItems = append(partialItems, service.PartialInvoiceItemInput{
				OrderItemID: orderItemID,
				Quantity:    quantity,
			})
		}
	}

	// Permission check
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Idempotency key (optional, can be used by service)
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	// Build service request with all fields from the incoming request
	svcReq := service.CreateInvoiceFromOrderRequest{
		OrderID:     req.OrderID,     // keep as string, service will parse if needed
		Items:       partialItems,    // ✅ new: partial invoicing items
		InvoiceDate: req.InvoiceDate, // ✅ passed to service
		DueDate:     req.DueDate,     // ✅ passed to service
		Notes:       req.Notes,
		CreatedBy:   &userID, // set the authenticated user
	}

	// Call service
	invoice, err := h.invoiceService.CreateInvoiceFromOrder(ctx, companyID, orderID, &svcReq)
	if err != nil {
		h.logger.Error("failed to create invoice from order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Build response
	resp := h.toInvoiceResponse(invoice)
	location := fmt.Sprintf("/invoices/%s", invoice.InvoiceID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CreateInvoiceFromQuote handles POST /invoices/from-quote
func (h *InvoiceHandler) CreateInvoiceFromQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createInvoiceFromQuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.QuoteID == "" {
		h.respondWithError(w, http.StatusBadRequest, "quote_id is required")
		return
	}
	quoteID, err := uuid.Parse(req.QuoteID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	svcReq := service.CreateInvoiceFromQuoteRequest{
		Notes: req.Notes,
	}
	invoice, err := h.invoiceService.CreateInvoiceFromQuote(ctx, companyID, quoteID, &svcReq)
	if err != nil {
		h.logger.Error("failed to create invoice from quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toInvoiceResponse(invoice)
	location := fmt.Sprintf("/invoices/%s", invoice.InvoiceID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateInvoice handles PUT /invoices/{id}
func (h *InvoiceHandler) UpdateInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req updateInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	svcReq := service.UpdateInvoiceRequest{
		Notes: req.Notes,
	}
	invoice, err := h.invoiceService.UpdateInvoice(ctx, companyID, invoiceID, &svcReq)
	if err != nil {
		h.logger.Error("failed to update invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toInvoiceResponse(invoice)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteInvoice handles DELETE /invoices/{id}
func (h *InvoiceHandler) DeleteInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.DeleteInvoice(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to delete invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice deleted successfully",
	})
}

// GetInvoiceByID handles GET /invoices/{id}
func (h *InvoiceHandler) GetInvoiceByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	invoice, err := h.invoiceService.GetInvoiceByID(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toInvoiceResponse(invoice)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetInvoiceByNumber handles GET /invoices/by-number
func (h *InvoiceHandler) GetInvoiceByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	invoiceNumber := r.URL.Query().Get("number")
	if invoiceNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	invoice, err := h.invoiceService.GetInvoiceByNumber(ctx, companyID, invoiceNumber)
	if err != nil {
		h.logger.Error("failed to get invoice by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toInvoiceResponse(invoice)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListInvoices handles GET /invoices
func (h *InvoiceHandler) ListInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	filter := service.InvoiceListFilter{
		CompanyID: companyID,
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		s := enums.InvoiceStatus(statusStr)
		filter.Status = &s
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		cID, err := uuid.Parse(customerIDStr)
		if err == nil {
			filter.CustomerID = &cID
		}
	}
	if orderIDStr := r.URL.Query().Get("order_id"); orderIDStr != "" {
		oID, err := uuid.Parse(orderIDStr)
		if err == nil {
			filter.OrderID = &oID
		}
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
		sort.Field = "invoice_date"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}
	invoices, total, err := h.invoiceService.ListInvoices(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list invoices")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	resp := listInvoicesResponse{
		Invoices: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchInvoices handles GET /invoices/search
func (h *InvoiceHandler) SearchInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
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
	invoices, total, err := h.invoiceService.SearchInvoices(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search invoices")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	resp := listInvoicesResponse{
		Invoices: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetInvoicesByCustomer handles GET /invoices/by-customer
func (h *InvoiceHandler) GetInvoicesByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
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
		sort.Field = "invoice_date"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}
	invoices, total, err := h.invoiceService.GetInvoicesByCustomer(ctx, companyID, customerID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get invoices by customer", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get invoices")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	resp := listInvoicesResponse{
		Invoices: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetInvoicesByOrder handles GET /invoices/by-order
func (h *InvoiceHandler) GetInvoicesByOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderIDStr := r.URL.Query().Get("order_id")
	if orderIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_id query parameter is required")
		return
	}
	orderID, err := uuid.Parse(orderIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	invoices, err := h.invoiceService.GetInvoicesByOrder(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get invoices by order", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get invoices")
		return
	}
	resp := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		resp[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// AddItems handles POST /invoices/{id}/items
func (h *InvoiceHandler) AddItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req addInvoiceItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	items := make([]service.CreateInvoiceItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		var discount *decimal.Decimal
		if it.Discount != nil && *it.Discount != "" {
			d, err := decimal.NewFromString(*it.Discount)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid discount")
				return
			}
			discount = &d
		}
		var productID uuid.UUID
		if it.ProductID != nil && *it.ProductID != "" {
			pid, err := uuid.Parse(*it.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
				return
			}
			productID = pid
		}
		items[i] = service.CreateInvoiceItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &unitPrice,
			Discount:  discount,
			Metadata:  it.Metadata,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.AddItems(ctx, companyID, invoiceID, items, userID)
	if err != nil {
		h.logger.Error("failed to add items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items added",
	})
}

// ReplaceItems handles PUT /invoices/{id}/items
func (h *InvoiceHandler) ReplaceItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req replaceInvoiceItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	items := make([]service.CreateInvoiceItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		var discount *decimal.Decimal
		if it.Discount != nil && *it.Discount != "" {
			d, err := decimal.NewFromString(*it.Discount)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid discount")
				return
			}
			discount = &d
		}
		var productID uuid.UUID
		if it.ProductID != nil && *it.ProductID != "" {
			pid, err := uuid.Parse(*it.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
				return
			}
			productID = pid
		}
		items[i] = service.CreateInvoiceItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &unitPrice,
			Discount:  discount,
			Metadata:  it.Metadata,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.ReplaceItems(ctx, companyID, invoiceID, items, userID)
	if err != nil {
		h.logger.Error("failed to replace items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items replaced",
	})
}

// RemoveItem handles DELETE /invoices/{id}/items/{itemId}
func (h *InvoiceHandler) RemoveItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	itemID, err := parseUUIDParamInvoice(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RemoveItem(ctx, companyID, invoiceID, itemID, userID)
	if err != nil {
		h.logger.Error("failed to remove item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "item removed",
	})
}

// GetInvoiceItems handles GET /invoices/{id}/items
func (h *InvoiceHandler) GetInvoiceItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	items, err := h.invoiceService.GetInvoiceItems(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get invoice items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]invoiceItemResponse, len(items))
	for i, item := range items {
		resp[i] = h.toInvoiceItemResponse(item)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculatePricing handles POST /invoices/{id}/calculate-pricing
func (h *InvoiceHandler) CalculatePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.CalculatePricing(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to calculate pricing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "pricing calculated",
	})
}

// PreviewPricing handles POST /invoices/preview-pricing
func (h *InvoiceHandler) PreviewPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req service.InvoicePricingPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CompanyID = companyID

	if !h.hasPermission(ctx, req.CompanyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	result, err := h.invoiceService.PreviewPricing(ctx, &req)
	if err != nil {
		h.logger.Error("failed to preview pricing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// RecalculateTotals handles POST /invoices/{id}/recalculate-totals
func (h *InvoiceHandler) RecalculateTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RecalculateTotals(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to recalculate totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "totals recalculated",
	})
}

// GetInvoiceTotals handles GET /invoices/{id}/totals
func (h *InvoiceHandler) GetInvoiceTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	subtotal, discountTotal, taxTotal, grandTotal, amountPaid, amountDue, err := h.invoiceService.GetInvoiceTotals(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get invoice totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := invoiceTotalsResponse{
		Subtotal:      subtotal.String(),
		DiscountTotal: discountTotal.String(),
		TaxTotal:      taxTotal.String(),
		GrandTotal:    grandTotal.String(),
		AmountPaid:    amountPaid.String(),
		AmountDue:     amountDue.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ApplyManualDiscount handles POST /invoices/{id}/manual-discount
func (h *InvoiceHandler) ApplyManualDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req manualDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	discountAmount, err := decimal.NewFromString(req.DiscountAmount)
	if err != nil || discountAmount.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount_amount")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.ApplyManualDiscount(ctx, companyID, invoiceID, discountAmount, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to apply manual discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "manual discount applied",
	})
}

// RemoveManualDiscount handles DELETE /invoices/{id}/manual-discount
func (h *InvoiceHandler) RemoveManualDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RemoveManualDiscount(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to remove manual discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "manual discount removed",
	})
}

// UpdateStatus handles PATCH /invoices/{id}/status
func (h *InvoiceHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req invoiceUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status := enums.InvoiceStatus(req.Status)
	if !status.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.UpdateStatus(ctx, companyID, invoiceID, status, userID)
	if err != nil {
		h.logger.Error("failed to update invoice status", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "status updated",
	})
}

// IssueInvoice handles POST /invoices/{id}/issue
func (h *InvoiceHandler) IssueInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.IssueInvoice(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to issue invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice issued",
	})
}

// MarkAsPaid handles POST /invoices/{id}/mark-paid
func (h *InvoiceHandler) MarkAsPaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req markPaidRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paidAt := time.Now()
	if req.PaidAt != "" {
		paidAt, err = time.Parse(time.RFC3339, req.PaidAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid paid_at")
			return
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.MarkAsPaid(ctx, companyID, invoiceID, paidAt, userID)
	if err != nil {
		h.logger.Error("failed to mark invoice as paid", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice marked as paid",
	})
}

// MarkAsOverdue handles POST /invoices/{id}/mark-overdue
func (h *InvoiceHandler) MarkAsOverdue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.MarkAsOverdue(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to mark invoice as overdue", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice marked as overdue",
	})
}

// VoidInvoice handles POST /invoices/{id}/void
func (h *InvoiceHandler) VoidInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req voidInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.VoidInvoice(ctx, companyID, invoiceID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to void invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice voided",
	})
}

// RegisterPayment handles POST /invoices/{id}/register-payment
func (h *InvoiceHandler) RegisterPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req registerPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paymentID, err := uuid.Parse(req.PaymentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_id")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RegisterPayment(ctx, &service.RegisterInvoicePaymentRequest{
		InvoiceID: invoiceID,
		PaymentID: paymentID,
		Amount:    amount,
	})
	if err != nil {
		h.logger.Error("failed to register payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment registered",
	})
}

// ApplyPayment handles POST /invoices/{id}/apply-payment
func (h *InvoiceHandler) ApplyPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req applyPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paymentID, err := uuid.Parse(req.PaymentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_id")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.ApplyPayment(ctx, companyID, invoiceID, paymentID, amount, userID)
	if err != nil {
		h.logger.Error("failed to apply payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment applied",
	})
}

// RemovePayment handles DELETE /invoices/{id}/payments/{paymentId}
func (h *InvoiceHandler) RemovePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	paymentID, err := parseUUIDParamInvoice(r, "paymentId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RemovePayment(ctx, companyID, invoiceID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to remove payment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment removed",
	})
}

// GetInvoicePayments handles GET /invoices/{id}/payments
func (h *InvoiceHandler) GetInvoicePayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	payments, err := h.invoiceService.GetInvoicePayments(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get invoice payments", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]invoicePaymentResponse, len(payments))
	for i, p := range payments {
		resp[i] = invoicePaymentResponse{
			PaymentID: p.PaymentID.String(),
			Amount:    p.Amount.String(),
			AppliedAt: p.AllocatedAt.Format(time.RFC3339),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetOutstandingAmount handles GET /invoices/{id}/outstanding
func (h *InvoiceHandler) GetOutstandingAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	amount, err := h.invoiceService.GetOutstandingAmount(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get outstanding amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"outstanding_amount": amount.String()},
	})
}

// RefreshPaymentBalances handles POST /invoices/{id}/refresh-balances
func (h *InvoiceHandler) RefreshPaymentBalances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.RefreshPaymentBalances(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to refresh payment balances", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment balances refreshed",
	})
}

// UpdateDueDate handles PATCH /invoices/{id}/due-date
func (h *InvoiceHandler) UpdateDueDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req updateDueDateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	dueDate, err := time.Parse(time.RFC3339, req.DueDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid due_date")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.UpdateDueDate(ctx, companyID, invoiceID, dueDate, userID)
	if err != nil {
		h.logger.Error("failed to update due date", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "due date updated",
	})
}

// GetOverdueInvoices handles GET /invoices/overdue
func (h *InvoiceHandler) GetOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	atStr := r.URL.Query().Get("at")
	at := time.Now()
	if atStr != "" {
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}
	invoices, err := h.invoiceService.GetOverdueInvoices(ctx, companyID, at)
	if err != nil {
		h.logger.Error("failed to get overdue invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get overdue invoices")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetInvoicesDueSoon handles GET /invoices/due-soon
func (h *InvoiceHandler) GetInvoicesDueSoon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before query parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before timestamp")
		return
	}
	invoices, err := h.invoiceService.GetInvoicesDueSoon(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get invoices due soon", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get invoices due soon")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// SendDueReminder handles POST /invoices/{id}/send-due-reminder
func (h *InvoiceHandler) SendDueReminder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.SendDueReminder(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to send due reminder", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "due reminder sent",
	})
}

// SendOverdueReminder handles POST /invoices/{id}/send-overdue-reminder
func (h *InvoiceHandler) SendOverdueReminder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.invoiceService.SendOverdueReminder(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to send overdue reminder", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "overdue reminder sent",
	})
}

// GetTotalInvoicedRevenue handles GET /invoices/total-revenue
func (h *InvoiceHandler) GetTotalInvoicedRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
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
	revenue, err := h.invoiceService.GetTotalInvoicedRevenue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total invoiced revenue", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get revenue")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_revenue": revenue.String()},
	})
}

// GetCollectedRevenue handles GET /invoices/collected-revenue
func (h *InvoiceHandler) GetCollectedRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
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
	revenue, err := h.invoiceService.GetCollectedRevenue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get collected revenue", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get revenue")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"collected_revenue": revenue.String()},
	})
}

// GetOutstandingReceivables handles GET /invoices/outstanding-receivables
func (h *InvoiceHandler) GetOutstandingReceivables(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	amount, err := h.invoiceService.GetOutstandingReceivables(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get outstanding receivables", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get receivables")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"outstanding_receivables": amount.String()},
	})
}

// GetAveragePaymentTime handles GET /invoices/average-payment-time
func (h *InvoiceHandler) GetAveragePaymentTime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
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
	avgDays, err := h.invoiceService.GetAveragePaymentTime(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get average payment time", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get average payment time")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"average_payment_days": avgDays.String()},
	})
}

// GetTopOverdueInvoices handles GET /invoices/top-overdue
func (h *InvoiceHandler) GetTopOverdueInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	invoices, err := h.invoiceService.GetTopOverdueInvoices(ctx, companyID, limit)
	if err != nil {
		h.logger.Error("failed to get top overdue invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get top overdue invoices")
		return
	}
	summaries := make([]invoiceSummary, len(invoices))
	for i, inv := range invoices {
		summaries[i] = invoiceSummary{
			InvoiceID:     inv.InvoiceID.String(),
			InvoiceNumber: inv.InvoiceNumber,
			CustomerID:    inv.CustomerID.String(),
			Status:        string(inv.Status),
			InvoiceDate:   inv.InvoiceDate.Format(time.RFC3339),
			DueDate:       inv.DueDate.Format(time.RFC3339),
			GrandTotal:    inv.GrandTotal.String(),
			AmountDue:     inv.AmountDue.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// InvoiceExists handles GET /invoices/{id}/exists
func (h *InvoiceHandler) InvoiceExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	exists, err := h.invoiceService.InvoiceExists(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to check invoice exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// IsInvoicePaid handles GET /invoices/{id}/is-paid
func (h *InvoiceHandler) IsInvoicePaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	paid, err := h.invoiceService.IsInvoicePaid(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to check if invoice paid", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"is_paid": paid},
	})
}

// IsInvoiceOverdue handles GET /invoices/{id}/is-overdue
func (h *InvoiceHandler) IsInvoiceOverdue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParamInvoice(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	atStr := r.URL.Query().Get("at")
	at := time.Now()
	if atStr != "" {
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	overdue, err := h.invoiceService.IsInvoiceOverdue(ctx, companyID, invoiceID, at)
	if err != nil {
		h.logger.Error("failed to check if invoice overdue", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"is_overdue": overdue},
	})
}
