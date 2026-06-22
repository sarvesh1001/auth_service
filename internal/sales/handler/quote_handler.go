// file: internal/sales/handler/quote_handler.go

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

// QuoteHandler handles HTTP requests for quote management.
type QuoteHandler struct {
	quoteService service.QuoteService
	customerSvc  service.CustomerService // for customer existence checks
	salesRepSvc  service.SalesRepService
	*BaseHandler
}

// NewQuoteHandler creates a new QuoteHandler.
func NewQuoteHandler(
	quoteService service.QuoteService,
	customerSvc service.CustomerService,
	salesRepSvc service.SalesRepService,
	logger *zap.Logger,
) *QuoteHandler {
	return &QuoteHandler{
		quoteService: quoteService,
		customerSvc:  customerSvc,
		salesRepSvc:  salesRepSvc,
		BaseHandler:  &BaseHandler{logger: logger.Named("quote_handler")},
	}
}

// ---------- Request/Response Types ----------

type createQuoteRequest struct {
	CompanyID  *string            `json:"company_id,omitempty"`
	CustomerID string             `json:"customer_id"`
	QuoteDate  string             `json:"quote_date"`
	ExpiryDate *string            `json:"expiry_date,omitempty"`
	Currency   string             `json:"currency"`
	Notes      *string            `json:"notes,omitempty"`
	SalesRepID *string            `json:"sales_rep_id,omitempty"`
	Items      []quoteItemRequest `json:"items"`
}

type quoteItemRequest struct {
	ProductID string `json:"product_id"`
	Quantity  string `json:"quantity"`
	UnitPrice string `json:"unit_price"`
}

type createQuoteResponse struct {
	QuoteID       string  `json:"quote_id"`
	CompanyID     string  `json:"company_id"`
	CustomerID    string  `json:"customer_id"`
	QuoteNumber   string  `json:"quote_number"`
	Revision      int     `json:"revision"`
	QuoteDate     string  `json:"quote_date"`
	ExpiryDate    *string `json:"expiry_date,omitempty"`
	Status        string  `json:"status"`
	Currency      string  `json:"currency"`
	Subtotal      string  `json:"subtotal"`
	DiscountTotal string  `json:"discount_total"`
	TaxTotal      string  `json:"tax_total"`
	GrandTotal    string  `json:"grand_total"`
	Notes         *string `json:"notes,omitempty"`
	SalesRepID    *string `json:"sales_rep_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type updateQuoteRequest struct {
	ExpiryDate *string `json:"expiry_date,omitempty"`
	Currency   *string `json:"currency,omitempty"`
	Notes      *string `json:"notes,omitempty"`
}

type updateQuoteStatusRequest struct {
	Status string `json:"status"`
}

type convertQuoteToOrderRequest struct {
	OrderDate *string `json:"order_date,omitempty"`
	Notes     *string `json:"notes,omitempty"`
}

type quoteAssignSalesRepRequest struct {
	SalesRepID string `json:"sales_rep_id"`
}

type createQuoteRevisionRequest struct {
	Items []quoteItemRequest `json:"items"`
	Notes *string            `json:"notes,omitempty"`
}

type listQuotesResponse struct {
	Quotes []quoteSummary `json:"quotes"`
	Total  int64          `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type quoteSummary struct {
	QuoteID     string  `json:"quote_id"`
	QuoteNumber string  `json:"quote_number"`
	Revision    int     `json:"revision"`
	CustomerID  string  `json:"customer_id"`
	Status      string  `json:"status"`
	GrandTotal  string  `json:"grand_total"`
	QuoteDate   string  `json:"quote_date"`
	ExpiryDate  *string `json:"expiry_date,omitempty"`
}

type quoteTotalsResponse struct {
	Subtotal      string `json:"subtotal"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
	GrandTotal    string `json:"grand_total"`
}

type quoteItemResponse struct {
	QuoteItemID         string `json:"quote_item_id"`
	ProductID           string `json:"product_id"`
	ProductNameSnapshot string `json:"product_name_snapshot"`
	Quantity            string `json:"quantity"`
	UnitPrice           string `json:"unit_price"`
	DiscountAmount      string `json:"discount_amount"`
	TaxAmount           string `json:"tax_amount"`
	TotalPrice          string `json:"total_price"`
}

type quotePricingPreviewRequest struct {
	CustomerID string             `json:"customer_id"`
	Items      []quoteItemRequest `json:"items"`
}

type quotePricingPreviewResponse struct {
	Subtotal      string `json:"subtotal"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
	GrandTotal    string `json:"grand_total"`
}

// Supported currencies
var supportedCurrencies = map[string]bool{
	"USD": true,
	"EUR": true,
	"GBP": true,
	"JPY": true,
	"CAD": true,
	"AUD": true,
	"CHF": true,
	"CNY": true,
	"INR": true,
}

// ---------- Helper ----------

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *QuoteHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// validateCurrency checks if the currency code is supported.
func (h *QuoteHandler) validateCurrency(currency string) error {
	if currency == "" {
		return nil // default will be applied later
	}
	if !supportedCurrencies[currency] {
		return fmt.Errorf("unsupported currency code: %s", currency)
	}
	return nil
}

// validateQuantityAndUnitPrice performs overflow checks.
func (h *QuoteHandler) validateQuantityAndUnitPrice(quantity decimal.Decimal, unitPrice decimal.Decimal, idx int) error {
	const maxQuantity = 999999
	const maxUnitPrice = 999999.9999

	if quantity.GreaterThan(decimal.NewFromInt(maxQuantity)) {
		return fmt.Errorf("item[%d] quantity exceeds maximum %d", idx, maxQuantity)
	}
	if unitPrice.GreaterThan(decimal.NewFromFloat(maxUnitPrice)) {
		return fmt.Errorf("item[%d] unit_price exceeds maximum %.4f", idx, maxUnitPrice)
	}
	return nil
}

// ---------- Handler Methods ----------

// CreateQuote handles POST /quotes
func (h *QuoteHandler) CreateQuote(w http.ResponseWriter, r *http.Request) {
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

	var req createQuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Optional company_id in body must match header if provided
	if req.CompanyID != nil && *req.CompanyID != "" {
		if *req.CompanyID != companyID.String() {
			h.respondWithError(w, http.StatusBadRequest, "company_id in body does not match header")
			return
		}
	}

	// Validate customer_id
	if req.CustomerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id is required")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	// Validate items
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	// Parse dates
	var quoteDate time.Time
	if req.QuoteDate != "" {
		quoteDate, err = time.Parse(time.RFC3339, req.QuoteDate)
		if err != nil {
			quoteDate, err = time.Parse("2006-01-02", req.QuoteDate)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid quote_date format, use RFC3339 or YYYY-MM-DD")
			return
		}
	} else {
		quoteDate = time.Now()
	}

	var expiryDate *time.Time
	if req.ExpiryDate != nil && *req.ExpiryDate != "" {
		exp, err := time.Parse(time.RFC3339, *req.ExpiryDate)
		if err != nil {
			exp, err = time.Parse("2006-01-02", *req.ExpiryDate)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid expiry_date format")
			return
		}
		expiryDate = &exp
	}

	// Expiry date must not be before quote date
	if expiryDate != nil && expiryDate.Before(quoteDate) {
		h.respondWithError(w, http.StatusBadRequest, "expiry_date cannot be before quote_date")
		return
	}

	// Currency validation
	currency := req.Currency
	if currency == "" {
		currency = "USD"
	}
	if err := h.validateCurrency(currency); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Notes length validation
	if req.Notes != nil && len(*req.Notes) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, "notes must not exceed 1000 characters")
		return
	}

	// Customer existence check
	customerExists, err := h.customerSvc.CustomerExists(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to check customer existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal error checking customer")
		return
	}
	if !customerExists {
		h.respondWithError(w, http.StatusNotFound, "customer not found")
		return
	}

	var salesRepID *uuid.UUID
	if req.SalesRepID != nil && *req.SalesRepID != "" {
		parsed, err := uuid.Parse(*req.SalesRepID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
			return
		}
		exists, err := h.salesRepSvc.SalesRepExists(ctx, companyID, parsed)
		if err != nil {
			h.logger.Error("failed to check sales rep existence", zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "internal error checking sales rep")
			return
		}
		if !exists {
			h.respondWithError(w, http.StatusNotFound, "sales_rep not found")
			return
		}
		salesRepID = &parsed
	}

	// Build items with overflow validation
	items := make([]*service.CreateQuoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		if it.ProductID == "" {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] product_id is required", i))
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid product_id", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid quantity", i))
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid unit_price", i))
			return
		}
		// Overflow checks
		if err := h.validateQuantityAndUnitPrice(quantity, unitPrice, i); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		up := unitPrice
		items[i] = &service.CreateQuoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &up,
		}
	}

	// Permission check
	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Idempotency
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	svcReq := &service.CreateQuoteRequest{
		CompanyID:  companyID,
		CustomerID: customerID,
		QuoteDate:  quoteDate,
		ExpiryDate: expiryDate,
		Currency:   currency,
		Notes:      req.Notes,
		SalesRepID: salesRepID,
		Items:      items,
		CreatedBy:  &userID,
	}

	quote, err := h.quoteService.CreateQuote(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       quote.QuoteID.String(),
		CompanyID:     quote.CompanyID.String(),
		CustomerID:    quote.CustomerID.String(),
		QuoteNumber:   quote.QuoteNumber,
		Revision:      quote.Revision,
		QuoteDate:     quote.QuoteDate.Format(time.RFC3339),
		Status:        string(quote.Status),
		Currency:      quote.Currency,
		Subtotal:      quote.Subtotal.String(),
		DiscountTotal: quote.DiscountTotal.String(),
		TaxTotal:      quote.TaxTotal.String(),
		GrandTotal:    quote.GrandTotal.String(),
		Notes:         quote.Notes,
		CreatedAt:     quote.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     quote.UpdatedAt.Format(time.RFC3339),
	}
	if quote.ExpiryDate != nil {
		exp := quote.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if quote.SalesRepID != nil {
		sid := quote.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	location := fmt.Sprintf("/quotes/%s", quote.QuoteID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateQuote handles PUT /quotes/{id}
func (h *QuoteHandler) UpdateQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateQuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Notes length validation
	if req.Notes != nil && len(*req.Notes) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, "notes must not exceed 1000 characters")
		return
	}

	var expiryDate *time.Time
	if req.ExpiryDate != nil && *req.ExpiryDate != "" {
		exp, err := time.Parse(time.RFC3339, *req.ExpiryDate)
		if err != nil {
			exp, err = time.Parse("2006-01-02", *req.ExpiryDate)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid expiry_date format")
			return
		}
		expiryDate = &exp
	}

	// Currency validation
	if req.Currency != nil && *req.Currency != "" {
		if err := h.validateCurrency(*req.Currency); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	svcReq := &service.UpdateQuoteRequest{
		ExpiryDate: expiryDate,
		Currency:   req.Currency,
		Notes:      req.Notes,
		UpdatedBy:  &userID,
	}

	updated, err := h.quoteService.UpdateQuote(ctx, companyID, quoteID, svcReq)
	if err != nil {
		h.logger.Error("failed to update quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       updated.QuoteID.String(),
		CompanyID:     updated.CompanyID.String(),
		CustomerID:    updated.CustomerID.String(),
		QuoteNumber:   updated.QuoteNumber,
		Revision:      updated.Revision,
		QuoteDate:     updated.QuoteDate.Format(time.RFC3339),
		Status:        string(updated.Status),
		Currency:      updated.Currency,
		Subtotal:      updated.Subtotal.String(),
		DiscountTotal: updated.DiscountTotal.String(),
		TaxTotal:      updated.TaxTotal.String(),
		GrandTotal:    updated.GrandTotal.String(),
		Notes:         updated.Notes,
		CreatedAt:     updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.ExpiryDate != nil {
		exp := updated.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if updated.SalesRepID != nil {
		sid := updated.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteQuote handles DELETE /quotes/{id}
func (h *QuoteHandler) DeleteQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.DeleteQuote(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to delete quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote deleted successfully",
	})
}

// GetQuoteByID handles GET /quotes/{id}
func (h *QuoteHandler) GetQuoteByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	quote, err := h.quoteService.GetQuoteByID(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to get quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       quote.QuoteID.String(),
		CompanyID:     quote.CompanyID.String(),
		CustomerID:    quote.CustomerID.String(),
		QuoteNumber:   quote.QuoteNumber,
		Revision:      quote.Revision,
		QuoteDate:     quote.QuoteDate.Format(time.RFC3339),
		Status:        string(quote.Status),
		Currency:      quote.Currency,
		Subtotal:      quote.Subtotal.String(),
		DiscountTotal: quote.DiscountTotal.String(),
		TaxTotal:      quote.TaxTotal.String(),
		GrandTotal:    quote.GrandTotal.String(),
		Notes:         quote.Notes,
		CreatedAt:     quote.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     quote.UpdatedAt.Format(time.RFC3339),
	}
	if quote.ExpiryDate != nil {
		exp := quote.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if quote.SalesRepID != nil {
		sid := quote.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetQuoteByNumber handles GET /quotes/by-number
func (h *QuoteHandler) GetQuoteByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	quoteNumber := r.URL.Query().Get("number")
	if quoteNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}

	revisionStr := r.URL.Query().Get("revision")
	revision := 1
	if revisionStr != "" {
		rev, err := strconv.Atoi(revisionStr)
		if err == nil && rev > 0 {
			revision = rev
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	quote, err := h.quoteService.GetQuoteByNumber(ctx, companyID, quoteNumber, revision)
	if err != nil {
		h.logger.Error("failed to get quote by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       quote.QuoteID.String(),
		CompanyID:     quote.CompanyID.String(),
		CustomerID:    quote.CustomerID.String(),
		QuoteNumber:   quote.QuoteNumber,
		Revision:      quote.Revision,
		QuoteDate:     quote.QuoteDate.Format(time.RFC3339),
		Status:        string(quote.Status),
		Currency:      quote.Currency,
		Subtotal:      quote.Subtotal.String(),
		DiscountTotal: quote.DiscountTotal.String(),
		TaxTotal:      quote.TaxTotal.String(),
		GrandTotal:    quote.GrandTotal.String(),
		Notes:         quote.Notes,
		CreatedAt:     quote.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     quote.UpdatedAt.Format(time.RFC3339),
	}
	if quote.ExpiryDate != nil {
		exp := quote.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if quote.SalesRepID != nil {
		sid := quote.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListQuotes handles GET /quotes
func (h *QuoteHandler) ListQuotes(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.QuoteListFilter{CompanyID: companyID}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		customerID, err := uuid.Parse(customerIDStr)
		if err == nil {
			filter.CustomerID = &customerID
		}
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		status := enums.QuoteStatus(statusStr)
		filter.Status = &status
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}

	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "created_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	quotes, total, err := h.quoteService.ListQuotes(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list quotes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list quotes")
		return
	}

	summaries := make([]quoteSummary, len(quotes))
	for i, q := range quotes {
		summaries[i] = quoteSummary{
			QuoteID:     q.QuoteID.String(),
			QuoteNumber: q.QuoteNumber,
			Revision:    q.Revision,
			CustomerID:  q.CustomerID.String(),
			Status:      string(q.Status),
			GrandTotal:  q.GrandTotal.String(),
			QuoteDate:   q.QuoteDate.Format(time.RFC3339),
		}
		if q.ExpiryDate != nil {
			exp := q.ExpiryDate.Format(time.RFC3339)
			summaries[i].ExpiryDate = &exp
		}
	}

	resp := listQuotesResponse{
		Quotes: summaries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchQuotes handles GET /quotes/search
func (h *QuoteHandler) SearchQuotes(w http.ResponseWriter, r *http.Request) {
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

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	quotes, total, err := h.quoteService.SearchQuotes(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search quotes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search quotes")
		return
	}

	summaries := make([]quoteSummary, len(quotes))
	for i, q := range quotes {
		summaries[i] = quoteSummary{
			QuoteID:     q.QuoteID.String(),
			QuoteNumber: q.QuoteNumber,
			Revision:    q.Revision,
			CustomerID:  q.CustomerID.String(),
			Status:      string(q.Status),
			GrandTotal:  q.GrandTotal.String(),
			QuoteDate:   q.QuoteDate.Format(time.RFC3339),
		}
		if q.ExpiryDate != nil {
			exp := q.ExpiryDate.Format(time.RFC3339)
			summaries[i].ExpiryDate = &exp
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"quotes": summaries,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// AddItems handles POST /quotes/{id}/items
func (h *QuoteHandler) AddItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var itemsReq []quoteItemRequest
	if err := json.NewDecoder(r.Body).Decode(&itemsReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(itemsReq) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	items := make([]*service.CreateQuoteItemRequest, len(itemsReq))
	for i, it := range itemsReq {
		if it.ProductID == "" {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] product_id is required", i))
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid product_id", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid quantity", i))
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid unit_price", i))
			return
		}
		// Overflow checks
		if err := h.validateQuantityAndUnitPrice(quantity, unitPrice, i); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		up := unitPrice
		items[i] = &service.CreateQuoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &up,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.AddItems(ctx, companyID, quoteID, items, userID)
	if err != nil {
		h.logger.Error("failed to add items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items added successfully",
	})
}

// ReplaceItems handles PUT /quotes/{id}/items
func (h *QuoteHandler) ReplaceItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var itemsReq []quoteItemRequest
	if err := json.NewDecoder(r.Body).Decode(&itemsReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Allow empty array to clear items
	items := make([]*service.CreateQuoteItemRequest, len(itemsReq))
	for i, it := range itemsReq {
		if it.ProductID == "" {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] product_id is required", i))
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid product_id", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid quantity", i))
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid unit_price", i))
			return
		}
		// Overflow checks
		if err := h.validateQuantityAndUnitPrice(quantity, unitPrice, i); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		up := unitPrice
		items[i] = &service.CreateQuoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &up,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.ReplaceItems(ctx, companyID, quoteID, items, userID)
	if err != nil {
		h.logger.Error("failed to replace items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items replaced successfully",
	})
}

// RemoveItem handles DELETE /quotes/{id}/items/{itemId}
func (h *QuoteHandler) RemoveItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
		return
	}

	itemID, err := h.parseUUIDParam(r, "itemId")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.RemoveItem(ctx, companyID, quoteID, itemID, userID)
	if err != nil {
		h.logger.Error("failed to remove item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "item removed successfully",
	})
}

// GetQuoteItems handles GET /quotes/{id}/items
func (h *QuoteHandler) GetQuoteItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.quoteService.GetQuoteItems(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to get quote items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]quoteItemResponse, len(items))
	for i, it := range items {
		resp[i] = quoteItemResponse{
			QuoteItemID:         it.QuoteItemID.String(),
			ProductID:           it.ProductID.String(),
			ProductNameSnapshot: it.ProductNameSnapshot,
			Quantity:            it.Quantity.String(),
			UnitPrice:           it.UnitPrice.String(),
			DiscountAmount:      it.DiscountAmount.String(),
			TaxAmount:           it.TaxAmount.String(),
			TotalPrice:          it.TotalPrice.String(),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ApplyCoupon handles POST /quotes/{id}/coupons
// ApplyCoupon handles POST /quotes/{id}/coupons
func (h *QuoteHandler) ApplyCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	// Log the request
	h.logger.Info("ApplyCoupon request",
		zap.String("quote_id", quoteID.String()),
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.logger.Warn("permission denied", zap.String("user_id", userID.String()))
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		CouponCode string `json:"coupon_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("invalid request body", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CouponCode == "" {
		h.logger.Warn("coupon_code missing")
		h.respondWithError(w, http.StatusBadRequest, "coupon_code is required")
		return
	}

	// Log the coupon code
	h.logger.Info("coupon code received", zap.String("coupon_code", req.CouponCode))

	// Get idempotency key from header
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.logger.Warn("idempotency key missing")
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	h.logger.Info("calling service ApplyCoupon",
		zap.String("quote_id", quoteID.String()),
		zap.String("coupon_code", req.CouponCode),
		zap.String("idempotency_key", idempotencyKey),
	)

	coupon, discount, err := h.quoteService.ApplyCoupon(ctx, companyID, quoteID, req.CouponCode, userID)
	if err != nil {
		h.logger.Error("failed to apply coupon",
			zap.Error(err),
			zap.String("quote_id", quoteID.String()),
			zap.String("coupon_code", req.CouponCode),
		)
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.logger.Info("coupon applied successfully",
		zap.String("coupon_code", coupon.Code),
		zap.String("discount_amount", discount.String()),
	)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"coupon_code":     coupon.Code,
			"discount_amount": discount.String(),
		},
	})
}

// RemoveCoupon handles DELETE /quotes/{id}/coupons/{code}
func (h *QuoteHandler) RemoveCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
		return
	}

	couponCode := chi.URLParam(r, "code")
	if couponCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon code is required")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.RemoveCoupon(ctx, companyID, quoteID, couponCode, userID)
	if err != nil {
		h.logger.Error("failed to remove coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon removed successfully",
	})
}

// ApplyBestDiscounts handles POST /quotes/{id}/best-discounts
func (h *QuoteHandler) ApplyBestDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.ApplyBestDiscounts(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to apply best discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "best discounts applied",
	})
}

// PreviewPricing handles POST /quotes/preview-pricing
func (h *QuoteHandler) PreviewPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req quotePricingPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.CustomerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id is required")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	items := make([]*service.CreateQuoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		if it.ProductID == "" {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] product_id is required", i))
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid product_id", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid quantity", i))
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid unit_price", i))
			return
		}
		// Overflow checks
		if err := h.validateQuantityAndUnitPrice(quantity, unitPrice, i); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		up := unitPrice
		items[i] = &service.CreateQuoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &up,
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	previewReq := &service.QuotePricingPreviewRequest{
		CompanyID:  companyID,
		CustomerID: &customerID,
		Items:      items,
	}

	result, err := h.quoteService.PreviewPricing(ctx, previewReq)
	if err != nil {
		h.logger.Error("failed to preview pricing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := quotePricingPreviewResponse{
		Subtotal:      result.Subtotal.String(),
		DiscountTotal: result.DiscountTotal.String(),
		TaxTotal:      result.TaxTotal.String(),
		GrandTotal:    result.GrandTotal.String(),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RecalculateTotals handles POST /quotes/{id}/recalculate
func (h *QuoteHandler) RecalculateTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.RecalculateTotals(ctx, companyID, quoteID, userID)
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

// GetQuoteTotals handles GET /quotes/{id}/totals
func (h *QuoteHandler) GetQuoteTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	subtotal, discountTotal, taxTotal, grandTotal, err := h.quoteService.GetQuoteTotals(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to get quote totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := quoteTotalsResponse{
		Subtotal:      subtotal.String(),
		DiscountTotal: discountTotal.String(),
		TaxTotal:      taxTotal.String(),
		GrandTotal:    grandTotal.String(),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CreateRevision handles POST /quotes/{id}/revision
func (h *QuoteHandler) CreateRevision(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createQuoteRevisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required for revision")
		return
	}

	items := make([]*service.CreateQuoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		if it.ProductID == "" {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] product_id is required", i))
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid product_id", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid quantity", i))
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("item[%d] invalid unit_price", i))
			return
		}
		// Overflow checks
		if err := h.validateQuantityAndUnitPrice(quantity, unitPrice, i); err != nil {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		up := unitPrice
		items[i] = &service.CreateQuoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: &up,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	revisionReq := &service.CreateQuoteRevisionRequest{
		Items:       items,
		Notes:       req.Notes,
		UpdatedBy:   &userID,
		ExpiryDate:  nil, // kept as nil to reuse existing logic
		CouponCodes: nil,
	}

	newQuote, err := h.quoteService.CreateRevision(ctx, companyID, quoteID, revisionReq)
	if err != nil {
		h.logger.Error("failed to create revision", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       newQuote.QuoteID.String(),
		CompanyID:     newQuote.CompanyID.String(),
		CustomerID:    newQuote.CustomerID.String(),
		QuoteNumber:   newQuote.QuoteNumber,
		Revision:      newQuote.Revision,
		QuoteDate:     newQuote.QuoteDate.Format(time.RFC3339),
		Status:        string(newQuote.Status),
		Currency:      newQuote.Currency,
		Subtotal:      newQuote.Subtotal.String(),
		DiscountTotal: newQuote.DiscountTotal.String(),
		TaxTotal:      newQuote.TaxTotal.String(),
		GrandTotal:    newQuote.GrandTotal.String(),
		Notes:         newQuote.Notes,
		CreatedAt:     newQuote.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     newQuote.UpdatedAt.Format(time.RFC3339),
	}
	if newQuote.ExpiryDate != nil {
		exp := newQuote.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if newQuote.SalesRepID != nil {
		sid := newQuote.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetLatestRevision handles GET /quotes/latest-revision
func (h *QuoteHandler) GetLatestRevision(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	quoteNumber := r.URL.Query().Get("number")
	if quoteNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	quote, err := h.quoteService.GetLatestRevision(ctx, companyID, quoteNumber)
	if err != nil {
		h.logger.Error("failed to get latest revision", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createQuoteResponse{
		QuoteID:       quote.QuoteID.String(),
		CompanyID:     quote.CompanyID.String(),
		CustomerID:    quote.CustomerID.String(),
		QuoteNumber:   quote.QuoteNumber,
		Revision:      quote.Revision,
		QuoteDate:     quote.QuoteDate.Format(time.RFC3339),
		Status:        string(quote.Status),
		Currency:      quote.Currency,
		Subtotal:      quote.Subtotal.String(),
		DiscountTotal: quote.DiscountTotal.String(),
		TaxTotal:      quote.TaxTotal.String(),
		GrandTotal:    quote.GrandTotal.String(),
		Notes:         quote.Notes,
		CreatedAt:     quote.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     quote.UpdatedAt.Format(time.RFC3339),
	}
	if quote.ExpiryDate != nil {
		exp := quote.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &exp
	}
	if quote.SalesRepID != nil {
		sid := quote.SalesRepID.String()
		resp.SalesRepID = &sid
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateStatus handles PATCH /quotes/{id}/status
func (h *QuoteHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateQuoteStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.UpdateStatus(ctx, companyID, quoteID, enums.QuoteStatus(req.Status), userID)
	if err != nil {
		h.logger.Error("failed to update quote status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote status updated",
	})
}

// MarkSent handles POST /quotes/{id}/send
func (h *QuoteHandler) MarkSent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.MarkSent(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to mark quote as sent", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote marked as sent",
	})
}

// AcceptQuote handles POST /quotes/{id}/accept
func (h *QuoteHandler) AcceptQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.AcceptQuote(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to accept quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote accepted",
	})
}

// RejectQuote handles POST /quotes/{id}/reject
func (h *QuoteHandler) RejectQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Reason *string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.RejectQuote(ctx, companyID, quoteID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to reject quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote rejected",
	})
}

// ExpireQuote handles POST /quotes/{id}/expire
func (h *QuoteHandler) ExpireQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.ExpireQuote(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to expire quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote expired",
	})
}

// GetExpiringQuotes handles GET /quotes/expiring
func (h *QuoteHandler) GetExpiringQuotes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before query parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		before, err = time.Parse("2006-01-02", beforeStr)
	}
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before date format")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	quotes, err := h.quoteService.GetExpiringQuotes(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get expiring quotes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get expiring quotes")
		return
	}

	summaries := make([]quoteSummary, len(quotes))
	for i, q := range quotes {
		summaries[i] = quoteSummary{
			QuoteID:     q.QuoteID.String(),
			QuoteNumber: q.QuoteNumber,
			Revision:    q.Revision,
			CustomerID:  q.CustomerID.String(),
			Status:      string(q.Status),
			GrandTotal:  q.GrandTotal.String(),
			QuoteDate:   q.QuoteDate.Format(time.RFC3339),
		}
		if q.ExpiryDate != nil {
			exp := q.ExpiryDate.Format(time.RFC3339)
			summaries[i].ExpiryDate = &exp
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ConvertToOrder handles POST /quotes/{id}/convert-to-order
func (h *QuoteHandler) ConvertToOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req convertQuoteToOrderRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // optional body

	var orderDate time.Time
	if req.OrderDate != nil && *req.OrderDate != "" {
		od, err := time.Parse(time.RFC3339, *req.OrderDate)
		if err != nil {
			od, err = time.Parse("2006-01-02", *req.OrderDate)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid order_date format")
			return
		}
		orderDate = od
	} else {
		orderDate = time.Now()
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	convertReq := &service.ConvertQuoteToOrderRequest{
		OrderDate: orderDate,
		Notes:     req.Notes,
		UpdatedBy: &userID,
	}

	order, err := h.quoteService.ConvertToOrder(ctx, companyID, quoteID, convertReq)
	if err != nil {
		h.logger.Error("failed to convert quote to order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"order_id":     order.OrderID.String(),
			"order_number": order.OrderNumber,
		},
	})
}

// IsConverted handles GET /quotes/{id}/is-converted
func (h *QuoteHandler) IsConverted(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	converted, err := h.quoteService.IsConverted(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to check if quote is converted", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"is_converted": converted},
	})
}

// AssignSalesRep handles POST /quotes/{id}/assign-sales-rep
func (h *QuoteHandler) AssignSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req quoteAssignSalesRepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SalesRepID == "" {
		h.respondWithError(w, http.StatusBadRequest, "sales_rep_id is required")
		return
	}
	salesRepID, err := uuid.Parse(req.SalesRepID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.AssignSalesRep(ctx, companyID, quoteID, salesRepID, userID)
	if err != nil {
		h.logger.Error("failed to assign sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sales rep assigned",
	})
}

// RemoveSalesRep handles DELETE /quotes/{id}/assign-sales-rep
func (h *QuoteHandler) RemoveSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	err = h.quoteService.RemoveSalesRep(ctx, companyID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to remove sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sales rep removed",
	})
}

// GetQuoteConversionRate handles GET /quotes/conversion-rate
func (h *QuoteHandler) GetQuoteConversionRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", fromStr)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from date")
			return
		}
		from = &t
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", toStr)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to date")
			return
		}
		to = &t
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rate, err := h.quoteService.GetQuoteConversionRate(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get quote conversion rate", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get conversion rate")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"conversion_rate": rate.String()},
	})
}

// GetTotalQuotedRevenue handles GET /quotes/total-quoted-revenue
func (h *QuoteHandler) GetTotalQuotedRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", fromStr)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from date")
			return
		}
		from = &t
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", toStr)
		}
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to date")
			return
		}
		to = &t
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	revenue, err := h.quoteService.GetTotalQuotedRevenue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total quoted revenue", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total quoted revenue")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_quoted_revenue": revenue.String()},
	})
}

// QuoteExists handles GET /quotes/{id}/exists
func (h *QuoteHandler) QuoteExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
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

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.quoteService.QuoteExists(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to check quote existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// IsExpired handles GET /quotes/{id}/expired
func (h *QuoteHandler) IsExpired(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "at query parameter is required")
		return
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		at, err = time.Parse("2006-01-02", atStr)
	}
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at date format")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "quote:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	expired, err := h.quoteService.IsExpired(ctx, companyID, quoteID, at)
	if err != nil {
		h.logger.Error("failed to check if quote is expired", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"expired": expired},
	})
}
