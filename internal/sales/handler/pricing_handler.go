package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/service"
)

type PricingHandler struct {
	pricingService service.PricingService
	*BaseHandler
	// Simple idempotency cache (replace with real store)
	idempotencyCache map[string]interface{}
}

func NewPricingHandler(pricingService service.PricingService, logger *zap.Logger) *PricingHandler {
	return &PricingHandler{
		pricingService:   pricingService,
		BaseHandler:      &BaseHandler{logger: logger.Named("commission_handler")},
		idempotencyCache: make(map[string]interface{}),
	}
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// GET /pricing/product-base-price
// ---------------------------------------------------------------------
func (h *PricingHandler) GetProductBasePrice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	productID, err := parseQueryUUID(r, "product_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	price, err := h.pricingService.GetProductBasePrice(ctx, companyID, productID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"base_price": price.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/products-base-prices
// ---------------------------------------------------------------------
func (h *PricingHandler) GetProductsBasePrices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	productIDsStr := r.URL.Query().Get("product_ids")
	if productIDsStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "product_ids query parameter is required (comma-separated)")
		return
	}
	parts := strings.Split(productIDsStr, ",")
	productIDs := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		id, err := uuid.Parse(strings.TrimSpace(p))
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
			return
		}
		productIDs = append(productIDs, id)
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	prices, err := h.pricingService.GetProductsBasePrices(ctx, companyID, productIDs)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make(map[string]string)
	for id, price := range prices {
		resp[id.String()] = price.String()
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// POST /pricing/order
// ---------------------------------------------------------------------
type calculateOrderPricingRequest struct {
	CompanyID    string             `json:"company_id"`
	CustomerID   *string            `json:"customer_id,omitempty"`
	Lines        []pricingLineInput `json:"lines"`
	CouponCodes  []string           `json:"coupon_codes,omitempty"`
	CalculateTax bool               `json:"calculate_tax"`
	At           *time.Time         `json:"at,omitempty"`
}
type pricingLineInput struct {
	ProductID string  `json:"product_id"`
	Quantity  string  `json:"quantity"`
	UnitPrice *string `json:"unit_price,omitempty"`
}
type pricingCalculationResultResponse struct {
	Subtotal          string                      `json:"subtotal"`
	DiscountTotal     string                      `json:"discount_total"`
	TaxTotal          string                      `json:"tax_total"`
	GrandTotal        string                      `json:"grand_total"`
	LineResults       []pricingLineResultResponse `json:"line_results"`
	AppliedCoupons    []couponSummary             `json:"applied_coupons"`
	AppliedPromotions []promotionSummary          `json:"applied_promotions"`
}
type pricingLineResultResponse struct {
	ProductID       string `json:"product_id"`
	Quantity        string `json:"quantity"`
	BasePrice       string `json:"base_price"`
	DiscountAmount  string `json:"discount_amount"`
	TaxAmount       string `json:"tax_amount"`
	FinalLineAmount string `json:"final_line_amount"`
}

func (h *PricingHandler) CalculateOrderPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateOrderPricingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CompanyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id required")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	if len(req.Lines) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one line required")
		return
	}
	lines := make([]service.PricingLineInput, len(req.Lines))
	for i, l := range req.Lines {
		prodID, err := uuid.Parse(l.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in line")
			return
		}
		qty, err := decimal.NewFromString(l.Quantity)
		if err != nil || qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity in line")
			return
		}
		var unitPrice *decimal.Decimal
		if l.UnitPrice != nil && *l.UnitPrice != "" {
			up, err := decimal.NewFromString(*l.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid unit_price in line")
				return
			}
			if up.LessThan(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, "unit_price cannot be negative")
				return
			}
			unitPrice = &up
		}
		lines[i] = service.PricingLineInput{
			ProductID: prodID,
			Quantity:  qty,
			UnitPrice: unitPrice,
		}
	}
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	// Idempotency: check cache (simple)
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	svcReq := service.CalculateOrderPricingRequest{
		CompanyID:    companyID,
		CustomerID:   customerID,
		Lines:        lines,
		CouponCodes:  req.CouponCodes,
		CalculateTax: req.CalculateTax,
		At:           at,
	}
	res, err := h.pricingService.CalculateOrderPricing(ctx, &svcReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingCalculationResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/preview-order
// ---------------------------------------------------------------------
func (h *PricingHandler) PreviewOrderPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req service.OrderPricingPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CompanyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id required")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	if !h.hasPermission(ctx, req.CompanyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	res, err := h.pricingService.PreviewOrderPricing(ctx, &req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingPreviewResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/order-tax
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateOrderTax(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := parseQueryUUID(r, "order_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	tax, err := h.pricingService.CalculateOrderTax(ctx, companyID, orderID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"tax_total": tax.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/order-discounts
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateOrderDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := parseQueryUUID(r, "order_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	res, err := h.pricingService.CalculateOrderDiscounts(ctx, companyID, orderID, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    convertDiscountCalculationResult(res),
	})
}

// ---------------------------------------------------------------------
// POST /pricing/quote
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateQuotePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateOrderPricingRequest // same structure
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// reuse same validation and conversion as CalculateOrderPricing
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	if len(req.Lines) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one line required")
		return
	}
	lines := make([]service.PricingLineInput, len(req.Lines))
	for i, l := range req.Lines {
		prodID, err := uuid.Parse(l.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in line")
			return
		}
		qty, err := decimal.NewFromString(l.Quantity)
		if err != nil || qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity in line")
			return
		}
		var unitPrice *decimal.Decimal
		if l.UnitPrice != nil && *l.UnitPrice != "" {
			up, err := decimal.NewFromString(*l.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid unit_price in line")
				return
			}
			unitPrice = &up
		}
		lines[i] = service.PricingLineInput{
			ProductID: prodID,
			Quantity:  qty,
			UnitPrice: unitPrice,
		}
	}
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	svcReq := service.CalculateQuotePricingRequest{
		CompanyID:    companyID,
		CustomerID:   customerID,
		Lines:        lines,
		CouponCodes:  req.CouponCodes,
		CalculateTax: req.CalculateTax,
		At:           at,
	}
	res, err := h.pricingService.CalculateQuotePricing(ctx, &svcReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingCalculationResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/preview-quote
// ---------------------------------------------------------------------
func (h *PricingHandler) PreviewQuotePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req service.QuotePricingPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CompanyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id required")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	if !h.hasPermission(ctx, req.CompanyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	res, err := h.pricingService.PreviewQuotePricing(ctx, &req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingPreviewResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/quote-tax
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateQuoteTax(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	quoteID, err := parseQueryUUID(r, "quote_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	tax, err := h.pricingService.CalculateQuoteTax(ctx, companyID, quoteID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"tax_total": tax.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/quote-discounts
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateQuoteDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	quoteID, err := parseQueryUUID(r, "quote_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	res, err := h.pricingService.CalculateQuoteDiscounts(ctx, companyID, quoteID, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    convertDiscountCalculationResult(res),
	})
}

// ---------------------------------------------------------------------
// POST /pricing/invoice
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateInvoicePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateOrderPricingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	if len(req.Lines) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one line required")
		return
	}
	lines := make([]service.PricingLineInput, len(req.Lines))
	for i, l := range req.Lines {
		prodID, err := uuid.Parse(l.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in line")
			return
		}
		qty, err := decimal.NewFromString(l.Quantity)
		if err != nil || qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity in line")
			return
		}
		var unitPrice *decimal.Decimal
		if l.UnitPrice != nil && *l.UnitPrice != "" {
			up, err := decimal.NewFromString(*l.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid unit_price in line")
				return
			}
			unitPrice = &up
		}
		lines[i] = service.PricingLineInput{
			ProductID: prodID,
			Quantity:  qty,
			UnitPrice: unitPrice,
		}
	}
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	svcReq := service.CalculateInvoicePricingRequest{
		CompanyID:    companyID,
		CustomerID:   customerID,
		Lines:        lines,
		CouponCodes:  req.CouponCodes,
		CalculateTax: req.CalculateTax,
		At:           at,
	}
	res, err := h.pricingService.CalculateInvoicePricing(ctx, &svcReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingCalculationResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/preview-invoice
// ---------------------------------------------------------------------
func (h *PricingHandler) PreviewInvoicePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req service.InvoicePricingPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CompanyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id required")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	if !h.hasPermission(ctx, req.CompanyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	res, err := h.pricingService.PreviewInvoicePricing(ctx, &req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertPricingPreviewResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/invoice-tax
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateInvoiceTax(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	invoiceID, err := parseQueryUUID(r, "invoice_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	tax, err := h.pricingService.CalculateInvoiceTax(ctx, companyID, invoiceID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"tax_total": tax.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/invoice-discounts
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateInvoiceDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	invoiceID, err := parseQueryUUID(r, "invoice_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	res, err := h.pricingService.CalculateInvoiceDiscounts(ctx, companyID, invoiceID, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    convertDiscountCalculationResult(res),
	})
}

// ---------------------------------------------------------------------
// POST /pricing/line-tax
// ---------------------------------------------------------------------
func (h *PricingHandler) CalculateLineTax(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateLineTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	productID, err := uuid.Parse(req.ProductID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
		return
	}
	lineAmount, err := decimal.NewFromString(req.LineAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid line_amount")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	tax, err := h.pricingService.CalculateLineTax(ctx, companyID, productID, lineAmount)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    map[string]string{"tax_amount": tax.String()},
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/tax-amount
// ---------------------------------------------------------------------
type calculateTaxAmountRequest struct {
	CompanyID     string `json:"company_id"`
	EntityType    string `json:"entity_type"`
	EntityID      string `json:"entity_id"`
	TaxableAmount string `json:"taxable_amount"`
}

func (h *PricingHandler) CalculateTaxAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateTaxAmountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	taxableAmount, err := decimal.NewFromString(req.TaxableAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid taxable_amount")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	tax, err := h.pricingService.CalculateTaxAmount(ctx, companyID, req.EntityType, entityID, taxableAmount)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    map[string]string{"tax_amount": tax.String()},
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/applicable-coupons
// ---------------------------------------------------------------------
func (h *PricingHandler) GetApplicableCoupons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	productIDsStr := r.URL.Query().Get("product_ids")
	var productIDs []uuid.UUID
	if productIDsStr != "" {
		parts := strings.Split(productIDsStr, ",")
		for _, p := range parts {
			id, err := uuid.Parse(strings.TrimSpace(p))
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
				return
			}
			productIDs = append(productIDs, id)
		}
	}
	orderAmount, err := parseQueryDecimal(r, "order_amount")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if orderAmount == nil {
		h.respondWithError(w, http.StatusBadRequest, "order_amount required")
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	coupons, err := h.pricingService.GetApplicableCoupons(ctx, companyID, customerID, productIDs, *orderAmount, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]couponSummary, len(coupons))
	for i, c := range coupons {
		resp[i] = couponSummary{
			CouponID: c.CouponID.String(),
			Code:     c.Code,
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// GET /pricing/best-coupon
// ---------------------------------------------------------------------
func (h *PricingHandler) GetBestCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	productIDsStr := r.URL.Query().Get("product_ids")
	var productIDs []uuid.UUID
	if productIDsStr != "" {
		parts := strings.Split(productIDsStr, ",")
		for _, p := range parts {
			id, err := uuid.Parse(strings.TrimSpace(p))
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
				return
			}
			productIDs = append(productIDs, id)
		}
	}
	orderAmount, err := parseQueryDecimal(r, "order_amount")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if orderAmount == nil {
		h.respondWithError(w, http.StatusBadRequest, "order_amount required")
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	coupon, discount, err := h.pricingService.GetBestCoupon(ctx, companyID, customerID, productIDs, *orderAmount, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	var resp interface{}
	if coupon == nil {
		resp = map[string]interface{}{
			"coupon":   nil,
			"discount": "0",
		}
	} else {
		resp = map[string]interface{}{
			"coupon": couponSummary{
				CouponID: coupon.CouponID.String(),
				Code:     coupon.Code,
			},
			"discount": discount.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// GET /pricing/applicable-promotions
// ---------------------------------------------------------------------
func (h *PricingHandler) GetApplicablePromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	productIDsStr := r.URL.Query().Get("product_ids")
	var productIDs []uuid.UUID
	if productIDsStr != "" {
		parts := strings.Split(productIDsStr, ",")
		for _, p := range parts {
			id, err := uuid.Parse(strings.TrimSpace(p))
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
				return
			}
			productIDs = append(productIDs, id)
		}
	}
	orderAmount, err := parseQueryDecimal(r, "order_amount")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if orderAmount == nil {
		h.respondWithError(w, http.StatusBadRequest, "order_amount required")
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	promos, err := h.pricingService.GetApplicablePromotions(ctx, companyID, customerID, productIDs, *orderAmount, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]promotionSummary, len(promos))
	for i, p := range promos {
		resp[i] = promotionSummary{
			PromotionID: p.PromotionID.String(),
			Name:        p.Name,
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// GET /pricing/best-promotion
// ---------------------------------------------------------------------
func (h *PricingHandler) GetBestPromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	productIDsStr := r.URL.Query().Get("product_ids")
	var productIDs []uuid.UUID
	if productIDsStr != "" {
		parts := strings.Split(productIDsStr, ",")
		for _, p := range parts {
			id, err := uuid.Parse(strings.TrimSpace(p))
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
				return
			}
			productIDs = append(productIDs, id)
		}
	}
	orderAmount, err := parseQueryDecimal(r, "order_amount")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if orderAmount == nil {
		h.respondWithError(w, http.StatusBadRequest, "order_amount required")
		return
	}
	at, err := parseQueryTime(r, "at")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	checkAt := time.Now()
	if at != nil {
		checkAt = *at
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	promo, discount, err := h.pricingService.GetBestPromotion(ctx, companyID, customerID, productIDs, *orderAmount, checkAt)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	var resp interface{}
	if promo == nil {
		resp = map[string]interface{}{
			"promotion": nil,
			"discount":  "0",
		}
	} else {
		resp = map[string]interface{}{
			"promotion": promotionSummary{
				PromotionID: promo.PromotionID.String(),
				Name:        promo.Name,
			},
			"discount": discount.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------------------------------------------------------------------
// POST /pricing/combined-discount
// ---------------------------------------------------------------------
type calculateCombinedDiscountRequest struct {
	CompanyID   string     `json:"company_id"`
	CustomerID  *string    `json:"customer_id,omitempty"`
	ProductIDs  []string   `json:"product_ids"`
	OrderAmount string     `json:"order_amount"`
	At          *time.Time `json:"at,omitempty"`
}

func (h *PricingHandler) CalculateCombinedDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req calculateCombinedDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, pid := range req.ProductIDs {
		id, err := uuid.Parse(pid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = id
	}
	orderAmount, err := decimal.NewFromString(req.OrderAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}
	at := time.Now()
	if req.At != nil {
		at = *req.At
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	res, err := h.pricingService.CalculateCombinedDiscount(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"data":    convertDiscountCalculationResult(res),
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/validate-discount-combination
// ---------------------------------------------------------------------
type validateDiscountCombinationRequest struct {
	CouponIDs    []string `json:"coupon_ids"`
	PromotionIDs []string `json:"promotion_ids"`
}

func (h *PricingHandler) ValidateDiscountCombination(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req validateDiscountCombinationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	couponIDs := make([]uuid.UUID, len(req.CouponIDs))
	for i, id := range req.CouponIDs {
		parsed, err := uuid.Parse(id)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
			return
		}
		couponIDs[i] = parsed
	}
	promotionIDs := make([]uuid.UUID, len(req.PromotionIDs))
	for i, id := range req.PromotionIDs {
		parsed, err := uuid.Parse(id)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
			return
		}
		promotionIDs[i] = parsed
	}
	// Permission: we need a companyID – we can't deduce from request; require it as query param
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	err = h.pricingService.ValidateDiscountCombination(ctx, couponIDs, promotionIDs)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"message": "combination valid",
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/customer-credit-limit
// ---------------------------------------------------------------------
func (h *PricingHandler) GetCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := parseQueryUUID(r, "customer_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit, err := h.pricingService.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_limit": limit.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/customer-outstanding-balance
// ---------------------------------------------------------------------
func (h *PricingHandler) GetCustomerOutstandingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := parseQueryUUID(r, "customer_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	balance, err := h.pricingService.GetCustomerOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"outstanding_balance": balance.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/can-purchase
// ---------------------------------------------------------------------
func (h *PricingHandler) CanCustomerPurchaseAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	customerID, err := parseQueryUUID(r, "customer_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	amountStr := r.URL.Query().Get("amount")
	if amountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "amount query parameter required")
		return
	}
	amount, err := decimal.NewFromString(amountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	can, err := h.pricingService.CanCustomerPurchaseAmount(ctx, companyID, customerID, amount)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"can_purchase": can},
	})
}

// ---------------------------------------------------------------------
// POST /pricing/validate
// ---------------------------------------------------------------------
type validatePricingRequest struct {
	CompanyID    string             `json:"company_id"`
	CustomerID   *string            `json:"customer_id,omitempty"`
	Lines        []pricingLineInput `json:"lines"`
	CouponIDs    []string           `json:"coupon_ids"`
	PromotionIDs []string           `json:"promotion_ids"`
}

func (h *PricingHandler) ValidatePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req validatePricingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	lines := make([]service.PricingLineInput, len(req.Lines))
	for i, l := range req.Lines {
		prodID, err := uuid.Parse(l.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in line")
			return
		}
		qty, err := decimal.NewFromString(l.Quantity)
		if err != nil || qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity in line")
			return
		}
		var unitPrice *decimal.Decimal
		if l.UnitPrice != nil && *l.UnitPrice != "" {
			up, err := decimal.NewFromString(*l.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid unit_price in line")
				return
			}
			unitPrice = &up
		}
		lines[i] = service.PricingLineInput{
			ProductID: prodID,
			Quantity:  qty,
			UnitPrice: unitPrice,
		}
	}
	couponIDs := make([]uuid.UUID, len(req.CouponIDs))
	for i, id := range req.CouponIDs {
		parsed, err := uuid.Parse(id)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
			return
		}
		couponIDs[i] = parsed
	}
	promotionIDs := make([]uuid.UUID, len(req.PromotionIDs))
	for i, id := range req.PromotionIDs {
		parsed, err := uuid.Parse(id)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
			return
		}
		promotionIDs[i] = parsed
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	svcReq := service.PricingValidationRequest{
		CompanyID:    companyID,
		CustomerID:   customerID,
		Lines:        lines,
		CouponIDs:    couponIDs,
		PromotionIDs: promotionIDs,
	}
	err = h.pricingService.ValidatePricing(ctx, &svcReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"message": "pricing valid",
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/validate-order
// ---------------------------------------------------------------------
func (h *PricingHandler) ValidateOrderPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		CompanyID string `json:"company_id"`
		OrderID   string `json:"order_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(body.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	orderID, err := uuid.Parse(body.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	err = h.pricingService.ValidateOrderPricing(ctx, companyID, orderID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"message": "order pricing valid",
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/validate-quote
// ---------------------------------------------------------------------
func (h *PricingHandler) ValidateQuotePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		CompanyID string `json:"company_id"`
		QuoteID   string `json:"quote_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(body.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	quoteID, err := uuid.Parse(body.QuoteID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	err = h.pricingService.ValidateQuotePricing(ctx, companyID, quoteID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"message": "quote pricing valid",
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// POST /pricing/validate-invoice
// ---------------------------------------------------------------------
func (h *PricingHandler) ValidateInvoicePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		CompanyID string `json:"company_id"`
		InvoiceID string `json:"invoice_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(body.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	invoiceID, err := uuid.Parse(body.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey != "" {
		if cached, ok := h.idempotencyCache[idempotencyKey]; ok {
			h.respondWithJSON(w, http.StatusOK, cached)
			return
		}
	}
	err = h.pricingService.ValidateInvoicePricing(ctx, companyID, invoiceID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	responseData := map[string]interface{}{
		"success": true,
		"message": "invoice pricing valid",
	}
	if idempotencyKey != "" {
		h.idempotencyCache[idempotencyKey] = responseData
	}
	h.respondWithJSON(w, http.StatusOK, responseData)
}

// ---------------------------------------------------------------------
// GET /pricing/average-discount-rate
// ---------------------------------------------------------------------
func (h *PricingHandler) GetAverageDiscountRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, err := parseQueryTime(r, "from")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseQueryTime(r, "to")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	rate, err := h.pricingService.GetAverageDiscountRate(ctx, companyID, from, to)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"average_discount_rate": rate.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/total-discount-amount
// ---------------------------------------------------------------------
func (h *PricingHandler) GetTotalDiscountAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, err := parseQueryTime(r, "from")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseQueryTime(r, "to")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	amount, err := h.pricingService.GetTotalDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_discount_amount": amount.String()},
	})
}

// ---------------------------------------------------------------------
// GET /pricing/effective-revenue
// ---------------------------------------------------------------------
func (h *PricingHandler) GetEffectiveRevenueAfterDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseQueryUUID(r, "company_id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, err := parseQueryTime(r, "from")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseQueryTime(r, "to")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "pricing:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	revenue, err := h.pricingService.GetEffectiveRevenueAfterDiscounts(ctx, companyID, from, to)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"effective_revenue": revenue.String()},
	})
}

// ---------------------------------------------------------------------
// Helper converters
// ---------------------------------------------------------------------
func convertPricingCalculationResult(res *service.PricingCalculationResult) *pricingCalculationResultResponse {
	lines := make([]pricingLineResultResponse, len(res.LineResults))
	for i, l := range res.LineResults {
		lines[i] = pricingLineResultResponse{
			ProductID:       l.ProductID.String(),
			Quantity:        l.Quantity.String(),
			BasePrice:       l.BasePrice.String(),
			DiscountAmount:  l.DiscountAmount.String(),
			TaxAmount:       l.TaxAmount.String(),
			FinalLineAmount: l.FinalLineAmount.String(),
		}
	}
	coupons := make([]couponSummary, len(res.AppliedCoupons))
	for i, c := range res.AppliedCoupons {
		coupons[i] = couponSummary{
			CouponID: c.CouponID.String(),
			Code:     c.Code,
		}
	}
	promos := make([]promotionSummary, len(res.AppliedPromotions))
	for i, p := range res.AppliedPromotions {
		promos[i] = promotionSummary{
			PromotionID: p.PromotionID.String(),
			Name:        p.Name,
		}
	}
	return &pricingCalculationResultResponse{
		Subtotal:          res.Subtotal.String(),
		DiscountTotal:     res.DiscountTotal.String(),
		TaxTotal:          res.TaxTotal.String(),
		GrandTotal:        res.GrandTotal.String(),
		LineResults:       lines,
		AppliedCoupons:    coupons,
		AppliedPromotions: promos,
	}
}

func convertPricingPreviewResult(res *service.PricingPreviewResult) *pricingPreviewResultResponse {
	coupons := make([]couponSummary, len(res.AppliedCoupons))
	for i, c := range res.AppliedCoupons {
		coupons[i] = couponSummary{
			CouponID: c.CouponID.String(),
			Code:     c.Code,
		}
	}
	promos := make([]promotionSummary, len(res.AppliedPromotions))
	for i, p := range res.AppliedPromotions {
		promos[i] = promotionSummary{
			PromotionID: p.PromotionID.String(),
			Name:        p.Name,
		}
	}
	return &pricingPreviewResultResponse{
		Subtotal:          res.Subtotal.String(),
		DiscountTotal:     res.DiscountTotal.String(),
		TaxTotal:          res.TaxTotal.String(),
		GrandTotal:        res.GrandTotal.String(),
		AppliedCoupons:    coupons,
		AppliedPromotions: promos,
	}
}

type pricingPreviewResultResponse struct {
	Subtotal          string             `json:"subtotal"`
	DiscountTotal     string             `json:"discount_total"`
	TaxTotal          string             `json:"tax_total"`
	GrandTotal        string             `json:"grand_total"`
	AppliedCoupons    []couponSummary    `json:"applied_coupons"`
	AppliedPromotions []promotionSummary `json:"applied_promotions"`
}

func convertDiscountCalculationResult(res *service.DiscountCalculationResult) *discountCalculationResultResponse {
	coupons := make([]couponSummary, len(res.AppliedCoupons))
	for i, c := range res.AppliedCoupons {
		coupons[i] = couponSummary{
			CouponID: c.CouponID.String(),
			Code:     c.Code,
		}
	}
	promos := make([]promotionSummary, len(res.AppliedPromotions))
	for i, p := range res.AppliedPromotions {
		promos[i] = promotionSummary{
			PromotionID: p.PromotionID.String(),
			Name:        p.Name,
		}
	}
	// AppliedAutomatic omitted for brevity
	return &discountCalculationResultResponse{
		DiscountTotal:     res.DiscountTotal.String(),
		AppliedCoupons:    coupons,
		AppliedPromotions: promos,
	}
}

type discountCalculationResultResponse struct {
	DiscountTotal     string             `json:"discount_total"`
	AppliedCoupons    []couponSummary    `json:"applied_coupons"`
	AppliedPromotions []promotionSummary `json:"applied_promotions"`
}
