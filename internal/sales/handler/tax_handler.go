// file: internal/sales/handler/tax_handler.go
package handler

import (
	"auth-service/internal/sales/models"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/service"
)

type TaxHandler struct {
	taxService service.TaxIntegrationService
	*BaseHandler
}

func NewTaxHandler(taxService service.TaxIntegrationService, logger *zap.Logger) *TaxHandler {
	return &TaxHandler{
		taxService:  taxService,
		BaseHandler: &BaseHandler{logger: logger.Named("tax_handler")},
	}
}

// ---------------------------------------------------------------------
// Request/Response types (company_id removed from request bodies)
// ---------------------------------------------------------------------

type calculateOrderTaxRequest struct {
	OrderID        string                   `json:"order_id"`
	LineItems      []*service.LineItemInput `json:"line_items,omitempty"`
	CustomerID     *string                  `json:"customer_id,omitempty"`
	BillingAddress *service.AddressInput    `json:"billing_address,omitempty"`
}

type calculateQuoteTaxRequest struct {
	QuoteID        string                   `json:"quote_id"`
	LineItems      []*service.LineItemInput `json:"line_items,omitempty"`
	CustomerID     *string                  `json:"customer_id,omitempty"`
	BillingAddress *service.AddressInput    `json:"billing_address,omitempty"`
}

type calculateInvoiceTaxRequest struct {
	InvoiceID      string                   `json:"invoice_id"`
	LineItems      []*service.LineItemInput `json:"line_items,omitempty"`
	CustomerID     *string                  `json:"customer_id,omitempty"`
	BillingAddress *service.AddressInput    `json:"billing_address,omitempty"`
}

type calculateReturnTaxRequest struct {
	ReturnID       string                   `json:"return_id"`
	LineItems      []*service.LineItemInput `json:"line_items,omitempty"`
	CustomerID     *string                  `json:"customer_id,omitempty"`
	BillingAddress *service.AddressInput    `json:"billing_address,omitempty"`
}

type calculateLineTaxRequest struct {
	ProductID      string  `json:"product_id"`
	LineAmount     string  `json:"line_amount"`
	TaxableAmount  string  `json:"taxable_amount"`
	CustomerID     *string `json:"customer_id,omitempty"`
	BillingCountry string  `json:"billing_country"`
	BillingState   *string `json:"billing_state,omitempty"`
}

type taxPreviewRequest struct {
	LineItems      []*service.LineItemInput `json:"line_items"`
	CustomerID     *string                  `json:"customer_id,omitempty"`
	BillingAddress *service.AddressInput    `json:"billing_address,omitempty"`
}

type taxCalculationResponse struct {
	TotalTax            string                  `json:"total_tax"`
	LineTaxes           []taxLineDetailResponse `json:"line_taxes"`
	TaxesByJurisdiction map[string]string       `json:"taxes_by_jurisdiction"`
	ApplicableRates     map[string]string       `json:"applicable_rates"`
	ExemptionsApplied   bool                    `json:"exemptions_applied"`
}

type taxLineDetailResponse struct {
	ProductID     string `json:"product_id"`
	LineAmount    string `json:"line_amount"`
	TaxableAmount string `json:"taxable_amount"`
	TaxAmount     string `json:"tax_amount"`
	TaxRateName   string `json:"tax_rate_name"`
}

type taxLineResultResponse struct {
	TaxAmount      string      `json:"tax_amount"`
	ApplicableRate string      `json:"applicable_rate"`
	Details        interface{} `json:"details,omitempty"`
}

type taxBreakdownLineResponse struct {
	TaxName       *string `json:"tax_name,omitempty"`
	TaxPercentage *string `json:"tax_percentage,omitempty"`
	TaxableAmount string  `json:"taxable_amount"`
	TaxAmount     string  `json:"tax_amount"`
}

type createTaxSnapshotRequest struct {
	EntityType    string  `json:"entity_type"`
	EntityID      string  `json:"entity_id"`
	LineID        *string `json:"line_id,omitempty"`
	TaxRateID     *string `json:"tax_rate_id,omitempty"`
	TaxName       *string `json:"tax_name,omitempty"`
	TaxPercentage *string `json:"tax_percentage,omitempty"`
	TaxableAmount string  `json:"taxable_amount"`
	TaxAmount     string  `json:"tax_amount"`
}

type taxSnapshotResponse struct {
	TaxSnapshotID string  `json:"tax_snapshot_id"`
	CompanyID     string  `json:"company_id"`
	EntityType    string  `json:"entity_type"`
	EntityID      string  `json:"entity_id"`
	LineID        *string `json:"line_id,omitempty"`
	TaxRateID     *string `json:"tax_rate_id,omitempty"`
	TaxName       *string `json:"tax_name,omitempty"`
	TaxPercentage *string `json:"tax_percentage,omitempty"`
	TaxableAmount string  `json:"taxable_amount"`
	TaxAmount     string  `json:"tax_amount"`
	CreatedAt     string  `json:"created_at"`
}

// ---------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Endpoint implementations
// ---------------------------------------------------------------------

// POST /tax/calculate-order
func (h *TaxHandler) CalculateOrderTaxes(w http.ResponseWriter, r *http.Request) {
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

	var req calculateOrderTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	orderID, err := uuid.Parse(req.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:calculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CalculateOrderTaxRequest{
		CompanyID:      companyID,
		OrderID:        orderID,
		LineItems:      req.LineItems,
		CustomerID:     customerID,
		BillingAddress: req.BillingAddress,
	}
	result, err := h.taxService.CalculateOrderTaxes(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate order taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxCalculationResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/calculate-quote
func (h *TaxHandler) CalculateQuoteTaxes(w http.ResponseWriter, r *http.Request) {
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

	var req calculateQuoteTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	quoteID, err := uuid.Parse(req.QuoteID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quote_id")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:calculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CalculateQuoteTaxRequest{
		CompanyID:      companyID,
		QuoteID:        quoteID,
		LineItems:      req.LineItems,
		CustomerID:     customerID,
		BillingAddress: req.BillingAddress,
	}
	result, err := h.taxService.CalculateQuoteTaxes(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate quote taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxCalculationResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/calculate-invoice
func (h *TaxHandler) CalculateInvoiceTaxes(w http.ResponseWriter, r *http.Request) {
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

	var req calculateInvoiceTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	invoiceID, err := uuid.Parse(req.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:calculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CalculateInvoiceTaxRequest{
		CompanyID:      companyID,
		InvoiceID:      invoiceID,
		LineItems:      req.LineItems,
		CustomerID:     customerID,
		BillingAddress: req.BillingAddress,
	}
	result, err := h.taxService.CalculateInvoiceTaxes(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate invoice taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxCalculationResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/calculate-return
func (h *TaxHandler) CalculateReturnTaxes(w http.ResponseWriter, r *http.Request) {
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

	var req calculateReturnTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	returnID, err := uuid.Parse(req.ReturnID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return_id")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:calculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CalculateReturnTaxRequest{
		CompanyID:      companyID,
		ReturnID:       returnID,
		LineItems:      req.LineItems,
		CustomerID:     customerID,
		BillingAddress: req.BillingAddress,
	}
	result, err := h.taxService.CalculateReturnTaxes(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate return taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxCalculationResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/calculate-line
func (h *TaxHandler) CalculateLineTax(w http.ResponseWriter, r *http.Request) {
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

	var req calculateLineTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	productID, err := uuid.Parse(req.ProductID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
		return
	}
	lineAmount, err := parseDecimal(req.LineAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid line_amount")
		return
	}
	taxableAmount, err := parseDecimal(req.TaxableAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid taxable_amount")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:calculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CalculateLineTaxRequest{
		CompanyID:      companyID,
		ProductID:      productID,
		LineAmount:     lineAmount,
		TaxableAmount:  taxableAmount,
		CustomerID:     customerID,
		BillingCountry: req.BillingCountry,
		BillingState:   req.BillingState,
	}
	result, err := h.taxService.CalculateLineTax(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate line tax", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := taxLineResultResponse{
		TaxAmount:      result.TaxAmount.String(),
		ApplicableRate: result.ApplicableRate.String(),
		Details:        result.Details,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/preview
func (h *TaxHandler) PreviewTaxes(w http.ResponseWriter, r *http.Request) {
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

	var req taxPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:preview") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.TaxPreviewRequest{
		CompanyID:      companyID,
		LineItems:      req.LineItems,
		CustomerID:     customerID,
		BillingAddress: req.BillingAddress,
	}
	result, err := h.taxService.PreviewTaxes(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to preview taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxPreviewResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/apply-to-order
func (h *TaxHandler) ApplyTaxesToOrder(w http.ResponseWriter, r *http.Request) {
	h.applyTaxesToEntity(w, r, "order")
}

// POST /tax/apply-to-quote
func (h *TaxHandler) ApplyTaxesToQuote(w http.ResponseWriter, r *http.Request) {
	h.applyTaxesToEntity(w, r, "quote")
}

// POST /tax/apply-to-invoice
func (h *TaxHandler) ApplyTaxesToInvoice(w http.ResponseWriter, r *http.Request) {
	h.applyTaxesToEntity(w, r, "invoice")
}

// generic apply handler
func (h *TaxHandler) applyTaxesToEntity(w http.ResponseWriter, r *http.Request, entityType string) {
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

	var body struct {
		EntityID string `json:"entity_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(body.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:apply") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var result *service.TaxCalculationResult
	switch entityType {
	case "order":
		result, err = h.taxService.ApplyTaxesToOrder(ctx, companyID, entityID, userID, idempotencyKey)
	case "quote":
		result, err = h.taxService.ApplyTaxesToQuote(ctx, companyID, entityID, userID, idempotencyKey)
	case "invoice":
		result, err = h.taxService.ApplyTaxesToInvoice(ctx, companyID, entityID, userID, idempotencyKey)
	default:
		h.respondWithError(w, http.StatusBadRequest, "unsupported entity type")
		return
	}
	if err != nil {
		h.logger.Error("failed to apply taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertTaxCalculationResult(result)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/refresh-order
func (h *TaxHandler) RefreshOrderTaxes(w http.ResponseWriter, r *http.Request) {
	h.refreshEntityTaxes(w, r, "order")
}

// POST /tax/refresh-invoice
func (h *TaxHandler) RefreshInvoiceTaxes(w http.ResponseWriter, r *http.Request) {
	h.refreshEntityTaxes(w, r, "invoice")
}

func (h *TaxHandler) refreshEntityTaxes(w http.ResponseWriter, r *http.Request, entityType string) {
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

	var body struct {
		EntityID string `json:"entity_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(body.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:apply") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if entityType == "order" {
		err = h.taxService.RefreshOrderTaxes(ctx, companyID, entityID, userID, idempotencyKey)
	} else {
		err = h.taxService.RefreshInvoiceTaxes(ctx, companyID, entityID, userID, idempotencyKey)
	}
	if err != nil {
		h.logger.Error("failed to refresh taxes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "taxes refreshed",
	})
}

// GET /tax/order-breakdown/{orderId}
func (h *TaxHandler) GetOrderTaxBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := parseUUIDParam(r, "orderId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
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
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	lines, err := h.taxService.GetOrderTaxBreakdown(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get order tax breakdown", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxBreakdownLines(lines)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /tax/invoice-breakdown/{invoiceId}
func (h *TaxHandler) GetInvoiceTaxBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invoiceID, err := parseUUIDParam(r, "invoiceId")
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
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	lines, err := h.taxService.GetInvoiceTaxBreakdown(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get invoice tax breakdown", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxBreakdownLines(lines)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /tax/quote-breakdown/{quoteId}
func (h *TaxHandler) GetQuoteTaxBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	quoteID, err := parseUUIDParam(r, "quoteId")
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
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	lines, err := h.taxService.GetQuoteTaxBreakdown(ctx, companyID, quoteID)
	if err != nil {
		h.logger.Error("failed to get quote tax breakdown", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxBreakdownLines(lines)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/snapshots
func (h *TaxHandler) CreateTaxSnapshot(w http.ResponseWriter, r *http.Request) {
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

	var req createTaxSnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	var lineID *uuid.UUID
	if req.LineID != nil && *req.LineID != "" {
		parsed, err := uuid.Parse(*req.LineID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid line_id")
			return
		}
		lineID = &parsed
	}
	var taxRateID *uuid.UUID
	if req.TaxRateID != nil && *req.TaxRateID != "" {
		parsed, err := uuid.Parse(*req.TaxRateID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate_id")
			return
		}
		taxRateID = &parsed
	}
	var taxPercentage *decimal.Decimal
	if req.TaxPercentage != nil && *req.TaxPercentage != "" {
		dec, err := decimal.NewFromString(*req.TaxPercentage)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tax_percentage")
			return
		}
		taxPercentage = &dec
	}
	taxableAmount, err := parseDecimal(req.TaxableAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid taxable_amount")
		return
	}
	taxAmount, err := parseDecimal(req.TaxAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax_amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CreateTaxSnapshotRequest{
		CompanyID:     companyID,
		EntityType:    req.EntityType,
		EntityID:      entityID,
		LineID:        lineID,
		TaxRateID:     taxRateID,
		TaxName:       req.TaxName,
		TaxPercentage: taxPercentage,
		TaxableAmount: taxableAmount,
		TaxAmount:     taxAmount,
	}
	snapshot, err := h.taxService.CreateTaxSnapshot(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create tax snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxSnapshot(snapshot)
	location := fmt.Sprintf("/tax/snapshots/%s", snapshot.TaxSnapshotID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /tax/snapshots/{id}
func (h *TaxHandler) GetTaxSnapshotByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snapshotID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid snapshot ID")
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
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	snapshot, err := h.taxService.GetTaxSnapshotByID(ctx, companyID, snapshotID)
	if err != nil {
		h.logger.Error("failed to get tax snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxSnapshot(snapshot)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /tax/snapshots/latest
func (h *TaxHandler) GetLatestTaxSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	entityType := r.URL.Query().Get("entity_type")
	entityIDStr := r.URL.Query().Get("entity_id")
	if entityType == "" || entityIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type and entity_id query parameters are required")
		return
	}
	entityID, err := uuid.Parse(entityIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	snapshot, err := h.taxService.GetLatestTaxSnapshot(ctx, companyID, entityType, entityID)
	if err != nil {
		h.logger.Error("failed to get latest tax snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxSnapshot(snapshot)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GET /tax/snapshots
func (h *TaxHandler) GetTaxSnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	entityType := r.URL.Query().Get("entity_type")
	entityIDStr := r.URL.Query().Get("entity_id")
	if entityType == "" || entityIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type and entity_id query parameters are required")
		return
	}
	entityID, err := uuid.Parse(entityIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	snapshots, err := h.taxService.GetTaxSnapshots(ctx, companyID, entityType, entityID)
	if err != nil {
		h.logger.Error("failed to get tax snapshots", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]taxSnapshotResponse, len(snapshots))
	for i, s := range snapshots {
		resp[i] = convertTaxSnapshot(s)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// POST /tax/snapshots/{id}/recalculate
func (h *TaxHandler) RecalculateTaxSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snapshotID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid snapshot ID")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	snapshot, err := h.taxService.RecalculateTaxSnapshot(ctx, companyID, snapshotID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to recalculate tax snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := convertTaxSnapshot(snapshot)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DELETE /tax/snapshots/{id}
func (h *TaxHandler) ArchiveTaxSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snapshotID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid snapshot ID")
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

	if !h.hasPermission(ctx, companyID, userID, "tax:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.taxService.ArchiveTaxSnapshot(ctx, companyID, snapshotID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to archive tax snapshot", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "tax snapshot archived",
	})
}

// GET /tax/snapshots/{id}/exists
func (h *TaxHandler) TaxSnapshotExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snapshotID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid snapshot ID")
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
	if !h.hasPermission(ctx, companyID, userID, "tax:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.taxService.TaxSnapshotExists(ctx, companyID, snapshotID)
	if err != nil {
		h.logger.Error("failed to check if tax snapshot exists", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// ---------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------

func convertTaxCalculationResult(res *service.TaxCalculationResult) taxCalculationResponse {
	resp := taxCalculationResponse{
		TotalTax:            res.TotalTax.String(),
		LineTaxes:           make([]taxLineDetailResponse, len(res.LineTaxes)),
		TaxesByJurisdiction: make(map[string]string),
		ApplicableRates:     make(map[string]string),
		ExemptionsApplied:   res.ExemptionsApplied,
	}
	for i, lt := range res.LineTaxes {
		resp.LineTaxes[i] = taxLineDetailResponse{
			ProductID:     lt.ProductID.String(),
			LineAmount:    lt.LineAmount.String(),
			TaxableAmount: lt.TaxableAmount.String(),
			TaxAmount:     lt.TaxAmount.String(),
			TaxRateName:   lt.TaxRateName,
		}
	}
	for k, v := range res.TaxesByJurisdiction {
		resp.TaxesByJurisdiction[k] = v.String()
	}
	for k, v := range res.ApplicableRates {
		resp.ApplicableRates[k] = v.String()
	}
	return resp
}

func convertTaxPreviewResult(res *service.TaxPreviewResult) taxCalculationResponse {
	return convertTaxCalculationResult(&service.TaxCalculationResult{
		TotalTax:            res.TotalTax,
		LineTaxes:           res.LineTaxes,
		TaxesByJurisdiction: res.TaxesByJurisdiction,
		ApplicableRates:     res.ApplicableRates,
		ExemptionsApplied:   res.ExemptionsApplied,
	})
}

func convertTaxBreakdownLines(lines []*service.TaxBreakdownLine) []taxBreakdownLineResponse {
	resp := make([]taxBreakdownLineResponse, len(lines))
	for i, l := range lines {
		var taxPct *string
		if l.TaxPercentage != nil {
			pct := l.TaxPercentage.String()
			taxPct = &pct
		}
		resp[i] = taxBreakdownLineResponse{
			TaxName:       l.TaxName,
			TaxPercentage: taxPct,
			TaxableAmount: l.TaxableAmount.String(),
			TaxAmount:     l.TaxAmount.String(),
		}
	}
	return resp
}

func convertTaxSnapshot(s *models.TaxSnapshot) taxSnapshotResponse {
	resp := taxSnapshotResponse{
		TaxSnapshotID: s.TaxSnapshotID.String(),
		CompanyID:     s.CompanyID.String(),
		EntityType:    s.EntityType,
		EntityID:      s.EntityID.String(),
		TaxableAmount: s.TaxableAmount.String(),
		TaxAmount:     s.TaxAmount.String(),
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
	}
	if s.LineID != nil {
		id := s.LineID.String()
		resp.LineID = &id
	}
	if s.TaxRateID != nil {
		id := s.TaxRateID.String()
		resp.TaxRateID = &id
	}
	if s.TaxName != nil {
		resp.TaxName = s.TaxName
	}
	if s.TaxPercentage != nil {
		pct := s.TaxPercentage.String()
		resp.TaxPercentage = &pct
	}
	return resp
}
