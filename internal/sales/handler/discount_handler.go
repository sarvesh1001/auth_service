package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/service"
)

// DiscountHandler handles all discount-related HTTP endpoints
type DiscountHandler struct {
	discountService service.DiscountEngineService
	*BaseHandler
}

// NewDiscountHandler creates a new discount handler
func NewDiscountHandler(discountService service.DiscountEngineService, logger *zap.Logger) *DiscountHandler {
	return &DiscountHandler{
		discountService: discountService,
		BaseHandler:     &BaseHandler{logger: logger.Named("discount_handler")},
	}
}

// injectIdempotencyKey reads the Idempotency-Key header and stores it in the request context.
// Used only by mutating endpoints.
func (h *DiscountHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// ---------- Request/Response Types ----------

type evaluateOrderDiscountsRequest struct {
	OrderID string `json:"order_id"`
}

type evaluateQuoteDiscountsRequest struct {
	QuoteID string `json:"quote_id"`
}

type evaluateInvoiceDiscountsRequest struct {
	InvoiceID string `json:"invoice_id"`
}

type bestDiscountCombinationRequest struct {
	CustomerID  *string  `json:"customer_id,omitempty"`
	ProductIDs  []string `json:"product_ids,omitempty"`
	OrderAmount string   `json:"order_amount"`
	At          string   `json:"at"`
}

type validateStackingRulesRequest struct {
	CouponIDs            []string `json:"coupon_ids,omitempty"`
	PromotionIDs         []string `json:"promotion_ids,omitempty"`
	AutomaticDiscountIDs []string `json:"automatic_discount_ids,omitempty"`
}

type calculateCouponDiscountRequest struct {
	CouponID   string   `json:"coupon_id"`
	Subtotal   string   `json:"subtotal"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type calculatePromotionDiscountRequest struct {
	PromotionID string   `json:"promotion_id"`
	Subtotal    string   `json:"subtotal"`
	ProductIDs  []string `json:"product_ids,omitempty"`
}

type calculateAutomaticDiscountRequest struct {
	AutomaticDiscountID string   `json:"automatic_discount_id"`
	Subtotal            string   `json:"subtotal"`
	ProductIDs          []string `json:"product_ids,omitempty"`
}

type combinedDiscountCalculationRequest struct {
	CustomerID  *string  `json:"customer_id,omitempty"`
	ProductIDs  []string `json:"product_ids,omitempty"`
	OrderAmount string   `json:"order_amount"`
	At          string   `json:"at"`
}

type applyCouponRequest struct {
	EntityType string `json:"entity_type"` // order, quote, invoice
	EntityID   string `json:"entity_id"`
	CouponCode string `json:"coupon_code"`
	AppliedBy  string `json:"applied_by"`
}

type removeCouponRequest struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	CouponCode string `json:"coupon_code"`
	RemovedBy  string `json:"removed_by"`
}

type applyPromotionRequest struct {
	EntityType  string `json:"entity_type"`
	EntityID    string `json:"entity_id"`
	PromotionID string `json:"promotion_id"`
	AppliedBy   string `json:"applied_by"`
}

type removePromotionRequest struct {
	EntityType  string `json:"entity_type"`
	EntityID    string `json:"entity_id"`
	PromotionID string `json:"promotion_id"`
	RemovedBy   string `json:"removed_by"`
}

type applyBestDiscountsRequest struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	AppliedBy  string `json:"applied_by"`
}

type clearDiscountsRequest struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	ClearedBy  string `json:"cleared_by"`
}

type trackCouponUsageRequest struct {
	CouponID   string  `json:"coupon_id"`
	CustomerID *string `json:"customer_id,omitempty"`
	EntityType string  `json:"entity_type"`
	EntityID   string  `json:"entity_id"`
	UsedAt     string  `json:"used_at"`
}

type trackPromotionUsageRequest struct {
	PromotionID string  `json:"promotion_id"`
	CustomerID  *string `json:"customer_id,omitempty"`
	EntityType  string  `json:"entity_type"`
	EntityID    string  `json:"entity_id"`
	UsedAt      string  `json:"used_at"`
}

// ---------- Read‑only endpoints (no idempotency required) ----------

// EvaluateOrderDiscounts handles POST /discounts/evaluate-order
func (h *DiscountHandler) EvaluateOrderDiscounts(w http.ResponseWriter, r *http.Request) {
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

	var req evaluateOrderDiscountsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrderID == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_id is required")
		return
	}
	orderID, err := uuid.Parse(req.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.EvaluateOrderDiscountsRequest{
		CompanyID: companyID,
		OrderID:   orderID,
	}
	result, err := h.discountService.EvaluateOrderDiscounts(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to evaluate order discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// EvaluateQuoteDiscounts handles POST /discounts/evaluate-quote
func (h *DiscountHandler) EvaluateQuoteDiscounts(w http.ResponseWriter, r *http.Request) {
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

	var req evaluateQuoteDiscountsRequest
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.EvaluateQuoteDiscountsRequest{
		CompanyID: companyID,
		QuoteID:   quoteID,
	}
	result, err := h.discountService.EvaluateQuoteDiscounts(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to evaluate quote discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// EvaluateInvoiceDiscounts handles POST /discounts/evaluate-invoice
func (h *DiscountHandler) EvaluateInvoiceDiscounts(w http.ResponseWriter, r *http.Request) {
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

	var req evaluateInvoiceDiscountsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.InvoiceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "invoice_id is required")
		return
	}
	invoiceID, err := uuid.Parse(req.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.EvaluateInvoiceDiscountsRequest{
		CompanyID: companyID,
		InvoiceID: invoiceID,
	}
	result, err := h.discountService.EvaluateInvoiceDiscounts(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to evaluate invoice discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// GetApplicableCoupons handles GET /discounts/applicable-coupons
func (h *DiscountHandler) GetApplicableCoupons(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err == nil {
			customerID = &parsed
		}
	}

	productIDs := []uuid.UUID{}
	for _, p := range r.URL.Query()["product_ids"] {
		parsed, err := uuid.Parse(p)
		if err == nil {
			productIDs = append(productIDs, parsed)
		}
	}

	orderAmountStr := r.URL.Query().Get("order_amount")
	if orderAmountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount query parameter is required")
		return
	}
	orderAmount, err := decimal.NewFromString(orderAmountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		atStr = time.Now().UTC().Format(time.RFC3339)
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	coupons, err := h.discountService.GetApplicableCoupons(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.logger.Error("failed to get applicable coupons", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    coupons,
	})
}

// GetApplicablePromotions handles GET /discounts/applicable-promotions
func (h *DiscountHandler) GetApplicablePromotions(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err == nil {
			customerID = &parsed
		}
	}

	productIDs := []uuid.UUID{}
	for _, p := range r.URL.Query()["product_ids"] {
		parsed, err := uuid.Parse(p)
		if err == nil {
			productIDs = append(productIDs, parsed)
		}
	}

	orderAmountStr := r.URL.Query().Get("order_amount")
	if orderAmountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount query parameter is required")
		return
	}
	orderAmount, err := decimal.NewFromString(orderAmountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		atStr = time.Now().UTC().Format(time.RFC3339)
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	promotions, err := h.discountService.GetApplicablePromotions(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.logger.Error("failed to get applicable promotions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    promotions,
	})
}

// GetApplicableAutomaticDiscounts handles GET /discounts/applicable-automatic
func (h *DiscountHandler) GetApplicableAutomaticDiscounts(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err == nil {
			customerID = &parsed
		}
	}

	productIDs := []uuid.UUID{}
	for _, p := range r.URL.Query()["product_ids"] {
		parsed, err := uuid.Parse(p)
		if err == nil {
			productIDs = append(productIDs, parsed)
		}
	}

	orderAmountStr := r.URL.Query().Get("order_amount")
	if orderAmountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount query parameter is required")
		return
	}
	orderAmount, err := decimal.NewFromString(orderAmountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		atStr = time.Now().UTC().Format(time.RFC3339)
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	discounts, err := h.discountService.GetApplicableAutomaticDiscounts(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.logger.Error("failed to get applicable automatic discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    discounts,
	})
}

// GetBestCoupon handles GET /discounts/best-coupon
func (h *DiscountHandler) GetBestCoupon(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err == nil {
			customerID = &parsed
		}
	}

	productIDs := []uuid.UUID{}
	for _, p := range r.URL.Query()["product_ids"] {
		parsed, err := uuid.Parse(p)
		if err == nil {
			productIDs = append(productIDs, parsed)
		}
	}

	orderAmountStr := r.URL.Query().Get("order_amount")
	if orderAmountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount query parameter is required")
		return
	}
	orderAmount, err := decimal.NewFromString(orderAmountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		atStr = time.Now().UTC().Format(time.RFC3339)
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	coupon, discount, err := h.discountService.GetBestCoupon(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.logger.Error("failed to get best coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"data":            coupon,
		"discount_amount": discount.String(),
	})
}

// GetBestPromotion handles GET /discounts/best-promotion
func (h *DiscountHandler) GetBestPromotion(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var customerID *uuid.UUID
	if cid := r.URL.Query().Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err == nil {
			customerID = &parsed
		}
	}

	productIDs := []uuid.UUID{}
	for _, p := range r.URL.Query()["product_ids"] {
		parsed, err := uuid.Parse(p)
		if err == nil {
			productIDs = append(productIDs, parsed)
		}
	}

	orderAmountStr := r.URL.Query().Get("order_amount")
	if orderAmountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount query parameter is required")
		return
	}
	orderAmount, err := decimal.NewFromString(orderAmountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	atStr := r.URL.Query().Get("at")
	if atStr == "" {
		atStr = time.Now().UTC().Format(time.RFC3339)
	}
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	promotion, discount, err := h.discountService.GetBestPromotion(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.logger.Error("failed to get best promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"data":            promotion,
		"discount_amount": discount.String(),
	})
}

// GetBestDiscountCombination handles POST /discounts/best-combination
func (h *DiscountHandler) GetBestDiscountCombination(w http.ResponseWriter, r *http.Request) {
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

	var req bestDiscountCombinationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrderAmount == "" || req.At == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount and at are required")
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
	for i, idStr := range req.ProductIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = parsed
	}
	orderAmount, err := decimal.NewFromString(req.OrderAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}
	at, err := time.Parse(time.RFC3339, req.At)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.BestDiscountCombinationRequest{
		CompanyID:         companyID,
		CustomerID:        customerID,
		ProductIDs:        productIDs,
		OrderAmount:       orderAmount,
		At:                at,
		IncludeCoupons:    true, // <-- add this
		IncludePromotions: true, // <-- add this
		IncludeAutomatic:  true, // <-- add this
		MaxCombinations:   5,    // <-- add this (or any reasonable limit)
	}
	result, err := h.discountService.GetBestDiscountCombination(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to get best discount combination", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// ValidateStackingRules handles POST /discounts/validate-stacking
func (h *DiscountHandler) ValidateStackingRules(w http.ResponseWriter, r *http.Request) {
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

	var req validateStackingRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	couponIDs := make([]uuid.UUID, len(req.CouponIDs))
	for i, idStr := range req.CouponIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
			return
		}
		couponIDs[i] = parsed
	}
	promotionIDs := make([]uuid.UUID, len(req.PromotionIDs))
	for i, idStr := range req.PromotionIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
			return
		}
		promotionIDs[i] = parsed
	}
	autoIDs := make([]uuid.UUID, len(req.AutomaticDiscountIDs))
	for i, idStr := range req.AutomaticDiscountIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid automatic_discount_id")
			return
		}
		autoIDs[i] = parsed
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.discountService.ValidateStackingRules(ctx, couponIDs, promotionIDs, autoIDs)
	if err != nil {
		h.logger.Error("failed to validate stacking rules", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "stacking rules valid",
	})
}

// CanStackDiscounts handles GET /discounts/can-stack
func (h *DiscountHandler) CanStackDiscounts(w http.ResponseWriter, r *http.Request) {
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

	firstIDStr := r.URL.Query().Get("first_discount_id")
	secondIDStr := r.URL.Query().Get("second_discount_id")
	if firstIDStr == "" || secondIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "first_discount_id and second_discount_id are required")
		return
	}
	firstID, err := uuid.Parse(firstIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid first_discount_id")
		return
	}
	secondID, err := uuid.Parse(secondIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid second_discount_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	canStack, err := h.discountService.CanStackDiscounts(ctx, firstID, secondID)
	if err != nil {
		h.logger.Error("failed to check discount stacking", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"can_stack": canStack,
	})
}

// CalculateCouponDiscount handles POST /discounts/calculate-coupon
func (h *DiscountHandler) CalculateCouponDiscount(w http.ResponseWriter, r *http.Request) {
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

	var req calculateCouponDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CouponID == "" || req.Subtotal == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id and subtotal are required")
		return
	}
	couponID, err := uuid.Parse(req.CouponID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
		return
	}
	subtotal, err := decimal.NewFromString(req.Subtotal)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subtotal")
		return
	}
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, idStr := range req.ProductIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = parsed
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discount, err := h.discountService.CalculateCouponDiscount(ctx, companyID, couponID, subtotal, productIDs)
	if err != nil {
		h.logger.Error("failed to calculate coupon discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"discount_amount": discount.String(),
	})
}

// CalculatePromotionDiscount handles POST /discounts/calculate-promotion
func (h *DiscountHandler) CalculatePromotionDiscount(w http.ResponseWriter, r *http.Request) {
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

	var req calculatePromotionDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PromotionID == "" || req.Subtotal == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id and subtotal are required")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	subtotal, err := decimal.NewFromString(req.Subtotal)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subtotal")
		return
	}
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, idStr := range req.ProductIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = parsed
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discount, err := h.discountService.CalculatePromotionDiscount(ctx, companyID, promotionID, subtotal, productIDs)
	if err != nil {
		h.logger.Error("failed to calculate promotion discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"discount_amount": discount.String(),
	})
}

// CalculateAutomaticDiscount handles POST /discounts/calculate-automatic
func (h *DiscountHandler) CalculateAutomaticDiscount(w http.ResponseWriter, r *http.Request) {
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

	var req calculateAutomaticDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AutomaticDiscountID == "" || req.Subtotal == "" {
		h.respondWithError(w, http.StatusBadRequest, "automatic_discount_id and subtotal are required")
		return
	}
	autoID, err := uuid.Parse(req.AutomaticDiscountID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid automatic_discount_id")
		return
	}
	subtotal, err := decimal.NewFromString(req.Subtotal)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subtotal")
		return
	}
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, idStr := range req.ProductIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = parsed
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discount, err := h.discountService.CalculateAutomaticDiscount(ctx, companyID, autoID, subtotal, productIDs)
	if err != nil {
		h.logger.Error("failed to calculate automatic discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"discount_amount": discount.String(),
	})
}

// CalculateCombinedDiscount handles POST /discounts/calculate-combined
func (h *DiscountHandler) CalculateCombinedDiscount(w http.ResponseWriter, r *http.Request) {
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

	var req combinedDiscountCalculationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrderAmount == "" || req.At == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_amount and at are required")
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
	for i, idStr := range req.ProductIDs {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = parsed
	}
	orderAmount, err := decimal.NewFromString(req.OrderAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}
	at, err := time.Parse(time.RFC3339, req.At)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CombinedDiscountCalculationRequest{
		CompanyID:   companyID,
		CustomerID:  customerID,
		ProductIDs:  productIDs,
		OrderAmount: orderAmount,
		At:          at,
	}
	result, err := h.discountService.CalculateCombinedDiscount(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to calculate combined discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// ---------- Mutating endpoints (require Idempotency-Key header) ----------

// ApplyCoupon handles POST /discounts/apply-coupon
func (h *DiscountHandler) ApplyCoupon(w http.ResponseWriter, r *http.Request) {
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

	var req applyCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" || req.CouponCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type, entity_id, and coupon_code are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	appliedBy, err := uuid.Parse(req.AppliedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid applied_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	coupon, discount, err := h.discountService.ApplyCoupon(ctx, companyID, req.EntityType, entityID, req.CouponCode, appliedBy)
	if err != nil {
		h.logger.Error("failed to apply coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"coupon":          coupon,
		"discount_amount": discount.String(),
	})
}

// RemoveCoupon handles DELETE /discounts/remove-coupon
func (h *DiscountHandler) RemoveCoupon(w http.ResponseWriter, r *http.Request) {
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

	var req removeCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" || req.CouponCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type, entity_id, and coupon_code are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	removedBy, err := uuid.Parse(req.RemovedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid removed_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.discountService.RemoveCoupon(ctx, companyID, req.EntityType, entityID, req.CouponCode, removedBy)
	if err != nil {
		h.logger.Error("failed to remove coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon removed",
	})
}

// ApplyPromotion handles POST /discounts/apply-promotion
func (h *DiscountHandler) ApplyPromotion(w http.ResponseWriter, r *http.Request) {
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

	var req applyPromotionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" || req.PromotionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type, entity_id, and promotion_id are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	appliedBy, err := uuid.Parse(req.AppliedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid applied_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	promotion, discount, err := h.discountService.ApplyPromotion(ctx, companyID, req.EntityType, entityID, promotionID, appliedBy)
	if err != nil {
		h.logger.Error("failed to apply promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"promotion":       promotion,
		"discount_amount": discount.String(),
	})
}

// RemovePromotion handles DELETE /discounts/remove-promotion
func (h *DiscountHandler) RemovePromotion(w http.ResponseWriter, r *http.Request) {
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

	var req removePromotionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" || req.PromotionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type, entity_id, and promotion_id are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	removedBy, err := uuid.Parse(req.RemovedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid removed_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.discountService.RemovePromotion(ctx, companyID, req.EntityType, entityID, promotionID, removedBy)
	if err != nil {
		h.logger.Error("failed to remove promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion removed",
	})
}

// ApplyBestDiscounts handles POST /discounts/apply-best
func (h *DiscountHandler) ApplyBestDiscounts(w http.ResponseWriter, r *http.Request) {
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

	var req applyBestDiscountsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type and entity_id are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	appliedBy, err := uuid.Parse(req.AppliedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid applied_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	result, err := h.discountService.ApplyBestDiscounts(ctx, companyID, req.EntityType, entityID, appliedBy)
	if err != nil {
		h.logger.Error("failed to apply best discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// ClearDiscounts handles DELETE /discounts/clear
func (h *DiscountHandler) ClearDiscounts(w http.ResponseWriter, r *http.Request) {
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

	var req clearDiscountsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EntityType == "" || req.EntityID == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type and entity_id are required")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	clearedBy, err := uuid.Parse(req.ClearedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cleared_by")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.discountService.ClearDiscounts(ctx, companyID, req.EntityType, entityID, clearedBy)
	if err != nil {
		h.logger.Error("failed to clear discounts", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "discounts cleared",
	})
}

// TrackCouponUsage handles POST /discounts/track-coupon-usage
func (h *DiscountHandler) TrackCouponUsage(w http.ResponseWriter, r *http.Request) {
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

	var req trackCouponUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CouponID == "" || req.EntityType == "" || req.EntityID == "" || req.UsedAt == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id, entity_type, entity_id, and used_at are required")
		return
	}
	couponID, err := uuid.Parse(req.CouponID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
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
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	usedAt, err := time.Parse(time.RFC3339, req.UsedAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid used_at timestamp")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.discountService.TrackCouponUsage(ctx, companyID, couponID, customerID, req.EntityType, entityID, usedAt)
	if err != nil {
		h.logger.Error("failed to track coupon usage", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon usage tracked",
	})
}

// TrackPromotionUsage handles POST /discounts/track-promotion-usage
func (h *DiscountHandler) TrackPromotionUsage(w http.ResponseWriter, r *http.Request) {
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

	var req trackPromotionUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PromotionID == "" || req.EntityType == "" || req.EntityID == "" || req.UsedAt == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id, entity_type, entity_id, and used_at are required")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
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
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	usedAt, err := time.Parse(time.RFC3339, req.UsedAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid used_at timestamp")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.discountService.TrackPromotionUsage(ctx, companyID, promotionID, customerID, req.EntityType, entityID, usedAt)
	if err != nil {
		h.logger.Error("failed to track promotion usage", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion usage tracked",
	})
}

// ---------- Read‑only analytics / reporting ----------

// GetCouponUsageCount handles GET /discounts/coupon-usage-count
func (h *DiscountHandler) GetCouponUsageCount(w http.ResponseWriter, r *http.Request) {
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

	couponIDStr := r.URL.Query().Get("coupon_id")
	if couponIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id query parameter is required")
		return
	}
	couponID, err := uuid.Parse(couponIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.discountService.GetCouponUsageCount(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to get coupon usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   count,
	})
}

// GetPromotionUsageCount handles GET /discounts/promotion-usage-count
func (h *DiscountHandler) GetPromotionUsageCount(w http.ResponseWriter, r *http.Request) {
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

	promotionIDStr := r.URL.Query().Get("promotion_id")
	if promotionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id query parameter is required")
		return
	}
	promotionID, err := uuid.Parse(promotionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.discountService.GetPromotionUsageCount(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to get promotion usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   count,
	})
}

// GetTopCoupons handles GET /discounts/top-coupons
func (h *DiscountHandler) GetTopCoupons(w http.ResponseWriter, r *http.Request) {
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

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err == nil && l > 0 {
			limit = l
		}
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	coupons, err := h.discountService.GetTopCoupons(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top coupons", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    coupons,
	})
}

// GetTopPromotions handles GET /discounts/top-promotions
func (h *DiscountHandler) GetTopPromotions(w http.ResponseWriter, r *http.Request) {
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

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err == nil && l > 0 {
			limit = l
		}
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, err := h.discountService.GetTopPromotions(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top promotions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    promotions,
	})
}

// GetTotalDiscountAmount handles GET /discounts/total-amount
func (h *DiscountHandler) GetTotalDiscountAmount(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.discountService.GetTotalDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total discount amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"total_discount": total.String(),
	})
}

// GetTotalCouponDiscountAmount handles GET /discounts/total-coupon-amount
func (h *DiscountHandler) GetTotalCouponDiscountAmount(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.discountService.GetTotalCouponDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total coupon discount amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"total_discount": total.String(),
	})
}

// GetTotalPromotionDiscountAmount handles GET /discounts/total-promotion-amount
func (h *DiscountHandler) GetTotalPromotionDiscountAmount(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.discountService.GetTotalPromotionDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total promotion discount amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"total_discount": total.String(),
	})
}

// GetAverageDiscountRate handles GET /discounts/average-rate
func (h *DiscountHandler) GetAverageDiscountRate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rate, err := h.discountService.GetAverageDiscountRate(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get average discount rate", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"average_rate": rate.String(),
	})
}

// CouponExists handles GET /discounts/coupon-exists
func (h *DiscountHandler) CouponExists(w http.ResponseWriter, r *http.Request) {
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

	couponIDStr := r.URL.Query().Get("coupon_id")
	if couponIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id query parameter is required")
		return
	}
	couponID, err := uuid.Parse(couponIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.discountService.CouponExists(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to check coupon existence", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"exists":  exists,
	})
}

// PromotionExists handles GET /discounts/promotion-exists
func (h *DiscountHandler) PromotionExists(w http.ResponseWriter, r *http.Request) {
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

	promotionIDStr := r.URL.Query().Get("promotion_id")
	if promotionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id query parameter is required")
		return
	}
	promotionID, err := uuid.Parse(promotionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.discountService.PromotionExists(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to check promotion existence", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"exists":  exists,
	})
}

// IsCouponExpired handles GET /discounts/coupon-expired
func (h *DiscountHandler) IsCouponExpired(w http.ResponseWriter, r *http.Request) {
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

	couponIDStr := r.URL.Query().Get("coupon_id")
	if couponIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id query parameter is required")
		return
	}
	couponID, err := uuid.Parse(couponIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
		return
	}
	atStr := r.URL.Query().Get("at")
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		at = time.Now().UTC()
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	expired, err := h.discountService.IsCouponExpired(ctx, companyID, couponID, at)
	if err != nil {
		h.logger.Error("failed to check coupon expired", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"expired": expired,
	})
}

// IsPromotionExpired handles GET /discounts/promotion-expired
func (h *DiscountHandler) IsPromotionExpired(w http.ResponseWriter, r *http.Request) {
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

	promotionIDStr := r.URL.Query().Get("promotion_id")
	if promotionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id query parameter is required")
		return
	}
	promotionID, err := uuid.Parse(promotionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	atStr := r.URL.Query().Get("at")
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		at = time.Now().UTC()
	}

	if !h.hasPermission(ctx, companyID, userID, "discount:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	expired, err := h.discountService.IsPromotionExpired(ctx, companyID, promotionID, at)
	if err != nil {
		h.logger.Error("failed to check promotion expired", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"expired": expired,
	})
}
