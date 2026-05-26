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
	"auth-service/internal/sales/service"
)

// PaymentTermHandler handles HTTP requests for payment term management.
type PaymentTermHandler struct {
	paymentTermService service.PaymentTermService
	logger             *zap.Logger
}

// NewPaymentTermHandler creates a new PaymentTermHandler.
func NewPaymentTermHandler(paymentTermService service.PaymentTermService, logger *zap.Logger) *PaymentTermHandler {
	return &PaymentTermHandler{
		paymentTermService: paymentTermService,
		logger:             logger.Named("payment_term_handler"),
	}
}

// ---------- Request/Response Types ----------

type createPaymentTermRequest struct {
	Code            string  `json:"code"`
	TermName        string  `json:"term_name"`
	Description     *string `json:"description,omitempty"`
	DueDays         int     `json:"due_days"`
	DiscountPercent string  `json:"discount_percent"`
	DiscountDays    int     `json:"discount_days"`
	IsActive        bool    `json:"is_active"`
}

type createPaymentTermResponse struct {
	TermID          string  `json:"term_id"`
	CompanyID       string  `json:"company_id"`
	Code            string  `json:"code"`
	TermName        string  `json:"term_name"`
	Description     *string `json:"description,omitempty"`
	DueDays         int     `json:"due_days"`
	DiscountPercent string  `json:"discount_percent"`
	DiscountDays    int     `json:"discount_days"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

type updatePaymentTermRequest struct {
	TermName        *string `json:"term_name,omitempty"`
	Description     *string `json:"description,omitempty"`
	DueDays         *int    `json:"due_days,omitempty"`
	DiscountPercent *string `json:"discount_percent,omitempty"`
	DiscountDays    *int    `json:"discount_days,omitempty"`
	IsActive        *bool   `json:"is_active,omitempty"`
}

type updateStatusRequest struct {
	IsActive bool `json:"is_active"`
}

type calculateDueDateRequest struct {
	InvoiceDate string `json:"invoice_date"`
}

type calculateDueDateResponse struct {
	DueDate string `json:"due_date"`
}

type calculateEarlyDiscountRequest struct {
	InvoiceAmount string `json:"invoice_amount"`
	PaymentDate   string `json:"payment_date"`
	InvoiceDate   string `json:"invoice_date"`
}

type calculateEarlyDiscountResponse struct {
	DiscountAmount string `json:"discount_amount"`
}

type assignCustomerRequest struct {
	CustomerID string `json:"customer_id"`
}

type listPaymentTermsResponse struct {
	PaymentTerms []paymentTermSummary `json:"payment_terms"`
	Total        int64                `json:"total"`
	Limit        int                  `json:"limit"`
	Offset       int                  `json:"offset"`
}

type paymentTermSummary struct {
	TermID          string  `json:"term_id"`
	Code            string  `json:"code"`
	TermName        string  `json:"term_name"`
	DueDays         int     `json:"due_days"`
	DiscountPercent string  `json:"discount_percent"`
	DiscountDays    int     `json:"discount_days"`
	IsActive        bool    `json:"is_active"`
	Description     *string `json:"description,omitempty"`
}

// ---------- Helper Functions ----------

func (h *PaymentTermHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *PaymentTermHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Implement real permission check
	return true
}

func (h *PaymentTermHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func (h *PaymentTermHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PaymentTermHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *PaymentTermHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, salesErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, salesErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidState):
		return http.StatusConflict, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Handler Methods ----------

// CreatePaymentTerm handles POST /payment-terms
func (h *PaymentTermHandler) CreatePaymentTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createPaymentTermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if req.Code == "" || req.TermName == "" {
		h.respondWithError(w, http.StatusBadRequest, "code and term_name are required")
		return
	}
	if req.DueDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "due_days must be positive")
		return
	}
	if req.DiscountDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "discount_days cannot be negative")
		return
	}

	discountPercent, err := decimal.NewFromString(req.DiscountPercent)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount_percent")
		return
	}
	if discountPercent.LessThan(decimal.Zero) || discountPercent.GreaterThan(decimal.NewFromInt(100)) {
		h.respondWithError(w, http.StatusBadRequest, "discount_percent must be between 0 and 100")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	isActive := req.IsActive
	svcReq := service.CreatePaymentTermRequest{
		Code:            req.Code,
		TermName:        req.TermName,
		Description:     req.Description,
		DueDays:         req.DueDays,
		DiscountPercent: discountPercent,
		DiscountDays:    req.DiscountDays,
		IsActive:        &isActive, // Fix: pass pointer
	}

	term, err := h.paymentTermService.CreatePaymentTerm(ctx, &svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createPaymentTermResponse{
		TermID:          term.TermID.String(),
		CompanyID:       term.CompanyID.String(),
		Code:            term.Code,
		TermName:        term.TermName,
		Description:     term.Description,
		DueDays:         term.DueDays,
		DiscountPercent: term.DiscountPercent.String(),
		DiscountDays:    term.DiscountDays,
		IsActive:        term.IsActive,
		CreatedAt:       term.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       term.UpdatedAt.Format(time.RFC3339),
	}

	location := fmt.Sprintf("/payment-terms/%s", term.TermID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePaymentTerm handles PUT /payment-terms/{id}
func (h *PaymentTermHandler) UpdatePaymentTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updatePaymentTermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Convert optional discount percent
	var discountPercent *decimal.Decimal
	if req.DiscountPercent != nil {
		dp, err := decimal.NewFromString(*req.DiscountPercent)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid discount_percent")
			return
		}
		if dp.LessThan(decimal.Zero) || dp.GreaterThan(decimal.NewFromInt(100)) {
			h.respondWithError(w, http.StatusBadRequest, "discount_percent must be between 0 and 100")
			return
		}
		discountPercent = &dp
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.UpdatePaymentTermRequest{
		TermName:        req.TermName,
		Description:     req.Description,
		DueDays:         req.DueDays,
		DiscountPercent: discountPercent,
		DiscountDays:    req.DiscountDays,
		IsActive:        req.IsActive,
	}

	updated, err := h.paymentTermService.UpdatePaymentTerm(ctx, companyID, termID, &svcReq, idempotencyKey) // Fix: pass pointer
	if err != nil {
		h.logger.Error("failed to update payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createPaymentTermResponse{
		TermID:          updated.TermID.String(),
		CompanyID:       updated.CompanyID.String(),
		Code:            updated.Code,
		TermName:        updated.TermName,
		Description:     updated.Description,
		DueDays:         updated.DueDays,
		DiscountPercent: updated.DiscountPercent.String(),
		DiscountDays:    updated.DiscountDays,
		IsActive:        updated.IsActive,
		CreatedAt:       updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       updated.UpdatedAt.Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePaymentTerm handles DELETE /payment-terms/{id}
func (h *PaymentTermHandler) DeletePaymentTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.paymentTermService.DeletePaymentTerm(ctx, companyID, termID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment term deleted",
	})
}

// GetPaymentTermByID handles GET /payment-terms/{id}
func (h *PaymentTermHandler) GetPaymentTermByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	term, err := h.paymentTermService.GetPaymentTermByID(ctx, companyID, termID)
	if err != nil {
		h.logger.Error("failed to get payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createPaymentTermResponse{
		TermID:          term.TermID.String(),
		CompanyID:       term.CompanyID.String(),
		Code:            term.Code,
		TermName:        term.TermName,
		Description:     term.Description,
		DueDays:         term.DueDays,
		DiscountPercent: term.DiscountPercent.String(),
		DiscountDays:    term.DiscountDays,
		IsActive:        term.IsActive,
		CreatedAt:       term.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       term.UpdatedAt.Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPaymentTermByCode handles GET /payment-terms/by-code
func (h *PaymentTermHandler) GetPaymentTermByCode(w http.ResponseWriter, r *http.Request) {
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

	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	term, err := h.paymentTermService.GetPaymentTermByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get payment term by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createPaymentTermResponse{
		TermID:          term.TermID.String(),
		CompanyID:       term.CompanyID.String(),
		Code:            term.Code,
		TermName:        term.TermName,
		Description:     term.Description,
		DueDays:         term.DueDays,
		DiscountPercent: term.DiscountPercent.String(),
		DiscountDays:    term.DiscountDays,
		IsActive:        term.IsActive,
		CreatedAt:       term.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       term.UpdatedAt.Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPaymentTermByName handles GET /payment-terms/by-name
func (h *PaymentTermHandler) GetPaymentTermByName(w http.ResponseWriter, r *http.Request) {
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

	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	term, err := h.paymentTermService.GetPaymentTermByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get payment term by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createPaymentTermResponse{
		TermID:          term.TermID.String(),
		CompanyID:       term.CompanyID.String(),
		Code:            term.Code,
		TermName:        term.TermName,
		Description:     term.Description,
		DueDays:         term.DueDays,
		DiscountPercent: term.DiscountPercent.String(),
		DiscountDays:    term.DiscountDays,
		IsActive:        term.IsActive,
		CreatedAt:       term.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       term.UpdatedAt.Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListPaymentTerms handles GET /payment-terms
func (h *PaymentTermHandler) ListPaymentTerms(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := service.PaymentTermListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}

	// Pagination: limit/offset
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

	// Sorting
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

	terms, total, err := h.paymentTermService.ListPaymentTerms(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list payment terms", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list payment terms")
		return
	}

	summaries := make([]paymentTermSummary, len(terms))
	for i, t := range terms {
		summaries[i] = paymentTermSummary{
			TermID:          t.TermID.String(),
			Code:            t.Code,
			TermName:        t.TermName,
			DueDays:         t.DueDays,
			DiscountPercent: t.DiscountPercent.String(),
			DiscountDays:    t.DiscountDays,
			IsActive:        t.IsActive,
			Description:     t.Description,
		}
	}

	resp := listPaymentTermsResponse{
		PaymentTerms: summaries,
		Total:        total,
		Limit:        limit,
		Offset:       offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchPaymentTerms handles GET /payment-terms/search
func (h *PaymentTermHandler) SearchPaymentTerms(w http.ResponseWriter, r *http.Request) {
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

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	terms, total, err := h.paymentTermService.SearchPaymentTerms(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search payment terms", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search payment terms")
		return
	}

	summaries := make([]paymentTermSummary, len(terms))
	for i, t := range terms {
		summaries[i] = paymentTermSummary{
			TermID:          t.TermID.String(),
			Code:            t.Code,
			TermName:        t.TermName,
			DueDays:         t.DueDays,
			DiscountPercent: t.DiscountPercent.String(),
			DiscountDays:    t.DiscountDays,
			IsActive:        t.IsActive,
			Description:     t.Description,
		}
	}

	resp := listPaymentTermsResponse{
		PaymentTerms: summaries,
		Total:        total,
		Limit:        limit,
		Offset:       offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActivePaymentTerms handles GET /payment-terms/active
func (h *PaymentTermHandler) GetActivePaymentTerms(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	terms, err := h.paymentTermService.GetActivePaymentTerms(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active payment terms", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active payment terms")
		return
	}

	summaries := make([]paymentTermSummary, len(terms))
	for i, t := range terms {
		summaries[i] = paymentTermSummary{
			TermID:          t.TermID.String(),
			Code:            t.Code,
			TermName:        t.TermName,
			DueDays:         t.DueDays,
			DiscountPercent: t.DiscountPercent.String(),
			DiscountDays:    t.DiscountDays,
			IsActive:        t.IsActive,
			Description:     t.Description,
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// UpdatePaymentTermStatus handles PATCH /payment-terms/{id}/status
func (h *PaymentTermHandler) UpdatePaymentTermStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if req.IsActive {
		err = h.paymentTermService.ActivatePaymentTerm(ctx, companyID, termID, userID, idempotencyKey)
	} else {
		err = h.paymentTermService.DeactivatePaymentTerm(ctx, companyID, termID, userID, idempotencyKey)
	}
	if err != nil {
		h.logger.Error("failed to update payment term status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("payment term %s", map[bool]string{true: "activated", false: "deactivated"}[req.IsActive]),
	})
}

// CalculateDueDate handles POST /payment-terms/{id}/calculate-due-date
func (h *PaymentTermHandler) CalculateDueDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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
	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req calculateDueDateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceDate, err := time.Parse(time.RFC3339, req.InvoiceDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_date format, use RFC3339")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	dueDate, err := h.paymentTermService.CalculateDueDate(ctx, companyID, termID, invoiceDate)
	if err != nil {
		h.logger.Error("failed to calculate due date", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := calculateDueDateResponse{
		DueDate: dueDate.Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculateEarlyPaymentDiscount handles POST /payment-terms/{id}/calculate-early-discount
func (h *PaymentTermHandler) CalculateEarlyPaymentDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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
	if !h.hasPermission(ctx, companyID, userID, "payment_term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req calculateEarlyDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	invoiceAmount, err := decimal.NewFromString(req.InvoiceAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_amount")
		return
	}
	if invoiceAmount.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invoice_amount cannot be negative")
		return
	}

	paymentDate, err := time.Parse(time.RFC3339, req.PaymentDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_date format, use RFC3339")
		return
	}
	invoiceDate, err := time.Parse(time.RFC3339, req.InvoiceDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_date format, use RFC3339")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	discount, err := h.paymentTermService.CalculateEarlyPaymentDiscount(ctx, companyID, termID, invoiceAmount, paymentDate, invoiceDate)
	if err != nil {
		h.logger.Error("failed to calculate early payment discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := calculateEarlyDiscountResponse{
		DiscountAmount: discount.String(),
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// AssignPaymentTermToCustomer handles POST /payment-terms/{id}/assign-customer
func (h *PaymentTermHandler) AssignPaymentTermToCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.paymentTermService.AssignPaymentTermToCustomer(ctx, companyID, customerID, termID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to assign payment term to customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment term assigned to customer",
	})
}

// RemovePaymentTermFromCustomer handles DELETE /payment-terms/{id}/assign-customer
func (h *PaymentTermHandler) RemovePaymentTermFromCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse termID from URL (even though service doesn't use it, we keep for route consistency)
	termID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment term ID")
		return
	}
	_ = termID // silences unused variable warning

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

	if !h.hasPermission(ctx, companyID, userID, "payment_term:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.paymentTermService.RemovePaymentTermFromCustomer(ctx, companyID, customerID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to remove payment term from customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment term removed from customer",
	})
}
