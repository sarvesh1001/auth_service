package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/service"
)

// CustomerHandler handles HTTP requests for customer management.
type CustomerHandler struct {
	customerService service.CustomerService
	logger          *zap.Logger
}

// NewCustomerHandler creates a new CustomerHandler.
func NewCustomerHandler(customerService service.CustomerService, logger *zap.Logger) *CustomerHandler {
	return &CustomerHandler{
		customerService: customerService,
		logger:          logger.Named("customer_handler"),
	}
}

// ---------- Request/Response Types ----------

type createCustomerRequest struct {
	CompanyID      string  `json:"company_id"`
	CustomerCode   string  `json:"customer_code"`
	Name           string  `json:"name"`
	Email          *string `json:"email,omitempty"`
	Phone          *string `json:"phone,omitempty"`
	TaxID          *string `json:"tax_id,omitempty"`
	BillingAddress *string `json:"billing_address,omitempty"`
	CreditLimit    *string `json:"credit_limit,omitempty"`
	PaymentTermID  *string `json:"payment_term_id,omitempty"`
}

type createCustomerResponse struct {
	CustomerID      string  `json:"customer_id"`
	CompanyID       string  `json:"company_id"`
	CustomerCode    string  `json:"customer_code"`
	Name            string  `json:"name"`
	Email           *string `json:"email,omitempty"`
	Phone           *string `json:"phone,omitempty"`
	TaxID           *string `json:"tax_id,omitempty"`
	BillingAddress  *string `json:"billing_address,omitempty"`
	ShippingAddress *string `json:"shipping_address,omitempty"`
	CreditLimit     *string `json:"credit_limit,omitempty"`
	PaymentTermID   *string `json:"payment_term_id,omitempty"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

type updateCustomerRequest struct {
	Name           *string `json:"name,omitempty"`
	Email          *string `json:"email,omitempty"`
	Phone          *string `json:"phone,omitempty"`
	TaxID          *string `json:"tax_id,omitempty"`
	BillingAddress *string `json:"billing_address,omitempty"`
}

type updateCreditLimitRequest struct {
	NewLimit string  `json:"new_limit"`
	Reason   *string `json:"reason,omitempty"`
}

type assignPaymentTermRequest struct {
	TermID string `json:"term_id"`
}

type assignSalesRepRequest struct {
	SalesRepID string `json:"sales_rep_id"`
}

type listCustomersResponse struct {
	Customers []customerSummary `json:"customers"`
	Total     int64             `json:"total"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
}

type customerSummary struct {
	CustomerID   string  `json:"customer_id"`
	CustomerCode string  `json:"customer_code"`
	Name         string  `json:"name"`
	Email        *string `json:"email,omitempty"`
	IsActive     bool    `json:"is_active"`
	CreditLimit  *string `json:"credit_limit,omitempty"`
}

// ---------- Helper Functions ----------

func (h *CustomerHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *CustomerHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Implement real permission check
	return true
}

func (h *CustomerHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *CustomerHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *CustomerHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, salesErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, salesErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidState):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Handler Methods ----------

// CreateCustomer handles POST /customers
func (h *CustomerHandler) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if req.CompanyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if req.CustomerCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_code is required")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}

	var creditLimit *decimal.Decimal
	if req.CreditLimit != nil && *req.CreditLimit != "" {
		limit, err := decimal.NewFromString(*req.CreditLimit)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid credit_limit")
			return
		}
		if limit.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "credit_limit cannot be negative")
			return
		}
		creditLimit = &limit
	}

	var paymentTermID *uuid.UUID
	if req.PaymentTermID != nil && *req.PaymentTermID != "" {
		parsed, err := uuid.Parse(*req.PaymentTermID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid payment_term_id")
			return
		}
		paymentTermID = &parsed
	}

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.CreateCustomerRequest{
		CompanyID:      companyID,
		CustomerCode:   req.CustomerCode,
		Name:           req.Name,
		Email:          req.Email,
		Phone:          req.Phone,
		TaxID:          req.TaxID,
		BillingAddress: req.BillingAddress,
		CreditLimit:    creditLimit,
		PaymentTermID:  paymentTermID,
		CreatedBy:      &userID,
	}

	customer, err := h.customerService.CreateCustomer(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createCustomerResponse{
		CustomerID:      customer.CustomerID.String(),
		CompanyID:       customer.CompanyID.String(),
		CustomerCode:    customer.CustomerCode,
		Name:            customer.Name,
		Email:           customer.Email,
		Phone:           customer.Phone,
		TaxID:           customer.TaxID,
		BillingAddress:  customer.BillingAddress,
		ShippingAddress: customer.ShippingAddress,
		IsActive:        customer.IsActive,
		CreatedAt:       customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       customer.UpdatedAt.Format(time.RFC3339),
	}
	if customer.CreditLimit != nil {
		limitStr := customer.CreditLimit.String()
		resp.CreditLimit = &limitStr
	}
	if customer.PaymentTermID != nil {
		idStr := customer.PaymentTermID.String()
		resp.PaymentTermID = &idStr
	}

	location := fmt.Sprintf("/customers/%s", customer.CustomerID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateCustomer handles PUT /customers/{id}
func (h *CustomerHandler) UpdateCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.UpdateCustomerRequest{
		Name:           req.Name,
		Email:          req.Email,
		Phone:          req.Phone,
		TaxID:          req.TaxID,
		BillingAddress: req.BillingAddress,
		UpdatedBy:      &userID,
	}

	updated, err := h.customerService.UpdateCustomer(ctx, companyID, customerID, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createCustomerResponse{
		CustomerID:      updated.CustomerID.String(),
		CompanyID:       updated.CompanyID.String(),
		CustomerCode:    updated.CustomerCode,
		Name:            updated.Name,
		Email:           updated.Email,
		Phone:           updated.Phone,
		TaxID:           updated.TaxID,
		BillingAddress:  updated.BillingAddress,
		ShippingAddress: updated.ShippingAddress,
		IsActive:        updated.IsActive,
		CreatedAt:       updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.CreditLimit != nil {
		limitStr := updated.CreditLimit.String()
		resp.CreditLimit = &limitStr
	}
	if updated.PaymentTermID != nil {
		idStr := updated.PaymentTermID.String()
		resp.PaymentTermID = &idStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteCustomer handles DELETE /customers/{id}
func (h *CustomerHandler) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.DeleteCustomer(ctx, companyID, customerID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "customer deleted successfully",
	})
}

// GetCustomerByID handles GET /customers/{id}
func (h *CustomerHandler) GetCustomerByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customer, err := h.customerService.GetCustomerByID(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createCustomerResponse{
		CustomerID:      customer.CustomerID.String(),
		CompanyID:       customer.CompanyID.String(),
		CustomerCode:    customer.CustomerCode,
		Name:            customer.Name,
		Email:           customer.Email,
		Phone:           customer.Phone,
		TaxID:           customer.TaxID,
		BillingAddress:  customer.BillingAddress,
		ShippingAddress: customer.ShippingAddress,
		IsActive:        customer.IsActive,
		CreatedAt:       customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       customer.UpdatedAt.Format(time.RFC3339),
	}
	if customer.CreditLimit != nil {
		limitStr := customer.CreditLimit.String()
		resp.CreditLimit = &limitStr
	}
	if customer.PaymentTermID != nil {
		idStr := customer.PaymentTermID.String()
		resp.PaymentTermID = &idStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCustomerByCode handles GET /customers/by-code
func (h *CustomerHandler) GetCustomerByCode(w http.ResponseWriter, r *http.Request) {
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

	customerCode := r.URL.Query().Get("code")
	if customerCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customer, err := h.customerService.GetCustomerByCode(ctx, companyID, customerCode)
	if err != nil {
		h.logger.Error("failed to get customer by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createCustomerResponse{
		CustomerID:      customer.CustomerID.String(),
		CompanyID:       customer.CompanyID.String(),
		CustomerCode:    customer.CustomerCode,
		Name:            customer.Name,
		Email:           customer.Email,
		Phone:           customer.Phone,
		TaxID:           customer.TaxID,
		BillingAddress:  customer.BillingAddress,
		ShippingAddress: customer.ShippingAddress,
		IsActive:        customer.IsActive,
		CreatedAt:       customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       customer.UpdatedAt.Format(time.RFC3339),
	}
	if customer.CreditLimit != nil {
		limitStr := customer.CreditLimit.String()
		resp.CreditLimit = &limitStr
	}
	if customer.PaymentTermID != nil {
		idStr := customer.PaymentTermID.String()
		resp.PaymentTermID = &idStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListCustomers handles GET /customers
func (h *CustomerHandler) ListCustomers(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := service.CustomerListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	// Note: CustomerListFilter does not have Search field, so we omit it.

	// Pagination -> limit/offset
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

	customers, total, err := h.customerService.ListCustomers(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list customers", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list customers")
		return
	}

	summaries := make([]customerSummary, len(customers))
	for i, c := range customers {
		summaries[i] = customerSummary{
			CustomerID:   c.CustomerID.String(),
			CustomerCode: c.CustomerCode,
			Name:         c.Name,
			Email:        c.Email,
			IsActive:     c.IsActive,
		}
		if c.CreditLimit != nil {
			limitStr := c.CreditLimit.String()
			summaries[i].CreditLimit = &limitStr
		}
	}

	resp := listCustomersResponse{
		Customers: summaries,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchCustomers handles GET /customers/search
func (h *CustomerHandler) SearchCustomers(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, total, err := h.customerService.SearchCustomers(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search customers", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search customers")
		return
	}

	summaries := make([]customerSummary, len(customers))
	for i, c := range customers {
		summaries[i] = customerSummary{
			CustomerID:   c.CustomerID.String(),
			CustomerCode: c.CustomerCode,
			Name:         c.Name,
			Email:        c.Email,
			IsActive:     c.IsActive,
		}
		if c.CreditLimit != nil {
			limitStr := c.CreditLimit.String()
			summaries[i].CreditLimit = &limitStr
		}
	}

	resp := listCustomersResponse{
		Customers: summaries,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ActivateCustomer handles PATCH /customers/{id}/activate
func (h *CustomerHandler) ActivateCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.ActivateCustomer(ctx, companyID, customerID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to activate customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "customer activated",
	})
}

// DeactivateCustomer handles PATCH /customers/{id}/deactivate
func (h *CustomerHandler) DeactivateCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.DeactivateCustomer(ctx, companyID, customerID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to deactivate customer", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "customer deactivated",
	})
}

// UpdateCreditLimit handles PATCH /customers/{id}/credit-limit
func (h *CustomerHandler) UpdateCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCreditLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewLimit == "" {
		h.respondWithError(w, http.StatusBadRequest, "new_limit is required")
		return
	}
	newLimit, err := decimal.NewFromString(req.NewLimit)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_limit")
		return
	}
	if newLimit.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "new_limit cannot be negative")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.UpdateCreditLimit(ctx, companyID, customerID, newLimit, req.Reason, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit limit updated",
	})
}

// GetCreditLimit handles GET /customers/{id}/credit-limit
func (h *CustomerHandler) GetCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, err := h.customerService.GetCreditLimit(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"credit_limit": limit.String(),
		},
	})
}

// GetOutstandingBalance handles GET /customers/{id}/outstanding-balance
func (h *CustomerHandler) GetOutstandingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	balance, err := h.customerService.GetOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get outstanding balance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"outstanding_balance": balance.String(),
		},
	})
}

// CanCustomerPurchaseAmount handles GET /customers/{id}/can-purchase
func (h *CustomerHandler) CanCustomerPurchaseAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	amountStr := r.URL.Query().Get("amount")
	if amountStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "amount query parameter is required")
		return
	}
	amount, err := decimal.NewFromString(amountStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	if amount.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "amount cannot be negative")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	canPurchase, err := h.customerService.CanCustomerPurchaseAmount(ctx, companyID, customerID, amount)
	if err != nil {
		h.logger.Error("failed to check purchase eligibility", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]bool{
			"can_purchase": canPurchase,
		},
	})
}

// AssignPaymentTerm handles POST /customers/{id}/payment-term
func (h *CustomerHandler) AssignPaymentTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignPaymentTermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TermID == "" {
		h.respondWithError(w, http.StatusBadRequest, "term_id is required")
		return
	}
	termID, err := uuid.Parse(req.TermID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term_id")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.AssignPaymentTerm(ctx, companyID, customerID, termID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to assign payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment term assigned",
	})
}

// RemovePaymentTerm handles DELETE /customers/{id}/payment-term
func (h *CustomerHandler) RemovePaymentTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.RemovePaymentTerm(ctx, companyID, customerID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to remove payment term", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "payment term removed",
	})
}

// AssignSalesRep handles POST /customers/{id}/sales-rep
func (h *CustomerHandler) AssignSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignSalesRepRequest
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

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.AssignSalesRep(ctx, companyID, customerID, salesRepID, &userID, idempotencyKey)
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

// RemoveSalesRep handles DELETE /customers/{id}/sales-rep
func (h *CustomerHandler) RemoveSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.customerService.RemoveSalesRep(ctx, companyID, customerID, &userID, idempotencyKey)
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

// GetCustomersWithOutstandingInvoices handles GET /customers/outstanding-invoices
func (h *CustomerHandler) GetCustomersWithOutstandingInvoices(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, err := h.customerService.GetCustomersWithOutstandingInvoices(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get customers with outstanding invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get customers")
		return
	}

	summaries := make([]customerSummary, len(customers))
	for i, c := range customers {
		summaries[i] = customerSummary{
			CustomerID:   c.CustomerID.String(),
			CustomerCode: c.CustomerCode,
			Name:         c.Name,
			Email:        c.Email,
			IsActive:     c.IsActive,
		}
		if c.CreditLimit != nil {
			limitStr := c.CreditLimit.String()
			summaries[i].CreditLimit = &limitStr
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetTopCustomersByRevenue handles GET /customers/top-revenue
func (h *CustomerHandler) GetTopCustomersByRevenue(w http.ResponseWriter, r *http.Request) {
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

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
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

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, err := h.customerService.GetTopCustomersByRevenue(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top customers by revenue", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get customers")
		return
	}

	summaries := make([]customerSummary, len(customers))
	for i, c := range customers {
		summaries[i] = customerSummary{
			CustomerID:   c.CustomerID.String(),
			CustomerCode: c.CustomerCode,
			Name:         c.Name,
			Email:        c.Email,
			IsActive:     c.IsActive,
		}
		if c.CreditLimit != nil {
			limitStr := c.CreditLimit.String()
			summaries[i].CreditLimit = &limitStr
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// CustomerExists handles GET /customers/{id}/exists
func (h *CustomerHandler) CustomerExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.customerService.CustomerExists(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to check customer existence", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// IsCustomerActive handles GET /customers/{id}/active
func (h *CustomerHandler) IsCustomerActive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	customerID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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

	if !h.hasPermission(ctx, companyID, userID, "customer:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	active, err := h.customerService.IsCustomerActive(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to check if customer is active", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"active": active},
	})
}
