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

type CreditCheckHandler struct {
	creditCheckService service.CreditCheckService
	logger             *zap.Logger
}

func NewCreditCheckHandler(creditCheckService service.CreditCheckService, logger *zap.Logger) *CreditCheckHandler {
	return &CreditCheckHandler{
		creditCheckService: creditCheckService,
		logger:             logger.Named("credit_check_handler"),
	}
}

// request/response types

type checkCustomerCreditRequest struct {
	CustomerID      string `json:"customer_id"`
	RequestedAmount string `json:"requested_amount"`
}

type checkOrderCreditRequest struct {
	OrderID string `json:"order_id"`
}

type checkInvoiceCreditRequest struct {
	InvoiceID string `json:"invoice_id"`
}

type creditCheckResponse struct {
	Eligible         bool   `json:"eligible"`
	Reason           string `json:"reason,omitempty"`
	CurrentBalance   string `json:"current_balance,omitempty"`
	CreditLimit      string `json:"credit_limit,omitempty"`
	AvailableCredit  string `json:"available_credit,omitempty"`
	RequestedAmount  string `json:"requested_amount,omitempty"`
	OutstandingCount int    `json:"outstanding_count,omitempty"`
}

type holdOrderRequest struct {
	Reason string `json:"reason"`
}

type updateOrderCreditStatusRequest struct {
	Status string `json:"status"` // pending, approved, rejected, hold
}

type setCreditLimitRequest struct {
	CreditLimit string `json:"credit_limit"`
}

type increaseDecreaseCreditLimitRequest struct {
	IncreaseAmount string `json:"increase_amount"`
	DecreaseAmount string `json:"decrease_amount"`
	Reason         string `json:"reason"`
}

type suspendCreditRequest struct {
	Reason string `json:"reason"`
}

type logCreditCheckRequest struct {
	CustomerID    string  `json:"customer_id"`
	ActionType    string  `json:"action_type"`
	PreviousLimit *string `json:"previous_limit,omitempty"`
	NewLimit      *string `json:"new_limit,omitempty"`
	Reason        *string `json:"reason,omitempty"`
	ApprovedBy    *string `json:"approved_by,omitempty"`
}

type creditCheckHistoryResponse struct {
	CreditHistoryID string  `json:"credit_history_id"`
	CustomerID      string  `json:"customer_id"`
	ActionType      string  `json:"action_type"`
	PreviousLimit   *string `json:"previous_limit,omitempty"`
	NewLimit        *string `json:"new_limit,omitempty"`
	Reason          *string `json:"reason,omitempty"`
	ApprovedBy      *string `json:"approved_by,omitempty"`
	CreatedBy       *string `json:"created_by,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

type creditHistoryListResponse struct {
	History []creditCheckHistoryResponse `json:"history"`
	Total   int64                        `json:"total"`
	Limit   int                          `json:"limit"`
	Offset  int                          `json:"offset"`
}

// helper methods

func (h *CreditCheckHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *CreditCheckHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *CreditCheckHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func (h *CreditCheckHandler) getCompanyIDFromQuery(r *http.Request) (uuid.UUID, error) {
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company_id query parameter is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *CreditCheckHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *CreditCheckHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *CreditCheckHandler) mapServiceError(err error) (status int, message string) {
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

func (h *CreditCheckHandler) toCreditCheckHistoryResponse(history *models.CreditCheckHistory) creditCheckHistoryResponse {
	resp := creditCheckHistoryResponse{
		CreditHistoryID: history.CreditHistoryID.String(),
		CustomerID:      history.CustomerID.String(),
		ActionType:      history.ActionType,
		CreatedAt:       history.CreatedAt.Format(time.RFC3339),
	}
	if history.PreviousLimit != nil {
		val := history.PreviousLimit.String()
		resp.PreviousLimit = &val
	}
	if history.NewLimit != nil {
		val := history.NewLimit.String()
		resp.NewLimit = &val
	}
	if history.Reason != nil {
		resp.Reason = history.Reason
	}
	if history.ApprovedBy != nil {
		val := history.ApprovedBy.String()
		resp.ApprovedBy = &val
	}
	if history.CreatedBy != nil {
		val := history.CreatedBy.String()
		resp.CreatedBy = &val
	}
	return resp
}

// endpoint implementations

func (h *CreditCheckHandler) CheckCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req checkCustomerCreditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
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

	requestedAmount, err := decimal.NewFromString(req.RequestedAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid requested_amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:check") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	result, err := h.creditCheckService.CheckCustomerCreditLimit(ctx, companyID, customerID, requestedAmount)
	if err != nil {
		h.logger.Error("failed to check customer credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := creditCheckResponse{
		Eligible:         result.Eligible,
		Reason:           result.Reason,
		CurrentBalance:   result.CurrentBalance.String(),
		CreditLimit:      result.CreditLimit.String(),
		AvailableCredit:  result.AvailableCredit.String(),
		RequestedAmount:  result.RequestedAmount.String(),
		OutstandingCount: result.OutstandingCount,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) CheckOrderCreditEligibility(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req checkOrderCreditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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

	if !h.hasPermission(ctx, companyID, userID, "credit:check") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	result, err := h.creditCheckService.CheckOrderCreditEligibility(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check order credit eligibility", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := creditCheckResponse{
		Eligible:         result.Eligible,
		Reason:           result.Reason,
		CurrentBalance:   result.CurrentBalance.String(),
		CreditLimit:      result.CreditLimit.String(),
		AvailableCredit:  result.AvailableCredit.String(),
		RequestedAmount:  result.RequestedAmount.String(),
		OutstandingCount: result.OutstandingCount,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) CheckInvoiceCreditEligibility(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req checkInvoiceCreditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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

	if !h.hasPermission(ctx, companyID, userID, "credit:check") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	result, err := h.creditCheckService.CheckInvoiceCreditEligibility(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to check invoice credit eligibility", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := creditCheckResponse{
		Eligible:         result.Eligible,
		Reason:           result.Reason,
		CurrentBalance:   result.CurrentBalance.String(),
		CreditLimit:      result.CreditLimit.String(),
		AvailableCredit:  result.AvailableCredit.String(),
		RequestedAmount:  result.RequestedAmount.String(),
		OutstandingCount: result.OutstandingCount,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) GetCustomerAvailableCredit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	available, err := h.creditCheckService.GetCustomerAvailableCredit(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer available credit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"available_credit": available.String()},
	})
}

func (h *CreditCheckHandler) GetCustomerOutstandingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	balance, err := h.creditCheckService.GetCustomerOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer outstanding balance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"outstanding_balance": balance.String()},
	})
}

func (h *CreditCheckHandler) GetCustomerCreditExposure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exposure, err := h.creditCheckService.GetCustomerCreditExposure(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer credit exposure", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_exposure": exposure.String()},
	})
}

func (h *CreditCheckHandler) CanCustomerPlaceOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	canPlace, err := h.creditCheckService.CanCustomerPlaceOrder(ctx, companyID, customerID, amount)
	if err != nil {
		h.logger.Error("failed to check if customer can place order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"can_place_order": canPlace},
	})
}

func (h *CreditCheckHandler) HoldOrderForCredit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req holdOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.HoldOrderForCredit(ctx, companyID, orderID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to hold order for credit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order placed on credit hold",
	})
}

func (h *CreditCheckHandler) ReleaseOrderCreditHold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req holdOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.ReleaseOrderCreditHold(ctx, companyID, orderID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to release order credit hold", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit hold released",
	})
}

func (h *CreditCheckHandler) IsOrderOnCreditHold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	onHold, err := h.creditCheckService.IsOrderOnCreditHold(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check if order is on credit hold", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"on_credit_hold": onHold},
	})
}

func (h *CreditCheckHandler) GetOrdersOnCreditHold(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, err := h.creditCheckService.GetOrdersOnCreditHold(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get orders on credit hold", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve orders")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orders,
	})
}

func (h *CreditCheckHandler) UpdateOrderCreditStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateOrderCreditStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	status := enums.CreditCheckStatus(req.Status)
	if !status.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit status")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.UpdateOrderCreditStatus(ctx, companyID, orderID, status, userID)
	if err != nil {
		h.logger.Error("failed to update order credit status", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order credit status updated",
	})
}

func (h *CreditCheckHandler) SetCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req setCreditLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	creditLimit, err := decimal.NewFromString(req.CreditLimit)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit_limit")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.SetCustomerCreditLimit(ctx, companyID, customerID, creditLimit, userID)
	if err != nil {
		h.logger.Error("failed to set customer credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit limit set",
	})
}

func (h *CreditCheckHandler) IncreaseCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req increaseDecreaseCreditLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	increaseAmount, err := decimal.NewFromString(req.IncreaseAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid increase_amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.IncreaseCustomerCreditLimit(ctx, companyID, customerID, increaseAmount, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to increase customer credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit limit increased",
	})
}

func (h *CreditCheckHandler) DecreaseCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req increaseDecreaseCreditLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	decreaseAmount, err := decimal.NewFromString(req.DecreaseAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid decrease_amount")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.DecreaseCustomerCreditLimit(ctx, companyID, customerID, decreaseAmount, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to decrease customer credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit limit decreased",
	})
}

func (h *CreditCheckHandler) SuspendCustomerCredit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req suspendCreditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.SuspendCustomerCredit(ctx, companyID, customerID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to suspend customer credit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "customer credit suspended",
	})
}

func (h *CreditCheckHandler) RestoreCustomerCredit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.creditCheckService.RestoreCustomerCredit(ctx, companyID, customerID, userID)
	if err != nil {
		h.logger.Error("failed to restore customer credit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "customer credit restored",
	})
}

func (h *CreditCheckHandler) GetCustomerCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, err := h.creditCheckService.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_limit": limit.String()},
	})
}

func (h *CreditCheckHandler) IsCustomerCreditSuspended(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	suspended, err := h.creditCheckService.IsCustomerCreditSuspended(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to check if customer credit suspended", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"suspended": suspended},
	})
}

func (h *CreditCheckHandler) LogCreditCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req logCreditCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
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

	var previousLimit, newLimit *decimal.Decimal
	if req.PreviousLimit != nil && *req.PreviousLimit != "" {
		pl, err := decimal.NewFromString(*req.PreviousLimit)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid previous_limit")
			return
		}
		previousLimit = &pl
	}
	if req.NewLimit != nil && *req.NewLimit != "" {
		nl, err := decimal.NewFromString(*req.NewLimit)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid new_limit")
			return
		}
		newLimit = &nl
	}

	var approvedBy *uuid.UUID
	if req.ApprovedBy != nil && *req.ApprovedBy != "" {
		ab, err := uuid.Parse(*req.ApprovedBy)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid approved_by")
			return
		}
		approvedBy = &ab
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.CreateCreditCheckHistoryRequest{
		CompanyID:     companyID,
		CustomerID:    customerID,
		ActionType:    req.ActionType,
		PreviousLimit: previousLimit,
		NewLimit:      newLimit,
		Reason:        req.Reason,
		ApprovedBy:    approvedBy,
		CreatedBy:     &userID,
	}

	history, err := h.creditCheckService.LogCreditCheck(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to log credit check", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditCheckHistoryResponse(history)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) GetCreditCheckHistoryByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	historyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid history ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	history, err := h.creditCheckService.GetCreditCheckHistoryByID(ctx, companyID, historyID)
	if err != nil {
		h.logger.Error("failed to get credit check history", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditCheckHistoryResponse(history)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) GetCustomerCreditHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	pagination := service.Pagination{
		Limit:  20,
		Offset: 0,
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			pagination.Limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			pagination.Offset = o
		}
	}
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

	history, total, err := h.creditCheckService.GetCustomerCreditHistory(ctx, companyID, customerID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get customer credit history", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	items := make([]creditCheckHistoryResponse, len(history))
	for i, hh := range history {
		items[i] = h.toCreditCheckHistoryResponse(hh)
	}
	resp := creditHistoryListResponse{
		History: items,
		Total:   total,
		Limit:   pagination.Limit,
		Offset:  pagination.Offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditCheckHandler) GetOrderCreditHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	history, err := h.creditCheckService.GetOrderCreditHistory(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get order credit history", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	items := make([]creditCheckHistoryResponse, len(history))
	for i, hh := range history {
		items[i] = h.toCreditCheckHistoryResponse(hh)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

func (h *CreditCheckHandler) GetFailedCreditChecks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
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

	failed, err := h.creditCheckService.GetFailedCreditChecks(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get failed credit checks", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve failed checks")
		return
	}

	items := make([]creditCheckHistoryResponse, len(failed))
	for i, f := range failed {
		items[i] = h.toCreditCheckHistoryResponse(f)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

func (h *CreditCheckHandler) RunAutomaticCreditReview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	result, err := h.creditCheckService.RunAutomaticCreditReview(ctx, companyID, customerID, userID)
	if err != nil {
		h.logger.Error("failed to run automatic credit review", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *CreditCheckHandler) GetCustomersExceedingCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, err := h.creditCheckService.GetCustomersExceedingCreditLimit(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get customers exceeding credit limit", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve customers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}

func (h *CreditCheckHandler) GetCustomersNearCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	thresholdStr := r.URL.Query().Get("threshold_percent")
	if thresholdStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "threshold_percent query parameter is required")
		return
	}
	threshold, err := decimal.NewFromString(thresholdStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid threshold_percent")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, err := h.creditCheckService.GetCustomersNearCreditLimit(ctx, companyID, threshold)
	if err != nil {
		h.logger.Error("failed to get customers near credit limit", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve customers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}

func (h *CreditCheckHandler) GetHighRiskCustomers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	customers, err := h.creditCheckService.GetHighRiskCustomers(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get high risk customers", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve customers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    customers,
	})
}

func (h *CreditCheckHandler) GetAveragePaymentDelay(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
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

	delay, err := h.creditCheckService.GetAveragePaymentDelay(ctx, companyID, customerID, from, to)
	if err != nil {
		h.logger.Error("failed to get average payment delay", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"average_payment_delay_days": delay.String()},
	})
}

func (h *CreditCheckHandler) GetCustomerCollectionScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	score, err := h.creditCheckService.GetCustomerCollectionScore(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer collection score", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"collection_score": score.String()},
	})
}

func (h *CreditCheckHandler) GetCustomerCreditUtilization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	utilization, err := h.creditCheckService.GetCustomerCreditUtilization(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer credit utilization", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_utilization": utilization.String()},
	})
}

func (h *CreditCheckHandler) GetTotalOutstandingCredit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.creditCheckService.GetTotalOutstandingCredit(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get total outstanding credit", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute total")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_outstanding_credit": total.String()},
	})
}

func (h *CreditCheckHandler) GetTotalCreditExposure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.creditCheckService.GetTotalCreditExposure(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get total credit exposure", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute exposure")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_credit_exposure": total.String()},
	})
}

func (h *CreditCheckHandler) GetAverageCreditUtilization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
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

	avg, err := h.creditCheckService.GetAverageCreditUtilization(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get average credit utilization", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute average")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"average_credit_utilization": avg.String()},
	})
}

func (h *CreditCheckHandler) GetCreditHoldRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
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

	rate, err := h.creditCheckService.GetCreditHoldRate(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get credit hold rate", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute rate")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_hold_rate": rate.String()},
	})
}

func (h *CreditCheckHandler) CreditHistoryExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	historyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid history ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.creditCheckService.CreditHistoryExists(ctx, companyID, historyID)
	if err != nil {
		h.logger.Error("failed to check credit history exists", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

func (h *CreditCheckHandler) OrderHasCreditIssues(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	hasIssues, err := h.creditCheckService.OrderHasCreditIssues(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check order has credit issues", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"has_credit_issues": hasIssues},
	})
}

func (h *CreditCheckHandler) CustomerExceededCreditLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}

	companyID, err := h.getCompanyIDFromQuery(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exceeded, err := h.creditCheckService.CustomerExceededCreditLimit(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to check if customer exceeded credit limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exceeded_credit_limit": exceeded},
	})
}
