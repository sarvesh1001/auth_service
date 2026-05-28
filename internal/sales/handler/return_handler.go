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

type ReturnHandler struct {
	returnService service.ReturnService
	*BaseHandler
}

func NewReturnHandler(returnService service.ReturnService, logger *zap.Logger) *ReturnHandler {
	return &ReturnHandler{
		returnService: returnService,
		BaseHandler:   &BaseHandler{logger: logger.Named("commission_handler")},
	}
}

// Request/Response types

type createReturnRequest struct {
	CompanyID  string                    `json:"company_id"`
	OrderID    string                    `json:"order_id"`
	InvoiceID  *string                   `json:"invoice_id,omitempty"`
	ReturnDate string                    `json:"return_date"`
	Reason     *string                   `json:"reason,omitempty"`
	Items      []createReturnItemRequest `json:"items"`
}

type createReturnItemRequest struct {
	OrderItemID *string `json:"order_item_id,omitempty"`
	ProductID   string  `json:"product_id"`
	Quantity    string  `json:"quantity"`
	Reason      *string `json:"reason,omitempty"`
}

type createReturnFromOrderRequest struct {
	OrderID    string                    `json:"order_id"`
	ReturnDate string                    `json:"return_date,omitempty"`
	Reason     *string                   `json:"reason,omitempty"`
	Items      []createReturnItemRequest `json:"items"`
}

type createReturnFromInvoiceRequest struct {
	InvoiceID  string                    `json:"invoice_id"`
	ReturnDate string                    `json:"return_date,omitempty"`
	Reason     *string                   `json:"reason,omitempty"`
	Items      []createReturnItemRequest `json:"items"`
}

type updateReturnRequest struct {
	ReturnDate *time.Time `json:"return_date,omitempty"`
	Reason     *string    `json:"reason,omitempty"`
}

type returnResponse struct {
	ReturnID     string  `json:"return_id"`
	CompanyID    string  `json:"company_id"`
	OrderID      string  `json:"order_id"`
	InvoiceID    *string `json:"invoice_id,omitempty"`
	CreditNoteID *string `json:"credit_note_id,omitempty"`
	ReturnNumber string  `json:"return_number"`
	ReturnDate   string  `json:"return_date"`
	Reason       *string `json:"reason,omitempty"`
	Status       string  `json:"status"`
	TotalRefund  string  `json:"total_refund"`
	ApprovedAt   *string `json:"approved_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

type returnItemResponse struct {
	ReturnItemID        string  `json:"return_item_id"`
	ReturnID            string  `json:"return_id"`
	OrderItemID         *string `json:"order_item_id,omitempty"`
	ProductID           string  `json:"product_id"`
	ProductNameSnapshot string  `json:"product_name_snapshot"`
	Quantity            string  `json:"quantity"`
	UnitPrice           string  `json:"unit_price"`
	RefundAmount        string  `json:"refund_amount"`
	Reason              *string `json:"reason,omitempty"`
	CreatedAt           string  `json:"created_at"`
}

type listReturnsResponse struct {
	Returns []returnSummary `json:"returns"`
	Total   int64           `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
}

type returnSummary struct {
	ReturnID     string `json:"return_id"`
	ReturnNumber string `json:"return_number"`
	OrderID      string `json:"order_id"`
	Status       string `json:"status"`
	ReturnDate   string `json:"return_date"`
	TotalRefund  string `json:"total_refund"`
}

type refundAmountResponse struct {
	Subtotal           string `json:"subtotal"`
	TaxRefund          string `json:"tax_refund"`
	DiscountAdjustment string `json:"discount_adjustment"`
	TotalRefund        string `json:"total_refund"`
}

type partialRefundRequest struct {
	ItemIDs []string `json:"item_ids"`
}

type previewRefundRequest struct {
	CompanyID string              `json:"company_id"`
	OrderID   *string             `json:"order_id,omitempty"`
	InvoiceID *string             `json:"invoice_id,omitempty"`
	Items     []previewRefundItem `json:"items"`
}

type previewRefundItem struct {
	ProductID string `json:"product_id"`
	Quantity  string `json:"quantity"`
}

type generateCreditNoteRequest struct {
	// empty – service only needs IssuedBy from context
}

type processRefundRequest struct {
	Amount string `json:"amount"`
	Reason string `json:"reason"`
}

type restockRequest struct {
	WarehouseID string `json:"warehouse_id"`
}

type markDamagedRequest struct {
	ItemIDs []string `json:"item_ids"`
}

// Helper functions

// Conversion helpers

func (h *ReturnHandler) toReturnResponse(r *models.Return) returnResponse {
	resp := returnResponse{
		ReturnID:     r.ReturnID.String(),
		CompanyID:    r.CompanyID.String(),
		OrderID:      r.OrderID.String(),
		ReturnNumber: r.ReturnNumber,
		ReturnDate:   r.ReturnDate.Format(time.RFC3339),
		Reason:       r.Reason,
		Status:       r.Status,
		TotalRefund:  r.TotalRefund.String(),
		CreatedAt:    r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    r.UpdatedAt.Format(time.RFC3339),
	}
	if r.InvoiceID != nil {
		idStr := r.InvoiceID.String()
		resp.InvoiceID = &idStr
	}
	if r.CreditNoteID != nil {
		idStr := r.CreditNoteID.String()
		resp.CreditNoteID = &idStr
	}
	if r.ApprovedAt != nil {
		at := r.ApprovedAt.Format(time.RFC3339)
		resp.ApprovedAt = &at
	}
	if r.CompletedAt != nil {
		at := r.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &at
	}
	return resp
}

func (h *ReturnHandler) toReturnItemResponse(item *models.ReturnItem) returnItemResponse {
	resp := returnItemResponse{
		ReturnItemID:        item.ReturnItemID.String(),
		ReturnID:            item.ReturnID.String(),
		ProductID:           item.ProductID.String(),
		ProductNameSnapshot: item.ProductNameSnapshot,
		Quantity:            item.Quantity.String(),
		UnitPrice:           item.UnitPrice.String(),
		RefundAmount:        item.RefundAmount.String(),
		Reason:              item.Reason,
		CreatedAt:           item.CreatedAt.Format(time.RFC3339),
	}
	if item.OrderItemID != nil {
		idStr := item.OrderItemID.String()
		resp.OrderItemID = &idStr
	}
	return resp
}

// Handlers

func (h *ReturnHandler) CreateReturnRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == "" || req.OrderID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id and order_id are required")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	orderID, err := uuid.Parse(req.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}
	var invoiceID *uuid.UUID
	if req.InvoiceID != nil && *req.InvoiceID != "" {
		parsed, err := uuid.Parse(*req.InvoiceID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
			return
		}
		invoiceID = &parsed
	}
	returnDate := time.Now()
	if req.ReturnDate != "" {
		returnDate, err = time.Parse(time.RFC3339, req.ReturnDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid return_date")
			return
		}
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	items := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		var orderItemID *uuid.UUID
		if it.OrderItemID != nil && *it.OrderItemID != "" {
			parsed, err := uuid.Parse(*it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			orderItemID = &parsed
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateReturnItemRequest{
			OrderItemID: orderItemID,
			ProductID:   productID,
			Quantity:    quantity,
			Reason:      it.Reason,
		}
	}

	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.CreateReturnRequest{
		CompanyID:  companyID,
		OrderID:    &orderID,
		InvoiceID:  invoiceID,
		ReturnDate: returnDate,
		Reason:     req.Reason,
		Items:      items,
		CreatedBy:  userID, // not pointer
	}
	ret, err := h.returnService.CreateReturnRequest(ctx, &svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create return request", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	location := fmt.Sprintf("/returns/%s", ret.ReturnID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) CreateReturnFromOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req createReturnFromOrderRequest
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	returnDate := time.Now()
	if req.ReturnDate != "" {
		returnDate, err = time.Parse(time.RFC3339, req.ReturnDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid return_date")
			return
		}
	}
	items := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		var orderItemID *uuid.UUID
		if it.OrderItemID != nil && *it.OrderItemID != "" {
			parsed, err := uuid.Parse(*it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			orderItemID = &parsed
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateReturnItemRequest{
			OrderItemID: orderItemID,
			ProductID:   productID,
			Quantity:    quantity,
			Reason:      it.Reason,
		}
	}
	svcReq := service.CreateReturnFromOrderRequest{
		ReturnDate: returnDate,
		Reason:     req.Reason,
		Items:      items,
		CreatedBy:  userID,
	}
	ret, err := h.returnService.CreateReturnFromOrder(ctx, companyID, orderID, &svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create return from order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	location := fmt.Sprintf("/returns/%s", ret.ReturnID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) CreateReturnFromInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req createReturnFromInvoiceRequest
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	returnDate := time.Now()
	if req.ReturnDate != "" {
		returnDate, err = time.Parse(time.RFC3339, req.ReturnDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid return_date")
			return
		}
	}
	items := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		var orderItemID *uuid.UUID
		if it.OrderItemID != nil && *it.OrderItemID != "" {
			parsed, err := uuid.Parse(*it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			orderItemID = &parsed
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateReturnItemRequest{
			OrderItemID: orderItemID,
			ProductID:   productID,
			Quantity:    quantity,
			Reason:      it.Reason,
		}
	}
	svcReq := service.CreateReturnFromInvoiceRequest{
		ReturnDate: returnDate,
		Reason:     req.Reason,
		Items:      items,
		CreatedBy:  userID,
	}
	ret, err := h.returnService.CreateReturnFromInvoice(ctx, companyID, invoiceID, &svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create return from invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	location := fmt.Sprintf("/returns/%s", ret.ReturnID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) UpdateReturnRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req updateReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	svcReq := service.UpdateReturnRequest{
		ReturnDate: req.ReturnDate,
		Reason:     req.Reason,
		UpdatedBy:  userID,
	}
	ret, err := h.returnService.UpdateReturnRequest(ctx, companyID, returnID, &svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) DeleteReturnRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.DeleteReturnRequest(ctx, companyID, returnID, userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return deleted",
	})
}

func (h *ReturnHandler) GetReturnByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	ret, err := h.returnService.GetReturnByID(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to get return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) GetReturnByNumber(w http.ResponseWriter, r *http.Request) {
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
	returnNumber := r.URL.Query().Get("number")
	if returnNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	ret, err := h.returnService.GetReturnByNumber(ctx, companyID, returnNumber)
	if err != nil {
		h.logger.Error("failed to get return by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toReturnResponse(ret)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) ListReturns(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	filter := service.ReturnListFilter{CompanyID: companyID}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		filter.Statuses = []enums.ReturnStatus{enums.ReturnStatus(statusStr)}
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		// Not directly in filter – we handle via GetReturnsByCustomer instead
		// For now, ignore customer_id in list filter; use dedicated endpoint
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			filter.ReturnDateFrom = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			filter.ReturnDateTo = &t
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
		sort.Field = "created_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}
	returns, total, err := h.returnService.ListReturns(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	resp := listReturnsResponse{
		Returns: summaries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) SearchReturns(w http.ResponseWriter, r *http.Request) {
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
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
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
	returns, total, err := h.returnService.SearchReturns(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	resp := listReturnsResponse{
		Returns: summaries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) GetReturnsByCustomer(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
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
		sort.Field = "created_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}
	returns, total, err := h.returnService.GetReturnsByCustomer(ctx, companyID, customerID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get returns by customer", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	resp := listReturnsResponse{
		Returns: summaries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) GetReturnsByOrder(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	returns, err := h.returnService.GetReturnsByOrder(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get returns by order", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

func (h *ReturnHandler) GetReturnsByInvoice(w http.ResponseWriter, r *http.Request) {
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
	invoiceIDStr := r.URL.Query().Get("invoice_id")
	if invoiceIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "invoice_id query parameter is required")
		return
	}
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	returns, err := h.returnService.GetReturnsByInvoice(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to get returns by invoice", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

func (h *ReturnHandler) AddItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Items []createReturnItemRequest `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	items := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		var orderItemID *uuid.UUID
		if it.OrderItemID != nil && *it.OrderItemID != "" {
			parsed, err := uuid.Parse(*it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			orderItemID = &parsed
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateReturnItemRequest{
			OrderItemID: orderItemID,
			ProductID:   productID,
			Quantity:    quantity,
			Reason:      it.Reason,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.AddItems(ctx, companyID, returnID, items, userID)
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

func (h *ReturnHandler) ReplaceItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Items []createReturnItemRequest `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	items := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		var orderItemID *uuid.UUID
		if it.OrderItemID != nil && *it.OrderItemID != "" {
			parsed, err := uuid.Parse(*it.OrderItemID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid order_item_id")
				return
			}
			orderItemID = &parsed
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateReturnItemRequest{
			OrderItemID: orderItemID,
			ProductID:   productID,
			Quantity:    quantity,
			Reason:      it.Reason,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.ReplaceItems(ctx, companyID, returnID, items, userID)
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

func (h *ReturnHandler) RemoveItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
		return
	}
	itemID, err := parseUUIDParamReturn(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.RemoveItem(ctx, companyID, returnID, itemID, userID)
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

func (h *ReturnHandler) GetReturnItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	items, err := h.returnService.GetReturnItems(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to get return items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]returnItemResponse, len(items))
	for i, it := range items {
		resp[i] = h.toReturnItemResponse(it)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) ApproveReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.ApproveReturn(ctx, companyID, returnID, userID)
	if err != nil {
		h.logger.Error("failed to approve return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return approved",
	})
}

func (h *ReturnHandler) RejectReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.RejectReturn(ctx, companyID, returnID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to reject return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return rejected",
	})
}

func (h *ReturnHandler) CancelReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.CancelReturn(ctx, companyID, returnID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to cancel return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return cancelled",
	})
}

func (h *ReturnHandler) MarkReceived(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		ReceivedAt string `json:"received_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	receivedAt := time.Now()
	if req.ReceivedAt != "" {
		receivedAt, err = time.Parse(time.RFC3339, req.ReceivedAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid received_at")
			return
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.MarkReceived(ctx, companyID, returnID, receivedAt, userID)
	if err != nil {
		h.logger.Error("failed to mark return received", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return marked as received",
	})
}

func (h *ReturnHandler) CompleteReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.CompleteReturn(ctx, companyID, returnID, time.Now(), userID)
	if err != nil {
		h.logger.Error("failed to complete return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "return completed",
	})
}

func (h *ReturnHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status := enums.ReturnStatus(req.Status)
	if !status.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.UpdateStatus(ctx, companyID, returnID, status, userID)
	if err != nil {
		h.logger.Error("failed to update return status", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "status updated",
	})
}

func (h *ReturnHandler) CalculateRefundAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	subtotal, taxRefund, discountAdjustment, totalRefund, err := h.returnService.CalculateRefundAmount(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to calculate refund amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := refundAmountResponse{
		Subtotal:           subtotal.String(),
		TaxRefund:          taxRefund.String(),
		DiscountAdjustment: discountAdjustment.String(),
		TotalRefund:        totalRefund.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) CalculatePartialRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req partialRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	itemIDs := make([]uuid.UUID, len(req.ItemIDs))
	for i, idStr := range req.ItemIDs {
		uid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
			return
		}
		itemIDs[i] = uid
	}
	subtotal, taxRefund, discountAdjustment, totalRefund, err := h.returnService.CalculatePartialRefund(ctx, companyID, returnID, itemIDs)
	if err != nil {
		h.logger.Error("failed to calculate partial refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := refundAmountResponse{
		Subtotal:           subtotal.String(),
		TaxRefund:          taxRefund.String(),
		DiscountAdjustment: discountAdjustment.String(),
		TotalRefund:        totalRefund.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReturnHandler) PreviewRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req previewRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CompanyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var orderIDPtr *uuid.UUID
	if req.OrderID != nil && *req.OrderID != "" {
		oid, err := uuid.Parse(*req.OrderID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
			return
		}
		orderIDPtr = &oid
	}
	var invoiceIDPtr *uuid.UUID
	if req.InvoiceID != nil && *req.InvoiceID != "" {
		iid, err := uuid.Parse(*req.InvoiceID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
			return
		}
		invoiceIDPtr = &iid
	}
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Use *service.CreateReturnItemRequest instead of missing ReturnRefundPreviewItem
	previewItems := make([]*service.CreateReturnItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		previewItems[i] = &service.CreateReturnItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			Reason:    nil, // Reason not needed for preview
		}
	}
	svcReq := service.ReturnRefundPreviewRequest{
		CompanyID: companyID,
		OrderID:   orderIDPtr,
		InvoiceID: invoiceIDPtr,
		Items:     previewItems,
	}
	result, err := h.returnService.PreviewRefund(ctx, &svcReq)
	if err != nil {
		h.logger.Error("failed to preview refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *ReturnHandler) GenerateCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	// No body needed – service only requires IssuedBy
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	svcReq := service.GenerateCreditNoteRequest{
		IssuedBy: userID,
	}
	creditNote, err := h.returnService.GenerateCreditNote(ctx, companyID, returnID, &svcReq)
	if err != nil {
		h.logger.Error("failed to generate credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    creditNote,
	})
}

func (h *ReturnHandler) GetCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	creditNote, err := h.returnService.GetCreditNote(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to get credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    creditNote,
	})
}

func (h *ReturnHandler) HasCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	has, err := h.returnService.HasCreditNote(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to check credit note existence", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"has_credit_note": has},
	})
}

func (h *ReturnHandler) ProcessRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req processRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
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
	svcReq := service.ProcessReturnRefundRequest{
		CompanyID:  companyID,
		ReturnID:   returnID,
		Amount:     amount,
		Reason:     req.Reason,
		RefundedBy: userID,
	}
	refund, err := h.returnService.ProcessRefund(ctx, &svcReq)
	if err != nil {
		h.logger.Error("failed to process refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    refund,
	})
}

func (h *ReturnHandler) ProcessFullRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	refund, err := h.returnService.ProcessFullRefund(ctx, companyID, returnID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to process full refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    refund,
	})
}

func (h *ReturnHandler) ProcessPartialRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req struct {
		Amount string `json:"amount"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
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
	refund, err := h.returnService.ProcessPartialRefund(ctx, companyID, returnID, amount, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to process partial refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    refund,
	})
}

func (h *ReturnHandler) GetRefunds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	refunds, err := h.returnService.GetRefunds(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to get refunds", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    refunds,
	})
}

func (h *ReturnHandler) GetRefundedAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	amount, err := h.returnService.GetRefundedAmount(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to get refunded amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"refunded_amount": amount.String()},
	})
}

func (h *ReturnHandler) RestockReturnedItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req restockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.RestockReturnedItems(ctx, companyID, returnID, warehouseID, userID)
	if err != nil {
		h.logger.Error("failed to restock returned items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items restocked",
	})
}

func (h *ReturnHandler) MarkItemsAsDamaged(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req markDamagedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	itemIDs := make([]uuid.UUID, len(req.ItemIDs))
	for i, idStr := range req.ItemIDs {
		uid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
			return
		}
		itemIDs[i] = uid
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	err = h.returnService.MarkItemsAsDamaged(ctx, companyID, returnID, itemIDs, userID)
	if err != nil {
		h.logger.Error("failed to mark items as damaged", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items marked as damaged",
	})
}

func (h *ReturnHandler) GetPendingReturns(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	returns, err := h.returnService.GetPendingReturns(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get pending returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get pending returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

func (h *ReturnHandler) GetApprovedReturns(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	returns, err := h.returnService.GetApprovedReturns(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get approved returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get approved returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

func (h *ReturnHandler) GetRejectedReturns(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	returns, err := h.returnService.GetRejectedReturns(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get rejected returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get rejected returns")
		return
	}
	summaries := make([]returnSummary, len(returns))
	for i, r := range returns {
		summaries[i] = returnSummary{
			ReturnID:     r.ReturnID.String(),
			ReturnNumber: r.ReturnNumber,
			OrderID:      r.OrderID.String(),
			Status:       r.Status,
			ReturnDate:   r.ReturnDate.Format(time.RFC3339),
			TotalRefund:  r.TotalRefund.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

func (h *ReturnHandler) GetReturnRate(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
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
	rate, err := h.returnService.GetReturnRate(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get return rate", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get return rate")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"return_rate": rate.String()},
	})
}

func (h *ReturnHandler) GetTotalRefundAmount(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
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
	amount, err := h.returnService.GetTotalRefundAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total refund amount", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total refund amount")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_refund_amount": amount.String()},
	})
}

func (h *ReturnHandler) GetMostReturnedProducts(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
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
	products, err := h.returnService.GetMostReturnedProducts(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get most returned products", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get most returned products")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    products,
	})
}

func (h *ReturnHandler) ReturnExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	exists, err := h.returnService.ReturnExists(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to check return exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

func (h *ReturnHandler) ReturnNumberExists(w http.ResponseWriter, r *http.Request) {
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
	returnNumber := r.URL.Query().Get("number")
	if returnNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	exists, err := h.returnService.ReturnNumberExists(ctx, companyID, returnNumber)
	if err != nil {
		h.logger.Error("failed to check return number exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

func (h *ReturnHandler) IsReturnApproved(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	approved, err := h.returnService.IsReturnApproved(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to check return approved status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"is_approved": approved},
	})
}

func (h *ReturnHandler) IsReturnCompleted(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnID, err := parseUUIDParamReturn(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return ID")
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
	if !h.hasPermission(ctx, companyID, userID, "return:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	completed, err := h.returnService.IsReturnCompleted(ctx, companyID, returnID)
	if err != nil {
		h.logger.Error("failed to check return completed status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"is_completed": completed},
	})
}
