package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

// OrderHandler handles HTTP requests for order management.
type OrderHandler struct {
	orderService service.OrderService
	*BaseHandler
}

// NewOrderHandler creates a new OrderHandler.
func NewOrderHandler(orderService service.OrderService, logger *zap.Logger) *OrderHandler {
	return &OrderHandler{
		orderService: orderService,
		BaseHandler:  &BaseHandler{logger: logger.Named("order_handler")},
	}
}

// ---------- Request/Response Types (CompanyID removed where present) ----------

type createOrderRequest struct {
	CustomerID      string                   `json:"customer_id"`
	OrderNumber     *string                  `json:"order_number,omitempty"`
	ExternalRef     *string                  `json:"external_ref,omitempty"`
	OrderDate       *string                  `json:"order_date,omitempty"`
	Currency        *string                  `json:"currency,omitempty"`
	Notes           *string                  `json:"notes,omitempty"`
	ShippingAddress map[string]interface{}   `json:"shipping_address,omitempty"`
	BillingAddress  map[string]interface{}   `json:"billing_address,omitempty"`
	SalesRepID      *string                  `json:"sales_rep_id,omitempty"`
	Items           []createOrderItemRequest `json:"items"`
}

type createOrderItemRequest struct {
	ProductID string                 `json:"product_id"`
	Quantity  string                 `json:"quantity"`
	UnitPrice *string                `json:"unit_price,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type createOrderResponse struct {
	OrderID         string      `json:"order_id"`
	CompanyID       string      `json:"company_id"`
	CustomerID      string      `json:"customer_id"`
	OrderNumber     string      `json:"order_number"`
	ExternalRef     *string     `json:"external_ref,omitempty"`
	OrderDate       string      `json:"order_date"`
	Status          string      `json:"status"`
	Currency        string      `json:"currency"`
	Subtotal        string      `json:"subtotal"`
	DiscountTotal   string      `json:"discount_total"`
	TaxTotal        string      `json:"tax_total"`
	GrandTotal      string      `json:"grand_total"`
	Notes           *string     `json:"notes,omitempty"`
	ShippingAddress interface{} `json:"shipping_address,omitempty"`
	BillingAddress  interface{} `json:"billing_address,omitempty"`
	SalesRepID      *string     `json:"sales_rep_id,omitempty"`
	CreditHold      bool        `json:"credit_hold"`
	CreditStatus    string      `json:"credit_status"`
	CreatedAt       string      `json:"created_at"`
	UpdatedAt       string      `json:"updated_at"`
}

type updateOrderRequest struct {
	OrderDate       *string                `json:"order_date,omitempty"`
	Currency        *string                `json:"currency,omitempty"`
	Notes           *string                `json:"notes,omitempty"`
	ShippingAddress map[string]interface{} `json:"shipping_address,omitempty"`
	BillingAddress  map[string]interface{} `json:"billing_address,omitempty"`
}

type updateOrderStatusRequest struct {
	Status string `json:"status"`
}

type markShippedRequest struct {
	ShippedAt string `json:"shipped_at"`
}

type markDeliveredRequest struct {
	DeliveredAt string `json:"delivered_at"`
}

type cancelOrderRequest struct {
	Reason string `json:"reason"`
}

type orderAssignSalesRepRequest struct {
	SalesRepID string `json:"sales_rep_id"`
}

type orderApplyCouponRequest struct {
	CouponCode string `json:"coupon_code"`
}

type addItemsRequest struct {
	Items []createOrderItemRequest `json:"items"`
}

type replaceItemsRequest struct {
	Items []createOrderItemRequest `json:"items"`
}

type previewPricingRequest struct {
	CustomerID string               `json:"customer_id"` // company_id removed
	Items      []previewPricingItem `json:"items"`
}

type previewPricingItem struct {
	ProductID string `json:"product_id"`
	Quantity  string `json:"quantity"`
}

type previewPricingResponse struct {
	Subtotal         string `json:"subtotal"`
	DiscountTotal    string `json:"discount_total"`
	TaxTotal         string `json:"tax_total"`
	GrandTotal       string `json:"grand_total"`
	AppliedDiscounts []struct {
		Name   string `json:"name"`
		Amount string `json:"amount"`
	} `json:"applied_discounts,omitempty"`
}

type listOrdersResponse struct {
	Orders []orderSummary `json:"orders"`
	Total  int64          `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type orderSummary struct {
	OrderID     string `json:"order_id"`
	OrderNumber string `json:"order_number"`
	CustomerID  string `json:"customer_id"`
	OrderDate   string `json:"order_date"`
	Status      string `json:"status"`
	GrandTotal  string `json:"grand_total"`
}

type orderTotalsResponse struct {
	Subtotal      string `json:"subtotal"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
	GrandTotal    string `json:"grand_total"`
}

type orderItemResponse struct {
	OrderItemID         string                 `json:"order_item_id"`
	ProductID           string                 `json:"product_id"`
	ProductNameSnapshot string                 `json:"product_name_snapshot"`
	Quantity            string                 `json:"quantity"`
	UnitPrice           string                 `json:"unit_price"`
	DiscountAmount      *string                `json:"discount_amount,omitempty"`
	TaxAmount           *string                `json:"tax_amount,omitempty"`
	TotalPrice          string                 `json:"total_price"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// ---------- Handler Methods ----------

// CreateDraftOrder handles POST /orders
func (h *OrderHandler) CreateDraftOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Get company from header
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	var orderDate time.Time
	if req.OrderDate != nil && *req.OrderDate != "" {
		orderDate, err = time.Parse(time.RFC3339, *req.OrderDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid order_date format, use RFC3339")
			return
		}
	} else {
		orderDate = time.Now()
	}

	orderNumber := ""
	if req.OrderNumber != nil {
		orderNumber = *req.OrderNumber
	}
	currency := "USD"
	if req.Currency != nil && *req.Currency != "" {
		currency = *req.Currency
	}

	var salesRepID *uuid.UUID
	if req.SalesRepID != nil && *req.SalesRepID != "" {
		parsed, err := uuid.Parse(*req.SalesRepID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
			return
		}
		salesRepID = &parsed
	}

	var shippingAddress models.JSONB
	if len(req.ShippingAddress) > 0 {
		shippingAddress = models.JSONB(req.ShippingAddress)
	}
	var billingAddress models.JSONB
	if len(req.BillingAddress) > 0 {
		billingAddress = models.JSONB(req.BillingAddress)
	}

	items := make([]*service.CreateOrderItemRequest, len(req.Items))
	for i, it := range req.Items {
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid product_id in item %d", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid quantity in item %d", i))
			return
		}
		var unitPrice *decimal.Decimal
		if it.UnitPrice != nil && *it.UnitPrice != "" {
			up, err := decimal.NewFromString(*it.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid unit_price in item %d", i))
				return
			}
			if up.LessThan(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("unit_price cannot be negative in item %d", i))
				return
			}
			unitPrice = &up
		}
		items[i] = &service.CreateOrderItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			Metadata:  it.Metadata,
		}
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.CreateOrderRequest{
		CustomerID:      customerID,
		OrderNumber:     orderNumber,
		ExternalRef:     req.ExternalRef,
		OrderDate:       orderDate,
		Currency:        currency,
		Notes:           req.Notes,
		ShippingAddress: shippingAddress,
		BillingAddress:  billingAddress,
		SalesRepID:      salesRepID,
		Items:           items,
	}

	order, err := h.orderService.CreateDraftOrder(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create draft order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertOrderToResponse(order)
	location := fmt.Sprintf("/orders/%s", order.OrderID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateOrder handles PUT /orders/{id}
func (h *OrderHandler) UpdateOrder(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var orderDate *time.Time
	if req.OrderDate != nil && *req.OrderDate != "" {
		od, err := time.Parse(time.RFC3339, *req.OrderDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid order_date format")
			return
		}
		orderDate = &od
	}

	var shippingAddress *models.JSONB
	if len(req.ShippingAddress) > 0 {
		ja := models.JSONB(req.ShippingAddress)
		shippingAddress = &ja
	}
	var billingAddress *models.JSONB
	if len(req.BillingAddress) > 0 {
		ja := models.JSONB(req.BillingAddress)
		billingAddress = &ja
	}

	svcReq := &service.UpdateOrderRequest{
		OrderDate:       orderDate,
		Currency:        req.Currency,
		Notes:           req.Notes,
		ShippingAddress: shippingAddress,
		BillingAddress:  billingAddress,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	updated, err := h.orderService.UpdateOrder(ctx, companyID, orderID, svcReq)
	if err != nil {
		h.logger.Error("failed to update order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertOrderToResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteOrder handles DELETE /orders/{id}
func (h *OrderHandler) DeleteOrder(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.DeleteOrder(ctx, companyID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to delete order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order deleted successfully",
	})
}

// GetOrderByID handles GET /orders/{id}
func (h *OrderHandler) GetOrderByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.orderService.GetOrderByID(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertOrderToResponse(order)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetOrderByNumber handles GET /orders/by-number
func (h *OrderHandler) GetOrderByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	orderNumber := r.URL.Query().Get("number")
	if orderNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "order number is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.orderService.GetOrderByNumber(ctx, companyID, orderNumber)
	if err != nil {
		h.logger.Error("failed to get order by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := convertOrderToResponse(order)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListOrders handles GET /orders
func (h *OrderHandler) ListOrders(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.OrderListFilter{
		CompanyID: companyID,
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		customerID, err := uuid.Parse(customerIDStr)
		if err == nil {
			filter.CustomerID = &customerID
		}
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		status := enums.OrderStatus(statusStr)
		if status.IsValid() {
			filter.Status = &status
		}
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

	orders, total, err := h.orderService.ListOrders(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	resp := listOrdersResponse{
		Orders: summaries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchOrders handles GET /orders/search
func (h *OrderHandler) SearchOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "search query (q) is required")
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, total, err := h.orderService.SearchOrders(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	resp := listOrdersResponse{
		Orders: summaries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetOrdersByCustomer handles GET /orders?customer_id=...
func (h *OrderHandler) GetOrdersByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	customerIDStr := r.URL.Query().Get("customer_id")
	if customerIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id is required")
		return
	}
	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
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

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, total, err := h.orderService.GetOrdersByCustomer(ctx, companyID, customerID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get orders by customer", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	resp := listOrdersResponse{
		Orders: summaries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// AddItems handles POST /orders/{id}/items
func (h *OrderHandler) AddItems(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req addItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	items := make([]*service.CreateOrderItemRequest, len(req.Items))
	for i, it := range req.Items {
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid product_id in item %d", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid quantity in item %d", i))
			return
		}
		var unitPrice *decimal.Decimal
		if it.UnitPrice != nil && *it.UnitPrice != "" {
			up, err := decimal.NewFromString(*it.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid unit_price in item %d", i))
				return
			}
			if up.LessThan(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("unit_price cannot be negative in item %d", i))
				return
			}
			unitPrice = &up
		}
		items[i] = &service.CreateOrderItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			Metadata:  it.Metadata,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.AddItems(ctx, companyID, orderID, items, userID)
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

// ReplaceItems handles PUT /orders/{id}/items
func (h *OrderHandler) ReplaceItems(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req replaceItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	items := make([]*service.CreateOrderItemRequest, len(req.Items))
	for i, it := range req.Items {
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid product_id in item %d", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid quantity in item %d", i))
			return
		}
		var unitPrice *decimal.Decimal
		if it.UnitPrice != nil && *it.UnitPrice != "" {
			up, err := decimal.NewFromString(*it.UnitPrice)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid unit_price in item %d", i))
				return
			}
			if up.LessThan(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("unit_price cannot be negative in item %d", i))
				return
			}
			unitPrice = &up
		}
		items[i] = &service.CreateOrderItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			Metadata:  it.Metadata,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.ReplaceItems(ctx, companyID, orderID, items, userID)
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

// RemoveItem handles DELETE /orders/{id}/items/{itemId}
func (h *OrderHandler) RemoveItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
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

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.RemoveItem(ctx, companyID, orderID, itemID, userID)
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

// GetOrderItems handles GET /orders/{id}/items
func (h *OrderHandler) GetOrderItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.orderService.GetOrderItems(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get order items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]orderItemResponse, len(items))
	for i, it := range items {
		itemResp := orderItemResponse{
			OrderItemID:         it.OrderItemID.String(),
			ProductID:           it.ProductID.String(),
			ProductNameSnapshot: it.ProductNameSnapshot,
			Quantity:            it.Quantity.String(),
			UnitPrice:           it.UnitPrice.String(),
			TotalPrice:          it.TotalPrice.String(),
			Metadata:            it.Metadata,
		}
		if it.DiscountAmount != nil {
			da := it.DiscountAmount.String()
			itemResp.DiscountAmount = &da
		}
		if it.TaxAmount != nil {
			ta := it.TaxAmount.String()
			itemResp.TaxAmount = &ta
		}
		resp[i] = itemResp
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ApplyCoupon handles POST /orders/{id}/coupons
func (h *OrderHandler) ApplyCoupon(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req orderApplyCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CouponCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_code is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	coupon, discount, err := h.orderService.ApplyCoupon(ctx, companyID, orderID, req.CouponCode, userID)
	if err != nil {
		h.logger.Error("failed to apply coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"coupon": map[string]interface{}{
				"code":   coupon.Code,
				"amount": discount.String(),
			},
		},
	})
}

// RemoveCoupon handles DELETE /orders/{id}/coupons/{code}
func (h *OrderHandler) RemoveCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
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

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.RemoveCoupon(ctx, companyID, orderID, couponCode, userID)
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

// ApplyBestDiscounts handles POST /orders/{id}/best-discounts
func (h *OrderHandler) ApplyBestDiscounts(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.ApplyBestDiscounts(ctx, companyID, orderID, userID)
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

// PreviewPricing handles POST /orders/preview-pricing
func (h *OrderHandler) PreviewPricing(w http.ResponseWriter, r *http.Request) {
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

	var req previewPricingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build preview items
	type previewItem struct {
		ProductID uuid.UUID       `json:"product_id"`
		Quantity  decimal.Decimal `json:"quantity"`
	}
	items := make([]previewItem, len(req.Items))
	for i, it := range req.Items {
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid product_id in item %d", i))
			return
		}
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid quantity in item %d", i))
			return
		}
		items[i] = previewItem{
			ProductID: productID,
			Quantity:  quantity,
		}
	}

	previewReqJSON, _ := json.Marshal(map[string]interface{}{
		"company_id":  companyID,
		"customer_id": customerID,
		"items":       items,
	})
	var previewReq service.OrderPricingPreviewRequest
	if err := json.Unmarshal(previewReqJSON, &previewReq); err != nil {
		h.logger.Error("failed to create preview request", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to prepare request")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	result, err := h.orderService.PreviewPricing(ctx, &previewReq)
	if err != nil {
		h.logger.Error("failed to preview pricing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := previewPricingResponse{
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

// RecalculateTotals handles POST /orders/{id}/recalculate
func (h *OrderHandler) RecalculateTotals(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.RecalculateTotals(ctx, companyID, orderID, userID)
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

// GetOrderTotals handles GET /orders/{id}/totals
func (h *OrderHandler) GetOrderTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	subtotal, discountTotal, taxTotal, grandTotal, err := h.orderService.GetOrderTotals(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to get order totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := orderTotalsResponse{
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

// UpdateStatus handles PATCH /orders/{id}/status
func (h *OrderHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateOrderStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}
	newStatus := enums.OrderStatus(req.Status)
	if !newStatus.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.UpdateStatus(ctx, companyID, orderID, newStatus, userID)
	if err != nil {
		h.logger.Error("failed to update order status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("order status updated to %s", req.Status),
	})
}

// ConfirmOrder handles POST /orders/{id}/confirm
func (h *OrderHandler) ConfirmOrder(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.ConfirmOrder(ctx, companyID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to confirm order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order confirmed",
	})
}

// MarkProcessing handles POST /orders/{id}/processing
func (h *OrderHandler) MarkProcessing(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.MarkProcessing(ctx, companyID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to mark order as processing", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order marked as processing",
	})
}

// MarkShipped handles POST /orders/{id}/shipped
func (h *OrderHandler) MarkShipped(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req markShippedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	shippedAt := time.Now()
	if req.ShippedAt != "" {
		shippedAt, err = time.Parse(time.RFC3339, req.ShippedAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid shipped_at format")
			return
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.MarkShipped(ctx, companyID, orderID, shippedAt, userID)
	if err != nil {
		h.logger.Error("failed to mark order as shipped", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order marked as shipped",
	})
}

// MarkDelivered handles POST /orders/{id}/delivered
func (h *OrderHandler) MarkDelivered(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req markDeliveredRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	deliveredAt := time.Now()
	if req.DeliveredAt != "" {
		deliveredAt, err = time.Parse(time.RFC3339, req.DeliveredAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid delivered_at format")
			return
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.MarkDelivered(ctx, companyID, orderID, deliveredAt, userID)
	if err != nil {
		h.logger.Error("failed to mark order as delivered", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order marked as delivered",
	})
}

// CancelOrder handles POST /orders/{id}/cancel
func (h *OrderHandler) CancelOrder(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req cancelOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.CancelOrder(ctx, companyID, orderID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to cancel order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order cancelled",
	})
}

// AssignSalesRep handles POST /orders/{id}/assign-sales-rep
func (h *OrderHandler) AssignSalesRep(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req orderAssignSalesRepRequest
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

	err = h.orderService.AssignSalesRep(ctx, companyID, orderID, salesRepID, userID)
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

// RemoveSalesRep handles DELETE /orders/{id}/assign-sales-rep
func (h *OrderHandler) RemoveSalesRep(w http.ResponseWriter, r *http.Request) {
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

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "order:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.orderService.RemoveSalesRep(ctx, companyID, orderID, userID)
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

// GetPendingOrders handles GET /orders/pending
func (h *OrderHandler) GetPendingOrders(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, err := h.orderService.GetPendingOrders(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get pending orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get pending orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetOrdersReadyForInvoicing handles GET /orders/ready-for-invoicing
func (h *OrderHandler) GetOrdersReadyForInvoicing(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, err := h.orderService.GetOrdersReadyForInvoicing(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get orders ready for invoicing", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetOrderRevenue handles GET /orders/revenue
func (h *OrderHandler) GetOrderRevenue(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
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

	revenue, err := h.orderService.GetOrderRevenue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get order revenue", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get revenue")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"revenue": revenue.String(),
		},
	})
}

// GetAverageOrderValue handles GET /orders/average-value
func (h *OrderHandler) GetAverageOrderValue(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
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

	avg, err := h.orderService.GetAverageOrderValue(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get average order value", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get average")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"average_order_value": avg.String(),
		},
	})
}

// GetTopOrdersByValue handles GET /orders/top
func (h *OrderHandler) GetTopOrdersByValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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

	if !h.hasPermission(ctx, companyID, userID, "order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	orders, err := h.orderService.GetTopOrdersByValue(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get top orders")
		return
	}

	summaries := make([]orderSummary, len(orders))
	for i, o := range orders {
		summaries[i] = orderSummary{
			OrderID:     o.OrderID.String(),
			OrderNumber: o.OrderNumber,
			CustomerID:  o.CustomerID.String(),
			OrderDate:   o.OrderDate.Format(time.RFC3339),
			Status:      string(o.Status),
			GrandTotal:  o.GrandTotal.String(),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// OrderExists handles GET /orders/{id}/exists
func (h *OrderHandler) OrderExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.orderService.OrderExists(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check order existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// HasInvoices handles GET /orders/{id}/has-invoices
func (h *OrderHandler) HasInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	has, err := h.orderService.HasInvoices(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"has_invoices": has},
	})
}

// HasReturns handles GET /orders/{id}/has-returns
func (h *OrderHandler) HasReturns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	has, err := h.orderService.HasReturns(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to check returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"has_returns": has},
	})
}

// ---------- Helper to convert model to response ----------

func convertOrderToResponse(order *models.Order) createOrderResponse {
	resp := createOrderResponse{
		OrderID:       order.OrderID.String(),
		CompanyID:     order.CompanyID.String(),
		CustomerID:    order.CustomerID.String(),
		OrderNumber:   order.OrderNumber,
		ExternalRef:   order.ExternalRef,
		OrderDate:     order.OrderDate.Format(time.RFC3339),
		Status:        string(order.Status),
		Currency:      order.Currency,
		Subtotal:      order.Subtotal.String(),
		DiscountTotal: order.DiscountTotal.String(),
		TaxTotal:      order.TaxTotal.String(),
		GrandTotal:    order.GrandTotal.String(),
		Notes:         order.Notes,
		CreditHold:    order.CreditHold,
		CreditStatus:  string(order.CreditStatus),
		CreatedAt:     order.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     order.UpdatedAt.Format(time.RFC3339),
	}
	if order.SalesRepID != nil {
		idStr := order.SalesRepID.String()
		resp.SalesRepID = &idStr
	}
	if order.ShippingAddress != nil {
		resp.ShippingAddress = order.ShippingAddress
	}
	if order.BillingAddress != nil {
		resp.BillingAddress = order.BillingAddress
	}
	return resp
}
