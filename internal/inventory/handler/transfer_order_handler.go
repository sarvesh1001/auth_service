package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

// TransferOrderHandler handles HTTP requests for stock transfer orders.
type TransferOrderHandler struct {
	transferService service.TransferOrderService
	logger          *zap.Logger
}

// NewTransferOrderHandler creates a new TransferOrderHandler.
func NewTransferOrderHandler(transferService service.TransferOrderService, logger *zap.Logger) *TransferOrderHandler {
	return &TransferOrderHandler{
		transferService: transferService,
		logger:          logger.Named("transfer_order_handler"),
	}
}

// --- Request/Response Types -------------------------------------------------

type createTransferOrderRequest struct {
	TransferNumber  string                     `json:"transfer_number"`
	FromWarehouseID string                     `json:"from_warehouse_id"`
	ToWarehouseID   string                     `json:"to_warehouse_id"`
	Items           []transferOrderItemRequest `json:"items"`
}

type transferOrderItemRequest struct {
	ItemID   string `json:"item_id"`
	Quantity string `json:"quantity"`
}

type transferOrderResponse struct {
	TransferOrderID string     `json:"transfer_order_id"`
	CompanyID       string     `json:"company_id"`
	TransferNumber  string     `json:"transfer_number"`
	FromWarehouseID string     `json:"from_warehouse_id"`
	ToWarehouseID   string     `json:"to_warehouse_id"`
	Status          string     `json:"status"`
	DispatchedAt    *time.Time `json:"dispatched_at,omitempty"`
	ReceivedAt      *time.Time `json:"received_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type transferOrderItemResponse struct {
	TransferItemID  string `json:"transfer_item_id"`
	TransferOrderID string `json:"transfer_order_id"`
	ItemID          string `json:"item_id"`
	Quantity        string `json:"quantity"`
}

type cancelTransferRequest struct {
	Reason string `json:"reason"`
}

// --- Helper Functions -------------------------------------------------------

func (h *TransferOrderHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *TransferOrderHandler) parseTransferOrderID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "transferOrderId")
	if idStr == "" {
		return uuid.Nil, errors.New("transfer order ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *TransferOrderHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: implement real permission check
	return true
}

func (h *TransferOrderHandler) toTransferOrderResponse(order *models.StockTransferOrder) transferOrderResponse {
	return transferOrderResponse{
		TransferOrderID: order.TransferOrderID.String(),
		CompanyID:       order.CompanyID.String(),
		TransferNumber:  order.TransferNumber,
		FromWarehouseID: order.FromWarehouseID.String(),
		ToWarehouseID:   order.ToWarehouseID.String(),
		Status:          order.Status,
		DispatchedAt:    order.DispatchedAt,
		ReceivedAt:      order.ReceivedAt,
		CreatedAt:       order.CreatedAt,
	}
}

func (h *TransferOrderHandler) toTransferOrderItemResponse(item *models.StockTransferItem) transferOrderItemResponse {
	return transferOrderItemResponse{
		TransferItemID:  item.TransferItemID.String(),
		TransferOrderID: item.TransferOrderID.String(),
		ItemID:          item.ItemID.String(),
		Quantity:        item.Quantity.String(),
	}
}

// --- Handlers ---------------------------------------------------------------

// CreateTransferOrder handles POST /companies/{companyID}/transfer-orders
func (h *TransferOrderHandler) CreateTransferOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createTransferOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.TransferNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "transfer_number is required")
		return
	}
	if req.FromWarehouseID == "" {
		h.respondWithError(w, http.StatusBadRequest, "from_warehouse_id is required")
		return
	}
	if req.ToWarehouseID == "" {
		h.respondWithError(w, http.StatusBadRequest, "to_warehouse_id is required")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one transfer item is required")
		return
	}

	fromWarehouseUUID, err := uuid.Parse(req.FromWarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from_warehouse_id")
		return
	}
	toWarehouseUUID, err := uuid.Parse(req.ToWarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to_warehouse_id")
		return
	}

	// Convert items
	items := make([]service.TransferOrderItemRequest, 0, len(req.Items))
	for _, it := range req.Items {
		if it.ItemID == "" {
			h.respondWithError(w, http.StatusBadRequest, "item_id is required for each item")
			return
		}
		itemUUID, err := uuid.Parse(it.ItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id: "+it.ItemID)
			return
		}
		qty, err := decimal.NewFromString(it.Quantity)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity for item "+it.ItemID)
			return
		}
		if qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "quantity must be positive for item "+it.ItemID)
			return
		}
		items = append(items, service.TransferOrderItemRequest{
			ItemID:   itemUUID,
			Quantity: qty,
		})
	}

	svcReq := service.CreateTransferOrderRequest{
		CompanyID:       companyID,
		TransferNumber:  req.TransferNumber,
		FromWarehouseID: fromWarehouseUUID,
		ToWarehouseID:   toWarehouseUUID,
		Items:           items,
		CreatedBy:       &userID,
	}

	order, err := h.transferService.CreateTransferOrder(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create transfer order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create transfer order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toTransferOrderResponse(order),
		"message": "Transfer order created successfully",
	})
}

// DispatchTransferOrder handles POST /companies/{companyID}/transfer-orders/{transferOrderId}/dispatch
func (h *TransferOrderHandler) DispatchTransferOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transferOrderID, err := h.parseTransferOrderID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:dispatch") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.transferService.DispatchTransferOrder(ctx, transferOrderID, companyID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to dispatch transfer order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to dispatch transfer order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transfer order dispatched successfully",
	})
}

// ReceiveTransferOrder handles POST /companies/{companyID}/transfer-orders/{transferOrderId}/receive
func (h *TransferOrderHandler) ReceiveTransferOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transferOrderID, err := h.parseTransferOrderID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:receive") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.transferService.ReceiveTransferOrder(ctx, transferOrderID, companyID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to receive transfer order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, "transfer order is not in dispatched state")
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to receive transfer order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transfer order received successfully",
	})
}

// CancelTransferOrder handles POST /companies/{companyID}/transfer-orders/{transferOrderId}/cancel
func (h *TransferOrderHandler) CancelTransferOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transferOrderID, err := h.parseTransferOrderID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req cancelTransferRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // reason is optional

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.transferService.CancelTransferOrder(ctx, transferOrderID, companyID, &userID, req.Reason, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to cancel transfer order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to cancel transfer order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transfer order cancelled successfully",
	})
}

// GetTransferOrder handles GET /companies/{companyID}/transfer-orders/{transferOrderId}
func (h *TransferOrderHandler) GetTransferOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transferOrderID, err := h.parseTransferOrderID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.transferService.GetTransferOrder(ctx, transferOrderID, companyID)
	if err != nil {
		h.logger.Error("failed to get transfer order", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transfer order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toTransferOrderResponse(order),
	})
}

// GetTransferOrderItems handles GET /companies/{companyID}/transfer-orders/{transferOrderId}/items
func (h *TransferOrderHandler) GetTransferOrderItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transferOrderID, err := h.parseTransferOrderID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.transferService.GetTransferOrderItems(ctx, transferOrderID, companyID)
	if err != nil {
		h.logger.Error("failed to get transfer order items", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transfer order items")
		}
		return
	}

	respItems := make([]transferOrderItemResponse, 0, len(items))
	for _, it := range items {
		respItems = append(respItems, h.toTransferOrderItemResponse(it))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    respItems,
	})
}

// ListTransferOrders handles GET /companies/{companyID}/transfer-orders
func (h *TransferOrderHandler) ListTransferOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "transfer_order:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.TransferOrderFilter{
		CompanyID: companyID,
	}

	if fromWHStr := query.Get("from_warehouse_id"); fromWHStr != "" {
		id, err := uuid.Parse(fromWHStr)
		if err == nil {
			filter.FromWarehouseID = &id
		}
	}
	if toWHStr := query.Get("to_warehouse_id"); toWHStr != "" {
		id, err := uuid.Parse(toWHStr)
		if err == nil {
			filter.ToWarehouseID = &id
		}
	}
	if status := query.Get("status"); status != "" {
		filter.Status = &status
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.DateFrom = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.DateTo = &t
		}
	}
	if search := query.Get("search"); search != "" {
		filter.Search = search
	}

	page := 1
	if pageStr := query.Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	pageSize := 20
	if pageSizeStr := query.Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	orders, total, err := h.transferService.ListTransferOrders(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list transfer orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list transfer orders")
		return
	}

	respOrders := make([]transferOrderResponse, 0, len(orders))
	for _, o := range orders {
		respOrders = append(respOrders, h.toTransferOrderResponse(o))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      respOrders,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// --- Response Helpers -------------------------------------------------------

func (h *TransferOrderHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TransferOrderHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
