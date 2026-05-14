package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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

// allowedReferenceTypes defines valid values for reference_type field.
var allowedReferenceTypes = map[string]bool{
	"sales_order":    true,
	"fulfillment":    true,
	"purchase_order": true,
	"transfer":       true,
	"adjustment":     true,
}

// FulfillmentOrderHandler handles API endpoints for fulfillment orders and shipments.
type FulfillmentOrderHandler struct {
	fulfillmentSvc service.FulfillmentService
	warehouseRepo  repository.WarehouseRepository
	logger         *zap.Logger
}

// NewFulfillmentOrderHandler creates a new handler instance with required dependencies.
func NewFulfillmentOrderHandler(
	fulfillmentSvc service.FulfillmentService,
	warehouseRepo repository.WarehouseRepository,
	logger *zap.Logger,
) *FulfillmentOrderHandler {
	return &FulfillmentOrderHandler{
		fulfillmentSvc: fulfillmentSvc,
		warehouseRepo:  warehouseRepo,
		logger:         logger.Named("fulfillment_order_handler"),
	}
}

// ---------- Request/Response DTOs ----------

type createFulfillmentOrderRequest struct {
	ReferenceType string `json:"reference_type"`
	ReferenceID   string `json:"reference_id"`
	WarehouseID   string `json:"warehouse_id"`
	Status        string `json:"status,omitempty"` // pending, allocated, shipped, etc.
}

type fulfillmentOrderItemRequest struct {
	ItemID     string `json:"item_id"`
	OrderedQty string `json:"ordered_qty"` // decimal string
}

type addFulfillmentItemsRequest struct {
	Items []fulfillmentOrderItemRequest `json:"items"`
}

type fulfillmentOrderResponse struct {
	FulfillmentOrderID string    `json:"fulfillment_order_id"`
	CompanyID          string    `json:"company_id"`
	ReferenceType      string    `json:"reference_type"`
	ReferenceID        string    `json:"reference_id"`
	WarehouseID        string    `json:"warehouse_id"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
}

type fulfillmentOrderItemResponse struct {
	FulfillmentItemID  string `json:"fulfillment_item_id"`
	FulfillmentOrderID string `json:"fulfillment_order_id"`
	ItemID             string `json:"item_id"`
	OrderedQty         string `json:"ordered_qty"`
	FulfilledQty       string `json:"fulfilled_qty"`
	BackorderedQty     string `json:"backordered_qty"`
}

// ---------- Handlers ----------

// CreateFulfillmentOrder handles POST /companies/{companyID}/fulfillment-orders
// CreateFulfillmentOrder handles POST /companies/{companyID}/fulfillment-orders
func (h *FulfillmentOrderHandler) CreateFulfillmentOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createFulfillmentOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.ReferenceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "reference_type is required")
		return
	}
	// Validate reference_type against allowed values
	if !allowedReferenceTypes[req.ReferenceType] {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_type")
		return
	}
	referenceID, err := uuid.Parse(req.ReferenceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_id")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	// REMOVED the problematic warehouse existence check – service will handle it.

	svcReq := service.CreateFulfillmentOrderRequest{
		CompanyID:     companyID,
		ReferenceType: req.ReferenceType,
		ReferenceID:   referenceID,
		WarehouseID:   warehouseID,
		Status:        req.Status,
		CreatedBy:     &userID,
	}

	order, err := h.fulfillmentSvc.CreateFulfillmentOrder(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create fulfillment order", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    toFulfillmentOrderResponse(order),
		"message": "Fulfillment order created successfully",
	})
}

// AddFulfillmentItems handles POST /companies/{companyID}/fulfillment-orders/{fulfillmentOrderID}/items
func (h *FulfillmentOrderHandler) AddFulfillmentItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	fulfillmentOrderID, err := parseFulfillmentOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req addFulfillmentItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	// Detect duplicate item_id in the same request
	seen := make(map[string]bool)
	items := make([]service.FulfillmentOrderItemRequest, 0, len(req.Items))

	for _, it := range req.Items {
		if seen[it.ItemID] {
			h.respondWithError(w, http.StatusBadRequest, "duplicate item_id in request: "+it.ItemID)
			return
		}
		seen[it.ItemID] = true

		itemID, err := uuid.Parse(it.ItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id: "+it.ItemID)
			return
		}
		orderedQty, err := decimal.NewFromString(it.OrderedQty)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid ordered_qty: "+it.OrderedQty)
			return
		}
		if orderedQty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "ordered_qty must be positive for item "+it.ItemID)
			return
		}
		items = append(items, service.FulfillmentOrderItemRequest{
			ItemID:         itemID,
			OrderedQty:     orderedQty,
			FulfilledQty:   decimal.Zero,
			BackorderedQty: decimal.Zero,
		})
	}

	if err := h.fulfillmentSvc.AddFulfillmentItems(ctx, fulfillmentOrderID, items, idempotencyKey); err != nil {
		h.logger.Error("failed to add fulfillment items", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fulfillment items added successfully",
	})
}

// ProcessFulfillmentOrder handles POST /companies/{companyID}/fulfillment-orders/{fulfillmentOrderID}/process
func (h *FulfillmentOrderHandler) ProcessFulfillmentOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	fulfillmentOrderID, err := parseFulfillmentOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:process") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if err := h.fulfillmentSvc.ProcessFulfillmentOrder(ctx, fulfillmentOrderID, idempotencyKey); err != nil {
		h.logger.Error("failed to process fulfillment order", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fulfillment order processed successfully",
	})
}

// AllocateStockToFulfillment handles POST /companies/{companyID}/fulfillment-orders/{fulfillmentOrderID}/allocate
func (h *FulfillmentOrderHandler) AllocateStockToFulfillment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	fulfillmentOrderID, err := parseFulfillmentOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:allocate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if err := h.fulfillmentSvc.AllocateStockToFulfillment(ctx, fulfillmentOrderID, idempotencyKey); err != nil {
		h.logger.Error("failed to allocate stock for fulfillment", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stock allocated to fulfillment order successfully",
	})
}

// GetFulfillmentOrder handles GET /companies/{companyID}/fulfillment-orders/{fulfillmentOrderID}
func (h *FulfillmentOrderHandler) GetFulfillmentOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	fulfillmentOrderID, err := parseFulfillmentOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.fulfillmentSvc.GetFulfillmentOrder(ctx, fulfillmentOrderID)
	if err != nil {
		h.logger.Error("failed to get fulfillment order", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "fulfillment order not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve fulfillment order")
		return
	}

	// Verify order belongs to the company
	if order.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "fulfillment order does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toFulfillmentOrderResponse(order),
	})
}

// GetFulfillmentOrderItems handles GET /companies/{companyID}/fulfillment-orders/{fulfillmentOrderID}/items
func (h *FulfillmentOrderHandler) GetFulfillmentOrderItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	fulfillmentOrderID, err := parseFulfillmentOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "fulfillment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.fulfillmentSvc.GetFulfillmentOrderItems(ctx, fulfillmentOrderID)
	if err != nil {
		h.logger.Error("failed to get fulfillment order items", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "fulfillment order not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve items")
		return
	}

	respItems := make([]fulfillmentOrderItemResponse, len(items))
	for i, it := range items {
		respItems[i] = toFulfillmentOrderItemResponse(it)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    respItems,
	})
}

// ---------- Helper Functions ----------

func parseFulfillmentOrderIDFromRequest(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "fulfillmentOrderID")
	if idStr == "" {
		return uuid.Nil, errors.New("fulfillment order ID is required")
	}
	return uuid.Parse(idStr)
}

func toFulfillmentOrderResponse(order *models.FulfillmentOrder) fulfillmentOrderResponse {
	return fulfillmentOrderResponse{
		FulfillmentOrderID: order.FulfillmentOrderID.String(),
		CompanyID:          order.CompanyID.String(),
		ReferenceType:      order.ReferenceType,
		ReferenceID:        order.ReferenceID.String(),
		WarehouseID:        order.WarehouseID.String(),
		Status:             order.Status,
		CreatedAt:          order.CreatedAt,
	}
}

func toFulfillmentOrderItemResponse(item *models.FulfillmentOrderItem) fulfillmentOrderItemResponse {
	return fulfillmentOrderItemResponse{
		FulfillmentItemID:  item.FulfillmentItemID.String(),
		FulfillmentOrderID: item.FulfillmentOrderID.String(),
		ItemID:             item.ItemID.String(),
		OrderedQty:         item.OrderedQty.String(),
		FulfilledQty:       item.FulfilledQty.String(),
		BackorderedQty:     item.BackorderedQty.String(),
	}
}

// ---------- Standard Response Helpers ----------

func (h *FulfillmentOrderHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: implement real permission check (RBAC)
	return true
}

func (h *FulfillmentOrderHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *FulfillmentOrderHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *FulfillmentOrderHandler) respondWithInventoryError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, inventory_errors.ErrNotFound):
		h.respondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidInput):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, inventory_errors.ErrDuplicate):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory_errors.ErrPermissionDenied):
		h.respondWithError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, inventory_errors.ErrInsufficientStock):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidTransition):
		h.respondWithError(w, http.StatusConflict, err.Error())
	default:
		// Check for foreign key violation (item not found)
		var pqErr interface{ Code() string }
		if errors.As(err, &pqErr) && pqErr.Code() == "23503" {
			h.respondWithError(w, http.StatusNotFound, "referenced record not found (item or warehouse)")
			return
		}
		h.logger.Error("unexpected error", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}
