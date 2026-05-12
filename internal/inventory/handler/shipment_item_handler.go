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

type ShipmentItemHandler struct {
	shipmentItemSvc service.ShipmentItemService
	logger          *zap.Logger
}

func NewShipmentItemHandler(shipmentItemSvc service.ShipmentItemService, logger *zap.Logger) *ShipmentItemHandler {
	return &ShipmentItemHandler{
		shipmentItemSvc: shipmentItemSvc,
		logger:          logger.Named("shipment_item_handler"),
	}
}

// ========== Request/Response Types ==========

type createShipmentItemsRequest struct {
	Items []shipmentItemEntry `json:"items"`
}

type shipmentItemEntry struct {
	FulfillmentItemID string `json:"fulfillment_item_id"`
	QuantityShipped   string `json:"quantity_shipped"`
}

type updateShippedQuantityRequest struct {
	QuantityShipped string `json:"quantity_shipped"`
}

type shipmentItemResponse struct {
	ShipmentItemID    string `json:"shipment_item_id"`
	ShipmentID        string `json:"shipment_id"`
	FulfillmentItemID string `json:"fulfillment_item_id"`
	QuantityShipped   string `json:"quantity_shipped"`
	CreatedAt         string `json:"created_at"`
}

// ========== Helper Functions ==========

func (h *ShipmentItemHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *ShipmentItemHandler) parseShipmentID(r *http.Request) (uuid.UUID, error) {
	shipmentIDStr := chi.URLParam(r, "shipmentID")
	if shipmentIDStr == "" {
		return uuid.Nil, errors.New("shipment ID is required")
	}
	return uuid.Parse(shipmentIDStr)
}

func (h *ShipmentItemHandler) parseShipmentItemID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "shipmentItemID")
	if idStr == "" {
		return uuid.Nil, errors.New("shipment item ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *ShipmentItemHandler) parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20

	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}
	return page, pageSize
}

func (h *ShipmentItemHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with actual permission check from your auth system
	return true
}

func (h *ShipmentItemHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ShipmentItemHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *ShipmentItemHandler) toShipmentItemResponse(si *models.ShipmentItem) shipmentItemResponse {
	return shipmentItemResponse{
		ShipmentItemID:    si.ShipmentItemID.String(),
		ShipmentID:        si.ShipmentID.String(),
		FulfillmentItemID: si.FulfillmentItemID.String(),
		QuantityShipped:   si.QuantityShipped.String(),
		CreatedAt:         si.CreatedAt.Format(time.RFC3339),
	}
}

// ========== Handlers ==========

// CreateShipmentItems creates shipment items for a given shipment.
// POST /api/v1/companies/{companyID}/inventory/shipments/{shipmentID}/items
func (h *ShipmentItemHandler) CreateShipmentItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	shipmentID, err := h.parseShipmentID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createShipmentItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	entries := make([]service.ShipmentItemEntry, 0, len(req.Items))
	for i, it := range req.Items {
		if it.FulfillmentItemID == "" {
			h.respondWithError(w, http.StatusBadRequest, "fulfillment_item_id is required for item "+strconv.Itoa(i))
			return
		}
		fulfillmentItemID, err := uuid.Parse(it.FulfillmentItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid fulfillment_item_id: "+it.FulfillmentItemID)
			return
		}
		qty, err := decimal.NewFromString(it.QuantityShipped)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity_shipped: "+it.QuantityShipped)
			return
		}
		if qty.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "quantity_shipped must be positive for item "+it.FulfillmentItemID)
			return
		}
		entries = append(entries, service.ShipmentItemEntry{
			FulfillmentItemID: fulfillmentItemID,
			QuantityShipped:   qty,
		})
	}

	svcReq := service.CreateShipmentItemsRequest{
		CompanyID:  companyID,
		ShipmentID: shipmentID,
		Items:      entries,
		CreatedBy:  &userID,
	}

	items, err := h.shipmentItemSvc.CreateShipmentItems(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create shipment items", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create shipment items")
		}
		return
	}

	responses := make([]shipmentItemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toShipmentItemResponse(it)
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    responses,
		"message": "Shipment items created successfully",
	})
}

// GetShipmentItems returns all items for a shipment.
// GET /api/v1/companies/{companyID}/inventory/shipments/{shipmentID}/items
func (h *ShipmentItemHandler) GetShipmentItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	shipmentID, err := h.parseShipmentID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.shipmentItemSvc.GetByShipmentID(ctx, shipmentID)
	if err != nil {
		h.logger.Error("failed to get shipment items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve shipment items")
		return
	}

	responses := make([]shipmentItemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toShipmentItemResponse(it)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetShipmentItemByID returns a single shipment item.
// GET /api/v1/companies/{companyID}/inventory/shipment-items/{shipmentItemID}
func (h *ShipmentItemHandler) GetShipmentItemByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	shipmentItemID, err := h.parseShipmentItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	item, err := h.shipmentItemSvc.GetShipmentItemByID(ctx, shipmentItemID)
	if err != nil {
		h.logger.Error("failed to get shipment item", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "shipment item not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve shipment item")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toShipmentItemResponse(item),
	})
}

// UpdateShippedQuantity updates the shipped quantity of a shipment item.
// PUT /api/v1/companies/{companyID}/inventory/shipment-items/{shipmentItemID}
func (h *ShipmentItemHandler) UpdateShippedQuantity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	shipmentItemID, err := h.parseShipmentItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req updateShippedQuantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	qty, err := decimal.NewFromString(req.QuantityShipped)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quantity_shipped")
		return
	}
	if qty.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "quantity_shipped must be positive")
		return
	}

	svcReq := service.UpdateShippedQuantityRequest{
		ShipmentItemID:  shipmentItemID,
		CompanyID:       companyID,
		QuantityShipped: qty,
		UpdatedBy:       &userID,
	}

	item, err := h.shipmentItemSvc.UpdateShippedQuantity(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update shipped quantity", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to update shipment item")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toShipmentItemResponse(item),
		"message": "Shipped quantity updated successfully",
	})
}

// DeleteShipmentItem soft-deletes a shipment item (only if shipment is draft).
// DELETE /api/v1/companies/{companyID}/inventory/shipment-items/{shipmentItemID}
func (h *ShipmentItemHandler) DeleteShipmentItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	shipmentItemID, err := h.parseShipmentItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if err := h.shipmentItemSvc.DeleteShipmentItem(ctx, shipmentItemID, companyID, idempotencyKey); err != nil {
		h.logger.Error("failed to delete shipment item", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to delete shipment item")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Shipment item deleted successfully",
	})
}

// ListShipmentItems lists shipment items with pagination and filters.
// GET /api/v1/companies/{companyID}/inventory/shipment-items?shipment_id=...&fulfillment_item_id=...&page=1&page_size=20
func (h *ShipmentItemHandler) ListShipmentItems(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "shipment_item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.ShipmentItemFilter{
		CompanyID: &companyID,
	}
	if shipmentIDStr := query.Get("shipment_id"); shipmentIDStr != "" {
		if shipmentID, err := uuid.Parse(shipmentIDStr); err == nil {
			filter.ShipmentID = &shipmentID
		}
	}
	if fulfillmentItemIDStr := query.Get("fulfillment_item_id"); fulfillmentItemIDStr != "" {
		if fid, err := uuid.Parse(fulfillmentItemIDStr); err == nil {
			filter.FulfillmentItemID = &fid
		}
	}
	if minQtyStr := query.Get("min_quantity_shipped"); minQtyStr != "" {
		if qty, err := decimal.NewFromString(minQtyStr); err == nil {
			filter.MinQuantityShipped = &qty
		}
	}

	page, pageSize := h.parsePagination(r)
	items, total, err := h.shipmentItemSvc.ListShipmentItems(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list shipment items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list shipment items")
		return
	}

	responses := make([]shipmentItemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toShipmentItemResponse(it)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      responses,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}
