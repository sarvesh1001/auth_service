package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type CreateItemRequest struct {
	SKU                string                  `json:"sku"`
	Name               string                  `json:"name"`
	Description        *string                 `json:"description,omitempty"`
	ItemType           enums.ItemType          `json:"item_type"`
	UnitOfMeasure      string                  `json:"unit_of_measure"`
	ValuationMethod    enums.ValuationMethod   `json:"valuation_method"`
	StandardCost       *decimal.Decimal        `json:"standard_cost,omitempty"`
	SellingPrice       *decimal.Decimal        `json:"selling_price,omitempty"`
	ReorderLevel       *decimal.Decimal        `json:"reorder_level,omitempty"`
	ReorderQuantity    *decimal.Decimal        `json:"reorder_quantity,omitempty"`
	IsActive           bool                    `json:"is_active"`
	TrackInventory     bool                    `json:"track_inventory"`
	AllowNegativeStock bool                    `json:"allow_negative_stock"`
	IsSellable         bool                    `json:"is_sellable"`
	IsPurchasable      bool                    `json:"is_purchasable"`
	RequiresShipping   bool                    `json:"requires_shipping"`
	IsBatchTracked     bool                    `json:"is_batch_tracked"`
	IsSerialTracked    bool                    `json:"is_serial_tracked"`
	FulfillmentPolicy  enums.FulfillmentPolicy `json:"fulfillment_policy"`
}

type UpdateItemRequest struct {
	SKU                *string                  `json:"sku,omitempty"` // ← ADD THIS LINE
	Name               *string                  `json:"name,omitempty"`
	Description        *string                  `json:"description,omitempty"`
	ItemType           *enums.ItemType          `json:"item_type,omitempty"`
	UnitOfMeasure      *string                  `json:"unit_of_measure,omitempty"`
	ValuationMethod    *enums.ValuationMethod   `json:"valuation_method,omitempty"`
	StandardCost       *decimal.Decimal         `json:"standard_cost,omitempty"`
	SellingPrice       *decimal.Decimal         `json:"selling_price,omitempty"`
	ReorderLevel       *decimal.Decimal         `json:"reorder_level,omitempty"`
	ReorderQuantity    *decimal.Decimal         `json:"reorder_quantity,omitempty"`
	IsActive           *bool                    `json:"is_active,omitempty"`
	TrackInventory     *bool                    `json:"track_inventory,omitempty"`
	AllowNegativeStock *bool                    `json:"allow_negative_stock,omitempty"`
	IsSellable         *bool                    `json:"is_sellable,omitempty"`
	IsPurchasable      *bool                    `json:"is_purchasable,omitempty"`
	RequiresShipping   *bool                    `json:"requires_shipping,omitempty"`
	IsBatchTracked     *bool                    `json:"is_batch_tracked,omitempty"`
	IsSerialTracked    *bool                    `json:"is_serial_tracked,omitempty"`
	FulfillmentPolicy  *enums.FulfillmentPolicy `json:"fulfillment_policy,omitempty"`
}

type ItemHandler struct {
	itemService service.ItemApplicationService
	logger      *zap.Logger
}

func NewItemHandler(itemService service.ItemApplicationService, logger *zap.Logger) *ItemHandler {
	return &ItemHandler{
		itemService: itemService,
		logger:      logger.Named("item_handler"),
	}
}

func (h *ItemHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "item:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StandardCost != nil && req.StandardCost.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "standard_cost must be >= 0")
		return
	}
	if req.ReorderLevel != nil && req.ReorderLevel.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "reorder_level must be >= 0")
		return
	}
	if !req.FulfillmentPolicy.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid fulfillment_policy")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	serviceReq := toServiceCreateReq(companyID, req, userID)
	item, err := h.itemService.CreateItem(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.handleServiceError(w, err, "failed to create item")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    item,
		"message": "Item created successfully",
	})
}

func (h *ItemHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemID, err := h.parseItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "item:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StandardCost != nil && req.StandardCost.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "standard_cost must be >= 0")
		return
	}
	if req.ReorderLevel != nil && req.ReorderLevel.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "reorder_level must be >= 0")
		return
	}
	if req.FulfillmentPolicy != nil && !req.FulfillmentPolicy.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid fulfillment_policy")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	serviceReq := toServiceUpdateReq(itemID, companyID, req, userID)
	item, err := h.itemService.UpdateItem(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.handleServiceError(w, err, "failed to update item")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    item,
		"message": "Item updated successfully",
	})
}

func (h *ItemHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemID, err := h.parseItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "item:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.itemService.DeleteItem(ctx, companyID, itemID, &userID, idempotencyKey)
	if err != nil {
		h.handleServiceError(w, err, "failed to delete item")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Item deleted successfully",
	})
}

func (h *ItemHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemID, err := h.parseItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	item, err := h.itemService.GetItemByID(ctx, companyID, itemID)
	if err != nil {
		h.handleServiceError(w, err, "failed to get item")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    item,
	})
}

func (h *ItemHandler) List(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := parseItemFilter(r)

	// Parse pagination with validation
	pagination, err := parsePagination(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sort := parseSort(r, "created_at", "DESC")

	items, total, err := h.itemService.ListItems(ctx, companyID, filter, pagination, sort)
	if err != nil {
		// Handle invalid sort field error from repository (if propagated)
		if errors.Is(err, repository.ErrInvalidSortField) {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.handleServiceError(w, err, "failed to list items")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  items,
			"total":  total,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

func (h *ItemHandler) GetLowStock(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "item:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	lowStockItems, err := h.itemService.GetLowStockItems(ctx, companyID)
	if err != nil {
		h.handleServiceError(w, err, "failed to get low stock items")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    lowStockItems,
	})
}

// ---------- Helper functions ----------

func (h *ItemHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	return uuid.Parse(companyIDStr)
}

func (h *ItemHandler) parseItemID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "itemID")
	return uuid.Parse(idStr)
}

func (h *ItemHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with actual permission check
	return true
}

func (h *ItemHandler) handleServiceError(w http.ResponseWriter, err error, logMsg string) {
	switch {
	case errors.Is(err, inventory_errors.ErrNotFound):
		h.respondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, inventory_errors.ErrDuplicate):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidInput):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, inventory_errors.ErrPermissionDenied):
		h.respondWithError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, inventory_errors.ErrInsufficientStock):
		h.respondWithError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		h.logger.Error(logMsg, zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

func (h *ItemHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ItemHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ---------- Conversion helpers ----------

func toServiceCreateReq(companyID uuid.UUID, req CreateItemRequest, userID uuid.UUID) service.CreateItemRequest {
	return service.CreateItemRequest{
		CompanyID:          companyID,
		SKU:                req.SKU,
		Name:               req.Name,
		Description:        req.Description,
		ItemType:           req.ItemType,
		UnitOfMeasure:      req.UnitOfMeasure,
		ValuationMethod:    req.ValuationMethod,
		StandardCost:       req.StandardCost,
		SellingPrice:       req.SellingPrice,
		ReorderLevel:       req.ReorderLevel,
		ReorderQuantity:    req.ReorderQuantity,
		IsActive:           req.IsActive,
		CreatedBy:          &userID,
		TrackInventory:     req.TrackInventory,
		AllowNegativeStock: req.AllowNegativeStock,
		IsSellable:         req.IsSellable,
		IsPurchasable:      req.IsPurchasable,
		RequiresShipping:   req.RequiresShipping,
		IsBatchTracked:     req.IsBatchTracked,
		IsSerialTracked:    req.IsSerialTracked,
		FulfillmentPolicy:  req.FulfillmentPolicy,
	}
}

func toServiceUpdateReq(itemID, companyID uuid.UUID, req UpdateItemRequest, userID uuid.UUID) service.UpdateItemRequest {
	return service.UpdateItemRequest{
		ItemID:             itemID,
		CompanyID:          companyID,
		SKU:                req.SKU, // ← ADD THIS LINE
		Name:               req.Name,
		Description:        req.Description,
		ItemType:           req.ItemType,
		UnitOfMeasure:      req.UnitOfMeasure,
		ValuationMethod:    req.ValuationMethod,
		StandardCost:       req.StandardCost,
		SellingPrice:       req.SellingPrice,
		ReorderLevel:       req.ReorderLevel,
		ReorderQuantity:    req.ReorderQuantity,
		IsActive:           req.IsActive,
		UpdatedBy:          &userID,
		TrackInventory:     req.TrackInventory,
		AllowNegativeStock: req.AllowNegativeStock,
		IsSellable:         req.IsSellable,
		IsPurchasable:      req.IsPurchasable,
		RequiresShipping:   req.RequiresShipping,
		IsBatchTracked:     req.IsBatchTracked,
		IsSerialTracked:    req.IsSerialTracked,
		FulfillmentPolicy:  req.FulfillmentPolicy,
	}
}

// ---------- Parameter parsers (with validation) ----------

func parseItemFilter(r *http.Request) service.ItemFilter {
	filter := service.ItemFilter{}
	if sku := r.URL.Query().Get("sku"); sku != "" {
		filter.SKU = &sku
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if itemType := r.URL.Query().Get("item_type"); itemType != "" {
		et := enums.ItemType(itemType)
		itemTypeStr := string(et)
		filter.ItemType = &itemTypeStr
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		if isActive, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &isActive
		}
	}
	return filter
}

// parsePagination now returns an error if limit=0 or invalid.
func parsePagination(r *http.Request) (repository.Pagination, error) {
	p := repository.Pagination{Limit: 20, Offset: 0}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			return repository.Pagination{}, errors.New("limit must be an integer")
		}
		if limit <= 0 {
			return repository.Pagination{}, errors.New("limit must be greater than 0")
		}
		if limit > 100 {
			return repository.Pagination{}, errors.New("limit must not exceed 100")
		}
		p.Limit = limit
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			return repository.Pagination{}, errors.New("offset must be an integer")
		}
		if offset < 0 {
			return repository.Pagination{}, errors.New("offset must be >= 0")
		}
		p.Offset = offset
	}

	return p, nil
}

func parseSort(r *http.Request, defaultField, defaultDir string) repository.Sort {
	field := r.URL.Query().Get("sort_field")
	if field == "" {
		field = defaultField
	}
	direction := strings.ToUpper(r.URL.Query().Get("sort_order"))
	if direction != "ASC" && direction != "DESC" {
		direction = defaultDir
	}
	return repository.Sort{Field: field, Direction: direction}
}

// getUserIDFromContext extracts user ID from request context (implementation depends on your auth middleware)
