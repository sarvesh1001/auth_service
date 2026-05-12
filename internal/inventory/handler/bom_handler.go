package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

// BOMHandler handles HTTP requests for Bill of Materials.
type BOMHandler struct {
	bomService service.BOMService
	logger     *zap.Logger
}

func NewBOMHandler(bomService service.BOMService, logger *zap.Logger) *BOMHandler {
	return &BOMHandler{
		bomService: bomService,
		logger:     logger.Named("bom_handler"),
	}
}

// Create a new BOM
// POST /api/v1/companies/{companyID}/boms
func (h *BOMHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqJSON struct {
		ProductItemID string          `json:"product_item_id"`
		BOMCode       string          `json:"bom_code"`
		Name          string          `json:"name"`
		Version       int             `json:"version"`
		Quantity      decimal.Decimal `json:"quantity"`
		IsActive      bool            `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	productItemID, err := uuid.Parse(reqJSON.ProductItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product_item_id")
		return
	}

	serviceReq := service.CreateBOMRequest{
		CompanyID:     companyID,
		ProductItemID: productItemID,
		BOMCode:       reqJSON.BOMCode,
		Name:          reqJSON.Name,
		Version:       reqJSON.Version,
		Quantity:      reqJSON.Quantity,
		IsActive:      reqJSON.IsActive,
		CreatedBy:     &userID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	bom, err := h.bomService.Create(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create BOM", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    bom,
		"message": "BOM created successfully",
	})
}

// GetByID returns a single BOM
// GET /api/v1/companies/{companyID}/boms/{bomID}
func (h *BOMHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomID, err := h.parseBOMID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	bom, err := h.bomService.GetByID(ctx, bomID, companyID)
	if err != nil {
		h.logger.Error("failed to get BOM", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    bom,
	})
}

// Update an existing BOM
// PUT /api/v1/companies/{companyID}/boms/{bomID}
func (h *BOMHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomID, err := h.parseBOMID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqJSON struct {
		ProductItemID *string          `json:"product_item_id,omitempty"`
		BOMCode       *string          `json:"bom_code,omitempty"`
		Name          *string          `json:"name,omitempty"`
		Version       *int             `json:"version,omitempty"`
		Quantity      *decimal.Decimal `json:"quantity,omitempty"`
		IsActive      *bool            `json:"is_active,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.UpdateBOMRequest{
		BOMID:     bomID,
		CompanyID: companyID,
		UpdatedBy: &userID,
	}
	if reqJSON.ProductItemID != nil {
		pid, _ := uuid.Parse(*reqJSON.ProductItemID)
		serviceReq.ProductItemID = &pid
	}
	serviceReq.BOMCode = reqJSON.BOMCode
	serviceReq.Name = reqJSON.Name
	serviceReq.Version = reqJSON.Version
	serviceReq.Quantity = reqJSON.Quantity
	serviceReq.IsActive = reqJSON.IsActive

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	bom, err := h.bomService.Update(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update BOM", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    bom,
		"message": "BOM updated successfully",
	})
}

// Delete a BOM
// DELETE /api/v1/companies/{companyID}/boms/{bomID}
func (h *BOMHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomID, err := h.parseBOMID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.bomService.Delete(ctx, bomID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete BOM", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "BOM deleted successfully",
	})
}

// List BOMs with optional filters
// GET /api/v1/companies/{companyID}/boms
func (h *BOMHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse pagination
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sort := repository.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_order"),
	}
	if sort.Field == "" {
		sort.Field = "created_at"
		sort.Direction = "desc"
	}

	filter := service.BOMFilter{}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, _ := strconv.ParseBool(isActiveStr)
		filter.IsActive = &isActive
	}

	boms, total, err := h.bomService.List(ctx, companyID, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list BOMs", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve BOMs")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  boms,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetByProductItemID returns all BOMs for a finished good
// GET /api/v1/companies/{companyID}/items/{productItemID}/boms
func (h *BOMHandler) GetByProductItemID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	productItemIDStr := chi.URLParam(r, "productItemID")
	productItemID, err := uuid.Parse(productItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product item ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	boms, err := h.bomService.GetByProductItemID(ctx, companyID, productItemID)
	if err != nil {
		h.logger.Error("failed to get BOMs by product", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    boms,
	})
}

// --- BOM Items endpoints ---

// AddBOMItem adds a component to a BOM
// POST /api/v1/companies/{companyID}/boms/{bomID}/items
func (h *BOMHandler) AddBOMItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomID, err := h.parseBOMID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqJSON struct {
		ComponentItemID string           `json:"component_item_id"`
		Quantity        decimal.Decimal  `json:"quantity"`
		ScrapPercentage *decimal.Decimal `json:"scrap_percentage,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	componentItemID, err := uuid.Parse(reqJSON.ComponentItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid component_item_id")
		return
	}

	serviceReq := service.AddBOMItemRequest{
		CompanyID:       companyID,
		BOMID:           bomID,
		ComponentItemID: componentItemID,
		Quantity:        reqJSON.Quantity,
		ScrapPercentage: reqJSON.ScrapPercentage,
		CreatedBy:       &userID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	item, err := h.bomService.AddBOMItem(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to add BOM item", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    item,
		"message": "BOM item added successfully",
	})
}

// UpdateBOMItem updates a BOM item (quantity / scrap %)
// PUT /api/v1/companies/{companyID}/boms/{bomID}/items/{bomItemID}
func (h *BOMHandler) UpdateBOMItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomItemIDStr := chi.URLParam(r, "bomItemID")
	bomItemID, err := uuid.Parse(bomItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid BOM item ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqJSON struct {
		Quantity        *decimal.Decimal `json:"quantity,omitempty"`
		ScrapPercentage *decimal.Decimal `json:"scrap_percentage,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.UpdateBOMItemRequest{
		BOMItemID:       bomItemID,
		CompanyID:       companyID,
		Quantity:        reqJSON.Quantity,
		ScrapPercentage: reqJSON.ScrapPercentage,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	item, err := h.bomService.UpdateBOMItem(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update BOM item", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    item,
		"message": "BOM item updated successfully",
	})
}

// RemoveBOMItem deletes a component from a BOM
// DELETE /api/v1/companies/{companyID}/boms/{bomID}/items/{bomItemID}
func (h *BOMHandler) RemoveBOMItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomItemIDStr := chi.URLParam(r, "bomItemID")
	bomItemID, err := uuid.Parse(bomItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid BOM item ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.bomService.RemoveBOMItem(ctx, bomItemID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to remove BOM item", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "BOM item removed successfully",
	})
}

// GetBOMItems lists all components of a BOM
// GET /api/v1/companies/{companyID}/boms/{bomID}/items
func (h *BOMHandler) GetBOMItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	bomID, err := h.parseBOMID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "bom:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.bomService.GetBOMItems(ctx, bomID, companyID)
	if err != nil {
		h.logger.Error("failed to get BOM items", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// --- helper methods ---

func (h *BOMHandler) parseCompanyID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return uuid.Nil, err
	}
	return companyID, nil
}

func (h *BOMHandler) parseBOMID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	bomIDStr := chi.URLParam(r, "bomID")
	bomID, err := uuid.Parse(bomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid BOM ID")
		return uuid.Nil, err
	}
	return bomID, nil
}

func (h *BOMHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *BOMHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *BOMHandler) respondWithInventoryError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case inventory_errors.IsNotFound(err):
		h.respondWithError(w, http.StatusNotFound, err.Error())
	case inventory_errors.IsInvalidInput(err):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case inventory_errors.IsPermissionDenied(err):
		h.respondWithError(w, http.StatusForbidden, err.Error())
	case inventory_errors.IsDuplicate(err):
		h.respondWithError(w, http.StatusConflict, err.Error())
	default:
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

// stub permission check – replace with real RBAC later
func (h *BOMHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	return true
}
