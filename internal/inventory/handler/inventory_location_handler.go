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
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/service"
)

// InventoryLocationHandler handles HTTP requests for inventory locations (warehouse hierarchy)
type InventoryLocationHandler struct {
	locationService service.InventoryLocationService
	logger          *zap.Logger
}

// NewInventoryLocationHandler creates a new handler instance
func NewInventoryLocationHandler(locationService service.InventoryLocationService, logger *zap.Logger) *InventoryLocationHandler {
	return &InventoryLocationHandler{
		locationService: locationService,
		logger:          logger.Named("inventory_location_handler"),
	}
}

// ---------- Request/Response DTOs ----------

type createLocationRequest struct {
	Code             string  `json:"code"`
	Name             string  `json:"name"`
	WarehouseID      string  `json:"warehouse_id"` // required
	LocationType     *string `json:"location_type,omitempty"`
	ParentLocationID *string `json:"parent_location_id,omitempty"`
}

type updateLocationRequest struct {
	Code             *string `json:"code,omitempty"`
	Name             *string `json:"name,omitempty"`
	WarehouseID      *string `json:"warehouse_id,omitempty"` // optional
	LocationType     *string `json:"location_type,omitempty"`
	ParentLocationID *string `json:"parent_location_id,omitempty"`
	IsActive         *bool   `json:"is_active,omitempty"`
}

type locationResponse struct {
	LocationID       string    `json:"locationId"`
	CompanyID        string    `json:"companyId"`
	WarehouseID      string    `json:"warehouseId"`
	Code             string    `json:"code"`
	Name             string    `json:"name"`
	LocationType     *string   `json:"locationType,omitempty"`
	ParentLocationID *string   `json:"parentLocationId,omitempty"`
	IsActive         bool      `json:"isActive"`
	CreatedAt        time.Time `json:"createdAt"`
}

type locationNodeResponse struct {
	LocationID       string                  `json:"locationId"`
	CompanyID        string                  `json:"companyId"`
	WarehouseID      string                  `json:"warehouseId"`
	Code             string                  `json:"code"`
	Name             string                  `json:"name"`
	LocationType     *string                 `json:"locationType,omitempty"`
	ParentLocationID *string                 `json:"parentLocationId,omitempty"`
	IsActive         bool                    `json:"isActive"`
	CreatedAt        time.Time               `json:"createdAt"`
	Children         []*locationNodeResponse `json:"children,omitempty"`
}

// ---------- Helper functions ----------

func (h *InventoryLocationHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		companyIDStr = chi.URLParam(r, "companyId")
	}
	if companyIDStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *InventoryLocationHandler) parseLocationID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "locationId")
	if idStr == "" {
		idStr = chi.URLParam(r, "id")
	}
	if idStr == "" {
		return uuid.Nil, errors.New("location ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *InventoryLocationHandler) uuidPtrFromStringPtr(s *string) *uuid.UUID {
	if s == nil || *s == "" {
		return nil
	}
	if id, err := uuid.Parse(*s); err == nil {
		return &id
	}
	return nil
}

func (h *InventoryLocationHandler) toLocationResponse(loc *models.InventoryLocation) locationResponse {
	resp := locationResponse{
		LocationID:   loc.LocationID.String(),
		CompanyID:    loc.CompanyID.String(),
		WarehouseID:  loc.WarehouseID.String(),
		Code:         loc.Code,
		Name:         loc.Name,
		LocationType: loc.LocationType,
		IsActive:     loc.IsActive,
		CreatedAt:    loc.CreatedAt,
	}
	if loc.ParentLocationID != nil {
		pid := loc.ParentLocationID.String()
		resp.ParentLocationID = &pid
	}
	return resp
}

func (h *InventoryLocationHandler) toLocationNodeResponse(node *service.LocationNode) *locationNodeResponse {
	resp := &locationNodeResponse{
		LocationID:   node.LocationID.String(),
		CompanyID:    node.CompanyID.String(),
		WarehouseID:  node.WarehouseID.String(),
		Code:         node.Code,
		Name:         node.Name,
		LocationType: node.LocationType,
		IsActive:     node.IsActive,
		CreatedAt:    node.CreatedAt,
	}
	if node.ParentLocationID != nil {
		pid := node.ParentLocationID.String()
		resp.ParentLocationID = &pid
	}
	children := make([]*locationNodeResponse, 0, len(node.Children))
	for _, child := range node.Children {
		children = append(children, h.toLocationNodeResponse(child))
	}
	resp.Children = children
	return resp
}

// ---------- Permission stub (same pattern as other handlers) ----------
func (h *InventoryLocationHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Implement actual permission check based on your auth system
	return true
}

// ---------- Handlers ----------

// CreateLocation handles POST /companies/{companyID}/locations
func (h *InventoryLocationHandler) CreateLocation(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "location:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.WarehouseID == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouse_id is required")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	parentID := h.uuidPtrFromStringPtr(req.ParentLocationID)

	serviceReq := service.CreateLocationRequest{
		CompanyID:        companyID,
		WarehouseID:      warehouseID,
		Code:             req.Code,
		Name:             req.Name,
		LocationType:     req.LocationType,
		ParentLocationID: parentID,
		CreatedBy:        &userID,
	}

	location, err := h.locationService.CreateLocation(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create location", zap.Error(err))
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			status = http.StatusBadRequest
		case errors.Is(err, inventory_errors.ErrDuplicate):
			status = http.StatusConflict
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			status = http.StatusForbidden
		case errors.Is(err, inventory_errors.ErrParentWarehouseMismatch):
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toLocationResponse(location),
		"message": "Location created successfully",
	})
}

// UpdateLocation handles PUT /companies/{companyID}/locations/{locationId}
func (h *InventoryLocationHandler) UpdateLocation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	locationID, err := h.parseLocationID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "location:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req updateLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.UpdateLocationRequest{
		LocationID:       locationID,
		CompanyID:        companyID,
		Code:             req.Code,
		Name:             req.Name,
		LocationType:     req.LocationType,
		ParentLocationID: h.uuidPtrFromStringPtr(req.ParentLocationID),
		IsActive:         req.IsActive,
		UpdatedBy:        &userID,
	}
	if req.WarehouseID != nil {
		whID, err := uuid.Parse(*req.WarehouseID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
			return
		}
		serviceReq.WarehouseID = &whID
	}

	location, err := h.locationService.UpdateLocation(ctx, serviceReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update location", zap.Error(err))
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			status = http.StatusBadRequest
		case errors.Is(err, inventory_errors.ErrDuplicate):
			status = http.StatusConflict
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			status = http.StatusForbidden
		case errors.Is(err, inventory_errors.ErrParentWarehouseMismatch):
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toLocationResponse(location),
		"message": "Location updated successfully",
	})
}

// DeleteLocation handles DELETE /companies/{companyID}/locations/{locationId}
func (h *InventoryLocationHandler) DeleteLocation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	locationID, err := h.parseLocationID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "location:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.locationService.DeleteLocation(ctx, companyID, locationID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete location", zap.Error(err))
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			status = http.StatusForbidden
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Location deleted successfully",
	})
}

// GetLocation handles GET /companies/{companyID}/locations/{locationId}
func (h *InventoryLocationHandler) GetLocation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	locationID, err := h.parseLocationID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "location:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	location, err := h.locationService.GetLocationByID(ctx, companyID, locationID)
	if err != nil {
		h.logger.Error("failed to get location", zap.Error(err))
		status := http.StatusInternalServerError
		if errors.Is(err, inventory_errors.ErrNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, inventory_errors.ErrPermissionDenied) {
			status = http.StatusForbidden
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toLocationResponse(location),
	})
}

// ListLocations handles GET /companies/{companyID}/locations
// Query params: warehouse_id (required), active_only (bool), parent_id (optional)
func (h *InventoryLocationHandler) ListLocations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// warehouse_id is required
	warehouseIDStr := r.URL.Query().Get("warehouse_id")
	if warehouseIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouse_id query parameter is required")
		return
	}
	warehouseID, err := uuid.Parse(warehouseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "location:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	activeOnly := false
	if activeOnlyStr := r.URL.Query().Get("active_only"); activeOnlyStr != "" {
		activeOnly, _ = strconv.ParseBool(activeOnlyStr)
	}

	var parentID *uuid.UUID
	if parentIDStr := r.URL.Query().Get("parent_id"); parentIDStr != "" {
		parsed, err := uuid.Parse(parentIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid parent_id")
			return
		}
		parentID = &parsed
	}

	locations, err := h.locationService.ListLocations(ctx, companyID, warehouseID, parentID, activeOnly)
	if err != nil {
		h.logger.Error("failed to list locations", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve locations")
		return
	}

	responses := make([]locationResponse, 0, len(locations))
	for _, loc := range locations {
		responses = append(responses, h.toLocationResponse(loc))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetLocationTree handles GET /companies/{companyID}/locations/tree
// Query param: warehouse_id (required)
func (h *InventoryLocationHandler) GetLocationTree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	warehouseIDStr := r.URL.Query().Get("warehouse_id")
	if warehouseIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouse_id query parameter is required")
		return
	}
	warehouseID, err := uuid.Parse(warehouseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "location:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	tree, err := h.locationService.GetLocationTree(ctx, companyID, warehouseID)
	if err != nil {
		h.logger.Error("failed to get location tree", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve location tree")
		return
	}

	rootNodes := make([]*locationNodeResponse, 0, len(tree))
	for _, node := range tree {
		rootNodes = append(rootNodes, h.toLocationNodeResponse(node))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rootNodes,
	})
}

// ---------- Response helpers ----------
func (h *InventoryLocationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *InventoryLocationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
