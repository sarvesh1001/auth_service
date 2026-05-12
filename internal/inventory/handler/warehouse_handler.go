package handler

import (
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WarehouseHandler struct {
	warehouseService service.WarehouseService
	logger           *zap.Logger
}

func NewWarehouseHandler(warehouseService service.WarehouseService, logger *zap.Logger) *WarehouseHandler {
	return &WarehouseHandler{
		warehouseService: warehouseService,
		logger:           logger.Named("warehouse_handler"),
	}
}

// ---------- Request/Response types ----------
type createWarehouseRequest struct {
	Code               string  `json:"code"`
	Name               string  `json:"name"`
	Location           *string `json:"location,omitempty"`
	IsActive           bool    `json:"is_active"`
	LocationID         *string `json:"location_id,omitempty"`    // New
	WarehouseType      *string `json:"warehouse_type,omitempty"` // New
	AllowNegativeStock bool    `json:"allow_negative_stock"`     // New
}

type updateWarehouseRequest struct {
	Code               *string `json:"code,omitempty"`
	Name               *string `json:"name,omitempty"`
	Location           *string `json:"location,omitempty"`
	IsActive           *bool   `json:"is_active,omitempty"`
	LocationID         *string `json:"location_id,omitempty"`          // New
	WarehouseType      *string `json:"warehouse_type,omitempty"`       // New
	AllowNegativeStock *bool   `json:"allow_negative_stock,omitempty"` // New
}

type setStatusRequest struct {
	IsActive bool `json:"is_active"`
}

// ---------- Create Warehouse ----------
func (h *WarehouseHandler) Create(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "warehouse:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createWarehouseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	// Parse optional location_id UUID
	var locationID *uuid.UUID
	if req.LocationID != nil && *req.LocationID != "" {
		parsed, err := uuid.Parse(*req.LocationID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid location_id")
			return
		}
		locationID = &parsed
	}

	svcReq := service.CreateWarehouseRequest{
		CompanyID:          companyID,
		Code:               req.Code,
		Name:               req.Name,
		Location:           req.Location,
		IsActive:           req.IsActive,
		CreatedBy:          &userID,
		LocationID:         locationID,
		WarehouseType:      req.WarehouseType,
		AllowNegativeStock: req.AllowNegativeStock,
	}

	warehouse, err := h.warehouseService.CreateWarehouse(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create warehouse", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    warehouse,
		"message": "Warehouse created successfully",
	})
}

// ---------- Bulk Create Warehouses ----------
func (h *WarehouseHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "warehouse:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []createWarehouseRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReqs := make([]service.CreateWarehouseRequest, len(reqs))
	for i, rq := range reqs {
		var locationID *uuid.UUID
		if rq.LocationID != nil && *rq.LocationID != "" {
			parsed, err := uuid.Parse(*rq.LocationID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid location_id in one of the entries")
				return
			}
			locationID = &parsed
		}
		svcReqs[i] = service.CreateWarehouseRequest{
			CompanyID:          companyID,
			Code:               rq.Code,
			Name:               rq.Name,
			Location:           rq.Location,
			IsActive:           rq.IsActive,
			CreatedBy:          &userID,
			LocationID:         locationID,
			WarehouseType:      rq.WarehouseType,
			AllowNegativeStock: rq.AllowNegativeStock,
		}
	}

	warehouses, err := h.warehouseService.BulkCreateWarehouses(ctx, svcReqs, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to bulk create warehouses", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    warehouses,
		"message": "Warehouses created successfully",
	})
}

// ---------- Get by ID ----------
func (h *WarehouseHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}
	warehouseID, err := h.parseWarehouseID(w, r)
	if err != nil {
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "warehouse:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	warehouse, err := h.warehouseService.GetWarehouseByID(ctx, companyID, warehouseID)
	if err != nil {
		h.logger.Error("failed to get warehouse", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    warehouse,
	})
}

// ---------- Get by Code ----------
func (h *WarehouseHandler) GetByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}
	code := chi.URLParam(r, "code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "warehouse:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	warehouse, err := h.warehouseService.GetWarehouseByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get warehouse by code", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    warehouse,
	})
}

// ---------- List Warehouses ----------
func (h *WarehouseHandler) List(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "warehouse:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.WarehouseFilter{
		CompanyID: companyID,
	}
	if isActiveStr := query.Get("is_active"); isActiveStr != "" {
		isActive, _ := strconv.ParseBool(isActiveStr)
		filter.IsActive = &isActive
	}
	if search := query.Get("search"); search != "" {
		filter.Search = search
	}

	// --- FIX: page validation ---
	pageStr := query.Get("page")
	page := 1
	if pageStr != "" {
		page, err = strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			h.respondWithError(w, http.StatusBadRequest, "page must be a positive integer")
			return
		}
	}

	pageSizeStr := query.Get("page_size")
	if pageSizeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "page_size is required")
		return
	}
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "page_size must be an integer")
		return
	}
	if pageSize < 1 {
		h.respondWithError(w, http.StatusBadRequest, "page_size must be greater than 0")
		return
	}
	if pageSize > 100 {
		pageSize = 100
	}
	// --- end of fix ---

	warehouses, total, err := h.warehouseService.ListWarehouses(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list warehouses", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve warehouses")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      warehouses,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// ---------- Update Warehouse ----------
func (h *WarehouseHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}
	warehouseID, err := h.parseWarehouseID(w, r)
	if err != nil {
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "warehouse:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateWarehouseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	// Parse optional location_id
	var locationID *uuid.UUID
	if req.LocationID != nil && *req.LocationID != "" {
		parsed, err := uuid.Parse(*req.LocationID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid location_id")
			return
		}
		locationID = &parsed
	}

	svcReq := service.UpdateWarehouseRequest{
		WarehouseID:        warehouseID,
		CompanyID:          companyID,
		Code:               req.Code,
		Name:               req.Name,
		Location:           req.Location,
		IsActive:           req.IsActive,
		UpdatedBy:          &userID,
		LocationID:         locationID,
		WarehouseType:      req.WarehouseType,
		AllowNegativeStock: req.AllowNegativeStock,
	}

	warehouse, err := h.warehouseService.UpdateWarehouse(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update warehouse", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    warehouse,
		"message": "Warehouse updated successfully",
	})
}

// ---------- Delete Warehouse (soft) ----------
func (h *WarehouseHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}
	warehouseID, err := h.parseWarehouseID(w, r)
	if err != nil {
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "warehouse:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.warehouseService.DeleteWarehouse(ctx, companyID, warehouseID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete warehouse", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Warehouse deleted successfully",
	})
}

// ---------- Set Warehouse Status (activate/deactivate) ----------
func (h *WarehouseHandler) SetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}
	warehouseID, err := h.parseWarehouseID(w, r)
	if err != nil {
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "warehouse:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req setStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.warehouseService.SetWarehouseStatus(ctx, companyID, warehouseID, req.IsActive, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to set warehouse status", zap.Error(err))
		h.respondWithError(w, h.statusCodeFromError(err), err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Warehouse status updated successfully",
	})
}

// ---------- Helper functions ----------
func (h *WarehouseHandler) parseCompanyID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return uuid.Nil, err
	}
	return companyID, nil
}

func (h *WarehouseHandler) parseWarehouseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "warehouseID")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse ID")
		return uuid.Nil, err
	}
	return id, nil
}

func (h *WarehouseHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: implement proper permission check (e.g., call auth service)
	return true
}

func (h *WarehouseHandler) statusCodeFromError(err error) int {
	switch {
	case errors.Is(err, inventory_errors.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, inventory_errors.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, inventory_errors.ErrDuplicate):
		return http.StatusConflict
	case errors.Is(err, inventory_errors.ErrPermissionDenied):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func (h *WarehouseHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *WarehouseHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
