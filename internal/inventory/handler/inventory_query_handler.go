package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type InventoryQueryHandler struct {
	querySvc service.InventoryQueryService
	logger   *zap.Logger
}

func NewInventoryQueryHandler(querySvc service.InventoryQueryService, logger *zap.Logger) *InventoryQueryHandler {
	return &InventoryQueryHandler{
		querySvc: querySvc,
		logger:   logger.Named("inventory_query_handler"),
	}
}

// GetCurrentStock GET /api/v1/companies/{companyId}/stock/current
func (h *InventoryQueryHandler) GetCurrentStock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	warehouseIDStr := r.URL.Query().Get("warehouseId")
	if warehouseIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouseId query parameter is required")
		return
	}
	warehouseID, err := uuid.Parse(warehouseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
		return
	}

	itemIDStr := r.URL.Query().Get("itemId")
	if itemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "itemId query parameter is required")
		return
	}
	itemID, err := uuid.Parse(itemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
		return
	}

	var batchID *uuid.UUID
	if batchIDStr := r.URL.Query().Get("batchId"); batchIDStr != "" {
		id, err := uuid.Parse(batchIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batchId")
			return
		}
		batchID = &id
	}

	stock, err := h.querySvc.GetCurrentStock(ctx, companyID, warehouseID, itemID, batchID)
	if err != nil {
		h.logger.Error("failed to get current stock", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve stock")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stock,
	})
}

// GetAllStockByWarehouse GET /api/v1/companies/{companyId}/warehouses/{warehouseId}/stock
func (h *InventoryQueryHandler) GetAllStockByWarehouse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	warehouseIDStr := chi.URLParam(r, "warehouseId")
	if warehouseIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouseId is required")
		return
	}
	warehouseID, err := uuid.Parse(warehouseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stockLevels, err := h.querySvc.GetAllStockByWarehouse(ctx, companyID, warehouseID)
	if err != nil {
		h.logger.Error("failed to get stock by warehouse", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve stock levels")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stockLevels,
	})
}

// GetAllStockByItem GET /api/v1/companies/{companyId}/items/{itemId}/stock
func (h *InventoryQueryHandler) GetAllStockByItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemIDStr := chi.URLParam(r, "itemId")
	if itemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "itemId is required")
		return
	}
	itemID, err := uuid.Parse(itemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stockLevels, err := h.querySvc.GetAllStockByItem(ctx, companyID, itemID)
	if err != nil {
		h.logger.Error("failed to get stock by item", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve stock levels")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stockLevels,
	})
}

// GetAllStockByBatch GET /api/v1/companies/{companyId}/batches/{batchId}/stock
func (h *InventoryQueryHandler) GetAllStockByBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	batchIDStr := chi.URLParam(r, "batchId")
	if batchIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "batchId is required")
		return
	}
	batchID, err := uuid.Parse(batchIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batchId")
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stockLevel, err := h.querySvc.GetAllStockByBatch(ctx, companyID, batchID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "stock not found for this batch")
			return
		}
		if err == inventory_errors.ErrPermissionDenied {
			h.respondWithError(w, http.StatusForbidden, err.Error())
			return
		}
		h.logger.Error("failed to get stock by batch", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve stock")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stockLevel,
	})
}

// GetMovements GET /api/v1/companies/{companyId}/movements
func (h *InventoryQueryHandler) GetMovements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.MovementFilter{
		CompanyID: companyID,
	}

	if itemIDStr := r.URL.Query().Get("itemId"); itemIDStr != "" {
		id, err := uuid.Parse(itemIDStr)
		if err == nil {
			filter.ItemID = &id
		}
	}
	if warehouseIDStr := r.URL.Query().Get("warehouseId"); warehouseIDStr != "" {
		id, err := uuid.Parse(warehouseIDStr)
		if err == nil {
			filter.WarehouseID = &id
		}
	}
	if movementType := r.URL.Query().Get("movementType"); movementType != "" {
		filter.MovementType = &movementType
	}
	if fromDateStr := r.URL.Query().Get("fromDate"); fromDateStr != "" {
		t, err := time.Parse("2006-01-02", fromDateStr)
		if err == nil {
			filter.DateFrom = &t
		}
	}
	if toDateStr := r.URL.Query().Get("toDate"); toDateStr != "" {
		t, err := time.Parse("2006-01-02", toDateStr)
		if err == nil {
			filter.DateTo = &t
		}
	}
	if refType := r.URL.Query().Get("referenceType"); refType != "" {
		filter.ReferenceType = &refType
	}
	if refIDStr := r.URL.Query().Get("referenceId"); refIDStr != "" {
		id, err := uuid.Parse(refIDStr)
		if err == nil {
			filter.ReferenceID = &id
		}
	}

	page := 1
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	pageSize := 20
	if pageSizeStr := r.URL.Query().Get("pageSize"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	result, err := h.querySvc.GetMovements(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to get movements", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve movements")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// GetLowStockItems GET /api/v1/companies/{companyId}/low-stock
func (h *InventoryQueryHandler) GetLowStockItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	items, err := h.querySvc.GetLowStockItems(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get low stock items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve low stock items")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// GetExpiringBatches GET /api/v1/companies/{companyId}/expiring-batches
func (h *InventoryQueryHandler) GetExpiringBatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	days := 30
	if daysStr := r.URL.Query().Get("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	batches, err := h.querySvc.GetExpiringBatches(ctx, companyID, days)
	if err != nil {
		h.logger.Error("failed to get expiring batches", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve expiring batches")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    batches,
	})
}

// GetReservationsByReference GET /api/v1/companies/{companyId}/reservations
func (h *InventoryQueryHandler) GetReservationsByReference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDParam(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "inventory:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reservationType := r.URL.Query().Get("reservationType")
	if reservationType == "" {
		h.respondWithError(w, http.StatusBadRequest, "reservationType query parameter is required")
		return
	}

	referenceIDStr := r.URL.Query().Get("referenceId")
	if referenceIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "referenceId query parameter is required")
		return
	}
	referenceID, err := uuid.Parse(referenceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid referenceId")
		return
	}

	reservations, err := h.querySvc.GetReservationsByReference(ctx, companyID, reservationType, referenceID)
	if err != nil {
		h.logger.Error("failed to get reservations by reference", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve reservations")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    reservations,
	})
}

// Helper functions

func parseCompanyIDParam(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		companyIDStr = chi.URLParam(r, "companyId")
	}
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *InventoryQueryHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: implement actual permission check
	return true
}

func (h *InventoryQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *InventoryQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
