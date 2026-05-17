package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

type ReorderHandler struct {
	reorderService service.ReorderService
	repo           repository.ReorderOrderRepository
	db             *sql.DB
	logger         *zap.Logger
}

func NewReorderHandler(
	reorderService service.ReorderService,
	repo repository.ReorderOrderRepository,
	db *sql.DB,
	logger *zap.Logger,
) *ReorderHandler {
	return &ReorderHandler{
		reorderService: reorderService,
		repo:           repo,
		db:             db,
		logger:         logger.Named("reorder_handler"),
	}
}

type triggerReorderRequest struct {
	ItemID          string   `json:"itemId"`
	WarehouseID     string   `json:"warehouseId"`
	NewAvailableQty *float64 `json:"newAvailableQty,omitempty"` // ignored, kept for compatibility
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

func (h *ReorderHandler) TriggerReorder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reorder:trigger") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req triggerReorderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
		return
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
		return
	}

	// newAvailableQty is ignored – we always use actual DB stock
	err = h.reorderService.CheckAndCreateReorderOrders(ctx, companyID, itemID, warehouseID, decimal.Zero)
	if err != nil {
		h.logger.Error("failed to trigger reorder", zap.Error(err))

		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, inventory_errors.ErrReorderLevelNotMet),
			errors.Is(err, inventory_errors.ErrOpenReorderExists):
			// Business rule skip – return 200 with explanation
			h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
				"success":       true,
				"order_created": false,
				"reason":        err.Error(),
			})
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to process reorder check")
		}
		return
	}

	// Order created successfully
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success":       true,
		"order_created": true,
		"message":       "Reorder order created",
	})
}

func (h *ReorderHandler) ProcessPending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reorder:process") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	processed, err := h.reorderService.ProcessPendingOrders(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to process pending orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to process pending orders")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"message":         "Pending reorder orders processed",
		"processed_count": processed,
	})
}

func (h *ReorderHandler) ListReorderOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reorder:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	status := query.Get("status")
	itemIDStr := query.Get("itemId")
	warehouseIDStr := query.Get("warehouseId")

	// Validate status if provided
	allowedStatuses := map[string]bool{
		"pending":   true,
		"approved":  true,
		"ordered":   true,
		"received":  true,
		"cancelled": true,
	}
	if status != "" && !allowedStatuses[status] {
		h.respondWithError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(query.Get("pageSize"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	// Parse optional UUIDs
	var itemID uuid.UUID
	if itemIDStr != "" {
		parsed, err := uuid.Parse(itemIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
			return
		}
		itemID = parsed
	}
	var warehouseID uuid.UUID
	if warehouseIDStr != "" {
		parsed, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
			return
		}
		warehouseID = parsed
	}

	filters := repository.ReorderFilters{
		CompanyID:   companyID,
		Status:      status,
		ItemID:      itemID,
		WarehouseID: warehouseID,
		Page:        page,
		PageSize:    pageSize,
	}

	orders, total, err := h.repo.ListByFilters(ctx, h.db, filters)
	if err != nil {
		h.logger.Error("failed to list reorder orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve reorder orders")
		return
	}

	// Calculate total pages (optional but helpful)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      orders,
			"total":      total,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
		},
	})
}

func (h *ReorderHandler) GetReorderOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	orderIDStr := chi.URLParam(r, "reorderOrderId")
	orderID, err := uuid.Parse(orderIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reorder order id")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reorder:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.repo.GetByID(ctx, h.db, orderID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "reorder order not found")
			return
		}
		h.logger.Error("failed to get reorder order", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve reorder order")
		return
	}

	if order.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "reorder order does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    order,
	})
}

func (h *ReorderHandler) UpdateReorderStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	orderIDStr := chi.URLParam(r, "reorderOrderId")
	orderID, err := uuid.Parse(orderIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reorder order id")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reorder:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.reorderService.UpdateOrderStatus(ctx, orderID, req.Status)
	if err != nil {
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, "reorder order not found")
		case errors.Is(err, inventory_errors.ErrInvalidStatus), errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		default:
			h.logger.Error("failed to update reorder status", zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to update status")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Reorder order status updated",
	})
}

// Helper functions

func (h *ReorderHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with real permission check
	return true
}

func (h *ReorderHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReorderHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
