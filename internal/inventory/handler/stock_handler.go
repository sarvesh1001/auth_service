package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/service"
)

// StockHandler handles HTTP requests for inventory stock operations.
type StockHandler struct {
	stockService    service.StockService
	queryService    service.InventoryQueryService
	movementService service.MovementService
	logger          *zap.Logger
}

// NewStockHandler creates a new StockHandler.
func NewStockHandler(
	stockService service.StockService,
	queryService service.InventoryQueryService,
	movementService service.MovementService,
	logger *zap.Logger,
) *StockHandler {
	return &StockHandler{
		stockService:    stockService,
		queryService:    queryService,
		movementService: movementService,
		logger:          logger.Named("stock_handler"),
	}
}

// ---------- Request/Response Types ----------

type getAvailableStockRequest struct {
	WarehouseID string `json:"warehouse_id"`
	ItemID      string `json:"item_id"`
	BatchID     string `json:"batch_id,omitempty"`
}

type adjustStockRequest struct {
	WarehouseID    string    `json:"warehouse_id"`
	ItemID         string    `json:"item_id"`
	BatchID        *string   `json:"batch_id,omitempty"`
	Delta          string    `json:"delta"`
	Reason         string    `json:"reason"`
	AdjustmentDate time.Time `json:"adjustment_date"`
}

type getBatchPickingRequest struct {
	ItemID      string `json:"item_id"`
	WarehouseID string `json:"warehouse_id"`
	RequiredQty string `json:"required_qty"`
	Strategy    string `json:"strategy"`
}

// ---------- Helper Functions ----------

func parseDecimalFromString(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, fmt.Errorf("empty decimal value")
	}
	return decimal.NewFromString(s)
}

func parseUUIDFromString(s string) (*uuid.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func parseUUIDFromStringPtr(s *string) (*uuid.UUID, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	return parseUUIDFromString(*s)
}

func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}
	return userID, nil
}

func (h *StockHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// Implement real permission check here.
	return true
}

func (h *StockHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *StockHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// GetAvailableStock handles POST /api/v1/companies/{companyID}/inventory/stock/available
func (h *StockHandler) GetAvailableStock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "stock:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req getAvailableStockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}
	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}
	batchID, err := parseUUIDFromString(req.BatchID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
		return
	}

	available, err := h.stockService.GetAvailableStock(ctx, companyID, warehouseID, itemID, batchID)
	if err != nil {
		h.logger.Error("failed to get available stock", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve available stock")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"available_quantity": available.String(),
		},
	})
}

// GetStockLevels handles GET /api/v1/companies/{companyID}/inventory/stock/levels
func (h *StockHandler) GetStockLevels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "stock:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	q := r.URL.Query()
	filter := service.StockFilter{
		CompanyID: companyID,
	}
	if whIDStr := q.Get("warehouse_id"); whIDStr != "" {
		whID, err := uuid.Parse(whIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
			return
		}
		filter.WarehouseID = &whID
	}
	if itemIDStr := q.Get("item_id"); itemIDStr != "" {
		itemID, err := uuid.Parse(itemIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
			return
		}
		filter.ItemID = &itemID
	}
	if batchIDStr := q.Get("batch_id"); batchIDStr != "" {
		batchID, err := uuid.Parse(batchIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		filter.BatchID = &batchID
	}
	if minOnHandStr := q.Get("min_on_hand"); minOnHandStr != "" {
		minOnHand, err := decimal.NewFromString(minOnHandStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid min_on_hand")
			return
		}
		filter.MinOnHand = &minOnHand
	}
	if minAvailStr := q.Get("min_available"); minAvailStr != "" {
		minAvail, err := decimal.NewFromString(minAvailStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid min_available")
			return
		}
		filter.MinAvail = &minAvail
	}

	balances, err := h.stockService.GetStockLevels(ctx, filter)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrInsufficientFilter) {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("failed to get stock levels", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve stock levels")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    balances,
	})
}

// AdjustStock handles POST /api/v1/companies/{companyID}/inventory/stock/adjust
func (h *StockHandler) AdjustStock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "stock:adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req adjustStockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}
	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}
	batchID, err := parseUUIDFromStringPtr(req.BatchID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
		return
	}
	delta, err := parseDecimalFromString(req.Delta)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid delta")
		return
	}
	if req.AdjustmentDate.IsZero() {
		req.AdjustmentDate = time.Now()
	}

	adjustReq := service.AdjustStockRequest{
		CompanyID:      companyID,
		WarehouseID:    warehouseID,
		ItemID:         itemID,
		BatchID:        batchID,
		Delta:          delta,
		Reason:         req.Reason,
		AdjustmentDate: req.AdjustmentDate,
		CreatedBy:      &userID,
	}

	movement, err := h.stockService.AdjustStock(ctx, adjustReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to adjust stock", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to adjust stock")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    movement,
		"message": "Stock adjusted successfully",
	})
}

// GetBatchPicking handles POST /api/v1/companies/{companyID}/inventory/stock/batch-picking
func (h *StockHandler) GetBatchPicking(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "stock:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req getBatchPickingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}
	requiredQty, err := parseDecimalFromString(req.RequiredQty)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid required_qty")
		return
	}

	var strategy service.PickingStrategy
	switch strings.ToUpper(req.Strategy) {
	case "FIFO":
		strategy = service.PickingStrategyFIFO
	case "FEFO":
		strategy = service.PickingStrategyFEFO
	default:
		h.respondWithError(w, http.StatusBadRequest, "strategy must be FIFO or FEFO")
		return
	}

	allocations, err := h.stockService.GetBatchPicking(ctx, companyID, itemID, warehouseID, requiredQty, strategy)
	if err != nil {
		h.logger.Error("failed to get batch picking", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to compute batch picking")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    allocations,
	})
}
