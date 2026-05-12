package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

// AdjustmentHandler handles HTTP requests for stock adjustments.
type AdjustmentHandler struct {
	stockService    service.StockService
	movementService service.MovementService
	logger          *zap.Logger
}

// NewAdjustmentHandler creates a new AdjustmentHandler.
func NewAdjustmentHandler(
	stockService service.StockService,
	movementService service.MovementService,
	logger *zap.Logger,
) *AdjustmentHandler {
	return &AdjustmentHandler{
		stockService:    stockService,
		movementService: movementService,
		logger:          logger.Named("adjustment_handler"),
	}
}

// ---------- Request/Response Types ----------

type createAdjustmentRequest struct {
	WarehouseID    string  `json:"warehouse_id"`
	ItemID         string  `json:"item_id"`
	BatchID        *string `json:"batch_id,omitempty"`
	Delta          string  `json:"delta"` // positive = increase, negative = decrease
	Reason         string  `json:"reason"`
	AdjustmentDate string  `json:"adjustment_date"` // YYYY-MM-DD, optional, defaults to now
}

type adjustmentResponse struct {
	MovementID    string    `json:"movement_id"`
	CompanyID     string    `json:"company_id"`
	MovementType  string    `json:"movement_type"`
	WarehouseID   string    `json:"warehouse_id"`
	ItemID        string    `json:"item_id"`
	BatchID       *string   `json:"batch_id,omitempty"`
	QuantityIn    string    `json:"quantity_in,omitempty"`
	QuantityOut   string    `json:"quantity_out,omitempty"`
	UnitCost      string    `json:"unit_cost"`
	Reason        *string   `json:"reason,omitempty"`
	MovementDate  time.Time `json:"movement_date"`
	ReferenceType *string   `json:"reference_type,omitempty"`
	ReferenceID   *string   `json:"reference_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type listAdjustmentsResponse struct {
	Data       []adjustmentResponse `json:"data"`
	TotalCount int64                `json:"totalCount"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"pageSize"`
}

// ---------- Handlers ----------

// CreateAdjustment handles POST /companies/{companyID}/adjustments
// Idempotency key is read from the "Idempotency-Key" header.
func (h *AdjustmentHandler) CreateAdjustment(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "inventory:adjustment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createAdjustmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	delta, err := decimal.NewFromString(req.Delta)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid delta: must be a decimal number")
		return
	}
	if delta.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "delta must be non-zero")
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

	var batchID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		parsed, err := uuid.Parse(*req.BatchID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		batchID = &parsed
	}

	var adjustmentDate time.Time
	if req.AdjustmentDate != "" {
		adjustmentDate, err = time.Parse("2006-01-02", req.AdjustmentDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "adjustment_date must be in YYYY-MM-DD format")
			return
		}
	} else {
		adjustmentDate = time.Now().UTC()
	}

	adjustReq := service.AdjustStockRequest{
		CompanyID:      companyID,
		WarehouseID:    warehouseID,
		ItemID:         itemID,
		BatchID:        batchID,
		Delta:          delta,
		Reason:         req.Reason,
		AdjustmentDate: adjustmentDate,
		CreatedBy:      &userID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	movement, err := h.stockService.AdjustStock(ctx, adjustReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create adjustment", zap.Error(err))
		switch {
		case strings.Contains(err.Error(), inventory_errors.ErrInvalidInput.Error()):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), inventory_errors.ErrInsufficientStock.Error()):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create adjustment")
		}
		return
	}

	resp := adjustmentResponse{
		MovementID:    movement.MovementID.String(),
		CompanyID:     movement.CompanyID.String(),
		MovementType:  string(movement.MovementType),
		WarehouseID:   movement.WarehouseID.String(),
		ItemID:        movement.ItemID.String(),
		QuantityIn:    movement.QuantityIn.String(),
		QuantityOut:   movement.QuantityOut.String(),
		UnitCost:      movement.UnitCost.String(),
		Reason:        movement.Reason,
		MovementDate:  movement.MovementDate,
		ReferenceType: movement.ReferenceType,
		CreatedAt:     movement.CreatedAt,
	}
	if movement.BatchID != nil {
		s := movement.BatchID.String()
		resp.BatchID = &s
	}
	if movement.ReferenceID != nil {
		s := movement.ReferenceID.String()
		resp.ReferenceID = &s
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
		"message": "Stock adjustment created successfully",
	})
}

// GetAdjustment handles GET /companies/{companyID}/adjustments/{id}
func (h *AdjustmentHandler) GetAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	movementID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:adjustment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	movement, err := h.movementService.GetMovement(ctx, movementID)
	if err != nil {
		h.logger.Error("failed to get adjustment", zap.Error(err))
		if strings.Contains(err.Error(), inventory_errors.ErrNotFound.Error()) {
			h.respondWithError(w, http.StatusNotFound, "adjustment not found")
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve adjustment")
		}
		return
	}

	if movement.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "adjustment does not belong to this company")
		return
	}

	if movement.MovementType != enums.MovementTypeAdjustmentIn && movement.MovementType != enums.MovementTypeAdjustmentOut {
		h.respondWithError(w, http.StatusNotFound, "movement is not an adjustment")
		return
	}

	resp := adjustmentResponse{
		MovementID:    movement.MovementID.String(),
		CompanyID:     movement.CompanyID.String(),
		MovementType:  string(movement.MovementType),
		WarehouseID:   movement.WarehouseID.String(),
		ItemID:        movement.ItemID.String(),
		QuantityIn:    movement.QuantityIn.String(),
		QuantityOut:   movement.QuantityOut.String(),
		UnitCost:      movement.UnitCost.String(),
		Reason:        movement.Reason,
		MovementDate:  movement.MovementDate,
		ReferenceType: movement.ReferenceType,
		CreatedAt:     movement.CreatedAt,
	}
	if movement.BatchID != nil {
		s := movement.BatchID.String()
		resp.BatchID = &s
	}
	if movement.ReferenceID != nil {
		s := movement.ReferenceID.String()
		resp.ReferenceID = &s
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListAdjustments handles GET /companies/{companyID}/adjustments
// Supports pagination and optional filtering by item_id, warehouse_id, and date range.
func (h *AdjustmentHandler) ListAdjustments(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "inventory:adjustment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	// Build the filter without type or date filters (the repository may not support them)
	filter := repository.MovementFilter{
		CompanyID: companyID,
	}
	if itemIDStr := query.Get("item_id"); itemIDStr != "" {
		if parsed, err := uuid.Parse(itemIDStr); err == nil {
			filter.ItemID = &parsed
		}
	}
	if warehouseIDStr := query.Get("warehouse_id"); warehouseIDStr != "" {
		if parsed, err := uuid.Parse(warehouseIDStr); err == nil {
			filter.WarehouseID = &parsed
		}
	}

	// Fetch all movements (paginated) matching company and optional item/warehouse
	movements, _, err := h.movementService.ListMovements(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list movements", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve adjustments")
		return
	}

	// Parse date filters from query (optional)
	var fromDate, toDate *time.Time
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			fromDate = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			toDate = &t
		}
	}

	// Filter in memory for adjustment types and date range
	filteredMovements := make([]*models.StockMovement, 0, len(movements))
	for _, m := range movements {
		if m.MovementType != enums.MovementTypeAdjustmentIn && m.MovementType != enums.MovementTypeAdjustmentOut {
			continue
		}
		if fromDate != nil && m.MovementDate.Before(*fromDate) {
			continue
		}
		if toDate != nil && m.MovementDate.After(*toDate) {
			continue
		}
		filteredMovements = append(filteredMovements, m)
	}

	// Note: total count reflects the pre‑filtered total, which may be larger than the final result.
	// For accurate counts, you would need repository support for type/date filters.
	respData := make([]adjustmentResponse, 0, len(filteredMovements))
	for _, m := range filteredMovements {
		item := adjustmentResponse{
			MovementID:    m.MovementID.String(),
			CompanyID:     m.CompanyID.String(),
			MovementType:  string(m.MovementType),
			WarehouseID:   m.WarehouseID.String(),
			ItemID:        m.ItemID.String(),
			QuantityIn:    m.QuantityIn.String(),
			QuantityOut:   m.QuantityOut.String(),
			UnitCost:      m.UnitCost.String(),
			Reason:        m.Reason,
			MovementDate:  m.MovementDate,
			ReferenceType: m.ReferenceType,
			CreatedAt:     m.CreatedAt,
		}
		if m.BatchID != nil {
			s := m.BatchID.String()
			item.BatchID = &s
		}
		if m.ReferenceID != nil {
			s := m.ReferenceID.String()
			item.ReferenceID = &s
		}
		respData = append(respData, item)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": listAdjustmentsResponse{
			Data:       respData,
			TotalCount: int64(len(respData)), // approximate; use total from repo if needed
			Page:       page,
			PageSize:   pageSize,
		},
	})
}

// CancelAdjustment handles POST /companies/{companyID}/adjustments/{id}/cancel
// Creates a compensating movement to reverse an adjustment.
func (h *AdjustmentHandler) CancelAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	movementID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:adjustment:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // reason is optional

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	cancelReq := service.CancelMovementRequest{
		MovementID:  movementID,
		CompanyID:   companyID,
		Reason:      req.Reason,
		CancelledBy: &userID,
	}

	err = h.movementService.CancelMovement(ctx, cancelReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to cancel adjustment", zap.Error(err))
		switch {
		case strings.Contains(err.Error(), inventory_errors.ErrNotFound.Error()):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case strings.Contains(err.Error(), inventory_errors.ErrPermissionDenied.Error()):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case strings.Contains(err.Error(), inventory_errors.ErrInvalidInput.Error()):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to cancel adjustment")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Adjustment cancelled successfully",
	})
}

// ---------- Helper Functions ----------

// hasPermission is a placeholder – implement proper permission checks.
func (h *AdjustmentHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: Integrate with your auth service
	return true
}

func (h *AdjustmentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *AdjustmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
