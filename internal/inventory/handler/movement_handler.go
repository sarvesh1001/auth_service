package handler

import (
	"context"
	"encoding/json"
	"fmt"
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

type MovementHandler struct {
	movementService service.MovementService
	logger          *zap.Logger
}

func NewMovementHandler(movementService service.MovementService, logger *zap.Logger) *MovementHandler {
	return &MovementHandler{
		movementService: movementService,
		logger:          logger.Named("movement_handler"),
	}
}

// createMovementJSONRequest represents the JSON body for creating a movement.
type createMovementJSONRequest struct {
	MovementType    string    `json:"movement_type"`
	MovementDate    time.Time `json:"movement_date"`
	WarehouseID     string    `json:"warehouse_id"`
	FromWarehouseID *string   `json:"from_warehouse_id,omitempty"`
	ItemID          string    `json:"item_id"`
	BatchID         *string   `json:"batch_id,omitempty"`
	QuantityIn      float64   `json:"quantity_in"`
	QuantityOut     float64   `json:"quantity_out"`
	UnitCost        float64   `json:"unit_cost"`
	Reason          *string   `json:"reason,omitempty"`
	ReferenceType   *string   `json:"reference_type,omitempty"`
	ReferenceID     *string   `json:"reference_id,omitempty"`
}

// CreateMovement handles POST /companies/{companyID}/movements
func (h *MovementHandler) CreateMovement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(zap.String("handler", "CreateMovement"))

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

	if !h.hasPermission(ctx, companyID, userID, "movement:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required for movement creation")
		return
	}

	var req createMovementJSONRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq, err := h.toCreateMovementRequest(req, companyID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	movement, err := h.movementService.CreateMovement(ctx, serviceReq, idempotencyKey)
	if err != nil {
		logger.Error("failed to create movement", zap.Error(err))
		h.handleServiceError(w, err)
		return
	}

	response := h.movementToJSON(movement)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    response,
		"message": "Movement created successfully",
	})
}

// CancelMovement handles POST /companies/{companyID}/movements/{movementID}/cancel
func (h *MovementHandler) CancelMovement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(zap.String("handler", "CancelMovement"))

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	movementIDStr := chi.URLParam(r, "movementID")
	movementID, err := uuid.Parse(movementIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid movement ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "movement:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required for cancellation")
		return
	}

	var reqBody struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&reqBody) // allow empty body

	cancelReq := service.CancelMovementRequest{
		MovementID:  movementID,
		CompanyID:   companyID,
		Reason:      reqBody.Reason,
		CancelledBy: &userID,
	}

	if err := h.movementService.CancelMovement(ctx, cancelReq, idempotencyKey); err != nil {
		logger.Error("failed to cancel movement", zap.Error(err))
		h.handleServiceError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Movement cancelled successfully",
	})
}

// GetMovement handles GET /companies/{companyID}/movements/{movementID}
func (h *MovementHandler) GetMovement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	movementIDStr := chi.URLParam(r, "movementID")
	movementID, err := uuid.Parse(movementIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid movement ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "movement:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	movement, err := h.movementService.GetMovement(ctx, movementID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if movement.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "movement does not belong to this company")
		return
	}

	response := h.movementToJSON(movement)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// ListMovements handles GET /companies/{companyID}/movements
func (h *MovementHandler) ListMovements(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "movement:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := h.parseMovementFilter(r, companyID)

	// ✅ Validate movement_type if present
	if filter.MovementType != nil && !enums.MovementType(*filter.MovementType).IsValid() {
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid movement_type: %s", *filter.MovementType))
		return
	}

	page, pageSize := h.parsePagination(r)

	movements, total, err := h.movementService.ListMovements(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list movements", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve movements")
		return
	}

	items := make([]interface{}, len(movements))
	for i, m := range movements {
		items[i] = h.movementToJSON(m)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":       items,
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// ------------------- Helper functions -------------------

func (h *MovementHandler) toCreateMovementRequest(req createMovementJSONRequest, companyID, userID uuid.UUID) (service.CreateMovementRequest, error) {
	if !enums.MovementType(req.MovementType).IsValid() {
		return service.CreateMovementRequest{}, fmt.Errorf("invalid movement_type: %s", req.MovementType)
	}
	movementType := enums.MovementType(req.MovementType)

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		return service.CreateMovementRequest{}, fmt.Errorf("invalid warehouse_id: %s", req.WarehouseID)
	}

	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		return service.CreateMovementRequest{}, fmt.Errorf("invalid item_id: %s", req.ItemID)
	}

	var batchID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		id, err := uuid.Parse(*req.BatchID)
		if err != nil {
			return service.CreateMovementRequest{}, fmt.Errorf("invalid batch_id: %s", *req.BatchID)
		}
		batchID = &id
	}

	var fromWarehouseID *uuid.UUID
	if req.FromWarehouseID != nil && *req.FromWarehouseID != "" {
		id, err := uuid.Parse(*req.FromWarehouseID)
		if err != nil {
			return service.CreateMovementRequest{}, fmt.Errorf("invalid from_warehouse_id: %s", *req.FromWarehouseID)
		}
		fromWarehouseID = &id
	}

	var referenceID *uuid.UUID
	if req.ReferenceID != nil && *req.ReferenceID != "" {
		id, err := uuid.Parse(*req.ReferenceID)
		if err != nil {
			return service.CreateMovementRequest{}, fmt.Errorf("invalid reference_id: %s", *req.ReferenceID)
		}
		referenceID = &id
	}

	return service.CreateMovementRequest{
		CompanyID:       companyID,
		MovementType:    movementType,
		MovementDate:    req.MovementDate,
		WarehouseID:     warehouseID,
		FromWarehouseID: fromWarehouseID,
		ItemID:          itemID,
		BatchID:         batchID,
		QuantityIn:      decimal.NewFromFloat(req.QuantityIn),
		QuantityOut:     decimal.NewFromFloat(req.QuantityOut),
		UnitCost:        decimal.NewFromFloat(req.UnitCost),
		Reason:          req.Reason,
		ReferenceType:   req.ReferenceType,
		ReferenceID:     referenceID,
		CreatedBy:       &userID,
	}, nil
}

func (h *MovementHandler) movementToJSON(m *models.StockMovement) map[string]interface{} {
	var batchIDStr *string
	if m.BatchID != nil {
		s := m.BatchID.String()
		batchIDStr = &s
	}
	var fromWarehouseIDStr *string
	if m.FromWarehouseID != nil {
		s := m.FromWarehouseID.String()
		fromWarehouseIDStr = &s
	}
	var referenceIDStr *string
	if m.ReferenceID != nil {
		s := m.ReferenceID.String()
		referenceIDStr = &s
	}
	return map[string]interface{}{
		"movement_id":       m.MovementID.String(),
		"company_id":        m.CompanyID.String(),
		"movement_type":     string(m.MovementType),
		"movement_date":     m.MovementDate,
		"warehouse_id":      m.WarehouseID.String(),
		"from_warehouse_id": fromWarehouseIDStr,
		"item_id":           m.ItemID.String(),
		"batch_id":          batchIDStr,
		"quantity_in":       h.decimalToFloat(m.QuantityIn),
		"quantity_out":      h.decimalToFloat(m.QuantityOut),
		"unit_cost":         h.decimalToFloat(m.UnitCost),
		"total_cost":        h.decimalToFloat(m.TotalCost),
		"reason":            m.Reason,
		"reference_type":    m.ReferenceType,
		"reference_id":      referenceIDStr,
		"created_at":        m.CreatedAt,
		"created_by":        m.CreatedBy,
	}
}

func (h *MovementHandler) parseMovementFilter(r *http.Request, companyID uuid.UUID) repository.MovementFilter {
	query := r.URL.Query()
	filter := repository.MovementFilter{
		CompanyID: companyID,
	}

	if itemIDStr := query.Get("item_id"); itemIDStr != "" {
		if id, err := uuid.Parse(itemIDStr); err == nil {
			filter.ItemID = &id
		}
	}
	if warehouseIDStr := query.Get("warehouse_id"); warehouseIDStr != "" {
		if id, err := uuid.Parse(warehouseIDStr); err == nil {
			filter.WarehouseID = &id
		}
	}
	if movementTypeStr := query.Get("movement_type"); movementTypeStr != "" {
		filter.MovementType = &movementTypeStr
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse(time.RFC3339, fromDateStr); err == nil {
			filter.DateFrom = &t
		} else if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.DateFrom = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse(time.RFC3339, toDateStr); err == nil {
			filter.DateTo = &t
		} else if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.DateTo = &t
		}
	}
	return filter
}

func (h *MovementHandler) parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func (h *MovementHandler) decimalToFloat(d decimal.Decimal) float64 {
	f, _ := d.Float64()
	return f
}

func (h *MovementHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case strings.Contains(err.Error(), inventory_errors.ErrNotFound.Error()):
		h.respondWithError(w, http.StatusNotFound, err.Error())
	case strings.Contains(err.Error(), inventory_errors.ErrInvalidInput.Error()):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case strings.Contains(err.Error(), inventory_errors.ErrPermissionDenied.Error()):
		h.respondWithError(w, http.StatusForbidden, err.Error())
	case strings.Contains(err.Error(), inventory_errors.ErrInsufficientStock.Error()):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case strings.Contains(err.Error(), inventory_errors.ErrConflict.Error()):
		h.respondWithError(w, http.StatusConflict, err.Error())
	default:
		h.logger.Error("unexpected service error", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

func (h *MovementHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: integrate with real authorization service
	return true
}

func (h *MovementHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *MovementHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
