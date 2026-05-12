// FILE: ./handler/shipment_handler.go
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

type ShipmentHandler struct {
	shipmentService    service.ShipmentService
	fulfillmentService service.FulfillmentService
	logger             *zap.Logger
}

func NewShipmentHandler(
	shipmentService service.ShipmentService,
	fulfillmentService service.FulfillmentService,
	logger *zap.Logger,
) *ShipmentHandler {
	return &ShipmentHandler{
		shipmentService:    shipmentService,
		fulfillmentService: fulfillmentService,
		logger:             logger.Named("shipment_handler"),
	}
}

// -------------------- Request/Response DTOs --------------------

type createShipmentRequest struct {
	FulfillmentOrderID string     `json:"fulfillment_order_id"`
	WarehouseID        string     `json:"warehouse_id"`
	ShipmentNumber     string     `json:"shipment_number,omitempty"`
	ShipmentStatus     string     `json:"shipment_status,omitempty"`
	ShippedAt          *time.Time `json:"shipped_at,omitempty"`
	DeliveredAt        *time.Time `json:"delivered_at,omitempty"`
}

type updateShipmentStatusRequest struct {
	Status      string     `json:"status"`
	ShippedAt   *time.Time `json:"shipped_at,omitempty"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

type shipmentResponse struct {
	ShipmentID         string     `json:"shipment_id"`
	CompanyID          string     `json:"company_id"`
	FulfillmentOrderID string     `json:"fulfillment_order_id"`
	WarehouseID        string     `json:"warehouse_id"`
	ShipmentNumber     string     `json:"shipment_number"`
	ShipmentStatus     string     `json:"shipment_status"`
	ShippedAt          *time.Time `json:"shipped_at,omitempty"`
	DeliveredAt        *time.Time `json:"delivered_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

func toShipmentResponse(s *models.Shipment) shipmentResponse {
	return shipmentResponse{
		ShipmentID:         s.ShipmentID.String(),
		CompanyID:          s.CompanyID.String(),
		FulfillmentOrderID: s.FulfillmentOrderID.String(),
		WarehouseID:        s.WarehouseID.String(),
		ShipmentNumber:     s.ShipmentNumber,
		ShipmentStatus:     s.ShipmentStatus,
		ShippedAt:          s.ShippedAt,
		DeliveredAt:        s.DeliveredAt,
		CreatedAt:          s.CreatedAt,
	}
}

// -------------------- Handlers --------------------

// CreateShipment POST /api/v1/companies/{companyID}/shipments
func (h *ShipmentHandler) CreateShipment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "shipment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createShipmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	fulfillmentOrderID, err := uuid.Parse(req.FulfillmentOrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fulfillment_order_id")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	svcReq := service.CreateShipmentRequest{
		CompanyID:          companyID,
		FulfillmentOrderID: fulfillmentOrderID,
		WarehouseID:        warehouseID,
		ShipmentNumber:     req.ShipmentNumber,
		ShipmentStatus:     req.ShipmentStatus,
		ShippedAt:          req.ShippedAt,
		DeliveredAt:        req.DeliveredAt,
		CreatedBy:          &userID,
	}

	shipment, err := h.shipmentService.CreateShipment(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create shipment", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create shipment")
		}
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    toShipmentResponse(shipment),
		"message": "Shipment created successfully",
	})
}

// GetShipment GET /api/v1/companies/{companyID}/shipments/{id}
func (h *ShipmentHandler) GetShipment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	shipmentID, err := parseShipmentIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "shipment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	shipment, err := h.shipmentService.GetShipmentByID(ctx, shipmentID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "shipment not found")
			return
		}
		h.logger.Error("failed to get shipment", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve shipment")
		return
	}
	if shipment.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "shipment does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toShipmentResponse(shipment),
	})
}

// ListShipments GET /api/v1/companies/{companyID}/shipments
func (h *ShipmentHandler) ListShipments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "shipment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	var status *string
	if s := query.Get("status"); s != "" {
		status = &s
	}
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

	shipments, total, err := h.shipmentService.ListShipments(ctx, companyID, status, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list shipments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve shipments")
		return
	}

	items := make([]shipmentResponse, len(shipments))
	for i, s := range shipments {
		items[i] = toShipmentResponse(s)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      items,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// Ship POST /api/v1/companies/{companyID}/shipments/{id}/ship
func (h *ShipmentHandler) Ship(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	shipmentID, err := parseShipmentIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "shipment:ship") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	// Optionally read a reason or other metadata from body
	// Not required by current spec, but we leave it for future.

	err = h.fulfillmentService.Ship(ctx, shipmentID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to ship", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to ship")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Shipment shipped successfully",
	})
}

// Deliver POST /api/v1/companies/{companyID}/shipments/{id}/deliver
func (h *ShipmentHandler) Deliver(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	shipmentID, err := parseShipmentIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "shipment:deliver") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.fulfillmentService.Deliver(ctx, shipmentID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to deliver shipment", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to deliver shipment")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Shipment delivered successfully",
	})
}

// -------------------- Helper Functions --------------------

func parseShipmentIDFromRequest(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		return uuid.Nil, errors.New("shipment ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *ShipmentHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with real permission check
	return true
}

func (h *ShipmentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ShipmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
