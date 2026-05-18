package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type ProductionHandler struct {
	prodService service.ProductionService
	logger      *zap.Logger
}

func NewProductionHandler(prodService service.ProductionService, logger *zap.Logger) *ProductionHandler {
	return &ProductionHandler{
		prodService: prodService,
		logger:      logger.Named("production_handler"),
	}
}

// ---------- Request/Response Types ----------

type createProductionOrderRequest struct {
	OrderNumber         string  `json:"order_number"`
	ProductItemID       string  `json:"product_item_id"`
	BOMID               string  `json:"bom_id"`
	PlannedQuantity     float64 `json:"planned_quantity"`
	PlannedStartDate    *string `json:"planned_start_date,omitempty"`
	PlannedEndDate      *string `json:"planned_end_date,omitempty"`
	WarehouseID         string  `json:"warehouse_id"`
	SourceReferenceType *string `json:"source_reference_type,omitempty"`
	SourceReferenceID   *string `json:"source_reference_id,omitempty"`
}

type releaseProductionOrderRequest struct{}
type startProductionOrderRequest struct{}
type cancelProductionOrderRequest struct {
	Reason string `json:"reason"`
}

type completeProductionOrderRequest struct {
	ProducedQuantity float64 `json:"produced_quantity"`
	// ComponentQuantities removed – components must be consumed via separate endpoint
}

type consumeComponentRequest struct {
	ComponentID string  `json:"component_id"`
	Quantity    float64 `json:"quantity"`
	BatchID     *string `json:"batch_id,omitempty"`
	Notes       string  `json:"notes,omitempty"`
}

type recordScrapRequest struct {
	ComponentID   *string `json:"component_id,omitempty"` // nil = scrap finished good
	ItemID        string  `json:"item_id"`
	BatchID       *string `json:"batch_id,omitempty"`
	ScrapQuantity float64 `json:"scrap_quantity"`
	Reason        string  `json:"reason"`
}

type productionOrderResponse struct {
	ProductionOrderID   string     `json:"production_order_id"`
	CompanyID           string     `json:"company_id"`
	OrderNumber         string     `json:"order_number"`
	ProductItemID       string     `json:"product_item_id"`
	BOMID               string     `json:"bom_id"`
	PlannedQuantity     float64    `json:"planned_quantity"`
	ProducedQuantity    float64    `json:"produced_quantity"`
	Status              string     `json:"status"`
	PlannedStartDate    *time.Time `json:"planned_start_date,omitempty"`
	PlannedEndDate      *time.Time `json:"planned_end_date,omitempty"`
	ActualStartTime     *time.Time `json:"actual_start_time,omitempty"`
	ActualEndTime       *time.Time `json:"actual_end_time,omitempty"`
	WarehouseID         string     `json:"warehouse_id"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	CreatedBy           *string    `json:"created_by,omitempty"`
	SourceReferenceType *string    `json:"source_reference_type,omitempty"`
	SourceReferenceID   *string    `json:"source_reference_id,omitempty"`
}

func toProductionOrderResponse(order *models.ProductionOrder) productionOrderResponse {
	resp := productionOrderResponse{
		ProductionOrderID:   order.ProductionOrderID.String(),
		CompanyID:           order.CompanyID.String(),
		OrderNumber:         order.OrderNumber,
		ProductItemID:       order.ProductItemID.String(),
		BOMID:               order.BOMID.String(),
		PlannedQuantity:     toFloat64(order.PlannedQuantity),
		ProducedQuantity:    toFloat64(order.ProducedQuantity),
		Status:              order.Status,
		PlannedStartDate:    order.PlannedStartDate,
		PlannedEndDate:      order.PlannedEndDate,
		ActualStartTime:     order.ActualStartTime,
		ActualEndTime:       order.ActualEndTime,
		WarehouseID:         order.WarehouseID.String(),
		CreatedAt:           order.CreatedAt,
		UpdatedAt:           order.UpdatedAt,
		SourceReferenceType: order.SourceReferenceType,
	}
	if order.CreatedBy != nil {
		cb := order.CreatedBy.String()
		resp.CreatedBy = &cb
	}
	if order.SourceReferenceID != nil {
		srid := order.SourceReferenceID.String()
		resp.SourceReferenceID = &srid
	}
	return resp
}

func toFloat64(d decimal.Decimal) float64 {
	f, _ := d.Float64()
	return f
}

// ---------- Helper functions ----------

func parseUUIDParam(r *http.Request, param string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, param)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", param)
	}
	return uuid.Parse(idStr)
}

func getCompanyIDFromRequest(r *http.Request) (uuid.UUID, error) {
	return parseUUIDParam(r, "companyID")
}

func getProductionOrderIDFromRequest(r *http.Request) (uuid.UUID, error) {
	return parseUUIDParam(r, "id")
}

func getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// ---------- Create ----------
func (h *ProductionHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createProductionOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.OrderNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "order_number is required")
		return
	}
	if req.ProductItemID == "" {
		h.respondWithError(w, http.StatusBadRequest, "product_item_id is required")
		return
	}
	if req.BOMID == "" {
		h.respondWithError(w, http.StatusBadRequest, "bom_id is required")
		return
	}
	if req.WarehouseID == "" {
		h.respondWithError(w, http.StatusBadRequest, "warehouse_id is required")
		return
	}
	if req.PlannedQuantity <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "planned_quantity must be positive")
		return
	}

	productItemID, err := uuid.Parse(req.ProductItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product_item_id")
		return
	}
	bomID, err := uuid.Parse(req.BOMID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid bom_id")
		return
	}
	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}
	var sourceReferenceID *uuid.UUID
	if req.SourceReferenceID != nil && *req.SourceReferenceID != "" {
		id, err := uuid.Parse(*req.SourceReferenceID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid source_reference_id")
			return
		}
		sourceReferenceID = &id
	}

	var plannedStartDate, plannedEndDate *time.Time
	if req.PlannedStartDate != nil && *req.PlannedStartDate != "" {
		t, err := time.Parse(time.RFC3339, *req.PlannedStartDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid planned_start_date format (use RFC3339)")
			return
		}
		plannedStartDate = &t
	}
	if req.PlannedEndDate != nil && *req.PlannedEndDate != "" {
		t, err := time.Parse(time.RFC3339, *req.PlannedEndDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid planned_end_date format (use RFC3339)")
			return
		}
		plannedEndDate = &t
	}

	serviceReq := service.CreateProductionOrderRequest{
		CompanyID:           companyID,
		OrderNumber:         req.OrderNumber,
		ProductItemID:       productItemID,
		BOMID:               bomID,
		PlannedQuantity:     decimal.NewFromFloat(req.PlannedQuantity),
		PlannedStartDate:    plannedStartDate,
		PlannedEndDate:      plannedEndDate,
		WarehouseID:         warehouseID,
		CreatedBy:           &userID,
		SourceReferenceType: req.SourceReferenceType,
		SourceReferenceID:   sourceReferenceID,
	}

	order, err := h.prodService.CreateProductionOrder(ctx, serviceReq, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to create production order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInactiveBOM):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    toProductionOrderResponse(order),
		"message": "Production order created successfully",
	})
}

// ---------- Release ----------
func (h *ProductionHandler) Release(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:release") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.prodService.ReleaseProductionOrder(ctx, orderID, companyID, &userID, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to release production order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to release production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Production order released successfully",
	})
}

// ---------- Start ----------
func (h *ProductionHandler) Start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:start") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.prodService.StartProduction(ctx, orderID, companyID, &userID, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to start production order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to start production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Production order started successfully",
	})
}

// ---------- ConsumeComponent (partial consumption) ----------
func (h *ProductionHandler) ConsumeComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:consume") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req consumeComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ComponentID == "" {
		h.respondWithError(w, http.StatusBadRequest, "component_id is required")
		return
	}
	if req.Quantity <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "quantity must be positive")
		return
	}
	componentID, err := uuid.Parse(req.ComponentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid component_id")
		return
	}

	var batchID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		id, err := uuid.Parse(*req.BatchID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		batchID = &id
	}

	serviceReq := service.ConsumeComponentRequest{
		ProductionOrderID: orderID,
		CompanyID:         companyID,
		ComponentID:       componentID,
		Quantity:          decimal.NewFromFloat(req.Quantity),
		BatchID:           batchID,
		ConsumedBy:        &userID,
		Notes:             req.Notes,
	}

	err = h.prodService.ConsumeComponent(ctx, serviceReq, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to consume component", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidQuantity):
			h.respondWithError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to consume component")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Component consumed successfully",
	})
}

// ---------- RecordScrap ----------
func (h *ProductionHandler) RecordScrap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:scrap") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req recordScrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ItemID == "" {
		h.respondWithError(w, http.StatusBadRequest, "item_id is required")
		return
	}
	if req.ScrapQuantity <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "scrap_quantity must be positive")
		return
	}
	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}

	var componentID *uuid.UUID
	if req.ComponentID != nil && *req.ComponentID != "" {
		id, err := uuid.Parse(*req.ComponentID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid component_id")
			return
		}
		componentID = &id
	}

	var batchID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		id, err := uuid.Parse(*req.BatchID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		batchID = &id
	}

	serviceReq := service.RecordScrapRequest{
		ProductionOrderID: orderID,
		CompanyID:         companyID,
		ComponentID:       componentID,
		ItemID:            itemID,
		BatchID:           batchID,
		ScrapQuantity:     decimal.NewFromFloat(req.ScrapQuantity),
		Reason:            req.Reason,
		RecordedBy:        &userID,
	}

	err = h.prodService.RecordScrap(ctx, serviceReq, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to record scrap", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to record scrap")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Scrap recorded successfully",
	})
}

// ---------- Complete ----------
func (h *ProductionHandler) Complete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:complete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req completeProductionOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ProducedQuantity <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "produced_quantity must be positive")
		return
	}

	serviceReq := service.CompleteProductionRequest{
		ProductionOrderID: orderID,
		CompanyID:         companyID,
		ProducedQuantity:  decimal.NewFromFloat(req.ProducedQuantity),
		CompletedBy:       &userID,
	}

	err = h.prodService.CompleteProduction(ctx, serviceReq, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to complete production order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidProductionCompletion):
			h.respondWithError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to complete production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Production order completed successfully",
	})
}

// ---------- Cancel ----------
func (h *ProductionHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req cancelProductionOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.CancelProductionOrderRequest{
		ProductionOrderID: orderID,
		CompanyID:         companyID,
		Reason:            req.Reason,
		CancelledBy:       &userID,
	}

	err = h.prodService.CancelProductionOrder(ctx, serviceReq, getIdempotencyKey(r))
	if err != nil {
		h.logger.Error("failed to cancel production order", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidTransition):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to cancel production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Production order cancelled successfully",
	})
}

// ---------- Get ----------
func (h *ProductionHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	orderID, err := getProductionOrderIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	order, err := h.prodService.GetProductionOrder(ctx, orderID, companyID)
	if err != nil {
		h.logger.Error("failed to get production order", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve production order")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toProductionOrderResponse(order),
	})
}

// ---------- List ----------
func (h *ProductionHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "production:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.ProductionOrderFilter{
		CompanyID: companyID,
	}
	if status := query.Get("status"); status != "" {
		filter.Status = status
	}
	if productItemIDStr := query.Get("product_item_id"); productItemIDStr != "" {
		if pid, err := uuid.Parse(productItemIDStr); err == nil {
			filter.ProductItemID = &pid
		}
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse(time.RFC3339, fromDateStr); err == nil {
			filter.DateFrom = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse(time.RFC3339, toDateStr); err == nil {
			filter.DateTo = &t
		}
	}
	if search := query.Get("search"); search != "" {
		filter.Search = search
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

	orders, total, err := h.prodService.ListProductionOrders(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list production orders", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve production orders")
		return
	}

	items := make([]productionOrderResponse, len(orders))
	for i, o := range orders {
		items[i] = toProductionOrderResponse(o)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":     items,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// ---------- Helper utilities ----------

func (h *ProductionHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Integrate with your permission service (e.g., RBAC)
	// For now, allow all requests.
	return true
}

func (h *ProductionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ProductionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
