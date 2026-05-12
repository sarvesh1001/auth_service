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
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/service"
)

type PickingHandler struct {
	pickingSvc service.PickingService
	logger     *zap.Logger
}

func NewPickingHandler(pickingSvc service.PickingService, logger *zap.Logger) *PickingHandler {
	return &PickingHandler{
		pickingSvc: pickingSvc,
		logger:     logger.Named("picking_handler"),
	}
}

// ------------------------------------------------------------
// Request/Response types
// ------------------------------------------------------------

type generatePickingListRequest struct {
	FulfillmentOrderID string `json:"fulfillment_order_id"`
	WarehouseID        string `json:"warehouse_id"`
}

type assignPickerRequest struct {
	PickerID string `json:"picker_id"`
}

type pickItemRequest struct {
	PickedQty string `json:"picked_qty"`
}

type pickingListItemResponse struct {
	PickingItemID     string `json:"picking_item_id"`
	PickingListID     string `json:"picking_list_id"`
	FulfillmentItemID string `json:"fulfillment_item_id"`
	OrderedQty        string `json:"ordered_qty"`
	PickedQty         string `json:"picked_qty"`
	CreatedAt         string `json:"created_at"`
}

type pickingListResponse struct {
	PickingListID      string                    `json:"picking_list_id"`
	CompanyID          string                    `json:"company_id"`
	FulfillmentOrderID string                    `json:"fulfillment_order_id"`
	WarehouseID        string                    `json:"warehouse_id"`
	Status             string                    `json:"status"`
	AssignedTo         *string                   `json:"assigned_to,omitempty"`
	CreatedAt          string                    `json:"created_at"`
	PickedAt           *string                   `json:"picked_at,omitempty"`
	CompletedAt        *string                   `json:"completed_at,omitempty"`
	Items              []pickingListItemResponse `json:"items,omitempty"`
}

// ------------------------------------------------------------
// Helper functions
// ------------------------------------------------------------

func (h *PickingHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "companyID")
	if idStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *PickingHandler) parsePickingListID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "listID")
	if idStr == "" {
		return uuid.Nil, errors.New("picking list ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *PickingHandler) parsePickingItemID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "itemID")
	if idStr == "" {
		return uuid.Nil, errors.New("picking item ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *PickingHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// In real implementation, check permissions via RBAC.
	return true
}

func (h *PickingHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PickingHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *PickingHandler) respondWithInventoryError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, inventory_errors.ErrNotFound):
		h.respondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidInput):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, inventory_errors.ErrDuplicate):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory_errors.ErrPermissionDenied):
		h.respondWithError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidTransition):
		h.respondWithError(w, http.StatusConflict, err.Error())
	default:
		h.logger.Error("unexpected error", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

// ------------------------------------------------------------
// Handlers
// ------------------------------------------------------------

// GeneratePickingList POST /api/v1/companies/{companyID}/inventory/picking/lists
func (h *PickingHandler) GeneratePickingList(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "picking:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req generatePickingListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FulfillmentOrderID == "" {
		h.respondWithError(w, http.StatusBadRequest, "fulfillment_order_id is required")
		return
	}
	fulfillmentOrderID, err := uuid.Parse(req.FulfillmentOrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fulfillment_order_id")
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

	svcReq := service.GeneratePickingListRequest{
		CompanyID:          companyID,
		FulfillmentOrderID: fulfillmentOrderID,
		WarehouseID:        warehouseID,
		GeneratedBy:        &userID,
	}

	list, err := h.pickingSvc.GeneratePickingList(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to generate picking list", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toPickingListResponse(list, nil),
		"message": "Picking list generated successfully",
	})
}

// AssignPicker POST /api/v1/companies/{companyID}/inventory/picking/lists/{listID}/assign
func (h *PickingHandler) AssignPicker(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	listID, err := h.parsePickingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "picking:assign") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req assignPickerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PickerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "picker_id is required")
		return
	}
	pickerID, err := uuid.Parse(req.PickerID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid picker_id")
		return
	}

	err = h.pickingSvc.AssignPicker(ctx, listID, pickerID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to assign picker", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Picker assigned successfully",
	})
}

// PickItem POST /api/v1/companies/{companyID}/inventory/picking/lists/{listID}/items/{itemID}/pick
func (h *PickingHandler) PickItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemID, err := h.parsePickingItemID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "picking:execute") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req pickItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PickedQty == "" {
		h.respondWithError(w, http.StatusBadRequest, "picked_qty is required")
		return
	}
	pickedQty, err := decimal.NewFromString(req.PickedQty)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid picked_qty")
		return
	}
	if pickedQty.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "picked_qty must be positive")
		return
	}

	err = h.pickingSvc.PickItem(ctx, itemID, pickedQty, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to pick item", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Item picked successfully",
	})
}

// CompletePicking POST /api/v1/companies/{companyID}/inventory/picking/lists/{listID}/complete
func (h *PickingHandler) CompletePicking(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	listID, err := h.parsePickingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "picking:complete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.pickingSvc.CompletePicking(ctx, listID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to complete picking", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Picking completed successfully",
	})
}

// GetPickingList GET /api/v1/companies/{companyID}/inventory/picking/lists/{listID}
func (h *PickingHandler) GetPickingList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	listID, err := h.parsePickingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "picking:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	list, items, err := h.pickingSvc.GetPickingList(ctx, listID, companyID)
	if err != nil {
		h.logger.Error("failed to get picking list", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toPickingListResponse(list, items),
	})
}

// ListPickingLists GET /api/v1/companies/{companyID}/inventory/picking/lists
func (h *PickingHandler) ListPickingLists(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "picking:read") {
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

	lists, total, err := h.pickingSvc.ListPickingListsByCompany(ctx, companyID, status, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list picking lists", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	resp := make([]pickingListResponse, 0, len(lists))
	for _, l := range lists {
		resp = append(resp, h.toPickingListResponse(l, nil))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      resp,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// ------------------------------------------------------------
// Response converters
// ------------------------------------------------------------

func (h *PickingHandler) toPickingListResponse(list *models.PickingList, items []*models.PickingListItem) pickingListResponse {
	resp := pickingListResponse{
		PickingListID:      list.PickingListID.String(),
		CompanyID:          list.CompanyID.String(),
		FulfillmentOrderID: list.FulfillmentOrderID.String(),
		WarehouseID:        list.WarehouseID.String(),
		Status:             list.Status,
		CreatedAt:          list.CreatedAt.Format(time.RFC3339),
	}
	if list.AssignedTo != nil {
		assigned := list.AssignedTo.String()
		resp.AssignedTo = &assigned
	}
	if list.PickedAt != nil {
		t := list.PickedAt.Format(time.RFC3339)
		resp.PickedAt = &t
	}
	if list.CompletedAt != nil {
		t := list.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &t
	}
	if items != nil {
		resp.Items = make([]pickingListItemResponse, len(items))
		for i, it := range items {
			resp.Items[i] = pickingListItemResponse{
				PickingItemID:     it.PickingItemID.String(),
				PickingListID:     it.PickingListID.String(),
				FulfillmentItemID: it.FulfillmentItemID.String(),
				OrderedQty:        it.OrderedQty.String(),
				PickedQty:         it.PickedQty.String(),
				CreatedAt:         it.CreatedAt.Format(time.RFC3339),
			}
		}
	}
	return resp
}
