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
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type PackingHandler struct {
	packingSvc service.PackingService
	logger     *zap.Logger
}

func NewPackingHandler(packingSvc service.PackingService, logger *zap.Logger) *PackingHandler {
	return &PackingHandler{
		packingSvc: packingSvc,
		logger:     logger.Named("packing_handler"),
	}
}

// request/response types

type generatePackingListRequest struct {
	ShipmentID string `json:"shipment_id"`
}

type packItemRequest struct {
	PackingItemID string `json:"packing_item_id"`
	PackedQty     string `json:"packed_qty"`
}

type bulkPackItemsRequest struct {
	Items []packItemRequest `json:"items"`
}

type verifyPackingRequest struct {
	ListID string `json:"list_id"`
}

type packingListResponse struct {
	PackingListID string     `json:"packing_list_id"`
	CompanyID     string     `json:"company_id"`
	ShipmentID    string     `json:"shipment_id"`
	Status        string     `json:"status"`
	PackedBy      *string    `json:"packed_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	PackedAt      *time.Time `json:"packed_at,omitempty"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

type packingListItemResponse struct {
	PackingItemID  string `json:"packing_item_id"`
	PackingListID  string `json:"packing_list_id"`
	ShipmentItemID string `json:"shipment_item_id"`
	PackedQty      string `json:"packed_qty"`
	CreatedAt      string `json:"created_at"`
}

// helper functions

func (h *PackingHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *PackingHandler) parsePackingListID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "listID")
	if idStr == "" {
		return uuid.Nil, errors.New("packing list ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *PackingHandler) parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v >= 1 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v >= 1 && v <= 100 {
			pageSize = v
		}
	}
	return page, pageSize
}

func (h *PackingHandler) decimalFromString(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, errors.New("empty decimal value")
	}
	return decimal.NewFromString(s)
}

func (h *PackingHandler) toPackingListResponse(list *models.PackingList) packingListResponse {
	resp := packingListResponse{
		PackingListID: list.PackingListID.String(),
		CompanyID:     list.CompanyID.String(),
		ShipmentID:    list.ShipmentID.String(),
		Status:        list.Status,
		CreatedAt:     list.CreatedAt,
		PackedAt:      list.PackedAt,
		VerifiedAt:    list.VerifiedAt,
		CompletedAt:   list.CompletedAt,
	}
	if list.PackedBy != nil {
		pb := list.PackedBy.String()
		resp.PackedBy = &pb
	}
	return resp
}

func (h *PackingHandler) toPackingListItemResponse(item *models.PackingListItem) packingListItemResponse {
	return packingListItemResponse{
		PackingItemID:  item.PackingItemID.String(),
		PackingListID:  item.PackingListID.String(),
		ShipmentItemID: item.ShipmentItemID.String(),
		PackedQty:      item.PackedQty.String(),
		CreatedAt:      item.CreatedAt.Format(time.RFC3339),
	}
}

// permission stub (to be replaced with actual permission check)
func (h *PackingHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: implement real permission check using JWT claims or RBAC
	return true
}

// handlers

func (h *PackingHandler) GeneratePackingList(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	var req generatePackingListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	shipmentID, err := uuid.Parse(req.ShipmentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid shipment_id")
		return
	}
	svcReq := service.GeneratePackingListRequest{
		CompanyID:  companyID,
		ShipmentID: shipmentID,
		CreatedBy:  &userID,
	}
	list, err := h.packingSvc.GeneratePackingList(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to generate packing list", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toPackingListResponse(list),
		"message": "Packing list generated successfully",
	})
}

func (h *PackingHandler) GetPackingList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	listID, err := h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.view") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	list, err := h.packingSvc.GetPackingListByID(ctx, listID)
	if err != nil {
		h.logger.Error("failed to get packing list", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve packing list")
		return
	}
	if list.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "packing list does not belong to this company")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toPackingListResponse(list),
	})
}

func (h *PackingHandler) ListPackingLists(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.view") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	filter := repository.PackingListFilter{
		CompanyID: companyID,
	}
	if shipmentIDStr := r.URL.Query().Get("shipment_id"); shipmentIDStr != "" {
		id, err := uuid.Parse(shipmentIDStr)
		if err == nil {
			filter.ShipmentID = &id
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	page, pageSize := h.parsePagination(r)
	lists, total, err := h.packingSvc.ListPackingLists(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list packing lists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve packing lists")
		return
	}
	items := make([]packingListResponse, 0, len(lists))
	for _, l := range lists {
		items = append(items, h.toPackingListResponse(l))
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

func (h *PackingHandler) VerifyPacking(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	listID, err := h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	req := service.VerifyPackingRequest{
		CompanyID:     companyID,
		PackingListID: listID,
		VerifiedBy:    &userID,
	}
	if err := h.packingSvc.VerifyPacking(ctx, req, idempotencyKey); err != nil {
		h.logger.Error("failed to verify packing", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Packing list verified successfully",
	})
}

func (h *PackingHandler) CompletePacking(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	listID, err := h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	if err := h.packingSvc.CompletePacking(ctx, listID, &userID, idempotencyKey); err != nil {
		h.logger.Error("failed to complete packing", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Packing list completed successfully",
	})
}

func (h *PackingHandler) PackItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	var req packItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	packingItemID, err := uuid.Parse(req.PackingItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid packing_item_id")
		return
	}
	packedQty, err := h.decimalFromString(req.PackedQty)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid packed_qty")
		return
	}
	svcReq := service.PackItemRequest{
		CompanyID:     companyID,
		PackingItemID: packingItemID,
		PackedQty:     packedQty,
		PackedBy:      &userID,
	}
	if err := h.packingSvc.PackItem(ctx, svcReq, idempotencyKey); err != nil {
		h.logger.Error("failed to pack item", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Item packed successfully",
	})
}

func (h *PackingHandler) BulkPackItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	var req bulkPackItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	bulkReq := service.BulkPackItemsRequest{
		CompanyID: companyID,
		Items:     make([]service.PackItemRequest, 0, len(req.Items)),
		PackedBy:  &userID,
	}
	for _, it := range req.Items {
		packingItemID, err := uuid.Parse(it.PackingItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid packing_item_id in bulk")
			return
		}
		packedQty, err := h.decimalFromString(it.PackedQty)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid packed_qty in bulk")
			return
		}
		bulkReq.Items = append(bulkReq.Items, service.PackItemRequest{
			CompanyID:     companyID,
			PackingItemID: packingItemID,
			PackedQty:     packedQty,
			PackedBy:      &userID,
		})
	}
	if err := h.packingSvc.BulkPackItems(ctx, bulkReq, idempotencyKey); err != nil {
		h.logger.Error("failed to bulk pack items", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Items packed successfully",
	})
}

func (h *PackingHandler) GetPackingListItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	listID, err := h.parsePackingListID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "inventory.stock.view") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	list, err := h.packingSvc.GetPackingListByID(ctx, listID)
	if err != nil {
		h.logger.Error("failed to get packing list", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve packing list")
		return
	}
	if list.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "packing list does not belong to this company")
		return
	}
	items, err := h.packingSvc.GetPackingListItems(ctx, listID)
	if err != nil {
		h.logger.Error("failed to get packing list items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve packing list items")
		return
	}
	respItems := make([]packingListItemResponse, 0, len(items))
	for _, it := range items {
		respItems = append(respItems, h.toPackingListItemResponse(it))
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    respItems,
	})
}

// helper response methods

func (h *PackingHandler) respondWithInventoryError(w http.ResponseWriter, err error) {
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
	case errors.Is(err, inventory_errors.ErrInsufficientStock):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory_errors.ErrInvalidTransition):
		h.respondWithError(w, http.StatusConflict, err.Error())
	default:
		h.logger.Error("unexpected error", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

func (h *PackingHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PackingHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
