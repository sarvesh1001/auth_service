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
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

// SerialNumberHandler handles HTTP requests for serialized inventory.
type SerialNumberHandler struct {
	serialSvc service.SerialNumberService
	logger    *zap.Logger
}

// NewSerialNumberHandler creates a new handler instance.
func NewSerialNumberHandler(serialSvc service.SerialNumberService, logger *zap.Logger) *SerialNumberHandler {
	return &SerialNumberHandler{
		serialSvc: serialSvc,
		logger:    logger.Named("serial_number_handler"),
	}
}

// ---------- Request/Response Types ----------

type registerSerialNumbersRequest struct {
	ItemID        string   `json:"item_id"`
	SerialNumbers []string `json:"serial_numbers"`
	WarehouseID   *string  `json:"warehouse_id,omitempty"`
	BatchID       *string  `json:"batch_id,omitempty"`
	Status        *string  `json:"status,omitempty"` // optional, default "available"
}

type assignSerialToWarehouseRequest struct {
	WarehouseID string `json:"warehouse_id"`
}

type assignSerialToBatchRequest struct {
	BatchID string `json:"batch_id"`
}

type updateSerialStatusRequest struct {
	Status string `json:"status"`
}

type serialNumberResponse struct {
	SerialID     string    `json:"serial_id"`
	CompanyID    string    `json:"company_id"`
	ItemID       string    `json:"item_id"`
	SerialNumber string    `json:"serial_number"`
	WarehouseID  *string   `json:"warehouse_id,omitempty"`
	BatchID      *string   `json:"batch_id,omitempty"`
	Status       *string   `json:"status,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// ---------- Helper: convert model to response ----------
func toSerialNumberResponse(s *models.SerialNumber) serialNumberResponse {
	resp := serialNumberResponse{
		SerialID:     s.SerialID.String(),
		CompanyID:    s.CompanyID.String(),
		ItemID:       s.ItemID.String(),
		SerialNumber: s.SerialNumber,
		CreatedAt:    s.CreatedAt,
	}
	if s.WarehouseID != nil {
		wh := s.WarehouseID.String()
		resp.WarehouseID = &wh
	}
	if s.BatchID != nil {
		b := s.BatchID.String()
		resp.BatchID = &b
	}
	if s.Status != nil {
		resp.Status = s.Status
	}
	return resp
}

// ---------- Handlers ----------

// RegisterSerialNumbers handles POST /serials/register
func (h *SerialNumberHandler) RegisterSerialNumbers(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "serial:register") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req registerSerialNumbersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ItemID == "" {
		h.respondWithError(w, http.StatusBadRequest, "item_id is required")
		return
	}
	itemUUID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}
	if len(req.SerialNumbers) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one serial_number required")
		return
	}

	var warehouseUUID *uuid.UUID
	if req.WarehouseID != nil && *req.WarehouseID != "" {
		parsed, err := uuid.Parse(*req.WarehouseID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
			return
		}
		warehouseUUID = &parsed
	}

	var batchUUID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		parsed, err := uuid.Parse(*req.BatchID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		batchUUID = &parsed
	}

	svcReq := service.RegisterSerialNumbersRequest{
		CompanyID:     companyID,
		ItemID:        itemUUID,
		SerialNumbers: req.SerialNumbers,
		WarehouseID:   warehouseUUID,
		BatchID:       batchUUID,
		Status:        req.Status,
		CreatedBy:     &userID,
	}

	serials, err := h.serialSvc.RegisterSerialNumbers(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to register serial numbers", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to register serial numbers")
		}
		return
	}

	responses := make([]serialNumberResponse, len(serials))
	for i, s := range serials {
		responses[i] = toSerialNumberResponse(s)
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    responses,
		"message": "Serial numbers registered successfully",
	})
}

// AssignToWarehouse handles PATCH /serials/{id}/warehouse
func (h *SerialNumberHandler) AssignToWarehouse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	serialID, err := h.parseSerialID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "serial:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req assignSerialToWarehouseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
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

	if err := h.serialSvc.AssignSerialToWarehouse(ctx, serialID, warehouseID, companyID, &userID, idempotencyKey); err != nil {
		h.logger.Error("failed to assign serial to warehouse", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to assign serial")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Serial assigned to warehouse successfully",
	})
}

// AssignToBatch handles PATCH /serials/{id}/batch
func (h *SerialNumberHandler) AssignToBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	serialID, err := h.parseSerialID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "serial:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req assignSerialToBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.BatchID == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_id is required")
		return
	}
	batchID, err := uuid.Parse(req.BatchID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
		return
	}

	if err := h.serialSvc.AssignSerialToBatch(ctx, serialID, batchID, companyID, &userID, idempotencyKey); err != nil {
		h.logger.Error("failed to assign serial to batch", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to assign serial to batch")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Serial assigned to batch successfully",
	})
}

// UpdateStatus handles PATCH /serials/{id}/status
func (h *SerialNumberHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	serialID, err := h.parseSerialID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "serial:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req updateSerialStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}

	if err := h.serialSvc.UpdateSerialStatus(ctx, serialID, companyID, req.Status, &userID, idempotencyKey); err != nil {
		h.logger.Error("failed to update serial status", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to update status")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Serial status updated successfully",
	})
}

// GetByID handles GET /serials/{id}
func (h *SerialNumberHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	serialID, err := h.parseSerialID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "serial:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	serial, err := h.serialSvc.GetSerialByID(ctx, serialID, companyID)
	if err != nil {
		h.logger.Error("failed to get serial by ID", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve serial")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toSerialNumberResponse(serial),
	})
}

// GetByNumber handles GET /serials/by-number?number=...
func (h *SerialNumberHandler) GetByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	serialNumber := r.URL.Query().Get("number")
	if serialNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "serial:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	serial, err := h.serialSvc.GetSerialByNumber(ctx, companyID, serialNumber)
	if err != nil {
		h.logger.Error("failed to get serial by number", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve serial")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toSerialNumberResponse(serial),
	})
}

// List handles GET /serials with filters and pagination
func (h *SerialNumberHandler) List(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "serial:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := h.parseSerialFilter(r, companyID)

	page, pageSize := h.parsePagination(r)
	serials, total, err := h.serialSvc.ListSerials(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list serials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list serials")
		return
	}

	responses := make([]serialNumberResponse, len(serials))
	for i, s := range serials {
		responses[i] = toSerialNumberResponse(s)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":      responses,
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// ---------- Helper functions ----------

func (h *SerialNumberHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "companyID")
	if idStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *SerialNumberHandler) parseSerialID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		return uuid.Nil, errors.New("serial ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *SerialNumberHandler) parseSerialFilter(r *http.Request, companyID uuid.UUID) repository.SerialFilter {
	filter := repository.SerialFilter{CompanyID: companyID}
	query := r.URL.Query()

	if itemIDStr := query.Get("item_id"); itemIDStr != "" {
		if id, err := uuid.Parse(itemIDStr); err == nil {
			filter.ItemID = &id
		}
	}
	if whIDStr := query.Get("warehouse_id"); whIDStr != "" {
		if id, err := uuid.Parse(whIDStr); err == nil {
			filter.WarehouseID = &id
		}
	}
	if batchIDStr := query.Get("batch_id"); batchIDStr != "" {
		if id, err := uuid.Parse(batchIDStr); err == nil {
			filter.BatchID = &id
		}
	}
	if status := query.Get("status"); status != "" {
		filter.Status = &status
	}
	if search := query.Get("search"); search != "" {
		filter.Search = search
	}
	return filter
}

func (h *SerialNumberHandler) parsePagination(r *http.Request) (page, pageSize int) {
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

func (h *SerialNumberHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with real permission logic
	return true
}

func (h *SerialNumberHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *SerialNumberHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
