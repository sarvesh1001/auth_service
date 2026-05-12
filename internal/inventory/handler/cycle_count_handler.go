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

// CycleCountHandler handles inventory cycle count endpoints.
type CycleCountHandler struct {
	cycleCountSvc service.CycleCountService
	logger        *zap.Logger
}

// NewCycleCountHandler creates a new CycleCountHandler.
func NewCycleCountHandler(cycleCountSvc service.CycleCountService, logger *zap.Logger) *CycleCountHandler {
	return &CycleCountHandler{
		cycleCountSvc: cycleCountSvc,
		logger:        logger.Named("cycle_count_handler"),
	}
}

// ---------- Request/Response DTOs ----------

type createCycleCountRequest struct {
	WarehouseID      string  `json:"warehouse_id"`
	ItemID           *string `json:"item_id,omitempty"`
	LocationID       *string `json:"location_id,omitempty"`
	CountType        string  `json:"count_type"`
	ScheduledDate    *string `json:"scheduled_date,omitempty"`
	ExpectedQuantity *string `json:"expected_quantity,omitempty"`
}

type startCycleCountRequest struct{}

type completeCycleCountRequest struct {
	ActualQuantity string `json:"actual_quantity"`
	Notes          string `json:"notes,omitempty"`
}

type cancelCycleCountRequest struct {
	Reason string `json:"reason"`
}

type cycleCountResponse struct {
	CycleCountID         string     `json:"cycle_count_id"`
	CompanyID            string     `json:"company_id"`
	WarehouseID          string     `json:"warehouse_id"`
	ItemID               *string    `json:"item_id,omitempty"`
	LocationID           *string    `json:"location_id,omitempty"`
	CountType            string     `json:"count_type"`
	Status               string     `json:"status"`
	ScheduledDate        *time.Time `json:"scheduled_date,omitempty"`
	CountedBy            *string    `json:"counted_by,omitempty"`
	CountedAt            *time.Time `json:"counted_at,omitempty"`
	ExpectedQuantity     string     `json:"expected_quantity"`
	ActualQuantity       string     `json:"actual_quantity"`
	Variance             string     `json:"variance"`
	AdjustmentMovementID *string    `json:"adjustment_movement_id,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ---------- Helper functions ----------

func (h *CycleCountHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *CycleCountHandler) parseCycleCountID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "cycleCountID")
	if idStr == "" {
		idStr = chi.URLParam(r, "countID")
	}
	if idStr == "" {
		return uuid.Nil, errors.New("cycle count ID is required")
	}
	return uuid.Parse(idStr)
}

func (h *CycleCountHandler) toCycleCountResponse(cc *models.InventoryCycleCount) cycleCountResponse {
	resp := cycleCountResponse{
		CycleCountID:     cc.CycleCountID.String(),
		CompanyID:        cc.CompanyID.String(),
		WarehouseID:      cc.WarehouseID.String(),
		CountType:        cc.CountType,
		Status:           cc.Status,
		ScheduledDate:    cc.ScheduledDate,
		CountedAt:        cc.CountedAt,
		ExpectedQuantity: cc.ExpectedQuantity.String(),
		ActualQuantity:   cc.ActualQuantity.String(),
		Variance:         cc.Variance.String(),
		CreatedAt:        cc.CreatedAt,
		UpdatedAt:        cc.UpdatedAt,
	}
	if cc.ItemID != nil {
		s := cc.ItemID.String()
		resp.ItemID = &s
	}
	if cc.LocationID != nil {
		s := cc.LocationID.String()
		resp.LocationID = &s
	}
	if cc.CountedBy != nil {
		s := cc.CountedBy.String()
		resp.CountedBy = &s
	}
	if cc.AdjustmentMovementID != nil {
		s := cc.AdjustmentMovementID.String()
		resp.AdjustmentMovementID = &s
	}
	return resp
}

func (h *CycleCountHandler) parseUUIDPtrFromStringPtr(s *string) *uuid.UUID {
	if s == nil || *s == "" {
		return nil
	}
	if id, err := uuid.Parse(*s); err == nil {
		return &id
	}
	return nil
}

func (h *CycleCountHandler) parseTimePtrFromStringPtr(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", *s)
	if err != nil {
		return nil
	}
	return &t
}

func (h *CycleCountHandler) decimalFromString(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, nil
	}
	return decimal.NewFromString(s)
}

// ---------- Permission stub (replace with actual permission check) ----------
func (h *CycleCountHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// TODO: integrate real permission middleware
	return true
}

// ---------- HTTP Handlers ----------

// CreateCycleCount handles POST /api/v1/companies/{companyID}/inventory/cycle-counts
func (h *CycleCountHandler) CreateCycleCount(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createCycleCountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	itemID := h.parseUUIDPtrFromStringPtr(req.ItemID)
	locationID := h.parseUUIDPtrFromStringPtr(req.LocationID)

	if req.CountType == "" {
		h.respondWithError(w, http.StatusBadRequest, "count_type is required (full, random, abc)")
		return
	}

	scheduledDate := h.parseTimePtrFromStringPtr(req.ScheduledDate)

	var expectedQty decimal.Decimal
	if req.ExpectedQuantity != nil && *req.ExpectedQuantity != "" {
		expectedQty, err = h.decimalFromString(*req.ExpectedQuantity)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid expected_quantity")
			return
		}
	}

	svcReq := service.CreateCycleCountRequest{
		CompanyID:        companyID,
		WarehouseID:      warehouseID,
		ItemID:           itemID,
		LocationID:       locationID,
		CountType:        req.CountType,
		ScheduledDate:    scheduledDate,
		ExpectedQuantity: expectedQty,
		CreatedBy:        &userID,
	}

	cycleCount, err := h.cycleCountSvc.CreateCycleCount(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create cycle count", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toCycleCountResponse(cycleCount),
		"message": "Cycle count created successfully",
	})
}

// StartCycleCount handles POST /api/v1/companies/{companyID}/inventory/cycle-counts/{cycleCountID}/start
func (h *CycleCountHandler) StartCycleCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	cycleCountID, err := h.parseCycleCountID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:start") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.cycleCountSvc.StartCycleCount(ctx, cycleCountID, companyID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to start cycle count", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Cycle count started successfully",
	})
}

// CompleteCycleCount handles POST /api/v1/companies/{companyID}/inventory/cycle-counts/{cycleCountID}/complete
func (h *CycleCountHandler) CompleteCycleCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	cycleCountID, err := h.parseCycleCountID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:complete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req completeCycleCountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actualQty, err := h.decimalFromString(req.ActualQuantity)
	if err != nil || actualQty.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "actual_quantity must be a positive decimal")
		return
	}

	svcReq := service.CompleteCycleCountRequest{
		CycleCountID:   cycleCountID,
		CompanyID:      companyID,
		ActualQuantity: actualQty,
		CountedBy:      &userID,
		Notes:          req.Notes,
	}

	err = h.cycleCountSvc.CompleteCycleCount(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to complete cycle count", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Cycle count completed successfully",
	})
}

// CancelCycleCount handles POST /api/v1/companies/{companyID}/inventory/cycle-counts/{cycleCountID}/cancel
func (h *CycleCountHandler) CancelCycleCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	cycleCountID, err := h.parseCycleCountID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req cancelCycleCountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.cycleCountSvc.CancelCycleCount(ctx, cycleCountID, companyID, &userID, req.Reason, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to cancel cycle count", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Cycle count cancelled successfully",
	})
}

// GetCycleCount handles GET /api/v1/companies/{companyID}/inventory/cycle-counts/{cycleCountID}
func (h *CycleCountHandler) GetCycleCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	cycleCountID, err := h.parseCycleCountID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	cycleCount, err := h.cycleCountSvc.GetCycleCount(ctx, cycleCountID, companyID)
	if err != nil {
		h.logger.Error("failed to get cycle count", zap.Error(err))
		h.respondWithInventoryError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toCycleCountResponse(cycleCount),
	})
}

// ListCycleCounts handles GET /api/v1/companies/{companyID}/inventory/cycle-counts
func (h *CycleCountHandler) ListCycleCounts(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "inventory:cycle_count:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.CycleCountFilter{
		CompanyID: companyID,
	}

	if whIDStr := query.Get("warehouse_id"); whIDStr != "" {
		if id, err := uuid.Parse(whIDStr); err == nil {
			filter.WarehouseID = &id
		}
	}
	if itemIDStr := query.Get("item_id"); itemIDStr != "" {
		if id, err := uuid.Parse(itemIDStr); err == nil {
			filter.ItemID = &id
		}
	}
	if locIDStr := query.Get("location_id"); locIDStr != "" {
		if id, err := uuid.Parse(locIDStr); err == nil {
			filter.LocationID = &id
		}
	}
	if countType := query.Get("count_type"); countType != "" {
		filter.CountType = &countType
	}
	if status := query.Get("status"); status != "" {
		filter.Status = &status
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.DateFrom = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.DateTo = &t
		}
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

	items, total, err := h.cycleCountSvc.ListCycleCounts(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list cycle counts", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve cycle counts")
		return
	}

	responses := make([]cycleCountResponse, len(items))
	for i, cc := range items {
		responses[i] = h.toCycleCountResponse(cc)
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

// ---------- Common Response Helpers ----------

func (h *CycleCountHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *CycleCountHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *CycleCountHandler) respondWithInventoryError(w http.ResponseWriter, err error) {
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
