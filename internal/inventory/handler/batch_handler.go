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

	"auth-service/internal/client"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type BatchHandler struct {
	inventorySvc service.InventoryService
	batchRepo    repository.BatchRepository
	pgClient     *client.PostgresClient
	logger       *zap.Logger
}

func NewBatchHandler(
	inventorySvc service.InventoryService,
	batchRepo repository.BatchRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) *BatchHandler {
	return &BatchHandler{
		inventorySvc: inventorySvc,
		batchRepo:    batchRepo,
		pgClient:     pgClient,
		logger:       logger.Named("batch_handler"),
	}
}

// ---------- Request/Response types ----------

type createBatchRequest struct {
	ItemID           string     `json:"item_id"`
	BatchNumber      string     `json:"batch_number"`
	SupplierBatch    *string    `json:"supplier_batch,omitempty"`
	ManufacturedDate *time.Time `json:"manufactured_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	ReceivedDate     *time.Time `json:"received_date,omitempty"`
	Quantity         string     `json:"quantity"`
	CostPerUnit      string     `json:"cost_per_unit"`
}

type adjustBatchRequest struct {
	Delta  string `json:"delta"`
	Reason string `json:"reason"`
}

type batchResponse struct {
	BatchID          string     `json:"batchId"`
	CompanyID        string     `json:"companyId"`
	ItemID           string     `json:"itemId"`
	BatchNumber      string     `json:"batchNumber"`
	SupplierBatch    *string    `json:"supplierBatch,omitempty"`
	ManufacturedDate *time.Time `json:"manufacturedDate,omitempty"`
	ExpiryDate       *time.Time `json:"expiryDate,omitempty"`
	ReceivedDate     *time.Time `json:"receivedDate,omitempty"`
	Quantity         string     `json:"quantity"`
	RemainingQty     string     `json:"remainingQty"`
	CostPerUnit      string     `json:"costPerUnit"`
	IsActive         bool       `json:"isActive"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	CreatedBy        *string    `json:"createdBy,omitempty"`
	UpdatedBy        *string    `json:"updatedBy,omitempty"`
}

func toBatchResponse(b *models.Batch) batchResponse {
	resp := batchResponse{
		BatchID:          b.BatchID.String(),
		CompanyID:        b.CompanyID.String(),
		ItemID:           b.ItemID.String(),
		BatchNumber:      b.BatchNumber,
		SupplierBatch:    b.SupplierBatch,
		ManufacturedDate: b.ManufacturedDate,
		ExpiryDate:       b.ExpiryDate,
		ReceivedDate:     b.ReceivedDate,
		Quantity:         b.Quantity.String(),
		RemainingQty:     b.RemainingQty.String(),
		CostPerUnit:      b.CostPerUnit.String(),
		IsActive:         b.IsActive,
		CreatedAt:        b.CreatedAt,
		UpdatedAt:        b.UpdatedAt,
	}
	if b.CreatedBy != nil {
		createdBy := b.CreatedBy.String()
		resp.CreatedBy = &createdBy
	}
	if b.UpdatedBy != nil {
		updatedBy := b.UpdatedBy.String()
		resp.UpdatedBy = &updatedBy
	}
	return resp
}

// ---------- Handlers ----------

// CreateBatch godoc
// @Summary Create a new batch
// @Tags batches
// @Accept json
// @Produce json
// @Param companyId path string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency key"
// @Param request body createBatchRequest true "Batch data"
// @Success 201 {object} map[string]interface{}
// @Router /api/v1/companies/{companyId}/batches [post]
func (h *BatchHandler) CreateBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "batch:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header required")
		return
	}

	var req createBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}

	quantity, err := decimal.NewFromString(req.Quantity)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
		return
	}
	if quantity.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "quantity must be positive")
		return
	}

	costPerUnit, err := decimal.NewFromString(req.CostPerUnit)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cost_per_unit")
		return
	}
	if costPerUnit.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "cost_per_unit cannot be negative")
		return
	}

	// --- Date validations ---
	// 1. Expiry date must be after manufactured date (if both provided)
	if req.ManufacturedDate != nil && req.ExpiryDate != nil {
		if !req.ExpiryDate.After(*req.ManufacturedDate) {
			h.respondWithError(w, http.StatusBadRequest, "expiry_date must be after manufactured_date")
			return
		}
	}
	// 2. Received date cannot be after expiry date (cannot receive already expired goods)
	if req.ReceivedDate != nil && req.ExpiryDate != nil {
		if req.ReceivedDate.After(*req.ExpiryDate) {
			h.respondWithError(w, http.StatusBadRequest, "received_date cannot be after expiry_date")
			return
		}
	}
	// 3. Manufactured date must not be after received date (logical production flow)
	if req.ManufacturedDate != nil && req.ReceivedDate != nil {
		if req.ManufacturedDate.After(*req.ReceivedDate) {
			h.respondWithError(w, http.StatusBadRequest, "manufactured_date cannot be after received_date")
			return
		}
	}

	svcReq := service.CreateBatchRequest{
		CompanyID:        companyID,
		ItemID:           itemID,
		BatchNumber:      req.BatchNumber,
		SupplierBatch:    req.SupplierBatch,
		ManufacturedDate: req.ManufacturedDate,
		ExpiryDate:       req.ExpiryDate,
		ReceivedDate:     req.ReceivedDate,
		Quantity:         quantity,
		CostPerUnit:      costPerUnit,
		CreatedBy:        &userID,
	}

	batch, err := h.inventorySvc.CreateBatch(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create batch", zap.Error(err))
		// Map errors to appropriate HTTP status codes
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			status = http.StatusBadRequest
		case errors.Is(err, inventory_errors.ErrDuplicate):
			status = http.StatusConflict // 409 Conflict
		default:
			status = http.StatusBadRequest
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    toBatchResponse(batch),
		"message": "Batch created successfully",
	})
}

// AdjustBatch godoc
// @Summary Adjust batch quantity (increase/decrease)
// @Tags batches
// @Accept json
// @Produce json
// @Param companyId path string true "Company ID"
// @Param batchId path string true "Batch ID"
// @Param Idempotency-Key header string true "Idempotency key"
// @Param request body adjustBatchRequest true "Adjustment delta and reason"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyId}/batches/{batchId}/adjust [post]
func (h *BatchHandler) AdjustBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchId"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "batch:adjust") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header required")
		return
	}

	var req adjustBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	delta, err := decimal.NewFromString(req.Delta)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid delta")
		return
	}
	if delta.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "delta must be non-zero")
		return
	}

	svcReq := service.AdjustBatchRequest{
		BatchID:    batchID,
		CompanyID:  companyID,
		Delta:      delta,
		Reason:     req.Reason,
		AdjustedBy: &userID,
	}

	if err := h.inventorySvc.AdjustBatch(ctx, svcReq, idempotencyKey); err != nil {
		h.logger.Error("failed to adjust batch", zap.Error(err))
		status := http.StatusBadRequest
		if err == inventory_errors.ErrNotFound {
			status = http.StatusNotFound
		} else if err == inventory_errors.ErrPermissionDenied {
			status = http.StatusForbidden
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Batch adjusted successfully",
	})
}

// GetBatch godoc
// @Summary Get batch by ID
// @Tags batches
// @Produce json
// @Param companyId path string true "Company ID"
// @Param batchId path string true "Batch ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyId}/batches/{batchId} [get]
func (h *BatchHandler) GetBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchId"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "batch:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// IMPORTANT: Pass a valid DBTX (use the pgClient's DB connection)
	batch, err := h.batchRepo.GetByID(ctx, h.pgClient.DB, batchID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "batch not found")
			return
		}
		h.logger.Error("failed to get batch", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve batch")
		return
	}

	if batch.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "batch does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    toBatchResponse(batch),
	})
}

// ListBatches godoc
// @Summary List batches with filters
// @Tags batches
// @Produce json
// @Param companyId path string true "Company ID"
// @Param item_id query string false "Filter by item ID"
// @Param expiry_before query string false "Filter batches expiring before this date (YYYY-MM-DD)"
// @Param is_active query bool false "Filter by active status"
// @Param limit query int false "Page size (default 20, max 100)"
// @Param offset query int false "Offset (default 0)"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyId}/batches [get]
func (h *BatchHandler) ListBatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "batch:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse query parameters
	itemIDStr := r.URL.Query().Get("item_id")
	expiryBeforeStr := r.URL.Query().Get("expiry_before")
	activeStr := r.URL.Query().Get("is_active")
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	// Build SQL query
	query := `SELECT batch_id, company_id, item_id, batch_number, supplier_batch,
		manufactured_date, expiry_date, received_date, quantity, remaining_qty,
		cost_per_unit, is_active, created_at, updated_at, created_by, updated_by
		FROM batches WHERE company_id = $1`
	args := []interface{}{companyID}
	argIdx := 2

	if itemIDStr != "" {
		itemID, err := uuid.Parse(itemIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
			return
		}
		query += ` AND item_id = $` + strconv.Itoa(argIdx)
		args = append(args, itemID)
		argIdx++
	}
	if expiryBeforeStr != "" {
		expiryDate, err := time.Parse("2006-01-02", expiryBeforeStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid expiry_before date (use YYYY-MM-DD)")
			return
		}
		query += ` AND expiry_date < $` + strconv.Itoa(argIdx)
		args = append(args, expiryDate)
		argIdx++
	}
	if activeStr != "" {
		isActive, err := strconv.ParseBool(activeStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid is_active")
			return
		}
		query += ` AND is_active = $` + strconv.Itoa(argIdx)
		args = append(args, isActive)
		argIdx++
	}

	// Count total
	countQuery := `SELECT COUNT(*) FROM (` + query + `) AS filtered`
	var total int64
	if err := h.pgClient.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		h.logger.Error("failed to count batches", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to count batches")
		return
	}

	// Paginated query
	query += ` ORDER BY expiry_date ASC NULLS LAST LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.pgClient.DB.QueryContext(ctx, query, args...)
	if err != nil {
		h.logger.Error("failed to list batches", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list batches")
		return
	}
	defer rows.Close()

	var batches []*models.Batch
	for rows.Next() {
		var b models.Batch
		var createdBy, updatedBy *uuid.UUID
		err := rows.Scan(
			&b.BatchID, &b.CompanyID, &b.ItemID, &b.BatchNumber, &b.SupplierBatch,
			&b.ManufacturedDate, &b.ExpiryDate, &b.ReceivedDate, &b.Quantity, &b.RemainingQty,
			&b.CostPerUnit, &b.IsActive, &b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
		)
		if err != nil {
			h.logger.Error("failed to scan batch row", zap.Error(err))
			continue
		}
		b.CreatedBy = createdBy
		b.UpdatedBy = updatedBy
		batches = append(batches, &b)
	}

	responses := make([]batchResponse, len(batches))
	for i, b := range batches {
		responses[i] = toBatchResponse(b)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  responses,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ListBatchesByItem is a convenience endpoint that redirects to ListBatches with item_id query param.
func (h *BatchHandler) ListBatchesByItem(w http.ResponseWriter, r *http.Request) {
	itemIDStr := chi.URLParam(r, "itemId")
	if itemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "itemId is required")
		return
	}
	q := r.URL.Query()
	q.Set("item_id", itemIDStr)
	r.URL.RawQuery = q.Encode()
	h.ListBatches(w, r)
}

// ---------- Helper methods ----------

func (h *BatchHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: implement real permission check
	return true
}

func (h *BatchHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *BatchHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
