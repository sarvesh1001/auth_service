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

// SerialNumberTransactionHandler handles serial number audit trail endpoints.
type SerialNumberTransactionHandler struct {
	txnSvc service.SerialNumberTransactionService
	db     repository.DBTX
	logger *zap.Logger
}

// NewSerialNumberTransactionHandler creates a new handler.
func NewSerialNumberTransactionHandler(
	txnSvc service.SerialNumberTransactionService,
	db repository.DBTX,
	logger *zap.Logger,
) *SerialNumberTransactionHandler {
	return &SerialNumberTransactionHandler{
		txnSvc: txnSvc,
		db:     db,
		logger: logger.Named("serial_number_txn_handler"),
	}
}

// serialNumberTransactionResponse is the JSON response for a transaction.
type serialNumberTransactionResponse struct {
	TransactionID   string    `json:"transactionId"`
	SerialID        string    `json:"serialId"`
	CompanyID       string    `json:"companyId"`
	MovementID      *string   `json:"movementId,omitempty"`
	FromWarehouseID *string   `json:"fromWarehouseId,omitempty"`
	ToWarehouseID   *string   `json:"toWarehouseId,omitempty"`
	FromBatchID     *string   `json:"fromBatchId,omitempty"`
	ToBatchID       *string   `json:"toBatchId,omitempty"`
	OldStatus       *string   `json:"oldStatus,omitempty"`
	NewStatus       *string   `json:"newStatus,omitempty"`
	TransactionType string    `json:"transactionType"`
	TransactionDate time.Time `json:"transactionDate"`
	CreatedBy       *string   `json:"createdBy,omitempty"`
	Notes           *string   `json:"notes,omitempty"`
}

func toSerialNumberTransactionResponse(t *models.SerialNumberTransaction) serialNumberTransactionResponse {
	resp := serialNumberTransactionResponse{
		TransactionID:   t.TransactionID.String(),
		SerialID:        t.SerialID.String(),
		CompanyID:       t.CompanyID.String(),
		TransactionType: t.TransactionType,
		TransactionDate: t.TransactionDate,
	}
	if t.MovementID != nil {
		s := t.MovementID.String()
		resp.MovementID = &s
	}
	if t.FromWarehouseID != nil {
		s := t.FromWarehouseID.String()
		resp.FromWarehouseID = &s
	}
	if t.ToWarehouseID != nil {
		s := t.ToWarehouseID.String()
		resp.ToWarehouseID = &s
	}
	if t.FromBatchID != nil {
		s := t.FromBatchID.String()
		resp.FromBatchID = &s
	}
	if t.ToBatchID != nil {
		s := t.ToBatchID.String()
		resp.ToBatchID = &s
	}
	if t.OldStatus != nil {
		resp.OldStatus = t.OldStatus
	}
	if t.NewStatus != nil {
		resp.NewStatus = t.NewStatus
	}
	if t.CreatedBy != nil {
		s := t.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if t.Notes != nil {
		resp.Notes = t.Notes
	}
	return resp
}

// GetTransactionHistory returns paginated transaction history for a specific serial number.
// GET /api/v1/companies/{companyID}/inventory/serials/{id}/transactions
func (h *SerialNumberTransactionHandler) GetTransactionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The URL param is "id" to match the test route (GET /serials/{id}/transactions)
	serialID, err := parseSerialIDFromParam(r, "id")
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

	limit, offset := parseLimitOffset(r)
	txns, err := h.txnSvc.GetTransactionHistory(ctx, h.db, serialID, limit, offset)
	if err != nil {
		h.logger.Error("failed to get transaction history", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "serial number not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transaction history")
		return
	}

	responses := make([]serialNumberTransactionResponse, len(txns))
	for i, txn := range txns {
		responses[i] = toSerialNumberTransactionResponse(txn)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  responses,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ListTransactions lists serial number transactions with optional filters.
// GET /api/v1/companies/{companyID}/inventory/serial-transactions
func (h *SerialNumberTransactionHandler) ListTransactions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseCompanyID(r)
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

	// Validate transaction_type if provided
	query := r.URL.Query()
	if txnType := query.Get("transaction_type"); txnType != "" {
		if !isValidTransactionType(txnType) {
			h.respondWithError(w, http.StatusBadRequest, "invalid transaction_type")
			return
		}
	}

	filter := h.parseTransactionFilter(r, companyID)

	// Validate from_date <= to_date
	if filter.FromDate != nil && filter.ToDate != nil && filter.FromDate.After(*filter.ToDate) {
		h.respondWithError(w, http.StatusBadRequest, "from_date must be before or equal to to_date")
		return
	}

	page, pageSize := parsePageAndSize(r)

	txns, total, err := h.txnSvc.ListTransactions(ctx, h.db, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list transactions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve transactions")
		return
	}

	responses := make([]serialNumberTransactionResponse, len(txns))
	for i, txn := range txns {
		responses[i] = toSerialNumberTransactionResponse(txn)
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

// isValidTransactionType checks if the transaction type is allowed.
func isValidTransactionType(txnType string) bool {
	allowed := map[string]bool{
		"created":       true,
		"assigned":      true,
		"status_change": true,
		"sold":          true,
		"transferred":   true,
	}
	return allowed[txnType]
}

// parseTransactionFilter builds the repository filter from query parameters.
func (h *SerialNumberTransactionHandler) parseTransactionFilter(r *http.Request, companyID uuid.UUID) repository.SerialNumberTransactionFilter {
	query := r.URL.Query()
	filter := repository.SerialNumberTransactionFilter{
		CompanyID: companyID,
	}

	if serialIDStr := query.Get("serial_id"); serialIDStr != "" {
		if id, err := uuid.Parse(serialIDStr); err == nil {
			filter.SerialID = &id
		}
	}
	if movementIDStr := query.Get("movement_id"); movementIDStr != "" {
		if id, err := uuid.Parse(movementIDStr); err == nil {
			filter.MovementID = &id
		}
	}
	if txnType := query.Get("transaction_type"); txnType != "" && isValidTransactionType(txnType) {
		filter.TransactionType = &txnType
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.ToDate = &t
		}
	}
	return filter
}

// Helper functions (avoid name conflicts with other handlers)
func parseCompanyID(r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "companyID")
	if idStr == "" {
		return uuid.Nil, errors.New("company ID is required")
	}
	return uuid.Parse(idStr)
}

// parseSerialIDFromParam reads the serial ID from a named URL parameter.
func parseSerialIDFromParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, errors.New("serial ID is required")
	}
	return uuid.Parse(idStr)
}

func parseLimitOffset(r *http.Request) (limit, offset int) {
	limit = 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	offset = 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	return
}

// parsePageAndSize extracts page and pageSize from URL query.
func parsePageAndSize(r *http.Request) (page, pageSize int) {
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
	return
}

func (h *SerialNumberTransactionHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	// Replace with real permission check
	return true
}

func (h *SerialNumberTransactionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *SerialNumberTransactionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
