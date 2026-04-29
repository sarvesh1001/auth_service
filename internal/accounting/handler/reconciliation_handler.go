package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/service"
)

type ReconciliationHandler struct {
	svc    service.ReconciliationService
	logger *zap.Logger
}

func NewReconciliationHandler(svc service.ReconciliationService, logger *zap.Logger) *ReconciliationHandler {
	return &ReconciliationHandler{
		svc:    svc,
		logger: logger.Named("reconciliation_handler"),
	}
}

// Request types
type createBatchRequest struct {
	ReconciliationType string     `json:"reconciliation_type"`
	Reference          *string    `json:"reference,omitempty"`
	StartDate          *time.Time `json:"start_date,omitempty"`
	EndDate            *time.Time `json:"end_date,omitempty"`
}

type listBatchesRequest struct {
	ReconciliationType string     `json:"reconciliation_type,omitempty"`
	Status             string     `json:"status,omitempty"`
	FromDate           *time.Time `json:"from_date,omitempty"`
	ToDate             *time.Time `json:"to_date,omitempty"`
	Limit              int        `json:"limit,omitempty"`
	Offset             int        `json:"offset,omitempty"`
}

type addItemsRequest struct {
	Items []service.ReconciliationItemInput `json:"items"`
}

type autoMatchRequest struct {
	Threshold string `json:"threshold"`
}

type manualMatchRequest struct {
	JournalEntryID string `json:"journal_entry_id"`
	Score          string `json:"score"`
}

type setMatchStatusRequest struct {
	Status         string  `json:"status"`
	JournalEntryID *string `json:"journal_entry_id,omitempty"`
	Score          *string `json:"score,omitempty"`
}

type createDifferenceRequest struct {
	IssueType      string  `json:"issue_type"`
	ExpectedAmount string  `json:"expected_amount"`
	ActualAmount   string  `json:"actual_amount"`
	SourceID       *string `json:"source_id,omitempty"`
	JournalEntryID *string `json:"journal_entry_id,omitempty"`
	Description    *string `json:"description,omitempty"`
}

type resolveDifferenceRequest struct {
	CreateAdjustment bool   `json:"create_adjustment"`
	DebitAccountID   string `json:"debit_account_id,omitempty"`
	CreditAccountID  string `json:"credit_account_id,omitempty"`
	Description      string `json:"description,omitempty"`
}

type createAdjustmentRequest struct {
	JournalEntryID   string  `json:"journal_entry_id"`
	Reason           *string `json:"reason,omitempty"`
	AdjustmentAmount string  `json:"adjustment_amount"`
}

// ----------------------------------------------------------------------------
// CreateBatch (already has idempotency – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) CreateBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req createBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ReconciliationType == "" {
		h.respondWithError(w, http.StatusBadRequest, "reconciliation_type required")
		return
	}
	svcReq := service.CreateReconciliationBatchRequest{
		CompanyID:          companyID,
		ReconciliationType: req.ReconciliationType,
		Reference:          req.Reference,
		StartDate:          req.StartDate,
		EndDate:            req.EndDate,
		CreatedBy:          &userID,
	}
	batch, err := h.svc.CreateBatch(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create batch", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    batch,
		"message": "Reconciliation batch created",
	})
}

// ----------------------------------------------------------------------------
// GetBatch (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) GetBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	batch, err := h.svc.GetBatch(ctx, batchID)
	if err != nil {
		h.logger.Error("failed to get batch", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if batch.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "batch does not belong to this company")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    batch,
	})
}

// ----------------------------------------------------------------------------
// ListBatches (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) ListBatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req listBatchesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = listBatchesRequest{}
	}
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	filter := service.ReconciliationFilter{
		CompanyID:          companyID,
		ReconciliationType: req.ReconciliationType,
		Status:             req.Status,
		FromDate:           req.FromDate,
		ToDate:             req.ToDate,
	}
	pagination := service.Pagination{Limit: req.Limit, Offset: req.Offset}
	batches, total, err := h.svc.ListBatches(ctx, filter, pagination)
	if err != nil {
		h.logger.Error("failed to list batches", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list batches")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  batches,
			"total":  total,
			"limit":  req.Limit,
			"offset": req.Offset,
		},
	})
}

// ----------------------------------------------------------------------------
// UpdateBatchStats (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) UpdateBatchStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if err := h.svc.UpdateBatchStats(ctx, batchID); err != nil {
		h.logger.Error("failed to update batch stats", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Batch stats updated",
	})
}

// ----------------------------------------------------------------------------
// CompleteBatch (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) CompleteBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:complete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if err := h.svc.CompleteBatch(ctx, batchID); err != nil {
		h.logger.Error("failed to complete batch", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Batch completed",
	})
}

// ----------------------------------------------------------------------------
// DeleteBatch (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) DeleteBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if err := h.svc.DeleteBatch(ctx, batchID); err != nil {
		h.logger.Error("failed to delete batch", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Batch deleted",
	})
}

// ----------------------------------------------------------------------------
// AddItems (already has idempotency – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) AddItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req addItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	items, err := h.svc.AddItems(ctx, batchID, req.Items)
	if err != nil {
		h.logger.Error("failed to add items", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    items,
		"message": "Items added",
	})
}

// ----------------------------------------------------------------------------
// GetItems (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) GetItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	status := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, err := h.svc.GetItems(ctx, batchID, status, limit, offset)
	if err != nil {
		h.logger.Error("failed to get items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve items")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// ----------------------------------------------------------------------------
// GetUnmatchedItems (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) GetUnmatchedItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, err := h.svc.GetUnmatchedItems(ctx, batchID, limit, offset)
	if err != nil {
		h.logger.Error("failed to get unmatched items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve unmatched items")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// ----------------------------------------------------------------------------
// AutoMatch (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) AutoMatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:auto_match") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req autoMatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	threshold, err := decimal.NewFromString(req.Threshold)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid threshold amount")
		return
	}
	result, err := h.svc.AutoMatch(ctx, batchID, threshold)
	if err != nil {
		h.logger.Error("auto-match failed", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// ----------------------------------------------------------------------------
// ManualMatch (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) ManualMatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:manual_match") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req manualMatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	jeID, err := uuid.Parse(req.JournalEntryID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal_entry_id")
		return
	}
	score, err := decimal.NewFromString(req.Score)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid score")
		return
	}
	if err := h.svc.ManualMatch(ctx, itemID, jeID, score); err != nil {
		h.logger.Error("manual match failed", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Item manually matched",
	})
}

// ----------------------------------------------------------------------------
// SetItemMatchStatus (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) SetItemMatchStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req setMatchStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}
	var jeID *uuid.UUID
	if req.JournalEntryID != nil {
		id, err := uuid.Parse(*req.JournalEntryID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid journal_entry_id")
			return
		}
		jeID = &id
	}
	var score *decimal.Decimal
	if req.Score != nil {
		s, err := decimal.NewFromString(*req.Score)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid score")
			return
		}
		score = &s
	}
	if err := h.svc.SetItemMatchStatus(ctx, itemID, req.Status, jeID, score); err != nil {
		h.logger.Error("failed to set match status", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Match status updated",
	})
}

// ----------------------------------------------------------------------------
// UnmatchItem (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) UnmatchItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if err := h.svc.UnmatchItem(ctx, itemID); err != nil {
		h.logger.Error("failed to unmatch item", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Item unmatched",
	})
}

// ----------------------------------------------------------------------------
// CreateDifference (already has idempotency – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) CreateDifference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:create_difference") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req createDifferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	expected, err := decimal.NewFromString(req.ExpectedAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid expected_amount")
		return
	}
	actual, err := decimal.NewFromString(req.ActualAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid actual_amount")
		return
	}
	var jeID *uuid.UUID
	if req.JournalEntryID != nil {
		id, err := uuid.Parse(*req.JournalEntryID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid journal_entry_id")
			return
		}
		jeID = &id
	}
	svcReq := service.CreateDifferenceRequest{
		BatchID:        batchID,
		IssueType:      req.IssueType,
		ExpectedAmount: expected,
		ActualAmount:   actual,
		SourceID:       req.SourceID,
		JournalEntryID: jeID,
		Description:    req.Description,
	}
	diff, err := h.svc.CreateDifference(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create difference", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    diff,
		"message": "Difference recorded",
	})
}

// ----------------------------------------------------------------------------
// ResolveDifference (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) ResolveDifference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	diffID, err := uuid.Parse(chi.URLParam(r, "diffID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid difference ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:resolve_difference") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req resolveDifferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var adjReq *service.ResolveDifferenceAdjustmentRequest
	if req.CreateAdjustment {
		debitID, err := uuid.Parse(req.DebitAccountID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid debit_account_id")
			return
		}
		creditID, err := uuid.Parse(req.CreditAccountID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid credit_account_id")
			return
		}
		adjReq = &service.ResolveDifferenceAdjustmentRequest{
			CreateAdjustment: true,
			DebitAccountID:   debitID,
			CreditAccountID:  creditID,
			Description:      req.Description,
		}
	}
	if err := h.svc.ResolveDifference(ctx, diffID, &userID, adjReq); err != nil {
		h.logger.Error("failed to resolve difference", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Difference resolved",
	})
}

// ----------------------------------------------------------------------------
// GetDifferences (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) GetDifferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	unresolvedOnly, _ := strconv.ParseBool(r.URL.Query().Get("unresolved_only"))
	diffs, err := h.svc.GetDifferences(ctx, batchID, unresolvedOnly)
	if err != nil {
		h.logger.Error("failed to get differences", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve differences")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    diffs,
	})
}

// ----------------------------------------------------------------------------
// CreateAdjustment (already has idempotency – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) CreateAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:create_adjustment") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req createAdjustmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	jeID, err := uuid.Parse(req.JournalEntryID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal_entry_id")
		return
	}
	amount, err := decimal.NewFromString(req.AdjustmentAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment_amount")
		return
	}
	svcReq := service.CreateAdjustmentRequest{
		BatchID:          batchID,
		JournalEntryID:   jeID,
		Reason:           req.Reason,
		AdjustmentAmount: amount,
		CreatedBy:        &userID,
	}
	adj, err := h.svc.CreateAdjustment(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create adjustment", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    adj,
		"message": "Adjustment created",
	})
}

// ----------------------------------------------------------------------------
// DeleteAdjustment (mutating – added idempotency)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) DeleteAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}

	adjID, err := uuid.Parse(chi.URLParam(r, "adjID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:delete_adjustment") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if err := h.svc.DeleteAdjustment(ctx, adjID); err != nil {
		h.logger.Error("failed to delete adjustment", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Adjustment deleted",
	})
}

// ----------------------------------------------------------------------------
// GetAdjustments (read-only – unchanged)
// ----------------------------------------------------------------------------
func (h *ReconciliationHandler) GetAdjustments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	batchID, err := uuid.Parse(chi.URLParam(r, "batchID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid batch ID")
		return
	}
	companyID, err := getCompanyIDFromRequest(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "reconciliation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	adjustments, err := h.svc.GetAdjustments(ctx, batchID)
	if err != nil {
		h.logger.Error("failed to get adjustments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve adjustments")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    adjustments,
	})
}

// Helper functions (unchanged)
func (h *ReconciliationHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	return true
}

func getCompanyIDFromRequest(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		companyIDStr = r.URL.Query().Get("companyId")
	}
	return uuid.Parse(companyIDStr)
}

func (h *ReconciliationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReconciliationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
