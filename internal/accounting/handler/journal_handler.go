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

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type JournalHandler struct {
	journalService service.JournalService
	logger         *zap.Logger
}

func NewJournalHandler(journalService service.JournalService, logger *zap.Logger) *JournalHandler {
	return &JournalHandler{
		journalService: journalService,
		logger:         logger.Named("journal_handler"),
	}
}

// ========== REQUEST TYPES ==========

type createJournalRequest struct {
	JournalType string               `json:"journal_type"`
	EntryDate   time.Time            `json:"entry_date"`
	Reference   *string              `json:"reference,omitempty"`
	Description *string              `json:"description,omitempty"`
	Lines       []journalLineRequest `json:"lines"`
	SourceType  *string              `json:"source_type,omitempty"`
	SourceID    *uuid.UUID           `json:"source_id,omitempty"`
}

type journalLineRequest struct {
	AccountID    uuid.UUID       `json:"account_id"`
	DebitAmount  decimal.Decimal `json:"debit_amount"`
	CreditAmount decimal.Decimal `json:"credit_amount"`
	Description  *string         `json:"description,omitempty"`
}

type updateJournalRequest struct {
	EntryDate   *time.Time           `json:"entry_date,omitempty"`
	Reference   *string              `json:"reference,omitempty"`
	Description *string              `json:"description,omitempty"`
	Lines       []journalLineRequest `json:"lines,omitempty"`
}

type reverseJournalRequest struct {
	Reason string `json:"reason"`
}

type listJournalsQuery struct {
	CompanyID   string     `json:"-"`
	JournalType *string    `json:"journal_type,omitempty"`
	Status      *string    `json:"status,omitempty"`
	FromDate    *time.Time `json:"from_date,omitempty"`
	ToDate      *time.Time `json:"to_date,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
}

// ========== HELPERS ==========

func (h *JournalHandler) withIdempotency(ctx context.Context, r *http.Request) context.Context {
	key := r.Header.Get("Idempotency-Key")
	if key != "" {
		ctx = context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

func (h *JournalHandler) getUserID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *JournalHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: implement actual permission check (e.g., via auth client)
	return true
}

// ========== CREATE ==========

func (h *JournalHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := h.withIdempotency(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createJournalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// --- validation (fail fast) ---
	if len(req.Lines) < 2 {
		h.respondWithError(w, http.StatusBadRequest, "journal must have at least 2 lines (double-entry)")
		return
	}

	var totalDebit, totalCredit decimal.Decimal
	for i, line := range req.Lines {
		if line.AccountID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("line %d: account_id is required", i+1))
			return
		}
		if line.DebitAmount.IsNegative() || line.CreditAmount.IsNegative() {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("line %d: amounts cannot be negative", i+1))
			return
		}
		if line.DebitAmount.IsZero() && line.CreditAmount.IsZero() {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("line %d: both debit and credit cannot be zero", i+1))
			return
		}
		if !line.DebitAmount.IsZero() && !line.CreditAmount.IsZero() {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("line %d: cannot have both debit and credit", i+1))
			return
		}
		totalDebit = totalDebit.Add(line.DebitAmount)
		totalCredit = totalCredit.Add(line.CreditAmount)
	}
	if !totalDebit.Equal(totalCredit) {
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("total debits (%s) must equal total credits (%s)", totalDebit.String(), totalCredit.String()))
		return
	}
	// -------------------------------

	h.logger.Info("create journal request",
		zap.String("company_id", companyID.String()),
		zap.String("journal_type", req.JournalType),
		zap.Int("lines", len(req.Lines)),
	)

	lines := make([]service.JournalLineRequest, len(req.Lines))
	for i, l := range req.Lines {
		lines[i] = service.JournalLineRequest{
			AccountID:    l.AccountID,
			DebitAmount:  l.DebitAmount,
			CreditAmount: l.CreditAmount,
			Description:  l.Description,
		}
	}

	svcReq := service.CreateJournalRequest{
		CompanyID:   companyID,
		JournalType: req.JournalType,
		EntryDate:   req.EntryDate,
		Reference:   req.Reference,
		Description: req.Description,
		Lines:       lines,
		CreatedBy:   &userID,
		UpdatedBy:   &userID,
		SourceType:  req.SourceType,
		SourceID:    req.SourceID,
	}

	journal, err := h.journalService.Create(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create journal", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    journal,
		"message": "Journal entry created successfully",
	})
}

// ========== UPDATE ==========

func (h *JournalHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := h.withIdempotency(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	journalID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal entry ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Fetch existing to check company ownership early
	existing, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if existing.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	var req updateJournalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var lines []service.JournalLineRequest
	if req.Lines != nil {
		lines = make([]service.JournalLineRequest, len(req.Lines))
		for i, l := range req.Lines {
			lines[i] = service.JournalLineRequest{
				AccountID:    l.AccountID,
				DebitAmount:  l.DebitAmount,
				CreditAmount: l.CreditAmount,
				Description:  l.Description,
			}
		}
	}

	svcReq := service.UpdateJournalRequest{
		JournalEntryID: journalID,
		EntryDate:      req.EntryDate,
		Reference:      req.Reference,
		Description:    req.Description,
		Lines:          lines,
		UpdatedBy:      &userID,
	}

	journal, err := h.journalService.Update(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to update journal", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    journal,
		"message": "Journal entry updated successfully",
	})
}

// ========== POST ==========

func (h *JournalHandler) Post(w http.ResponseWriter, r *http.Request) {
	ctx := h.withIdempotency(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	journalID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal entry ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:post") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Post(ctx, journalID, &userID); err != nil {
		h.logger.Error("failed to post journal", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry posted successfully",
	})
}

// ========== REVERSE ==========

func (h *JournalHandler) Reverse(w http.ResponseWriter, r *http.Request) {
	ctx := h.withIdempotency(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	journalID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal entry ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:reverse") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req reverseJournalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Reverse(ctx, journalID, req.Reason, &userID); err != nil {
		h.logger.Error("failed to reverse journal", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry reversed successfully",
	})
}

// ========== GET BY ID ==========

func (h *JournalHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	journalID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal entry ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    journal,
	})
}

// ========== LIST ==========

func (h *JournalHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.JournalFilter{CompanyID: companyID}

	if journalType := query.Get("journal_type"); journalType != "" {
		filter.JournalType = journalType
	}
	if status := query.Get("status"); status != "" {
		filter.Status = status
	}
	if fromDateStr := query.Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse(time.RFC3339, fromDateStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toDateStr := query.Get("to_date"); toDateStr != "" {
		if t, err := time.Parse(time.RFC3339, toDateStr); err == nil {
			filter.ToDate = &t
		}
	}

	limit := 50
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	journals, total, err := h.journalService.List(ctx, filter, service.Pagination{Limit: limit, Offset: offset})
	if err != nil {
		h.logger.Error("failed to list journals", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve journals")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  journals,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ========== DELETE ==========

func (h *JournalHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := h.withIdempotency(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	journalID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid journal entry ID")
		return
	}

	userID, err := h.getUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "journal:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Delete(ctx, journalID, &userID); err != nil {
		h.logger.Error("failed to delete journal", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry deleted successfully",
	})
}

// ========== HELPERS: RESPONSE & ERROR MAPPING ==========

func (h *JournalHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *JournalHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *JournalHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, service.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, service.ErrInvalidState):
		return http.StatusConflict, err.Error()
	default:
		return http.StatusBadRequest, err.Error()
	}
}
