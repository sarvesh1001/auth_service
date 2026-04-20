package handler

import (
	"context"
	"encoding/json"
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

// Request/Response types

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

// Helper functions

func (h *JournalHandler) getUserID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *JournalHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// Implement real permission check or delegate to RBAC service
	return true
}

// Handlers

// Create godoc
// @Summary Create a new journal entry
// @Tags journals
// @Accept json
// @Produce json
// @Param companyID path string true "Company ID"
// @Param request body createJournalRequest true "Journal data"
// @Success 201 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals [post]
func (h *JournalHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "journal:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createJournalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate lines
	if len(req.Lines) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one journal line is required")
		return
	}

	// Build service request
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
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    journal,
		"message": "Journal entry created successfully",
	})
}

// Update godoc
// @Summary Update a draft journal entry
// @Tags journals
// @Accept json
// @Produce json
// @Param companyID path string true "Company ID"
// @Param id path string true "Journal Entry ID"
// @Param request body updateJournalRequest true "Update data"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals/{id} [put]
func (h *JournalHandler) Update(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "journal:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateJournalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build service request
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
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify ownership
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    journal,
		"message": "Journal entry updated successfully",
	})
}

// Post godoc
// @Summary Post a journal entry (move to ledger)
// @Tags journals
// @Produce json
// @Param companyID path string true "Company ID"
// @Param id path string true "Journal Entry ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals/{id}/post [post]
func (h *JournalHandler) Post(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "journal:post") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Optional: verify journal belongs to company before posting
	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Post(ctx, journalID, &userID); err != nil {
		h.logger.Error("failed to post journal", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry posted successfully",
	})
}

// Reverse godoc
// @Summary Reverse a posted journal entry
// @Tags journals
// @Accept json
// @Produce json
// @Param companyID path string true "Company ID"
// @Param id path string true "Journal Entry ID"
// @Param request body reverseJournalRequest true "Reason for reversal"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals/{id}/reverse [post]
func (h *JournalHandler) Reverse(w http.ResponseWriter, r *http.Request) {
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

	// Verify ownership
	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Reverse(ctx, journalID, req.Reason, &userID); err != nil {
		h.logger.Error("failed to reverse journal", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry reversed successfully",
	})
}

// GetByID godoc
// @Summary Get journal entry by ID
// @Tags journals
// @Produce json
// @Param companyID path string true "Company ID"
// @Param id path string true "Journal Entry ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals/{id} [get]
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
		h.logger.Error("failed to get journal", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
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

// List godoc
// @Summary List journal entries
// @Tags journals
// @Produce json
// @Param companyID path string true "Company ID"
// @Param journal_type query string false "Filter by journal type"
// @Param status query string false "Filter by status"
// @Param from_date query string false "Filter from date (RFC3339)"
// @Param to_date query string false "Filter to date (RFC3339)"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals [get]
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

	filter := repository.JournalFilter{
		CompanyID: companyID,
	}
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

// Delete godoc
// @Summary Soft-delete a draft journal entry
// @Tags journals
// @Produce json
// @Param companyID path string true "Company ID"
// @Param id path string true "Journal Entry ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/companies/{companyID}/journals/{id} [delete]
func (h *JournalHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "journal:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Verify ownership
	journal, err := h.journalService.GetByID(ctx, journalID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if journal.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "journal entry does not belong to this company")
		return
	}

	if err := h.journalService.Delete(ctx, journalID, &userID); err != nil {
		h.logger.Error("failed to delete journal", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Journal entry deleted successfully",
	})
}

// Helper response methods

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
