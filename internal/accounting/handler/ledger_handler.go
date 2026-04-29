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
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type LedgerHandler struct {
	ledgerService service.LedgerService
	logger        *zap.Logger
}

func NewLedgerHandler(ledgerService service.LedgerService, logger *zap.Logger) *LedgerHandler {
	return &LedgerHandler{
		ledgerService: ledgerService,
		logger:        logger.Named("ledger_handler"),
	}
}

// ========== REQUEST/RESPONSE TYPES ==========

type getAccountBalanceResponse struct {
	AccountID      string `json:"account_id"`
	OpeningBalance string `json:"opening_balance"`
	ClosingBalance string `json:"closing_balance"`
}

type recomputeBalancesRequest struct {
	FiscalYear int `json:"fiscal_year"`
}

type recomputeBalancesResponse struct {
	Message string `json:"message"`
}

// ========== HELPERS ==========

func (h *LedgerHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: implement actual permission check
	return true
}

func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}
	return userID, nil
}

// ========== EXISTING ENDPOINTS (kept as-is but improved error handling) ==========

func (h *LedgerHandler) GetAccountBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	accountIDStr := r.URL.Query().Get("account_id")
	if accountIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "account_id query parameter is required")
		return
	}
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	fiscalYearStr := r.URL.Query().Get("fiscal_year")
	if fiscalYearStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year query parameter is required")
		return
	}
	fiscalYear, err := strconv.Atoi(fiscalYearStr)
	if err != nil || fiscalYear <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "invalid fiscal_year")
		return
	}

	periodStr := r.URL.Query().Get("period")
	if periodStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "period query parameter is required")
		return
	}
	period, err := strconv.Atoi(periodStr)
	if err != nil || period <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "invalid period")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "ledger:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	balance, err := h.ledgerService.GetAccountBalance(ctx, companyID, accountID, fiscalYear, period)
	if err != nil {
		h.logger.Error("failed to get account balance", zap.Error(err))
		if errors.Is(err, repository.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "account balance not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := getAccountBalanceResponse{
		AccountID:      balance.AccountID.String(),
		OpeningBalance: balance.OpeningBalance.String(),
		ClosingBalance: balance.ClosingBalance.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *LedgerHandler) RecomputeBalances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var req recomputeBalancesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FiscalYear <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year must be a positive integer")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "ledger:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.ledgerService.RecomputeBalances(ctx, companyID, req.FiscalYear)
	if err != nil {
		h.logger.Error("failed to recompute balances", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": recomputeBalancesResponse{
			Message: fmt.Sprintf("Balances recomputed successfully for fiscal year %d", req.FiscalYear),
		},
	})
}

// ========== NEW REPORT ENDPOINTS ==========

// TrialBalance returns the trial balance for a date range.
// GET /api/v1/companies/{companyID}/ledger/trial-balance?from=...&to=...
func (h *LedgerHandler) TrialBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "ledger:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339 format)")
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format, use RFC3339")
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format, use RFC3339")
		return
	}

	data, err := h.ledgerService.ComputeTrialBalance(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to compute trial balance", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    data,
	})
}

// ProfitAndLoss returns the P&L statement for a date range.
// GET /api/v1/companies/{companyID}/ledger/profit-and-loss?from=...&to=...
func (h *LedgerHandler) ProfitAndLoss(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "ledger:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339 format)")
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format, use RFC3339")
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format, use RFC3339")
		return
	}

	data, err := h.ledgerService.ComputePAndL(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to compute profit and loss", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    data,
	})
}

// BalanceSheet returns the balance sheet as of a specific date.
// GET /api/v1/companies/{companyID}/ledger/balance-sheet?as_of=...
func (h *LedgerHandler) BalanceSheet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "ledger:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	asOfStr := r.URL.Query().Get("as_of")
	if asOfStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "as_of query parameter is required (RFC3339 format)")
		return
	}
	asOf, err := time.Parse(time.RFC3339, asOfStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid as_of date format, use RFC3339")
		return
	}

	data, err := h.ledgerService.ComputeBalanceSheet(ctx, companyID, asOf)
	if err != nil {
		h.logger.Error("failed to compute balance sheet", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    data,
	})
}

// ========== RESPONSE HELPERS ==========

func (h *LedgerHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *LedgerHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
