package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/service"
)

// LedgerHandler handles HTTP requests for ledger operations.
type LedgerHandler struct {
	ledgerService service.LedgerService
	logger        *zap.Logger
}

// NewLedgerHandler creates a new LedgerHandler.
func NewLedgerHandler(ledgerService service.LedgerService, logger *zap.Logger) *LedgerHandler {
	return &LedgerHandler{
		ledgerService: ledgerService,
		logger:        logger.Named("ledger_handler"),
	}
}

// ----------------------------
// Request / Response structs
// ----------------------------

type getAccountBalanceRequest struct {
	FiscalYear int `json:"fiscal_year"`
	Period     int `json:"period"`
}

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

// ----------------------------
// Handlers
// ----------------------------

// GetAccountBalance handles GET /companies/{companyID}/ledger/balance?account_id=...&fiscal_year=...&period=...
func (h *LedgerHandler) GetAccountBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Parse account ID from query parameter
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

	// Parse fiscal year and period
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

	// Authenticate user
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Permission check
	if !h.hasPermission(ctx, companyID, userID, "ledger:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Call service
	balance, err := h.ledgerService.GetAccountBalance(ctx, companyID, accountID, fiscalYear, period)
	if err != nil {
		h.logger.Error("failed to get account balance", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build response
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

// RecomputeBalances handles POST /companies/{companyID}/ledger/recompute
func (h *LedgerHandler) RecomputeBalances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Parse request body
	var req recomputeBalancesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FiscalYear <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year must be a positive integer")
		return
	}

	// Authenticate user
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Permission check
	if !h.hasPermission(ctx, companyID, userID, "ledger:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Call service
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

// ----------------------------
// Helper functions (same pattern as AcademicYearHandler)
// ----------------------------

// hasPermission is a placeholder for real RBAC logic.
// In production, implement actual permission checks using your RBAC service.
func (h *LedgerHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Integrate with actual permission service
	// For now, allow all requests (as in the academic example)
	return true
}

// respondWithJSON sends a JSON response with the given status code and data.
func (h *LedgerHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError sends an error response in the standard format.
func (h *LedgerHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// getUserIDFromContext extracts the user ID from the request context.
// Assumes the context has been populated by authentication middleware.
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
