package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/service"
)

// AccountingSettingsHandler handles HTTP requests for company accounting settings.
type AccountingSettingsHandler struct {
	accountingService service.AccountingService
	logger            *zap.Logger
}

// NewAccountingSettingsHandler creates a new AccountingSettingsHandler.
func NewAccountingSettingsHandler(accountingService service.AccountingService, logger *zap.Logger) *AccountingSettingsHandler {
	return &AccountingSettingsHandler{
		accountingService: accountingService,
		logger:            logger.Named("accounting_settings_handler"),
	}
}

// ---------- Request/Response Types ----------

type getSettingsResponse struct {
	CompanyID                string `json:"company_id"`
	FiscalYearStartMonth     int    `json:"fiscal_year_start_month"`
	CurrencyCode             string `json:"currency_code"`
	TaxScheme                string `json:"tax_scheme"`
	AllowIntercompanyJournal bool   `json:"allow_intercompany_journal"`
	AutoGenerateReversals    bool   `json:"auto_generate_reversals"`
}

type updateFiscalYearRequest struct {
	StartMonth int `json:"start_month"`
}

type updateCurrencyRequest struct {
	CurrencyCode string `json:"currency_code"`
}

type updateTaxSchemeRequest struct {
	TaxScheme string `json:"tax_scheme"`
}

// ---------- Handler Methods ----------

// GetSettings handles GET /api/v1/accounting/settings
// Retrieves accounting settings for the company.
func (h *AccountingSettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	settings, err := h.accountingService.GetAccountingSettings(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get accounting settings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve settings")
		return
	}

	resp := getSettingsResponse{
		CompanyID:                settings.CompanyID.String(),
		FiscalYearStartMonth:     settings.FiscalYearStartMonth,
		CurrencyCode:             settings.CurrencyCode,
		TaxScheme:                settings.TaxScheme,
		AllowIntercompanyJournal: settings.AllowIntercompanyJournal,
		AutoGenerateReversals:    settings.AutoGenerateReversals,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateFiscalYear handles PUT /api/v1/accounting/settings/fiscal-year
// Updates the fiscal year start month for the company.
func (h *AccountingSettingsHandler) UpdateFiscalYear(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateFiscalYearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StartMonth < 1 || req.StartMonth > 12 {
		h.respondWithError(w, http.StatusBadRequest, "start_month must be between 1 and 12")
		return
	}

	err = h.accountingService.UpdateFiscalYear(ctx, companyID, req.StartMonth, &userID)
	if err != nil {
		h.logger.Error("failed to update fiscal year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fiscal year start month updated successfully",
	})
}

// UpdateCurrency handles PUT /api/v1/accounting/settings/currency
// Updates the functional currency for the company.
func (h *AccountingSettingsHandler) UpdateCurrency(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCurrencyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.CurrencyCode) != 3 {
		h.respondWithError(w, http.StatusBadRequest, "currency_code must be a 3-letter ISO code")
		return
	}

	err = h.accountingService.UpdateCurrency(ctx, companyID, req.CurrencyCode, &userID)
	if err != nil {
		h.logger.Error("failed to update currency", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Currency updated successfully",
	})
}

// UpdateTaxScheme handles PUT /api/v1/accounting/settings/tax-scheme
// Updates the tax scheme (accrual or cash) for the company.
func (h *AccountingSettingsHandler) UpdateTaxScheme(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateTaxSchemeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TaxScheme != "accrual" && req.TaxScheme != "cash" {
		h.respondWithError(w, http.StatusBadRequest, "tax_scheme must be 'accrual' or 'cash'")
		return
	}

	err = h.accountingService.UpdateTaxScheme(ctx, companyID, req.TaxScheme, &userID)
	if err != nil {
		h.logger.Error("failed to update tax scheme", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax scheme updated successfully",
	})
}

// ---------- Helper Methods ----------

// parseCompanyID extracts and validates company_id from URL parameter.
func (h *AccountingSettingsHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID is required")
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid company ID format")
	}
	return companyID, nil
}

// hasPermission is a placeholder permission check. In production, integrate with RBAC.
func (h *AccountingSettingsHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Implement real permission check using RBAC service
	return true
}

// respondWithJSON sends a JSON response with the given status code and data.
func (h *AccountingSettingsHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError sends a JSON error response.
func (h *AccountingSettingsHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// getUserIDFromContext extracts the user ID from the request context.
