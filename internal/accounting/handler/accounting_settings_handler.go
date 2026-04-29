package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/settings"
	"auth-service/internal/accounting/service"
)

type AccountingSettingsHandler struct {
	accountingService service.AccountingService
	logger            *zap.Logger
}

func NewAccountingSettingsHandler(accountingService service.AccountingService, logger *zap.Logger) *AccountingSettingsHandler {
	return &AccountingSettingsHandler{
		accountingService: accountingService,
		logger:            logger.Named("accounting_settings_handler"),
	}
}

// -------------------- response/request types --------------------
type getSettingsResponse struct {
	CompanyID                string `json:"company_id"`
	FiscalYearStartMonth     int    `json:"fiscal_year_start_month"`
	CurrencyCode             string `json:"currency_code"`
	TaxScheme                string `json:"tax_scheme"`
	AllowIntercompanyJournal bool   `json:"allow_intercompany_journal"`
	AutoGenerateReversals    bool   `json:"auto_generate_reversals"`
}

type createSettingsRequest struct {
	CompanyID                string `json:"company_id"`
	FiscalYearStartMonth     int    `json:"fiscal_year_start_month"`
	CurrencyCode             string `json:"currency_code"`
	TaxScheme                string `json:"tax_scheme"`
	AllowIntercompanyJournal bool   `json:"allow_intercompany_journal"`
	AutoGenerateReversals    bool   `json:"auto_generate_reversals"`
}

type updateSettingsRequest struct {
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

type updateFlagsRequest struct {
	AllowIntercompanyJournal bool `json:"allow_intercompany_journal"`
	AutoGenerateReversals    bool `json:"auto_generate_reversals"`
}

// -------------------- Handlers --------------------

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
		// ✅ Use errors.Is instead of direct comparison
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
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

func (h *AccountingSettingsHandler) CreateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if req.FiscalYearStartMonth < 1 || req.FiscalYearStartMonth > 12 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year_start_month must be between 1 and 12")
		return
	}
	if len(req.CurrencyCode) != 3 {
		h.respondWithError(w, http.StatusBadRequest, "currency_code must be a 3-letter ISO code")
		return
	}
	if req.TaxScheme != "accrual" && req.TaxScheme != "cash" {
		h.respondWithError(w, http.StatusBadRequest, "tax_scheme must be 'accrual' or 'cash'")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	h.logger.Info("CreateSettings called",
		zap.String("company_id", companyID.String()),
		zap.String("idempotency_key", idempotencyKey),
		zap.String("user_id", userID.String()),
	)

	accSettings := &settings.AccountingSettings{
		CompanyID:                companyID,
		FiscalYearStartMonth:     req.FiscalYearStartMonth,
		CurrencyCode:             req.CurrencyCode,
		TaxScheme:                req.TaxScheme,
		AllowIntercompanyJournal: req.AllowIntercompanyJournal,
		AutoGenerateReversals:    req.AutoGenerateReversals,
		CreatedBy:                &userID,
		UpdatedBy:                &userID,
	}

	err = h.accountingService.CreateAccountingSettings(ctx, accSettings, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create accounting settings", zap.Error(err))
		if errors.Is(err, service.ErrDuplicate) {
			h.respondWithError(w, http.StatusConflict, "settings already exist for this company")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to create settings")
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/api/v1/accounting/settings?company_id=%s", companyID.String()))
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Accounting settings created successfully",
	})
}

func (h *AccountingSettingsHandler) UpsertSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if req.FiscalYearStartMonth < 1 || req.FiscalYearStartMonth > 12 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year_start_month must be between 1 and 12")
		return
	}
	if len(req.CurrencyCode) != 3 {
		h.respondWithError(w, http.StatusBadRequest, "currency_code must be a 3-letter ISO code")
		return
	}
	if req.TaxScheme != "accrual" && req.TaxScheme != "cash" {
		h.respondWithError(w, http.StatusBadRequest, "tax_scheme must be 'accrual' or 'cash'")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	accSettings := &settings.AccountingSettings{
		CompanyID:                companyID,
		FiscalYearStartMonth:     req.FiscalYearStartMonth,
		CurrencyCode:             req.CurrencyCode,
		TaxScheme:                req.TaxScheme,
		AllowIntercompanyJournal: req.AllowIntercompanyJournal,
		AutoGenerateReversals:    req.AutoGenerateReversals,
		CreatedBy:                &userID,
		UpdatedBy:                &userID,
	}

	err = h.accountingService.UpsertAccountingSettings(ctx, accSettings, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to upsert accounting settings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to upsert settings")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Accounting settings upserted successfully",
	})
}

func (h *AccountingSettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "accounting:settings:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FiscalYearStartMonth < 1 || req.FiscalYearStartMonth > 12 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year_start_month must be between 1 and 12")
		return
	}
	if len(req.CurrencyCode) != 3 {
		h.respondWithError(w, http.StatusBadRequest, "currency_code must be a 3-letter ISO code")
		return
	}
	if req.TaxScheme != "accrual" && req.TaxScheme != "cash" {
		h.respondWithError(w, http.StatusBadRequest, "tax_scheme must be 'accrual' or 'cash'")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	accSettings := &settings.AccountingSettings{
		CompanyID:                companyID,
		FiscalYearStartMonth:     req.FiscalYearStartMonth,
		CurrencyCode:             req.CurrencyCode,
		TaxScheme:                req.TaxScheme,
		AllowIntercompanyJournal: req.AllowIntercompanyJournal,
		AutoGenerateReversals:    req.AutoGenerateReversals,
		UpdatedBy:                &userID,
	}

	err = h.accountingService.UpdateAccountingSettings(ctx, accSettings, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update accounting settings", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update settings")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Accounting settings updated successfully",
	})
}

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

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.accountingService.UpdateFiscalYear(ctx, companyID, req.StartMonth, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update fiscal year", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update fiscal year")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fiscal year start month updated successfully",
	})
}

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

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.accountingService.UpdateCurrency(ctx, companyID, req.CurrencyCode, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update currency", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update currency")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Currency updated successfully",
	})
}

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

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.accountingService.UpdateTaxScheme(ctx, companyID, req.TaxScheme, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update tax scheme", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update tax scheme")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax scheme updated successfully",
	})
}

// UpdateFlags updates the boolean flags
func (h *AccountingSettingsHandler) UpdateFlags(w http.ResponseWriter, r *http.Request) {
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

	var req updateFlagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.accountingService.UpdateFlags(
		ctx,
		companyID,
		req.AllowIntercompanyJournal,
		req.AutoGenerateReversals,
		&userID,
		idempotencyKey,
	)

	if err != nil {
		h.logger.Error("failed to update flags", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update flags")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Flags updated successfully",
	})
}

// ExistsSettings checks whether accounting settings exist for a company.
func (h *AccountingSettingsHandler) ExistsSettings(w http.ResponseWriter, r *http.Request) {
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

	exists, err := h.accountingService.ExistsAccountingSettings(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to check existence of accounting settings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check settings")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"exists":  exists,
	})
}

// GetFiscalPeriod returns the fiscal year and period for a given date.
func (h *AccountingSettingsHandler) GetFiscalPeriod(w http.ResponseWriter, r *http.Request) {
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

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	fiscalYear, period, err := h.accountingService.GetFiscalYearPeriod(ctx, companyID, date)
	if err != nil {
		h.logger.Error("failed to get fiscal period", zap.Error(err))
		if errors.Is(err, service.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "settings not found for company")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to get fiscal period")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"fiscal_year": fiscalYear,
		"period":      period,
	})
}

// -------------------- Helper functions --------------------

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

// hasPermission always returns true because permissions are enforced at the router level.
func (h *AccountingSettingsHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	return true
}

func (h *AccountingSettingsHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *AccountingSettingsHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// getUserIDFromContext is assumed to exist in the same package (e.g., from auth middleware)
// func getUserIDFromContext(ctx context.Context) (uuid.UUID, error)
