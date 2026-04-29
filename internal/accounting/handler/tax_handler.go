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

	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type TaxHandler struct {
	taxSvc service.TaxEngineService
	logger *zap.Logger
}

func NewTaxHandler(taxSvc service.TaxEngineService, logger *zap.Logger) *TaxHandler {
	return &TaxHandler{
		taxSvc: taxSvc,
		logger: logger.Named("tax_handler"),
	}
}

// ----------------------------------------------------------------------------
// Tax Rate handlers
// ----------------------------------------------------------------------------

type createTaxRateRequest struct {
	TaxName        string          `json:"tax_name"`
	RatePercentage decimal.Decimal `json:"rate_percentage"`
	EffectiveFrom  time.Time       `json:"effective_from"`
	EffectiveTo    *time.Time      `json:"effective_to,omitempty"`
	IsActive       bool            `json:"is_active"`
}

func (h *TaxHandler) CreateTaxRate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:rate:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createTaxRateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if req.RatePercentage.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "rate percentage must be greater than 0")
		return
	}
	if req.TaxName == "" {
		h.respondWithError(w, http.StatusBadRequest, "tax name is required")
		return
	}

	rate := &tax.TaxRate{
		TaxRateID:      uuid.New(),
		CompanyID:      companyID,
		TaxName:        req.TaxName,
		RatePercentage: req.RatePercentage,
		EffectiveFrom:  req.EffectiveFrom,
		EffectiveTo:    req.EffectiveTo,
		IsActive:       req.IsActive,
		CreatedBy:      &userID,
		UpdatedBy:      &userID,
	}

	// Idempotency
	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.CreateTaxRate(ctx, rate); err != nil {
		h.logger.Error("failed to create tax rate", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    rate,
		"message": "Tax rate created successfully",
	})
}

type updateTaxRateRequest struct {
	TaxName        *string          `json:"tax_name,omitempty"`
	RatePercentage *decimal.Decimal `json:"rate_percentage,omitempty"`
	EffectiveFrom  *time.Time       `json:"effective_from,omitempty"`
	EffectiveTo    *time.Time       `json:"effective_to,omitempty"`
	IsActive       *bool            `json:"is_active,omitempty"`
}

func (h *TaxHandler) UpdateTaxRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	rateID, err := uuid.Parse(chi.URLParam(r, "rateID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax rate ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:rate:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Fetch directly – service should provide GetByID; fallback to list+scan (inefficient but safe)
	// For production, implement GetTaxRateByID in service.
	filter := repository.TaxRateFilter{CompanyID: companyID}
	rates, _, err := h.taxSvc.ListTaxRates(ctx, filter, repository.Pagination{Limit: 1000}, repository.Sort{})
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch tax rate")
		return
	}

	var existing *tax.TaxRate
	for _, r := range rates {
		if r.TaxRateID == rateID {
			existing = r
			break
		}
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "tax rate not found")
		return
	}

	var req updateTaxRateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TaxName != nil {
		existing.TaxName = *req.TaxName
	}
	if req.RatePercentage != nil {
		if req.RatePercentage.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "rate percentage must be > 0")
			return
		}
		existing.RatePercentage = *req.RatePercentage
	}
	if req.EffectiveFrom != nil {
		existing.EffectiveFrom = *req.EffectiveFrom
	}
	if req.EffectiveTo != nil {
		existing.EffectiveTo = req.EffectiveTo
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}
	existing.UpdatedBy = &userID

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.UpdateTaxRate(ctx, existing); err != nil {
		h.logger.Error("failed to update tax rate", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    existing,
		"message": "Tax rate updated successfully",
	})
}

func (h *TaxHandler) ListTaxRates(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:rate:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.TaxRateFilter{CompanyID: companyID}
	if taxName := query.Get("tax_name"); taxName != "" {
		filter.TaxName = taxName
	}
	if activeStr := query.Get("is_active"); activeStr != "" {
		active, _ := strconv.ParseBool(activeStr)
		filter.IsActive = &active
	}

	pagination := parsePagination(query)
	sort := parseSort(query)

	rates, total, err := h.taxSvc.ListTaxRates(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list tax rates", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax rates")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  rates,
			"total":  total,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

func (h *TaxHandler) DeleteTaxRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	rateID, err := uuid.Parse(chi.URLParam(r, "rateID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax rate ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:rate:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	// ✅ FIXED: added companyID parameter
	if err := h.taxSvc.DeleteTaxRate(ctx, companyID, rateID, &userID); err != nil {
		h.logger.Error("failed to delete tax rate", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax rate deleted successfully",
	})
}

func (h *TaxHandler) CloseOpenRates(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:rate:close") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		TaxName    string    `json:"tax_name"`
		BeforeDate time.Time `json:"before_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	// ✅ FIXED: added updatedBy parameter
	if err := h.taxSvc.CloseOpenRates(ctx, companyID, req.TaxName, req.BeforeDate, &userID); err != nil {
		h.logger.Error("failed to close open rates", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Open rates closed successfully",
	})
}

// ----------------------------------------------------------------------------
// Tax Rule handlers
// ----------------------------------------------------------------------------

type createTaxRuleRequest struct {
	RuleName   string             `json:"rule_name"`
	AppliesTo  string             `json:"applies_to"`
	Priority   int                `json:"priority"`
	IsActive   bool               `json:"is_active"`
	Conditions []tax.TaxCondition `json:"conditions,omitempty"`
	Actions    []tax.TaxAction    `json:"actions,omitempty"`
}

func (h *TaxHandler) CreateTaxRule(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:rule:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createTaxRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rule := &tax.TaxRule{
		TaxRuleID: uuid.New(),
		CompanyID: companyID,
		RuleName:  req.RuleName,
		AppliesTo: req.AppliesTo,
		Priority:  req.Priority,
		IsActive:  req.IsActive,
		CreatedBy: &userID,
		UpdatedBy: &userID,
	}

	conditions := make([]*tax.TaxCondition, len(req.Conditions))
	for i := range req.Conditions {
		req.Conditions[i].ConditionID = uuid.New()
		req.Conditions[i].TaxRuleID = rule.TaxRuleID
		conditions[i] = &req.Conditions[i]
	}

	actions := make([]*tax.TaxAction, len(req.Actions))
	for i := range req.Actions {
		req.Actions[i].ActionID = uuid.New()
		req.Actions[i].TaxRuleID = rule.TaxRuleID
		actions[i] = &req.Actions[i]
	}

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.CreateTaxRule(ctx, rule, conditions, actions); err != nil {
		h.logger.Error("failed to create tax rule", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    rule,
		"message": "Tax rule created successfully",
	})
}

type updateTaxRuleRequest struct {
	RuleName   *string            `json:"rule_name,omitempty"`
	AppliesTo  *string            `json:"applies_to,omitempty"`
	Priority   *int               `json:"priority,omitempty"`
	IsActive   *bool              `json:"is_active,omitempty"`
	Conditions []tax.TaxCondition `json:"conditions,omitempty"`
	Actions    []tax.TaxAction    `json:"actions,omitempty"`
}

func (h *TaxHandler) UpdateTaxRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax rule ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:rule:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIXED: added companyID parameter
	bundle, err := h.taxSvc.GetRuleBundle(ctx, companyID, ruleID)
	if err != nil || bundle == nil {
		h.respondWithError(w, http.StatusNotFound, "tax rule not found")
		return
	}
	rule := bundle.Rule

	var req updateTaxRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RuleName != nil {
		rule.RuleName = *req.RuleName
	}
	if req.AppliesTo != nil {
		rule.AppliesTo = *req.AppliesTo
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsActive != nil {
		rule.IsActive = *req.IsActive
	}
	rule.UpdatedBy = &userID

	conditions := make([]*tax.TaxCondition, len(req.Conditions))
	for i := range req.Conditions {
		req.Conditions[i].ConditionID = uuid.New()
		req.Conditions[i].TaxRuleID = rule.TaxRuleID
		conditions[i] = &req.Conditions[i]
	}

	actions := make([]*tax.TaxAction, len(req.Actions))
	for i := range req.Actions {
		req.Actions[i].ActionID = uuid.New()
		req.Actions[i].TaxRuleID = rule.TaxRuleID
		actions[i] = &req.Actions[i]
	}

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.UpdateTaxRule(ctx, rule, conditions, actions); err != nil {
		h.logger.Error("failed to update tax rule", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rule,
		"message": "Tax rule updated successfully",
	})
}

func (h *TaxHandler) DeleteTaxRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax rule ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:rule:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	// ✅ FIXED: added companyID parameter
	if err := h.taxSvc.DeleteTaxRule(ctx, companyID, ruleID, &userID); err != nil {
		h.logger.Error("failed to delete tax rule", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax rule deleted successfully",
	})
}

func (h *TaxHandler) GetRuleBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax rule ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:rule:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIXED: added companyID parameter
	bundle, err := h.taxSvc.GetRuleBundle(ctx, companyID, ruleID)
	if err != nil || bundle == nil {
		h.respondWithError(w, http.StatusNotFound, "tax rule not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    bundle,
	})
}

// ----------------------------------------------------------------------------
// Tax Profile handlers
// ----------------------------------------------------------------------------

type createTaxProfileRequest struct {
	TaxRegime          string     `json:"tax_regime"`
	Jurisdiction       string     `json:"jurisdiction"`
	RegistrationNumber *string    `json:"registration_number,omitempty"`
	DefaultTaxRateID   *uuid.UUID `json:"default_tax_rate_id,omitempty"`
	Settings           []byte     `json:"settings,omitempty"`
	IsActive           bool       `json:"is_active"`
}

func (h *TaxHandler) CreateTaxProfile(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:profile:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createTaxProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	profile := &tax.TaxProfile{
		TaxProfileID:       uuid.New(),
		CompanyID:          companyID,
		TaxRegime:          req.TaxRegime,
		Jurisdiction:       req.Jurisdiction,
		RegistrationNumber: req.RegistrationNumber,
		DefaultTaxRateID:   req.DefaultTaxRateID,
		Settings:           req.Settings,
		IsActive:           req.IsActive,
		CreatedBy:          &userID,
		UpdatedBy:          &userID,
	}

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.CreateTaxProfile(ctx, profile); err != nil {
		h.logger.Error("failed to create tax profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    profile,
		"message": "Tax profile created successfully",
	})
}

type updateTaxProfileRequest struct {
	TaxRegime          *string    `json:"tax_regime,omitempty"`
	Jurisdiction       *string    `json:"jurisdiction,omitempty"`
	RegistrationNumber *string    `json:"registration_number,omitempty"`
	DefaultTaxRateID   *uuid.UUID `json:"default_tax_rate_id,omitempty"`
	Settings           []byte     `json:"settings,omitempty"`
	IsActive           *bool      `json:"is_active,omitempty"`
}

func (h *TaxHandler) UpdateTaxProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	profileID, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax profile ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:profile:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Fetch existing profile
	profiles, err := h.taxSvc.ListTaxProfiles(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch profile")
		return
	}
	var profile *tax.TaxProfile
	for _, p := range profiles {
		if p.TaxProfileID == profileID {
			profile = p
			break
		}
	}
	if profile == nil {
		h.respondWithError(w, http.StatusNotFound, "tax profile not found")
		return
	}

	var req updateTaxProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TaxRegime != nil {
		profile.TaxRegime = *req.TaxRegime
	}
	if req.Jurisdiction != nil {
		profile.Jurisdiction = *req.Jurisdiction
	}
	if req.RegistrationNumber != nil {
		profile.RegistrationNumber = req.RegistrationNumber
	}
	if req.DefaultTaxRateID != nil {
		profile.DefaultTaxRateID = req.DefaultTaxRateID
	}
	if req.Settings != nil {
		profile.Settings = req.Settings
	}
	if req.IsActive != nil {
		profile.IsActive = *req.IsActive
	}
	profile.UpdatedBy = &userID

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.UpdateTaxProfile(ctx, profile); err != nil {
		h.logger.Error("failed to update tax profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profile,
		"message": "Tax profile updated successfully",
	})
}

func (h *TaxHandler) ListTaxProfiles(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:profile:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	profiles, err := h.taxSvc.ListTaxProfiles(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to list tax profiles", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax profiles")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profiles,
	})
}

func (h *TaxHandler) SetDefaultTaxProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	profileID, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax profile ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:profile:set_default") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.SetDefaultTaxProfile(ctx, companyID, profileID); err != nil {
		h.logger.Error("failed to set default tax profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Default tax profile set successfully",
	})
}

func (h *TaxHandler) DeleteTaxProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	profileID, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid tax profile ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:profile:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	// ✅ FIXED: added companyID parameter
	if err := h.taxSvc.DeleteTaxProfile(ctx, companyID, profileID, &userID); err != nil {
		h.logger.Error("failed to delete tax profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax profile deleted successfully",
	})
}

// ----------------------------------------------------------------------------
// Tax Transaction handlers
// ----------------------------------------------------------------------------

type createTaxTransactionRequest struct {
	TransactionType    string          `json:"transaction_type"`
	TransactionID      uuid.UUID       `json:"transaction_id"`
	TaxRuleID          *uuid.UUID      `json:"tax_rule_id,omitempty"`
	TaxRateID          *uuid.UUID      `json:"tax_rate_id,omitempty"`
	TaxableAmount      decimal.Decimal `json:"taxable_amount"`
	TaxAmount          decimal.Decimal `json:"tax_amount"`
	Currency           string          `json:"currency"`
	ExchangeRate       decimal.Decimal `json:"exchange_rate"`
	BaseCurrencyAmount decimal.Decimal `json:"base_currency_amount"`
	TransactionDate    time.Time       `json:"transaction_date"`
}

func (h *TaxHandler) CreateTaxTransaction(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:transaction:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createTaxTransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svcReq := service.CreateTaxTransactionRequest{
		CompanyID:          companyID,
		TransactionType:    req.TransactionType,
		TransactionID:      req.TransactionID,
		TaxRuleID:          req.TaxRuleID,
		TaxRateID:          req.TaxRateID,
		TaxableAmount:      req.TaxableAmount,
		TaxAmount:          req.TaxAmount,
		Currency:           req.Currency,
		ExchangeRate:       req.ExchangeRate,
		BaseCurrencyAmount: req.BaseCurrencyAmount,
		TransactionDate:    req.TransactionDate,
	}

	ctx = withIdempotencyKey(ctx, r)

	tx, err := h.taxSvc.CreateTaxTransaction(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create tax transaction", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    tx,
		"message": "Tax transaction created successfully",
	})
}

func (h *TaxHandler) GetTransactionTaxBreakdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transactionType := chi.URLParam(r, "transactionType")
	transactionIDStr := chi.URLParam(r, "transactionID")
	transactionID, err := uuid.Parse(transactionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid transaction ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:transaction:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	transactions, err := h.taxSvc.GetTransactionTaxBreakdown(ctx, transactionType, transactionID)
	if err != nil {
		h.logger.Error("failed to get tax breakdown", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax breakdown")
		return
	}

	// Security: verify all returned transactions belong to the company
	for _, tx := range transactions {
		if tx.CompanyID != companyID {
			h.respondWithError(w, http.StatusForbidden, "cross-company data access denied")
			return
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    transactions,
	})
}

func (h *TaxHandler) VoidTaxTransaction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	transactionType := chi.URLParam(r, "transactionType")
	transactionIDStr := chi.URLParam(r, "transactionID")
	transactionID, err := uuid.Parse(transactionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid transaction ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "tax:transaction:void") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx = withIdempotencyKey(ctx, r)

	if err := h.taxSvc.VoidTaxTransaction(ctx, transactionType, transactionID, req.Reason); err != nil {
		h.logger.Error("failed to void tax transaction", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tax transaction voided successfully",
	})
}

// ----------------------------------------------------------------------------
// Computation & evaluation handlers
// ----------------------------------------------------------------------------

type computeTaxRequest struct {
	Amount          decimal.Decimal        `json:"amount"`
	Currency        string                 `json:"currency"`
	TransactionType string                 `json:"transaction_type"`
	ProductType     string                 `json:"product_type"`
	CustomerType    string                 `json:"customer_type"`
	Jurisdiction    string                 `json:"jurisdiction"`
	Date            time.Time              `json:"date"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

func (h *TaxHandler) ComputeTax(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:compute") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req computeTaxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := service.TaxComputationInput{
		Amount:          req.Amount,
		Currency:        req.Currency,
		TransactionType: req.TransactionType,
		ProductType:     req.ProductType,
		CustomerType:    req.CustomerType,
		Jurisdiction:    req.Jurisdiction,
		Date:            req.Date,
		Metadata:        req.Metadata,
	}

	result, err := h.taxSvc.ComputeTaxBreakdown(ctx, companyID, input)
	if err != nil {
		h.logger.Error("failed to compute tax", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

type evaluateRulesRequest struct {
	AppliesTo string                 `json:"applies_to"`
	Data      map[string]interface{} `json:"data"`
}

func (h *TaxHandler) EvaluateRules(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:evaluate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req evaluateRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	results, err := h.taxSvc.EvaluateRules(ctx, companyID, req.AppliesTo, req.Data)
	if err != nil {
		h.logger.Error("failed to evaluate rules", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    results,
	})
}

// ----------------------------------------------------------------------------
// Reporting handlers
// ----------------------------------------------------------------------------

func (h *TaxHandler) GenerateTaxReturn(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:return:generate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}

	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format (use YYYY-MM-DD)")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format (use YYYY-MM-DD)")
		return
	}

	taxReturn, err := h.taxSvc.GenerateTaxReturn(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to generate tax return", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate tax return")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    taxReturn,
	})
}

func (h *TaxHandler) GetTaxSummary(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "tax:summary:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}

	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date format (use YYYY-MM-DD)")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date format (use YYYY-MM-DD)")
		return
	}

	summary, err := h.taxSvc.GetTaxSummary(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get tax summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	return uuid.Parse(companyIDStr)
}

func parsePagination(query map[string][]string) repository.Pagination {
	limit := 10
	if l, err := strconv.Atoi(getQueryParam(query, "limit")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(getQueryParam(query, "offset")); err == nil && o >= 0 {
		offset = o
	}
	return repository.Pagination{Limit: limit, Offset: offset}
}

func parseSort(query map[string][]string) repository.Sort {
	field := getQueryParam(query, "sort_field")
	if field == "" {
		field = "created_at"
	}
	direction := getQueryParam(query, "sort_order")
	if direction == "" {
		direction = "desc"
	}
	return repository.Sort{Field: field, Direction: direction}
}

func getQueryParam(query map[string][]string, key string) string {
	if vals, ok := query[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Placeholder – replace with actual auth/permission logic
func (h *TaxHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	return true
}

// Helper to inject idempotency key into context
func withIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		ctx = context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// Placeholder – replace with actual user extraction from JWT, etc.

func (h *TaxHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TaxHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
