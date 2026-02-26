package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type StatutoryProfileHandler struct {
	profileService service.StatutoryProfileService
	engine         service.StatutoryEngine
	logger         *zap.Logger
}

func NewStatutoryProfileHandler(
	profileService service.StatutoryProfileService,
	engine service.StatutoryEngine,
	logger *zap.Logger,
) *StatutoryProfileHandler {
	return &StatutoryProfileHandler{
		profileService: profileService,
		engine:         engine,
		logger:         logger,
	}
}

// Request / response types
type createStatutoryProfileRequest struct {
	UserID        uuid.UUID `json:"user_id"`
	StatutoryCode string    `json:"statutory_code"`
	OptIn         bool      `json:"opt_in"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type updateStatutoryProfileRequest struct {
	OptIn         *bool     `json:"opt_in,omitempty"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type changeTaxRegimeRequest struct {
	TaxRegimeCode string    `json:"tax_regime_code"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type bulkUpsertProfileRequest struct {
	Profiles []createStatutoryProfileRequest `json:"profiles"`
}

type createRuleSetRequest struct {
	CountryCode   string    `json:"country_code"`
	VersionLabel  string    `json:"version_label"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type updateRuleSetRequest struct {
	VersionLabel  string     `json:"version_label"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      bool       `json:"is_active"`
}

type createComponentDefinitionRequest struct {
	StatutoryCode    string `json:"statutory_code"`
	Description      string `json:"description"`
	CountryCode      string `json:"country_code"`
	CalculationBasis string `json:"calculation_basis"`
	HasEmployee      bool   `json:"has_employee"`
	HasEmployer      bool   `json:"has_employer"`
}

type setContributionRuleRequest struct {
	StatutoryCode    string    `json:"statutory_code"`
	ContributionSide string    `json:"contribution_side"`
	CalculationType  string    `json:"calculation_type"`
	RateValue        *float64  `json:"rate_value"`
	WageCeiling      *float64  `json:"wage_ceiling"`
	MinThreshold     *float64  `json:"min_threshold"`
	EffectiveFrom    time.Time `json:"effective_from"`
}

// Tax slab request (used directly from service.CreateTaxSlabInput, but we redefine for clarity)
type createTaxSlabRequest struct {
	StatutoryCode string    `json:"statutory_code"`
	MinAmount     float64   `json:"min_amount"`
	MaxAmount     *float64  `json:"max_amount,omitempty"`
	Rate          float64   `json:"rate"`
	IsPercentage  bool      `json:"is_percentage"`
	SlabOrder     int       `json:"slab_order"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type updateTaxSlabRequest struct {
	MinAmount     *float64   `json:"min_amount,omitempty"`
	MaxAmount     *float64   `json:"max_amount,omitempty"`
	Rate          *float64   `json:"rate,omitempty"`
	IsPercentage  *bool      `json:"is_percentage,omitempty"`
	SlabOrder     *int       `json:"slab_order,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
}

// Deduction limit request
type createDeductionLimitRequest struct {
	LimitCode  string                 `json:"limit_code"`
	LimitValue float64                `json:"limit_value"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type updateDeductionLimitRequest struct {
	LimitValue *float64               `json:"limit_value,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Component mapping request
type createComponentMappingRequest struct {
	StatutoryCode string    `json:"statutory_code"`
	ComponentCode string    `json:"component_code"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type updateComponentMappingRequest struct {
	ComponentCode *string    `json:"component_code,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
	Version       int        `json:"version"`
}

// Response helpers
type statutoryProfileResponse struct {
	ProfileID     uuid.UUID  `json:"profile_id"`
	CompanyID     uuid.UUID  `json:"company_id"`
	UserID        uuid.UUID  `json:"user_id"`
	StatutoryCode string     `json:"statutory_code"`
	OptIn         bool       `json:"opt_in"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      bool       `json:"is_active"`
	CreatedAt     time.Time  `json:"created_at"`
	CreatedBy     uuid.UUID  `json:"created_by"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

func mapProfileToResponse(p *models.StatutoryProfileVersion) statutoryProfileResponse {
	return statutoryProfileResponse{
		ProfileID:     p.ProfileID,
		CompanyID:     p.CompanyID,
		UserID:        p.UserID,
		StatutoryCode: p.StatutoryCode,
		OptIn:         p.OptIn,
		EffectiveFrom: p.EffectiveFrom,
		EffectiveTo:   p.EffectiveTo,
		IsActive:      p.IsActive,
		CreatedAt:     p.CreatedAt,
		CreatedBy:     p.CreatedBy,
	}
}

// ----------------------------------------------------------------------
// Existing handlers (profiles, rule sets, component definitions, etc.)
// ----------------------------------------------------------------------

func (h *StatutoryProfileHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createStatutoryProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.CreateStatutoryProfileInput{
		CompanyID:     companyID,
		UserID:        req.UserID,
		StatutoryCode: req.StatutoryCode,
		OptIn:         req.OptIn,
		EffectiveFrom: req.EffectiveFrom,
		CreatedBy:     actorID,
	}
	profile, err := h.profileService.CreateProfile(ctx, input)
	if err != nil {
		h.logger.Error("failed to create statutory profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    mapProfileToResponse(profile),
	})
}

func (h *StatutoryProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	profileID, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateStatutoryProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.UpdateStatutoryProfileInput{
		ProfileID:     profileID,
		OptIn:         req.OptIn,
		EffectiveFrom: req.EffectiveFrom,
		UpdatedBy:     actorID,
	}
	profile, err := h.profileService.UpdateProfile(ctx, input)
	if err != nil {
		h.logger.Error("failed to update statutory profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapProfileToResponse(profile),
	})
}

func (h *StatutoryProfileHandler) DeactivateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	profileID, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.profileService.DeactivateProfile(ctx, profileID, actorID); err != nil {
		h.logger.Error("failed to deactivate statutory profile", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "statutory profile deactivated",
	})
}

func (h *StatutoryProfileHandler) ChangeTaxRegime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req changeTaxRegimeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.ChangeTaxRegimeInput{
		CompanyID:     companyID,
		UserID:        userID,
		TaxRegimeCode: req.TaxRegimeCode,
		EffectiveFrom: req.EffectiveFrom,
		ChangedBy:     actorID,
	}
	profile, err := h.profileService.ChangeTaxRegime(ctx, input)
	if err != nil {
		h.logger.Error("failed to change tax regime", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapProfileToResponse(profile),
	})
}

func (h *StatutoryProfileHandler) BulkUpsertProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req bulkUpsertProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	inputs := make([]*models.CreateStatutoryProfileInput, 0, len(req.Profiles))
	for _, p := range req.Profiles {
		inputs = append(inputs, &models.CreateStatutoryProfileInput{
			CompanyID:     companyID,
			UserID:        p.UserID,
			StatutoryCode: p.StatutoryCode,
			OptIn:         p.OptIn,
			EffectiveFrom: p.EffectiveFrom,
			CreatedBy:     actorID,
		})
	}
	if err := h.profileService.BulkUpsertProfiles(ctx, inputs); err != nil {
		h.logger.Error("failed to bulk upsert statutory profiles", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "profiles upserted successfully",
	})
}

func (h *StatutoryProfileHandler) GetActiveProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	statutoryCode := chi.URLParam(r, "code")
	if statutoryCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "statutory code required")
		return
	}
	asOf := time.Now().UTC()
	if asOfStr := r.URL.Query().Get("asOf"); asOfStr != "" {
		parsed, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid asOf format, use RFC3339")
			return
		}
		asOf = parsed
	}
	profile, err := h.profileService.GetActiveProfile(ctx, companyID, userID, statutoryCode, asOf)
	if err != nil {
		h.logger.Error("failed to get active statutory profile", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profile == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nil,
		})
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapProfileToResponse(profile),
	})
}

func (h *StatutoryProfileHandler) GetEmployeeActiveProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	asOf := time.Now().UTC()
	if asOfStr := r.URL.Query().Get("asOf"); asOfStr != "" {
		parsed, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid asOf format, use RFC3339")
			return
		}
		asOf = parsed
	}
	profiles, err := h.profileService.GetEmployeeActiveProfiles(ctx, companyID, userID, asOf)
	if err != nil {
		h.logger.Error("failed to get employee active profiles", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]statutoryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, mapProfileToResponse(p))
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *StatutoryProfileHandler) GetProfileHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	statutoryCode := chi.URLParam(r, "code")
	if statutoryCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "statutory code required")
		return
	}
	profiles, err := h.profileService.GetProfileHistory(ctx, companyID, userID, statutoryCode)
	if err != nil {
		h.logger.Error("failed to get profile history", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]statutoryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, mapProfileToResponse(p))
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *StatutoryProfileHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	var userID *uuid.UUID
	if uidStr := r.URL.Query().Get("user_id"); uidStr != "" {
		uid, err := uuid.Parse(uidStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id format")
			return
		}
		userID = &uid
	}
	var statutoryCode *string
	if code := r.URL.Query().Get("statutory_code"); code != "" {
		statutoryCode = &code
	}
	var activeOn *time.Time
	if aoStr := r.URL.Query().Get("active_on"); aoStr != "" {
		parsed, err := time.Parse(time.RFC3339, aoStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid active_on format, use RFC3339")
			return
		}
		activeOn = &parsed
	}
	page := parseIntQuery(r, "page", 1)
	pageSize := parseIntQuery(r, "page_size", 20)

	filter := &models.StatutoryProfileFilter{
		CompanyID:     companyID,
		UserID:        userID,
		StatutoryCode: statutoryCode,
		ActiveOn:      activeOn,
		Page:          page,
		PageSize:      pageSize,
	}
	profiles, total, err := h.profileService.ListProfiles(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list statutory profiles", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]statutoryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, mapProfileToResponse(p))
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
		"total":   total,
		"page":    page,
		"size":    pageSize,
	})
}

// ------------------------------
// Rule set handlers
// ------------------------------

func (h *StatutoryProfileHandler) CreateRuleSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createRuleSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := &models.CreateRuleSetInput{
		CompanyID:     companyID,
		CountryCode:   req.CountryCode,
		VersionLabel:  req.VersionLabel,
		EffectiveFrom: req.EffectiveFrom,
		ActorID:       actorID,
	}
	if err := h.engine.CreateRuleSet(ctx, input); err != nil {
		h.logger.Error("failed to create rule set", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "rule set created successfully",
	})
}

func (h *StatutoryProfileHandler) DeactivateRuleSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.engine.DeactivateRuleSet(ctx, ruleSetID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "rule set deactivated",
	})
}

func (h *StatutoryProfileHandler) UpdateRuleSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	var req updateRuleSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &models.UpdateRuleSetInput{
		RuleSetID:     ruleSetID,
		CompanyID:     companyID,
		VersionLabel:  req.VersionLabel,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		IsActive:      req.IsActive,
	}
	if err := h.engine.UpdateRuleSet(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "rule set updated",
	})
}

func (h *StatutoryProfileHandler) ListRuleSets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSets, err := h.engine.ListRuleSets(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ruleSets,
	})
}

func (h *StatutoryProfileHandler) ActivateRuleSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.engine.ActivateRuleSet(ctx, ruleSetID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "rule set activated",
	})
}

// ------------------------------
// Component definition handlers
// ------------------------------

func (h *StatutoryProfileHandler) CreateComponentDefinition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req createComponentDefinitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.CreateComponentDefinitionInput{
		CompanyID:        companyID,
		StatutoryCode:    req.StatutoryCode,
		Description:      req.Description,
		CountryCode:      req.CountryCode,
		CalculationBasis: req.CalculationBasis,
		HasEmployee:      req.HasEmployee,
		HasEmployer:      req.HasEmployer,
		ActorID:          actorID,
	}
	if err := h.engine.CreateComponentDefinition(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
	})
}

func (h *StatutoryProfileHandler) ListComponentDefinitions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	defs, err := h.engine.ListComponentDefinitions(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    defs,
	})
}

// NEW: UpdateComponentDefinition
func (h *StatutoryProfileHandler) UpdateComponentDefinition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	code := chi.URLParam(r, "statutoryCode")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "statutory code required")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createComponentDefinitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}

	input := &service.UpdateComponentDefinitionInput{
		CompanyID:        companyID,
		StatutoryCode:    code,
		Description:      req.Description,
		CalculationBasis: req.CalculationBasis,
		HasEmployee:      req.HasEmployee,
		HasEmployer:      req.HasEmployer,
		ActorID:          actorID,
	}
	if err := h.engine.UpdateComponentDefinition(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// NEW: DeleteComponentDefinition
func (h *StatutoryProfileHandler) DeleteComponentDefinition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	code := chi.URLParam(r, "statutoryCode")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "statutory code required")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.engine.DeleteComponentDefinition(ctx, companyID, code, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ------------------------------
// Contribution rule handlers
// ------------------------------

func (h *StatutoryProfileHandler) SetContributionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req setContributionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ContributionSide != "employee" && req.ContributionSide != "employer" {
		h.respondWithError(w, http.StatusBadRequest, "invalid contribution_side: must be 'employee' or 'employer'")
		return
	}
	if req.CalculationType != "percentage" && req.CalculationType != "fixed" && req.CalculationType != "slab" {
		h.respondWithError(w, http.StatusBadRequest, "invalid calculation_type: must be 'percentage', 'fixed', or 'slab'")
		return
	}
	if req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "effective_from is required")
		return
	}
	input := &models.CreateStatutoryContributionRuleInput{
		CompanyID:        companyID,
		RuleSetID:        ruleSetID,
		StatutoryCode:    req.StatutoryCode,
		ContributionSide: req.ContributionSide,
		CalculationType:  req.CalculationType,
		RateValue:        req.RateValue,
		WageCeiling:      req.WageCeiling,
		MinThreshold:     req.MinThreshold,
		EffectiveFrom:    req.EffectiveFrom,
		ActorID:          actorID,
	}
	if err := h.engine.SetContributionRule(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) ListContributionRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	code := r.URL.Query().Get("statutory_code")
	rules, err := h.engine.ListContributionRules(ctx, companyID, code)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *StatutoryProfileHandler) DeactivateContributionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.engine.DeactivateContributionRule(ctx, ruleID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// Aliases for router compatibility
func (h *StatutoryProfileHandler) CreateContributionRule(w http.ResponseWriter, r *http.Request) {
	h.SetContributionRule(w, r)
}

func (h *StatutoryProfileHandler) UpdateContributionRule(w http.ResponseWriter, r *http.Request) {
	h.SetContributionRule(w, r)
}

func (h *StatutoryProfileHandler) DeleteContributionRule(w http.ResponseWriter, r *http.Request) {
	h.DeactivateContributionRule(w, r)
}

// ------------------------------
// Tax slab handlers
// ------------------------------

func (h *StatutoryProfileHandler) CreateTaxSlab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req createTaxSlabRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.CreateTaxSlabInput{
		CompanyID:     companyID,
		StatutoryCode: req.StatutoryCode,
		MinAmount:     req.MinAmount,
		MaxAmount:     req.MaxAmount,
		Rate:          req.Rate,
		IsPercentage:  req.IsPercentage,
		SlabOrder:     req.SlabOrder,
		EffectiveFrom: req.EffectiveFrom,
		RuleSetID:     ruleSetID,
		ActorID:       actorID,
	}
	if err := h.engine.CreateTaxSlab(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) ListTaxSlabs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	statutoryCode := chi.URLParam(r, "statutoryCode")
	if statutoryCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "statutory code required")
		return
	}
	slabs, err := h.engine.ListTaxSlabs(ctx, companyID, statutoryCode)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    slabs,
	})
}

func (h *StatutoryProfileHandler) UpdateTaxSlab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slabID, err := uuid.Parse(chi.URLParam(r, "slabID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slabID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req updateTaxSlabRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.UpdateTaxSlabInput{
		SlabID:        slabID,
		MinAmount:     req.MinAmount,
		MaxAmount:     req.MaxAmount,
		Rate:          req.Rate,
		IsPercentage:  req.IsPercentage,
		SlabOrder:     req.SlabOrder,
		EffectiveFrom: req.EffectiveFrom,
		ActorID:       actorID,
	}
	if err := h.engine.UpdateTaxSlab(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) DeleteTaxSlab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slabID, err := uuid.Parse(chi.URLParam(r, "slabID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slabID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// Engine uses DeactivateTaxSlab for deletion
	if err := h.engine.DeactivateTaxSlab(ctx, slabID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ------------------------------
// Deduction limit handlers
// ------------------------------

func (h *StatutoryProfileHandler) CreateDeductionLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req createDeductionLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.CreateDeductionLimitInput{
		CompanyID:  companyID,
		RuleSetID:  ruleSetID,
		LimitCode:  req.LimitCode,
		LimitValue: req.LimitValue,
		Metadata:   req.Metadata,
		ActorID:    actorID,
	}
	if err := h.engine.CreateDeductionLimit(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) ListDeductionLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	var ruleSetID *uuid.UUID
	if rs := chi.URLParam(r, "ruleSetID"); rs != "" {
		if id, err := uuid.Parse(rs); err == nil {
			ruleSetID = &id
		}
	}
	limits, err := h.engine.ListDeductionLimits(ctx, companyID, ruleSetID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    limits,
	})
}

func (h *StatutoryProfileHandler) UpdateDeductionLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limitID, err := uuid.Parse(chi.URLParam(r, "limitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid limitID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req updateDeductionLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.UpdateDeductionLimitInput{
		LimitID:    limitID,
		LimitValue: req.LimitValue,
		Metadata:   req.Metadata,
		ActorID:    actorID,
	}
	if err := h.engine.UpdateDeductionLimit(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) DeleteDeductionLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limitID, err := uuid.Parse(chi.URLParam(r, "limitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid limitID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.engine.DeleteDeductionLimit(ctx, limitID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ------------------------------
// Component mapping handlers
// ------------------------------

func (h *StatutoryProfileHandler) CreateComponentMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ruleSetID, err := uuid.Parse(chi.URLParam(r, "ruleSetID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid ruleSetID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req createComponentMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.CreateComponentMappingInput{
		CompanyID:     companyID,
		StatutoryCode: req.StatutoryCode,
		ComponentCode: req.ComponentCode,
		EffectiveFrom: req.EffectiveFrom,
		RuleSetID:     ruleSetID,
		ActorID:       actorID,
	}
	if err := h.engine.CreateComponentMapping(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) ListComponentMappings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	var statutoryCode *string
	if sc := chi.URLParam(r, "statutoryCode"); sc != "" {
		statutoryCode = &sc
	}
	mappings, err := h.engine.ListComponentMappings(ctx, companyID, statutoryCode)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mappings,
	})
}

func (h *StatutoryProfileHandler) UpdateComponentMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mappingID, err := uuid.Parse(chi.URLParam(r, "mappingID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mappingID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req updateComponentMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	input := &service.UpdateComponentMappingInput{
		MappingID:     mappingID,
		ComponentCode: req.ComponentCode,
		EffectiveFrom: req.EffectiveFrom,
		Version:       req.Version,
		ActorID:       actorID,
	}
	if err := h.engine.UpdateComponentMapping(ctx, input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *StatutoryProfileHandler) DeleteComponentMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mappingID, err := uuid.Parse(chi.URLParam(r, "mappingID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mappingID")
		return
	}
	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// Engine uses DeactivateComponentMapping for deletion
	if err := h.engine.DeactivateComponentMapping(ctx, mappingID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ------------------------------
// Helper functions
// ------------------------------

func (h *StatutoryProfileHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in context")
	}
	return userID, nil
}

func (h *StatutoryProfileHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *StatutoryProfileHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

func parseIntQuery(r *http.Request, key string, defaultValue int) int {
	valStr := r.URL.Query().Get(key)
	if valStr == "" {
		return defaultValue
	}
	val, err := parseInt(valStr)
	if err != nil {
		return defaultValue
	}
	if val < 1 {
		return defaultValue
	}
	return val
}

func parseInt(s string) (int, error) {
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
