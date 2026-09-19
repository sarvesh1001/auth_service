package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

type AttendanceRuleHandler struct {
	ruleService service.AttendanceRuleService
	validate    *validator.Validate
}

func NewAttendanceRuleHandler(ruleService service.AttendanceRuleService) *AttendanceRuleHandler {
	return &AttendanceRuleHandler{
		ruleService: ruleService,
		validate:    validator.New(),
	}
}

// ----- request/response types -----

type createAttendanceRuleRequest struct {
	RuleType         string  `json:"rule_type" validate:"required,oneof=overtime late absent"`
	CalculationType  string  `json:"calculation_type" validate:"required,oneof=percentage flat multiplier"`
	Value            float64 `json:"value" validate:"required,gt=0"`
	BasedOn          *string `json:"based_on,omitempty" validate:"omitempty,oneof=daily hourly"`
	ThresholdMinutes int     `json:"threshold_minutes" validate:"min=0"`
	ComponentCode    string  `json:"component_code" validate:"required"`
}

type updateAttendanceRuleVersionRequest struct {
	RuleType         string  `json:"rule_type" validate:"required,oneof=overtime late absent"`
	CalculationType  string  `json:"calculation_type" validate:"required,oneof=percentage flat multiplier"`
	Value            float64 `json:"value" validate:"required,gt=0"`
	BasedOn          *string `json:"based_on,omitempty" validate:"omitempty,oneof=daily hourly"`
	ThresholdMinutes int     `json:"threshold_minutes" validate:"min=0"`
	ComponentCode    string  `json:"component_code" validate:"required"`
}

type bulkDeactivateByTypeRequest struct {
	RuleType string `json:"rule_type" validate:"required"`
}

// ----- helpers -----

func (h *AttendanceRuleHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	return uuid.Parse(userIDStr)
}

// ----- handlers -----

func (h *AttendanceRuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createAttendanceRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	input := service.CreateAttendanceRuleInput{
		CompanyID:        companyID,
		RuleType:         req.RuleType,
		CalculationType:  req.CalculationType,
		Value:            req.Value,
		BasedOn:          req.BasedOn,
		ThresholdMinutes: req.ThresholdMinutes,
		ComponentCode:    req.ComponentCode,
		CreatedBy:        actorID,
	}

	rule, err := h.ruleService.CreateRule(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    rule,
	})
}

func (h *AttendanceRuleHandler) UpdateRuleVersion(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateAttendanceRuleVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	input := service.UpdateAttendanceRuleInput{
		CompanyID:        companyID,
		RuleID:           ruleID,
		RuleType:         req.RuleType,
		CalculationType:  req.CalculationType,
		Value:            req.Value,
		BasedOn:          req.BasedOn,
		ThresholdMinutes: req.ThresholdMinutes,
		ComponentCode:    req.ComponentCode,
		UpdatedBy:        actorID,
	}

	rule, err := h.ruleService.UpdateRuleVersion(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rule,
	})
}

func (h *AttendanceRuleHandler) ActivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.ruleService.ActivateRule(ctx, companyID, ruleID, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rule activated successfully",
	})
}

func (h *AttendanceRuleHandler) DeactivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.ruleService.DeactivateRule(ctx, companyID, ruleID, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rule deactivated successfully",
	})
}

func (h *AttendanceRuleHandler) BulkDeactivateByType(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req bulkDeactivateByTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	err = h.ruleService.BulkDeactivateByType(ctx, companyID, req.RuleType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rules deactivated successfully",
	})
}

func (h *AttendanceRuleHandler) GetRuleByID(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	rule, err := h.ruleService.GetRuleByID(ctx, companyID, ruleID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rule == nil {
		h.respondWithError(w, http.StatusNotFound, "Rule not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rule,
	})
}

func (h *AttendanceRuleHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	filter := models.AttendanceRuleFilter{
		CompanyID: companyID,
	}

	if ruleType := r.URL.Query().Get("rule_type"); ruleType != "" {
		filter.RuleType = &ruleType
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive
		}
	}
	if basedOn := r.URL.Query().Get("based_on"); basedOn != "" {
		filter.BasedOn = &basedOn
	}
	if minThresholdStr := r.URL.Query().Get("min_threshold"); minThresholdStr != "" {
		minThreshold, err := strconv.Atoi(minThresholdStr)
		if err == nil && minThreshold >= 0 {
			filter.MinThreshold = &minThreshold
		}
	}

	page := 1
	size := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if sizeStr := r.URL.Query().Get("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 {
			size = s
		}
	}
	filter.Page = page
	filter.PageSize = size

	rules, total, err := h.ruleService.GetRulesByFilter(ctx, filter)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
		"total":   total,
		"page":    page,
		"size":    size,
	})
}

func (h *AttendanceRuleHandler) GetActiveRules(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	asOf := time.Now()
	if asOfStr := r.URL.Query().Get("as_of"); asOfStr != "" {
		parsed, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			parsed, err = time.Parse("2006-01-02", asOfStr)
		}
		if err == nil {
			asOf = parsed
		}
	}

	rules, err := h.ruleService.GetActiveRules(ctx, companyID, asOf)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceRuleHandler) GetRulesByType(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleType := chi.URLParam(r, "ruleType")
	if ruleType == "" {
		h.respondWithError(w, http.StatusBadRequest, "rule_type is required")
		return
	}

	rules, err := h.ruleService.GetRulesByType(ctx, companyID, ruleType)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceRuleHandler) ExistsActiveRuleOfType(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	ruleType := r.URL.Query().Get("rule_type")
	if ruleType == "" {
		h.respondWithError(w, http.StatusBadRequest, "rule_type query parameter is required")
		return
	}

	exists, err := h.ruleService.ExistsActiveRuleOfType(ctx, companyID, ruleType)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"exists":  exists,
	})
}

// ----- response helpers -----

func (h *AttendanceRuleHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceRuleHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
