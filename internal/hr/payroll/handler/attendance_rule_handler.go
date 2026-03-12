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
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

// AttendanceRuleHandler handles HTTP requests for attendance rules.
type AttendanceRuleHandler struct {
	ruleService service.AttendanceRuleService
	logger      *zap.Logger
	validate    *validator.Validate
}

// NewAttendanceRuleHandler creates a new attendance rule handler.
func NewAttendanceRuleHandler(ruleService service.AttendanceRuleService, logger *zap.Logger) *AttendanceRuleHandler {
	return &AttendanceRuleHandler{
		ruleService: ruleService,
		logger:      logger,
		validate:    validator.New(),
	}
}

// ---------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------

type createAttendanceRuleRequest struct {
	RuleType         string  `json:"rule_type" validate:"required,oneof=overtime late absent"`
	CalculationType  string  `json:"calculation_type" validate:"required,oneof=percentage flat multiplier"`
	Value            float64 `json:"value" validate:"required,gt=0"`
	BasedOn          *string `json:"based_on,omitempty" validate:"omitempty,oneof=daily hourly"`
	ThresholdMinutes int     `json:"threshold_minutes" validate:"min=0"`
	ComponentCode    string  `json:"component_code" validate:"required"` // Added missing field
}

type updateAttendanceRuleVersionRequest struct {
	RuleType         string  `json:"rule_type" validate:"required,oneof=overtime late absent"`
	CalculationType  string  `json:"calculation_type" validate:"required,oneof=percentage flat multiplier"`
	Value            float64 `json:"value" validate:"required,gt=0"`
	BasedOn          *string `json:"based_on,omitempty" validate:"omitempty,oneof=daily hourly"`
	ThresholdMinutes int     `json:"threshold_minutes" validate:"min=0"`
	ComponentCode    string  `json:"component_code" validate:"required"` // Added missing field
}

type bulkDeactivateByTypeRequest struct {
	RuleType string `json:"rule_type" validate:"required"`
}

// ---------------------------------------------------------------------
// Create Rule (POST /companies/{companyID}/attendance/rules)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to create attendance rule",
			zap.String("company_id", companyID.String()),
			zap.String("actor_id", actorID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    rule,
	})
}

// ---------------------------------------------------------------------
// Update Rule Version (POST /companies/{companyID}/attendance/rules/{ruleID}/versions)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) UpdateRuleVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to update attendance rule version",
			zap.String("company_id", companyID.String()),
			zap.String("rule_id", ruleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rule,
	})
}

// ---------------------------------------------------------------------
// Activate Rule (PUT /companies/{companyID}/attendance/rules/{ruleID}/activate)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) ActivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to activate attendance rule",
			zap.String("company_id", companyID.String()),
			zap.String("rule_id", ruleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rule activated successfully",
	})
}

// ---------------------------------------------------------------------
// Deactivate Rule (PUT /companies/{companyID}/attendance/rules/{ruleID}/deactivate)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) DeactivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to deactivate attendance rule",
			zap.String("company_id", companyID.String()),
			zap.String("rule_id", ruleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rule deactivated successfully",
	})
}

// ---------------------------------------------------------------------
// Bulk Deactivate by Type (POST /companies/{companyID}/attendance/rules/bulk-deactivate-by-type)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) BulkDeactivateByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to bulk deactivate attendance rules by type",
			zap.String("company_id", companyID.String()),
			zap.String("rule_type", req.RuleType),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rules deactivated successfully",
	})
}

// ---------------------------------------------------------------------
// Get Rule by ID (GET /companies/{companyID}/attendance/rules/{ruleID})
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetRuleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to get attendance rule by ID",
			zap.String("company_id", companyID.String()),
			zap.String("rule_id", ruleID.String()),
			zap.Error(err))
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

// ---------------------------------------------------------------------
// Get Rules (GET /companies/{companyID}/attendance/rules)
// Supports filtering by rule_type, is_active, based_on, min_threshold, pagination.
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		} else {
			h.logger.Warn("Invalid is_active parameter", zap.String("value", isActiveStr))
		}
	}
	if basedOn := r.URL.Query().Get("based_on"); basedOn != "" {
		filter.BasedOn = &basedOn
	}
	if minThresholdStr := r.URL.Query().Get("min_threshold"); minThresholdStr != "" {
		minThreshold, err := strconv.Atoi(minThresholdStr)
		if err == nil && minThreshold >= 0 {
			filter.MinThreshold = &minThreshold
		} else {
			h.logger.Warn("Invalid min_threshold parameter", zap.String("value", minThresholdStr))
		}
	}

	// Pagination defaults
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
		h.logger.Error("Failed to get attendance rules",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
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

// ---------------------------------------------------------------------
// Get Active Rules (GET /companies/{companyID}/attendance/rules/active)
// Query param: as_of (ISO date or YYYY-MM-DD)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetActiveRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	asOf := time.Now()
	if asOfStr := r.URL.Query().Get("as_of"); asOfStr != "" {
		parsed, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			// Try YYYY-MM-DD
			parsed, err = time.Parse("2006-01-02", asOfStr)
		}
		if err == nil {
			asOf = parsed
		} else {
			h.logger.Warn("Invalid as_of parameter, using current time", zap.String("value", asOfStr))
		}
	}

	rules, err := h.ruleService.GetActiveRules(ctx, companyID, asOf)
	if err != nil {
		h.logger.Error("Failed to get active attendance rules",
			zap.String("company_id", companyID.String()),
			zap.Time("as_of", asOf),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

// ---------------------------------------------------------------------
// Get Rules by Type (GET /companies/{companyID}/attendance/rules/types/{ruleType})
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetRulesByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to get attendance rules by type",
			zap.String("company_id", companyID.String()),
			zap.String("rule_type", ruleType),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

// ---------------------------------------------------------------------
// Check Exists Active Rule of Type (GET /companies/{companyID}/attendance/rules/exists-active)
// Query param: rule_type
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) ExistsActiveRuleOfType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.logger.Error("Failed to check existence of active rule",
			zap.String("company_id", companyID.String()),
			zap.String("rule_type", ruleType),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"exists":  exists,
	})
}

// ---------------------------------------------------------------------
// Helper: get actor ID from context
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	return uuid.Parse(userIDStr)
}

// ---------------------------------------------------------------------
// Standard JSON responses
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *AttendanceRuleHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
