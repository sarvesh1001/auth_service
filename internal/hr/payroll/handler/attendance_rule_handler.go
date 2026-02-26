package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

// AttendanceRuleHandler handles HTTP requests for attendance rules.
type AttendanceRuleHandler struct {
	ruleService service.AttendanceRuleService
	logger      *zap.Logger
}

// NewAttendanceRuleHandler creates a new attendance rule handler.
func NewAttendanceRuleHandler(ruleService service.AttendanceRuleService, logger *zap.Logger) *AttendanceRuleHandler {
	return &AttendanceRuleHandler{
		ruleService: ruleService,
		logger:      logger,
	}
}

// ---------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------

type createAttendanceRuleRequest struct {
	RuleType         string  `json:"rule_type"`
	CalculationType  string  `json:"calculation_type"`
	Value            float64 `json:"value"`
	BasedOn          *string `json:"based_on,omitempty"`
	ThresholdMinutes int     `json:"threshold_minutes"`
}

type updateAttendanceRuleVersionRequest struct {
	RuleType         string  `json:"rule_type"`
	CalculationType  string  `json:"calculation_type"`
	Value            float64 `json:"value"`
	BasedOn          *string `json:"based_on,omitempty"`
	ThresholdMinutes int     `json:"threshold_minutes"`
}

type bulkDeactivateByTypeRequest struct {
	RuleType string `json:"rule_type"`
}

// ---------------------------------------------------------------------
// Create Rule (POST /companies/{companyID}/attendance/rules)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createAttendanceRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build input
	input := service.CreateAttendanceRuleInput{
		CompanyID:        companyID,
		RuleType:         req.RuleType,
		CalculationType:  req.CalculationType,
		Value:            req.Value,
		BasedOn:          req.BasedOn,
		ThresholdMinutes: req.ThresholdMinutes,
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

// ---------------------------------------------------------------------
// Update Rule Version (POST /companies/{companyID}/attendance/rules/{ruleID}/versions)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) UpdateRuleVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateAttendanceRuleVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
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

// ---------------------------------------------------------------------
// Activate Rule (PUT /companies/{companyID}/attendance/rules/{ruleID}/activate)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) ActivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule id")
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
		"message": "rule activated successfully",
	})
}

// ---------------------------------------------------------------------
// Deactivate Rule (PUT /companies/{companyID}/attendance/rules/{ruleID}/deactivate)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) DeactivateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule id")
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
		"message": "rule deactivated successfully",
	})
}

// ---------------------------------------------------------------------
// Bulk Deactivate by Type (POST /companies/{companyID}/attendance/rules/bulk-deactivate-by-type)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) BulkDeactivateByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req bulkDeactivateByTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RuleType == "" {
		h.respondWithError(w, http.StatusBadRequest, "rule_type is required")
		return
	}

	err = h.ruleService.BulkDeactivateByType(ctx, companyID, req.RuleType, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "rules deactivated successfully",
	})
}

// ---------------------------------------------------------------------
// Get Rule by ID (GET /companies/{companyID}/attendance/rules/{ruleID})
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetRuleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	rule, err := h.ruleService.GetRuleByID(ctx, companyID, ruleID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rule == nil {
		h.respondWithError(w, http.StatusNotFound, "rule not found")
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
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
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
		if err == nil {
			filter.MinThreshold = &minThreshold
		}
	}
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		page, err := strconv.Atoi(pageStr)
		if err == nil && page > 0 {
			filter.Page = page
		}
	}
	if sizeStr := r.URL.Query().Get("page_size"); sizeStr != "" {
		size, err := strconv.Atoi(sizeStr)
		if err == nil && size > 0 {
			filter.PageSize = size
		}
	}

	rules, total, err := h.ruleService.GetRulesByFilter(ctx, filter)
	if err != nil {
		h.logger.Error("failed to get attendance rules", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
		"total":   total,
		"page":    filter.Page,
		"size":    filter.PageSize,
	})
}

// ---------------------------------------------------------------------
// Get Active Rules (GET /companies/{companyID}/attendance/rules/active)
// Query param: as_of (ISO date)
// ---------------------------------------------------------------------

func (h *AttendanceRuleHandler) GetActiveRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	asOf := time.Now()
	if asOfStr := r.URL.Query().Get("as_of"); asOfStr != "" {
		parsed, err := time.Parse(time.RFC3339, asOfStr)
		if err == nil {
			asOf = parsed
		}
	}

	rules, err := h.ruleService.GetActiveRules(ctx, companyID, asOf)
	if err != nil {
		h.logger.Error("failed to get active attendance rules", zap.Error(err))
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
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleType := chi.URLParam(r, "ruleType")
	if ruleType == "" {
		h.respondWithError(w, http.StatusBadRequest, "rule_type is required")
		return
	}

	rules, err := h.ruleService.GetRulesByType(ctx, companyID, ruleType)
	if err != nil {
		h.logger.Error("failed to get attendance rules by type", zap.Error(err))
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
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	ruleType := r.URL.Query().Get("rule_type")
	if ruleType == "" {
		h.respondWithError(w, http.StatusBadRequest, "rule_type query parameter is required")
		return
	}

	exists, err := h.ruleService.ExistsActiveRuleOfType(ctx, companyID, ruleType)
	if err != nil {
		h.logger.Error("failed to check existence of active rule", zap.Error(err))
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
