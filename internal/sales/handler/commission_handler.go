// file: internal/sales/handler/commission_handler.go
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

// CommissionHandler handles HTTP requests for commission management.
type CommissionHandler struct {
	commissionService service.SalesRepCommissionService
	*BaseHandler
}

// NewCommissionHandler creates a new CommissionHandler.
func NewCommissionHandler(commissionService service.SalesRepCommissionService, logger *zap.Logger) *CommissionHandler {
	return &CommissionHandler{
		commissionService: commissionService,
		BaseHandler:       &BaseHandler{logger: logger.Named("commission_handler")},
	}
}

// ---------- Request/Response Types ----------

type createCommissionPlanRequest struct {
	CompanyID     string                `json:"company_id"`
	Code          string                `json:"code"`
	Name          string                `json:"name"`
	Description   *string               `json:"description,omitempty"`
	EffectiveFrom string                `json:"effective_from"`
	EffectiveTo   *string               `json:"effective_to,omitempty"`
	IsActive      bool                  `json:"is_active"`
	Rules         []commissionRuleInput `json:"rules"`
}

type commissionRuleInput struct {
	RuleType     string  `json:"rule_type"`
	AppliesTo    string  `json:"applies_to"`
	ProductID    *string `json:"product_id,omitempty"`
	TierMin      *string `json:"tier_min,omitempty"`
	TierMax      *string `json:"tier_max,omitempty"`
	Rate         string  `json:"rate"`
	IsPercentage bool    `json:"is_percentage"`
	Priority     int     `json:"priority"`
}

type createCommissionPlanResponse struct {
	PlanID        string  `json:"plan_id"`
	CompanyID     string  `json:"company_id"`
	Code          string  `json:"code"`
	Name          string  `json:"name"`
	Description   *string `json:"description,omitempty"`
	EffectiveFrom string  `json:"effective_from"`
	EffectiveTo   *string `json:"effective_to,omitempty"`
	IsActive      bool    `json:"is_active"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type updateCommissionPlanRequest struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	EffectiveFrom *string `json:"effective_from,omitempty"`
	EffectiveTo   *string `json:"effective_to,omitempty"`
	IsActive      *bool   `json:"is_active,omitempty"`
}

type createCommissionRuleRequest struct {
	CompanyID    string  `json:"company_id"`
	PlanID       string  `json:"plan_id"`
	RuleType     string  `json:"rule_type"`
	AppliesTo    string  `json:"applies_to"`
	ProductID    *string `json:"product_id,omitempty"`
	TierMin      *string `json:"tier_min,omitempty"`
	TierMax      *string `json:"tier_max,omitempty"`
	Rate         string  `json:"rate"`
	IsPercentage bool    `json:"is_percentage"`
	Priority     int     `json:"priority"`
}

type createCommissionRuleResponse struct {
	RuleID       string  `json:"rule_id"`
	CompanyID    string  `json:"company_id"`
	PlanID       string  `json:"plan_id"`
	RuleType     string  `json:"rule_type"`
	AppliesTo    string  `json:"applies_to"`
	ProductID    *string `json:"product_id,omitempty"`
	TierMin      *string `json:"tier_min,omitempty"`
	TierMax      *string `json:"tier_max,omitempty"`
	Rate         string  `json:"rate"`
	IsPercentage bool    `json:"is_percentage"`
	Priority     int     `json:"priority"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

type updateCommissionRuleRequest struct {
	RuleType     *string `json:"rule_type,omitempty"`
	AppliesTo    *string `json:"applies_to,omitempty"`
	ProductID    *string `json:"product_id,omitempty"`
	TierMin      *string `json:"tier_min,omitempty"`
	TierMax      *string `json:"tier_max,omitempty"`
	Rate         *string `json:"rate,omitempty"`
	IsPercentage *bool   `json:"is_percentage,omitempty"`
	Priority     *int    `json:"priority,omitempty"`
}

type assignPlanRequest struct {
	PlanID        string `json:"plan_id"`
	EffectiveFrom string `json:"effective_from"`
}

type reverseCommissionRequest struct {
	Reason string `json:"reason"`
}

type rejectCommissionRequest struct {
	Reason string `json:"reason"`
}

type calculatePeriodRequest struct {
	SalesRepID string `json:"sales_rep_id"`
	From       string `json:"from"`
	To         string `json:"to"`
}

type previewCommissionRequest struct {
	CompanyID     string `json:"company_id"`
	SalesRepID    string `json:"sales_rep_id"`
	ReferenceType string `json:"reference_type"`
	ReferenceID   string `json:"reference_id"`
	CalculationAt string `json:"calculation_at"`
}

type previewCommissionResponse struct {
	BaseAmount       string  `json:"base_amount"`
	ApplicableRate   string  `json:"applicable_rate"`
	CommissionAmount string  `json:"commission_amount"`
	RuleID           *string `json:"rule_id,omitempty"`
}

type createCommissionRecordRequest struct {
	CompanyID        string `json:"company_id"`
	SalesRepID       string `json:"sales_rep_id"`
	ReferenceType    string `json:"reference_type"`
	ReferenceID      string `json:"reference_id"`
	CommissionBase   string `json:"commission_base"`
	CommissionRate   string `json:"commission_rate"`
	CommissionAmount string `json:"commission_amount"`
	EarnedAt         string `json:"earned_at"`
	Status           string `json:"status"`
}

type updateCommissionRecordRequest struct {
	Status       *string `json:"status,omitempty"`
	PaidAt       *string `json:"paid_at,omitempty"`
	ApprovedAt   *string `json:"approved_at,omitempty"`
	RejectedAt   *string `json:"rejected_at,omitempty"`
	RejectReason *string `json:"reject_reason,omitempty"`
}

type commissionRecordResponse struct {
	CommissionID     string  `json:"commission_id"`
	CompanyID        string  `json:"company_id"`
	SalesRepID       string  `json:"sales_rep_id"`
	ReferenceType    string  `json:"reference_type"`
	ReferenceID      string  `json:"reference_id"`
	CommissionBase   string  `json:"commission_base"`
	CommissionRate   string  `json:"commission_rate"`
	CommissionAmount string  `json:"commission_amount"`
	Status           string  `json:"status"`
	EarnedAt         string  `json:"earned_at"`
	PaidAt           *string `json:"paid_at,omitempty"`
	ApprovedAt       *string `json:"approved_at,omitempty"`
	RejectedAt       *string `json:"rejected_at,omitempty"`
	RejectReason     *string `json:"reject_reason,omitempty"`
	Notes            *string `json:"notes,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

type commissionPlanSummary struct {
	PlanID        string  `json:"plan_id"`
	Code          string  `json:"code"`
	Name          string  `json:"name"`
	Description   *string `json:"description,omitempty"`
	EffectiveFrom string  `json:"effective_from"`
	EffectiveTo   *string `json:"effective_to,omitempty"`
	IsActive      bool    `json:"is_active"`
}

type commissionRuleSummary struct {
	RuleID       string  `json:"rule_id"`
	PlanID       string  `json:"plan_id"`
	RuleType     string  `json:"rule_type"`
	AppliesTo    string  `json:"applies_to"`
	ProductID    *string `json:"product_id,omitempty"`
	TierMin      *string `json:"tier_min,omitempty"`
	TierMax      *string `json:"tier_max,omitempty"`
	Rate         string  `json:"rate"`
	IsPercentage bool    `json:"is_percentage"`
	Priority     int     `json:"priority"`
}

type listCommissionPlansResponse struct {
	Plans  []commissionPlanSummary `json:"plans"`
	Total  int64                   `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

type listCommissionRulesResponse struct {
	Rules  []commissionRuleSummary `json:"rules"`
	Total  int64                   `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

type listCommissionsResponse struct {
	Commissions []commissionRecordResponse `json:"commissions"`
	Total       int64                      `json:"total"`
	Limit       int                        `json:"limit"`
	Offset      int                        `json:"offset"`
}

type salesRepCommissionSummaryResponse struct {
	SalesRepID    string `json:"sales_rep_id"`
	TotalEarned   string `json:"total_earned"`
	TotalApproved string `json:"total_approved"`
	TotalPaid     string `json:"total_paid"`
	PendingCount  int    `json:"pending_count"`
	ApprovedCount int    `json:"approved_count"`
	PaidCount     int    `json:"paid_count"`
	RejectedCount int    `json:"rejected_count"`
}

type commissionTrendPointResponse struct {
	Date             string `json:"date"`
	CommissionAmount string `json:"commission_amount"`
}

// ---------- Commission Plan Handlers ----------

// CreateCommissionPlan handles POST /commission-plans
func (h *CommissionHandler) CreateCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createCommissionPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if req.Code == "" || req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "code and name are required")
		return
	}
	effectiveFrom, err := time.Parse(time.RFC3339, req.EffectiveFrom)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid effective_from (RFC3339)")
		return
	}
	var effectiveTo *time.Time
	if req.EffectiveTo != nil && *req.EffectiveTo != "" {
		t, err := time.Parse(time.RFC3339, *req.EffectiveTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid effective_to (RFC3339)")
			return
		}
		effectiveTo = &t
	}
	// Parse rules
	rules := make([]service.CommissionRuleInput, 0, len(req.Rules))
	for _, ruleReq := range req.Rules {
		ruleType := enums.CommissionRuleType(ruleReq.RuleType)
		appliesTo := enums.CommissionBaseType(ruleReq.AppliesTo)
		var productID *uuid.UUID
		if ruleReq.ProductID != nil && *ruleReq.ProductID != "" {
			pid, err := uuid.Parse(*ruleReq.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id in rule")
				return
			}
			productID = &pid
		}
		var tierMin, tierMax *decimal.Decimal
		if ruleReq.TierMin != nil && *ruleReq.TierMin != "" {
			val, err := decimal.NewFromString(*ruleReq.TierMin)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tier_min")
				return
			}
			tierMin = &val
		}
		if ruleReq.TierMax != nil && *ruleReq.TierMax != "" {
			val, err := decimal.NewFromString(*ruleReq.TierMax)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tier_max")
				return
			}
			tierMax = &val
		}
		rate, err := decimal.NewFromString(ruleReq.Rate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid rate")
			return
		}
		rules = append(rules, service.CommissionRuleInput{
			RuleType:     ruleType,
			AppliesTo:    appliesTo,
			ProductID:    productID,
			TierMin:      tierMin,
			TierMax:      tierMax,
			Rate:         rate,
			IsPercentage: ruleReq.IsPercentage,
			Priority:     ruleReq.Priority,
		})
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.CreateCommissionPlanRequest{
		CompanyID:     companyID,
		Code:          req.Code,
		Name:          req.Name,
		Description:   req.Description,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
		IsActive:      req.IsActive,
		CreatedBy:     &userID,
		Rules:         rules,
	}

	plan, err := h.commissionService.CreateCommissionPlan(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.planToResponse(plan)
	location := fmt.Sprintf("/commission-plans/%s", plan.PlanID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateCommissionPlan handles PUT /commission-plans/{id}
func (h *CommissionHandler) UpdateCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCommissionPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svcReq := &service.UpdateCommissionPlanRequest{
		UpdatedBy: &userID,
	}
	if req.Name != nil {
		svcReq.Name = req.Name
	}
	if req.Description != nil {
		svcReq.Description = req.Description
	}
	if req.EffectiveFrom != nil {
		t, err := time.Parse(time.RFC3339, *req.EffectiveFrom)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid effective_from")
			return
		}
		svcReq.EffectiveFrom = &t
	}
	if req.EffectiveTo != nil {
		if *req.EffectiveTo == "" {
			svcReq.EffectiveTo = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.EffectiveTo)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid effective_to")
				return
			}
			svcReq.EffectiveTo = &t
		}
	}
	if req.IsActive != nil {
		svcReq.IsActive = req.IsActive
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	plan, err := h.commissionService.UpdateCommissionPlan(ctx, companyID, planID, svcReq)
	if err != nil {
		h.logger.Error("failed to update commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.planToResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteCommissionPlan handles DELETE /commission-plans/{id}
func (h *CommissionHandler) DeleteCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.DeleteCommissionPlan(ctx, companyID, planID, userID)
	if err != nil {
		h.logger.Error("failed to delete commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission plan deleted successfully",
	})
}

// GetCommissionPlanByID handles GET /commission-plans/{id}
func (h *CommissionHandler) GetCommissionPlanByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	plan, err := h.commissionService.GetCommissionPlanByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.planToResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCommissionPlanByCode handles GET /commission-plans/by-code
func (h *CommissionHandler) GetCommissionPlanByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	plan, err := h.commissionService.GetCommissionPlanByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get commission plan by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.planToResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListCommissionPlans handles GET /commission-plans
func (h *CommissionHandler) ListCommissionPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.CommissionPlanListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if code := r.URL.Query().Get("code"); code != "" {
		filter.Code = &code
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if effectiveStr := r.URL.Query().Get("effective"); effectiveStr != "" {
		effective, err := time.Parse(time.RFC3339, effectiveStr)
		if err == nil {
			filter.Effective = &effective
		}
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "created_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	plans, total, err := h.commissionService.ListCommissionPlans(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list commission plans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list commission plans")
		return
	}

	summaries := make([]commissionPlanSummary, len(plans))
	for i, p := range plans {
		summaries[i] = h.planToSummary(p)
	}
	resp := listCommissionPlansResponse{
		Plans:  summaries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveCommissionPlans handles GET /commission-plans/active
func (h *CommissionHandler) GetActiveCommissionPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	atStr := r.URL.Query().Get("at")
	var at time.Time
	if atStr == "" {
		at = time.Now()
	} else {
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	plans, err := h.commissionService.GetActiveCommissionPlans(ctx, companyID, at)
	if err != nil {
		h.logger.Error("failed to get active commission plans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active commission plans")
		return
	}

	summaries := make([]commissionPlanSummary, len(plans))
	for i, p := range plans {
		summaries[i] = h.planToSummary(p)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ---------- Commission Rule Handlers ----------

// CreateCommissionRule handles POST /commission-rules
func (h *CommissionHandler) CreateCommissionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createCommissionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	planID, err := uuid.Parse(req.PlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
		return
	}
	rate, err := decimal.NewFromString(req.Rate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rate")
		return
	}
	var productID *uuid.UUID
	if req.ProductID != nil && *req.ProductID != "" {
		pid, err := uuid.Parse(*req.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productID = &pid
	}
	var tierMin, tierMax *decimal.Decimal
	if req.TierMin != nil && *req.TierMin != "" {
		val, err := decimal.NewFromString(*req.TierMin)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tier_min")
			return
		}
		tierMin = &val
	}
	if req.TierMax != nil && *req.TierMax != "" {
		val, err := decimal.NewFromString(*req.TierMax)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tier_max")
			return
		}
		tierMax = &val
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.CreateCommissionRuleRequest{
		CompanyID:    companyID,
		PlanID:       planID,
		RuleType:     enums.CommissionRuleType(req.RuleType),
		AppliesTo:    enums.CommissionBaseType(req.AppliesTo),
		ProductID:    productID,
		TierMin:      tierMin,
		TierMax:      tierMax,
		Rate:         rate,
		IsPercentage: req.IsPercentage,
		Priority:     req.Priority,
		CreatedBy:    &userID,
	}
	rule, err := h.commissionService.CreateCommissionRule(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create commission rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.ruleToResponse(rule)
	location := fmt.Sprintf("/commission-rules/%s", rule.RuleID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateCommissionRule handles PUT /commission-rules/{id}
func (h *CommissionHandler) UpdateCommissionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCommissionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svcReq := &service.UpdateCommissionRuleRequest{
		UpdatedBy: &userID,
	}
	if req.RuleType != nil {
		rt := enums.CommissionRuleType(*req.RuleType)
		svcReq.RuleType = &rt
	}
	if req.AppliesTo != nil {
		at := enums.CommissionBaseType(*req.AppliesTo)
		svcReq.AppliesTo = &at
	}
	if req.ProductID != nil {
		if *req.ProductID == "" {
			svcReq.ProductID = nil
		} else {
			pid, err := uuid.Parse(*req.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
				return
			}
			svcReq.ProductID = &pid
		}
	}
	if req.TierMin != nil {
		if *req.TierMin == "" {
			svcReq.TierMin = nil
		} else {
			val, err := decimal.NewFromString(*req.TierMin)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tier_min")
				return
			}
			svcReq.TierMin = &val
		}
	}
	if req.TierMax != nil {
		if *req.TierMax == "" {
			svcReq.TierMax = nil
		} else {
			val, err := decimal.NewFromString(*req.TierMax)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tier_max")
				return
			}
			svcReq.TierMax = &val
		}
	}
	if req.Rate != nil {
		val, err := decimal.NewFromString(*req.Rate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid rate")
			return
		}
		svcReq.Rate = &val
	}
	if req.IsPercentage != nil {
		svcReq.IsPercentage = req.IsPercentage
	}
	if req.Priority != nil {
		svcReq.Priority = req.Priority
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	rule, err := h.commissionService.UpdateCommissionRule(ctx, companyID, ruleID, svcReq)
	if err != nil {
		h.logger.Error("failed to update commission rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.ruleToResponse(rule)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteCommissionRule handles DELETE /commission-rules/{id}
func (h *CommissionHandler) DeleteCommissionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.DeleteCommissionRule(ctx, companyID, ruleID, userID)
	if err != nil {
		h.logger.Error("failed to delete commission rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission rule deleted successfully",
	})
}

// GetCommissionRuleByID handles GET /commission-rules/{id}
func (h *CommissionHandler) GetCommissionRuleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rule, err := h.commissionService.GetCommissionRuleByID(ctx, companyID, ruleID)
	if err != nil {
		h.logger.Error("failed to get commission rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.ruleToResponse(rule)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCommissionRules handles GET /commission-rules
func (h *CommissionHandler) GetCommissionRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	planIDStr := r.URL.Query().Get("plan_id")
	if planIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_id query parameter is required")
		return
	}
	planID, err := uuid.Parse(planIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rules, err := h.commissionService.GetCommissionRules(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get commission rules", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	summaries := make([]commissionRuleSummary, len(rules))
	for i, rl := range rules {
		summaries[i] = h.ruleToSummary(rl)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ---------- Sales Rep Commission Assignment Handlers ----------

// AssignCommissionPlan handles POST /sales-reps/{salesRepId}/assign-plan
func (h *CommissionHandler) AssignCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	salesRepID, err := h.parseUUIDParam(r, "salesRepId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	planID, err := uuid.Parse(req.PlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
		return
	}
	effectiveFrom, err := time.Parse(time.RFC3339, req.EffectiveFrom)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid effective_from (RFC3339)")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.AssignCommissionPlan(ctx, companyID, salesRepID, planID, effectiveFrom, userID)
	if err != nil {
		h.logger.Error("failed to assign commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission plan assigned successfully",
	})
}

// RemoveCommissionPlan handles DELETE /sales-reps/{salesRepId}/assign-plan
func (h *CommissionHandler) RemoveCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	salesRepID, err := h.parseUUIDParam(r, "salesRepId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.RemoveCommissionPlan(ctx, companyID, salesRepID, userID)
	if err != nil {
		h.logger.Error("failed to remove commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission plan removed successfully",
	})
}

// GetSalesRepCommissionPlan handles GET /sales-reps/{salesRepId}/commission-plan
func (h *CommissionHandler) GetSalesRepCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	salesRepID, err := h.parseUUIDParam(r, "salesRepId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	atStr := r.URL.Query().Get("at")
	var at time.Time
	if atStr == "" {
		at = time.Now()
	} else {
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	plan, err := h.commissionService.GetSalesRepCommissionPlan(ctx, companyID, salesRepID, at)
	if err != nil {
		h.logger.Error("failed to get sales rep commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.planToResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------- Commission Calculation Handlers ----------

// CalculateOrderCommission handles POST /commissions/calculate-order
func (h *CommissionHandler) CalculateOrderCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		OrderID string `json:"order_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	orderID, err := uuid.Parse(body.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.CalculateOrderCommission(ctx, companyID, orderID)
	if err != nil {
		h.logger.Error("failed to calculate order commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculateInvoiceCommission handles POST /commissions/calculate-invoice
func (h *CommissionHandler) CalculateInvoiceCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(body.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.CalculateInvoiceCommission(ctx, companyID, invoiceID)
	if err != nil {
		h.logger.Error("failed to calculate invoice commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculatePaymentCommission handles POST /commissions/calculate-payment
func (h *CommissionHandler) CalculatePaymentCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		PaymentID string `json:"payment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paymentID, err := uuid.Parse(body.PaymentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.CalculatePaymentCommission(ctx, companyID, paymentID)
	if err != nil {
		h.logger.Error("failed to calculate payment commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculateCommissionForPeriod handles POST /commissions/calculate-period
func (h *CommissionHandler) CalculateCommissionForPeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req calculatePeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	salesRepID, err := uuid.Parse(req.SalesRepID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
		return
	}
	from, err := time.Parse(time.RFC3339, req.From)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date")
		return
	}
	to, err := time.Parse(time.RFC3339, req.To)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commissions, total, err := h.commissionService.CalculateCommissionForPeriod(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to calculate commission for period", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"commissions": responses,
			"total":       total.String(),
		},
	})
}

// PreviewCommission handles POST /commissions/preview
func (h *CommissionHandler) PreviewCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req previewCommissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	salesRepID, err := uuid.Parse(req.SalesRepID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
		return
	}
	referenceID, err := uuid.Parse(req.ReferenceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_id")
		return
	}
	calculationAt, err := time.Parse(time.RFC3339, req.CalculationAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid calculation_at")
		return
	}
	refType := enums.CommissionReferenceType(req.ReferenceType)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.CommissionPreviewRequest{
		CompanyID:     companyID,
		SalesRepID:    salesRepID,
		ReferenceType: refType,
		ReferenceID:   referenceID,
		CalculationAt: calculationAt,
	}
	result, err := h.commissionService.PreviewCommission(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to preview commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := previewCommissionResponse{
		BaseAmount:       result.BaseAmount.String(),
		ApplicableRate:   result.ApplicableRate.String(),
		CommissionAmount: result.CommissionAmount.String(),
	}
	if result.RuleID != nil {
		rid := result.RuleID.String()
		resp.RuleID = &rid
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CommissionHandler) ProcessOrderCompletedCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		OrderID string `json:"order_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	orderID, err := uuid.Parse(body.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.ProcessOrderCompletedCommission(ctx, companyID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to process order commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ProcessInvoicePaidCommission handles POST /commissions/process-invoice
func (h *CommissionHandler) ProcessInvoicePaidCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(body.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.ProcessInvoicePaidCommission(ctx, companyID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to process invoice commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ProcessPaymentReceivedCommission handles POST /commissions/process-payment
func (h *CommissionHandler) ProcessPaymentReceivedCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		PaymentID string `json:"payment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paymentID, err := uuid.Parse(body.PaymentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.ProcessPaymentReceivedCommission(ctx, companyID, paymentID, userID)
	if err != nil {
		h.logger.Error("failed to process payment commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RecalculateCommission handles POST /commissions/{id}/recalculate
func (h *CommissionHandler) RecalculateCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.RecalculateCommission(ctx, companyID, commissionID, userID)
	if err != nil {
		h.logger.Error("failed to recalculate commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission recalculated",
	})
}

// ReverseCommission handles POST /commissions/{id}/reverse
func (h *CommissionHandler) ReverseCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	var req reverseCommissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.ReverseCommission(ctx, companyID, commissionID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to reverse commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission reversed",
	})
}

// ---------- Commission Record CRUD ----------

// CreateCommissionRecord handles POST /commissions
func (h *CommissionHandler) CreateCommissionRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createCommissionRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	salesRepID, err := uuid.Parse(req.SalesRepID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales_rep_id")
		return
	}
	referenceID, err := uuid.Parse(req.ReferenceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_id")
		return
	}
	commissionBase, err := decimal.NewFromString(req.CommissionBase)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission_base")
		return
	}
	commissionRate, err := decimal.NewFromString(req.CommissionRate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission_rate")
		return
	}
	commissionAmount, err := decimal.NewFromString(req.CommissionAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission_amount")
		return
	}
	earnedAt, err := time.Parse(time.RFC3339, req.EarnedAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid earned_at")
		return
	}
	status := enums.CommissionStatus(req.Status)

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.CreateSalesCommissionRequest{
		CompanyID:        companyID,
		SalesRepID:       salesRepID,
		ReferenceType:    enums.CommissionReferenceType(req.ReferenceType),
		ReferenceID:      referenceID,
		CommissionBase:   commissionBase,
		CommissionRate:   commissionRate,
		CommissionAmount: commissionAmount,
		EarnedAt:         earnedAt,
		Status:           status,
		CreatedBy:        &userID,
	}
	commission, err := h.commissionService.CreateCommissionRecord(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create commission record", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	location := fmt.Sprintf("/commissions/%s", commission.CommissionID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateCommissionRecord handles PUT /commissions/{id}
func (h *CommissionHandler) UpdateCommissionRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCommissionRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svcReq := &service.UpdateSalesCommissionRequest{
		UpdatedBy: &userID,
	}
	if req.Status != nil {
		st := enums.CommissionStatus(*req.Status)
		svcReq.Status = &st
	}
	if req.PaidAt != nil {
		t, err := time.Parse(time.RFC3339, *req.PaidAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid paid_at")
			return
		}
		svcReq.PaidAt = &t
	}
	if req.ApprovedAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ApprovedAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid approved_at")
			return
		}
		svcReq.ApprovedAt = &t
	}
	if req.RejectedAt != nil {
		t, err := time.Parse(time.RFC3339, *req.RejectedAt)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid rejected_at")
			return
		}
		svcReq.RejectedAt = &t
	}
	if req.RejectReason != nil {
		svcReq.RejectReason = req.RejectReason
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	commission, err := h.commissionService.UpdateCommissionRecord(ctx, companyID, commissionID, svcReq)
	if err != nil {
		h.logger.Error("failed to update commission record", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCommissionByID handles GET /commissions/{id}
func (h *CommissionHandler) GetCommissionByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commission, err := h.commissionService.GetCommissionByID(ctx, companyID, commissionID)
	if err != nil {
		h.logger.Error("failed to get commission record", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.commissionToResponse(commission)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCommissionByReference handles GET /commissions/by-reference
func (h *CommissionHandler) GetCommissionByReference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	refTypeStr := r.URL.Query().Get("reference_type")
	if refTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "reference_type query parameter is required")
		return
	}
	refIDStr := r.URL.Query().Get("reference_id")
	if refIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "reference_id query parameter is required")
		return
	}
	refID, err := uuid.Parse(refIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_id")
		return
	}
	refType := enums.CommissionReferenceType(refTypeStr)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, err := h.commissionService.GetCommissionByReference(ctx, companyID, refType, refID)
	if err != nil {
		h.logger.Error("failed to get commissions by reference", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ListCommissions handles GET /commissions
func (h *CommissionHandler) ListCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.SalesCommissionListFilter{
		CompanyID: companyID,
	}
	if salesRepIDStr := r.URL.Query().Get("sales_rep_id"); salesRepIDStr != "" {
		sid, err := uuid.Parse(salesRepIDStr)
		if err == nil {
			filter.SalesRepID = &sid
		}
	}
	if refTypeStr := r.URL.Query().Get("reference_type"); refTypeStr != "" {
		rt := enums.CommissionReferenceType(refTypeStr)
		filter.ReferenceType = &rt
	}
	if refIDStr := r.URL.Query().Get("reference_id"); refIDStr != "" {
		rid, err := uuid.Parse(refIDStr)
		if err == nil {
			filter.ReferenceID = &rid
		}
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		st := enums.CommissionStatus(statusStr)
		filter.Status = &st
	}
	if fromStr := r.URL.Query().Get("earned_from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			filter.EarnedFrom = &t
		}
	}
	if toStr := r.URL.Query().Get("earned_to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			filter.EarnedTo = &t
		}
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "earned_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	commissions, total, err := h.commissionService.ListCommissions(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list commissions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list commissions")
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	resp := listCommissionsResponse{
		Commissions: responses,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetSalesRepCommissions handles GET /sales-reps/{id}/commissions
func (h *CommissionHandler) GetSalesRepCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "earned_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, total, err := h.commissionService.GetSalesRepCommissions(ctx, companyID, salesRepID, from, to, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get sales rep commissions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"commissions": responses,
			"total":       total,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// MarkCommissionPending handles PATCH /commissions/{id}/pending
func (h *CommissionHandler) MarkCommissionPending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.MarkCommissionPending(ctx, companyID, commissionID, userID)
	if err != nil {
		h.logger.Error("failed to mark commission pending", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission marked as pending",
	})
}

// ApproveCommission handles POST /commissions/{id}/approve
func (h *CommissionHandler) ApproveCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.ApproveCommission(ctx, companyID, commissionID, userID)
	if err != nil {
		h.logger.Error("failed to approve commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission approved",
	})
}

// RejectCommission handles POST /commissions/{id}/reject
func (h *CommissionHandler) RejectCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	var req rejectCommissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.RejectCommission(ctx, companyID, commissionID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to reject commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission rejected",
	})
}

// MarkCommissionPaid handles POST /commissions/{id}/mark-paid
func (h *CommissionHandler) MarkCommissionPaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}

	var req markPaidRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paidAt, err := time.Parse(time.RFC3339, req.PaidAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid paid_at (RFC3339)")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)

	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.commissionService.MarkCommissionPaid(ctx, companyID, commissionID, paidAt, userID)
	if err != nil {
		h.logger.Error("failed to mark commission paid", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission marked as paid",
	})
}

// GetPendingCommissions handles GET /commissions/pending
func (h *CommissionHandler) GetPendingCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, err := h.commissionService.GetPendingCommissions(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get pending commissions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get pending commissions")
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetApprovedCommissions handles GET /commissions/approved
func (h *CommissionHandler) GetApprovedCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, err := h.commissionService.GetApprovedCommissions(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get approved commissions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get approved commissions")
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetUnpaidCommissions handles GET /commissions/unpaid
func (h *CommissionHandler) GetUnpaidCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, err := h.commissionService.GetUnpaidCommissions(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get unpaid commissions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get unpaid commissions")
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetTotalCommissionAmount handles GET /commissions/total-amount
func (h *CommissionHandler) GetTotalCommissionAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.commissionService.GetTotalCommissionAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total commission amount", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total commission amount")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"total_commission_amount": amount.String(),
		},
	})
}

// GetTotalPaidCommission handles GET /commissions/total-paid
func (h *CommissionHandler) GetTotalPaidCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.commissionService.GetTotalPaidCommission(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total paid commission", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total paid commission")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"total_paid_commission": amount.String(),
		},
	})
}

// GetOutstandingCommissionLiability handles GET /commissions/outstanding-liability
func (h *CommissionHandler) GetOutstandingCommissionLiability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.commissionService.GetOutstandingCommissionLiability(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get outstanding commission liability", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get outstanding liability")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"outstanding_liability": amount.String(),
		},
	})
}

// GetTopSalesRepCommissions handles GET /commissions/top-sales-reps
func (h *CommissionHandler) GetTopSalesRepCommissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	commissions, err := h.commissionService.GetTopSalesRepCommissions(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top sales rep commissions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get top sales rep commissions")
		return
	}

	responses := make([]commissionRecordResponse, len(commissions))
	for i, c := range commissions {
		responses[i] = h.commissionToResponse(c)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetCommissionSummaryBySalesRep handles GET /sales-reps/{id}/commission-summary
func (h *CommissionHandler) GetCommissionSummaryBySalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	summary, err := h.commissionService.GetCommissionSummaryBySalesRep(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get commission summary", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := salesRepCommissionSummaryResponse{
		SalesRepID:    summary.SalesRepID.String(),
		TotalEarned:   summary.TotalEarned.String(),
		TotalApproved: summary.TotalApproved.String(),
		TotalPaid:     summary.TotalPaid.String(),
		PendingCount:  summary.PendingCount,
		ApprovedCount: summary.ApprovedCount,
		PaidCount:     summary.PaidCount,
		RejectedCount: summary.RejectedCount,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCommissionTrend handles GET /commissions/trend
func (h *CommissionHandler) GetCommissionTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	points, err := h.commissionService.GetCommissionTrend(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get commission trend", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get commission trend")
		return
	}

	respPoints := make([]commissionTrendPointResponse, len(points))
	for i, p := range points {
		respPoints[i] = commissionTrendPointResponse{
			Date:             p.Period.Format(time.RFC3339),
			CommissionAmount: p.Earned.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    respPoints,
	})
}

// CommissionPlanExists handles GET /commission-plans/{id}/exists
func (h *CommissionHandler) CommissionPlanExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.commissionService.CommissionPlanExists(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to check commission plan existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// CommissionRuleExists handles GET /commission-rules/{id}/exists
func (h *CommissionHandler) CommissionRuleExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.commissionService.CommissionRuleExists(ctx, companyID, ruleID)
	if err != nil {
		h.logger.Error("failed to check commission rule existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// CommissionRecordExists handles GET /commissions/{id}/exists
func (h *CommissionHandler) CommissionRecordExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commissionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission ID")
		return
	}
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.commissionService.CommissionRecordExists(ctx, companyID, commissionID)
	if err != nil {
		h.logger.Error("failed to check commission record existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// CommissionAlreadyGenerated handles GET /commissions/already-generated
func (h *CommissionHandler) CommissionAlreadyGenerated(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	refTypeStr := r.URL.Query().Get("reference_type")
	if refTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "reference_type query parameter is required")
		return
	}
	refIDStr := r.URL.Query().Get("reference_id")
	if refIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "reference_id query parameter is required")
		return
	}
	refID, err := uuid.Parse(refIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reference_id")
		return
	}
	refType := enums.CommissionReferenceType(refTypeStr)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "commission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.commissionService.CommissionAlreadyGenerated(ctx, companyID, refType, refID)
	if err != nil {
		h.logger.Error("failed to check if commission already generated", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"already_generated": exists},
	})
}

// ---------- Conversion Helpers ----------

func (h *CommissionHandler) planToResponse(plan *models.CommissionPlan) createCommissionPlanResponse {
	resp := createCommissionPlanResponse{
		PlanID:        plan.PlanID.String(),
		CompanyID:     plan.CompanyID.String(),
		Code:          plan.Code,
		Name:          plan.Name,
		Description:   plan.Description,
		EffectiveFrom: plan.EffectiveFrom.Format(time.RFC3339),
		IsActive:      plan.IsActive,
		CreatedAt:     plan.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     plan.UpdatedAt.Format(time.RFC3339),
	}
	if plan.EffectiveTo != nil {
		to := plan.EffectiveTo.Format(time.RFC3339)
		resp.EffectiveTo = &to
	}
	return resp
}

func (h *CommissionHandler) planToSummary(plan *models.CommissionPlan) commissionPlanSummary {
	sum := commissionPlanSummary{
		PlanID:        plan.PlanID.String(),
		Code:          plan.Code,
		Name:          plan.Name,
		Description:   plan.Description,
		EffectiveFrom: plan.EffectiveFrom.Format(time.RFC3339),
		IsActive:      plan.IsActive,
	}
	if plan.EffectiveTo != nil {
		to := plan.EffectiveTo.Format(time.RFC3339)
		sum.EffectiveTo = &to
	}
	return sum
}

func (h *CommissionHandler) ruleToResponse(rule *models.CommissionRule) createCommissionRuleResponse {
	resp := createCommissionRuleResponse{
		RuleID:       rule.RuleID.String(),
		CompanyID:    rule.CompanyID.String(),
		PlanID:       rule.PlanID.String(),
		RuleType:     string(rule.RuleType),
		AppliesTo:    string(rule.AppliesTo),
		Rate:         rule.Rate.String(),
		IsPercentage: rule.IsPercentage,
		Priority:     rule.Priority,
		CreatedAt:    rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    rule.UpdatedAt.Format(time.RFC3339),
	}
	if rule.ProductID != nil {
		pid := rule.ProductID.String()
		resp.ProductID = &pid
	}
	if rule.TierMin != nil {
		min := rule.TierMin.String()
		resp.TierMin = &min
	}
	if rule.TierMax != nil {
		max := rule.TierMax.String()
		resp.TierMax = &max
	}
	return resp
}

func (h *CommissionHandler) ruleToSummary(rule *models.CommissionRule) commissionRuleSummary {
	sum := commissionRuleSummary{
		RuleID:       rule.RuleID.String(),
		PlanID:       rule.PlanID.String(),
		RuleType:     string(rule.RuleType),
		AppliesTo:    string(rule.AppliesTo),
		Rate:         rule.Rate.String(),
		IsPercentage: rule.IsPercentage,
		Priority:     rule.Priority,
	}
	if rule.ProductID != nil {
		pid := rule.ProductID.String()
		sum.ProductID = &pid
	}
	if rule.TierMin != nil {
		min := rule.TierMin.String()
		sum.TierMin = &min
	}
	if rule.TierMax != nil {
		max := rule.TierMax.String()
		sum.TierMax = &max
	}
	return sum
}

func (h *CommissionHandler) commissionToResponse(c *models.SalesCommission) commissionRecordResponse {
	resp := commissionRecordResponse{
		CommissionID:     c.CommissionID.String(),
		CompanyID:        c.CompanyID.String(),
		SalesRepID:       c.SalesRepID.String(),
		ReferenceType:    string(c.ReferenceType),
		ReferenceID:      c.ReferenceID.String(),
		CommissionBase:   c.CommissionBase.String(),
		CommissionRate:   c.CommissionRate.String(),
		CommissionAmount: c.CommissionAmount.String(),
		Status:           string(c.Status),
		EarnedAt:         c.EarnedAt.Format(time.RFC3339),
		Notes:            c.Notes,
		CreatedAt:        c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        c.UpdatedAt.Format(time.RFC3339),
	}
	if c.PaidAt != nil {
		paid := c.PaidAt.Format(time.RFC3339)
		resp.PaidAt = &paid
	}
	if c.ApprovedAt != nil {
		approved := c.ApprovedAt.Format(time.RFC3339)
		resp.ApprovedAt = &approved
	}
	if c.RejectedAt != nil {
		rejected := c.RejectedAt.Format(time.RFC3339)
		resp.RejectedAt = &rejected
	}
	if c.RejectReason != nil {
		resp.RejectReason = c.RejectReason
	}
	return resp
}
