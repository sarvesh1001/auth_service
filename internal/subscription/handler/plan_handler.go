package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// PlanHandler handles all plan-related endpoints.
type PlanHandler struct {
	planService        service.PlanService
	planItemService    service.PlanItemService
	planCloneService   service.PlanCloneService
	planVersionService service.PlanVersionService
	*BaseHandler
}

// NewPlanHandler creates a new PlanHandler.
func NewPlanHandler(
	planService service.PlanService,
	planItemService service.PlanItemService,
	planCloneService service.PlanCloneService,
	planVersionService service.PlanVersionService,
	logger *zap.Logger,
) *PlanHandler {
	return &PlanHandler{
		planService:        planService,
		planItemService:    planItemService,
		planCloneService:   planCloneService,
		planVersionService: planVersionService,
		BaseHandler:        &BaseHandler{logger: logger.Named("plan_handler")},
	}
}

// -------------------- Request & Response types --------------------

// Plan requests
type createPlanRequest struct {
	Name               string                 `json:"name"`
	PlanType           string                 `json:"plan_type"`
	Description        *string                `json:"description,omitempty"`
	BillingPolicyID    string                 `json:"billing_policy_id"`
	RenewalPolicyID    string                 `json:"renewal_policy_id"`
	PausePolicyID      string                 `json:"pause_policy_id"`
	ProrationPolicyID  string                 `json:"proration_policy_id"`
	DurationDays       int                    `json:"duration_days"`
	CancellationPolicy *string                `json:"cancellation_policy,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type updatePlanRequest struct {
	Name               *string                `json:"name,omitempty"`
	PlanType           *string                `json:"plan_type,omitempty"`
	Description        *string                `json:"description,omitempty"`
	BillingPolicyID    *string                `json:"billing_policy_id,omitempty"`
	RenewalPolicyID    *string                `json:"renewal_policy_id,omitempty"`
	PausePolicyID      *string                `json:"pause_policy_id,omitempty"`
	ProrationPolicyID  *string                `json:"proration_policy_id,omitempty"`
	DurationDays       *int                   `json:"duration_days,omitempty"`
	CancellationPolicy *string                `json:"cancellation_policy,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type planUpdatePriceRequest struct {
	Price    string `json:"price"`
	Currency string `json:"currency"`
}

type planUpdateDurationRequest struct {
	DurationDays int `json:"duration_days"`
}

type planUpdatePolicyRequest struct {
	PolicyID string `json:"policy_id"`
}

// Plan item requests – extended with tax_rate, product_id, metadata
type createPlanItemRequest struct {
	ItemType        string  `json:"item_type"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	FeatureKey      *string `json:"feature_key,omitempty"`
	BillingPolicyID *string `json:"billing_policy_id,omitempty"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
	EffectiveFrom   string  `json:"effective_from,omitempty"`
	EffectiveTo     *string `json:"effective_to,omitempty"`
	IsMandatory     bool    `json:"is_mandatory"`
	// NEW FIELDS
	TaxRate   *string                `json:"tax_rate,omitempty"`
	ProductID *string                `json:"product_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type bulkCreatePlanItemsRequest struct {
	Items []createPlanItemRequest `json:"items"`
}

type updatePlanItemRequest struct {
	Name            *string `json:"name,omitempty"`
	Description     *string `json:"description,omitempty"`
	FeatureKey      *string `json:"feature_key,omitempty"`
	BillingPolicyID *string `json:"billing_policy_id,omitempty"`
	Price           *string `json:"price,omitempty"`
	Currency        *string `json:"currency,omitempty"`
	EffectiveFrom   *string `json:"effective_from,omitempty"`
	EffectiveTo     *string `json:"effective_to,omitempty"`
	IsMandatory     *bool   `json:"is_mandatory,omitempty"`
	// NEW FIELDS
	TaxRate   *string                `json:"tax_rate,omitempty"`
	ProductID *string                `json:"product_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Clone request
type clonePlanRequest struct {
	Name              string `json:"name"`
	CloneItems        bool   `json:"clone_items"`
	CloneBenefits     bool   `json:"clone_benefits"`
	CloneEntitlements bool   `json:"clone_entitlements"`
	ClonePolicies     bool   `json:"clone_policies"`
	CreatedBy         string `json:"created_by"`
}

// Version requests
type createVersionRequest struct {
	VersionNumber int     `json:"version_number,omitempty"`
	Reason        *string `json:"reason,omitempty"`
}

type cloneVersionRequest struct {
	SourceVersionID string `json:"source_version_id"`
	NewVersion      int    `json:"new_version"`
	CreatedBy       string `json:"created_by"`
}

type rollbackVersionRequest struct {
	Version     int    `json:"version"`
	PerformedBy string `json:"performed_by"`
}

// -------------------- Response types --------------------

type planResponse struct {
	PlanID             string                 `json:"plan_id"`
	CompanyID          string                 `json:"company_id"`
	Name               string                 `json:"name"`
	PlanType           string                 `json:"plan_type"`
	Description        *string                `json:"description,omitempty"`
	BillingPolicyID    string                 `json:"billing_policy_id"`
	RenewalPolicyID    string                 `json:"renewal_policy_id"`
	PausePolicyID      string                 `json:"pause_policy_id"`
	ProrationPolicyID  string                 `json:"proration_policy_id"`
	DurationDays       int                    `json:"duration_days"`
	CancellationPolicy *string                `json:"cancellation_policy,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	IsActive           bool                   `json:"is_active"`
	Version            int                    `json:"version"`
	PublishedAt        *string                `json:"published_at,omitempty"`
	PublishedBy        *string                `json:"published_by,omitempty"`
	CreatedAt          string                 `json:"created_at"`
	UpdatedAt          string                 `json:"updated_at"`
	DeletedAt          *string                `json:"deleted_at,omitempty"`
}

type planItemResponse struct {
	PlanItemID      string  `json:"plan_item_id"`
	PlanID          string  `json:"plan_id"`
	CompanyID       string  `json:"company_id"` // NEW
	ItemType        string  `json:"item_type"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	FeatureKey      *string `json:"feature_key,omitempty"`
	BillingPolicyID *string `json:"billing_policy_id,omitempty"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
	EffectiveFrom   string  `json:"effective_from"`
	EffectiveTo     *string `json:"effective_to,omitempty"`
	IsMandatory     bool    `json:"is_mandatory"`
	IsActive        bool    `json:"is_active"`
	// NEW FIELDS
	TaxRate   *string                `json:"tax_rate,omitempty"`
	ProductID *string                `json:"product_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
	DeletedAt *string                `json:"deleted_at,omitempty"`
}

type listPlansResponse struct {
	Plans  []planResponse `json:"plans"`
	Total  int64          `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type listPlanItemsResponse struct {
	Items  []planItemResponse `json:"items"`
	Total  int64              `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

type planClonePreviewResponse struct {
	Items          int `json:"items"`
	Benefits       int `json:"benefits"`
	Entitlements   int `json:"entitlements"`
	Policies       int `json:"policies"`
	EstimatedSteps int `json:"estimated_steps"`
}

type planVersionComparisonResponse struct {
	LeftVersionID  string       `json:"left_version_id"`
	RightVersionID string       `json:"right_version_id"`
	PlanChanged    bool         `json:"plan_changed"`
	ItemsChanged   bool         `json:"items_changed"`
	Changes        []planChange `json:"changes"`
}

type planChange struct {
	Entity string      `json:"entity"`
	Field  string      `json:"field"`
	Old    interface{} `json:"old"`
	New    interface{} `json:"new"`
}

// -------------------- Conversion helpers --------------------

func (h *PlanHandler) toPlanResponse(p *models.Plan) planResponse {
	resp := planResponse{
		PlanID:             p.PlanID.String(),
		CompanyID:          p.CompanyID.String(),
		Name:               p.Name,
		PlanType:           string(p.PlanType),
		Description:        p.Description,
		BillingPolicyID:    p.BillingPolicyID.String(),
		RenewalPolicyID:    p.RenewalPolicyID.String(),
		PausePolicyID:      p.PausePolicyID.String(),
		ProrationPolicyID:  p.ProrationPolicyID.String(),
		DurationDays:       p.DurationDays,
		CancellationPolicy: p.CancellationPolicy,
		Metadata:           p.Metadata,
		IsActive:           p.IsActive,
		Version:            p.Version,
		CreatedAt:          p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:          p.UpdatedAt.Format(time.RFC3339),
	}
	if p.PublishedAt != nil {
		pub := p.PublishedAt.Format(time.RFC3339)
		resp.PublishedAt = &pub
	}
	if p.PublishedBy != nil {
		by := p.PublishedBy.String()
		resp.PublishedBy = &by
	}
	if p.DeletedAt != nil {
		del := p.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &del
	}
	return resp
}

func (h *PlanHandler) toPlanItemResponse(item *models.PlanItem) planItemResponse {
	resp := planItemResponse{
		PlanItemID:    item.PlanItemID.String(),
		PlanID:        item.PlanID.String(),
		CompanyID:     item.CompanyID.String(),
		ItemType:      string(item.ItemType),
		Name:          item.Name,
		Description:   item.Description,
		FeatureKey:    item.FeatureKey,
		Price:         item.Price.String(),
		Currency:      item.Currency,
		EffectiveFrom: item.EffectiveFrom.Format(time.RFC3339),
		IsMandatory:   item.IsMandatory,
		IsActive:      item.IsActive,
		CreatedAt:     item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     item.UpdatedAt.Format(time.RFC3339),
		Metadata:      item.Metadata,
	}
	if item.BillingPolicyID != nil {
		id := item.BillingPolicyID.String()
		resp.BillingPolicyID = &id
	}
	if item.EffectiveTo != nil {
		to := item.EffectiveTo.Format(time.RFC3339)
		resp.EffectiveTo = &to
	}
	if item.DeletedAt != nil {
		del := item.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &del
	}
	if item.TaxRate != nil {
		tr := item.TaxRate.String()
		resp.TaxRate = &tr
	}
	if item.ProductID != nil {
		pid := item.ProductID.String()
		resp.ProductID = &pid
	}
	return resp
}

type planVersionResponse struct {
	VersionID     string                 `json:"version_id"`
	CompanyID     string                 `json:"company_id"`
	PlanID        string                 `json:"plan_id"`
	VersionNumber int                    `json:"version_number"`
	Snapshot      map[string]interface{} `json:"snapshot"`
	IsPublished   bool                   `json:"is_published"`
	PublishedAt   *string                `json:"published_at,omitempty"`
	PublishedBy   *string                `json:"published_by,omitempty"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
	DeletedAt     *string                `json:"deleted_at,omitempty"`
}

func (h *PlanHandler) toPlanVersionResponse(v *models.PlanVersion) planVersionResponse {
	resp := planVersionResponse{
		VersionID:     v.VersionID.String(),
		CompanyID:     v.CompanyID.String(),
		PlanID:        v.PlanID.String(),
		VersionNumber: v.VersionNumber,
		Snapshot:      v.Snapshot,
		IsPublished:   v.IsPublished,
		CreatedAt:     v.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     v.UpdatedAt.Format(time.RFC3339),
	}
	if v.PublishedAt != nil {
		pub := v.PublishedAt.Format(time.RFC3339)
		resp.PublishedAt = &pub
	}
	if v.PublishedBy != nil {
		by := v.PublishedBy.String()
		resp.PublishedBy = &by
	}
	if v.DeletedAt != nil {
		del := v.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &del
	}
	return resp
}

// -------------------- Plan CRUD --------------------

// CreatePlan creates a new plan.
func (h *PlanHandler) CreatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.Name == "" || req.BillingPolicyID == "" || req.RenewalPolicyID == "" ||
		req.PausePolicyID == "" || req.ProrationPolicyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	planType := enums.PlanType(req.PlanType)
	if !planType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_type")
		return
	}

	// Parse UUIDs
	billingPolicyID, err := uuid.Parse(req.BillingPolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
		return
	}
	renewalPolicyID, err := uuid.Parse(req.RenewalPolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal_policy_id")
		return
	}
	pausePolicyID, err := uuid.Parse(req.PausePolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause_policy_id")
		return
	}
	prorationPolicyID, err := uuid.Parse(req.ProrationPolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration_policy_id")
		return
	}

	if req.DurationDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "duration_days must be > 0")
		return
	}

	plan := &models.Plan{
		PlanID:             uuid.New(),
		CompanyID:          companyID,
		Name:               req.Name,
		PlanType:           planType,
		Description:        req.Description,
		BillingPolicyID:    billingPolicyID,
		RenewalPolicyID:    renewalPolicyID,
		PausePolicyID:      pausePolicyID,
		ProrationPolicyID:  prorationPolicyID,
		DurationDays:       req.DurationDays,
		CancellationPolicy: req.CancellationPolicy,
		Metadata:           req.Metadata,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Create(ctx, plan); err != nil {
		h.logger.Error("failed to create plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanResponse(plan)
	location := fmt.Sprintf("/plans/%s", plan.PlanID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPlan retrieves a plan by ID.
func (h *PlanHandler) GetPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	plan, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if plan == nil {
		h.respondWithError(w, http.StatusNotFound, "plan not found")
		return
	}

	resp := h.toPlanResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePlan updates a plan.
func (h *PlanHandler) UpdatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	_, err = h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updatePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get plan for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "plan not found")
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.PlanType != nil {
		pt := enums.PlanType(*req.PlanType)
		if !pt.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid plan_type")
			return
		}
		existing.PlanType = pt
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.BillingPolicyID != nil {
		id, err := uuid.Parse(*req.BillingPolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
			return
		}
		existing.BillingPolicyID = id
	}
	if req.RenewalPolicyID != nil {
		id, err := uuid.Parse(*req.RenewalPolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid renewal_policy_id")
			return
		}
		existing.RenewalPolicyID = id
	}
	if req.PausePolicyID != nil {
		id, err := uuid.Parse(*req.PausePolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid pause_policy_id")
			return
		}
		existing.PausePolicyID = id
	}
	if req.ProrationPolicyID != nil {
		id, err := uuid.Parse(*req.ProrationPolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid proration_policy_id")
			return
		}
		existing.ProrationPolicyID = id
	}
	if req.DurationDays != nil {
		if *req.DurationDays <= 0 {
			h.respondWithError(w, http.StatusBadRequest, "duration_days must be > 0")
			return
		}
		existing.DurationDays = *req.DurationDays
	}
	if req.CancellationPolicy != nil {
		existing.CancellationPolicy = req.CancellationPolicy
	}
	if req.Metadata != nil {
		existing.Metadata = req.Metadata
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePlan deletes (archives) a plan.
func (h *PlanHandler) DeletePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Delete(ctx, companyID, planID); err != nil {
		h.logger.Error("failed to delete plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan deleted",
	})
}

// ActivatePlan activates a plan.
func (h *PlanHandler) ActivatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Activate(ctx, companyID, planID); err != nil {
		h.logger.Error("failed to activate plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan activated",
	})
}

// DeactivatePlan deactivates a plan.
func (h *PlanHandler) DeactivatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Deactivate(ctx, companyID, planID); err != nil {
		h.logger.Error("failed to deactivate plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan deactivated",
	})
}

// ArchivePlan archives a plan.
func (h *PlanHandler) ArchivePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Archive(ctx, companyID, planID); err != nil {
		h.logger.Error("failed to archive plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan archived",
	})
}

// RestorePlan restores an archived plan.
func (h *PlanHandler) RestorePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.Restore(ctx, companyID, planID); err != nil {
		h.logger.Error("failed to restore plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan restored",
	})
}

// UpdatePlanPrice updates the price of a plan (via its base item).
func (h *PlanHandler) UpdatePlanPrice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req planUpdatePriceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Price == "" || req.Currency == "" {
		h.respondWithError(w, http.StatusBadRequest, "price and currency are required")
		return
	}

	price, err := decimal.NewFromString(req.Price)
	if err != nil || price.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid price")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.UpdatePrice(ctx, companyID, planID, price, req.Currency); err != nil {
		h.logger.Error("failed to update plan price", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	plan, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		// If we can't fetch the updated plan, still return success with message
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}
	if plan == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}

	resp := h.toPlanResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePlanDuration updates the duration of a plan.
func (h *PlanHandler) UpdatePlanDuration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req planUpdateDurationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DurationDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "duration_days must be > 0")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planService.UpdateDuration(ctx, companyID, planID, req.DurationDays); err != nil {
		h.logger.Error("failed to update plan duration", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	plan, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "duration updated",
		})
		return
	}
	if plan == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "duration updated",
		})
		return
	}

	resp := h.toPlanResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// generic policy update handler
func (h *PlanHandler) updatePlanPolicy(w http.ResponseWriter, r *http.Request, policyType string, updateFunc func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req planUpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PolicyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "policy_id is required")
		return
	}

	policyID, err := uuid.Parse(req.PolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := updateFunc(ctx, companyID, planID, policyID); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update %s policy", policyType), zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	plan, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("%s policy updated", policyType),
		})
		return
	}
	if plan == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("%s policy updated", policyType),
		})
		return
	}

	resp := h.toPlanResponse(plan)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePlanBillingPolicy updates the billing policy.
func (h *PlanHandler) UpdatePlanBillingPolicy(w http.ResponseWriter, r *http.Request) {
	h.updatePlanPolicy(w, r, "billing", h.planService.UpdateBillingPolicy)
}

// UpdatePlanRenewalPolicy updates the renewal policy.
func (h *PlanHandler) UpdatePlanRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	h.updatePlanPolicy(w, r, "renewal", h.planService.UpdateRenewalPolicy)
}

// UpdatePlanPausePolicy updates the pause policy.
func (h *PlanHandler) UpdatePlanPausePolicy(w http.ResponseWriter, r *http.Request) {
	h.updatePlanPolicy(w, r, "pause", h.planService.UpdatePausePolicy)
}

// UpdatePlanProrationPolicy updates the proration policy.
func (h *PlanHandler) UpdatePlanProrationPolicy(w http.ResponseWriter, r *http.Request) {
	h.updatePlanPolicy(w, r, "proration", h.planService.UpdateProrationPolicy)
}

// ListPlans lists plans with filters and pagination.
func (h *PlanHandler) ListPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, offset := h.parsePagination(r)

	if limit < 0 || offset < 0 {
		h.respondWithError(w, http.StatusBadRequest, "limit and offset must be non-negative")
		return
	}

	filter := repository.PlanFilter{
		CompanyID: companyID,
	}

	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if planType := r.URL.Query().Get("plan_type"); planType != "" {
		pt := enums.PlanType(planType)
		if pt.IsValid() {
			filter.PlanType = &pt
		}
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		if isActive, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &isActive
		}
	}
	if billingPolicyIDStr := r.URL.Query().Get("billing_policy_id"); billingPolicyIDStr != "" {
		if bpID, err := uuid.Parse(billingPolicyIDStr); err == nil {
			filter.BillingPolicyID = &bpID
		}
	}
	// similarly for other policy filters

	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")
	if sortField == "" {
		sortField = "created_at"
	}
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := service.Sort{Field: sortField, Direction: sortDir}

	plans, total, err := h.planService.List(ctx, filter, service.Pagination{Limit: limit, Offset: offset}, sort)
	if err != nil {
		h.logger.Error("failed to list plans", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]planResponse, len(plans))
	for i, p := range plans {
		responses[i] = h.toPlanResponse(p)
	}

	resp := listPlansResponse{
		Plans:  responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchPlans searches plans by query.
func (h *PlanHandler) SearchPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, offset := h.parsePagination(r)

	plans, total, err := h.planService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search plans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search plans")
		return
	}

	responses := make([]planResponse, len(plans))
	for i, p := range plans {
		responses[i] = h.toPlanResponse(p)
	}

	resp := listPlansResponse{
		Plans:  responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActivePlans returns all active plans.
func (h *PlanHandler) GetActivePlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	plans, err := h.planService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active plans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active plans")
		return
	}

	responses := make([]planResponse, len(plans))
	for i, p := range plans {
		responses[i] = h.toPlanResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetArchivedPlans returns archived plans.
func (h *PlanHandler) GetArchivedPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	plans, err := h.planService.GetArchived(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get archived plans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get archived plans")
		return
	}

	responses := make([]planResponse, len(plans))
	for i, p := range plans {
		responses[i] = h.toPlanResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// -------------------- Plan Item handlers --------------------

// CreatePlanItem creates a new plan item.
func (h *PlanHandler) CreatePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	_, err = h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createPlanItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate
	if req.Name == "" || req.Price == "" || req.Currency == "" {
		h.respondWithError(w, http.StatusBadRequest, "name, price, currency are required")
		return
	}
	itemType := enums.ItemType(req.ItemType)
	if !itemType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_type")
		return
	}
	price, err := decimal.NewFromString(req.Price)
	if err != nil || price.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid price")
		return
	}

	var effectiveFrom time.Time
	if req.EffectiveFrom != "" {
		effectiveFrom, err = time.Parse(time.RFC3339, req.EffectiveFrom)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid effective_from format")
			return
		}
	} else {
		effectiveFrom = time.Now()
	}
	var effectiveTo *time.Time
	if req.EffectiveTo != nil && *req.EffectiveTo != "" {
		t, err := time.Parse(time.RFC3339, *req.EffectiveTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid effective_to format")
			return
		}
		effectiveTo = &t
	}

	var billingPolicyID *uuid.UUID
	if req.BillingPolicyID != nil && *req.BillingPolicyID != "" {
		id, err := uuid.Parse(*req.BillingPolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
			return
		}
		billingPolicyID = &id
	}

	item := &models.PlanItem{
		PlanItemID:      uuid.New(),
		PlanID:          planID,
		CompanyID:       companyID,
		ItemType:        itemType,
		Name:            req.Name,
		Description:     req.Description,
		FeatureKey:      req.FeatureKey,
		BillingPolicyID: billingPolicyID,
		Price:           price,
		Currency:        req.Currency,
		EffectiveFrom:   effectiveFrom,
		EffectiveTo:     effectiveTo,
		IsMandatory:     req.IsMandatory,
		IsActive:        true,
		Metadata:        req.Metadata,
	}

	// Parse tax_rate
	if req.TaxRate != nil && *req.TaxRate != "" {
		tr, err := decimal.NewFromString(*req.TaxRate)
		if err == nil && tr.GreaterThan(decimal.Zero) {
			item.TaxRate = &tr
		}
	}
	// Parse product_id
	if req.ProductID != nil && *req.ProductID != "" {
		pid, err := uuid.Parse(*req.ProductID)
		if err == nil {
			item.ProductID = &pid
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	// Verify plan exists and belongs to company
	plan, err := h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if plan == nil {
		h.respondWithError(w, http.StatusNotFound, "plan not found")
		return
	}

	if err := h.planItemService.Create(ctx, item); err != nil {
		h.logger.Error("failed to create plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanItemResponse(item)
	location := fmt.Sprintf("/plans/%s/items/%s", planID, item.PlanItemID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPlanItem retrieves a plan item.
func (h *PlanHandler) GetPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	item, err := h.planItemService.GetByID(ctx, companyID, planItemID)
	if err != nil {
		h.logger.Error("failed to get plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if item == nil {
		h.respondWithError(w, http.StatusNotFound, "plan item not found")
		return
	}

	resp := h.toPlanItemResponse(item)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePlanItem updates a plan item.
func (h *PlanHandler) UpdatePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updatePlanItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.planItemService.GetByID(ctx, companyID, planItemID)
	if err != nil {
		h.logger.Error("failed to get plan item for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "plan item not found")
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.FeatureKey != nil {
		existing.FeatureKey = req.FeatureKey
	}
	if req.BillingPolicyID != nil {
		if *req.BillingPolicyID == "" {
			existing.BillingPolicyID = nil
		} else {
			id, err := uuid.Parse(*req.BillingPolicyID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
				return
			}
			existing.BillingPolicyID = &id
		}
	}
	if req.Price != nil {
		price, err := decimal.NewFromString(*req.Price)
		if err != nil || price.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid price")
			return
		}
		existing.Price = price
	}
	if req.Currency != nil {
		existing.Currency = *req.Currency
	}
	if req.EffectiveFrom != nil {
		t, err := time.Parse(time.RFC3339, *req.EffectiveFrom)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid effective_from format")
			return
		}
		existing.EffectiveFrom = t
	}
	if req.EffectiveTo != nil {
		if *req.EffectiveTo == "" {
			existing.EffectiveTo = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.EffectiveTo)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid effective_to format")
				return
			}
			existing.EffectiveTo = &t
		}
	}
	if req.IsMandatory != nil {
		existing.IsMandatory = *req.IsMandatory
	}
	// NEW: TaxRate
	if req.TaxRate != nil {
		if *req.TaxRate == "" {
			existing.TaxRate = nil
		} else {
			tr, err := decimal.NewFromString(*req.TaxRate)
			if err != nil || tr.LessThan(decimal.Zero) {
				h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
				return
			}
			existing.TaxRate = &tr
		}
	}
	// NEW: ProductID
	if req.ProductID != nil {
		if *req.ProductID == "" {
			existing.ProductID = nil
		} else {
			pid, err := uuid.Parse(*req.ProductID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
				return
			}
			existing.ProductID = &pid
		}
	}
	// NEW: Metadata
	if req.Metadata != nil {
		existing.Metadata = req.Metadata
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanItemResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePlanItem deletes a plan item.
func (h *PlanHandler) DeletePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.Delete(ctx, companyID, planItemID); err != nil {
		h.logger.Error("failed to delete plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item deleted",
	})
}

// ActivatePlanItem activates a plan item.
func (h *PlanHandler) ActivatePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.Activate(ctx, companyID, planItemID); err != nil {
		h.logger.Error("failed to activate plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item activated",
	})
}

// DeactivatePlanItem deactivates a plan item.
func (h *PlanHandler) DeactivatePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.Deactivate(ctx, companyID, planItemID); err != nil {
		h.logger.Error("failed to deactivate plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item deactivated",
	})
}

// RestorePlanItem restores a deleted plan item.
func (h *PlanHandler) RestorePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.Restore(ctx, companyID, planItemID); err != nil {
		h.logger.Error("failed to restore plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item restored",
	})
}

// UpdatePlanItemPrice updates the price of a plan item.
func (h *PlanHandler) UpdatePlanItemPrice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planItemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req planUpdatePriceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Price == "" || req.Currency == "" {
		h.respondWithError(w, http.StatusBadRequest, "price and currency are required")
		return
	}

	price, err := decimal.NewFromString(req.Price)
	if err != nil || price.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid price")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.UpdatePrice(ctx, companyID, planItemID, price, req.Currency); err != nil {
		h.logger.Error("failed to update plan item price", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	item, err := h.planItemService.GetByID(ctx, companyID, planItemID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}
	if item == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}

	resp := h.toPlanItemResponse(item)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListPlanItems lists items for a plan.
func (h *PlanHandler) ListPlanItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify plan exists
	_, err = h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("plan not found", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	filter := repository.PlanItemFilter{
		PlanID: planID,
	}

	limit, offset := h.parsePagination(r)

	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")
	if sortField == "" {
		sortField = "created_at"
	}
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := service.Sort{Field: sortField, Direction: sortDir}

	items, total, err := h.planItemService.List(ctx, filter, service.Pagination{Limit: limit, Offset: offset}, sort)
	if err != nil {
		h.logger.Error("failed to list plan items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list plan items")
		return
	}

	responses := make([]planItemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toPlanItemResponse(it)
	}

	resp := listPlanItemsResponse{
		Items:  responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// BulkCreatePlanItems creates multiple plan items at once.
func (h *PlanHandler) BulkCreatePlanItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req bulkCreatePlanItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "items array cannot be empty")
		return
	}

	// Verify plan exists
	_, err = h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("plan not found", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	items := make([]*models.PlanItem, 0, len(req.Items))
	for _, rItem := range req.Items {
		itemType := enums.ItemType(rItem.ItemType)
		if !itemType.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid item_type")
			return
		}
		price, err := decimal.NewFromString(rItem.Price)
		if err != nil || price.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid price")
			return
		}
		var effectiveFrom time.Time
		if rItem.EffectiveFrom != "" {
			effectiveFrom, err = time.Parse(time.RFC3339, rItem.EffectiveFrom)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid effective_from format")
				return
			}
		} else {
			effectiveFrom = time.Now()
		}
		var effectiveTo *time.Time
		if rItem.EffectiveTo != nil && *rItem.EffectiveTo != "" {
			t, err := time.Parse(time.RFC3339, *rItem.EffectiveTo)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid effective_to format")
				return
			}
			effectiveTo = &t
		}
		var billingPolicyID *uuid.UUID
		if rItem.BillingPolicyID != nil && *rItem.BillingPolicyID != "" {
			id, err := uuid.Parse(*rItem.BillingPolicyID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
				return
			}
			billingPolicyID = &id
		}

		item := &models.PlanItem{
			PlanItemID:      uuid.New(),
			PlanID:          planID,
			CompanyID:       companyID,
			ItemType:        itemType,
			Name:            rItem.Name,
			Description:     rItem.Description,
			FeatureKey:      rItem.FeatureKey,
			BillingPolicyID: billingPolicyID,
			Price:           price,
			Currency:        rItem.Currency,
			EffectiveFrom:   effectiveFrom,
			EffectiveTo:     effectiveTo,
			IsMandatory:     rItem.IsMandatory,
			IsActive:        true,
			Metadata:        rItem.Metadata,
		}
		// Parse tax_rate
		if rItem.TaxRate != nil && *rItem.TaxRate != "" {
			tr, err := decimal.NewFromString(*rItem.TaxRate)
			if err == nil && tr.GreaterThan(decimal.Zero) {
				item.TaxRate = &tr
			}
		}
		// Parse product_id
		if rItem.ProductID != nil && *rItem.ProductID != "" {
			pid, err := uuid.Parse(*rItem.ProductID)
			if err == nil {
				item.ProductID = &pid
			}
		}
		items = append(items, item)
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.BulkCreate(ctx, items); err != nil {
		h.logger.Error("failed to bulk create plan items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]planItemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toPlanItemResponse(it)
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// MovePlanItem moves a plan item from one plan to another.
func (h *PlanHandler) MovePlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sourcePlanID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid source plan ID")
		return
	}
	targetPlanID, err := h.parseUUIDParam(r, "targetPlanId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid target plan ID")
		return
	}
	itemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify both plans exist and belong to company
	_, err = h.planService.GetByID(ctx, companyID, sourcePlanID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "source plan not found")
		return
	}
	_, err = h.planService.GetByID(ctx, companyID, targetPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "target plan not found")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.MoveToPlan(ctx, sourcePlanID, targetPlanID, itemID); err != nil {
		h.logger.Error("failed to move plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item moved",
	})
}

// CopyPlanItem copies a plan item to another plan.
func (h *PlanHandler) CopyPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sourcePlanID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid source plan ID")
		return
	}
	targetPlanID, err := h.parseUUIDParam(r, "targetPlanId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid target plan ID")
		return
	}
	itemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err = h.planService.GetByID(ctx, companyID, sourcePlanID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "source plan not found")
		return
	}
	_, err = h.planService.GetByID(ctx, companyID, targetPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "target plan not found")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planItemService.CopyToPlan(ctx, sourcePlanID, targetPlanID, itemID); err != nil {
		h.logger.Error("failed to copy plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "plan item copied",
	})
}

// -------------------- Plan Clone handlers --------------------

// ClonePlan clones a plan with specified options.
func (h *PlanHandler) ClonePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req clonePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	createdBy, err := uuid.Parse(req.CreatedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid created_by")
		return
	}

	cloneReq := &service.ClonePlanRequest{
		Name:              req.Name,
		CloneItems:        req.CloneItems,
		CloneBenefits:     req.CloneBenefits,
		CloneEntitlements: req.CloneEntitlements,
		ClonePolicies:     req.ClonePolicies,
		CreatedBy:         createdBy,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	newPlan, err := h.planCloneService.ClonePlan(ctx, companyID, planID, cloneReq)
	if err != nil {
		h.logger.Error("failed to clone plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanResponse(newPlan)
	location := fmt.Sprintf("/plans/%s", newPlan.PlanID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// PreviewClonePlan returns a preview of what will be cloned.
func (h *PlanHandler) PreviewClonePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	preview, err := h.planCloneService.PreviewClone(ctx, planID)
	if err != nil {
		h.logger.Error("failed to preview clone", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := planClonePreviewResponse{
		Items:          preview.Items,
		Benefits:       preview.Benefits,
		Entitlements:   preview.Entitlements,
		Policies:       preview.Policies,
		EstimatedSteps: preview.EstimatedSteps,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// -------------------- Plan Version handlers --------------------

// CreatePlanVersion creates a new version of a plan.
func (h *PlanHandler) CreatePlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate plan exists
	_, err = h.planService.GetByID(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("plan not found", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	version := &models.PlanVersion{
		VersionID:     uuid.New(),
		CompanyID:     companyID,
		PlanID:        planID,
		VersionNumber: req.VersionNumber,
		IsPublished:   false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planVersionService.CreateVersion(ctx, planID, version); err != nil {
		h.logger.Error("failed to create plan version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanVersionResponse(version)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// PublishPlanVersion publishes a version.
func (h *PlanHandler) PublishPlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	versionID, err := h.parseUUIDParam(r, "versionId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid version ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planVersionService.Publish(ctx, companyID, versionID, userID); err != nil {
		h.logger.Error("failed to publish version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "version published",
	})
}

// UnpublishPlanVersion unpublishes a version.
func (h *PlanHandler) UnpublishPlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	versionID, err := h.parseUUIDParam(r, "versionId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid version ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planVersionService.Unpublish(ctx, companyID, versionID); err != nil {
		h.logger.Error("failed to unpublish version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "version unpublished",
	})
}

// ArchivePlanVersion archives a version.
func (h *PlanHandler) ArchivePlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	versionID, err := h.parseUUIDParam(r, "versionId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid version ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planVersionService.Archive(ctx, companyID, versionID); err != nil {
		h.logger.Error("failed to archive version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "version archived",
	})
}

// RestorePlanVersion restores an archived version.
func (h *PlanHandler) RestorePlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	versionID, err := h.parseUUIDParam(r, "versionId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid version ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.planVersionService.Restore(ctx, companyID, versionID); err != nil {
		h.logger.Error("failed to restore version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "version restored",
	})
}

// ClonePlanVersion clones a version to a new version number.
func (h *PlanHandler) ClonePlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req cloneVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sourceVersionID, err := uuid.Parse(req.SourceVersionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid source_version_id")
		return
	}
	createdBy, err := uuid.Parse(req.CreatedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid created_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	newVersion, err := h.planVersionService.CloneVersion(ctx, companyID, sourceVersionID, req.NewVersion, createdBy)
	if err != nil {
		h.logger.Error("failed to clone version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPlanVersionResponse(newVersion)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RollbackPlanVersion rolls back to a specific version number.
func (h *PlanHandler) RollbackPlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req rollbackVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Version <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "version must be > 0")
		return
	}
	performedBy, err := uuid.Parse(req.PerformedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid performed_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	version, err := h.planVersionService.Rollback(ctx, companyID, planID, req.Version, performedBy)
	if err != nil {
		h.logger.Error("failed to rollback version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if version == nil {
		h.respondWithError(w, http.StatusNotFound, "version not found")
		return
	}

	resp := h.toPlanVersionResponse(version)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ComparePlanVersions compares two versions.
func (h *PlanHandler) ComparePlanVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	leftVersionID, err := uuid.Parse(r.URL.Query().Get("left_version_id"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid left_version_id")
		return
	}
	rightVersionID, err := uuid.Parse(r.URL.Query().Get("right_version_id"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid right_version_id")
		return
	}

	comparison, err := h.planVersionService.Compare(ctx, companyID, leftVersionID, rightVersionID)
	if err != nil {
		h.logger.Error("failed to compare versions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	changes := make([]planChange, len(comparison.Changes))
	for i, c := range comparison.Changes {
		changes[i] = planChange{
			Entity: c.Entity,
			Field:  c.Field,
			Old:    c.Old,
			New:    c.New,
		}
	}
	resp := planVersionComparisonResponse{
		LeftVersionID:  comparison.LeftVersion.VersionID.String(),
		RightVersionID: comparison.RightVersion.VersionID.String(),
		PlanChanged:    comparison.PlanChanged,
		ItemsChanged:   comparison.ItemsChanged,
		Changes:        changes,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetLatestPlanVersion returns the latest version of a plan.
func (h *PlanHandler) GetLatestPlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	version, err := h.planVersionService.GetLatest(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get latest version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if version == nil {
		h.respondWithError(w, http.StatusNotFound, "version not found")
		return
	}

	resp := h.toPlanVersionResponse(version)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPublishedPlanVersion returns the published version of a plan.
func (h *PlanHandler) GetPublishedPlanVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	version, err := h.planVersionService.GetPublished(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get published version", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if version == nil {
		h.respondWithError(w, http.StatusNotFound, "published version not found")
		return
	}

	resp := h.toPlanVersionResponse(version)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// -------------------- Error mapping --------------------

func (h *PlanHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case err == nil:
		return http.StatusOK, "success"
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "duplicate record"
	case errors.Is(err, subErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, subErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	case errors.Is(err, subErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrVersionMismatch):
		return http.StatusConflict, "version mismatch"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
