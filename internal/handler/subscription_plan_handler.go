// internal/handler/subscription_plan_handler.go
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/service"
)

// SubscriptionPlanHandler handles subscription plan endpoints.
type SubscriptionPlanHandler struct {
	planService      *service.SubscriptionPlanService
	idempotencyStore idempotency.Store
}

// NewSubscriptionPlanHandler creates a new SubscriptionPlanHandler.
func NewSubscriptionPlanHandler(
	planService *service.SubscriptionPlanService,
	idempotencyStore idempotency.Store,
) *SubscriptionPlanHandler {
	return &SubscriptionPlanHandler{
		planService:      planService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- Helpers ----------

func (h *SubscriptionPlanHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

func (h *SubscriptionPlanHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

func (h *SubscriptionPlanHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// ---------- CRUD Endpoints ----------

// CreatePlan POST /api/v1/admin/subscription-plans
func (h *SubscriptionPlanHandler) CreatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req models.SubscriptionPlan
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	plan, err := h.planService.CreatePlan(ctx, &req)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusCreated, successResponse(plan, "Subscription plan created"))
}

// GetPlanByID GET /api/v1/admin/subscription-plans/{planID}
func (h *SubscriptionPlanHandler) GetPlanByID(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	planIDStr := chi.URLParam(r, "planID")
	planID, err := uuid.Parse(planIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid plan ID")
		return
	}
	plan, err := h.planService.GetPlanByID(ctx, planID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(plan, "Plan retrieved"))
}

// GetPlanByCode GET /api/v1/admin/subscription-plans/code/{planCode}
func (h *SubscriptionPlanHandler) GetPlanByCode(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	planCode := chi.URLParam(r, "planCode")
	if planCode == "" {
		respondError(w, http.StatusBadRequest, "Plan code is required")
		return
	}
	plan, err := h.planService.GetPlanByCode(ctx, planCode)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(plan, "Plan retrieved"))
}

// ListPlans GET /api/v1/admin/subscription-plans
func (h *SubscriptionPlanHandler) ListPlans(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit
	includeInactive := r.URL.Query().Get("include_inactive") == "true"

	var plans []*models.SubscriptionPlan
	var total int
	var err error

	if includeInactive {
		plans, total, err = h.planService.ListAllPlans(ctx, limit, offset)
	} else {
		plans, err = h.planService.ListActivePlans(ctx)
		total = len(plans)
	}
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"plans": plans,
		"total": total,
		"page":  page,
		"limit": limit,
	}, "Plans retrieved"))
}

// UpdatePlan PUT /api/v1/admin/subscription-plans/{planID}
func (h *SubscriptionPlanHandler) UpdatePlan(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	planIDStr := chi.URLParam(r, "planID")
	planID, err := uuid.Parse(planIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid plan ID")
		return
	}
	var req models.SubscriptionPlan
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	plan, err := h.planService.UpdatePlan(ctx, planID, &req)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(plan, "Plan updated"))
}

// DeletePlan DELETE /api/v1/admin/subscription-plans/{planID}
func (h *SubscriptionPlanHandler) DeletePlan(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	planIDStr := chi.URLParam(r, "planID")
	planID, err := uuid.Parse(planIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid plan ID")
		return
	}
	if err := h.planService.SoftDeletePlan(ctx, planID); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Plan deleted"))
}
