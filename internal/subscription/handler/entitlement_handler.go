package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// EntitlementHandler handles HTTP requests for entitlements.
type EntitlementHandler struct {
	entitlementService service.EntitlementService
	*BaseHandler
}

// NewEntitlementHandler creates a new EntitlementHandler.
func NewEntitlementHandler(entitlementService service.EntitlementService, logger *zap.Logger) *EntitlementHandler {
	return &EntitlementHandler{
		entitlementService: entitlementService,
		BaseHandler:        &BaseHandler{logger: logger.Named("entitlement_handler")},
	}
}

// ---------- Request/Response DTOs ----------

type createEntitlementRequest struct {
	PlanItemID  string  `json:"plan_item_id"`
	FeatureKey  string  `json:"feature_key"`
	LimitValue  *string `json:"limit_value,omitempty"`
	LimitPeriod *string `json:"limit_period,omitempty"`
	IsEnabled   *bool   `json:"is_enabled,omitempty"`
}

type updateEntitlementRequest struct {
	PlanItemID  *string `json:"plan_item_id,omitempty"`
	FeatureKey  *string `json:"feature_key,omitempty"`
	LimitValue  *string `json:"limit_value,omitempty"`
	LimitPeriod *string `json:"limit_period,omitempty"`
	IsEnabled   *bool   `json:"is_enabled,omitempty"`
}

type entitlementResponse struct {
	EntitlementID string  `json:"entitlement_id"`
	PlanItemID    string  `json:"plan_item_id"`
	FeatureKey    string  `json:"feature_key"`
	LimitValue    *string `json:"limit_value,omitempty"`
	LimitPeriod   *string `json:"limit_period,omitempty"`
	IsEnabled     bool    `json:"is_enabled"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type listEntitlementsResponse struct {
	Entitlements []entitlementResponse `json:"entitlements"`
	Total        int64                 `json:"total"`
	Limit        int                   `json:"limit"`
	Offset       int                   `json:"offset"`
}

type grantRequest struct {
	SubscriptionID string `json:"subscription_id"`
}

// ---------- Response mapping ----------

func (h *EntitlementHandler) toEntitlementResponse(ent *models.Entitlement) entitlementResponse {
	resp := entitlementResponse{
		EntitlementID: ent.EntitlementID.String(),
		PlanItemID:    ent.PlanItemID.String(),
		FeatureKey:    ent.FeatureKey,
		IsEnabled:     ent.IsEnabled,
		CreatedAt:     ent.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     ent.UpdatedAt.Format(time.RFC3339),
	}
	if ent.LimitValue != nil {
		val := ent.LimitValue.String()
		resp.LimitValue = &val
	}
	if ent.LimitPeriod != "" {
		period := string(ent.LimitPeriod)
		resp.LimitPeriod = &period
	}
	return resp
}

// ---------- Handlers ----------

// CreateEntitlement godoc
// @Summary Create a new entitlement
// @Tags entitlements
// @Accept json
// @Produce json
// @Param body body createEntitlementRequest true "Entitlement data"
// @Success 201 {object} map[string]interface{} "data contains entitlementResponse"
// @Failure 400 {object} map[string]interface{} "error message"
// @Failure 401 {object} map[string]interface{} "unauthorized"
// @Router /entitlements [post]
func (h *EntitlementHandler) CreateEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Auth check (optional – get userID)
	if _, err := h.getUserIDFromContext(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Company ID from header
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = companyID // may be used for permission checks if needed

	var req createEntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.PlanItemID == "" || req.FeatureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id and feature_key are required")
		return
	}

	planItemID, err := uuid.Parse(req.PlanItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	ent := &models.Entitlement{
		EntitlementID: uuid.New(),
		PlanItemID:    planItemID,
		FeatureKey:    req.FeatureKey,
		IsEnabled:     true,
	}
	if req.IsEnabled != nil {
		ent.IsEnabled = *req.IsEnabled
	}
	if req.LimitValue != nil {
		val, err := decimal.NewFromString(*req.LimitValue)
		if err != nil || val.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid limit_value")
			return
		}
		ent.LimitValue = &val
	}
	if req.LimitPeriod != nil {
		period := enums.LimitPeriod(*req.LimitPeriod)
		if !period.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid limit_period")
			return
		}
		ent.LimitPeriod = period
	}

	// Idempotency
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.Create(ctx, ent); err != nil {
		h.logger.Error("failed to create entitlement", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toEntitlementResponse(ent)
	location := fmt.Sprintf("/entitlements/%s", ent.EntitlementID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetEntitlement godoc
// @Summary Get entitlement by ID
// @Tags entitlements
// @Produce json
// @Param id path string true "Entitlement ID"
// @Success 200 {object} map[string]interface{} "data contains entitlementResponse"
// @Failure 404 {object} map[string]interface{} "not found"
// @Router /entitlements/{id} [get]
func (h *EntitlementHandler) GetEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entitlementID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entitlement ID")
		return
	}

	ent, err := h.entitlementService.GetByID(ctx, entitlementID)
	if err != nil {
		h.logger.Error("failed to get entitlement", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toEntitlementResponse(ent)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateEntitlement godoc
// @Summary Update an existing entitlement
// @Tags entitlements
// @Accept json
// @Produce json
// @Param id path string true "Entitlement ID"
// @Param body body updateEntitlementRequest true "Update fields"
// @Success 200 {object} map[string]interface{} "updated entitlement"
// @Router /entitlements/{id} [put]
func (h *EntitlementHandler) UpdateEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entitlementID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entitlement ID")
		return
	}

	// Auth
	if _, err := h.getUserIDFromContext(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Get existing
	existing, err := h.entitlementService.GetByID(ctx, entitlementID)
	if err != nil {
		h.logger.Error("failed to get entitlement for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	var req updateEntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Apply updates
	if req.PlanItemID != nil {
		pid, err := uuid.Parse(*req.PlanItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
			return
		}
		existing.PlanItemID = pid
	}
	if req.FeatureKey != nil {
		existing.FeatureKey = *req.FeatureKey
	}
	if req.LimitValue != nil {
		val, err := decimal.NewFromString(*req.LimitValue)
		if err != nil || val.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid limit_value")
			return
		}
		existing.LimitValue = &val
	}
	if req.LimitPeriod != nil {
		period := enums.LimitPeriod(*req.LimitPeriod)
		if !period.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid limit_period")
			return
		}
		existing.LimitPeriod = period
	}
	if req.IsEnabled != nil {
		existing.IsEnabled = *req.IsEnabled
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update entitlement", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toEntitlementResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteEntitlement godoc
// @Summary Delete an entitlement
// @Tags entitlements
// @Param id path string true "Entitlement ID"
// @Success 200 {object} map[string]interface{} "success message"
// @Router /entitlements/{id} [delete]
func (h *EntitlementHandler) DeleteEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entitlementID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entitlement ID")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.Delete(ctx, entitlementID); err != nil {
		h.logger.Error("failed to delete entitlement", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "entitlement deleted successfully",
	})
}

// ListEntitlements godoc
// @Summary List entitlements with filters and pagination
// @Tags entitlements
// @Produce json
// @Param plan_item_id query string false "Filter by plan item ID"
// @Param feature_key query string false "Filter by feature key"
// @Param is_enabled query bool false "Filter by enabled status"
// @Param limit query int false "Pagination limit (default 20, max 100)"
// @Param offset query int false "Pagination offset"
// @Param sort_field query string false "Sort field (default created_at)"
// @Param sort_dir query string false "Sort direction (DESC/ASC, default DESC)"
// @Success 200 {object} map[string]interface{} "data contains listEntitlementsResponse"
// @Router /entitlements [get]
func (h *EntitlementHandler) ListEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Build filter
	filter := repository.EntitlementFilter{}

	if planItemIDStr := r.URL.Query().Get("plan_item_id"); planItemIDStr != "" {
		if pid, err := uuid.Parse(planItemIDStr); err == nil {
			filter.PlanItemID = &pid
		}
	}
	if featureKey := r.URL.Query().Get("feature_key"); featureKey != "" {
		filter.FeatureKey = &featureKey
	}
	if isEnabledStr := r.URL.Query().Get("is_enabled"); isEnabledStr != "" {
		if isEnabled, err := strconv.ParseBool(isEnabledStr); err == nil {
			filter.IsEnabled = &isEnabled
		}
	}

	// Pagination
	limit, offset := h.parsePagination(r)
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_dir")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	entitlements, total, err := h.entitlementService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list entitlements", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list entitlements")
		return
	}

	responses := make([]entitlementResponse, len(entitlements))
	for i, e := range entitlements {
		responses[i] = h.toEntitlementResponse(e)
	}

	resp := listEntitlementsResponse{
		Entitlements: responses,
		Total:        total,
		Limit:        limit,
		Offset:       offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchEntitlements godoc
// @Summary Search entitlements by query string
// @Tags entitlements
// @Produce json
// @Param q query string true "Search query"
// @Param limit query int false "Pagination limit"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{} "listEntitlementsResponse"
// @Router /entitlements/search [get]
func (h *EntitlementHandler) SearchEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	planItemIDStr := r.URL.Query().Get("plan_item_id")
	if planItemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id is required for search")
		return
	}
	planItemID, err := uuid.Parse(planItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	limit, offset := h.parsePagination(r)

	entitlements, total, err := h.entitlementService.Search(ctx, planItemID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search entitlements", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search entitlements")
		return
	}

	responses := make([]entitlementResponse, len(entitlements))
	for i, e := range entitlements {
		responses[i] = h.toEntitlementResponse(e)
	}
	resp := listEntitlementsResponse{
		Entitlements: responses,
		Total:        total,
		Limit:        limit,
		Offset:       offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetEntitlementsByPlanItem godoc
// @Summary Get all entitlements for a plan item
// @Tags entitlements
// @Produce json
// @Param planItemId path string true "Plan Item ID"
// @Success 200 {object} map[string]interface{} "data is array of entitlementResponse"
// @Router /plan-items/{planItemId}/entitlements [get]
func (h *EntitlementHandler) GetEntitlementsByPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planItemID, err := h.parseUUIDParam(r, "planItemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan item ID")
		return
	}

	ents, err := h.entitlementService.GetByPlanItem(ctx, planItemID)
	if err != nil {
		h.logger.Error("failed to get entitlements by plan item", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get entitlements")
		return
	}

	responses := make([]entitlementResponse, len(ents))
	for i, e := range ents {
		responses[i] = h.toEntitlementResponse(e)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetEntitlementsBySubscription godoc
// @Summary Get all entitlements for a subscription
// @Tags entitlements
// @Produce json
// @Param subscriptionId path string true "Subscription ID"
// @Success 200 {object} map[string]interface{} "array of entitlementResponse"
// @Router /subscriptions/{subscriptionId}/entitlements [get]
func (h *EntitlementHandler) GetEntitlementsBySubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	subID, err := h.parseUUIDParam(r, "subscriptionId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}

	ents, err := h.entitlementService.GetBySubscription(ctx, subID)
	if err != nil {
		h.logger.Error("failed to get entitlements for subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	responses := make([]entitlementResponse, len(ents))
	for i, e := range ents {
		responses[i] = h.toEntitlementResponse(e)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GrantEntitlementsToSubscription godoc
// @Summary Grant all entitlements of a plan to a subscription
// @Tags entitlements
// @Accept json
// @Produce json
// @Param body body grantRequest true "Subscription ID"
// @Success 200 {object} map[string]interface{} "success message"
// @Router /entitlements/grant [post]
func (h *EntitlementHandler) GrantEntitlementsToSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SubscriptionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "subscription_id is required")
		return
	}
	subID, err := uuid.Parse(req.SubscriptionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.GrantToSubscription(ctx, subID); err != nil {
		h.logger.Error("failed to grant entitlements", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "entitlements granted successfully",
	})
}

// RevokeEntitlementsFromSubscription godoc
// @Summary Revoke all entitlements from a subscription
// @Tags entitlements
// @Accept json
// @Produce json
// @Param body body grantRequest true "Subscription ID"
// @Success 200 {object} map[string]interface{} "success message"
// @Router /entitlements/revoke [post]
func (h *EntitlementHandler) RevokeEntitlementsFromSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SubscriptionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "subscription_id is required")
		return
	}
	subID, err := uuid.Parse(req.SubscriptionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.RevokeFromSubscription(ctx, subID); err != nil {
		h.logger.Error("failed to revoke entitlements", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "entitlements revoked successfully",
	})
}

// RefreshSubscriptionEntitlements godoc
// @Summary Refresh entitlements for a subscription (revoke + grant)
// @Tags entitlements
// @Accept json
// @Produce json
// @Param body body grantRequest true "Subscription ID"
// @Success 200 {object} map[string]interface{} "success message"
// @Router /entitlements/refresh [post]
func (h *EntitlementHandler) RefreshSubscriptionEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SubscriptionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "subscription_id is required")
		return
	}
	subID, err := uuid.Parse(req.SubscriptionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.entitlementService.RefreshSubscription(ctx, subID); err != nil {
		h.logger.Error("failed to refresh entitlements", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "entitlements refreshed successfully",
	})
}

// ---------- Error Mapping ----------

func (h *EntitlementHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "entitlement not found"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrSubscriptionNotFound):
		return http.StatusNotFound, "subscription not found"
	case errors.Is(err, subErrors.ErrConflict):
		return http.StatusConflict, "conflict"
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
