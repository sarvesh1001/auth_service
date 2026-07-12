// file: internal/subscription/handler/addon_handler.go
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
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// AddonHandler handles HTTP requests for add-ons.
type AddonHandler struct {
	addonService service.AddonService
	*BaseHandler
}

// NewAddonHandler creates a new AddonHandler.
func NewAddonHandler(addonService service.AddonService, logger *zap.Logger) *AddonHandler {
	return &AddonHandler{
		addonService: addonService,
		BaseHandler:  &BaseHandler{logger: logger.Named("addon_handler")},
	}
}

// ---- Request/Response Types ----

type createAddonRequest struct {
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	BillingPolicyID string  `json:"billing_policy_id"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
}

type updateAddonRequest struct {
	Name            *string `json:"name,omitempty"`
	Description     *string `json:"description,omitempty"`
	BillingPolicyID *string `json:"billing_policy_id,omitempty"`
	Price           *string `json:"price,omitempty"`
	Currency        *string `json:"currency,omitempty"`
}

type updatePriceRequest struct {
	Price    string `json:"price"`
	Currency string `json:"currency"`
}

type updateBillingPolicyRequest struct {
	BillingPolicyID string `json:"billing_policy_id"`
}

type addonResponse struct {
	AddonID         string  `json:"addon_id"`
	CompanyID       string  `json:"company_id"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	BillingPolicyID string  `json:"billing_policy_id"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	DeletedAt       *string `json:"deleted_at,omitempty"`
}

type listAddonsResponse struct {
	Addons []addonResponse `json:"addons"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// ---- Helper to convert model to response ----
// NOTE: This function assumes the input is never nil.
// All callers must ensure the pointer is non‑nil before calling.
func (h *AddonHandler) toAddonResponse(addon *models.Addon) addonResponse {
	resp := addonResponse{
		AddonID:         addon.AddonID.String(),
		CompanyID:       addon.CompanyID.String(),
		Name:            addon.Name,
		Description:     addon.Description,
		BillingPolicyID: addon.BillingPolicyID.String(),
		Price:           addon.Price.String(),
		Currency:        addon.Currency,
		IsActive:        addon.IsActive,
		CreatedAt:       addon.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       addon.UpdatedAt.Format(time.RFC3339),
	}
	if addon.DeletedAt != nil {
		deleted := addon.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &deleted
	}
	return resp
}

// ---- Endpoint Handlers ----

// CreateAddon handles POST /addons
func (h *AddonHandler) CreateAddon(w http.ResponseWriter, r *http.Request) {
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

	var req createAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.BillingPolicyID == "" || req.Price == "" || req.Currency == "" {
		h.respondWithError(w, http.StatusBadRequest, "name, billing_policy_id, price, currency are required")
		return
	}

	price, err := decimal.NewFromString(req.Price)
	if err != nil || price.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid price")
		return
	}
	billingPolicyID, err := uuid.Parse(req.BillingPolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
		return
	}

	addon := &models.Addon{
		AddonID:         uuid.New(),
		CompanyID:       companyID,
		Name:            req.Name,
		Description:     req.Description,
		BillingPolicyID: billingPolicyID,
		Price:           price,
		Currency:        req.Currency,
		IsActive:        true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.addonService.Create(ctx, addon); err != nil {
		h.logger.Error("failed to create addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toAddonResponse(addon)
	location := fmt.Sprintf("/addons/%s", addon.AddonID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetAddon handles GET /addons/{id}
func (h *AddonHandler) GetAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addon, err := h.addonService.GetByID(ctx, companyID, addonID)
	if err != nil {
		h.logger.Error("failed to get addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	// 🔥 FIX: Check for nil before converting
	if addon == nil {
		h.respondWithError(w, http.StatusNotFound, "addon not found")
		return
	}

	resp := h.toAddonResponse(addon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetAddonByName handles GET /addons/name?name=...
func (h *AddonHandler) GetAddonByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addon, err := h.addonService.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get addon by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	// 🔥 FIX: Check for nil before converting
	if addon == nil {
		h.respondWithError(w, http.StatusNotFound, "addon not found")
		return
	}

	resp := h.toAddonResponse(addon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateAddon handles PUT /addons/{id}
func (h *AddonHandler) UpdateAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
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

	var req updateAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing addon to update
	existing, err := h.addonService.GetByID(ctx, companyID, addonID)
	if err != nil {
		h.logger.Error("failed to get addon for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	// 🔥 FIX: Check if existing is nil (not found)
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "addon not found")
		return
	}

	// Apply updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.BillingPolicyID != nil {
		bpID, err := uuid.Parse(*req.BillingPolicyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
			return
		}
		existing.BillingPolicyID = bpID
	}
	if req.Price != nil {
		price, err := decimal.NewFromString(*req.Price)
		if err != nil || price.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid price")
			return
		}
		existing.Price = price
	}
	if req.Currency != nil {
		existing.Currency = *req.Currency
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.addonService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toAddonResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteAddon handles DELETE /addons/{id}
func (h *AddonHandler) DeleteAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
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

	if err := h.addonService.Delete(ctx, companyID, addonID); err != nil {
		h.logger.Error("failed to delete addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "addon deleted successfully",
	})
}

// ActivateAddon handles PATCH /addons/{id}/activate
func (h *AddonHandler) ActivateAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
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

	if err := h.addonService.Activate(ctx, companyID, addonID); err != nil {
		h.logger.Error("failed to activate addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "addon activated",
	})
}

// DeactivateAddon handles PATCH /addons/{id}/deactivate
func (h *AddonHandler) DeactivateAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
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

	if err := h.addonService.Deactivate(ctx, companyID, addonID); err != nil {
		h.logger.Error("failed to deactivate addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "addon deactivated",
	})
}

// RestoreAddon handles POST /addons/{id}/restore
func (h *AddonHandler) RestoreAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
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

	if err := h.addonService.Restore(ctx, companyID, addonID); err != nil {
		h.logger.Error("failed to restore addon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "addon restored",
	})
}

// UpdateAddonPrice handles PATCH /addons/{id}/price
func (h *AddonHandler) UpdateAddonPrice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updatePriceRequest
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

	if err := h.addonService.UpdatePrice(ctx, companyID, addonID, price, req.Currency); err != nil {
		h.logger.Error("failed to update addon price", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Return updated addon
	addon, err := h.addonService.GetByID(ctx, companyID, addonID)
	if err != nil {
		h.logger.Warn("failed to fetch updated addon", zap.Error(err))
		// Fallback: just return a success message
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}
	// 🔥 FIX: Check for nil before converting
	if addon == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "price updated",
		})
		return
	}
	resp := h.toAddonResponse(addon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateAddonBillingPolicy handles PATCH /addons/{id}/billing-policy
func (h *AddonHandler) UpdateAddonBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateBillingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.BillingPolicyID == "" {
		h.respondWithError(w, http.StatusBadRequest, "billing_policy_id is required")
		return
	}
	billingPolicyID, err := uuid.Parse(req.BillingPolicyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing_policy_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.addonService.UpdateBillingPolicy(ctx, companyID, addonID, billingPolicyID); err != nil {
		h.logger.Error("failed to update addon billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Return updated addon
	addon, err := h.addonService.GetByID(ctx, companyID, addonID)
	if err != nil {
		h.logger.Warn("failed to fetch updated addon", zap.Error(err))
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "billing policy updated",
		})
		return
	}
	// 🔥 FIX: Check for nil before converting
	if addon == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "billing policy updated",
		})
		return
	}
	resp := h.toAddonResponse(addon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListAddons handles GET /addons with filters
func (h *AddonHandler) ListAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.AddonFilter{
		CompanyID: companyID,
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive
		}
	}
	if billingPolicyIDStr := r.URL.Query().Get("billing_policy_id"); billingPolicyIDStr != "" {
		if bpID, err := uuid.Parse(billingPolicyIDStr); err == nil {
			filter.BillingPolicyID = &bpID
		}
	}

	limit, offset := h.parsePagination(r)
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")
	if sortField == "" {
		sortField = "created_at"
	}
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	addons, total, err := h.addonService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list addons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list addons")
		return
	}

	responses := make([]addonResponse, len(addons))
	for i, a := range addons {
		responses[i] = h.toAddonResponse(a)
	}

	resp := listAddonsResponse{
		Addons: responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchAddons handles GET /addons/search?q=...
func (h *AddonHandler) SearchAddons(w http.ResponseWriter, r *http.Request) {
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
	addons, total, err := h.addonService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search addons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search addons")
		return
	}

	responses := make([]addonResponse, len(addons))
	for i, a := range addons {
		responses[i] = h.toAddonResponse(a)
	}

	resp := listAddonsResponse{
		Addons: responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveAddons handles GET /addons/active
func (h *AddonHandler) GetActiveAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addons, err := h.addonService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active addons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active addons")
		return
	}

	responses := make([]addonResponse, len(addons))
	for i, a := range addons {
		responses[i] = h.toAddonResponse(a)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetAddonsByBillingPolicy handles GET /addons/billing-policy/{billingPolicyId}
func (h *AddonHandler) GetAddonsByBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	billingPolicyID, err := h.parseUUIDParam(r, "billingPolicyId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addons, err := h.addonService.GetByBillingPolicy(ctx, companyID, billingPolicyID)
	if err != nil {
		h.logger.Error("failed to get addons by billing policy", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get addons")
		return
	}

	responses := make([]addonResponse, len(addons))
	for i, a := range addons {
		responses[i] = h.toAddonResponse(a)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetAddonsByPriceRange handles GET /addons/price-range?min=...&max=...
func (h *AddonHandler) GetAddonsByPriceRange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	minStr := r.URL.Query().Get("min")
	maxStr := r.URL.Query().Get("max")
	if minStr == "" || maxStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "min and max query parameters are required")
		return
	}
	min, err := decimal.NewFromString(minStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid min amount")
		return
	}
	max, err := decimal.NewFromString(maxStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid max amount")
		return
	}
	if min.GreaterThan(max) {
		h.respondWithError(w, http.StatusBadRequest, "min must be less than or equal to max")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	addons, err := h.addonService.GetByPriceRange(ctx, companyID, min, max)
	if err != nil {
		h.logger.Error("failed to get addons by price range", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get addons")
		return
	}

	responses := make([]addonResponse, len(addons))
	for i, a := range addons {
		responses[i] = h.toAddonResponse(a)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// AddonExists handles HEAD /addons/{id}
func (h *AddonHandler) AddonExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addonID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid addon ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.addonService.Exists(ctx, companyID, addonID)
	if err != nil {
		h.logger.Error("failed to check addon existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- Error mapping override ----

func (h *AddonHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrAddonNotFound):
		return http.StatusNotFound, "addon not found"
	case errors.Is(err, subErrors.ErrAddonAlreadyExists):
		return http.StatusConflict, "addon with this name already exists"
	case errors.Is(err, subErrors.ErrAddonInactive):
		return http.StatusBadRequest, "addon is inactive"
	case errors.Is(err, subErrors.ErrBillingPolicyNotFound):
		return http.StatusNotFound, "billing policy not found"
	case errors.Is(err, subErrors.ErrInvalidCurrency):
		return http.StatusBadRequest, "invalid currency code"
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
