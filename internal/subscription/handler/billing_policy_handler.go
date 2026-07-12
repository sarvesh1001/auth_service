package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// BillingPolicyHandler handles HTTP requests for billing policies.
type BillingPolicyHandler struct {
	service service.BillingPolicyService
	*BaseHandler
}

// NewBillingPolicyHandler creates a new instance.
func NewBillingPolicyHandler(svc service.BillingPolicyService, logger *zap.Logger) *BillingPolicyHandler {
	return &BillingPolicyHandler{
		service:     svc,
		BaseHandler: &BaseHandler{logger: logger.Named("billing_policy_handler")},
	}
}

// ---------- Request/Response DTOs ----------

type createBillingPolicyRequest struct {
	Name            string `json:"name"`
	FrequencyID     int16  `json:"frequency_id"`
	BillingInterval int    `json:"billing_interval"`
	ModelID         int16  `json:"model_id"`
	AdvanceDays     int    `json:"advance_days"`
}

// Unique name to avoid conflict with addon_handler's updateBillingPolicyRequest
type billingPolicyUpdateRequest struct {
	Name            *string `json:"name,omitempty"`
	FrequencyID     *int16  `json:"frequency_id,omitempty"`
	BillingInterval *int    `json:"billing_interval,omitempty"`
	ModelID         *int16  `json:"model_id,omitempty"`
	AdvanceDays     *int    `json:"advance_days,omitempty"`
}

type billingPolicyFrequencyUpdateRequest struct {
	FrequencyID int16 `json:"frequency_id"`
}

type billingPolicyModelUpdateRequest struct {
	ModelID int16 `json:"model_id"`
}

type billingPolicyIntervalUpdateRequest struct {
	BillingInterval int `json:"billing_interval"`
}

type billingPolicyAdvanceDaysUpdateRequest struct {
	AdvanceDays int `json:"advance_days"`
}

type billingPolicyResponse struct {
	BillingPolicyID string  `json:"billing_policy_id"`
	CompanyID       string  `json:"company_id"`
	Name            string  `json:"name"`
	FrequencyID     int16   `json:"frequency_id"`
	BillingInterval int     `json:"billing_interval"`
	ModelID         int16   `json:"model_id"`
	AdvanceDays     int     `json:"advance_days"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	DeletedAt       *string `json:"deleted_at,omitempty"`
}

type listBillingPoliciesResponse struct {
	Policies []billingPolicyResponse `json:"policies"`
	Total    int64                   `json:"total"`
	Limit    int                     `json:"limit"`
	Offset   int                     `json:"offset"`
}

// ---------- Conversion helper ----------

func (h *BillingPolicyHandler) toResponse(policy *models.BillingPolicy) billingPolicyResponse {
	resp := billingPolicyResponse{
		BillingPolicyID: policy.BillingPolicyID.String(),
		CompanyID:       policy.CompanyID.String(),
		Name:            policy.Name,
		FrequencyID:     policy.FrequencyID,
		BillingInterval: policy.BillingInterval,
		ModelID:         policy.ModelID,
		AdvanceDays:     policy.AdvanceDays,
		IsActive:        policy.IsActive,
		CreatedAt:       policy.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       policy.UpdatedAt.Format(time.RFC3339),
	}
	if policy.DeletedAt != nil {
		deleted := policy.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &deleted
	}
	return resp
}

// ---------- Handlers ----------

// CreateBillingPolicy POST /billing-policies
func (h *BillingPolicyHandler) CreateBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if _, err := h.getUserIDFromContext(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createBillingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.FrequencyID <= 0 || req.BillingInterval <= 0 || req.ModelID <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "name, frequency_id, billing_interval, model_id are required")
		return
	}

	policy := &models.BillingPolicy{
		CompanyID:       companyID,
		Name:            req.Name,
		FrequencyID:     req.FrequencyID,
		BillingInterval: req.BillingInterval,
		ModelID:         req.ModelID,
		AdvanceDays:     req.AdvanceDays,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.Create(ctx, policy); err != nil {
		h.logger.Error("failed to create billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toResponse(policy)
	location := fmt.Sprintf("/billing-policies/%s", policy.BillingPolicyID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetBillingPolicy GET /billing-policies/{id}
func (h *BillingPolicyHandler) GetBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "billing policy not found")
		return
	}

	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetBillingPolicyByName GET /billing-policies/name?name=...
func (h *BillingPolicyHandler) GetBillingPolicyByName(w http.ResponseWriter, r *http.Request) {
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

	policy, err := h.service.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get billing policy by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "billing policy not found")
		return
	}

	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateBillingPolicy PUT /billing-policies/{id}
// Full update – all fields are required.
func (h *BillingPolicyHandler) UpdateBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	if _, err := h.getUserIDFromContext(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req billingPolicyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate that all required fields are provided and valid
	if req.Name == nil || *req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.FrequencyID == nil || *req.FrequencyID <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "frequency_id is required and must be positive")
		return
	}
	if req.BillingInterval == nil || *req.BillingInterval <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "billing_interval is required and must be positive")
		return
	}
	if req.ModelID == nil || *req.ModelID <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "model_id is required and must be positive")
		return
	}
	if req.AdvanceDays == nil || *req.AdvanceDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "advance_days is required and cannot be negative")
		return
	}

	existing, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get billing policy for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "billing policy not found")
		return
	}

	// Apply all fields (full update)
	existing.Name = *req.Name
	existing.FrequencyID = *req.FrequencyID
	existing.BillingInterval = *req.BillingInterval
	existing.ModelID = *req.ModelID
	existing.AdvanceDays = *req.AdvanceDays

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteBillingPolicy DELETE /billing-policies/{id}
func (h *BillingPolicyHandler) DeleteBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
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

	if err := h.service.Delete(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to delete billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "billing policy deleted successfully",
	})
}

// ActivateBillingPolicy POST /billing-policies/{id}/activate
func (h *BillingPolicyHandler) ActivateBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
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

	if err := h.service.Activate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to activate billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "billing policy activated",
	})
}

// DeactivateBillingPolicy POST /billing-policies/{id}/deactivate
func (h *BillingPolicyHandler) DeactivateBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
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

	if err := h.service.Deactivate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to deactivate billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "billing policy deactivated",
	})
}

// RestoreBillingPolicy POST /billing-policies/{id}/restore
func (h *BillingPolicyHandler) RestoreBillingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
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

	if err := h.service.Restore(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to restore billing policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "billing policy restored",
	})
}

// UpdateBillingPolicyFrequency PUT /billing-policies/{id}/frequency
func (h *BillingPolicyHandler) UpdateBillingPolicyFrequency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req billingPolicyFrequencyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FrequencyID <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "frequency_id is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.UpdateFrequency(ctx, companyID, policyID, req.FrequencyID); err != nil {
		h.logger.Error("failed to update billing policy frequency", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "frequency updated",
		})
		return
	}
	if policy == nil {
		// Should not happen because the update succeeded, but handle gracefully
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "frequency updated",
		})
		return
	}
	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateBillingPolicyModel PUT /billing-policies/{id}/model
func (h *BillingPolicyHandler) UpdateBillingPolicyModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req billingPolicyModelUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ModelID <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "model_id is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.UpdateBillingModel(ctx, companyID, policyID, req.ModelID); err != nil {
		h.logger.Error("failed to update billing policy model", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "model updated",
		})
		return
	}
	if policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "model updated",
		})
		return
	}
	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateBillingPolicyInterval PUT /billing-policies/{id}/interval
func (h *BillingPolicyHandler) UpdateBillingPolicyInterval(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req billingPolicyIntervalUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.BillingInterval <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "billing_interval must be positive")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.UpdateBillingInterval(ctx, companyID, policyID, req.BillingInterval); err != nil {
		h.logger.Error("failed to update billing policy interval", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "interval updated",
		})
		return
	}
	if policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "interval updated",
		})
		return
	}
	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateBillingPolicyAdvanceDays PUT /billing-policies/{id}/advance-days
func (h *BillingPolicyHandler) UpdateBillingPolicyAdvanceDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req billingPolicyAdvanceDaysUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AdvanceDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "advance_days cannot be negative")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.service.UpdateAdvanceBillingDays(ctx, companyID, policyID, req.AdvanceDays); err != nil {
		h.logger.Error("failed to update billing policy advance days", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.service.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "advance days updated",
		})
		return
	}
	if policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "advance days updated",
		})
		return
	}
	resp := h.toResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListBillingPolicies GET /billing-policies
func (h *BillingPolicyHandler) ListBillingPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.BillingPolicyFilter{
		CompanyID: companyID,
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		if isActive, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &isActive
		}
	}
	if freqStr := r.URL.Query().Get("frequency_id"); freqStr != "" {
		if freq, err := strconv.Atoi(freqStr); err == nil {
			fid := int16(freq)
			filter.FrequencyID = &fid
		}
	}
	if modelStr := r.URL.Query().Get("model_id"); modelStr != "" {
		if mod, err := strconv.Atoi(modelStr); err == nil {
			mid := int16(mod)
			filter.ModelID = &mid
		}
	}

	limit, offset := h.parsePagination(r)
	// Validate pagination parameters
	if limit < 0 || offset < 0 {
		h.respondWithError(w, http.StatusBadRequest, "limit and offset must be non-negative")
		return
	}
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

	policies, total, err := h.service.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list billing policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list billing policies")
		return
	}

	responses := make([]billingPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toResponse(p)
	}

	resp := listBillingPoliciesResponse{
		Policies: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchBillingPolicies GET /billing-policies/search?q=...
func (h *BillingPolicyHandler) SearchBillingPolicies(w http.ResponseWriter, r *http.Request) {
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
	// Validate pagination parameters
	if limit < 0 || offset < 0 {
		h.respondWithError(w, http.StatusBadRequest, "limit and offset must be non-negative")
		return
	}

	policies, total, err := h.service.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search billing policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search billing policies")
		return
	}

	responses := make([]billingPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toResponse(p)
	}

	resp := listBillingPoliciesResponse{
		Policies: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveBillingPolicies GET /billing-policies/active
func (h *BillingPolicyHandler) GetActiveBillingPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.service.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active billing policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active policies")
		return
	}

	responses := make([]billingPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toResponse(p)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// BillingPolicyExists HEAD /billing-policies/{id}
func (h *BillingPolicyHandler) BillingPolicyExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.service.Exists(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to check billing policy existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------- Error Mapping ----------

func (h *BillingPolicyHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "billing policy not found"
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "billing policy with this name already exists"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
