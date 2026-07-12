package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

type ProrationPolicyHandler struct {
	prorationService service.ProrationPolicyService
	*BaseHandler
}

func NewProrationPolicyHandler(prorationService service.ProrationPolicyService, logger *zap.Logger) *ProrationPolicyHandler {
	return &ProrationPolicyHandler{
		prorationService: prorationService,
		BaseHandler:      &BaseHandler{logger: logger.Named("proration_policy_handler")},
	}
}

// Request types
type createProrationPolicyRequest struct {
	Name          string `json:"name"`
	UpgradeType   string `json:"upgrade_type"`
	DowngradeType string `json:"downgrade_type"`
}

type updateProrationPolicyRequest struct {
	Name          *string `json:"name,omitempty"`
	UpgradeType   *string `json:"upgrade_type,omitempty"`
	DowngradeType *string `json:"downgrade_type,omitempty"`
}

type updateUpgradeTypeRequest struct {
	UpgradeType string `json:"upgrade_type"`
}

type updateDowngradeTypeRequest struct {
	DowngradeType string `json:"downgrade_type"`
}

// Response types
type prorationPolicyResponse struct {
	ProrationPolicyID string  `json:"proration_policy_id"`
	CompanyID         string  `json:"company_id"`
	Name              string  `json:"name"`
	UpgradeType       string  `json:"upgrade_type"`
	DowngradeType     string  `json:"downgrade_type"`
	IsActive          bool    `json:"is_active"`
	CreatedAt         string  `json:"created_at"`
	UpdatedAt         string  `json:"updated_at"`
	DeletedAt         *string `json:"deleted_at,omitempty"`
}

type listProrationPoliciesResponse struct {
	ProrationPolicies []prorationPolicyResponse `json:"proration_policies"`
	Total             int64                     `json:"total"`
	Limit             int                       `json:"limit"`
	Offset            int                       `json:"offset"`
}

// Helper to convert model to response
func (h *ProrationPolicyHandler) toProrationPolicyResponse(policy *models.ProrationPolicy) prorationPolicyResponse {
	resp := prorationPolicyResponse{
		ProrationPolicyID: policy.ProrationPolicyID.String(),
		CompanyID:         policy.CompanyID.String(),
		Name:              policy.Name,
		UpgradeType:       string(policy.UpgradeType),
		DowngradeType:     string(policy.DowngradeType),
		IsActive:          policy.IsActive,
		CreatedAt:         policy.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         policy.UpdatedAt.Format(time.RFC3339),
	}
	if policy.DeletedAt != nil {
		deleted := policy.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &deleted
	}
	return resp
}

// CreateProrationPolicy godoc
// @Summary Create a new proration policy
// @Tags proration-policies
// @Accept json
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param request body createProrationPolicyRequest true "Proration policy details"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies [post]
func (h *ProrationPolicyHandler) CreateProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from context (optional, for audit)
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

	var req createProrationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.UpgradeType == "" || req.DowngradeType == "" {
		h.respondWithError(w, http.StatusBadRequest, "name, upgrade_type, downgrade_type are required")
		return
	}

	// Validate enums
	upgradeType := enums.UpgradeType(req.UpgradeType)
	if !upgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid upgrade_type")
		return
	}
	downgradeType := enums.DowngradeType(req.DowngradeType)
	if !downgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid downgrade_type")
		return
	}

	policy := &models.ProrationPolicy{
		CompanyID:     companyID,
		Name:          req.Name,
		UpgradeType:   upgradeType,
		DowngradeType: downgradeType,
		IsActive:      true,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.prorationService.Create(ctx, policy); err != nil {
		h.logger.Error("failed to create proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toProrationPolicyResponse(policy)
	location := fmt.Sprintf("/proration-policies/%s", policy.ProrationPolicyID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetProrationPolicy godoc
// @Summary Get proration policy by ID
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param id path string true "Proration Policy ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id} [get]
func (h *ProrationPolicyHandler) GetProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy, err := h.prorationService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toProrationPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetProrationPolicyByName godoc
// @Summary Get proration policy by name
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param name query string true "Proration Policy Name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/by-name [get]
func (h *ProrationPolicyHandler) GetProrationPolicyByName(w http.ResponseWriter, r *http.Request) {
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

	policy, err := h.prorationService.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get proration policy by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toProrationPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateProrationPolicy godoc
// @Summary Update proration policy
// @Tags proration-policies
// @Accept json
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Param request body updateProrationPolicyRequest true "Update fields"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id} [put]
func (h *ProrationPolicyHandler) UpdateProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
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

	var req updateProrationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing policy
	existing, err := h.prorationService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get proration policy for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Apply updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.UpgradeType != nil {
		upgradeType := enums.UpgradeType(*req.UpgradeType)
		if !upgradeType.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid upgrade_type")
			return
		}
		existing.UpgradeType = upgradeType
	}
	if req.DowngradeType != nil {
		downgradeType := enums.DowngradeType(*req.DowngradeType)
		if !downgradeType.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid downgrade_type")
			return
		}
		existing.DowngradeType = downgradeType
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.prorationService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toProrationPolicyResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteProrationPolicy godoc
// @Summary Soft delete proration policy
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id} [delete]
func (h *ProrationPolicyHandler) DeleteProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
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

	if err := h.prorationService.Delete(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to delete proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "proration policy deleted successfully",
	})
}

// ActivateProrationPolicy godoc
// @Summary Activate a proration policy
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/activate [post]
func (h *ProrationPolicyHandler) ActivateProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
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

	if err := h.prorationService.Activate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to activate proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "proration policy activated",
	})
}

// DeactivateProrationPolicy godoc
// @Summary Deactivate a proration policy
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/deactivate [post]
func (h *ProrationPolicyHandler) DeactivateProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
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

	if err := h.prorationService.Deactivate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to deactivate proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "proration policy deactivated",
	})
}

// RestoreProrationPolicy godoc
// @Summary Restore a soft-deleted proration policy
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/restore [post]
func (h *ProrationPolicyHandler) RestoreProrationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
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

	if err := h.prorationService.Restore(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to restore proration policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "proration policy restored",
	})
}

// UpdateProrationPolicyUpgradeType godoc
// @Summary Update upgrade type of a proration policy
// @Tags proration-policies
// @Accept json
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Param request body updateUpgradeTypeRequest true "New upgrade type"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/upgrade-type [put]
func (h *ProrationPolicyHandler) UpdateProrationPolicyUpgradeType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateUpgradeTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UpgradeType == "" {
		h.respondWithError(w, http.StatusBadRequest, "upgrade_type is required")
		return
	}
	upgradeType := enums.UpgradeType(req.UpgradeType)
	if !upgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid upgrade_type")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.prorationService.UpdateUpgradeType(ctx, companyID, policyID, upgradeType); err != nil {
		h.logger.Error("failed to update upgrade type", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Fetch updated policy to return
	policy, err := h.prorationService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "upgrade type updated",
		})
		return
	}

	resp := h.toProrationPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateProrationPolicyDowngradeType godoc
// @Summary Update downgrade type of a proration policy
// @Tags proration-policies
// @Accept json
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param Idempotency-Key header string true "Idempotency Key"
// @Param id path string true "Proration Policy ID"
// @Param request body updateDowngradeTypeRequest true "New downgrade type"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/downgrade-type [put]
func (h *ProrationPolicyHandler) UpdateProrationPolicyDowngradeType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateDowngradeTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DowngradeType == "" {
		h.respondWithError(w, http.StatusBadRequest, "downgrade_type is required")
		return
	}
	downgradeType := enums.DowngradeType(req.DowngradeType)
	if !downgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid downgrade_type")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.prorationService.UpdateDowngradeType(ctx, companyID, policyID, downgradeType); err != nil {
		h.logger.Error("failed to update downgrade type", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Fetch updated policy to return
	policy, err := h.prorationService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "downgrade type updated",
		})
		return
	}

	resp := h.toProrationPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListProrationPolicies godoc
// @Summary List proration policies with filters
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param name query string false "Filter by name"
// @Param is_active query bool false "Filter by active status"
// @Param upgrade_type query string false "Filter by upgrade type"
// @Param downgrade_type query string false "Filter by downgrade type"
// @Param limit query int false "Limit (default 20, max 100)"
// @Param offset query int false "Offset (default 0)"
// @Param sort_field query string false "Sort field (default created_at)"
// @Param sort_dir query string false "Sort direction (ASC/DESC, default DESC)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies [get]
func (h *ProrationPolicyHandler) ListProrationPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.ProrationPolicyFilter{
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
	if upgradeTypeStr := r.URL.Query().Get("upgrade_type"); upgradeTypeStr != "" {
		ut := enums.UpgradeType(upgradeTypeStr)
		if ut.IsValid() {
			filter.UpgradeType = &ut
		}
	}
	if downgradeTypeStr := r.URL.Query().Get("downgrade_type"); downgradeTypeStr != "" {
		dt := enums.DowngradeType(downgradeTypeStr)
		if dt.IsValid() {
			filter.DowngradeType = &dt
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

	policies, total, err := h.prorationService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list proration policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list proration policies")
		return
	}

	responses := make([]prorationPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toProrationPolicyResponse(p)
	}

	resp := listProrationPoliciesResponse{
		ProrationPolicies: responses,
		Total:             total,
		Limit:             limit,
		Offset:            offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchProrationPolicies godoc
// @Summary Search proration policies by query
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param q query string true "Search query"
// @Param limit query int false "Limit (default 20)"
// @Param offset query int false "Offset (default 0)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/search [get]
func (h *ProrationPolicyHandler) SearchProrationPolicies(w http.ResponseWriter, r *http.Request) {
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

	policies, total, err := h.prorationService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search proration policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search proration policies")
		return
	}

	responses := make([]prorationPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toProrationPolicyResponse(p)
	}

	resp := listProrationPoliciesResponse{
		ProrationPolicies: responses,
		Total:             total,
		Limit:             limit,
		Offset:            offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveProrationPolicies godoc
// @Summary Get all active proration policies
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/active [get]
func (h *ProrationPolicyHandler) GetActiveProrationPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.prorationService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active proration policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active proration policies")
		return
	}

	responses := make([]prorationPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toProrationPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetProrationPoliciesByUpgradeType godoc
// @Summary Get proration policies by upgrade type
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param upgrade_type path string true "Upgrade type"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/upgrade-type/{upgrade_type} [get]
func (h *ProrationPolicyHandler) GetProrationPoliciesByUpgradeType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	upgradeTypeStr := chi.URLParam(r, "upgrade_type")
	if upgradeTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "upgrade_type path parameter is required")
		return
	}
	upgradeType := enums.UpgradeType(upgradeTypeStr)
	if !upgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid upgrade_type")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.prorationService.GetByUpgradeType(ctx, companyID, upgradeType)
	if err != nil {
		h.logger.Error("failed to get proration policies by upgrade type", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get proration policies")
		return
	}

	responses := make([]prorationPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toProrationPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetProrationPoliciesByDowngradeType godoc
// @Summary Get proration policies by downgrade type
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param downgrade_type path string true "Downgrade type"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/downgrade-type/{downgrade_type} [get]
func (h *ProrationPolicyHandler) GetProrationPoliciesByDowngradeType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	downgradeTypeStr := chi.URLParam(r, "downgrade_type")
	if downgradeTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "downgrade_type path parameter is required")
		return
	}
	downgradeType := enums.DowngradeType(downgradeTypeStr)
	if !downgradeType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid downgrade_type")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.prorationService.GetByDowngradeType(ctx, companyID, downgradeType)
	if err != nil {
		h.logger.Error("failed to get proration policies by downgrade type", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get proration policies")
		return
	}

	responses := make([]prorationPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toProrationPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ProrationPolicyExists godoc
// @Summary Check if proration policy exists
// @Tags proration-policies
// @Produce json
// @Param X-Company-ID header string true "Company ID"
// @Param id path string true "Proration Policy ID"
// @Success 200 "Exists"
// @Failure 404 "Not found"
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /proration-policies/{id}/exists [head]
func (h *ProrationPolicyHandler) ProrationPolicyExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid proration policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.prorationService.Exists(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to check proration policy existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// mapServiceError maps service errors to HTTP status and message
func (h *ProrationPolicyHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "proration policy not found"
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "proration policy with this name already exists"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
