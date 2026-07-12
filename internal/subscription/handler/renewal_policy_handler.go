package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

type RenewalPolicyHandler struct {
	renewalPolicyService service.RenewalPolicyService
	*BaseHandler
}

func NewRenewalPolicyHandler(renewalPolicyService service.RenewalPolicyService, logger *zap.Logger) *RenewalPolicyHandler {
	return &RenewalPolicyHandler{
		renewalPolicyService: renewalPolicyService,
		BaseHandler:          &BaseHandler{logger: logger.Named("renewal_policy_handler")},
	}
}

// Request/Response types
type createRenewalPolicyRequest struct {
	Name           string `json:"name"`
	AutoRenew      bool   `json:"auto_renew"`
	GraceDays      int    `json:"grace_days"`
	LateFeePercent string `json:"late_fee_percent"`
	NoticeDays     int    `json:"notice_days"`
}

type updateRenewalPolicyRequest struct {
	Name           *string `json:"name,omitempty"`
	AutoRenew      *bool   `json:"auto_renew,omitempty"`
	GraceDays      *int    `json:"grace_days,omitempty"`
	LateFeePercent *string `json:"late_fee_percent,omitempty"`
	NoticeDays     *int    `json:"notice_days,omitempty"`
}

type updateAutoRenewRequest struct {
	AutoRenew bool `json:"auto_renew"`
}

type updateGracePeriodRequest struct {
	GraceDays int `json:"grace_days"`
}

type updateLateFeeRequest struct {
	LateFeePercent string `json:"late_fee_percent"`
}

type updateNoticePeriodRequest struct {
	NoticeDays int `json:"notice_days"`
}

type renewalPolicyResponse struct {
	RenewalPolicyID string  `json:"renewal_policy_id"`
	CompanyID       string  `json:"company_id"`
	Name            string  `json:"name"`
	AutoRenew       bool    `json:"auto_renew"`
	GraceDays       int     `json:"grace_days"`
	LateFeePercent  string  `json:"late_fee_percent"`
	NoticeDays      int     `json:"notice_days"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	DeletedAt       *string `json:"deleted_at,omitempty"`
}

type listRenewalPoliciesResponse struct {
	RenewalPolicies []renewalPolicyResponse `json:"renewal_policies"`
	Total           int64                   `json:"total"`
	Limit           int                     `json:"limit"`
	Offset          int                     `json:"offset"`
}

// Helper to convert model to response
func (h *RenewalPolicyHandler) toRenewalPolicyResponse(policy *models.RenewalPolicy) renewalPolicyResponse {
	// Defensive: if policy is nil, return empty struct (should never happen if service returns error)
	if policy == nil {
		return renewalPolicyResponse{}
	}
	resp := renewalPolicyResponse{
		RenewalPolicyID: policy.RenewalPolicyID.String(),
		CompanyID:       policy.CompanyID.String(),
		Name:            policy.Name,
		AutoRenew:       policy.AutoRenew,
		GraceDays:       policy.GraceDays,
		LateFeePercent:  policy.LateFeePercent.String(),
		NoticeDays:      policy.NoticeDays,
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

// ---- CRUD ----

// CreateRenewalPolicy creates a new renewal policy.
func (h *RenewalPolicyHandler) CreateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
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

	var req createRenewalPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.GraceDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "grace_days must be >= 0")
		return
	}
	if req.NoticeDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "notice_days must be >= 0")
		return
	}

	lateFee, err := decimal.NewFromString(req.LateFeePercent)
	if err != nil || lateFee.Sign() < 0 || lateFee.GreaterThanOrEqual(decimal.NewFromInt(100)) {
		h.respondWithError(w, http.StatusBadRequest, "invalid late_fee_percent (must be 0-99.99)")
		return
	}

	policy := &models.RenewalPolicy{
		CompanyID:      companyID,
		Name:           req.Name,
		AutoRenew:      req.AutoRenew,
		GraceDays:      req.GraceDays,
		LateFeePercent: lateFee,
		NoticeDays:     req.NoticeDays,
		IsActive:       true,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.Create(ctx, policy); err != nil {
		h.logger.Error("failed to create renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRenewalPolicyResponse(policy)
	location := fmt.Sprintf("/renewal-policies/%s", policy.RenewalPolicyID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetRenewalPolicy retrieves a renewal policy by ID.
func (h *RenewalPolicyHandler) GetRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	// Defensive nil check (service should return ErrNotFound, but guard anyway)
	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "renewal policy not found")
		return
	}

	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetRenewalPolicyByName retrieves a renewal policy by name.
func (h *RenewalPolicyHandler) GetRenewalPolicyByName(w http.ResponseWriter, r *http.Request) {
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

	policy, err := h.renewalPolicyService.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get renewal policy by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "renewal policy not found")
		return
	}

	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateRenewalPolicy updates an existing renewal policy.
func (h *RenewalPolicyHandler) UpdateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
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

	var req updateRenewalPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get renewal policy for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "renewal policy not found")
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.AutoRenew != nil {
		existing.AutoRenew = *req.AutoRenew
	}
	if req.GraceDays != nil {
		if *req.GraceDays < 0 {
			h.respondWithError(w, http.StatusBadRequest, "grace_days must be >= 0")
			return
		}
		existing.GraceDays = *req.GraceDays
	}
	if req.LateFeePercent != nil {
		lateFee, err := decimal.NewFromString(*req.LateFeePercent)
		if err != nil || lateFee.Sign() < 0 || lateFee.GreaterThanOrEqual(decimal.NewFromInt(100)) {
			h.respondWithError(w, http.StatusBadRequest, "invalid late_fee_percent")
			return
		}
		existing.LateFeePercent = lateFee
	}
	if req.NoticeDays != nil {
		if *req.NoticeDays < 0 {
			h.respondWithError(w, http.StatusBadRequest, "notice_days must be >= 0")
			return
		}
		existing.NoticeDays = *req.NoticeDays
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toRenewalPolicyResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteRenewalPolicy soft-deletes a renewal policy.
func (h *RenewalPolicyHandler) DeleteRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
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

	if err := h.renewalPolicyService.Delete(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to delete renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "renewal policy deleted successfully",
	})
}

// ---- Status management ----

// ActivateRenewalPolicy activates a renewal policy.
func (h *RenewalPolicyHandler) ActivateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
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

	if err := h.renewalPolicyService.Activate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to activate renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "renewal policy activated",
	})
}

// DeactivateRenewalPolicy deactivates a renewal policy.
func (h *RenewalPolicyHandler) DeactivateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
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

	if err := h.renewalPolicyService.Deactivate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to deactivate renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "renewal policy deactivated",
	})
}

// RestoreRenewalPolicy restores a soft-deleted renewal policy.
func (h *RenewalPolicyHandler) RestoreRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
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

	if err := h.renewalPolicyService.Restore(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to restore renewal policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "renewal policy restored",
	})
}

// ---- Specific updates ----

// UpdateAutoRenew updates the auto-renew flag.
func (h *RenewalPolicyHandler) UpdateAutoRenew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateAutoRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.UpdateAutoRenew(ctx, companyID, policyID, req.AutoRenew); err != nil {
		h.logger.Error("failed to update auto-renew", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil || policy == nil {
		// If we can't fetch the updated policy, still return a success message.
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "auto-renew updated",
		})
		return
	}
	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateGracePeriod updates the grace period.
func (h *RenewalPolicyHandler) UpdateGracePeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateGracePeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.GraceDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "grace_days must be >= 0")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.UpdateGracePeriod(ctx, companyID, policyID, req.GraceDays); err != nil {
		h.logger.Error("failed to update grace period", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil || policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "grace period updated",
		})
		return
	}
	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateLateFee updates the late fee percentage.
func (h *RenewalPolicyHandler) UpdateLateFee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateLateFeeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	lateFee, err := decimal.NewFromString(req.LateFeePercent)
	if err != nil || lateFee.Sign() < 0 || lateFee.GreaterThanOrEqual(decimal.NewFromInt(100)) {
		h.respondWithError(w, http.StatusBadRequest, "invalid late_fee_percent")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.UpdateLateFee(ctx, companyID, policyID, lateFee.InexactFloat64()); err != nil {
		h.logger.Error("failed to update late fee", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil || policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "late fee updated",
		})
		return
	}
	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateNoticePeriod updates the notice period.
func (h *RenewalPolicyHandler) UpdateNoticePeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateNoticePeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NoticeDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "notice_days must be >= 0")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.renewalPolicyService.UpdateNoticePeriod(ctx, companyID, policyID, req.NoticeDays); err != nil {
		h.logger.Error("failed to update notice period", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.renewalPolicyService.GetByID(ctx, companyID, policyID)
	if err != nil || policy == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "notice period updated",
		})
		return
	}
	resp := h.toRenewalPolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---- List / Search / Filter ----

// ListRenewalPolicies lists renewal policies with filters and pagination.
func (h *RenewalPolicyHandler) ListRenewalPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.RenewalPolicyFilter{
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
	if autoRenewStr := r.URL.Query().Get("auto_renew"); autoRenewStr != "" {
		autoRenew, err := strconv.ParseBool(autoRenewStr)
		if err == nil {
			filter.AutoRenew = &autoRenew
		}
	}

	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")
	if sortField == "" {
		sortField = "created_at"
	}
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := service.Sort{Field: sortField, Direction: sortDir}

	policies, total, err := h.renewalPolicyService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list renewal policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list renewal policies")
		return
	}

	responses := make([]renewalPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toRenewalPolicyResponse(p)
	}

	resp := listRenewalPoliciesResponse{
		RenewalPolicies: responses,
		Total:           total,
		Limit:           limit,
		Offset:          offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchRenewalPolicies performs a full-text search on renewal policies.
func (h *RenewalPolicyHandler) SearchRenewalPolicies(w http.ResponseWriter, r *http.Request) {
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
	policies, total, err := h.renewalPolicyService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search renewal policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search renewal policies")
		return
	}

	responses := make([]renewalPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toRenewalPolicyResponse(p)
	}

	resp := listRenewalPoliciesResponse{
		RenewalPolicies: responses,
		Total:           total,
		Limit:           limit,
		Offset:          offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveRenewalPolicies returns all active renewal policies.
func (h *RenewalPolicyHandler) GetActiveRenewalPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.renewalPolicyService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active renewal policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active renewal policies")
		return
	}

	responses := make([]renewalPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toRenewalPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetAutoRenewPolicies returns policies that allow auto-renewal.
func (h *RenewalPolicyHandler) GetAutoRenewPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.renewalPolicyService.GetAutoRenewPolicies(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get auto-renew policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get auto-renew policies")
		return
	}

	responses := make([]renewalPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toRenewalPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetManualRenewPolicies returns policies that require manual renewal.
func (h *RenewalPolicyHandler) GetManualRenewPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.renewalPolicyService.GetManualRenewPolicies(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get manual-renew policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get manual-renew policies")
		return
	}

	responses := make([]renewalPolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toRenewalPolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// RenewalPolicyExists checks if a renewal policy exists (returns 200 if found, 404 otherwise).
func (h *RenewalPolicyHandler) RenewalPolicyExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewal policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.renewalPolicyService.Exists(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to check renewal policy existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- Error mapping ----

func (h *RenewalPolicyHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "renewal policy not found"
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "renewal policy with this name already exists"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrConflict):
		return http.StatusConflict, "cannot delete renewal policy because it is in use by one or more plans"
	case errors.Is(err, subErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, subErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
