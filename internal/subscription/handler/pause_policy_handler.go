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

// PausePolicyHandler handles HTTP requests for pause policies.
type PausePolicyHandler struct {
	pauseService service.PausePolicyService
	*BaseHandler
}

// NewPausePolicyHandler creates a new PausePolicyHandler.
func NewPausePolicyHandler(pauseService service.PausePolicyService, logger *zap.Logger) *PausePolicyHandler {
	return &PausePolicyHandler{
		pauseService: pauseService,
		BaseHandler:  &BaseHandler{logger: logger.Named("pause_policy_handler")},
	}
}

// Request/Response types

type createPausePolicyRequest struct {
	Name           string   `json:"name"`
	MaxPauseDays   int      `json:"max_pause_days"`
	AllowedReasons []string `json:"allowed_reasons,omitempty"`
	FreezeDays     int      `json:"freeze_days"`
}

type updatePausePolicyRequest struct {
	Name           *string  `json:"name,omitempty"`
	MaxPauseDays   *int     `json:"max_pause_days,omitempty"`
	AllowedReasons []string `json:"allowed_reasons,omitempty"`
	FreezeDays     *int     `json:"freeze_days,omitempty"`
}

type updateMaxPauseDaysRequest struct {
	MaxPauseDays int `json:"max_pause_days"`
}

type updateFreezeDaysRequest struct {
	FreezeDays int `json:"freeze_days"`
}

type addAllowedReasonRequest struct {
	Reason string `json:"reason"`
}

type removeAllowedReasonRequest struct {
	Reason string `json:"reason"`
}

type pausePolicyResponse struct {
	PausePolicyID  string   `json:"pause_policy_id"`
	CompanyID      string   `json:"company_id"`
	Name           string   `json:"name"`
	MaxPauseDays   int      `json:"max_pause_days"`
	AllowedReasons []string `json:"allowed_reasons,omitempty"`
	FreezeDays     int      `json:"freeze_days"`
	IsActive       bool     `json:"is_active"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	DeletedAt      *string  `json:"deleted_at,omitempty"`
}

type listPausePoliciesResponse struct {
	Policies []pausePolicyResponse `json:"policies"`
	Total    int64                 `json:"total"`
	Limit    int                   `json:"limit"`
	Offset   int                   `json:"offset"`
}

// toPausePolicyResponse converts a models.PausePolicy to the response format.
func (h *PausePolicyHandler) toPausePolicyResponse(policy *models.PausePolicy) pausePolicyResponse {
	resp := pausePolicyResponse{
		PausePolicyID:  policy.PausePolicyID.String(),
		CompanyID:      policy.CompanyID.String(),
		Name:           policy.Name,
		MaxPauseDays:   policy.MaxPauseDays,
		AllowedReasons: policy.AllowedReasons,
		FreezeDays:     policy.FreezeDays,
		IsActive:       policy.IsActive,
		CreatedAt:      policy.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      policy.UpdatedAt.Format(time.RFC3339),
	}
	if policy.DeletedAt != nil {
		deleted := policy.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &deleted
	}
	return resp
}

// mapServiceError maps service errors to HTTP status codes and messages.
func (h *PausePolicyHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrPausePolicyNotFound):
		return http.StatusNotFound, "pause policy not found"
	case errors.Is(err, subErrors.ErrPausePolicyAlreadyExists):
		return http.StatusConflict, "pause policy with this name already exists"
	case errors.Is(err, subErrors.ErrPausePolicyInUse):
		return http.StatusConflict, "pause policy is in use by one or more plans"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "duplicate record"
	case errors.Is(err, subErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, subErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	default:
		// Fallback to base handler mapping
		return h.BaseHandler.mapServiceError(err)
	}
}

// --- Handlers ---

// CreatePausePolicy handles POST /pause-policies
func (h *PausePolicyHandler) CreatePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authenticate user
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Get company from header
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createPausePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.MaxPauseDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "max_pause_days must be >= 0")
		return
	}
	if req.FreezeDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "freeze_days must be >= 0")
		return
	}

	policy := &models.PausePolicy{
		CompanyID:      companyID,
		Name:           req.Name,
		MaxPauseDays:   req.MaxPauseDays,
		AllowedReasons: req.AllowedReasons,
		FreezeDays:     req.FreezeDays,
		IsActive:       true, // will be set by service, but we'll set anyway
	}

	// Idempotency key
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.Create(ctx, policy); err != nil {
		h.logger.Error("failed to create pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPausePolicyResponse(policy)
	location := fmt.Sprintf("/pause-policies/%s", policy.PausePolicyID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPausePolicy handles GET /pause-policies/{id}
func (h *PausePolicyHandler) GetPausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPausePolicyByName handles GET /pause-policies?name=...
func (h *PausePolicyHandler) GetPausePolicyByName(w http.ResponseWriter, r *http.Request) {
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

	policy, err := h.pauseService.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get pause policy by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePausePolicy handles PUT /pause-policies/{id}
func (h *PausePolicyHandler) UpdatePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
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

	var req updatePausePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing policy to update
	existing, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to get pause policy for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.MaxPauseDays != nil {
		if *req.MaxPauseDays < 0 {
			h.respondWithError(w, http.StatusBadRequest, "max_pause_days must be >= 0")
			return
		}
		existing.MaxPauseDays = *req.MaxPauseDays
	}
	if req.FreezeDays != nil {
		if *req.FreezeDays < 0 {
			h.respondWithError(w, http.StatusBadRequest, "freeze_days must be >= 0")
			return
		}
		existing.FreezeDays = *req.FreezeDays
	}
	if req.AllowedReasons != nil {
		existing.AllowedReasons = req.AllowedReasons
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toPausePolicyResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePausePolicy handles DELETE /pause-policies/{id}
func (h *PausePolicyHandler) DeletePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
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

	if err := h.pauseService.Delete(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to delete pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "pause policy deleted successfully",
	})
}

// ActivatePausePolicy handles PATCH /pause-policies/{id}/activate
func (h *PausePolicyHandler) ActivatePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
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

	if err := h.pauseService.Activate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to activate pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "pause policy activated",
	})
}

// DeactivatePausePolicy handles PATCH /pause-policies/{id}/deactivate
func (h *PausePolicyHandler) DeactivatePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
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

	if err := h.pauseService.Deactivate(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to deactivate pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "pause policy deactivated",
	})
}

// RestorePausePolicy handles PATCH /pause-policies/{id}/restore
func (h *PausePolicyHandler) RestorePausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
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

	if err := h.pauseService.Restore(ctx, companyID, policyID); err != nil {
		h.logger.Error("failed to restore pause policy", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "pause policy restored",
	})
}

// UpdateMaxPauseDays handles PATCH /pause-policies/{id}/max-pause-days
func (h *PausePolicyHandler) UpdateMaxPauseDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateMaxPauseDaysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.MaxPauseDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "max_pause_days must be >= 0")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.UpdateMaxPauseDays(ctx, companyID, policyID, req.MaxPauseDays); err != nil {
		h.logger.Error("failed to update max pause days", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Fetch updated policy to return
	policy, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "max pause days updated",
		})
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateFreezeDays handles PATCH /pause-policies/{id}/freeze-days
func (h *PausePolicyHandler) UpdateFreezeDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateFreezeDaysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FreezeDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "freeze_days must be >= 0")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.UpdateFreezeDays(ctx, companyID, policyID, req.FreezeDays); err != nil {
		h.logger.Error("failed to update freeze days", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "freeze days updated",
		})
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// AddAllowedReason handles POST /pause-policies/{id}/allowed-reasons
func (h *PausePolicyHandler) AddAllowedReason(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req addAllowedReasonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.AddAllowedReason(ctx, companyID, policyID, req.Reason); err != nil {
		h.logger.Error("failed to add allowed reason", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "allowed reason added",
		})
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RemoveAllowedReason handles DELETE /pause-policies/{id}/allowed-reasons
func (h *PausePolicyHandler) RemoveAllowedReason(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req removeAllowedReasonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.pauseService.RemoveAllowedReason(ctx, companyID, policyID, req.Reason); err != nil {
		h.logger.Error("failed to remove allowed reason", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	policy, err := h.pauseService.GetByID(ctx, companyID, policyID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "allowed reason removed",
		})
		return
	}

	resp := h.toPausePolicyResponse(policy)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListPausePolicies handles GET /pause-policies
func (h *PausePolicyHandler) ListPausePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.PausePolicyFilter{
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
	if maxDaysStr := r.URL.Query().Get("max_pause_days"); maxDaysStr != "" {
		if maxDays, err := strconv.Atoi(maxDaysStr); err == nil {
			filter.MaxPauseDays = &maxDays
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

	policies, total, err := h.pauseService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list pause policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list pause policies")
		return
	}

	responses := make([]pausePolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toPausePolicyResponse(p)
	}

	resp := listPausePoliciesResponse{
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

// SearchPausePolicies handles GET /pause-policies/search?q=...
func (h *PausePolicyHandler) SearchPausePolicies(w http.ResponseWriter, r *http.Request) {
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
	policies, total, err := h.pauseService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search pause policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search pause policies")
		return
	}

	responses := make([]pausePolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toPausePolicyResponse(p)
	}

	resp := listPausePoliciesResponse{
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

// GetActivePausePolicies handles GET /pause-policies/active
func (h *PausePolicyHandler) GetActivePausePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.pauseService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active pause policies", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active pause policies")
		return
	}

	responses := make([]pausePolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toPausePolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetPausePoliciesByMaxDays handles GET /pause-policies?max_pause_days=...
// This could be a separate endpoint or we can use list with filter. We'll implement it as a dedicated endpoint for clarity.
func (h *PausePolicyHandler) GetPausePoliciesByMaxDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	maxDaysStr := r.URL.Query().Get("max_pause_days")
	if maxDaysStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "max_pause_days query parameter is required")
		return
	}
	maxDays, err := strconv.Atoi(maxDaysStr)
	if err != nil || maxDays < 0 {
		h.respondWithError(w, http.StatusBadRequest, "invalid max_pause_days")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.pauseService.GetByMaxPauseDays(ctx, companyID, maxDays)
	if err != nil {
		h.logger.Error("failed to get pause policies by max days", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get pause policies")
		return
	}

	responses := make([]pausePolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toPausePolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetPausePoliciesByAllowedReason handles GET /pause-policies?allowed_reason=...
func (h *PausePolicyHandler) GetPausePoliciesByAllowedReason(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	reason := r.URL.Query().Get("allowed_reason")
	if reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "allowed_reason query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.pauseService.GetByAllowedReason(ctx, companyID, reason)
	if err != nil {
		h.logger.Error("failed to get pause policies by allowed reason", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get pause policies")
		return
	}

	responses := make([]pausePolicyResponse, len(policies))
	for i, p := range policies {
		responses[i] = h.toPausePolicyResponse(p)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ExistsPausePolicy handles HEAD /pause-policies/{id} (optional)
func (h *PausePolicyHandler) ExistsPausePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid pause policy ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.pauseService.Exists(ctx, companyID, policyID)
	if err != nil {
		h.logger.Error("failed to check pause policy existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}
