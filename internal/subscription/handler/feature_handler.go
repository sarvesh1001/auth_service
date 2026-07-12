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

// FeatureHandler handles HTTP requests for FeatureRegistry resources.
type FeatureHandler struct {
	featureService service.FeatureService
	*BaseHandler
}

// NewFeatureHandler creates a new FeatureHandler.
func NewFeatureHandler(featureService service.FeatureService, logger *zap.Logger) *FeatureHandler {
	return &FeatureHandler{
		featureService: featureService,
		BaseHandler:    &BaseHandler{logger: logger.Named("feature_handler")},
	}
}

// ---------- Request/Response Types ----------

type createFeatureRequest struct {
	FeatureKey      string   `json:"feature_key"`
	Module          string   `json:"module"`
	FeatureGroup    *string  `json:"feature_group,omitempty"`
	PermissionScope *string  `json:"permission_scope,omitempty"`
	Description     *string  `json:"description,omitempty"`
	DefaultLimit    *string  `json:"default_limit,omitempty"` // decimal string
	DependsOn       []string `json:"depends_on,omitempty"`
}

type updateFeatureRequest struct {
	Module          *string  `json:"module,omitempty"`
	FeatureGroup    *string  `json:"feature_group,omitempty"`
	PermissionScope *string  `json:"permission_scope,omitempty"`
	Description     *string  `json:"description,omitempty"`
	DefaultLimit    *string  `json:"default_limit,omitempty"`
	DependsOn       []string `json:"depends_on,omitempty"`
	IsActive        *bool    `json:"is_active,omitempty"`
}

type updateModuleRequest struct {
	Module string `json:"module"`
}

type updateFeatureGroupRequest struct {
	FeatureGroup *string `json:"feature_group"`
}

type updatePermissionScopeRequest struct {
	PermissionScope *string `json:"permission_scope"`
}

type updateDescriptionRequest struct {
	Description *string `json:"description"`
}

type updateDefaultLimitRequest struct {
	DefaultLimit *string `json:"default_limit"`
}

type updateDependsOnRequest struct {
	DependsOn []string `json:"depends_on"`
}

type featureResponse struct {
	FeatureKey      string   `json:"feature_key"`
	Module          string   `json:"module"`
	FeatureGroup    *string  `json:"feature_group,omitempty"`
	PermissionScope *string  `json:"permission_scope,omitempty"`
	Description     *string  `json:"description,omitempty"`
	DefaultLimit    *string  `json:"default_limit,omitempty"`
	DependsOn       []string `json:"depends_on,omitempty"`
	Version         int      `json:"version"`
	IsActive        bool     `json:"is_active"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

type listFeaturesResponse struct {
	Features []featureResponse `json:"features"`
	Total    int64             `json:"total"`
	Limit    int               `json:"limit"`
	Offset   int               `json:"offset"`
}

// ---------- Conversion Helpers ----------

func (h *FeatureHandler) toFeatureResponse(feature *models.FeatureRegistry) featureResponse {
	resp := featureResponse{
		FeatureKey:      feature.FeatureKey,
		Module:          feature.Module,
		FeatureGroup:    feature.FeatureGroup,
		PermissionScope: feature.PermissionScope,
		Description:     feature.Description,
		DependsOn:       feature.DependsOn,
		Version:         feature.Version,
		IsActive:        feature.IsActive,
		CreatedAt:       feature.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       feature.UpdatedAt.Format(time.RFC3339),
	}
	if feature.DefaultLimit != nil {
		resp.DefaultLimit = new(string)
		*resp.DefaultLimit = feature.DefaultLimit.String()
	}
	return resp
}

// ---------- CRUD Handlers ----------

// CreateFeature creates a new feature.
func (h *FeatureHandler) CreateFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication & company context
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// (companyID is not stored in FeatureRegistry, but we keep it for context)
	_, err = h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createFeatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FeatureKey == "" || req.Module == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key and module are required")
		return
	}

	feature := &models.FeatureRegistry{
		FeatureKey:      req.FeatureKey,
		Module:          req.Module,
		FeatureGroup:    req.FeatureGroup,
		PermissionScope: req.PermissionScope,
		Description:     req.Description,
		DependsOn:       req.DependsOn,
	}

	if req.DefaultLimit != nil {
		limit, err := decimal.NewFromString(*req.DefaultLimit)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid default_limit")
			return
		}
		feature.DefaultLimit = &limit
	}

	// Idempotency key (using feature key)
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.featureService.Create(ctx, feature); err != nil {
		h.logger.Error("failed to create feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toFeatureResponse(feature)
	location := fmt.Sprintf("/features/%s", feature.FeatureKey)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetFeature retrieves a feature by its key.
func (h *FeatureHandler) GetFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	feature, err := h.featureService.GetByKey(ctx, companyID, featureKey)
	if err != nil {
		h.logger.Error("failed to get feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toFeatureResponse(feature)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateFeature updates a feature.
func (h *FeatureHandler) UpdateFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

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

	var req updateFeatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing feature
	existing, err := h.featureService.GetByKey(ctx, companyID, featureKey)
	if err != nil {
		h.logger.Error("failed to get feature for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Apply updates
	if req.Module != nil {
		existing.Module = *req.Module
	}
	if req.FeatureGroup != nil {
		existing.FeatureGroup = req.FeatureGroup
	}
	if req.PermissionScope != nil {
		existing.PermissionScope = req.PermissionScope
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.DefaultLimit != nil {
		if *req.DefaultLimit == "" {
			existing.DefaultLimit = nil
		} else {
			limit, err := decimal.NewFromString(*req.DefaultLimit)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid default_limit")
				return
			}
			existing.DefaultLimit = &limit
		}
	}
	if req.DependsOn != nil {
		existing.DependsOn = req.DependsOn
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.featureService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Re-fetch to get updated version/timestamps
	updated, err := h.featureService.GetByKey(ctx, companyID, featureKey)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "feature updated",
		})
		return
	}
	resp := h.toFeatureResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteFeature deletes a feature.
func (h *FeatureHandler) DeleteFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
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

	if err := h.featureService.Delete(ctx, companyID, featureKey); err != nil {
		h.logger.Error("failed to delete feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "feature deleted successfully",
	})
}

// ActivateFeature activates a feature.
func (h *FeatureHandler) ActivateFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
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

	if err := h.featureService.Activate(ctx, companyID, featureKey); err != nil {
		h.logger.Error("failed to activate feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "feature activated",
	})
}

// DeactivateFeature deactivates a feature.
func (h *FeatureHandler) DeactivateFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
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

	if err := h.featureService.Deactivate(ctx, companyID, featureKey); err != nil {
		h.logger.Error("failed to deactivate feature", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "feature deactivated",
	})
}

// ---------- Field-specific Update Handlers ----------

// UpdateFeatureModule updates only the module.
func (h *FeatureHandler) UpdateFeatureModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateModuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Module == "" {
		h.respondWithError(w, http.StatusBadRequest, "module is required")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.featureService.UpdateModule(ctx, companyID, featureKey, req.Module); err != nil {
		h.logger.Error("failed to update module", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "module updated",
	})
}

// UpdateFeatureFeatureGroup updates only the feature group.
func (h *FeatureHandler) UpdateFeatureFeatureGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateFeatureGroupRequest
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

	if err := h.featureService.UpdateFeatureGroup(ctx, companyID, featureKey, req.FeatureGroup); err != nil {
		h.logger.Error("failed to update feature group", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "feature group updated",
	})
}

// UpdateFeaturePermissionScope updates the permission scope.
func (h *FeatureHandler) UpdateFeaturePermissionScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updatePermissionScopeRequest
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

	if err := h.featureService.UpdatePermissionScope(ctx, companyID, featureKey, req.PermissionScope); err != nil {
		h.logger.Error("failed to update permission scope", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "permission scope updated",
	})
}

// UpdateFeatureDescription updates the description.
func (h *FeatureHandler) UpdateFeatureDescription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateDescriptionRequest
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

	if err := h.featureService.UpdateDescription(ctx, companyID, featureKey, req.Description); err != nil {
		h.logger.Error("failed to update description", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "description updated",
	})
}

// UpdateFeatureDefaultLimit updates the default limit.
func (h *FeatureHandler) UpdateFeatureDefaultLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateDefaultLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var limit *decimal.Decimal
	if req.DefaultLimit != nil {
		if *req.DefaultLimit == "" {
			limit = nil
		} else {
			d, err := decimal.NewFromString(*req.DefaultLimit)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid default_limit")
				return
			}
			limit = &d
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.featureService.UpdateDefaultLimit(ctx, companyID, featureKey, limit); err != nil {
		h.logger.Error("failed to update default limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "default limit updated",
	})
}

// UpdateFeatureDependsOn updates the dependencies.
func (h *FeatureHandler) UpdateFeatureDependsOn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateDependsOnRequest
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

	if err := h.featureService.UpdateDependsOn(ctx, companyID, featureKey, req.DependsOn); err != nil {
		h.logger.Error("failed to update depends_on", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "depends_on updated",
	})
}

// ---------- Query/List Handlers ----------

// ListFeatures lists features with filtering, pagination, and sorting.
func (h *FeatureHandler) ListFeatures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// CompanyID is not needed for FeatureFilter, but we keep it for potential auth/logging.
	_, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.FeatureFilter{} // no CompanyID field

	if module := r.URL.Query().Get("module"); module != "" {
		filter.Module = &module
	}
	if featureGroup := r.URL.Query().Get("feature_group"); featureGroup != "" {
		filter.FeatureGroup = &featureGroup
	}
	if permissionScope := r.URL.Query().Get("permission_scope"); permissionScope != "" {
		filter.PermissionScope = &permissionScope
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive
		}
	}
	// FeatureKey is not a filter field; use GetFeature for single lookup.

	limit, offset := h.parsePagination(r)
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_dir")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	features, total, err := h.featureService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list features", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}

	resp := listFeaturesResponse{
		Features: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchFeatures performs a full-text search.
func (h *FeatureHandler) SearchFeatures(w http.ResponseWriter, r *http.Request) {
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

	features, total, err := h.featureService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search features", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}

	resp := listFeaturesResponse{
		Features: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveFeatures returns all active features.
func (h *FeatureHandler) GetActiveFeatures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	features, err := h.featureService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active features", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetFeaturesByModule returns features for a given module.
func (h *FeatureHandler) GetFeaturesByModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	module := r.URL.Query().Get("module")
	if module == "" {
		h.respondWithError(w, http.StatusBadRequest, "module query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	features, err := h.featureService.GetByModule(ctx, companyID, module)
	if err != nil {
		h.logger.Error("failed to get features by module", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetFeaturesByFeatureGroup returns features for a given feature group.
func (h *FeatureHandler) GetFeaturesByFeatureGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureGroup := r.URL.Query().Get("feature_group")
	if featureGroup == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_group query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	features, err := h.featureService.GetByFeatureGroup(ctx, companyID, featureGroup)
	if err != nil {
		h.logger.Error("failed to get features by feature group", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetFeaturesByPermissionScope returns features for a given permission scope.
func (h *FeatureHandler) GetFeaturesByPermissionScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	permissionScope := r.URL.Query().Get("permission_scope")
	if permissionScope == "" {
		h.respondWithError(w, http.StatusBadRequest, "permission_scope query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	features, err := h.featureService.GetByPermissionScope(ctx, companyID, permissionScope)
	if err != nil {
		h.logger.Error("failed to get features by permission scope", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get features")
		return
	}

	responses := make([]featureResponse, len(features))
	for i, f := range features {
		responses[i] = h.toFeatureResponse(f)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ---------- Utility: Existence Check ----------

// FeatureExists checks if a feature exists (returns 200 or 404).
func (h *FeatureHandler) FeatureExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	featureKey := r.URL.Query().Get("feature_key")
	if featureKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "feature_key query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.featureService.Exists(ctx, companyID, featureKey)
	if err != nil {
		h.logger.Error("failed to check feature existence", zap.Error(err))
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

func (h *FeatureHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "feature not found"
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "feature key already exists"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
