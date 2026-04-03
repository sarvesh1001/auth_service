package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

type GradingHandler struct {
	gradingService service.GradingService
	logger         *zap.Logger
}

func NewGradingHandler(gradingService service.GradingService, logger *zap.Logger) *GradingHandler {
	return &GradingHandler{
		gradingService: gradingService,
		logger:         logger.Named("grading_handler"),
	}
}

// ----------------------------------------------------------------------
// Grading Policy endpoints
// ----------------------------------------------------------------------

// CreateGradingPolicy handles POST /api/v1/companies/{companyID}/grading-policies
func (h *GradingHandler) CreateGradingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateGradingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.PolicyName == "" {
		h.respondWithError(w, http.StatusBadRequest, "policy_name is required")
		return
	}
	if req.GradingScale == "" {
		h.respondWithError(w, http.StatusBadRequest, "grading_scale is required")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	policy, err := h.gradingService.CreateGradingPolicy(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create grading policy",
			zap.String("company_id", companyID.String()),
			zap.String("policy_name", req.PolicyName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    policy,
		"message": "Grading policy created successfully",
	})
}

// GetGradingPolicy handles GET /api/v1/companies/{companyID}/grading-policies/{policyID}
func (h *GradingHandler) GetGradingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	policy, err := h.gradingService.GetGradingPolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get grading policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}

// GetDefaultGradingPolicy handles GET /api/v1/companies/{companyID}/grading-policies/default
func (h *GradingHandler) GetDefaultGradingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	policy, err := h.gradingService.GetDefaultGradingPolicy(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get default grading policy",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}

// ListGradingPolicies handles GET /api/v1/companies/{companyID}/grading-policies
func (h *GradingHandler) ListGradingPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.GradingPolicyFilter{
		CompanyID: companyID,
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search // Search is string, not pointer
	}
	if scale := r.URL.Query().Get("grading_scale"); scale != "" {
		filter.GradingScale = &scale // GradingScale is *string
	}
	if isDefaultStr := r.URL.Query().Get("is_default"); isDefaultStr != "" {
		isDefault, _ := strconv.ParseBool(isDefaultStr)
		filter.IsDefault = &isDefault // IsDefault is *bool
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	policies, err := h.gradingService.ListGradingPolicies(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list grading policies",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list grading policies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"policies": policies,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// UpdateGradingPolicy handles PUT /api/v1/companies/{companyID}/grading-policies/{policyID}
func (h *GradingHandler) UpdateGradingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateGradingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.PolicyID = policyID
	req.UpdatedBy = &userID

	policy, err := h.gradingService.UpdateGradingPolicy(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update grading policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
		"message": "Grading policy updated successfully",
	})
}

// DeleteGradingPolicy handles DELETE /api/v1/companies/{companyID}/grading-policies/{policyID}
func (h *GradingHandler) DeleteGradingPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:policy:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.gradingService.DeleteGradingPolicy(ctx, policyID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete grading policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Grading policy deleted successfully",
	})
}

// ----------------------------------------------------------------------
// Grade Boundary endpoints
// ----------------------------------------------------------------------

// CreateGradeBoundary handles POST /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries
func (h *GradingHandler) CreateGradeBoundary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateGradeBoundaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.PolicyID = policyID

	boundary, err := h.gradingService.CreateGradeBoundary(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create grade boundary",
			zap.String("policy_id", policyID.String()),
			zap.String("grade", req.Grade),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    boundary,
		"message": "Grade boundary created successfully",
	})
}

// BulkCreateGradeBoundaries handles POST /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries/bulk
func (h *GradingHandler) BulkCreateGradeBoundaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateGradeBoundaryRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Ensure all boundaries belong to the same policy
	for i := range reqs {
		reqs[i].PolicyID = policyID
	}

	boundaries, err := h.gradingService.BulkCreateGradeBoundaries(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create grade boundaries",
			zap.String("policy_id", policyID.String()),
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    boundaries,
		"message": "Grade boundaries created successfully",
	})
}

// GetGradeBoundary handles GET /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries/{boundaryID}
func (h *GradingHandler) GetGradeBoundary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	boundaryID, err := h.parseBoundaryID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	boundary, err := h.gradingService.GetGradeBoundaryByID(ctx, boundaryID)
	if err != nil {
		h.logger.Error("Failed to get grade boundary",
			zap.String("boundary_id", boundaryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    boundary,
	})
}

// ListGradeBoundaries handles GET /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries
func (h *GradingHandler) ListGradeBoundaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.GradeBoundaryFilter{
		PolicyID: policyID,
	}
	// Note: Grade field is not present in the current filter struct; remove or adapt as needed.
	// If Grade filtering is required, ensure the repository filter includes it.
	// For now, we skip the grade filter to avoid compilation error.

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "min_percentage"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	boundaries, err := h.gradingService.ListGradeBoundaries(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list grade boundaries",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list grade boundaries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"boundaries": boundaries,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// UpdateGradeBoundary handles PUT /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries/{boundaryID}
func (h *GradingHandler) UpdateGradeBoundary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	boundaryID, err := h.parseBoundaryID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateGradeBoundaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.BoundaryID = boundaryID

	boundary, err := h.gradingService.UpdateGradeBoundary(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update grade boundary",
			zap.String("boundary_id", boundaryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    boundary,
		"message": "Grade boundary updated successfully",
	})
}

// DeleteGradeBoundary handles DELETE /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries/{boundaryID}
func (h *GradingHandler) DeleteGradeBoundary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	boundaryID, err := h.parseBoundaryID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.gradingService.DeleteGradeBoundary(ctx, boundaryID)
	if err != nil {
		h.logger.Error("Failed to delete grade boundary",
			zap.String("boundary_id", boundaryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Grade boundary deleted successfully",
	})
}

// DeleteAllGradeBoundaries handles DELETE /api/v1/companies/{companyID}/grading-policies/{policyID}/boundaries
func (h *GradingHandler) DeleteAllGradeBoundaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	policyID, err := h.parsePolicyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "grading:boundary:delete_all") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.gradingService.DeleteGradeBoundariesByPolicy(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to delete all grade boundaries",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All grade boundaries deleted successfully",
	})
}

// ----------------------------------------------------------------------
// Helper methods
// ----------------------------------------------------------------------

func (h *GradingHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		return uuid.Nil, errInvalidCompanyID
	}
	return companyID, nil
}

func (h *GradingHandler) parsePolicyID(r *http.Request) (uuid.UUID, error) {
	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		return uuid.Nil, errInvalidPolicyID
	}
	return policyID, nil
}

func (h *GradingHandler) parseBoundaryID(r *http.Request) (uuid.UUID, error) {
	boundaryIDStr := chi.URLParam(r, "boundaryID")
	boundaryID, err := uuid.Parse(boundaryIDStr)
	if err != nil {
		return uuid.Nil, errInvalidBoundaryID
	}
	return boundaryID, nil
}

func (h *GradingHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *GradingHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *GradingHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// Error definitions
var (
	errInvalidCompanyID  = &handlerError{msg: "invalid company ID"}
	errInvalidPolicyID   = &handlerError{msg: "invalid grading policy ID"}
	errInvalidBoundaryID = &handlerError{msg: "invalid grade boundary ID"}
)

type handlerError struct {
	msg string
}

func (e *handlerError) Error() string {
	return e.msg
}
