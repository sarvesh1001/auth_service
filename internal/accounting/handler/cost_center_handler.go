package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

type CostCenterHandler struct {
	svc    service.CostCenterService
	logger *zap.Logger
}

func NewCostCenterHandler(svc service.CostCenterService, logger *zap.Logger) *CostCenterHandler {
	return &CostCenterHandler{
		svc:    svc,
		logger: logger.Named("cost_center_handler"),
	}
}

// ========== REQUEST TYPES ==========

type createCostCenterRequest struct {
	Code        string     `json:"cost_center_code"`
	Name        string     `json:"cost_center_name"`
	Description *string    `json:"description,omitempty"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	AccountID   *uuid.UUID `json:"account_id,omitempty"`
	IsActive    *bool      `json:"is_active,omitempty"`
}

type updateCostCenterRequest struct {
	Code        string     `json:"cost_center_code"`
	Name        string     `json:"cost_center_name"`
	Description *string    `json:"description,omitempty"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	AccountID   *uuid.UUID `json:"account_id,omitempty"`
	IsActive    *bool      `json:"is_active,omitempty"`
}

// ========== HELPERS ==========

func (h *CostCenterHandler) withIdempotency(r *http.Request) *http.Request {
	return r
}

func (h *CostCenterHandler) getUserID(r *http.Request) (uuid.UUID, error) {
	userIDStr, ok := r.Context().Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

func (h *CostCenterHandler) hasPermission(companyID, userID uuid.UUID, permission string) bool {
	// TODO: wire real permission check (auth client)
	return true
}

// ========== CREATE ==========

func (h *CostCenterHandler) Create(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := h.getUserID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(companyID, userID, "cost_center:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createCostCenterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Code == "" || req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "cost_center_code and cost_center_name are required")
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	cc, err := h.svc.Create(r.Context(), service.CreateCostCenterRequest{
		CompanyID:   companyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
		AccountID:   req.AccountID,
		IsActive:    &isActive,
		CreatedBy:   &userID,
	})
	if err != nil {
		h.logger.Error("failed to create cost center", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    cc,
		"message": "Cost center created successfully",
	})
}

// ========== UPDATE ==========

func (h *CostCenterHandler) Update(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "costCenterID")
	costCenterID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cost center ID")
		return
	}

	userID, err := h.getUserID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(companyID, userID, "cost_center:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCostCenterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cc, err := h.svc.Update(r.Context(), service.UpdateCostCenterRequest{
		CostCenterID: costCenterID,
		CompanyID:    companyID,
		Code:         req.Code,
		Name:         req.Name,
		Description:  req.Description,
		ParentID:     req.ParentID,
		AccountID:    req.AccountID,
		IsActive:     req.IsActive,
		UpdatedBy:    &userID,
	})
	if err != nil {
		h.logger.Error("failed to update cost center", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    cc,
		"message": "Cost center updated successfully",
	})
}

// ========== DEACTIVATE ==========

func (h *CostCenterHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "costCenterID")
	costCenterID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cost center ID")
		return
	}

	userID, err := h.getUserID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(companyID, userID, "cost_center:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.svc.Deactivate(r.Context(), companyID, costCenterID, &userID); err != nil {
		h.logger.Error("failed to deactivate cost center", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Cost center deactivated successfully",
	})
}

// ========== GET BY ID ==========

func (h *CostCenterHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "costCenterID")
	costCenterID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cost center ID")
		return
	}

	userID, err := h.getUserID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(companyID, userID, "cost_center:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	cc, err := h.svc.GetByID(r.Context(), companyID, costCenterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    cc,
	})
}

// ========== LIST ==========

func (h *CostCenterHandler) List(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := h.getUserID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(companyID, userID, "cost_center:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	includeInactive := query.Get("include_inactive") == "true"
	withTree := query.Get("tree") == "true"

	if withTree {
		nodes, err := h.svc.GetTree(r.Context(), companyID, includeInactive)
		if err != nil {
			h.logger.Error("failed to build cost center tree", zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve cost center tree")
			return
		}
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nodes,
		})
		return
	}

	limit := 100
	if lStr := query.Get("limit"); lStr != "" {
		if v, err := strconv.Atoi(lStr); err == nil && v > 0 {
			limit = v
		}
	}
	offset := 0
	if oStr := query.Get("offset"); oStr != "" {
		if v, err := strconv.Atoi(oStr); err == nil && v >= 0 {
			offset = v
		}
	}

	items, total, err := h.svc.List(r.Context(), companyID, includeInactive, service.Pagination{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		h.logger.Error("failed to list cost centers", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve cost centers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ========== RESPONSE HELPERS ==========

func (h *CostCenterHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *CostCenterHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *CostCenterHandler) mapServiceError(err error) (int, string) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, repository.ErrCostCenterCodeExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, service.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, service.ErrInvalidState):
		return http.StatusConflict, err.Error()
	case errors.Is(err, service.ErrDuplicate):
		return http.StatusConflict, err.Error()
	default:
		return http.StatusBadRequest, err.Error()
	}
}
