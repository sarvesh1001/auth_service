// internal/attendance/handler/work_center_handler.go

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/workcenter"
	"auth-service/internal/infrastructure/audit"
)

// WorkCenterHandler handles HTTP requests for work center management.
type WorkCenterHandler struct {
	workCenterService      workcenter.Service
	workCenterQueryService workcenter.QueryService
	auditService           *audit.AuditService
	logger                 *zap.Logger
}

// NewWorkCenterHandler creates a new handler.
func NewWorkCenterHandler(
	workCenterService workcenter.Service,
	workCenterQueryService workcenter.QueryService,
	auditService *audit.AuditService,
	logger *zap.Logger,
) *WorkCenterHandler {
	return &WorkCenterHandler{
		workCenterService:      workCenterService,
		workCenterQueryService: workCenterQueryService,
		auditService:           auditService,
		logger:                 logger,
	}
}

// ---- Request/Response DTOs ----

type CreateWorkCenterRequest struct {
	WorkCenterCode string  `json:"work_center_code"`
	Name           string  `json:"name"`
	Description    *string `json:"description,omitempty"`
	Timezone       string  `json:"timezone"`
	IsActive       bool    `json:"is_active"`
}

type UpdateWorkCenterRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Timezone    *string `json:"timezone,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// ---- Handlers ----

func (h *WorkCenterHandler) CreateWorkCenter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req CreateWorkCenterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.WorkCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center name is required")
		return
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	workCenter := &models.WorkCenter{
		WorkCenterCode: req.WorkCenterCode,
		CompanyID:      companyID,
		Name:           req.Name,
		Description:    req.Description,
		Timezone:       req.Timezone,
		IsActive:       req.IsActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	result, err := h.workCenterService.CreateWorkCenter(ctx, workCenter, actorType, actorID, metadata)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, err.Error())
			return
		}
		h.logger.Error("Failed to create work center",
			zap.String("company_id", companyID.String()),
			zap.String("work_center_code", req.WorkCenterCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create work center")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    result,
		"message": "Work center created successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) GetWorkCenter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	workCenterCode := chi.URLParam(r, "workCenterCode")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}

	workCenter, err := h.workCenterQueryService.GetWorkCenter(ctx, companyID, workCenterCode)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Work center not found")
		} else {
			h.logger.Error("Failed to get work center",
				zap.String("company_id", companyID.String()),
				zap.String("work_center_code", workCenterCode),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve work center")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    workCenter,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) UpdateWorkCenter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	workCenterCode := chi.URLParam(r, "workCenterCode")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req UpdateWorkCenterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == nil && req.Description == nil && req.Timezone == nil && req.IsActive == nil {
		h.respondWithError(w, http.StatusBadRequest, "No update fields provided")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	result, err := h.workCenterService.UpdateWorkCenter(
		ctx,
		companyID,
		workCenterCode,
		req.Name,
		req.Description,
		req.Timezone,
		req.IsActive,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Work center not found")
		} else if strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, err.Error())
		} else {
			h.logger.Error("Failed to update work center",
				zap.String("company_id", companyID.String()),
				zap.String("work_center_code", workCenterCode),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to update work center")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
		"message": "Work center updated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) DeleteWorkCenter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	workCenterCode := chi.URLParam(r, "workCenterCode")
	if workCenterCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Work center code is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	err = h.workCenterService.DeleteWorkCenter(ctx, companyID, workCenterCode, actorType, actorID, metadata)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Work center not found")
		} else {
			h.logger.Error("Failed to delete work center",
				zap.String("company_id", companyID.String()),
				zap.String("work_center_code", workCenterCode),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete work center")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Work center deleted successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) ListWorkCenters(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	workCenters, totalCount, err := h.workCenterQueryService.ListWorkCenters(ctx, companyID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list work centers",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list work centers")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    workCenters,
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  totalCount,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"duration":     time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) SearchWorkCenters(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	filters := make(map[string]interface{})
	if name := r.URL.Query().Get("name"); name != "" {
		filters["name"] = name
	}
	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			filters["is_active"] = active
		}
	}
	if code := r.URL.Query().Get("code"); code != "" {
		filters["work_center_code"] = code
	}

	workCenters, totalCount, err := h.workCenterQueryService.SearchWorkCenters(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search work centers",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search work centers")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    workCenters,
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  totalCount,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"filters":      filters,
			"duration":     time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) GetActiveWorkCenters(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	workCenters, err := h.workCenterQueryService.GetActiveWorkCenters(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get active work centers",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve active work centers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    workCenters,
		"meta": map[string]interface{}{
			"count":    len(workCenters),
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *WorkCenterHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.workCenterService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("Work center service health check failed: %v", err))
		return
	}
	if err := h.workCenterQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("Work center query service health check failed: %v", err))
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Work center services are healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---- Helper methods ----

func (h *WorkCenterHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("session type not found in context")
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}
	return actorType, userID, nil
}

func (h *WorkCenterHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *WorkCenterHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
	})
}
