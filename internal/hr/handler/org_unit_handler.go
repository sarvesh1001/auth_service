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
	"github.com/google/uuid"
	"go.uber.org/zap"

	apperrors "auth-service/internal/errors"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/service"
	a "auth-service/internal/infrastructure/audit"
	"auth-service/internal/util"
)

type OrgUnitHandler struct {
	orgUnitService      *service.OrgUnitService
	orgUnitQueryService *service.OrgUnitQueryService
	auditService        *a.AuditService
	logger              *zap.Logger
}

func NewOrgUnitHandler(
	orgUnitService *service.OrgUnitService,
	orgUnitQueryService *service.OrgUnitQueryService,
	auditService *a.AuditService,
	logger *zap.Logger,
) *OrgUnitHandler {
	return &OrgUnitHandler{
		orgUnitService:      orgUnitService,
		orgUnitQueryService: orgUnitQueryService,
		auditService:        auditService,
		logger:              logger,
	}
}

// ============================================================================
// ERROR MAPPING — single source of truth for HTTP status codes.
// ============================================================================
//
// Everything the service layer returns is either an hrErrors.* sentinel or an
// apperrors.* sentinel (wrapped with fmt.Errorf "%w: ..."). This function
// resolves both families and returns the correct status + user-facing message.
// ============================================================================
func (h *OrgUnitHandler) mapOrgUnitError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	switch {
	// ----- Not found -----
	case errors.Is(err, hrErrors.ErrOrgUnitNotFound):
		return http.StatusNotFound, "Org unit not found"
	case errors.Is(err, hrErrors.ErrOrgUnitMemberNotFound):
		return http.StatusNotFound, "Membership not found"
	case errors.Is(err, hrErrors.ErrOrgUnitRoleNotFound):
		return http.StatusNotFound, "Role assignment not found"
	case errors.Is(err, apperrors.ErrNotFound):
		return http.StatusNotFound, "Resource not found"

	// ----- Conflict (unique / primary / duplicate) -----
	case errors.Is(err, hrErrors.ErrOrgUnitPrimaryAlreadyExists):
		return http.StatusConflict,
			"This user already has an active primary role in this org unit. Unset it first."
	case errors.Is(err, hrErrors.ErrOrgUnitRoleAlreadyExists):
		return http.StatusConflict,
			"This role is already assigned for the chosen start date."
	case errors.Is(err, hrErrors.ErrOrgUnitAlreadyExists):
		return http.StatusConflict, "Org unit already exists"
	case errors.Is(err, apperrors.ErrDuplicate):
		return http.StatusConflict, "Resource already exists"
	case errors.Is(err, apperrors.ErrConflict):
		return http.StatusConflict, "Conflicting state"

	// ----- Invalid input -----
	case errors.Is(err, apperrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()

	// ----- Auth / permission -----
	case errors.Is(err, apperrors.ErrUnauthorized):
		return http.StatusUnauthorized, "Authentication required"
	case errors.Is(err, apperrors.ErrPermissionDenied):
		return http.StatusForbidden, "Permission denied"

	// ----- Fallback -----
	case errors.Is(err, apperrors.ErrInternal):
		return http.StatusInternalServerError, "Internal server error"
	default:
		return http.StatusInternalServerError, "Internal server error"
	}
}

// ============================================================================
// WRITE HANDLERS
// ============================================================================

func (h *OrgUnitHandler) CreateOrgUnit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req orgunit.CreateOrgUnitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "Org unit name is required")
		return
	}
	if req.OrgUnitType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Org unit type is required")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	orgUnit, err := h.orgUnitService.CreateOrgUnit(ctx, companyID, &req, actorType, actorID, metadata)
	if err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to create org unit",
				util.String("company_id", companyID.String()),
				util.String("name", req.Name),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    orgUnit,
		"message": "Org unit created successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) UpdateOrgUnit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req orgunit.UpdateOrgUnitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == nil && req.Description == nil && req.DepartmentID == nil && req.IsActive == nil {
		h.respondWithError(w, http.StatusBadRequest, "No update fields provided")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	orgUnit, err := h.orgUnitService.UpdateOrgUnit(ctx, companyID, orgUnitID, &req, actorType, actorID, metadata)
	if err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to update org unit",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orgUnit,
		"message": "Org unit updated successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) DeleteOrgUnit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
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

	if err := h.orgUnitService.DeleteOrgUnit(ctx, companyID, orgUnitID, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to delete org unit",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Org unit deleted successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// ============================================================================
// MEMBER HANDLERS
// ============================================================================

func (h *OrgUnitHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req orgunit.AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	if err := h.orgUnitService.AddMember(ctx, companyID, orgUnitID, &req, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to add member",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.String("user_id", req.UserID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Member added successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var req orgunit.UpdateMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr,
		"user_agent": r.UserAgent(),
	}

	if err := h.orgUnitService.UpdateMember(ctx, companyID, orgUnitID, userID, &req, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		// UpdateMember validates dates → surface the actual message on 400.
		if status == http.StatusBadRequest {
			msg = err.Error()
		}
		if status >= 500 {
			h.logger.Error("Failed to update membership",
				util.String("org_unit_id", orgUnitID.String()),
				util.String("user_id", userID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Membership updated successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
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

	if err := h.orgUnitService.RemoveMember(ctx, companyID, orgUnitID, userID, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to remove member",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.String("user_id", userID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Member removed successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// ============================================================================
// ROLE HANDLERS
// ============================================================================

func (h *OrgUnitHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req orgunit.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	if err := h.orgUnitService.AssignRole(ctx, companyID, orgUnitID, &req, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to assign role",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.String("user_id", req.UserID.String()),
				util.String("role", req.Role),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Role assigned successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	role := chi.URLParam(r, "role")
	if role == "" {
		h.respondWithError(w, http.StatusBadRequest, "Role is required")
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

	if err := h.orgUnitService.RemoveRole(ctx, companyID, orgUnitID, userID, role, actorType, actorID, metadata); err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to remove role",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.String("user_id", userID.String()),
				util.String("role", role),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Role removed successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// ============================================================================
// READ HANDLERS
// ============================================================================

func (h *OrgUnitHandler) GetOrgUnit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	withDetails := r.URL.Query().Get("details") == "true"

	orgUnit, err := h.orgUnitQueryService.GetOrgUnit(ctx, companyID, orgUnitID, withDetails)
	if err != nil {
		status, msg := h.mapOrgUnitError(err)
		if status >= 500 {
			h.logger.Error("Failed to get org unit",
				util.String("company_id", companyID.String()),
				util.String("org_unit_id", orgUnitID.String()),
				util.ErrorField(err))
		}
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orgUnit,
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) ListOrgUnits(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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

	var orgUnitType *string
	if typeParam := r.URL.Query().Get("type"); typeParam != "" {
		orgUnitType = &typeParam
	}
	var isActive *bool
	if activeParam := r.URL.Query().Get("is_active"); activeParam != "" {
		if active, err := strconv.ParseBool(activeParam); err == nil {
			isActive = &active
		}
	}

	orgUnits, totalCount, err := h.orgUnitQueryService.ListOrgUnits(ctx, companyID, page, pageSize, orgUnitType, isActive)
	if err != nil {
		h.logger.Error("Failed to list org units",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list org units")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orgUnits,
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

func (h *OrgUnitHandler) SearchOrgUnits(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
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
	if orgUnitType := r.URL.Query().Get("type"); orgUnitType != "" {
		filters["org_unit_type"] = orgUnitType
	}
	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			filters["is_active"] = active
		}
	}
	if departmentID := r.URL.Query().Get("department_id"); departmentID != "" {
		if deptUUID, err := uuid.Parse(departmentID); err == nil {
			filters["department_id"] = deptUUID
		}
	}

	orgUnits, totalCount, err := h.orgUnitQueryService.SearchOrgUnits(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search org units",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search org units")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orgUnits,
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

func (h *OrgUnitHandler) GetActiveOrgUnits(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	orgUnits, err := h.orgUnitQueryService.GetActiveOrgUnits(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get active org units",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve active org units")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    orgUnits,
		"meta":    map[string]interface{}{"count": len(orgUnits), "duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) GetOrgUnitMembers(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	// Verify the org unit belongs to this company (404 if not).
	if _, err := h.orgUnitQueryService.GetOrgUnit(ctx, companyID, orgUnitID, false); err != nil {
		status, msg := h.mapOrgUnitError(err)
		h.respondWithError(w, status, msg)
		return
	}

	onlyActive := r.URL.Query().Get("active") == "true"

	members, err := h.orgUnitQueryService.GetOrgUnitMembers(ctx, orgUnitID, onlyActive)
	if err != nil {
		h.logger.Error("Failed to get org unit members",
			util.String("org_unit_id", orgUnitID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve members")
		return
	}
	if members == nil {
		members = []*orgunit.OrgUnitMember{}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    members,
		"meta":    map[string]interface{}{"count": len(members), "duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) GetOrgUnitRoles(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	orgUnitID, err := uuid.Parse(chi.URLParam(r, "orgUnitID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid org unit ID")
		return
	}

	// Verify the org unit belongs to this company (404 if not).
	if _, err := h.orgUnitQueryService.GetOrgUnit(ctx, companyID, orgUnitID, false); err != nil {
		status, msg := h.mapOrgUnitError(err)
		h.respondWithError(w, status, msg)
		return
	}

	onlyActive := r.URL.Query().Get("active") != "false"

	roles, err := h.orgUnitQueryService.GetOrgUnitRoles(ctx, orgUnitID, onlyActive)
	if err != nil {
		h.logger.Error("Failed to get org unit roles",
			util.String("org_unit_id", orgUnitID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve roles")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    roles,
		"meta":    map[string]interface{}{"count": len(roles), "duration": time.Since(startTime).String()},
	})
}

func (h *OrgUnitHandler) GetUserMemberships(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	onlyActive := r.URL.Query().Get("active") != "false"

	memberships, err := h.orgUnitQueryService.GetUserMemberships(ctx, userID, onlyActive)
	if err != nil {
		h.logger.Error("Failed to get user memberships",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve memberships")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    memberships,
		"meta":    map[string]interface{}{"count": len(memberships), "duration": time.Since(startTime).String()},
	})
}

// ============================================================================
// HEALTH
// ============================================================================

func (h *OrgUnitHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	if err := h.orgUnitService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("Org unit service health check failed: %v", err))
		return
	}
	if err := h.orgUnitQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("Org unit query service health check failed: %v", err))
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Org unit services are healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// HELPERS
// ============================================================================

func (h *OrgUnitHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("session type not found in context")
	}
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}
	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}
	return actorType, userID, nil
}

func (h *OrgUnitHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *OrgUnitHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    statusCode,
	})
}