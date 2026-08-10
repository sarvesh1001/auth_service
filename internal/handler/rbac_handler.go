package handler

import (
	"auth-service/internal/contextkeys"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// RBACHandler handles Role-Based Access Control operations.
type RBACHandler struct {
	companyService *service.CompanyService
}

// NewRBACHandler creates a new RBACHandler.
func NewRBACHandler(companyService *service.CompanyService) *RBACHandler {
	return &RBACHandler{
		companyService: companyService,
	}
}

// ---------- Context injection helpers ----------

func (h *RBACHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *RBACHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		// Use the shared context key type
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *RBACHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// ---------- Error mapping ----------

func (h *RBACHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"

	// RBAC specific errors can be added here if defined
	default:
		// Fallback to string-based detection for any untyped errors
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist") {
			return http.StatusNotFound, errMsg
		}
		if strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "Permission") {
			return http.StatusForbidden, errMsg
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "Invalid") {
			return http.StatusBadRequest, errMsg
		}
		if strings.Contains(errMsg, "duplicate") || strings.Contains(errMsg, "already exists") {
			return http.StatusConflict, errMsg
		}
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Role CRUD ----------

// ListRoles retrieves paginated roles for a company.
// @Summary List roles
// @Description Returns roles for the company with pagination and optional permission inclusion.
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(50) maximum(100)
// @Param include_permissions query bool false "Include permissions in response" default(false)
// @Success 200 {object} map[string]interface{} "Roles retrieved"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/companies/{companyID}/rbac/roles [get]
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	includePermissions := r.URL.Query().Get("include_permissions") == "true"

	roles, total, err := h.companyService.ListRoles(ctx, companyID, limit, (page-1)*limit, includePermissions)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"roles": roles,
		"total": total,
		"page":  page,
		"limit": limit,
	}, "Roles retrieved successfully"))
}

// GetRole retrieves a specific role by ID.
// @Summary Get role
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "Role details"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID} [get]
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	role, err := h.companyService.GetRole(ctx, roleID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Role retrieved successfully"))
}

// UpdateRole updates an existing role.
// @Summary Update role
// @Description Update role name, description, departments, and permissions.
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Param body body object true "Update fields" example({"role_name":"New Name","description":"Updated desc","add_departments":["Sales"],"remove_departments":["IT"],"add_permissions":["user.view"],"remove_permissions":["user.delete"],"replace_permissions":["user.edit"]})
// @Success 200 {object} map[string]interface{} "Role updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Cannot update system roles"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID} [put]
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	companyID, err := h.getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Company ID required")
		return
	}

	updatedBy, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		RoleName           string   `json:"role_name" validate:"required"`
		Description        string   `json:"description"`
		AddDepartments     []string `json:"add_departments"`
		RemoveDepartments  []string `json:"remove_departments"`
		AddPermissions     []string `json:"add_permissions"`
		RemovePermissions  []string `json:"remove_permissions"`
		ReplacePermissions []string `json:"replace_permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if strings.TrimSpace(req.RoleName) == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role name is required")
		return
	}

	updateReq := service.UpdateRoleRequest{
		CompanyID:          companyID,
		RoleID:             roleID,
		RoleName:           req.RoleName,
		Description:        req.Description,
		AddDepartments:     req.AddDepartments,
		RemoveDepartments:  req.RemoveDepartments,
		AddPermissions:     req.AddPermissions,
		RemovePermissions:  req.RemovePermissions,
		ReplacePermissions: req.ReplacePermissions,
		UpdatedBy:          updatedBy,
	}

	if err := h.companyService.UpdateRole(ctx, updateReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role updated successfully"))
}

// DeleteRole deletes a role.
// @Summary Delete role
// @Tags rbac
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "Role deleted"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 403 {object} map[string]interface{} "Cannot delete system role"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID} [delete]
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	if err := h.companyService.DeleteRole(ctx, roleID, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role deleted successfully"))
}

// ---------- Department management ----------

// ListDepartments lists departments with pagination.
// @Summary List departments
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(50) maximum(100)
// @Param include_employees query bool false "Include employee count" default(false)
// @Success 200 {object} map[string]interface{} "Departments retrieved"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/companies/{companyID}/rbac/departments [get]
func (h *RBACHandler) ListDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	includeEmployees := r.URL.Query().Get("include_employees") == "true"

	departments, total, err := h.companyService.ListDepartments(ctx, companyID, limit, (page-1)*limit, includeEmployees)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"departments": departments,
		"total":       total,
		"page":        page,
		"limit":       limit,
	}, "Departments retrieved successfully"))
}

// DeactivateDepartment deactivates a department.
// @Summary Deactivate department
// @Tags rbac
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Department deactivated"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/departments/{departmentID}/deactivate [post]
func (h *RBACHandler) DeactivateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	if err := h.companyService.DeactivateDepartment(ctx, departmentID, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department deactivated successfully"))
}

// DeleteDepartment permanently deletes a department and its role mappings.
// @Summary Delete department
// @Tags rbac
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Department deleted"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/departments/{departmentID} [delete]
func (h *RBACHandler) DeleteDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	if err := h.companyService.DeleteDepartment(ctx, departmentID, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department and its role mappings deleted successfully"))
}

// RenameDepartment renames a department.
// @Summary Rename department
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Param body body object true "New name" example({"department_name":"New Dept Name"})
// @Success 200 {object} map[string]interface{} "Department renamed"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/departments/{departmentID}/rename [put]
func (h *RBACHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	var req struct {
		DepartmentName string `json:"department_name" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

	if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))
}

// ---------- Permission management ----------

// ListAllPermissions retrieves all permissions with optional filters.
// @Summary List all permissions
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param module query string false "Filter by module"
// @Param category query string false "Filter by category"
// @Param tier query string false "Filter by tier"
// @Success 200 {object} map[string]interface{} "Permissions list"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/companies/{companyID}/rbac/permissions [get]
func (h *RBACHandler) ListAllPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	module := r.URL.Query().Get("module")
	category := r.URL.Query().Get("category")
	tier := r.URL.Query().Get("tier")

	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "All permissions retrieved successfully"))
}

// GetPermissionByName retrieves a permission by its name.
// @Summary Get permission by name
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param permissionName path string true "Permission name"
// @Success 200 {object} map[string]interface{} "Permission details"
// @Failure 400 {object} map[string]interface{} "Invalid name"
// @Failure 404 {object} map[string]interface{} "Permission not found"
// @Router /api/v1/companies/{companyID}/rbac/permissions/name/{permissionName} [get]
func (h *RBACHandler) GetPermissionByName(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	permissionName := chi.URLParam(r, "permissionName")
	if permissionName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Permission name is required")
		return
	}

	permission, err := h.companyService.GetPermissionByName(ctx, permissionName)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permission, "Permission retrieved successfully"))
}

// ListPermissionsByModule retrieves permissions for a module.
// @Summary List permissions by module
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param module path string true "Module name"
// @Success 200 {object} map[string]interface{} "Permissions for module"
// @Failure 400 {object} map[string]interface{} "Invalid module"
// @Router /api/v1/companies/{companyID}/rbac/permissions/module/{module} [get]
func (h *RBACHandler) ListPermissionsByModule(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	module := chi.URLParam(r, "module")
	if module == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Module name is required")
		return
	}

	permissions, err := h.companyService.ListPermissionsByModule(ctx, module)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions,
		fmt.Sprintf("Permissions for module '%s' retrieved successfully", module)))
}

// ---------- Role permission assignments ----------

// GetRolePermissions retrieves permissions assigned to a role.
// @Summary Get role permissions
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "List of permissions"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID}/permissions [get]
func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	permissions, err := h.companyService.GetRolePermissions(ctx, roleID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	type PermissionResponse struct {
		PermissionID   uuid.UUID `json:"permission_id"`
		PermissionName string    `json:"permission_name"`
		Description    string    `json:"description"`
		Category       string    `json:"category"`
		Module         string    `json:"module"`
		Action         string    `json:"action"`
		RequiresTier   string    `json:"requires_tier,omitempty"`
		CreatedAt      string    `json:"created_at"`
	}
	response := make([]PermissionResponse, len(permissions))
	for i, perm := range permissions {
		response[i] = PermissionResponse{
			PermissionID:   perm.PermissionID,
			PermissionName: perm.PermissionName,
			Description:    perm.Description,
			Category:       perm.Category,
			Module:         perm.Module,
			RequiresTier:   perm.RequiresTier,
			CreatedAt:      perm.CreatedAt.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Role permissions retrieved successfully"))
}

// AssignPermissionsToRole grants permissions to a role.
// @Summary Assign permissions to role
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Param body body object true "Permission names" example({"permission_names":["user.view","user.edit"]})
// @Success 200 {object} map[string]interface{} "Permissions assigned"
// @Failure 400 {object} map[string]interface{} "Invalid permissions"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID}/permissions [post]
func (h *RBACHandler) AssignPermissionsToRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		PermissionNames []string `json:"permission_names" validate:"required,min=1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	if len(req.PermissionNames) == 0 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "At least one permission name is required")
		return
	}

	// Validate permissions exist
	allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	permMap := make(map[string]uuid.UUID)
	for _, perm := range allPermissions {
		permMap[perm.PermissionName] = perm.PermissionID
	}
	var permissionIDs []uuid.UUID
	var invalidPermissions []string
	for _, permName := range req.PermissionNames {
		if permID, exists := permMap[permName]; exists {
			permissionIDs = append(permissionIDs, permID)
		} else {
			invalidPermissions = append(invalidPermissions, permName)
		}
	}
	if len(invalidPermissions) > 0 {
		h.respondWithError(w, http.StatusBadRequest,
			customErrors.ErrInvalidInput,
			fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
		return
	}

	var grantedCount int
	var errorsList []string
	sessionType, _ := ctx.Value("session_type").(string)
	for _, permissionID := range permissionIDs {
		var err error
		if sessionType == "admin" {
			err = h.companyService.GrantRolePermissionAdmin(ctx, roleID, permissionID, adminID)
		} else {
			err = h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminID)
		}
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("Failed to grant permission: %v", err))
			continue
		}
		grantedCount++
	}
	if len(errorsList) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("partial failure: %v", errorsList),
			fmt.Sprintf("Successfully granted %d out of %d permissions", grantedCount, len(permissionIDs)))
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
		fmt.Sprintf("All %d permissions granted successfully to role", grantedCount)))
}

// RemovePermissionsFromRole revokes permissions from a role.
// @Summary Remove permissions from role
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Param body body object true "Permission names" example({"permission_names":["user.delete"]})
// @Success 200 {object} map[string]interface{} "Permissions revoked"
// @Failure 400 {object} map[string]interface{} "Invalid permissions"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID}/permissions [delete]
func (h *RBACHandler) RemovePermissionsFromRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		PermissionNames []string `json:"permission_names" validate:"required,min=1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	if len(req.PermissionNames) == 0 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "At least one permission name is required")
		return
	}

	allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	permMap := make(map[string]uuid.UUID)
	for _, perm := range allPermissions {
		permMap[perm.PermissionName] = perm.PermissionID
	}
	var permissionIDs []uuid.UUID
	var invalidPermissions []string
	for _, permName := range req.PermissionNames {
		if permID, exists := permMap[permName]; exists {
			permissionIDs = append(permissionIDs, permID)
		} else {
			invalidPermissions = append(invalidPermissions, permName)
		}
	}
	if len(invalidPermissions) > 0 {
		h.respondWithError(w, http.StatusBadRequest,
			customErrors.ErrInvalidInput,
			fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
		return
	}

	var revokedCount int
	var errorsList []string
	for _, permissionID := range permissionIDs {
		if err := h.companyService.RevokeRolePermission(ctx, roleID, permissionID, adminID); err != nil {
			errorsList = append(errorsList, fmt.Sprintf("Failed to revoke permission: %v", err))
			continue
		}
		revokedCount++
	}
	if len(errorsList) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("partial failure: %v", errorsList),
			fmt.Sprintf("Successfully revoked %d out of %d permissions", revokedCount, len(permissionIDs)))
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
		fmt.Sprintf("All %d permissions revoked successfully from role", revokedCount)))
}

// ReplaceRolePermissions replaces all permissions of a role with a new set.
// @Summary Replace role permissions
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param roleID path string true "Role UUID"
// @Param body body object true "New permission list" example({"permission_names":["user.view","report.view"]})
// @Success 200 {object} map[string]interface{} "Permissions replaced"
// @Failure 400 {object} map[string]interface{} "Invalid permissions"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/roles/{roleID}/permissions [put]
func (h *RBACHandler) ReplaceRolePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		PermissionNames []string `json:"permission_names" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	permMap := make(map[string]uuid.UUID)
	for _, perm := range allPermissions {
		permMap[perm.PermissionName] = perm.PermissionID
	}
	var permissionIDs []uuid.UUID
	var invalidPermissions []string
	for _, permName := range req.PermissionNames {
		if permID, exists := permMap[permName]; exists {
			permissionIDs = append(permissionIDs, permID)
		} else {
			invalidPermissions = append(invalidPermissions, permName)
		}
	}
	if len(invalidPermissions) > 0 {
		h.respondWithError(w, http.StatusBadRequest,
			customErrors.ErrInvalidInput,
			fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
		return
	}

	currentPermissions, _ := h.companyService.GetRolePermissions(ctx, roleID)
	for _, perm := range currentPermissions {
		_ = h.companyService.RevokeRolePermission(ctx, roleID, perm.PermissionID, adminID)
	}

	var grantedCount int
	var errorsList []string
	sessionType, _ := ctx.Value("session_type").(string)
	for _, permissionID := range permissionIDs {
		var err error
		if sessionType == "admin" {
			err = h.companyService.GrantRolePermissionAdmin(ctx, roleID, permissionID, adminID)
		} else {
			err = h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminID)
		}
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("Failed to grant permission: %v", err))
			continue
		}
		grantedCount++
	}

	response := map[string]interface{}{
		"role_id":             roleID,
		"permissions_granted": grantedCount,
		"total_requested":     len(permissionIDs),
		"errors":              errorsList,
	}
	if len(errorsList) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("partial failure: %v", errorsList),
			fmt.Sprintf("Role permissions replaced with %d out of %d permissions", grantedCount, len(permissionIDs)))
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response,
		fmt.Sprintf("All %d permissions successfully assigned to role", grantedCount)))
}

// ---------- User permission checks ----------

// CheckUserPermission checks if a user has a specific permission.
// @Summary Check user permission
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Param permission query string true "Permission name"
// @Success 200 {object} map[string]interface{} "Permission check result"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Router /api/v1/companies/{companyID}/rbac/users/{userID}/permissions/check [get]
func (h *RBACHandler) CheckUserPermission(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	permissionName := r.URL.Query().Get("permission")
	if permissionName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Permission name is required")
		return
	}

	hasPermission, err := h.companyService.CheckUserPermission(ctx, companyID, userID, permissionName)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"has_permission": hasPermission,
		"user_id":        userID,
		"permission":     permissionName,
	}, "Permission check completed"))
}

// GetUserPermissions retrieves all permissions for a user.
// @Summary Get user permissions
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "List of permissions"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Router /api/v1/companies/{companyID}/rbac/users/{userID}/permissions [get]
func (h *RBACHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "User permissions retrieved successfully"))
}

// GetUserPermissionBitmask retrieves the user's permission bitmask.
// @Summary Get user permission bitmask
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Bitmask and permissions"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Router /api/v1/companies/{companyID}/rbac/users/{userID}/permissions/bitmask [get]
func (h *RBACHandler) GetUserPermissionBitmask(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	permissionNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionNames[i] = perm.PermissionName
	}

	permissionMask, err := h.companyService.GetUserPermissionBitmask(ctx, companyID, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"user_id":          userID,
		"company_id":       companyID,
		"permissions":      permissionNames,
		"permission_mask":  permissionMask,
		"permission_count": len(permissionNames),
	}, "User permissions with bitmask retrieved successfully"))
}

// GetUserHierarchy retrieves the user's organizational hierarchy.
// @Summary Get user hierarchy
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Hierarchy structure"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Router /api/v1/companies/{companyID}/rbac/users/{userID}/hierarchy [get]
func (h *RBACHandler) GetUserHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	hierarchy, err := h.companyService.GetUserHierarchy(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "User hierarchy retrieved successfully"))
}

// ---------- Employee/Manager management ----------

// AddEmployee adds an employee with a role.
// @Summary Add employee
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Employee details" example({"phone":"+919876543210","username":"jdoe","full_name":"John Doe","employee_id":"EMP001","role_id":"...","reports_to":"...","position_id":"..."})
// @Success 201 {object} map[string]interface{} "Employee added"
// @Failure 400 {object} map[string]interface{} "Invalid input or role/position mismatch"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Employee already exists or limit reached"
// @Router /api/v1/companies/{companyID}/rbac/employees [post]
func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req struct {
		PhoneNumber string     `json:"phone" validate:"required"`
		Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
		FullName    string     `json:"full_name" validate:"required,max=255"`
		EmployeeID  string     `json:"employee_id" validate:"required"`
		RoleID      uuid.UUID  `json:"role_id" validate:"required"`
		ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
		PositionID  *uuid.UUID `json:"position_id,omitempty"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
		return
	}

	// Validate role belongs to company
	role, err := h.companyService.GetRole(ctx, req.RoleID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}
	if role.CompanyID != companyID {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role does not belong to this company")
		return
	}

	// Validate position if provided
	if req.PositionID != nil {
		position, err := h.companyService.GetPosition(ctx, *req.PositionID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
			return
		}
		if position.CompanyID != companyID {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position does not belong to this company")
			return
		}
		if !position.IsOpen {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position is not open for assignment")
			return
		}
	}

	// Validate reports-to if provided
	if req.ReportsTo != nil {
		isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
		if err != nil || !isActive {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Reports-to employee not found or not active")
			return
		}
	}

	employeeReq := &service.AddEmployeeRequest{
		CompanyID:   companyID,
		PhoneNumber: req.PhoneNumber,
		Username:    req.Username,
		FullName:    req.FullName,
		EmployeeID:  req.EmployeeID,
		RoleID:      req.RoleID,
		ReportsTo:   req.ReportsTo,
		PositionID:  req.PositionID,
	}
	if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
}

// AddManager adds a manager with a role (role level >= 500).
// @Summary Add manager
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Manager details" example({"phone":"+919876543210","username":"mgr","full_name":"Manager Name","employee_id":"MGR001","role_id":"...","reports_to":"...","position_id":"..."})
// @Success 201 {object} map[string]interface{} "Manager added"
// @Failure 400 {object} map[string]interface{} "Invalid input or role level too low"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/managers [post]
func (h *RBACHandler) AddManager(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req struct {
		PhoneNumber string     `json:"phone" validate:"required"`
		Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
		FullName    string     `json:"full_name" validate:"required,max=255"`
		EmployeeID  string     `json:"employee_id" validate:"required"`
		RoleID      uuid.UUID  `json:"role_id" validate:"required"`
		ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
		PositionID  *uuid.UUID `json:"position_id,omitempty"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
		return
	}

	role, err := h.companyService.GetRole(ctx, req.RoleID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}
	if role.CompanyID != companyID {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role does not belong to this company")
		return
	}
	if role.RoleLevel < 500 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role level must be 500 or higher for managers")
		return
	}

	if req.PositionID != nil {
		position, err := h.companyService.GetPosition(ctx, *req.PositionID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
			return
		}
		if position.CompanyID != companyID {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position does not belong to this company")
			return
		}
		if !position.IsOpen {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position is not open for assignment")
			return
		}
	}

	if req.ReportsTo != nil {
		isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
		if err != nil || !isActive {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Reports-to employee not found or not active")
			return
		}
	}

	managerReq := &service.AddEmployeeRequest{
		CompanyID:   companyID,
		PhoneNumber: req.PhoneNumber,
		Username:    req.Username,
		FullName:    req.FullName,
		EmployeeID:  req.EmployeeID,
		RoleID:      req.RoleID,
		ReportsTo:   req.ReportsTo,
		PositionID:  req.PositionID,
	}
	if err := h.companyService.AddEmployee(ctx, managerReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))
}

// UpdateEmployeePosition updates the position of an employee.
// @Summary Update employee position
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Param body body object true "New position" example({"position_id":"..."})
// @Success 200 {object} map[string]interface{} "Position updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Router /api/v1/companies/{companyID}/rbac/employees/{userID}/position [put]
func (h *RBACHandler) UpdateEmployeePosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	var req struct {
		PositionID *uuid.UUID `json:"position_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.PositionID != nil {
		position, err := h.companyService.GetPosition(ctx, *req.PositionID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
			return
		}
		if position.CompanyID != companyID {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position does not belong to this company")
			return
		}
		if !position.IsOpen {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Position is not open for assignment")
			return
		}
	}

	if err := h.companyService.UpdateEmployeePosition(ctx, companyID, userID, req.PositionID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee position updated successfully"))
}

// UpdateEmployeeDepartment updates the employee's role (department changes).
// @Summary Update employee role (department)
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Param body body object true "New role ID" example({"new_role_id":"..."})
// @Success 200 {object} map[string]interface{} "Role updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Router /api/v1/companies/{companyID}/rbac/employees/{userID}/role [put]
func (h *RBACHandler) UpdateEmployeeDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	updatedBy, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		NewRoleID uuid.UUID `json:"new_role_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	newRole, err := h.companyService.GetRole(ctx, req.NewRoleID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "New role not found")
		return
	}
	if newRole.CompanyID != companyID {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "New role does not belong to this company")
		return
	}

	if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.NewRoleID, updatedBy); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role updated successfully"))
}

// GetEmployeeWithPosition retrieves employee details including position.
// @Summary Get employee with position
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Employee details"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Router /api/v1/companies/{companyID}/rbac/employees/{userID} [get]
func (h *RBACHandler) GetEmployeeWithPosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	employee, err := h.companyService.GetEmployeeWithPosition(ctx, companyID, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(employee, "Employee with position retrieved successfully"))
}

// GetAvailablePermissions retrieves permissions available to the current user.
// @Summary Get available permissions
// @Description Returns permissions that the current user can assign based on their own permissions.
// @Tags rbac
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Available permissions"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Authentication required"
// @Router /api/v1/companies/{companyID}/rbac/available-permissions [get]
func (h *RBACHandler) GetAvailablePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	currentUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	sessionType, _ := ctx.Value("session_type").(string)

	if sessionType == "admin" {
		allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		h.respondWithJSON(w, http.StatusOK, successResponse(allPermissions, "Available permissions retrieved successfully"))
		return
	}

	currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	userPermMap := make(map[string]bool)
	for _, perm := range currentUserPermissions {
		userPermMap[perm.PermissionName] = true
	}
	var availablePermissions []*models.Permission
	for _, perm := range allPermissions {
		if userPermMap[perm.PermissionName] {
			availablePermissions = append(availablePermissions, perm)
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(availablePermissions, "Available permissions retrieved successfully"))
}

// CreateRole creates a new role with optional departments and permissions.
// @Summary Create role
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Role details" example({"role_name":"Admin","role_level":1000,"description":"Administrator","department_ids":["..."],"permission_names":["user.view"]})
// @Success 201 {object} map[string]interface{} "Role created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/roles [post]
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	sessionType, _ := ctx.Value("session_type").(string)

	var req struct {
		RoleName        string      `json:"role_name" validate:"required"`
		RoleLevel       int         `json:"role_level" validate:"required"`
		Description     string      `json:"description"`
		SystemRole      bool        `json:"system_role"`
		DepartmentIDs   []uuid.UUID `json:"department_ids"`
		PermissionNames []string    `json:"permission_names"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
		return
	}

	// Validate permission names exist
	if len(req.PermissionNames) > 0 {
		allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		validPermMap := make(map[string]bool)
		for _, perm := range allPermissions {
			validPermMap[perm.PermissionName] = true
		}
		for _, permName := range req.PermissionNames {
			if !validPermMap[permName] {
				h.respondWithError(w, http.StatusBadRequest,
					customErrors.ErrInvalidInput,
					fmt.Sprintf("Permission not found: %s", permName))
				return
			}
		}
	}

	// Map permission names to IDs
	permissionIDs := []uuid.UUID{}
	if len(req.PermissionNames) > 0 {
		allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		permMap := make(map[string]uuid.UUID)
		for _, perm := range allPermissions {
			permMap[perm.PermissionName] = perm.PermissionID
		}
		for _, permName := range req.PermissionNames {
			if permID, exists := permMap[permName]; exists {
				permissionIDs = append(permissionIDs, permID)
			}
		}
	}

	// Validate department-permission compatibility if both provided
	if len(req.DepartmentIDs) > 0 && len(permissionIDs) > 0 {
		compatible, errorMsg, err := h.companyService.ValidatePermissionDepartmentCompatibility(
			ctx, req.DepartmentIDs, permissionIDs)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !compatible {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, errorMsg)
			return
		}
	}

	roleReq := &service.CreateRoleRequest{
		CompanyID:     companyID,
		RoleName:      req.RoleName,
		RoleLevel:     req.RoleLevel,
		Description:   req.Description,
		DepartmentIDs: req.DepartmentIDs,
		PermissionIDs: permissionIDs,
		CreatedBy:     adminID,
	}

	var role *models.Role
	if sessionType == "admin" {
		role, err = h.companyService.CreateRoleAdmin(ctx, roleReq)
	} else {
		role, err = h.companyService.CreateRole(ctx, roleReq)
	}
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
}

// BulkAssignRoles performs bulk assignment of roles to users.
// @Summary Bulk assign roles
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Assignments" example({"assignments":[{"user_id":"...","role_id":"..."}]})
// @Success 200 {object} map[string]interface{} "Bulk assignment results"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/rbac/bulk-assign [post]
func (h *RBACHandler) BulkAssignRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	adminID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
		return
	}

	var req struct {
		Assignments []service.BulkAssignment `json:"assignments" validate:"required,min=1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	results, err := h.companyService.BulkAssignRoles(ctx, companyID, req.Assignments, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Bulk role assignment completed"))
}

// ---------- Utility helpers ----------

func (h *RBACHandler) getCompanyIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw := ctx.Value("company_id")
	if raw == nil {
		return uuid.Nil, customErrors.ErrInvalidInput
	}
	switch v := raw.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, customErrors.ErrInvalidInput
	}
}

func (h *RBACHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw := ctx.Value("user_id")
	if raw == nil {
		return uuid.Nil, customErrors.ErrUnauthorized
	}
	switch v := raw.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, customErrors.ErrInvalidInput
	}
}

func (h *RBACHandler) getClientIP(r *http.Request) string {
	// Simplified IP extraction; can be shared with admin handler
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

func (h *RBACHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *RBACHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// GetRoleDepartments handles GET /roles/{roleID}/departments
func (h *RBACHandler) GetRoleDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	departments, err := h.companyService.GetRoleDepartments(ctx, roleID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	type DepartmentResponse struct {
		DepartmentID       uuid.UUID  `json:"department_id"`
		DepartmentName     string     `json:"department_name"`
		CompanyID          uuid.UUID  `json:"company_id"`
		SystemDepartmentID *uuid.UUID `json:"system_department_id,omitempty"`
		ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
		IsActive           bool       `json:"is_active"`
		CreatedAt          string     `json:"created_at"`
		UpdatedAt          string     `json:"updated_at"`
	}

	response := make([]DepartmentResponse, len(departments))
	for i, dept := range departments {
		response[i] = DepartmentResponse{
			DepartmentID:       dept.DepartmentID,
			DepartmentName:     dept.DepartmentName,
			CompanyID:          dept.CompanyID,
			SystemDepartmentID: dept.SystemDepartmentID,
			ParentDepartmentID: dept.ParentDepartmentID,
			IsActive:           dept.IsActive,
			CreatedAt:          dept.CreatedAt.Format(time.RFC3339),
			UpdatedAt:          dept.UpdatedAt.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Role departments retrieved successfully"))
}

// GetRoleDepartments returns the departments assigned to a role.
func (h *RBACHandler) GetRoleDepartmentsForPermission(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	departments, err := h.companyService.GetRoleDepartmentsForPermissions(ctx, roleID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	type DepartmentResponse struct {
		DepartmentID       uuid.UUID  `json:"department_id"`
		DepartmentName     string     `json:"department_name"`
		SystemDepartmentID *uuid.UUID `json:"system_department_id,omitempty"`
		ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
		IsActive           bool       `json:"is_active"`
		CreatedAt          string     `json:"created_at"`
		UpdatedAt          string     `json:"updated_at"`
	}

	response := make([]DepartmentResponse, len(departments))
	for i, dept := range departments {
		response[i] = DepartmentResponse{
			DepartmentID:       dept.DepartmentID,
			DepartmentName:     dept.DepartmentName,
			SystemDepartmentID: dept.SystemDepartmentID,
			ParentDepartmentID: dept.ParentDepartmentID,
			IsActive:           dept.IsActive,
			CreatedAt:          dept.CreatedAt.Format(time.RFC3339),
			UpdatedAt:          dept.UpdatedAt.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Role departments retrieved successfully"))
}

// UpdateEmployee updates an existing employee's role, position, reports_to, employee_id, or status.
// @Summary Update employee
// @Tags rbac
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID (employee identifier)"
// @Param body body object true "Employee fields to update" example({"role_id":"...","reports_to":"..."})
// @Success 200 {object} map[string]interface{} "Employee updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Failure 409 {object} map[string]interface{} "Conflict"
// @Router /api/v1/companies/{companyID}/rbac/employees/{userID} [patch]

// UpdateEmployee handles PATCH requests to update an employee.
func (h *RBACHandler) UpdateEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), "ip_address", getClientIP(r)) // helper to get client IP

	// Extract company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Extract user ID from URL
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// Parse request body
	var req struct {
		EmployeeID *string    `json:"employee_id,omitempty"`
		RoleID     *uuid.UUID `json:"role_id,omitempty"`
		PositionID *uuid.UUID `json:"position_id,omitempty"`
		ReportsTo  *uuid.UUID `json:"reports_to,omitempty"`
		IsActive   *bool      `json:"is_active,omitempty"`
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
		return
	}

	// Ensure at least one field is provided
	if req.EmployeeID == nil && req.RoleID == nil && req.PositionID == nil && req.ReportsTo == nil && req.IsActive == nil {
		h.respondWithError(w, http.StatusBadRequest, nil, "No fields to update")
		return
	}

	// Build service request
	updateReq := &service.UpdateEmployeeRequest{
		CompanyID:  companyID,
		UserID:     userID,
		EmployeeID: req.EmployeeID,
		RoleID:     req.RoleID,
		PositionID: req.PositionID,
		ReportsTo:  req.ReportsTo,
		IsActive:   req.IsActive,
	}

	// Call service
	if err := h.companyService.UpdateEmployee(ctx, updateReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee updated successfully"))
}
