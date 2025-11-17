// internal/handler/rbac_handler.go
package handler

import (
	"auth-service/internal/service"
	"auth-service/internal/util"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RBACHandler handles RBAC operations for companies
type RBACHandler struct {
	companyService *service.CompanyService
	logger         *zap.Logger
}

func NewRBACHandler(companyService *service.CompanyService, logger *zap.Logger) *RBACHandler {
	return &RBACHandler{
		companyService: companyService,
		logger:         logger,
	}
}

// internal/handler/rbac_handler.go
// internal/handler/rbac_handler.go
// internal/handler/rbac_handler.go

func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		RoleName      string      `json:"role_name" validate:"required"`
		RoleLevel     int         `json:"role_level" validate:"required"`
		Description   string      `json:"description"`
		SystemRole    bool        `json:"system_role"`
		DepartmentIDs []uuid.UUID `json:"department_ids"` // 🔥 ADD THIS FIELD
		Permissions   []struct {
			PermissionID uuid.UUID `json:"permission_id"`
		} `json:"permissions,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Extract permission IDs
	permissionIDs := make([]uuid.UUID, len(req.Permissions))
	for i, perm := range req.Permissions {
		permissionIDs[i] = perm.PermissionID
	}

	// Create the role using existing service method
	roleReq := &service.CreateRoleRequest{
		CompanyID:     companyID,
		RoleName:      req.RoleName,
		RoleLevel:     req.RoleLevel,
		Description:   req.Description,
		DepartmentIDs: req.DepartmentIDs, // 🔥 PASS DEPARTMENT IDs
		PermissionIDs: permissionIDs,
		CreatedBy:     adminIDParsed,
	}

	role, err := h.companyService.CreateRole(ctx, roleReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create role")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
} // // CreateRole creates a new role for a company
// func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get admin ID from context
// 	adminID := r.Context().Value("user_id")
// 	if adminID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// 		return
// 	}

// 	adminIDParsed, err := uuid.Parse(adminID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
// 		return
// 	}

// 	var req struct {
// 		RoleName    string `json:"role_name" validate:"required"`
// 		RoleLevel   int    `json:"role_level" validate:"required"`
// 		Description string `json:"description"`
// 		SystemRole  bool   `json:"system_role"`
// 		Permissions []struct {
// 			PermissionID uuid.UUID `json:"permission_id"`
// 		} `json:"permissions,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Create role with permissions
// 	role, err := h.companyService.CreateRoleWithPermissions(
// 		ctx,
// 		companyID,
// 		req.RoleName, // ✅ Added this parameter
// 		req.RoleLevel,
// 		adminIDParsed,
// 		req.Description,
// 		req.SystemRole,
// 		req.Permissions,
// 	)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
// }

// ListRoles lists all roles for a company
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list roles")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"roles": roles,
		"total": total,
		"page":  page,
		"limit": limit,
	}, "Roles retrieved successfully"))
}

// GetRole retrieves a specific role with permissions
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	role, err := h.companyService.GetRole(ctx, roleID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Role not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Role retrieved successfully"))
}

// UpdateRole updates a role
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		RoleName    string `json:"role_name" validate:"required"`
		RoleLevel   int    `json:"role_level" validate:"required"`
		Description string `json:"description"`
		IsActive    *bool  `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// FIXED: Remove unused IsActive field from call
	if err := h.companyService.UpdateRole(ctx, roleID, req.RoleName, req.RoleLevel, adminIDParsed, req.Description); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role updated successfully"))
}

// DeleteRole deletes a role
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	if err := h.companyService.DeleteRole(ctx, roleID, adminIDParsed); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to delete role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role deleted successfully"))
}

// CreateDepartment creates a new department
func (h *RBACHandler) CreateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req service.CreateDepartmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = adminIDParsed

	department, err := h.companyService.CreateDepartment(ctx, &req)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create department")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department created successfully"))
}

// ListDepartments lists all departments for a company
func (h *RBACHandler) ListDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list departments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"departments": departments,
		"total":       total,
		"page":        page,
		"limit":       limit,
	}, "Departments retrieved successfully"))
}

// UpdateDepartment updates a department
func (h *RBACHandler) UpdateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		Name        string    `json:"name" validate:"required"`
		Head        uuid.UUID `json:"head,omitempty"`
		Description string    `json:"description"`
		IsActive    *bool     `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// FIXED: Corrected argument count and order
	if err := h.companyService.UpdateDepartment(ctx, departmentID, req.Name, &req.Head, adminIDParsed); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update department")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department updated successfully"))
}

// DeactivateDepartment deactivates a department
func (h *RBACHandler) DeactivateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	if err := h.companyService.DeactivateDepartment(ctx, departmentID, adminIDParsed); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to deactivate department")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department deactivated successfully"))
}

// AssignPermissionsToRole assigns permissions to a role
func (h *RBACHandler) AssignPermissionsToRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required,min=1"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(req.PermissionIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission ID is required")
		return
	}

	// Grant each permission to the role
	var grantedCount int
	var errors []string

	for _, permissionID := range req.PermissionIDs {
		if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to grant permission %s: %v", permissionID, err))
			continue
		}
		grantedCount++
	}

	if len(errors) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
			fmt.Sprintf("Successfully granted %d out of %d permissions", grantedCount, len(req.PermissionIDs)))
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
		fmt.Sprintf("All %d permissions granted successfully to role", grantedCount)))
}

// RemovePermissionsFromRole removes permissions from a role
func (h *RBACHandler) RemovePermissionsFromRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required,min=1"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(req.PermissionIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission ID is required")
		return
	}

	// Revoke each permission from the role
	var revokedCount int
	var errors []string

	for _, permissionID := range req.PermissionIDs {
		// FIXED: Added adminIDParsed as the revokedBy parameter
		if err := h.companyService.RevokeRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to revoke permission %s: %v", permissionID, err))
			continue
		}
		revokedCount++
	}

	if len(errors) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
			fmt.Sprintf("Successfully revoked %d out of %d permissions", revokedCount, len(req.PermissionIDs)))
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
		fmt.Sprintf("All %d permissions revoked successfully from role", revokedCount)))
}

// GetRolePermissions retrieves all permissions for a role
func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	permissions, err := h.companyService.GetRolePermissions(ctx, roleID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve role permissions")
		return
	}

	// Convert to a more structured response
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

// GetPermissionByName retrieves a permission by name
func (h *RBACHandler) GetPermissionByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	permissionName := chi.URLParam(r, "permissionName")
	if permissionName == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSION_NAME"), "Permission name is required")
		return
	}

	permission, err := h.companyService.GetPermissionByName(ctx, permissionName)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Permission not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permission, "Permission retrieved successfully"))
}

// ListAllPermissions retrieves all available permissions
func (h *RBACHandler) ListAllPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get query parameters for filtering
	module := r.URL.Query().Get("module")
	category := r.URL.Query().Get("category")
	tier := r.URL.Query().Get("tier")

	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "All permissions retrieved successfully"))
}

// ListPermissionsByModule retrieves permissions by module
func (h *RBACHandler) ListPermissionsByModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	module := chi.URLParam(r, "module")
	if module == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_MODULE"), "Module name is required")
		return
	}

	permissions, err := h.companyService.ListPermissionsByModule(ctx, module)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions by module")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions,
		fmt.Sprintf("Permissions for module '%s' retrieved successfully", module)))
}

// ReplaceRolePermissions replaces all permissions for a role (overwrite existing)
func (h *RBACHandler) ReplaceRolePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// First, get current permissions to show what changed
	currentPermissions, _ := h.companyService.GetRolePermissions(ctx, roleID)

	// Revoke all current permissions first
	if len(currentPermissions) > 0 {
		for _, perm := range currentPermissions {
			// FIXED: Added adminIDParsed as the revokedBy parameter
			_ = h.companyService.RevokeRolePermission(ctx, roleID, perm.PermissionID, adminIDParsed)
		}
	}

	// Grant new permissions
	var grantedCount int
	var errors []string

	for _, permissionID := range req.PermissionIDs {
		if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to grant permission %s: %v", permissionID, err))
			continue
		}
		grantedCount++
	}

	response := map[string]interface{}{
		"role_id":             roleID,
		"permissions_granted": grantedCount,
		"total_requested":     len(req.PermissionIDs),
		"errors":              errors,
	}

	if len(errors) > 0 {
		h.respondWithError(w, http.StatusPartialContent,
			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
			fmt.Sprintf("Role permissions replaced with %d out of %d permissions", grantedCount, len(req.PermissionIDs)))
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response,
		fmt.Sprintf("All %d permissions successfully assigned to role", grantedCount)))
}

// CheckUserPermission checks if a user has a specific permission
func (h *RBACHandler) CheckUserPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSION"), "Permission name is required")
		return
	}

	// FIXED: Added companyID parameter
	hasPermission, err := h.companyService.CheckUserPermission(ctx, companyID, userID, permissionName)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to check user permission")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"has_permission": hasPermission,
		"user_id":        userID,
		"permission":     permissionName,
	}, "Permission check completed"))
}

// GetUserPermissions retrieves all permissions for a user across roles
func (h *RBACHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "User permissions retrieved successfully"))
}

// CreatePermission creates a new system permission (admin only)
func (h *RBACHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	var req struct {
		PermissionName string `json:"permission_name" validate:"required"`
		Description    string `json:"description"`
		Category       string `json:"category" validate:"required"`
		Module         string `json:"module" validate:"required"`
		Action         string `json:"action" validate:"required"`
		RequiresTier   string `json:"requires_tier,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	permission, err := h.companyService.CreatePermission(ctx, req.PermissionName, req.Description, req.Category, req.Module, req.RequiresTier)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create permission")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(permission, "Permission created successfully"))
}

// GetUserHierarchy retrieves the organizational hierarchy for a user
func (h *RBACHandler) GetUserHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	hierarchy, err := h.companyService.GetUserHierarchy(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user hierarchy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "User hierarchy retrieved successfully"))
}

// BulkAssignRoles bulk assigns roles to users
func (h *RBACHandler) BulkAssignRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value("user_id")
	if adminID == nil {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
		return
	}

	adminIDParsed, err := uuid.Parse(adminID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	var req struct {
		Assignments []service.BulkAssignment `json:"assignments" validate:"required,min=1"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	results, err := h.companyService.BulkAssignRoles(ctx, companyID, req.Assignments, adminIDParsed)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to bulk assign roles")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Bulk role assignment completed"))
}

// Helper methods
func (h *RBACHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *RBACHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("RBAC HTTP error",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}
