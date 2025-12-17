package handler

import (
    "auth-service/internal/models"
    "auth-service/internal/service"
    "auth-service/internal/util"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "strings"
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
// // CreateRole creates a new role for a company
// func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     // Get admin ID from context
//     adminID := r.Context().Value("user_id")
//     if adminID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     adminIDParsed, err := uuid.Parse(adminID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     var req struct {
//         RoleName        string      `json:"role_name" validate:"required"`
//         RoleLevel       int         `json:"role_level" validate:"required"`
//         Description     string      `json:"description"`
//         SystemRole      bool        `json:"system_role"`
//         DepartmentIDs   []uuid.UUID `json:"department_ids"`
//         PermissionNames []string    `json:"permission_names"` // Changed from PermissionIDs
//     }

//     // Use DisallowUnknownFields to reject extra fields
//     decoder := json.NewDecoder(r.Body)
//     decoder.DisallowUnknownFields()
//     if err := decoder.Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
//         return
//     }

//     // Validate permission names exist
//     if len(req.PermissionNames) > 0 {
//         allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
//         if err != nil {
//             h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
//             return
//         }

//         validPermissionNames := make(map[string]bool)
//         for _, perm := range allPermissions {
//             validPermissionNames[perm.PermissionName] = true
//         }

//         for _, permName := range req.PermissionNames {
//             if !validPermissionNames[permName] {
//                 h.respondWithError(w, http.StatusBadRequest,
//                     fmt.Errorf("PERMISSION_NOT_FOUND"),
//                     fmt.Sprintf("Permission not found: %s", permName))
//                 return
//             }
//         }

//         // Check if user has the permissions they're trying to assign
//         currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, adminIDParsed)
//         if err != nil {
//             h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate user permissions")
//             return
//         }

//         userPermMap := make(map[string]bool)
//         for _, perm := range currentUserPermissions {
//             userPermMap[perm.PermissionName] = true
//         }

//         for _, permName := range req.PermissionNames {
//             if !userPermMap[permName] {
//                 h.respondWithError(w, http.StatusForbidden,
//                     fmt.Errorf("PERMISSION_DENIED"),
//                     fmt.Sprintf("You cannot assign permission '%s' that you don't possess", permName))
//                 return
//             }
//         }
//     }

//     // Convert permission names to IDs
//     permissionIDs := []uuid.UUID{}
//     if len(req.PermissionNames) > 0 {
//         allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
//         if err != nil {
//             h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
//             return
//         }

//         permMap := make(map[string]uuid.UUID)
//         for _, perm := range allPermissions {
//             permMap[perm.PermissionName] = perm.PermissionID
//         }

//         for _, permName := range req.PermissionNames {
//             if permID, exists := permMap[permName]; exists {
//                 permissionIDs = append(permissionIDs, permID)
//             }
//         }
//     }

//     // ✅ ADDED: Validate permission-department compatibility
//     if len(req.DepartmentIDs) > 0 && len(permissionIDs) > 0 {
//         compatible, errorMsg, err := h.companyService.ValidatePermissionDepartmentCompatibility(
//             ctx, req.DepartmentIDs, permissionIDs)
//         if err != nil {
//             h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
//             return
//         }
//         if !compatible {
//             h.respondWithError(w, http.StatusBadRequest, 
//                 fmt.Errorf("PERMISSION_DEPARTMENT_MISMATCH"), errorMsg)
//             return
//         }
//     }

//     roleReq := &service.CreateRoleRequest{
//         CompanyID:     companyID,
//         RoleName:      req.RoleName,
//         RoleLevel:     req.RoleLevel,
//         Description:   req.Description,
//         DepartmentIDs: req.DepartmentIDs,
//         PermissionIDs: permissionIDs,
//         CreatedBy:     adminIDParsed,
//     }

//     role, err := h.companyService.CreateRole(ctx, roleReq)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create role")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
// }



// CreateRole creates a new role for a company
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

    // Get session type from context
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok {
        sessionType = ""
    }

    var req struct {
        RoleName        string      `json:"role_name" validate:"required"`
        RoleLevel       int         `json:"role_level" validate:"required"`
        Description     string      `json:"description"`
        SystemRole      bool        `json:"system_role"`
        DepartmentIDs   []uuid.UUID `json:"department_ids"`
        PermissionNames []string    `json:"permission_names"` // Changed from PermissionIDs
    }

    // Use DisallowUnknownFields to reject extra fields
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
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
            return
        }

        validPermissionNames := make(map[string]bool)
        for _, perm := range allPermissions {
            validPermissionNames[perm.PermissionName] = true
        }

        for _, permName := range req.PermissionNames {
            if !validPermissionNames[permName] {
                h.respondWithError(w, http.StatusBadRequest,
                    fmt.Errorf("PERMISSION_NOT_FOUND"),
                    fmt.Sprintf("Permission not found: %s", permName))
                return
            }
        }

        // ✅ MODIFIED: Only check if user has permissions if they are NOT an admin
        if sessionType != "admin" {
            currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, adminIDParsed)
            if err != nil {
                h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate user permissions")
                return
            }

            userPermMap := make(map[string]bool)
            for _, perm := range currentUserPermissions {
                userPermMap[perm.PermissionName] = true
            }

            for _, permName := range req.PermissionNames {
                if !userPermMap[permName] {
                    h.respondWithError(w, http.StatusForbidden,
                        fmt.Errorf("PERMISSION_DENIED"),
                        fmt.Sprintf("You cannot assign permission '%s' that you don't possess", permName))
                    return
                }
            }
        }
    }

    // Convert permission names to IDs
    permissionIDs := []uuid.UUID{}
    if len(req.PermissionNames) > 0 {
        allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
        if err != nil {
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
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

    // ✅ ADDED: Validate permission-department compatibility
    if len(req.DepartmentIDs) > 0 && len(permissionIDs) > 0 {
        compatible, errorMsg, err := h.companyService.ValidatePermissionDepartmentCompatibility(
            ctx, req.DepartmentIDs, permissionIDs)
        if err != nil {
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
            return
        }
        if !compatible {
            h.respondWithError(w, http.StatusBadRequest, 
                fmt.Errorf("PERMISSION_DEPARTMENT_MISMATCH"), errorMsg)
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
        CreatedBy:     adminIDParsed,
    }

    role, err := h.companyService.CreateRole(ctx, roleReq)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create role")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
}

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

    // Get admin ID from context - already validated by middleware
    adminID := r.Context().Value("user_id")
    if adminID == nil {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
        return
    }

    _, err = uuid.Parse(adminID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    var req struct {
        DepartmentName     string     `json:"department_name" validate:"required"`
        SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
        DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
        ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Create the department using service method
    departmentReq := &service.CreateDepartmentRequest{
        CompanyID:          companyID,
        DepartmentName:     req.DepartmentName,
        SystemDepartmentID: req.SystemDepartmentID,
        DepartmentHead:     req.DepartmentHead,
        ParentDepartmentID: req.ParentDepartmentID,
    }

    department, err := h.companyService.CreateDepartment(ctx, departmentReq)
    if err != nil {
        // Map specific errors to appropriate HTTP status codes
        statusCode := http.StatusInternalServerError
        message := "Failed to create department"

        switch {
        case strings.Contains(err.Error(), "only admin users"):
            statusCode = http.StatusForbidden
            message = "Only admin users can create departments"
        case strings.Contains(err.Error(), "company not found"):
            statusCode = http.StatusNotFound
            message = "Company not found"
        case strings.Contains(err.Error(), "company is not active"):
            statusCode = http.StatusConflict
            message = "Company is not active"
        case strings.Contains(err.Error(), "system department not found"):
            statusCode = http.StatusNotFound
            message = "System department not found"
        case strings.Contains(err.Error(), "already exists"):
            statusCode = http.StatusConflict
            message = err.Error()
        case strings.Contains(err.Error(), "department head not found"):
            statusCode = http.StatusBadRequest
            message = "Department head not found or is not active"
        case strings.Contains(err.Error(), "parent department not found"):
            statusCode = http.StatusBadRequest
            message = "Parent department not found"
        }

        h.respondWithError(w, statusCode, err, message)
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

    if err := h.companyService.UpdateDepartment(ctx, departmentID, req.Name, &req.Head, adminIDParsed); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update department")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department updated successfully"))
}
// DeactivateDepartment deactivates a department
func (h *RBACHandler) DeactivateDepartment(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Check session type - only admin can deactivate departments
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), 
            "Only admin users can deactivate departments")
        return
    }

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
// func (h *RBACHandler) AssignPermissionsToRole(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     roleIDStr := chi.URLParam(r, "roleID")
//     roleID, err := uuid.Parse(roleIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
//         return
//     }

//     // Get admin ID from context
//     adminID := r.Context().Value("user_id")
//     if adminID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     adminIDParsed, err := uuid.Parse(adminID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     var req struct {
//         PermissionNames []string `json:"permission_names" validate:"required,min=1"` // Changed from PermissionIDs
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if len(req.PermissionNames) == 0 {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission name is required")
//         return
//     }

//     // Convert permission names to IDs
//     allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
//         return
//     }

//     permMap := make(map[string]uuid.UUID)
//     for _, perm := range allPermissions {
//         permMap[perm.PermissionName] = perm.PermissionID
//     }

//     var permissionIDs []uuid.UUID
//     var invalidPermissions []string
//     for _, permName := range req.PermissionNames {
//         if permID, exists := permMap[permName]; exists {
//             permissionIDs = append(permissionIDs, permID)
//         } else {
//             invalidPermissions = append(invalidPermissions, permName)
//         }
//     }

//     if len(invalidPermissions) > 0 {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("INVALID_PERMISSIONS"),
//             fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
//         return
//     }

//     var grantedCount int
//     var errors []string

//     for _, permissionID := range permissionIDs {
//         if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
//             errors = append(errors, fmt.Sprintf("Failed to grant permission: %v", err))
//             continue
//         }
//         grantedCount++
//     }

//     if len(errors) > 0 {
//         h.respondWithError(w, http.StatusPartialContent,
//             fmt.Errorf("PARTIAL_FAILURE: %v", errors),
//             fmt.Sprintf("Successfully granted %d out of %d permissions", grantedCount, len(permissionIDs)))
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil,
//         fmt.Sprintf("All %d permissions granted successfully to role", grantedCount)))
// }
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

    // Get session type from context
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok {
        sessionType = ""
    }

    var req struct {
        PermissionNames []string `json:"permission_names" validate:"required,min=1"` // Changed from PermissionIDs
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if len(req.PermissionNames) == 0 {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission name is required")
        return
    }

    // Convert permission names to IDs
    allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
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
            fmt.Errorf("INVALID_PERMISSIONS"),
            fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
        return
    }

    // ✅ MODIFIED: Only validate user permissions if NOT admin
    if sessionType != "admin" {
        currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, adminIDParsed)
        if err != nil {
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate user permissions")
            return
        }

        userPermMap := make(map[string]bool)
        for _, perm := range currentUserPermissions {
            userPermMap[perm.PermissionName] = true
        }

        for _, permName := range req.PermissionNames {
            if !userPermMap[permName] {
                h.respondWithError(w, http.StatusForbidden,
                    fmt.Errorf("PERMISSION_DENIED"),
                    fmt.Sprintf("You cannot assign permission '%s' that you don't possess", permName))
                return
            }
        }
    }

    var grantedCount int
    var errors []string

    for _, permissionID := range permissionIDs {
        if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
            errors = append(errors, fmt.Sprintf("Failed to grant permission: %v", err))
            continue
        }
        grantedCount++
    }

    if len(errors) > 0 {
        h.respondWithError(w, http.StatusPartialContent,
            fmt.Errorf("PARTIAL_FAILURE: %v", errors),
            fmt.Sprintf("Successfully granted %d out of %d permissions", grantedCount, len(permissionIDs)))
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
        PermissionNames []string `json:"permission_names" validate:"required,min=1"` // Changed from PermissionIDs
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if len(req.PermissionNames) == 0 {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission name is required")
        return
    }

    // Convert permission names to IDs
    allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
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
            fmt.Errorf("INVALID_PERMISSIONS"),
            fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
        return
    }

    var revokedCount int
    var errors []string

    for _, permissionID := range permissionIDs {
        if err := h.companyService.RevokeRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
            errors = append(errors, fmt.Sprintf("Failed to revoke permission: %v", err))
            continue
        }
        revokedCount++
    }

    if len(errors) > 0 {
        h.respondWithError(w, http.StatusPartialContent,
            fmt.Errorf("PARTIAL_FAILURE: %v", errors),
            fmt.Sprintf("Successfully revoked %d out of %d permissions", revokedCount, len(permissionIDs)))
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
// func (h *RBACHandler) ReplaceRolePermissions(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     roleIDStr := chi.URLParam(r, "roleID")
//     roleID, err := uuid.Parse(roleIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
//         return
//     }

//     // Get admin ID from context
//     adminID := r.Context().Value("user_id")
//     if adminID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     adminIDParsed, err := uuid.Parse(adminID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     var req struct {
//         PermissionNames []string `json:"permission_names" validate:"required"` // Changed from PermissionIDs
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Convert permission names to IDs
//     allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
//         return
//     }

//     permMap := make(map[string]uuid.UUID)
//     for _, perm := range allPermissions {
//         permMap[perm.PermissionName] = perm.PermissionID
//     }

//     var permissionIDs []uuid.UUID
//     var invalidPermissions []string
//     for _, permName := range req.PermissionNames {
//         if permID, exists := permMap[permName]; exists {
//             permissionIDs = append(permissionIDs, permID)
//         } else {
//             invalidPermissions = append(invalidPermissions, permName)
//         }
//     }

//     if len(invalidPermissions) > 0 {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("INVALID_PERMISSIONS"),
//             fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
//         return
//     }

//     currentPermissions, _ := h.companyService.GetRolePermissions(ctx, roleID)

//     if len(currentPermissions) > 0 {
//         for _, perm := range currentPermissions {
//             _ = h.companyService.RevokeRolePermission(ctx, roleID, perm.PermissionID, adminIDParsed)
//         }
//     }

//     var grantedCount int
//     var errors []string

//     for _, permissionID := range permissionIDs {
//         if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
//             errors = append(errors, fmt.Sprintf("Failed to grant permission: %v", err))
//             continue
//         }
//         grantedCount++
//     }

//     response := map[string]interface{}{
//         "role_id":             roleID,
//         "permissions_granted": grantedCount,
//         "total_requested":     len(permissionIDs),
//         "errors":              errors,
//     }

//     if len(errors) > 0 {
//         h.respondWithError(w, http.StatusPartialContent,
//             fmt.Errorf("PARTIAL_FAILURE: %v", errors),
//             fmt.Sprintf("Role permissions replaced with %d out of %d permissions", grantedCount, len(permissionIDs)))
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response,
//         fmt.Sprintf("All %d permissions successfully assigned to role", grantedCount)))
// }
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

    // Get session type from context
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok {
        sessionType = ""
    }

    var req struct {
        PermissionNames []string `json:"permission_names" validate:"required"` // Changed from PermissionIDs
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Convert permission names to IDs
    allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
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
            fmt.Errorf("INVALID_PERMISSIONS"),
            fmt.Sprintf("Invalid permission names: %v", invalidPermissions))
        return
    }

    // ✅ MODIFIED: Only validate user permissions if NOT admin
    if sessionType != "admin" {
        currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, adminIDParsed)
        if err != nil {
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate user permissions")
            return
        }

        userPermMap := make(map[string]bool)
        for _, perm := range currentUserPermissions {
            userPermMap[perm.PermissionName] = true
        }

        for _, permName := range req.PermissionNames {
            if !userPermMap[permName] {
                h.respondWithError(w, http.StatusForbidden,
                    fmt.Errorf("PERMISSION_DENIED"),
                    fmt.Sprintf("You cannot assign permission '%s' that you don't possess", permName))
                return
            }
        }
    }

    currentPermissions, _ := h.companyService.GetRolePermissions(ctx, roleID)

    if len(currentPermissions) > 0 {
        for _, perm := range currentPermissions {
            _ = h.companyService.RevokeRolePermission(ctx, roleID, perm.PermissionID, adminIDParsed)
        }
    }

    var grantedCount int
    var errors []string

    for _, permissionID := range permissionIDs {
        if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
            errors = append(errors, fmt.Sprintf("Failed to grant permission: %v", err))
            continue
        }
        grantedCount++
    }

    response := map[string]interface{}{
        "role_id":             roleID,
        "permissions_granted": grantedCount,
        "total_requested":     len(permissionIDs),
        "errors":              errors,
    }

    if len(errors) > 0 {
        h.respondWithError(w, http.StatusPartialContent,
            fmt.Errorf("PARTIAL_FAILURE: %v", errors),
            fmt.Sprintf("Role permissions replaced with %d out of %d permissions", grantedCount, len(permissionIDs)))
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(response,
        fmt.Sprintf("All %d permissions successfully assigned to role", grantedCount)))
}

// DeleteDepartment permanently deletes a department and its role mappings (admin only)
func (h *RBACHandler) DeleteDepartment(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Check session type - only admin can delete departments
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok || sessionType != "admin" {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), 
            "Only admin users can delete departments")
        return
    }

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

    if err := h.companyService.DeleteDepartment(ctx, departmentID, adminIDParsed); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to delete department")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department and its role mappings deleted successfully"))
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

    companyIDStr := chi.URLParam(r, "companyID")
    _, err = uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
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

// GetUserPermissionBitmask retrieves user permissions with bitmask
func (h *RBACHandler) GetUserPermissionBitmask(w http.ResponseWriter, r *http.Request) {
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

    // Get permission names
    permissions, err := h.companyService.GetUserPermissions(ctx, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permissions")
        return
    }

    permissionNames := make([]string, len(permissions))
    for i, perm := range permissions {
        permissionNames[i] = perm.PermissionName
    }

    // Get permission mask
    permissionMask, err := h.companyService.GetUserPermissionBitmask(ctx, companyID, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permission bitmask")
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

// RenameDepartment renames a department (only updates the name)
func (h *RBACHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

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

    // Get user ID from context
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    var req struct {
        DepartmentName string `json:"department_name" validate:"required"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Sanitize input
    req.DepartmentName = util.SanitizeInput(req.DepartmentName)

    // Call the service method
    if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName); err != nil {
        statusCode := http.StatusInternalServerError
        if strings.Contains(err.Error(), "permission") {
            statusCode = http.StatusForbidden
        } else if strings.Contains(err.Error(), "not found") {
            statusCode = http.StatusNotFound
        } else if strings.Contains(err.Error(), "Invalid") {
            statusCode = http.StatusBadRequest
        }
        h.respondWithError(w, statusCode, err, "Failed to rename department")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))

    h.logger.Info("Department renamed via RBAC",
        util.String("company_id", companyID.String()),
        util.String("department_id", departmentID.String()),
        util.String("new_name", req.DepartmentName),
        util.String("updated_by", userIDParsed.String()),
        util.Duration("duration", time.Since(startTime)))
}

// In rbac_handler.go - Update the ListAllPermissions method
func (h *RBACHandler) ListAllPermissions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    companyIDStr := chi.URLParam(r, "companyID")
    _, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    // Get query parameters for filtering
    module := r.URL.Query().Get("module")
    category := r.URL.Query().Get("category")
    tier := r.URL.Query().Get("tier")

    // Use GetAllPermissions instead of GetPermissionsByCompanyDepartments
    // This will return ALL permissions regardless of company departments
    permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "All permissions retrieved successfully"))
}

// AddEmployee creates a new employee without permissions field
func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

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
    }

    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&req); err != nil {
        if strings.Contains(err.Error(), "unknown field") {
            h.respondWithError(w, http.StatusBadRequest, err,
                "Invalid request: 'permissions' or 'department_id' fields are not allowed. Permissions and departments are assigned at role level only.")
            return
        }
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    currentUserID := r.Context().Value("user_id")
    if currentUserID == nil {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
        return
    }

    _, err = uuid.Parse(currentUserID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    role, err := h.companyService.GetRole(ctx, req.RoleID)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
        return
    }

    if role.CompanyID != companyID {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_ROLE"),
            "Role does not belong to this company")
        return
    }

    if req.ReportsTo != nil {
        isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
        if err != nil || !isActive {
            h.respondWithError(w, http.StatusBadRequest,
                fmt.Errorf("INVALID_REPORTS_TO"),
                "Reports-to employee not found or not active")
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
    }

    if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
        statusCode := http.StatusInternalServerError
        message := "Failed to add employee"

        switch {
        case strings.Contains(err.Error(), "max employee limit reached"):
            statusCode = http.StatusConflict
            message = err.Error()
        case strings.Contains(err.Error(), "already an active employee"):
            statusCode = http.StatusConflict
            message = err.Error()
        case strings.Contains(err.Error(), "company is not active"):
            statusCode = http.StatusConflict
            message = err.Error()
        }

        h.respondWithError(w, statusCode, err, message)
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
}

// UpdateEmployeeDepartment updates an employee's role (which changes their department via role_departments)
func (h *RBACHandler) UpdateEmployeeDepartment(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

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

    currentUserID := r.Context().Value("user_id")
    if currentUserID == nil {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
        return
    }

    updatedBy, err := uuid.Parse(currentUserID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    var req struct {
        NewRoleID uuid.UUID `json:"new_role_id" validate:"required"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Check if the new role exists and belongs to the company
    newRole, err := h.companyService.GetRole(ctx, req.NewRoleID)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "New role not found")
        return
    }

    if newRole.CompanyID != companyID {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_ROLE"),
            "New role does not belong to this company")
        return
    }

    // Update employee's role (which indirectly changes their department via role_departments)
    if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.NewRoleID, updatedBy); err != nil {
        statusCode := http.StatusInternalServerError
        message := "Failed to update employee role"

        switch {
        case strings.Contains(err.Error(), "employee not found"):
            statusCode = http.StatusNotFound
            message = err.Error()
        case strings.Contains(err.Error(), "permission"):
            statusCode = http.StatusForbidden
            message = err.Error()
        }

        h.respondWithError(w, statusCode, err, message)
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role (and thus department) updated successfully"))
}

// AddManager creates a new manager using role_id instead of role_name
func (h *RBACHandler) AddManager(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    companyIDStr := chi.URLParam(r, "companyID")
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    // Get current user ID from context
    currentUserID := r.Context().Value("user_id")
    if currentUserID == nil {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
        return
    }

    _, err = uuid.Parse(currentUserID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    var req struct {
        PhoneNumber string     `json:"phone" validate:"required"`
        Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
        FullName    string     `json:"full_name" validate:"required,max=255"`
        EmployeeID  string     `json:"employee_id" validate:"required"`
        RoleID      uuid.UUID  `json:"role_id" validate:"required"`
        ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`
        // NO permissions field here
    }

    // Use DisallowUnknownFields to reject "permissions" field
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&req); err != nil {
        if strings.Contains(err.Error(), "unknown field") {
            h.respondWithError(w, http.StatusBadRequest, err,
                "Invalid request: 'permissions' field is not allowed. Permissions are assigned at role level only.")
            return
        }
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Verify the role exists and is valid for manager (role level 500 or higher)
    role, err := h.companyService.GetRole(ctx, req.RoleID)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
        return
    }

    // Check if role belongs to the company
    if role.CompanyID != companyID {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_ROLE"),
            "Role does not belong to this company")
        return
    }

    // Check if role level is appropriate for manager (typically 500 or higher)
    if role.RoleLevel < 500 {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_ROLE_LEVEL"),
            "Role level must be 500 or higher for managers")
        return
    }

    // Validate reports_to if provided
    if req.ReportsTo != nil {
        // Check if reports_to employee exists and is active
        isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
        if err != nil || !isActive {
            h.respondWithError(w, http.StatusBadRequest,
                fmt.Errorf("INVALID_REPORTS_TO"),
                "Reports-to employee not found or not active")
            return
        }
    }

    // Create manager using the same AddEmployeeRequest (managers are just employees with higher-level roles)
    managerReq := &service.AddEmployeeRequest{
        CompanyID:   companyID,
        PhoneNumber: req.PhoneNumber,
        Username:    req.Username,
        FullName:    req.FullName,
        EmployeeID:  req.EmployeeID,
        RoleID:      req.RoleID,
        ReportsTo:   req.ReportsTo,
    }

    if err := h.companyService.AddEmployee(ctx, managerReq); err != nil {
        statusCode := http.StatusInternalServerError
        message := "Failed to add manager"

        switch {
        case strings.Contains(err.Error(), "max employee limit reached"):
            statusCode = http.StatusConflict
            message = err.Error()
        case strings.Contains(err.Error(), "already an active employee"):
            statusCode = http.StatusConflict
            message = err.Error()
        case strings.Contains(err.Error(), "company is not active"):
            statusCode = http.StatusConflict
            message = err.Error()
        }

        h.respondWithError(w, statusCode, err, message)
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))
}

// // GetAvailablePermissions returns permissions that the current user can assign
// func (h *RBACHandler) GetAvailablePermissions(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     // Get current user ID from context
//     currentUserID := r.Context().Value("user_id")
//     if currentUserID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
//         return
//     }

//     // Get current user's permissions
//     currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user permissions")
//         return
//     }

//     // Get all permissions available for the company
//     allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get available permissions")
//         return
//     }

//     // Filter permissions to only those the user has
//     userPermMap := make(map[string]bool)
//     for _, perm := range currentUserPermissions {
//         userPermMap[perm.PermissionName] = true
//     }

//     var availablePermissions []*models.Permission
//     for _, perm := range allPermissions {
//         if userPermMap[perm.PermissionName] {
//             availablePermissions = append(availablePermissions, perm)
//         }
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(availablePermissions, "Available permissions retrieved successfully"))
// }

// GetAvailablePermissions returns permissions that the current user can assign
func (h *RBACHandler) GetAvailablePermissions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    companyIDStr := chi.URLParam(r, "companyID")
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    // Get current user ID from context
    currentUserID := r.Context().Value("user_id")
    if currentUserID == nil {
        h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
        return
    }

    currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    // Get session type from context
    sessionType, ok := ctx.Value("session_type").(string)
    if !ok {
        sessionType = ""
    }

    // ✅ MODIFIED: If admin, return all permissions without filtering
    if sessionType == "admin" {
        allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
        if err != nil {
            h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get available permissions")
            return
        }
        h.respondWithJSON(w, http.StatusOK, successResponse(allPermissions, "Available permissions retrieved successfully"))
        return
    }

    // Get current user's permissions (for non-admin users)
    currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user permissions")
        return
    }

    // Get all permissions available for the company
    allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get available permissions")
        return
    }

    // Filter permissions to only those the user has
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

// package handler

// import (
// 	"auth-service/internal/models"
// 	"auth-service/internal/service"
// 	"auth-service/internal/util"
// 	"encoding/json"
// 	"fmt"
// 	"net/http"
// 	"strconv"
// 	"strings"
// 	"time"

// 	"github.com/go-chi/chi/v5"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// // RBACHandler handles RBAC operations for companies
// type RBACHandler struct {
// 	companyService *service.CompanyService
// 	logger         *zap.Logger
// }

// func NewRBACHandler(companyService *service.CompanyService, logger *zap.Logger) *RBACHandler {
// 	return &RBACHandler{
// 		companyService: companyService,
// 		logger:         logger,
// 	}
// }
// // CreateRole creates a new role for a company
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
// 		RoleName      string      `json:"role_name" validate:"required"`
// 		RoleLevel     int         `json:"role_level" validate:"required"`
// 		Description   string      `json:"description"`
// 		SystemRole    bool        `json:"system_role"`
// 		DepartmentIDs []uuid.UUID `json:"department_ids"`
// 		PermissionIDs []uuid.UUID `json:"permission_ids"` // Changed from nested struct to direct array
// 	}

// 	// Use DisallowUnknownFields to reject extra fields
// 	decoder := json.NewDecoder(r.Body)
// 	decoder.DisallowUnknownFields()
// 	if err := decoder.Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body: unknown fields not allowed")
// 		return
// 	}

// 	// Validate permission IDs exist in system
// 	if len(req.PermissionIDs) > 0 {
// 		// Get all available permissions from the system
// 		allPermissions, err := h.companyService.GetAllPermissions(ctx, "", "", "")
// 		if err != nil {
// 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
// 			return
// 		}

// 		// Create map of valid permission IDs
// 		validPermissionIDs := make(map[uuid.UUID]bool)
// 		for _, perm := range allPermissions {
// 			validPermissionIDs[perm.PermissionID] = true
// 		}

// 		// Check each requested permission ID
// 		for _, permID := range req.PermissionIDs {
// 			if !validPermissionIDs[permID] {
// 				h.respondWithError(w, http.StatusBadRequest, 
// 					fmt.Errorf("PERMISSION_NOT_FOUND"), 
// 					fmt.Sprintf("Permission ID not found: %s", permID))
// 				return
// 			}
// 		}

// 		// Check if current user has all these permissions
// 		currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, adminIDParsed)
// 		if err != nil {
// 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate user permissions")
// 			return
// 		}

// 		userPermMap := make(map[uuid.UUID]bool)
// 		for _, perm := range currentUserPermissions {
// 			userPermMap[perm.PermissionID] = true
// 		}

// 		for _, permID := range req.PermissionIDs {
// 			if !userPermMap[permID] {
// 				// Get permission name for better error message
// 				for _, perm := range allPermissions {
// 					if perm.PermissionID == permID {
// 						h.respondWithError(w, http.StatusForbidden,
// 							fmt.Errorf("PERMISSION_DENIED"),
// 							fmt.Sprintf("You cannot assign permission '%s' that you don't possess", perm.PermissionName))
// 						return
// 					}
// 				}
// 				h.respondWithError(w, http.StatusForbidden,
// 					fmt.Errorf("PERMISSION_DENIED"),
// 					fmt.Sprintf("You cannot assign permission ID %s that you don't possess", permID))
// 				return
// 			}
// 		}
// 	}

// 	// Create the role using existing service method
// 	roleReq := &service.CreateRoleRequest{
// 		CompanyID:     companyID,
// 		RoleName:      req.RoleName,
// 		RoleLevel:     req.RoleLevel,
// 		Description:   req.Description,
// 		DepartmentIDs: req.DepartmentIDs,
// 		PermissionIDs: req.PermissionIDs,
// 		CreatedBy:     adminIDParsed,
// 	}

// 	role, err := h.companyService.CreateRole(ctx, roleReq)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))
// }
// // ListRoles lists all roles for a company
// func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
// 	if page <= 0 {
// 		page = 1
// 	}

// 	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
// 	if limit <= 0 || limit > 100 {
// 		limit = 50
// 	}

// 	includePermissions := r.URL.Query().Get("include_permissions") == "true"

// 	roles, total, err := h.companyService.ListRoles(ctx, companyID, limit, (page-1)*limit, includePermissions)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list roles")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
// 		"roles": roles,
// 		"total": total,
// 		"page":  page,
// 		"limit": limit,
// 	}, "Roles retrieved successfully"))
// }

// // GetRole retrieves a specific role with permissions
// func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
// 		return
// 	}

// 	role, err := h.companyService.GetRole(ctx, roleID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusNotFound, err, "Role not found")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Role retrieved successfully"))
// }

// // UpdateRole updates a role
// func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
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
// 		IsActive    *bool  `json:"is_active"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if err := h.companyService.UpdateRole(ctx, roleID, req.RoleName, req.RoleLevel, adminIDParsed, req.Description); err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role updated successfully"))
// }

// // DeleteRole deletes a role
// func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
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

// 	if err := h.companyService.DeleteRole(ctx, roleID, adminIDParsed); err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to delete role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Role deleted successfully"))
// }

// // CreateDepartment creates a new department
// func (h *RBACHandler) CreateDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get admin ID from context - already validated by middleware
// 	adminID := r.Context().Value("user_id")
// 	if adminID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// 		return
// 	}

// 	_, err = uuid.Parse(adminID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
// 		return
// 	}

// 	var req struct {
// 		DepartmentName     string    `json:"department_name" validate:"required"`
// 		SystemDepartmentID uuid.UUID `json:"system_department_id" validate:"required"`
// 		DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
// 		ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Create the department using service method
// 	departmentReq := &service.CreateDepartmentRequest{
// 		CompanyID:          companyID,
// 		DepartmentName:     req.DepartmentName,
// 		SystemDepartmentID: req.SystemDepartmentID,
// 		DepartmentHead:     req.DepartmentHead,
// 		ParentDepartmentID: req.ParentDepartmentID,
// 	}

// 	department, err := h.companyService.CreateDepartment(ctx, departmentReq)
// 	if err != nil {
// 		// Map specific errors to appropriate HTTP status codes
// 		statusCode := http.StatusInternalServerError
// 		message := "Failed to create department"
		
// 		switch {
// 		case strings.Contains(err.Error(), "only admin users"):
// 			statusCode = http.StatusForbidden
// 			message = "Only admin users can create departments"
// 		case strings.Contains(err.Error(), "company not found"):
// 			statusCode = http.StatusNotFound
// 			message = "Company not found"
// 		case strings.Contains(err.Error(), "company is not active"):
// 			statusCode = http.StatusConflict
// 			message = "Company is not active"
// 		case strings.Contains(err.Error(), "system department not found"):
// 			statusCode = http.StatusNotFound
// 			message = "System department not found"
// 		case strings.Contains(err.Error(), "already exists"):
// 			statusCode = http.StatusConflict
// 			message = err.Error()
// 		case strings.Contains(err.Error(), "department head not found"):
// 			statusCode = http.StatusBadRequest
// 			message = "Department head not found or is not active"
// 		case strings.Contains(err.Error(), "parent department not found"):
// 			statusCode = http.StatusBadRequest
// 			message = "Parent department not found"
// 		}
		
// 		h.respondWithError(w, statusCode, err, message)
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department created successfully"))
// }
// // ListDepartments lists all departments for a company
// func (h *RBACHandler) ListDepartments(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
// 	if page <= 0 {
// 		page = 1
// 	}

// 	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
// 	if limit <= 0 || limit > 100 {
// 		limit = 50
// 	}

// 	includeEmployees := r.URL.Query().Get("include_employees") == "true"

// 	departments, total, err := h.companyService.ListDepartments(ctx, companyID, limit, (page-1)*limit, includeEmployees)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list departments")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
// 		"departments": departments,
// 		"total":       total,
// 		"page":        page,
// 		"limit":       limit,
// 	}, "Departments retrieved successfully"))
// }

// // UpdateDepartment updates a department
// func (h *RBACHandler) UpdateDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	departmentIDStr := chi.URLParam(r, "departmentID")
// 	departmentID, err := uuid.Parse(departmentIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
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
// 		Name        string    `json:"name" validate:"required"`
// 		Head        uuid.UUID `json:"head,omitempty"`
// 		Description string    `json:"description"`
// 		IsActive    *bool     `json:"is_active"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if err := h.companyService.UpdateDepartment(ctx, departmentID, req.Name, &req.Head, adminIDParsed); err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department updated successfully"))
// }

// // DeactivateDepartment deactivates a department
// func (h *RBACHandler) DeactivateDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	departmentIDStr := chi.URLParam(r, "departmentID")
// 	departmentID, err := uuid.Parse(departmentIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
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

// 	if err := h.companyService.DeactivateDepartment(ctx, departmentID, adminIDParsed); err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to deactivate department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department deactivated successfully"))
// }

// // AssignPermissionsToRole assigns permissions to a role
// func (h *RBACHandler) AssignPermissionsToRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
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
// 		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required,min=1"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if len(req.PermissionIDs) == 0 {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission ID is required")
// 		return
// 	}

// 	// Grant each permission to the role
// 	var grantedCount int
// 	var errors []string

// 	for _, permissionID := range req.PermissionIDs {
// 		if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
// 			errors = append(errors, fmt.Sprintf("Failed to grant permission %s: %v", permissionID, err))
// 			continue
// 		}
// 		grantedCount++
// 	}

// 	if len(errors) > 0 {
// 		h.respondWithError(w, http.StatusPartialContent,
// 			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
// 			fmt.Sprintf("Successfully granted %d out of %d permissions", grantedCount, len(req.PermissionIDs)))
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
// 		fmt.Sprintf("All %d permissions granted successfully to role", grantedCount)))
// }

// // RemovePermissionsFromRole removes permissions from a role
// func (h *RBACHandler) RemovePermissionsFromRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
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
// 		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required,min=1"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if len(req.PermissionIDs) == 0 {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSIONS"), "At least one permission ID is required")
// 		return
// 	}

// 	// Revoke each permission from the role
// 	var revokedCount int
// 	var errors []string

// 	for _, permissionID := range req.PermissionIDs {
// 		if err := h.companyService.RevokeRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
// 			errors = append(errors, fmt.Sprintf("Failed to revoke permission %s: %v", permissionID, err))
// 			continue
// 		}
// 		revokedCount++
// 	}

// 	if len(errors) > 0 {
// 		h.respondWithError(w, http.StatusPartialContent,
// 			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
// 			fmt.Sprintf("Successfully revoked %d out of %d permissions", revokedCount, len(req.PermissionIDs)))
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil,
// 		fmt.Sprintf("All %d permissions revoked successfully from role", revokedCount)))
// }

// // GetRolePermissions retrieves all permissions for a role
// func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
// 		return
// 	}

// 	permissions, err := h.companyService.GetRolePermissions(ctx, roleID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve role permissions")
// 		return
// 	}

// 	// Convert to a more structured response
// 	type PermissionResponse struct {
// 		PermissionID   uuid.UUID `json:"permission_id"`
// 		PermissionName string    `json:"permission_name"`
// 		Description    string    `json:"description"`
// 		Category       string    `json:"category"`
// 		Module         string    `json:"module"`
// 		Action         string    `json:"action"`
// 		RequiresTier   string    `json:"requires_tier,omitempty"`
// 		CreatedAt      string    `json:"created_at"`
// 	}

// 	response := make([]PermissionResponse, len(permissions))
// 	for i, perm := range permissions {
// 		response[i] = PermissionResponse{
// 			PermissionID:   perm.PermissionID,
// 			PermissionName: perm.PermissionName,
// 			Description:    perm.Description,
// 			Category:       perm.Category,
// 			Module:         perm.Module,
// 			RequiresTier:   perm.RequiresTier,
// 			CreatedAt:      perm.CreatedAt.Format(time.RFC3339),
// 		}
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Role permissions retrieved successfully"))
// }

// // GetPermissionByName retrieves a permission by name
// func (h *RBACHandler) GetPermissionByName(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	permissionName := chi.URLParam(r, "permissionName")
// 	if permissionName == "" {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSION_NAME"), "Permission name is required")
// 		return
// 	}

// 	permission, err := h.companyService.GetPermissionByName(ctx, permissionName)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusNotFound, err, "Permission not found")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(permission, "Permission retrieved successfully"))
// }

// // // ListAllPermissions retrieves all available permissions
// // func (h *RBACHandler) ListAllPermissions(w http.ResponseWriter, r *http.Request) {
// // 	ctx := r.Context()

// // 	// Get query parameters for filtering
// // 	module := r.URL.Query().Get("module")
// // 	category := r.URL.Query().Get("category")
// // 	tier := r.URL.Query().Get("tier")

// // 	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions")
// // 		return
// // 	}

// // 	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "All permissions retrieved successfully"))
// // }

// // ListPermissionsByModule retrieves permissions by module
// func (h *RBACHandler) ListPermissionsByModule(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	module := chi.URLParam(r, "module")
// 	if module == "" {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_MODULE"), "Module name is required")
// 		return
// 	}

// 	permissions, err := h.companyService.ListPermissionsByModule(ctx, module)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions by module")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(permissions,
// 		fmt.Sprintf("Permissions for module '%s' retrieved successfully", module)))
// }

// // ReplaceRolePermissions replaces all permissions for a role (overwrite existing)
// func (h *RBACHandler) ReplaceRolePermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
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
// 		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// First, get current permissions to show what changed
// 	currentPermissions, _ := h.companyService.GetRolePermissions(ctx, roleID)

// 	// Revoke all current permissions first
// 	if len(currentPermissions) > 0 {
// 		for _, perm := range currentPermissions {
// 			_ = h.companyService.RevokeRolePermission(ctx, roleID, perm.PermissionID, adminIDParsed)
// 		}
// 	}

// 	// Grant new permissions
// 	var grantedCount int
// 	var errors []string

// 	for _, permissionID := range req.PermissionIDs {
// 		if err := h.companyService.GrantRolePermission(ctx, roleID, permissionID, adminIDParsed); err != nil {
// 			errors = append(errors, fmt.Sprintf("Failed to grant permission %s: %v", permissionID, err))
// 			continue
// 		}
// 		grantedCount++
// 	}

// 	response := map[string]interface{}{
// 		"role_id":             roleID,
// 		"permissions_granted": grantedCount,
// 		"total_requested":     len(req.PermissionIDs),
// 		"errors":              errors,
// 	}

// 	if len(errors) > 0 {
// 		h.respondWithError(w, http.StatusPartialContent,
// 			fmt.Errorf("PARTIAL_FAILURE: %v", errors),
// 			fmt.Sprintf("Role permissions replaced with %d out of %d permissions", grantedCount, len(req.PermissionIDs)))
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response,
// 		fmt.Sprintf("All %d permissions successfully assigned to role", grantedCount)))
// }

// // CheckUserPermission checks if a user has a specific permission
// func (h *RBACHandler) CheckUserPermission(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	permissionName := r.URL.Query().Get("permission")
// 	if permissionName == "" {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("EMPTY_PERMISSION"), "Permission name is required")
// 		return
// 	}

// 	hasPermission, err := h.companyService.CheckUserPermission(ctx, companyID, userID, permissionName)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to check user permission")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
// 		"has_permission": hasPermission,
// 		"user_id":        userID,
// 		"permission":     permissionName,
// 	}, "Permission check completed"))
// }

// // GetUserPermissions retrieves all permissions for a user across roles
// func (h *RBACHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	_, err = uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "User permissions retrieved successfully"))
// }

// // CreatePermission creates a new system permission (admin only)
// func (h *RBACHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	// Get admin ID from context
// 	adminID := r.Context().Value("user_id")
// 	if adminID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// 		return
// 	}

// 	var req struct {
// 		PermissionName string `json:"permission_name" validate:"required"`
// 		Description    string `json:"description"`
// 		Category       string `json:"category" validate:"required"`
// 		Module         string `json:"module" validate:"required"`
// 		Action         string `json:"action" validate:"required"`
// 		RequiresTier   string `json:"requires_tier,omitempty"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	permission, err := h.companyService.CreatePermission(ctx, req.PermissionName, req.Description, req.Category, req.Module, req.RequiresTier)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create permission")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(permission, "Permission created successfully"))
// }

// // GetUserHierarchy retrieves the organizational hierarchy for a user
// func (h *RBACHandler) GetUserHierarchy(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	hierarchy, err := h.companyService.GetUserHierarchy(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user hierarchy")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "User hierarchy retrieved successfully"))
// }

// // BulkAssignRoles bulk assigns roles to users
// func (h *RBACHandler) BulkAssignRoles(w http.ResponseWriter, r *http.Request) {
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
// 		Assignments []service.BulkAssignment `json:"assignments" validate:"required,min=1"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	results, err := h.companyService.BulkAssignRoles(ctx, companyID, req.Assignments, adminIDParsed)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to bulk assign roles")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Bulk role assignment completed"))
// }

// // GetUserPermissionBitmask retrieves user permissions with bitmask
// func (h *RBACHandler) GetUserPermissionBitmask(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get permission names
// 	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permissions")
// 		return
// 	}

// 	permissionNames := make([]string, len(permissions))
// 	for i, perm := range permissions {
// 		permissionNames[i] = perm.PermissionName
// 	}

// 	// Get permission mask
// 	permissionMask, err := h.companyService.GetUserPermissionBitmask(ctx, companyID, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve user permission bitmask")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
// 		"user_id":          userID,
// 		"company_id":       companyID,
// 		"permissions":      permissionNames,
// 		"permission_mask":  permissionMask,
// 		"permission_count": len(permissionNames),
// 	}, "User permissions with bitmask retrieved successfully"))
// }

// // Helper methods
// func (h *RBACHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	json.NewEncoder(w).Encode(data)
// }

// func (h *RBACHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
// 	h.logger.Warn("RBAC HTTP error",
// 		util.ErrorField(err),
// 		util.Int("status_code", statusCode),
// 		util.String("message", message),
// 	)
// 	h.respondWithJSON(w, statusCode, errorResponse(err, message))
// }

// // RenameDepartment renames a department (only updates the name)
// func (h *RBACHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	departmentIDStr := chi.URLParam(r, "departmentID")
// 	departmentID, err := uuid.Parse(departmentIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
// 		return
// 	}

// 	// Get user ID from context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req struct {
// 		DepartmentName string `json:"department_name" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize input
// 	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

// 	// Call the service method
// 	if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName); err != nil {
// 		statusCode := http.StatusInternalServerError
// 		if strings.Contains(err.Error(), "permission") {
// 			statusCode = http.StatusForbidden
// 		} else if strings.Contains(err.Error(), "not found") {
// 			statusCode = http.StatusNotFound
// 		} else if strings.Contains(err.Error(), "Invalid") {
// 			statusCode = http.StatusBadRequest
// 		}
// 		h.respondWithError(w, statusCode, err, "Failed to rename department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))

// 	h.logger.Info("Department renamed via RBAC",
// 		util.String("company_id", companyID.String()),
// 		util.String("department_id", departmentID.String()),
// 		util.String("new_name", req.DepartmentName),
// 		util.String("updated_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // In rbac_handler.go - Update the ListAllPermissions method
// func (h *RBACHandler) ListAllPermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	_, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get query parameters for filtering
// 	module := r.URL.Query().Get("module")
// 	category := r.URL.Query().Get("category")
// 	tier := r.URL.Query().Get("tier")

// 	// Use GetAllPermissions instead of GetPermissionsByCompanyDepartments
// 	// This will return ALL permissions regardless of company departments
// 	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to retrieve permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "All permissions retrieved successfully"))
// } // AddEmployee creates a new employee with restricted permissions
// // func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
// // 	ctx := r.Context()

// // 	companyIDStr := chi.URLParam(r, "companyID")
// // 	companyID, err := uuid.Parse(companyIDStr)
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// // 		return
// // 	}

// // 	// Get current user ID from context
// // 	currentUserID := r.Context().Value("user_id")
// // 	if currentUserID == nil {
// // 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// // 		return
// // 	}

// // 	currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// // 		return
// // 	}

// // 	var req struct {
// // 		PhoneNumber  string     `json:"phone" validate:"required"`
// // 		EmployeeID   string     `json:"employee_id" validate:"required"`
// // 		RoleID       uuid.UUID  `json:"role_id" validate:"required"`
// // 		DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// // 		ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// // 		Permissions  []string   `json:"permissions"` // Only permissions the current user has
// // 	}

// // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// // 		return
// // 	}

// // 	// Validate that current user can only assign permissions they have
// // 	if len(req.Permissions) > 0 {
// // 		// Get current user's permissions
// // 		currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
// // 		if err != nil {
// // 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
// // 			return
// // 		}

// // 		// Convert to map for easy lookup
// // 		userPermMap := make(map[string]bool)
// // 		for _, perm := range currentUserPermissions {
// // 			userPermMap[perm.PermissionName] = true
// // 		}

// // 		// Validate each requested permission
// // 		for _, reqPerm := range req.Permissions {
// // 			if !userPermMap[reqPerm] {
// // 				h.respondWithError(w, http.StatusForbidden,
// // 					fmt.Errorf("PERMISSION_DENIED"),
// // 					fmt.Sprintf("You cannot assign permission '%s' that you don't possess", reqPerm))
// // 				return
// // 			}
// // 		}
// // 	}

// // 	// Create employee using service
// // 	employeeReq := &service.AddEmployeeRequest{
// // 		CompanyID:    companyID,
// // 		PhoneNumber:  req.PhoneNumber,
// // 		EmployeeID:   req.EmployeeID,
// // 		RoleID:       req.RoleID,
// // 		DepartmentID: req.DepartmentID,
// // 		ReportsTo:    req.ReportsTo,
// // 		Permissions:  req.Permissions,
// // 	}

// // 	// Check if current user is manager to use manager-specific flow
// // 	sessionType, _ := ctx.Value("session_type").(string)
// // 	if sessionType != "admin" {
// // 		// Use manager flow which validates department restrictions
// // 		if err := h.companyService.ManagerAddEmployee(ctx, employeeReq, currentUserIDParsed); err != nil {
// // 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add employee")
// // 			return
// // 		}
// // 	} else {
// // 		// Use admin flow (full access)
// // 		if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
// // 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add employee")
// // 			return
// // 		}
// // 	}

// // 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
// // }

// // AddManager creates a new manager with restricted permissions
// // func (h *RBACHandler) AddManager(w http.ResponseWriter, r *http.Request) {
// // 	ctx := r.Context()

// // 	companyIDStr := chi.URLParam(r, "companyID")
// // 	companyID, err := uuid.Parse(companyIDStr)
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// // 		return
// // 	}

// // 	// Get current user ID from context
// // 	currentUserID := r.Context().Value("user_id")
// // 	if currentUserID == nil {
// // 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// // 		return
// // 	}

// // 	currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// // 		return
// // 	}

// // 	var req struct {
// // 		PhoneNumber  string     `json:"phone" validate:"required"`
// // 		RoleName     string     `json:"role_name" validate:"required"`
// // 		DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// // 		ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// // 		Permissions  []string   `json:"permissions" validate:"required,min=1"` // Only permissions the current user has
// // 	}

// // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// // 		return
// // 	}

// // 	// Validate that current user can only assign permissions they have
// // 	currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
// // 		return
// // 	}

// // 	// Convert to map for easy lookup
// // 	userPermMap := make(map[string]bool)
// // 	for _, perm := range currentUserPermissions {
// // 		userPermMap[perm.PermissionName] = true
// // 	}

// // 	// Validate each requested permission
// // 	for _, reqPerm := range req.Permissions {
// // 		if !userPermMap[reqPerm] {
// // 			h.respondWithError(w, http.StatusForbidden,
// // 				fmt.Errorf("PERMISSION_DENIED"),
// // 				fmt.Sprintf("You cannot assign permission '%s' that you don't possess", reqPerm))
// // 			return
// // 		}
// // 	}

// // 	// Create manager using service
// // 	managerReq := &service.AddManagerRequest{
// // 		CompanyID:    companyID,
// // 		PhoneNumber:  req.PhoneNumber,
// // 		RoleName:     req.RoleName,
// // 		DepartmentID: req.DepartmentID,
// // 		ReportsTo:    req.ReportsTo,
// // 		Permissions:  req.Permissions,
// // 	}

// // 	if err := h.companyService.AddManager(ctx, managerReq); err != nil {
// // 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add manager")
// // 		return
// // 	}

// // 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))
// // }

// // GetAvailablePermissions returns permissions that the current user can assign
// func (h *RBACHandler) GetAvailablePermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get current user ID from context
// 	currentUserID := r.Context().Value("user_id")
// 	if currentUserID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// 		return
// 	}

// 	currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	// Get current user's permissions
// 	currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user permissions")
// 		return
// 	}

// 	// Get all permissions available for the company
// 	allPermissions, err := h.companyService.GetPermissionsByCompanyDepartments(ctx, companyID, "", "", "")
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get available permissions")
// 		return
// 	}

// 	// Filter permissions to only those the user has
// 	userPermMap := make(map[string]bool)
// 	for _, perm := range currentUserPermissions {
// 		userPermMap[perm.PermissionName] = true
// 	}

// 	var availablePermissions []*models.Permission
// 	for _, perm := range allPermissions {
// 		if userPermMap[perm.PermissionName] {
// 			availablePermissions = append(availablePermissions, perm)
// 		}
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(availablePermissions, "Available permissions retrieved successfully"))
// }

// // // AddEmployee creates a new employee with restricted permissions
// // func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
// // 	ctx := r.Context()

// // 	companyIDStr := chi.URLParam(r, "companyID")
// // 	companyID, err := uuid.Parse(companyIDStr)
// // 	if err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// // 		return
// // 	}

// // 	var req struct {
// // 		PhoneNumber  string     `json:"phone" validate:"required"`
// // 		EmployeeID   string     `json:"employee_id" validate:"required"`
// // 		RoleID       uuid.UUID  `json:"role_id" validate:"required"`
// // 		DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// // 		ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// // 		Permissions  []string   `json:"permissions"` // Only permissions the current user has
// // 	}

// // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// // 		return
// // 	}

// // 	// Create employee using service
// // 	employeeReq := &service.AddEmployeeRequest{
// // 		CompanyID:    companyID,
// // 		PhoneNumber:  req.PhoneNumber,
// // 		EmployeeID:   req.EmployeeID,
// // 		RoleID:       req.RoleID,
// // 		DepartmentID: req.DepartmentID,
// // 		ReportsTo:    req.ReportsTo,
// // 		Permissions:  req.Permissions,
// // 	}

// // 	// Directly call AddEmployee - permission check is handled inside the service
// // 	if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
// // 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add employee")
// // 		return
// // 	}

// // 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
// // }


// // AddEmployee creates a new employee without permissions field
// // AddEmployee creates a new employee without permissions field
// func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     var req struct {
//         PhoneNumber  string     `json:"phone" validate:"required"`
//         Username     string     `json:"username" validate:"required,min=3,max=100,alphanum"`
//         FullName     string     `json:"full_name" validate:"required,max=255"`
//         EmployeeID   string     `json:"employee_id" validate:"required"`
//         RoleID       uuid.UUID  `json:"role_id" validate:"required"`
//         DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
//         ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
//         // NO permissions field here
//     }

//     // Use DisallowUnknownFields to reject "permissions" field
//     decoder := json.NewDecoder(r.Body)
//     decoder.DisallowUnknownFields()
//     if err := decoder.Decode(&req); err != nil {
//         if strings.Contains(err.Error(), "unknown field") {
//             h.respondWithError(w, http.StatusBadRequest, err, 
//                 "Invalid request: 'permissions' field is not allowed. Permissions are assigned at role level only.")
//             return
//         }
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Validate user has access to the department
//     currentUserID := r.Context().Value("user_id")
//     if currentUserID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     _, err = uuid.Parse(currentUserID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
//         return
//     }

//     // Get user's accessible departments
//     userDepartments, _, err := h.companyService.ListDepartments(ctx, companyID, 1000, 0, false)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate department access")
//         return
//     }

//     // Check if user has access to the requested department
//     hasAccess := false
//     for _, dept := range userDepartments {
//         if dept.DepartmentID == req.DepartmentID {
//             hasAccess = true
//             break
//         }
//     }

//     if !hasAccess {
//         h.respondWithError(w, http.StatusForbidden, 
//             fmt.Errorf("PERMISSION_DENIED"),
//             "You don't have access to assign employees to this department")
//         return
//     }

//     // Verify the role exists and belongs to the company
//     role, err := h.companyService.GetRole(ctx, req.RoleID)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
//         return
//     }
    
//     if role.CompanyID != companyID {
//         h.respondWithError(w, http.StatusBadRequest, 
//             fmt.Errorf("INVALID_ROLE"),
//             "Role does not belong to this company")
//         return
//     }

//     // Check if role is assigned to the department
//     roleDepartments, err := h.companyService.GetRoleDepartments(ctx, req.RoleID)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate role-department mapping")
//         return
//     }
    
//     roleInDepartment := false
//     for _, dept := range roleDepartments {
//         if dept.DepartmentID == req.DepartmentID {
//             roleInDepartment = true
//             break
//         }
//     }
    
//     if !roleInDepartment {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("ROLE_NOT_IN_DEPARTMENT"),
//             "Role is not assigned to the selected department")
//         return
//     }

//     // Validate reports_to if provided
//     if req.ReportsTo != nil {
//         // Check if reports_to employee exists and is active
//         isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
//         if err != nil || !isActive {
//             h.respondWithError(w, http.StatusBadRequest,
//                 fmt.Errorf("INVALID_REPORTS_TO"),
//                 "Reports-to employee not found or not active")
//             return
//         }
//     }

//     // Create employee using service
//     employeeReq := &service.AddEmployeeRequest{
//         CompanyID:    companyID,
//         PhoneNumber:  req.PhoneNumber,
//         Username:     req.Username,
//         FullName:     req.FullName,
//         EmployeeID:   req.EmployeeID,
//         RoleID:       req.RoleID,
//         DepartmentID: req.DepartmentID,
//         ReportsTo:    req.ReportsTo,
//     }

//     if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
//         statusCode := http.StatusInternalServerError
//         message := "Failed to add employee"
        
//         switch {
//         case strings.Contains(err.Error(), "max employee limit reached"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         case strings.Contains(err.Error(), "already an active employee"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         case strings.Contains(err.Error(), "role is not assigned"):
//             statusCode = http.StatusBadRequest
//             message = err.Error()
//         case strings.Contains(err.Error(), "reports_to employee"):
//             statusCode = http.StatusBadRequest
//             message = err.Error()
//         case strings.Contains(err.Error(), "company is not active"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         }
        
//         h.respondWithError(w, statusCode, err, message)
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
// }
// // AddManager creates a new manager using role_id instead of role_name
// // AddManager creates a new manager using role_id instead of role_name
// func (h *RBACHandler) AddManager(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     // Get current user ID from context
//     currentUserID := r.Context().Value("user_id")
//     if currentUserID == nil {
//         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
//         return
//     }

//     _, err = uuid.Parse(currentUserID.(string))
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
//         return
//     }

//     var req struct {
//         PhoneNumber  string     `json:"phone" validate:"required"`
//         Username     string     `json:"username" validate:"required,min=3,max=100,alphanum"`
//         FullName     string     `json:"full_name" validate:"required,max=255"`
//         EmployeeID   string     `json:"employee_id" validate:"required"`
//         RoleID       uuid.UUID  `json:"role_id" validate:"required"`
//         DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
//         ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
//         // NO permissions field here
//     }

//     // Use DisallowUnknownFields to reject "permissions" field
//     decoder := json.NewDecoder(r.Body)
//     decoder.DisallowUnknownFields()
//     if err := decoder.Decode(&req); err != nil {
//         if strings.Contains(err.Error(), "unknown field") {
//             h.respondWithError(w, http.StatusBadRequest, err, 
//                 "Invalid request: 'permissions' field is not allowed. Permissions are assigned at role level only.")
//             return
//         }
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Validate user has access to the department
//     userDepartments, _, err := h.companyService.ListDepartments(ctx, companyID, 1000, 0, false)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate department access")
//         return
//     }

//     // Check if user has access to the requested department
//     hasAccess := false
//     for _, dept := range userDepartments {
//         if dept.DepartmentID == req.DepartmentID {
//             hasAccess = true
//             break
//         }
//     }

//     if !hasAccess {
//         h.respondWithError(w, http.StatusForbidden, 
//             fmt.Errorf("PERMISSION_DENIED"),
//             "You don't have access to assign managers to this department")
//         return
//     }

//     // Verify the role exists and is valid for manager (role level 500 or higher)
//     role, err := h.companyService.GetRole(ctx, req.RoleID)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
//         return
//     }

//     // Check if role belongs to the company
//     if role.CompanyID != companyID {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("INVALID_ROLE"),
//             "Role does not belong to this company")
//         return
//     }

//     // Check if role level is appropriate for manager (typically 500 or higher)
//     if role.RoleLevel < 500 {
//         h.respondWithError(w, http.StatusBadRequest, 
//             fmt.Errorf("INVALID_ROLE_LEVEL"),
//             "Role level must be 500 or higher for managers")
//         return
//     }

//     // Check if role is assigned to the department
//     roleDepartments, err := h.companyService.GetRoleDepartments(ctx, req.RoleID)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate role-department mapping")
//         return
//     }
    
//     roleInDepartment := false
//     for _, dept := range roleDepartments {
//         if dept.DepartmentID == req.DepartmentID {
//             roleInDepartment = true
//             break
//         }
//     }
    
//     if !roleInDepartment {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("ROLE_NOT_IN_DEPARTMENT"),
//             "Role is not assigned to the selected department")
//         return
//     }

//     // Validate reports_to if provided
//     if req.ReportsTo != nil {
//         // Check if reports_to employee exists and is active
//         isActive, err := h.companyService.IsUserActiveEmployee(ctx, companyID, *req.ReportsTo)
//         if err != nil || !isActive {
//             h.respondWithError(w, http.StatusBadRequest,
//                 fmt.Errorf("INVALID_REPORTS_TO"),
//                 "Reports-to employee not found or not active")
//             return
//         }
//     }

//     // Create manager using the same AddEmployeeRequest (managers are just employees with higher-level roles)
//     managerReq := &service.AddEmployeeRequest{
//         CompanyID:    companyID,
//         PhoneNumber:  req.PhoneNumber,
//         Username:     req.Username,
//         FullName:     req.FullName,
//         EmployeeID:   req.EmployeeID,
//         RoleID:       req.RoleID,
//         DepartmentID: req.DepartmentID,
//         ReportsTo:    req.ReportsTo,
//     }

//     if err := h.companyService.AddEmployee(ctx, managerReq); err != nil {
//         statusCode := http.StatusInternalServerError
//         message := "Failed to add manager"
        
//         switch {
//         case strings.Contains(err.Error(), "max employee limit reached"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         case strings.Contains(err.Error(), "already an active employee"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         case strings.Contains(err.Error(), "role is not assigned"):
//             statusCode = http.StatusBadRequest
//             message = err.Error()
//         case strings.Contains(err.Error(), "reports_to employee"):
//             statusCode = http.StatusBadRequest
//             message = err.Error()
//         case strings.Contains(err.Error(), "company is not active"):
//             statusCode = http.StatusConflict
//             message = err.Error()
//         }
        
//         h.respondWithError(w, statusCode, err, message)
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))
// }
// // func (h *RBACHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
// //     ctx := r.Context()

// //     companyIDStr := chi.URLParam(r, "companyID")
// //     companyID, err := uuid.Parse(companyIDStr)
// //     if err != nil {
// //         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// //         return
// //     }

// //     var req struct {
// //         PhoneNumber  string     `json:"phone" validate:"required"`
// //         Username     string     `json:"username" validate:"required,min=3,max=100,alphanum"` // NEW
// //         FullName     string     `json:"full_name" validate:"required,max=255"` // NEW
// //         EmployeeID   string     `json:"employee_id" validate:"required"`
// //         RoleID       uuid.UUID  `json:"role_id" validate:"required"`
// //         DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// //         ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// //         Permissions  []string   `json:"permissions"` // Only permissions the current user has
// //     }

// //     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// //         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// //         return
// //     }

// //     // Create employee using service
// //     employeeReq := &service.AddEmployeeRequest{
// //         CompanyID:    companyID,
// //         PhoneNumber:  req.PhoneNumber,
// //         Username:     req.Username,     // NEW
// //         FullName:     req.FullName,     // NEW
// //         EmployeeID:   req.EmployeeID,
// //         RoleID:       req.RoleID,
// //         DepartmentID: req.DepartmentID,
// //         ReportsTo:    req.ReportsTo,
// //         Permissions:  req.Permissions,
// //     }

// //     // Directly call AddEmployee - permission check is handled inside the service
// //     if err := h.companyService.AddEmployee(ctx, employeeReq); err != nil {
// //         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add employee")
// //         return
// //     }

// //     h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))
// // }

// // // AddManager creates a new manager with username and full_name
// // func (h *RBACHandler) AddManager(w http.ResponseWriter, r *http.Request) {
// //     ctx := r.Context()

// //     companyIDStr := chi.URLParam(r, "companyID")
// //     companyID, err := uuid.Parse(companyIDStr)
// //     if err != nil {
// //         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// //         return
// //     }

// //     // Get current user ID from context
// //     currentUserID := r.Context().Value("user_id")
// //     if currentUserID == nil {
// //         h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("UNAUTHORIZED"), "Authentication required")
// //         return
// //     }

// //     currentUserIDParsed, err := uuid.Parse(currentUserID.(string))
// //     if err != nil {
// //         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// //         return
// //     }

// //     var req struct {
// //         PhoneNumber  string     `json:"phone" validate:"required"`
// //         Username     string     `json:"username" validate:"required,min=3,max=100,alphanum"` // NEW
// //         FullName     string     `json:"full_name" validate:"required,max=255"` // NEW
// //         RoleName     string     `json:"role_name" validate:"required"`
// //         DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// //         ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// //         Permissions  []string   `json:"permissions" validate:"required,min=1"` // Only permissions the current user has
// //     }

// //     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// //         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// //         return
// //     }

// //     // Validate that current user can only assign permissions they have
// //     currentUserPermissions, err := h.companyService.GetUserPermissions(ctx, currentUserIDParsed)
// //     if err != nil {
// //         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate permissions")
// //         return
// //     }

// //     // Convert to map for easy lookup
// //     userPermMap := make(map[string]bool)
// //     for _, perm := range currentUserPermissions {
// //         userPermMap[perm.PermissionName] = true
// //     }

// //     // Validate each requested permission
// //     for _, reqPerm := range req.Permissions {
// //         if !userPermMap[reqPerm] {
// //             h.respondWithError(w, http.StatusForbidden,
// //                 fmt.Errorf("PERMISSION_DENIED"),
// //                 fmt.Sprintf("You cannot assign permission '%s' that you don't possess", reqPerm))
// //             return
// //         }
// //     }

// //     // Create manager using service
// //     managerReq := &service.AddManagerRequest{
// //         CompanyID:    companyID,
// //         PhoneNumber:  req.PhoneNumber,
// //         Username:     req.Username,     // NEW
// //         FullName:     req.FullName,     // NEW
// //         RoleName:     req.RoleName,
// //         DepartmentID: req.DepartmentID,
// //         ReportsTo:    req.ReportsTo,
// //         Permissions:  req.Permissions,
// //     }

// //     if err := h.companyService.AddManager(ctx, managerReq); err != nil {
// //         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to add manager")
// //         return
// //     }

// //     h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))
// // }
