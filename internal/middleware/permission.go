// internal/middleware/permission.go
package middleware

import (
	"auth-service/internal/rbac"
	"auth-service/internal/util"
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// internal/middleware/permission.go
// internal/middleware/permission.go

// Helper function to safely extract string from context
func getStringFromContext(ctx context.Context, key string) string {
	value := ctx.Value(key)
	if value == nil {
		return "unknown"
	}

	switch v := value.(type) {
	case string:
		return v
	case uuid.UUID:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Updated BitmaskPermissionMiddleware
func BitmaskPermissionMiddleware(requiredPermission string, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get session type
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "session type not found")
				return
			}

			// Admin bypass - full access
			if sessionType == "admin" {
				logger.Debug("Admin session - permission bypass",
					util.String("required_permission", requiredPermission),
				)
				next.ServeHTTP(w, r)
				return
			}

			// Get permission mask from context
			permissionMask, ok := r.Context().Value("permission_mask").([]uint64)
			if !ok || permissionMask == nil {
				userID := getStringFromContext(r.Context(), "user_id")
				logger.Warn("Permission mask not found in context",
					util.String("user_id", userID),
				)
				util.JSONError(w, http.StatusForbidden, "permission mask not found")
				return
			}

			// Safely get user ID and company ID for logging
			userID := getStringFromContext(r.Context(), "user_id")
			companyID := getStringFromContext(r.Context(), "company_id")

			// Check permission using RBAC package with bitmask
			if !rbac.HasPermission(permissionMask, requiredPermission) {
				logger.Warn("Permission denied by bitmask",
					util.String("required_permission", requiredPermission),
					util.String("user_id", userID),
					util.String("company_id", companyID),
					util.Any("permission_mask", permissionMask),
				)
				util.JSONError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			logger.Debug("Bitmask permission granted",
				util.String("permission", requiredPermission),
				util.String("user_id", userID),
			)

			next.ServeHTTP(w, r)
		})
	}
}

// BulkPermissionMiddleware checks multiple permissions
func BulkPermissionMiddleware(requiredPermissions []string, checkAll bool, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "session type not found")
				return
			}

			// Admin bypass
			if sessionType == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			permissionMask, ok := r.Context().Value("permission_mask").([]uint64)
			if !ok || permissionMask == nil {
				util.JSONError(w, http.StatusForbidden, "permission mask not found")
				return
			}

			var hasRequired bool
			if checkAll {
				hasRequired = rbac.HasAllPermissions(permissionMask, requiredPermissions...)
			} else {
				hasRequired = rbac.HasAnyPermission(permissionMask, requiredPermissions...)
			}

			if !hasRequired {
				checkType := "any"
				if checkAll {
					checkType = "all"
				}
				logger.Warn("Bulk permission check failed",
					util.String("check_type", checkType),
					util.String("user_id", r.Context().Value("user_id").(string)),
					util.Any("required_permissions", requiredPermissions),
				)
				util.JSONError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
