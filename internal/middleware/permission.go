package middleware

import (
	"net/http"
	"strings"

	"auth-service/internal/rbac"
	"auth-service/internal/util"
)

// BitmaskPermissionMiddleware checks a single permission (or OR‑separated list)
// using the permission mask stored in the context.
// If the session type is "admin" (including super_admin), the check is bypassed.
func BitmaskPermissionMiddleware(requiredPermission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "session type not found")
				return
			}

			// Admin bypass (super_admin and admin users)
			if sessionType == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			permissionMask, ok := r.Context().Value("permission_mask").([]uint64)
			if !ok || permissionMask == nil {
				util.JSONError(w, http.StatusForbidden, "permission mask not found")
				return
			}

			permissions := strings.Split(requiredPermission, "|")
			allowed := false
			for _, perm := range permissions {
				perm = strings.TrimSpace(perm)
				if perm == "" {
					continue
				}
				if rbac.HasPermission(permissionMask, perm) {
					allowed = true
					break
				}
			}

			if !allowed {
				util.JSONError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BulkPermissionMiddleware checks multiple permissions.
// If checkAll is true, all must be present; otherwise, any one is sufficient.
// Admin sessions are bypassed.
func BulkPermissionMiddleware(requiredPermissions []string, checkAll bool) func(http.Handler) http.Handler {
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
				util.JSONError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
