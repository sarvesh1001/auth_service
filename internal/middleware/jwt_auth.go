package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

//
// ============================================================================
// TOKEN PARSER
// ============================================================================
//

func parseBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false
	}
	fields := strings.Fields(authHeader)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	tokenStr := strings.TrimSpace(strings.Trim(strings.Join(fields[1:], " "), `"`))
	if strings.Count(tokenStr, ".") != 2 {
		return "", false
	}
	return tokenStr, true
}

//
// ============================================================================
// JWT AUTH (REDIS BACKED)  ✅ FINAL
// ============================================================================
//

func JWTAuthMiddlewareWithRedis(
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
				ctx = context.WithValue(ctx, "validated_company_id", claims.CompanyID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//
// ============================================================================
// ADMIN JWT AUTH  ✅ FINAL
// ============================================================================
//

func AdminJWTAuthMiddleware(
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
				return
			}

			if claims.SessionType != "admin" {
				util.JSONError(w, http.StatusForbidden, "admin session required")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "admin_id", claims.UserID)
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
				ctx = context.WithValue(ctx, "validated_company_id", claims.CompanyID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//
// ============================================================================
// USER JWT AUTH  ✅ FINAL
// ============================================================================
//

func UserAuthMiddleware(
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
				return
			}

			if claims.SessionType != "user" {
				util.JSONError(w, http.StatusForbidden, "user session required")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
				ctx = context.WithValue(ctx, "validated_company_id", claims.CompanyID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//
// ============================================================================
// ADMIN ROLE MIDDLEWARE
// ============================================================================
//

func AdminRoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value("role").(string)
			if !ok || getRoleLevel(role) < getRoleLevel(requiredRole) {
				util.JSONError(w, http.StatusForbidden, "insufficient admin privileges")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getRoleLevel(role string) int {
	switch role {
	case models.RoleAdminSuperAdmin:
		return 3
	case models.RoleAdminManager:
		return 2
	case models.RoleAdminEmployee:
		return 1
	case models.RoleUserOwner:
		return 3
	case models.RoleUserSuperEmployee:
		return 2
	case models.RoleUserEmployee:
		return 1
	default:
		return 0
	}
}

//
// ============================================================================
// ADMIN PERMISSION MIDDLEWARE
// ============================================================================
//

func AdminPermissionMiddleware(requiredPermission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value("session_type") != "admin" {
				util.JSONError(w, http.StatusForbidden, "admin session required")
				return
			}
			mask, ok := r.Context().Value("permission_mask").([]uint64)
			if !ok || mask == nil {
				util.JSONError(w, http.StatusForbidden, "permission mask not found")
				return
			}
			if r.Context().Value("role") == models.RoleAdminSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}
			if !hasAdminPermission(mask, requiredPermission) {
				util.JSONError(w, http.StatusForbidden, "insufficient admin permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasAdminPermission(mask []uint64, permission string) bool {
	if len(mask) == 0 {
		return false
	}
	// TODO: integrate RBAC permission checker
	return false
}

//
// ============================================================================
// COMBINED MIDDLEWARES
// ============================================================================
//

func CombinedMiddleware(
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	jwt := JWTAuthMiddlewareWithRedis(sessionService)
	session := SessionValidationMiddleware(sessionService)
	return func(next http.Handler) http.Handler {
		return jwt(session(next))
	}
}

func CombinedAdminMiddleware(
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	admin := AdminJWTAuthMiddleware(sessionService)
	session := SessionValidationMiddleware(sessionService)
	return func(next http.Handler) http.Handler {
		return admin(session(next))
	}
}

//
// ============================================================================
// ADMIN ROLE OR PERMISSION
// ============================================================================
//

func AdminRoleOrPermissionMiddleware(
	minRole string,
	requiredPermission string,
	sessionService *service.SessionService,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}
			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				util.JSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			if claims.SessionType != "admin" {
				util.JSONError(w, http.StatusForbidden, "admin session required")
				return
			}
			if getRoleLevel(claims.Role) >= getRoleLevel(minRole) ||
				hasAdminPermission(claims.PermissionMask, requiredPermission) {
				ctx := buildContext(r.Context(), claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			util.JSONError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

//
// ============================================================================
// CONTEXT BUILDER  ✅ FINAL
// ============================================================================
//

func buildContext(ctx context.Context, claims *models.JWTClaims) context.Context {
	ctx = context.WithValue(ctx, "admin_id", claims.UserID)
	ctx = context.WithValue(ctx, "user_id", claims.UserID)
	ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
	ctx = context.WithValue(ctx, "role", claims.Role)
	ctx = context.WithValue(ctx, "session_type", claims.SessionType)
	ctx = context.WithValue(ctx, "jti", claims.JTI)
	ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

	if claims.CompanyID != "" {
		ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
		ctx = context.WithValue(ctx, "validated_company_id", claims.CompanyID)
	}
	return ctx
}
