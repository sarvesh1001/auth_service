package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"go.uber.org/zap"
)

//
// ============================================================================
// TOKEN PARSER
// ============================================================================
//

func parseBearerToken(r *http.Request, logger *zap.Logger) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn("Missing Authorization header")
		return "", false
	}

	fields := strings.Fields(authHeader)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
		logger.Warn("Invalid Authorization header format",
			zap.String("header", authHeader))
		return "", false
	}

	tokenStr := strings.TrimSpace(strings.Trim(strings.Join(fields[1:], " "), `"`))
	if strings.Count(tokenStr, ".") != 2 {
		logger.Warn("Malformed JWT token",
			zap.Int("dot_count", strings.Count(tokenStr, ".")))
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
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed",
					util.ErrorField(err),
					util.String("token", util.MaskString(tokenStr, 8)))
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

			// ✅ COMPANY CONTEXT (STRING ONLY)
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
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			tokenStr, ok := parseBearerToken(r, logger)
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

			// ✅ COMPANY CONTEXT (STRING ONLY)
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
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			tokenStr, ok := parseBearerToken(r, logger)
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

			// ✅ COMPANY CONTEXT (STRING ONLY)
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

func AdminPermissionMiddleware(requiredPermission string, logger *zap.Logger) func(http.Handler) http.Handler {
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
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	jwt := JWTAuthMiddlewareWithRedis(sessionService, logger)
	session := SessionValidationMiddleware(sessionService, logger)

	return func(next http.Handler) http.Handler {
		return jwt(session(next))
	}
}

func CombinedAdminMiddleware(
	sessionService *service.SessionService,
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	admin := AdminJWTAuthMiddleware(sessionService, logger)
	session := SessionValidationMiddleware(sessionService, logger)

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
	logger *zap.Logger,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			tokenStr, ok := parseBearerToken(r, logger)
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

//
// ============================================================================
// JWT ERROR RESPONSE
// ============================================================================
//

func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
	if logger != nil {
		logger.Warn("JWT auth error",
			zap.Int("status_code", statusCode),
			zap.String("message", message))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"message": "Authentication failed",
		"code":    statusCode,
	})
}
