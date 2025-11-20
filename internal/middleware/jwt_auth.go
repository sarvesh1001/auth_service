package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-service/internal/service"
	"auth-service/internal/util"

	"go.uber.org/zap"
)

// parseBearerToken safely extracts and sanitizes the JWT from Authorization header.
func parseBearerToken(r *http.Request, logger *zap.Logger) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn("Missing Authorization header")
		return "", false
	}

	// Split on whitespace
	fields := strings.Fields(authHeader)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
		logger.Warn("Invalid Authorization header format", zap.String("header", authHeader))
		return "", false
	}

	tokenStr := strings.Join(fields[1:], " ")
	tokenStr = strings.TrimSpace(strings.Trim(tokenStr, `"`))

	// Structural validation: JWT must have exactly 2 dots
	if strings.Count(tokenStr, ".") != 2 {
		logger.Warn("Malformed JWT token", zap.Int("dot_count", strings.Count(tokenStr, ".")))
		return "", false
	}

	return tokenStr, true
}

// ============================================================================
//                            MAIN JWT MIDDLEWARE
// ============================================================================
// internal/middleware/jwt_auth.go
// internal/middleware/jwt_auth.go

func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			// Validate JWT
			claims, err := jwtService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Prepare context with all claims including permission mask
			ctx := r.Context()

			// Store as strings (already strings from JWT claims)
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "company_id", claims.CompanyID) // This should be string
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			// Handle admin-specific claims
			if claims.SessionType == "admin" {
				ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
				ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)

				// Ensure admin has full permission mask
				if claims.PermissionMask == nil || len(claims.PermissionMask) == 0 {
					ctx = context.WithValue(ctx, "permission_mask", buildFullAccessMask())
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper function for full access mask
func buildFullAccessMask() []uint64 {
	mask := make([]uint64, 4)
	for i := range mask {
		mask[i] = ^uint64(0)
	}
	return mask
}

// ============================================================================
//                     USER-ONLY SESSION MIDDLEWARE
// ============================================================================

func UserAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := jwtService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Only allow "user" session type
			if claims.SessionType != "user" {
				util.JSONError(w, http.StatusForbidden, "access denied: user session required")
				return
			}

			// Add to context
			ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)

			// Add permission mask
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
//
//	ADMIN-ONLY SESSION MIDDLEWARE
//
// ============================================================================
// internal/middleware/jwt_auth.go

func AdminJWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			claims, err := jwtService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Only admin allowed
			if claims.SessionType != "admin" {
				util.JSONError(w, http.StatusForbidden, "access denied: admin session required")
				return
			}

			ctx := context.WithValue(r.Context(), "admin_id", claims.UserID) // String
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)       // String
			ctx = context.WithValue(ctx, "role", claims.Role)                // String
			ctx = context.WithValue(ctx, "session_type", claims.SessionType) // String
			ctx = context.WithValue(ctx, "jti", claims.JTI)                  // String
			ctx = context.WithValue(ctx, "company_id", claims.CompanyID)     // String

			// Full permission mask for admin
			ctx = context.WithValue(ctx, "permission_mask", buildFullAccessMask())

			// Admin-specific fields
			ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
			ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
//                      ADMIN ROLE-HIERARCHY CHECK
// ============================================================================

func AdminRoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			adminRole, ok := r.Context().Value("admin_role").(string)
			if !ok {
				util.JSONError(w, http.StatusForbidden, "admin role not found")
				return
			}

			if !isRoleAuthorized(adminRole, requiredRole) {
				util.JSONError(w, http.StatusForbidden, "insufficient admin privileges")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isRoleAuthorized(userRole, requiredRole string) bool {
	roleHierarchy := map[string]int{
		"owner":          3,
		"super_employee": 2,
		"employee":       1,
	}

	userLevel, uok := roleHierarchy[userRole]
	requiredLevel, rok := roleHierarchy[requiredRole]

	if !uok || !rok {
		return false
	}

	return userLevel >= requiredLevel
}
