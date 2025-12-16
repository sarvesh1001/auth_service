package middleware

import (
	"context"
	"net/http"
	"strings"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
	"encoding/json"

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
//                            MAIN JWT MIDDLEWARE WITH REDIS VALIDATION
// ============================================================================

func JWTAuthMiddlewareWithRedis(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			// ✅ NEW: Validate JWT with Redis check
			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", 
					util.ErrorField(err),
					util.String("token", util.MaskString(tokenStr, 8)))
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
				return
			}

			// Prepare context with all claims including permission mask
			ctx := r.Context()

			// Store as strings (already strings from JWT claims)
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			// Handle admin-specific claims
			if claims.SessionType == "admin" {
				ctx = context.WithValue(ctx, "admin_role_mask", claims.AdminRoleMask)
				
				// Ensure admin has full permission mask
				if claims.PermissionMask == nil || len(claims.PermissionMask) == 0 {
					ctx = context.WithValue(ctx, "permission_mask", buildFullAccessMask())
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
//                     USER-ONLY SESSION MIDDLEWARE WITH REDIS VALIDATION
// ============================================================================

func UserAuthMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			// ✅ NEW: Validate JWT with Redis check
			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
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
			ctx = context.WithValue(ctx, "company_id", claims.CompanyID)

			// Add permission mask
			ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
//                     ADMIN-ONLY SESSION MIDDLEWARE WITH REDIS VALIDATION
// ============================================================================

func AdminJWTAuthMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			// ✅ NEW: Validate JWT with Redis check
			claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
				return
			}

			// Only admin allowed
			if claims.SessionType != "admin" {
				util.JSONError(w, http.StatusForbidden, "access denied: admin session required")
				return
			}

			ctx := context.WithValue(r.Context(), "admin_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			ctx = context.WithValue(ctx, "company_id", claims.CompanyID)

			// Full permission mask for admin
			ctx = context.WithValue(ctx, "permission_mask", buildFullAccessMask())
			ctx = context.WithValue(ctx, "admin_role_mask", claims.AdminRoleMask)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
//                      ADMIN ROLE-HIERARCHY CHECK
// ============================================================================

func AdminRoleMiddleware(requiredRoleMask uint64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminRoleMask, ok := r.Context().Value("admin_role_mask").(uint64)
			if !ok {
				util.JSONError(w, http.StatusForbidden, "admin role mask not found in context")
				return
			}

			if !isRoleAuthorizedByMask(adminRoleMask, requiredRoleMask) {
				util.JSONError(w, http.StatusForbidden, "insufficient admin privileges")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper function for full access mask
func buildFullAccessMask() []uint64 {
	mask := make([]uint64, 4)
	for i := range mask {
		mask[i] = ^uint64(0) // Set all bits to 1
	}
	return mask
}

func isRoleAuthorizedByMask(userRoleMask, requiredRoleMask uint64) bool {
	// Check if user has at least the required role level
	userRoleLevel := getRoleHierarchyLevel(userRoleMask)
	requiredRoleLevel := getRoleHierarchyLevel(requiredRoleMask)
	
	return userRoleLevel >= requiredRoleLevel
}

func getRoleHierarchyLevel(roleMask uint64) int {
	if (roleMask & models.RoleMaskOwner) != 0 {
		return 3
	}
	if (roleMask & models.RoleMaskSuperEmployee) != 0 {
		return 2
	}
	if (roleMask & models.RoleMaskEmployee) != 0 {
		return 1
	}
	return 0
}

func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header")
				return
			}

			accessToken := parts[1]
			claims, err := jwtService.ValidateAccessToken(r.Context(), accessToken)
			if err != nil {
				logger.Warn("Invalid JWT token", zap.Error(err))
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)

			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
			}
			if claims.PermissionMask != nil {
				ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
			}
			if claims.AdminRoleMask != 0 {
				ctx = context.WithValue(ctx, "admin_role_mask", claims.AdminRoleMask)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
	if logger != nil {
		logger.Warn("JWT auth error",
			zap.Int("status_code", statusCode),
			zap.String("message", message),
		)
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