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

	// Split on whitespace to tolerate multiple spaces or extra data
	fields := strings.Fields(authHeader)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
		logger.Warn("Invalid Authorization header format", zap.String("header", authHeader))
		return "", false
	}

	// Join all remaining fields (handles accidental spaces inside token)
	tokenStr := strings.Join(fields[1:], " ")

	// Trim quotes and spaces
	tokenStr = strings.TrimSpace(strings.Trim(tokenStr, `"`))

	// Structural validation: JWT should contain exactly 2 dots
	if strings.Count(tokenStr, ".") != 2 {
		logger.Warn("Malformed JWT token", zap.Int("dot_count", strings.Count(tokenStr, ".")), zap.Int("len", len(tokenStr)))
		return "", false
	}

	return tokenStr, true
}

// JWTAuthMiddleware validates JWT access tokens (stateless, no Redis lookup)
func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := parseBearerToken(r, logger)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			// Validate JWT (stateless)
			claims, err := jwtService.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				logger.Warn("JWT validation failed", util.ErrorField(err))
				util.JSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)

			if claims.SessionType == "admin" {
				ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
				ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserAuthMiddleware validates JWT tokens and ensures user session type
func UserAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
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

			// Ensure it's a user session (not admin)
			if claims.SessionType != "user" {
				logger.Warn("Access denied: not a user session",
					util.String("session_type", claims.SessionType),
					util.String("user_id", claims.UserID),
				)
				util.JSONError(w, http.StatusForbidden, "access denied: user session required")
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
