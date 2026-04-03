package middleware

import (
	"context"
	"net/http"
	"time"

	"auth-service/internal/service"
	"auth-service/internal/util"

	"go.uber.org/zap"
)

// SessionValidationMiddleware performs comprehensive session validation
// REQUIRED checks from the specification
func SessionValidationMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// 🔥 Step 1 — Read JWT data from context (already populated by JWT middleware)
			jwtUserID, ok := ctx.Value("user_id").(string)
			if !ok || jwtUserID == "" {
				logger.Warn("SessionValidationMiddleware: JWT user ID not found in context")
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: user ID missing")
				return
			}

			jwtDeviceID, ok := ctx.Value("device_id").(string)
			if !ok || jwtDeviceID == "" {
				logger.Warn("SessionValidationMiddleware: JWT device ID not found in context")
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: device ID missing")
				return
			}

			jwtCompanyID, _ := ctx.Value("company_id").(string) // May be empty for admin sessions
			jwtJTI, ok := ctx.Value("jti").(string)
			if !ok || jwtJTI == "" {
				logger.Warn("SessionValidationMiddleware: JWT JTI not found in context")
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: JTI missing")
				return
			}

			sessionType, ok := ctx.Value("session_type").(string)
			// ✅ Allow student sessions alongside user and admin
			if !ok || (sessionType != "user" && sessionType != "admin" && sessionType != "student") {
				logger.Warn("SessionValidationMiddleware: Invalid session type in context",
					zap.String("session_type", sessionType))
				util.JSONError(w, http.StatusUnauthorized, "Invalid session type")
				return
			}

			// 🔥 Step 2 — Read client headers
			clientDeviceID := r.Header.Get("X-Device-ID")
			if clientDeviceID == "" {
				logger.Warn("SessionValidationMiddleware: X-Device-ID header missing")
				util.JSONError(w, http.StatusBadRequest, "X-Device-ID header required")
				return
			}

			clientCompanyID := r.Header.Get("X-Company-ID")
			// Note: For admin sessions, company ID may not be required
			// We'll check conditionally based on session type

			// 🔥 Step 3 — Load Redis session by JTI
			accessTokenData, err := sessionService.GetAccessTokenDataByJTI(ctx, jwtJTI)
			if err != nil {
				logger.Warn("SessionValidationMiddleware: Failed to get access token data from Redis",
					util.ErrorField(err),
					util.String("jti", jwtJTI))
				util.JSONError(w, http.StatusUnauthorized, "Session not found or expired")
				return
			}

			// Extract Redis session data
			redisUserID := accessTokenData.UserID
			redisDeviceID := accessTokenData.DeviceID
			redisCompanyID := accessTokenData.CompanyID
			redisRevoked := !accessTokenData.Active
			redisExpiresAt := accessTokenData.ExpiresAt

			logger.Debug("Session validation data",
				zap.String("jwt_user_id", jwtUserID),
				zap.String("redis_user_id", redisUserID),
				zap.String("session_type", sessionType),
				zap.String("jti", jwtJTI))

			// 🔥 Step 4 — Critical Security Checks

			// 1️⃣ Compare JWT.device_id vs Redis.device_id
			if jwtDeviceID != redisDeviceID {
				logger.Warn("SessionValidationMiddleware: JWT device ID does not match Redis device ID",
					zap.String("jwt_device_id", jwtDeviceID),
					zap.String("redis_device_id", redisDeviceID),
					zap.String("jti", jwtJTI))
				util.JSONError(w, http.StatusUnauthorized, "Device mismatch")
				return
			}

			// 2️⃣ Compare Client.device_id vs Redis.device_id
			if clientDeviceID != redisDeviceID {
				logger.Warn("SessionValidationMiddleware: Client device ID does not match Redis device ID",
					zap.String("client_device_id", clientDeviceID),
					zap.String("redis_device_id", redisDeviceID),
					zap.String("jti", jwtJTI))
				util.JSONError(w, http.StatusUnauthorized, "Device mismatch")
				return
			}

			// 3️⃣ Compare JWT.company_id vs Redis.company_id (only for users and students)
			if (sessionType == "user" || sessionType == "student") && jwtCompanyID != redisCompanyID {
				logger.Warn("SessionValidationMiddleware: JWT company ID does not match Redis company ID for user/student session",
					zap.String("jwt_company_id", jwtCompanyID),
					zap.String("redis_company_id", redisCompanyID),
					zap.String("jti", jwtJTI))
				util.JSONError(w, http.StatusUnauthorized, "Company mismatch")
				return
			}

			// 4️⃣ Compare Client.company_id vs JWT.company_id (only for users and students)
			if (sessionType == "user" || sessionType == "student") && clientCompanyID != jwtCompanyID {
				logger.Warn("SessionValidationMiddleware: Client company ID does not match JWT company ID for user/student session",
					zap.String("client_company_id", clientCompanyID),
					zap.String("jwt_company_id", jwtCompanyID),
					zap.String("jti", jwtJTI))
				util.JSONError(w, http.StatusBadRequest, "Company ID mismatch")
				return
			}

			// 5️⃣ Verify session not revoked
			if redisRevoked {
				logger.Warn("SessionValidationMiddleware: Access token is revoked",
					zap.String("jti", jwtJTI),
					zap.String("user_id", jwtUserID))
				util.JSONError(w, http.StatusUnauthorized, "Session revoked")
				return
			}

			// 6️⃣ Verify user ids match
			if jwtUserID != redisUserID {
				logger.Warn("SessionValidationMiddleware: JWT user ID does not match Redis user ID",
					zap.String("jwt_user_id", jwtUserID),
					zap.String("redis_user_id", redisUserID),
					zap.String("jti", jwtJTI))
				util.JSONError(w, http.StatusUnauthorized, "User mismatch")
				return
			}

			// 7️⃣ Verify session not expired
			if time.Now().After(redisExpiresAt) {
				logger.Warn("SessionValidationMiddleware: Access token expired",
					zap.String("jti", jwtJTI),
					zap.Time("expires_at", redisExpiresAt),
					zap.String("user_id", jwtUserID))
				util.JSONError(w, http.StatusUnauthorized, "Session expired")
				return
			}

			// ✅ All checks passed - add additional context if needed
			logger.Debug("Session validation passed",
				zap.String("user_id", jwtUserID),
				zap.String("session_type", sessionType),
				zap.String("jti", jwtJTI))

			// Add validated session info to context
			ctx = context.WithValue(ctx, "validated_session", true)
			ctx = context.WithValue(ctx, "validated_device_id", clientDeviceID)

			if (sessionType == "user" || sessionType == "student") && clientCompanyID != "" {
				ctx = context.WithValue(ctx, "validated_company_id", clientCompanyID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
