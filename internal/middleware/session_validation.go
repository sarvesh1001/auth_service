package middleware

import (
	"context"
	"net/http"
	"time"

	"auth-service/internal/service"
	"auth-service/internal/util"
)

// SessionValidationMiddleware performs comprehensive session validation
// comparing JWT claims, Redis session data, and client headers.
func SessionValidationMiddleware(sessionService *service.SessionService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Step 1 — Read JWT data from context (populated by JWT middleware)
			jwtUserID, ok := ctx.Value("user_id").(string)
			if !ok || jwtUserID == "" {
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: user ID missing")
				return
			}

			jwtDeviceID, ok := ctx.Value("device_id").(string)
			if !ok || jwtDeviceID == "" {
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: device ID missing")
				return
			}

			jwtCompanyID, _ := ctx.Value("company_id").(string) // may be empty for admin
			jwtJTI, ok := ctx.Value("jti").(string)
			if !ok || jwtJTI == "" {
				util.JSONError(w, http.StatusUnauthorized, "Invalid session: JTI missing")
				return
			}

			sessionType, ok := ctx.Value("session_type").(string)
			if !ok || (sessionType != "user" && sessionType != "admin" && sessionType != "student") {
				util.JSONError(w, http.StatusUnauthorized, "Invalid session type")
				return
			}

			// Step 2 — Read client headers
			clientDeviceID := r.Header.Get("X-Device-ID")
			if clientDeviceID == "" {
				util.JSONError(w, http.StatusBadRequest, "X-Device-ID header required")
				return
			}

			clientCompanyID := r.Header.Get("X-Company-ID")

			// Step 3 — Load Redis session by JTI
			accessTokenData, err := sessionService.GetAccessTokenDataByJTI(ctx, jwtJTI)
			if err != nil {
				util.JSONError(w, http.StatusUnauthorized, "Session not found or expired")
				return
			}

			redisUserID := accessTokenData.UserID
			redisDeviceID := accessTokenData.DeviceID
			redisCompanyID := accessTokenData.CompanyID
			redisRevoked := !accessTokenData.Active
			redisExpiresAt := accessTokenData.ExpiresAt

			// Step 4 — Critical Security Checks

			// 1. JWT.device_id vs Redis.device_id
			if jwtDeviceID != redisDeviceID {
				util.JSONError(w, http.StatusUnauthorized, "Device mismatch")
				return
			}

			// 2. Client.device_id vs Redis.device_id
			if clientDeviceID != redisDeviceID {
				util.JSONError(w, http.StatusUnauthorized, "Device mismatch")
				return
			}

			// 3. JWT.company_id vs Redis.company_id (only for users/students)
			if (sessionType == "user" || sessionType == "student") && jwtCompanyID != redisCompanyID {
				util.JSONError(w, http.StatusUnauthorized, "Company mismatch")
				return
			}

			// 4. Client.company_id vs JWT.company_id (only for users/students)
			if (sessionType == "user" || sessionType == "student") && clientCompanyID != jwtCompanyID {
				util.JSONError(w, http.StatusBadRequest, "Company ID mismatch")
				return
			}

			// 5. Session revocation
			if redisRevoked {
				util.JSONError(w, http.StatusUnauthorized, "Session revoked")
				return
			}

			// 6. User ID match
			if jwtUserID != redisUserID {
				util.JSONError(w, http.StatusUnauthorized, "User mismatch")
				return
			}

			// 7. Expiry
			if time.Now().After(redisExpiresAt) {
				util.JSONError(w, http.StatusUnauthorized, "Session expired")
				return
			}

			// All checks passed – add extra context
			ctx = context.WithValue(ctx, "validated_session", true)
			ctx = context.WithValue(ctx, "validated_device_id", clientDeviceID)
			if (sessionType == "user" || sessionType == "student") && clientCompanyID != "" {
				ctx = context.WithValue(ctx, "validated_company_id", clientCompanyID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
