package middleware

import (
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type DeviceAuthMiddleware struct {
	tokenService service.DeviceTokenService
	logger       *zap.Logger
}

func NewDeviceAuthMiddleware(
	tokenService service.DeviceTokenService,
	logger *zap.Logger,
) *DeviceAuthMiddleware {
	return &DeviceAuthMiddleware{
		tokenService: tokenService,
		logger:       logger,
	}
}

// =================================================
// OPTIONAL DEVICE AUTH (device OR user/admin)
// =================================================
func (m *DeviceAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		deviceToken := r.Header.Get("X-Device-Token")
		if deviceToken == "" {
			// No device token → normal JWT flow
			next.ServeHTTP(w, r)
			return
		}

		companyIDHeader := r.Header.Get("X-Company-ID")
		deviceIDHeader := r.Header.Get("X-Device-ID")

		if companyIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Company-ID header required")
			return
		}
		if deviceIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Device-ID header required")
			return
		}

		companyID, err := uuid.Parse(companyIDHeader)
		if err != nil {
			m.respondWithError(w, http.StatusBadRequest, "invalid company id")
			return
		}

		authContext, err := m.tokenService.ValidateToken(
			r.Context(),
			deviceToken,
			deviceIDHeader,
		)
		if err != nil {
			m.logger.Warn("Device token validation failed",
				util.String("company_id", companyID.String()),
				util.String("device_id", deviceIDHeader),
				util.ErrorField(err),
			)
			m.respondWithError(w, http.StatusUnauthorized, "invalid or expired device token")
			return
		}

		if authContext.CompanyID != companyID {
			m.respondWithError(w, http.StatusUnauthorized, "company id mismatch")
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "session_type", "device")
		ctx = context.WithValue(ctx, "company_id", authContext.CompanyID)
		ctx = context.WithValue(ctx, "device_id", authContext.DeviceID)
		ctx = context.WithValue(ctx, "source_type", authContext.SourceType)
		ctx = context.WithValue(ctx, "device_auth_context", authContext)
		ctx = context.WithValue(ctx, "is_trusted_device", authContext.IsTrusted)

		if authContext.WorkCenterID != nil {
			ctx = context.WithValue(ctx, "work_center_code", *authContext.WorkCenterID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =================================================
// DEVICE-ONLY ENDPOINTS (STRICT)
// =================================================
func (m *DeviceAuthMiddleware) MiddlewareForDeviceOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		deviceToken := r.Header.Get("X-Device-Token")
		if deviceToken == "" {
			m.respondWithError(w, http.StatusUnauthorized, "device token required")
			return
		}

		companyIDHeader := r.Header.Get("X-Company-ID")
		deviceIDHeader := r.Header.Get("X-Device-ID")

		if companyIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Company-ID header required")
			return
		}
		if deviceIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Device-ID header required")
			return
		}

		companyID, err := uuid.Parse(companyIDHeader)
		if err != nil {
			m.respondWithError(w, http.StatusBadRequest, "invalid company id")
			return
		}

		authContext, err := m.tokenService.ValidateToken(
			r.Context(),
			deviceToken,
			deviceIDHeader,
		)
		if err != nil {
			m.logger.Warn("Device token validation failed (device-only)",
				util.String("company_id", companyID.String()),
				util.String("device_id", deviceIDHeader),
				util.ErrorField(err),
			)
			m.respondWithError(w, http.StatusUnauthorized, "invalid or expired device token")
			return
		}

		if authContext.CompanyID != companyID {
			m.respondWithError(w, http.StatusUnauthorized, "company id mismatch")
			return
		}

		if !authContext.IsTrusted {
			m.respondWithError(w, http.StatusForbidden, "device is not trusted")
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "session_type", "device")
		ctx = context.WithValue(ctx, "company_id", authContext.CompanyID)
		ctx = context.WithValue(ctx, "device_id", authContext.DeviceID)
		ctx = context.WithValue(ctx, "source_type", authContext.SourceType)
		ctx = context.WithValue(ctx, "device_auth_context", authContext)
		ctx = context.WithValue(ctx, "is_trusted_device", true)

		if authContext.WorkCenterID != nil {
			ctx = context.WithValue(ctx, "work_center_code", *authContext.WorkCenterID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =================================================
// HELPERS
// =================================================
func (m *DeviceAuthMiddleware) respondWithError(
	w http.ResponseWriter,
	statusCode int,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	_ = util.JSONEncode(w, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func GetDeviceAuthContext(ctx context.Context) (*service.DeviceAuthContext, bool) {
	authContext, ok := ctx.Value("device_auth_context").(*service.DeviceAuthContext)
	return authContext, ok
}

func HasDeviceAuth(ctx context.Context) bool {
	sessionType, ok := ctx.Value("session_type").(string)
	return ok && sessionType == "device"
}
