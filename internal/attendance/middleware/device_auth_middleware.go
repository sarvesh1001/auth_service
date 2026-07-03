package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/device"
)

// DeviceAuthMiddleware handles device token authentication.
type DeviceAuthMiddleware struct {
	tokenService device.TokenService
	logger       *zap.Logger
}

// NewDeviceAuthMiddleware creates a new middleware instance.
func NewDeviceAuthMiddleware(
	tokenService device.TokenService,
	logger *zap.Logger,
) *DeviceAuthMiddleware {
	return &DeviceAuthMiddleware{
		tokenService: tokenService,
		logger:       logger,
	}
}

// Middleware allows both device token and regular JWT (optional device auth).
func (m *DeviceAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceToken := r.Header.Get("X-Device-Token")
		if deviceToken == "" {
			// No device token → fall back to normal auth (JWT, etc.)
			next.ServeHTTP(w, r)
			return
		}

		companyIDHeader := r.Header.Get("X-Company-ID")
		deviceIDHeader := r.Header.Get("X-Device-ID")

		if companyIDHeader == "" || deviceIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Company-ID and X-Device-ID are required")
			return
		}

		companyID, err := uuid.Parse(companyIDHeader)
		if err != nil {
			m.respondWithError(w, http.StatusBadRequest, "invalid company id")
			return
		}

		authCtx, err := m.tokenService.ValidateToken(r.Context(), deviceToken, deviceIDHeader)
		if err != nil {
			m.logger.Warn("Device token validation failed",
				zap.String("company_id", companyIDHeader),
				zap.String("device_id", deviceIDHeader),
				zap.Error(err),
			)
			m.respondWithError(w, http.StatusUnauthorized, "invalid or expired device token")
			return
		}

		if authCtx.CompanyID != companyID {
			m.respondWithError(w, http.StatusUnauthorized, "company id mismatch")
			return
		}

		// Store device context in request context
		ctx := context.WithValue(r.Context(), "session_type", "device")
		ctx = context.WithValue(ctx, "company_id", authCtx.CompanyID)
		ctx = context.WithValue(ctx, "device_id", authCtx.DeviceID)
		ctx = context.WithValue(ctx, "source_type", authCtx.SourceType)
		ctx = context.WithValue(ctx, "device_auth_context", authCtx)
		ctx = context.WithValue(ctx, "is_trusted_device", authCtx.IsTrusted)
		if authCtx.WorkCenterID != nil {
			ctx = context.WithValue(ctx, "work_center_code", *authCtx.WorkCenterID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareForDeviceOnly enforces strict device authentication (no fallback).
func (m *DeviceAuthMiddleware) MiddlewareForDeviceOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceToken := r.Header.Get("X-Device-Token")
		if deviceToken == "" {
			m.respondWithError(w, http.StatusUnauthorized, "device token required")
			return
		}

		companyIDHeader := r.Header.Get("X-Company-ID")
		deviceIDHeader := r.Header.Get("X-Device-ID")

		if companyIDHeader == "" || deviceIDHeader == "" {
			m.respondWithError(w, http.StatusBadRequest, "X-Company-ID and X-Device-ID are required")
			return
		}

		companyID, err := uuid.Parse(companyIDHeader)
		if err != nil {
			m.respondWithError(w, http.StatusBadRequest, "invalid company id")
			return
		}

		authCtx, err := m.tokenService.ValidateToken(r.Context(), deviceToken, deviceIDHeader)
		if err != nil {
			m.logger.Warn("Device token validation failed (device-only)",
				zap.String("company_id", companyIDHeader),
				zap.String("device_id", deviceIDHeader),
				zap.Error(err),
			)
			m.respondWithError(w, http.StatusUnauthorized, "invalid or expired device token")
			return
		}

		if authCtx.CompanyID != companyID {
			m.respondWithError(w, http.StatusUnauthorized, "company id mismatch")
			return
		}

		if !authCtx.IsTrusted {
			m.respondWithError(w, http.StatusForbidden, "device is not trusted")
			return
		}

		ctx := context.WithValue(r.Context(), "session_type", "device")
		ctx = context.WithValue(ctx, "company_id", authCtx.CompanyID)
		ctx = context.WithValue(ctx, "device_id", authCtx.DeviceID)
		ctx = context.WithValue(ctx, "source_type", authCtx.SourceType)
		ctx = context.WithValue(ctx, "device_auth_context", authCtx)
		ctx = context.WithValue(ctx, "is_trusted_device", true)
		if authCtx.WorkCenterID != nil {
			ctx = context.WithValue(ctx, "work_center_code", *authCtx.WorkCenterID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *DeviceAuthMiddleware) respondWithError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}

// GetDeviceAuthContext retrieves the device auth context from the request context.
func GetDeviceAuthContext(ctx context.Context) (*models.DeviceAuthContext, bool) {
	auth, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext)
	return auth, ok
}

// HasDeviceAuth checks if the request was authenticated as a device.
func HasDeviceAuth(ctx context.Context) bool {
	sessionType, ok := ctx.Value("session_type").(string)
	return ok && sessionType == "device"
}
