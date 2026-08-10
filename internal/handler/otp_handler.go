package handler

import (
	"auth-service/internal/contextkeys"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// OTPHandler handles HTTP requests for OTP operations.
type OTPHandler struct {
	otpService     *service.OTPService
	sessionService *service.SessionService
	validator      *validator.Validate
}

// NewOTPHandler creates a new OTPHandler.
func NewOTPHandler(
	otpService *service.OTPService,
	sessionService *service.SessionService,
) *OTPHandler {
	return &OTPHandler{
		otpService:     otpService,
		sessionService: sessionService,
		validator:      validator.New(),
	}
}

// ---------- Context injection ----------

func (h *OTPHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *OTPHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		// Use the shared context key type
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *OTPHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// getClientIP extracts client IP.
func (h *OTPHandler) getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RegisterRoutes registers all OTP routes.
func (h *OTPHandler) RegisterRoutes(router chi.Router) {
	router.Route("/otp", func(r chi.Router) {
		// Apply idempotency middleware directly on these two endpoints
		r.With(IdempotencyMiddleware).Post("/send", h.SendOTP)
		r.With(IdempotencyMiddleware).Post("/verify", h.VerifyOTP)
		r.Get("/health", h.HealthCheck)
		r.Group(func(r chi.Router) {
			r.Get("/stats", h.GetOTPStats)
			r.Post("/cleanup", h.CleanupExpiredOTPs)
		})
	})
}

// SendOTP handles OTP send requests.
// @Summary Send OTP
// @Description Sends an OTP to the provided phone number.
// @Tags otp
// @Accept json
// @Produce json
// @Param body body service.OTPSendRequest true "OTP send request"
// @Success 200 {object} map[string]interface{} "OTP sent"
// @Failure 400 {object} map[string]interface{} "Validation failed"
// @Failure 404 {object} map[string]interface{} "Phone not registered"
// @Failure 429 {object} map[string]interface{} "Rate limit exceeded"
// @Router /api/v1/otp/send [post]
func (h *OTPHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req service.OTPSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(strings.TrimSpace(req.PhoneNumber))
	req.Purpose = util.SanitizeInput(strings.TrimSpace(strings.ToLower(req.Purpose)))
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.Provider = util.SanitizeInput(req.Provider)
	req.IPAddress = h.getClientIP(r)

	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}

	if util.ContainsSuspicious(req.PhoneNumber) || util.ContainsSuspicious(req.DeviceID) {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Invalid request")
		return
	}

	response, err := h.otpService.SendOTP(ctx, &req)
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		if response != nil {
			// Retry-After header must be a string containing seconds
			if response.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(response.RetryAfter))
			}
			h.respondWithJSON(w, statusCode, response)
			return
		}
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP sent successfully"))
}

// VerifyOTP verifies OTP and optionally issues tokens.
// @Summary Verify OTP
// @Description Verifies the OTP and can issue authentication tokens.
// @Tags otp
// @Accept json
// @Produce json
// @Param body body service.OTPVerifyRequest true "OTP verification request"
// @Success 200 {object} map[string]interface{} "Verification result with tokens"
// @Failure 400 {object} map[string]interface{} "Validation failed"
// @Failure 401 {object} map[string]interface{} "Invalid OTP"
// @Failure 423 {object} map[string]interface{} "Attempts exceeded"
// @Failure 429 {object} map[string]interface{} "Too many attempts"
// @Failure 410 {object} map[string]interface{} "OTP expired"
// @Router /api/v1/otp/verify [post]
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req service.OTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(strings.TrimSpace(req.PhoneNumber))
	req.OTP = strings.TrimSpace(req.OTP)
	req.Purpose = util.SanitizeInput(strings.TrimSpace(strings.ToLower(req.Purpose)))
	req.IPAddress = h.getClientIP(r)
	req.DeviceID = r.Header.Get("X-Device-ID")

	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}

	response, err := h.otpService.VerifyOTP(ctx, &req)
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		if response != nil {
			if response.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(response.RetryAfter))
			}
			h.respondWithJSON(w, statusCode, response)
			return
		}
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	// Issue tokens if successful and device ID present
	if response.Success && req.DeviceID != "" {
		userID := "user-" + req.PhoneNumber // placeholder – replace with actual user ID lookup
		tokenPair, err := h.sessionService.IssueTokenPair(ctx, &service.IssueTokenPairRequest{
			UserID:      userID,
			Role:        "user",
			DeviceID:    req.DeviceID,
			SessionType: "user",
			IPAddress:   req.IPAddress,
		})
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
			"verified": true,
			"tokens":   tokenPair,
			"message":  "OTP verified successfully",
		}, "OTP verified successfully"))
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP verification completed"))
}

// HealthCheck checks OTP service health.
// @Summary OTP service health
// @Tags otp
// @Produce json
// @Success 200 {object} map[string]interface{} "Service healthy"
// @Failure 500 {object} map[string]interface{} "Service unhealthy"
// @Router /api/v1/otp/health [get]
func (h *OTPHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)
	if err := h.otpService.HealthCheck(ctx); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "otp",
	}, "OTP service is healthy"))
}

// GetOTPStats returns OTP statistics (admin only).
// @Summary Get OTP stats
// @Tags otp
// @Produce json
// @Success 200 {object} map[string]interface{} "Statistics"
// @Failure 500 {object} map[string]interface{} "Failed to get stats"
// @Router /api/v1/otp/stats [get]
func (h *OTPHandler) GetOTPStats(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)
	stats, err := h.otpService.GetOTPStats(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "OTP statistics retrieved"))
}

// CleanupExpiredOTPs triggers cleanup (admin only).
// @Summary Cleanup expired OTPs
// @Tags otp
// @Produce json
// @Success 200 {object} map[string]interface{} "Cleanup result"
// @Failure 500 {object} map[string]interface{} "Cleanup failed"
// @Router /api/v1/otp/cleanup [post]
func (h *OTPHandler) CleanupExpiredOTPs(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)
	count, err := h.otpService.CleanupExpiredOTPs(ctx, 1000)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"deleted_count": count,
		"message":       "Cleanup completed",
	}, "OTP cleanup successful"))
}

// ---------- Error mapping ----------
func (h *OTPHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	switch {
	case errors.Is(err, customErrors.ErrNotFound),
		errors.Is(err, customErrors.ErrOTPNotFound),
		errors.Is(err, customErrors.ErrPhoneNotRegistered):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrOTPExpired):
		return http.StatusGone, err.Error()
	case errors.Is(err, customErrors.ErrOTPInvalid):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrOTPAttemptsExceeded):
		return http.StatusLocked, err.Error()
	case errors.Is(err, customErrors.ErrOTPRateLimitExceeded),
		errors.Is(err, customErrors.ErrDailyQuotaExceeded),
		errors.Is(err, customErrors.ErrSecurityCheckFailed):
		return http.StatusTooManyRequests, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Response helpers ----------
func (h *OTPHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *OTPHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}
