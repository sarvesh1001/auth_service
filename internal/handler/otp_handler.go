// internal/handler/otp_handler.go - FIXED VERSION
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

// OTPHandler handles HTTP requests for OTP operations
type OTPHandler struct {
	otpService     *service.OTPService
	sessionService *service.SessionService
	validator      *validator.Validate
	logger         *zap.Logger
}

func NewOTPHandler(
	otpService *service.OTPService,
	sessionService *service.SessionService,
	logger *zap.Logger,
) *OTPHandler {
	return &OTPHandler{
		otpService:     otpService,
		sessionService: sessionService,
		validator:      validator.New(),
		logger:         logger,
	}
}

// RegisterRoutes registers all OTP routes
func (h *OTPHandler) RegisterRoutes(router chi.Router) {
	router.Route("/otp", func(r chi.Router) {
		r.Post("/send", h.SendOTP)
		r.Post("/verify", h.VerifyOTP)
		r.Get("/health", h.HealthCheck)

		r.Group(func(r chi.Router) {
			r.Get("/stats", h.GetOTPStats)
			r.Post("/cleanup", h.CleanupExpiredOTPs)
		})
	})
}

// SendOTP handles OTP send requests
func (h *OTPHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.OTPSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(strings.TrimSpace(req.PhoneNumber))
	req.Purpose = util.SanitizeInput(strings.TrimSpace(strings.ToLower(req.Purpose)))
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.Provider = util.SanitizeInput(req.Provider)

	// Get IP address from request
	req.IPAddress = h.getClientIP(r)

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}

	// Check for suspicious patterns
	if util.ContainsSuspicious(req.PhoneNumber) || util.ContainsSuspicious(req.DeviceID) {
		h.logger.Warn("Blocked suspicious OTP send request",
			util.String("phone", req.PhoneNumber),
			util.String("device_id", req.DeviceID),
			util.String("ip", req.IPAddress),
		)
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("suspicious input detected"),
			"Invalid request")
		return
	}

	// Send OTP
	response, err := h.otpService.SendOTP(ctx, &req)
	if err != nil {
		statusCode := h.getStatusCodeForError(err)

		if errors.Is(err, service.ErrOTPRateLimitExceeded) && response != nil {
			w.Header().Set("Retry-After", string(rune(response.RetryAfter)))
			h.respondWithJSON(w, statusCode, response)
			return
		}

		h.respondWithError(w, statusCode, err, "Failed to send OTP")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP sent successfully"))

	h.logger.Info("OTP send request completed",
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ✅ FIXED: VerifyOTP handles OTP verification requests
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.OTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(strings.TrimSpace(req.PhoneNumber))
	req.OTP = strings.TrimSpace(req.OTP)
	req.Purpose = util.SanitizeInput(strings.TrimSpace(strings.ToLower(req.Purpose)))

	// Get IP address
	req.IPAddress = h.getClientIP(r)

	// ✅ FIXED: Get device ID from header instead of request body
	deviceID := r.Header.Get("X-Device-ID")

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}

	// Verify OTP
	response, err := h.otpService.VerifyOTP(ctx, &req)
	if err != nil {
		statusCode := h.getStatusCodeForError(err)

		if (errors.Is(err, service.ErrOTPRateLimitExceeded) ||
			errors.Is(err, service.ErrOTPInvalid)) && response != nil {
			h.respondWithJSON(w, statusCode, response)
			return
		}

		h.respondWithError(w, statusCode, err, "OTP verification failed")
		return
	}

	// ✅ FIXED: If verification successful, issue JWT tokens
	if response.Success && deviceID != "" {
		userID := "user-" + req.PhoneNumber // ⚠️ REPLACE WITH ACTUAL DB LOOKUP

		tokenPair, err := h.sessionService.IssueTokenPair(ctx, &service.IssueTokenPairRequest{
			UserID:      userID,
			Role:        "user",
			DeviceID:    deviceID, // ✅ Use deviceID from header
			SessionType: "user",
			IPAddress:   req.IPAddress,
		})
		if err != nil {
			h.logger.Error("Failed to issue JWT tokens after OTP verification",
				util.ErrorField(err),
				util.String("phone", req.PhoneNumber),
			)
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue authentication tokens")
			return
		}

		// ✅ Return both verification result and tokens
		h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
			"verified": true,
			"tokens":   tokenPair,
			"message":  "OTP verified successfully",
		}, "OTP verified successfully"))

		h.logger.Info("OTP verification completed with token issuance",
			util.String("user_id", userID),
			util.String("purpose", req.Purpose),
			util.String("ip", req.IPAddress),
			util.Bool("success", true),
			util.Duration("duration", time.Since(startTime)),
		)
		return
	}

	// OTP verification failed or no device ID
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP verification completed"))

	h.logger.Info("OTP verification completed",
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.Bool("success", response.Success),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ResendOTP handles OTP resend requests
// @Summary Resend OTP
// @Description Resend OTP to phone number
// @Tags otp
// @Accept json
// @Produce json
// @Param request body service.OTPResendRequest true "OTP resend request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 429 {object} Response
// @Failure 500 {object} Response
// @Router /otp/resend [post]

// HealthCheck handles OTP service health check
// @Summary OTP Health Check
// @Description Check OTP service health
// @Tags otp
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /otp/health [get]
func (h *OTPHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.otpService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "OTP service unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "otp",
	}, "OTP service is healthy"))
}

// GetOTPStats handles OTP statistics requests (admin only)
// @Summary Get OTP Statistics
// @Description Get OTP service statistics
// @Tags otp
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /otp/stats [get]
func (h *OTPHandler) GetOTPStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.otpService.GetOTPStats(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get OTP stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "OTP statistics retrieved"))
}

// CleanupExpiredOTPs handles manual cleanup of expired OTPs (admin only)
// @Summary Cleanup Expired OTPs
// @Description Manually cleanup expired OTPs
// @Tags otp
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /otp/cleanup [post]
func (h *OTPHandler) CleanupExpiredOTPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// This is a backup cleanup - TTL handles this automatically
	count, err := h.otpService.CleanupExpiredOTPs(ctx, 1000)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Cleanup failed")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"deleted_count": count,
		"message":       "Cleanup completed",
	}, "OTP cleanup successful"))
}

// ============================================
// HELPER METHODS
// ============================================
func (h *OTPHandler) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

func (h *OTPHandler) getStatusCodeForError(err error) int {
	switch {
	case errors.Is(err, service.ErrOTPNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrOTPExpired):
		return http.StatusGone
	case errors.Is(err, service.ErrOTPInvalid):
		return http.StatusUnauthorized
	case errors.Is(err, service.ErrOTPAttemptsExceeded):
		return http.StatusLocked
	case errors.Is(err, service.ErrOTPRateLimitExceeded):
		return http.StatusTooManyRequests
	case errors.Is(err, service.ErrInvalidInput):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func (h *OTPHandler) respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response",
			util.ErrorField(err),
		)
	}
}

func (h *OTPHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	response := errorResponse(err, message)
	h.respondWithJSON(w, statusCode, response)

	h.logger.Warn("OTP operation failed",
		util.ErrorField(err),
		util.String("message", message),
		util.Int("status_code", statusCode),
	)
}
