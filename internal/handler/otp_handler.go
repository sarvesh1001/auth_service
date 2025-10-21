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
	otpService *service.OTPService
	validator  *validator.Validate
	logger     *zap.Logger
}

// NewOTPHandler creates a new OTP handler
func NewOTPHandler(otpService *service.OTPService, logger *zap.Logger) *OTPHandler {
	return &OTPHandler{
		otpService: otpService,
		validator:  validator.New(),
		logger:     logger,
	}
}

// RegisterRoutes registers all OTP routes
func (h *OTPHandler) RegisterRoutes(router chi.Router) {
	router.Route("/otp", func(r chi.Router) {
		// Public routes
		r.Post("/send", h.SendOTP)
		r.Post("/verify", h.VerifyOTP)
		r.Post("/resend", h.ResendOTP)
		r.Get("/health", h.HealthCheck)
		
		// Protected/Admin routes
		r.Group(func(r chi.Router) {
			// Add auth middleware here
			r.Get("/stats", h.GetOTPStats)
			r.Post("/cleanup", h.CleanupExpiredOTPs)
		})
	})
}

// SendOTP handles OTP send requests
// @Summary Send OTP
// @Description Send OTP to phone number for verification
// @Tags otp
// @Accept json
// @Produce json
// @Param request body service.OTPSendRequest true "OTP send request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 429 {object} Response
// @Failure 500 {object} Response
// @Router /otp/send [post]
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
		
		// For rate limit errors, include retry-after in response
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

// VerifyOTP handles OTP verification requests
// @Summary Verify OTP
// @Description Verify OTP for phone number
// @Tags otp
// @Accept json
// @Produce json
// @Param request body service.OTPVerifyRequest true "OTP verification request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 429 {object} Response
// @Failure 500 {object} Response
// @Router /otp/verify [post]
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
	
	// Validate request
	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}
	
	// Verify OTP
	response, err := h.otpService.VerifyOTP(ctx, &req)
	if err != nil {
		statusCode := h.getStatusCodeForError(err)
		
		// For rate limit or invalid OTP, return the response with attempts left
		if (errors.Is(err, service.ErrOTPRateLimitExceeded) || 
			errors.Is(err, service.ErrOTPInvalid)) && response != nil {
			h.respondWithJSON(w, statusCode, response)
			return
		}
		
		h.respondWithError(w, statusCode, err, "OTP verification failed")
		return
	}
	
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP verified successfully"))
	
	h.logger.Info("OTP verification completed",
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.Bool("success", true),
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
func (h *OTPHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()
	
	var req service.OTPResendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	
	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(strings.TrimSpace(req.PhoneNumber))
	req.Purpose = util.SanitizeInput(strings.TrimSpace(strings.ToLower(req.Purpose)))
	req.IPAddress = h.getClientIP(r)
	
	// Validate
	if req.PhoneNumber == "" || req.Purpose == "" {
		h.respondWithError(w, http.StatusBadRequest, 
			errors.New("phone_number and purpose are required"), 
			"Invalid request")
		return
	}
	
	// Resend OTP
	response, err := h.otpService.ResendOTP(ctx, &req)
	if err != nil {
		statusCode := h.getStatusCodeForError(err)
		
		if errors.Is(err, service.ErrOTPRateLimitExceeded) && response != nil {
			w.Header().Set("Retry-After", string(rune(response.RetryAfter)))
			h.respondWithJSON(w, statusCode, response)
			return
		}
		
		h.respondWithError(w, statusCode, err, "Failed to resend OTP")
		return
	}
	
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "OTP resent successfully"))
	
	h.logger.Info("OTP resend completed",
		util.String("purpose", req.Purpose),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
		"status": "healthy",
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
		"message": "Cleanup completed",
	}, "OTP cleanup successful"))
}

// ============================================
// HELPER METHODS
// ============================================

// getClientIP extracts client IP from request
func (h *OTPHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// getStatusCodeForError maps service errors to HTTP status codes
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

// respondWithJSON sends a JSON response
func (h *OTPHandler) respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response",
			util.ErrorField(err),
		)
	}
}

// respondWithError sends an error response
func (h *OTPHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	response := errorResponse(err, message)
	h.respondWithJSON(w, statusCode, response)
	
	h.logger.Warn("OTP operation failed",
		util.ErrorField(err),
		util.String("message", message),
		util.Int("status_code", statusCode),
	)
}