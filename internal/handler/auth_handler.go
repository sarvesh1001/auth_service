package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"regexp"

	"github.com/go-playground/validator/v10"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var validate = validator.New()

func init() {
	// Custom validation for alphanumeric + dash + underscore
	validate.RegisterValidation("alphanumdash", func(fl validator.FieldLevel) bool {
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(fl.Field().String())
	})
}

// AuthHandler handles HTTP requests for authentication and user operations
type AuthHandler struct {
	otpService     *service.OTPService
	mpinService    *service.MPINService
	sessionService *service.SessionService
	userService    *service.UserService
	deviceService  *service.DeviceService
	jwtService     *service.JWTService
	logger         *zap.Logger
}

func NewAuthHandler(
	otpService *service.OTPService,
	mpinService *service.MPINService,
	sessionService *service.SessionService,
	userService *service.UserService,
	deviceService *service.DeviceService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		otpService:     otpService,
		mpinService:    mpinService,
		sessionService: sessionService,
		userService:    userService,
		deviceService:  deviceService,
		jwtService:     jwtService,
		logger:         logger,
	}
}

// ============================================
// ROUTE REGISTRATION
// ============================================

// RegisterPublicRoutes registers only public authentication routes
func (h *AuthHandler) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth", func(r chi.Router) {
		// Complete authentication flow (public)
		r.Post("/login/initiate", h.InitiateLogin)
		r.Post("/login/verify-otp", h.VerifyOTPLogin)
		r.Post("/login/verify-mpin", h.VerifyMPINLogin)
		r.Post("/register", h.RegisterUser)
		r.Post("/mpin/setup", h.SetupMPIN)

		// ✅ ADDED: MPIN Forgot Flow APIs
		r.Post("/mpin/forgot/send-otp", h.SendForgotMPINOTP)
		r.Post("/mpin/forgot/verify-otp", h.VerifyForgotMPINOTP)
		r.Post("/mpin/forgot", h.ForgotMPIN)
		r.Post("/mpin/change", h.ChangeMPIN)

		// Token refresh (public - uses refresh token)
		r.Post("/refresh", h.RefreshTokens)

		// Debug endpoint (temporary - remove in production)
		r.Get("/debug-token", h.DebugToken)
	})
}

// RegisterProtectedRoutes registers JWT-protected authentication and user routes
func (h *AuthHandler) RegisterProtectedRoutes(router chi.Router) {
	router.Route("/auth", func(r chi.Router) {
		// Session validation (protected - requires JWT)
		r.Get("/validate", h.ValidateSession)
		r.Get("/status", h.GetAuthStatus)
		r.Post("/logout", h.Logout)
		r.Post("/logout/all", h.LogoutAllDevices)
	})

	// User management routes (protected - requires JWT)
	router.Route("/users", func(r chi.Router) {
		// User profile operations
		r.Get("/{userID}", h.GetUserByID)
		r.Put("/{userID}", h.UpdateUser)
		r.Patch("/{userID}/last-login", h.UpdateLastLogin)

		// Health check
		r.Get("/health", h.UserHealthCheck)
	})
}

// RegisterUserPublicRoutes registers user routes that should be publicly accessible
func (h *AuthHandler) RegisterUserPublicRoutes(router chi.Router) {
	router.Route("/users", func(r chi.Router) {
		// Public user routes - for checking user existence without authentication
		r.Get("/phone/{phoneNumber}", h.GetUserByPhonePublic)
		r.Get("/health", h.UserHealthCheck)
	})
}

// For backward compatibility
func (h *AuthHandler) RegisterRoutes(router chi.Router) {
	h.RegisterPublicRoutes(router)
}

// ============================================
// AUTHENTICATION FLOW METHODS (Google-style: OTP first, then MPIN)
// ============================================

// LoginFlowRequest for starting login process
type LoginFlowRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
}

// LoginFlowResponse returns available auth methods and flow state
type LoginFlowResponse struct {
	FlowState     string `json:"flow_state"` // "new_user", "existing_user_mpin", "existing_user_otp", "mpin_locked"
	UserExists    bool   `json:"user_exists"`
	HasMPIN       bool   `json:"has_mpin"`
	MPINLocked    bool   `json:"mpin_locked"`
	DeviceTrusted bool   `json:"device_trusted"`
	Message       string `json:"message"`
	UserID        string `json:"user_id,omitempty"`
}

// InitiateLogin determines the authentication flow for user
func (h *AuthHandler) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req LoginFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.DataRegion = util.SanitizeInput(req.DataRegion)

	// Check if user exists
	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	userExists := err == nil && user != nil

	response := &LoginFlowResponse{
		UserExists: userExists,
	}

	if !userExists {
		// New user flow - always requires OTP
		response.FlowState = "new_user"
		response.Message = "New user - OTP verification required for registration"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	// Existing user - check MPIN status
	mpinStatus, err := h.mpinService.GetMPINStatus(ctx, user.UserID)
	if err != nil {
		// No MPIN setup - require OTP
		response.FlowState = "existing_user_otp"
		response.Message = "Existing user - OTP verification required (no MPIN setup)"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	response.HasMPIN = true
	response.MPINLocked = mpinStatus.IsLocked

	// Check if device is trusted
	deviceTrusted, _ := h.deviceService.IsDeviceTrusted(ctx, user.UserID, req.DeviceID)

	if response.MPINLocked {
		// MPIN locked - require OTP
		response.FlowState = "mpin_locked"
		response.Message = "MPIN locked - OTP verification required"
	} else if deviceTrusted {
		// Trusted device - allow MPIN login
		response.FlowState = "existing_user_mpin"
		response.DeviceTrusted = true
		response.Message = "Trusted device - MPIN login available"
		response.UserID = user.UserID.String()
	} else {
		// Untrusted device - require OTP first
		response.FlowState = "existing_user_otp"
		response.Message = "Untrusted device - OTP verification required"
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))

	h.logger.Info("Login initiation completed",
		util.String("phone", req.PhoneNumber),
		util.Bool("user_exists", userExists),
		util.Bool("has_mpin", response.HasMPIN),
		util.Bool("mpin_locked", response.MPINLocked),
		util.Bool("device_trusted", deviceTrusted),
		util.String("flow_state", response.FlowState),
		util.Duration("duration", time.Since(startTime)),
	)
}

// RegisterUserRequest for user registration
type RegisterUserRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
	OTP               string `json:"otp" validate:"required"`
}

// RegisterUser handles new user registration with OTP verification - NO TOKENS (Google Pay style)
func (h *AuthHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.DataRegion = util.SanitizeInput(req.DataRegion)
	req.OTP = util.SanitizeInput(req.OTP)

	// Verify OTP first
	otpVerifyReq := service.OTPVerifyRequest{
		PhoneNumber: req.PhoneNumber,
		OTP:         req.OTP,
		Purpose:     "registration",
		IPAddress:   h.getClientIP(r),
	}

	otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Invalid OTP")
		return
	}

	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("OTP_VERIFICATION_FAILED: OTP verification failed"),
			"OTP verification failed")
		return
	}

	// Create user
	createUserReq := service.UserCreateRequest{
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		DataRegion:        req.DataRegion,
		ConsentAgreed:     true,
		ConsentVersion:    "v1.0",
	}

	user, err := h.userService.CreateUser(ctx, &createUserReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create user")
		return
	}

	// Bind device as trusted
	deviceReq := service.BindDeviceRequest{
		UserID:    user.UserID,
		DeviceID:  req.DeviceID,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		h.logger.Warn("Failed to bind device during registration", util.ErrorField(err))
	}

	// ✅ NO TOKENS ISSUED - Google Pay style: OTP only for device setup
	h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
		"user_id":        user.UserID.String(),
		"device_trusted": true,
		"has_mpin":       false,
		"message":        "User registered successfully. Please setup MPIN for daily authentication.",
	}, "User registered successfully"))

	h.logger.Info("User registered via OTP - device trusted (no tokens issued)",
		util.String("user_id", user.UserID.String()),
		util.String("phone", req.PhoneNumber),
		util.Duration("duration", time.Since(startTime)),
	)
}

// VerifyOTPLogin handles OTP verification for device setup/recovery - NO TOKENS (Google Pay style)
func (h *AuthHandler) VerifyOTPLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		OTP               string `json:"otp" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.OTP = util.SanitizeInput(req.OTP)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	// Verify OTP
	otpVerifyReq := service.OTPVerifyRequest{
		PhoneNumber: req.PhoneNumber,
		OTP:         req.OTP,
		Purpose:     "login",
		IPAddress:   h.getClientIP(r),
	}

	otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "OTP verification failed")
		return
	}

	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("OTP_VERIFICATION_FAILED: OTP verification failed"),
			"OTP verification failed")
		return
	}

	// Get user
	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "User not found")
		return
	}

	// Update device trust (mark device as trusted)
	deviceReq := service.BindDeviceRequest{
		UserID:    user.UserID,
		DeviceID:  req.DeviceID,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		h.logger.Warn("Failed to update device trust", util.ErrorField(err))
	}

	// Unlock MPIN if it was locked
	if mpinStatus, err := h.mpinService.GetMPINStatus(ctx, user.UserID); err == nil && mpinStatus.IsLocked {
		if err := h.mpinService.UnlockMPIN(ctx, user.UserID); err != nil {
			h.logger.Warn("Failed to unlock MPIN after OTP verification", util.ErrorField(err))
		}
	}

	// ✅ NO TOKENS ISSUED - Google Pay style: OTP only for device trust
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"user_id":        user.UserID.String(),
		"device_trusted": true,
		"has_mpin":       h.hasMPIN(ctx, user.UserID),
		"mpin_locked":    false, // Just unlocked if it was locked
		"message":        "OTP verification successful. Device is now trusted.",
	}, "Device setup successful"))

	h.logger.Info("OTP verification completed - device trusted (no tokens issued)",
		util.String("user_id", user.UserID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
}

// VerifyMPINLogin handles MPIN verification for daily login - RETURNS JWT TOKENS (Google Pay style)
func (h *AuthHandler) VerifyMPINLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		UserID            string `json:"user_id" validate:"required"`
		MPIN              string `json:"mpin" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// Verify device trust
	deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, userID, req.DeviceID)
	if err != nil || !deviceTrusted {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
			"MPIN login not allowed on this device")
		return
	}

	// Verify MPIN
	mpinVerifyReq := service.MPINVerifyRequest{
		UserID:   userID,
		MPIN:     req.MPIN,
		DeviceID: req.DeviceID,
	}

	mpinResult, err := h.mpinService.VerifyMPIN(ctx, &mpinVerifyReq)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "MPIN verification failed")
		return
	}

	if !mpinResult.Verified {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("MPIN_VERIFICATION_FAILED: %s", mpinResult.Message),
			"MPIN verification failed")
		return
	}

	// ✅ USE JWT TOKEN PAIR FOR DAILY AUTHENTICATION
	tokenReq := &service.IssueTokenPairRequest{
		UserID:      userID.String(),
		Role:        "user",
		DeviceID:    req.DeviceID,
		SessionType: "user",
		IPAddress:   h.getClientIP(r),
	}

	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue tokens")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"tokens":  tokens, // ✅ JWT access_token + refresh_token for API access
		"user_id": userID.String(),
		"message": "MPIN login successful",
	}, "Login successful"))

	h.logger.Info("MPIN login completed with JWT tokens",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SetupMPINRequest for MPIN setup
type SetupMPINRequest struct {
	UserID   string `json:"user_id" validate:"required"`
	MPIN     string `json:"mpin" validate:"required,min=4,max=6"`
	DeviceID string `json:"device_id" validate:"required"`
}

// SetupMPIN handles MPIN setup after registration - NO TOKENS (Google Pay style)
func (h *AuthHandler) SetupMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req SetupMPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// Setup MPIN
	mpinReq := service.MPINSetupRequest{
		UserID:   userID,
		MPIN:     req.MPIN,
		DeviceID: req.DeviceID,
	}

	if err := h.mpinService.SetupMPIN(ctx, &mpinReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to setup MPIN")
		return
	}

	// ✅ NO TOKENS ISSUED - Only MPIN setup completed
	h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
		"message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
	}, "MPIN setup successful"))

	h.logger.Info("MPIN setup completed (no tokens issued)",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ============================================
// ✅ ADDED: MPIN FORGOT FLOW METHODS
// ============================================

// SendForgotMPINOTP handles sending OTP for MPIN reset
func (h *AuthHandler) SendForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid request")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid user ID")
		return
	}

	requestID, err := h.mpinService.SendForgotMPINOTP(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "failed to send OTP")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"request_id": requestID,
		"message":    "OTP sent to registered phone number",
	}, "OTP sent successfully"))
}

// VerifyForgotMPINOTP handles OTP verification and MPIN reset
func (h *AuthHandler) VerifyForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.MPINForgotWithOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid request")
		return
	}

	if err := h.mpinService.VerifyForgotMPINOTP(ctx, &req); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "failed to verify OTP and reset MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))
}

// ForgotMPIN handles MPIN reset on trusted devices
func (h *AuthHandler) ForgotMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.MPINForgotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)

	if err := h.mpinService.ForgotMPIN(ctx, &req); err != nil {
		statusCode := h.getForgotMPINStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to reset MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully on trusted device"))

	h.logger.Info("MPIN reset via forgot flow",
		util.String("user_id", req.UserID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ChangeMPIN handles MPIN change with current MPIN verification
func (h *AuthHandler) ChangeMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.MPINChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.CurrentMPIN = util.SanitizeInput(req.CurrentMPIN)
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)

	if err := h.mpinService.ChangeMPIN(ctx, &req); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to change MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN changed successfully"))

	h.logger.Info("MPIN changed via HTTP",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ============================================
// SESSION MANAGEMENT METHODS
// ============================================

// RefreshTokens handles token refresh
func (h *AuthHandler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	ipAddress := h.getClientIP(r)

	tokenPair, err := h.sessionService.RefreshTokenPair(ctx, req.RefreshToken, ipAddress)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Failed to refresh tokens")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Tokens refreshed successfully"))
}

// Logout handles user logout (single device) - PROTECTED
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.sessionService.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to logout")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Logged out successfully"))
}

// LogoutAllDevices handles logout from all devices - PROTECTED
func (h *AuthHandler) LogoutAllDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		UserID string `json:"user_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// FIXED: Convert UUID to string for the session service method
	if err := h.sessionService.RevokeAllUserRefreshTokens(ctx, userID.String()); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to logout from all devices")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Logged out from all devices successfully"))
}

// ValidateSession checks if the current session is valid - PROTECTED
func (h *AuthHandler) ValidateSession(w http.ResponseWriter, r *http.Request) {
	// If JWT middleware passes, the session is valid
	userID := r.Context().Value("user_id")
	deviceID := r.Context().Value("device_id")

	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("INVALID_SESSION: No valid session"),
			"Session validation failed")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"valid":     true,
		"user_id":   userID,
		"device_id": deviceID,
		"message":   "Session is valid",
	}, "Session validation successful"))
}

// GetAuthStatus returns authentication status - PROTECTED
func (h *AuthHandler) GetAuthStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")

	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("NOT_AUTHENTICATED: User not authenticated"),
			"Authentication required")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"authenticated": true,
		"user_id":       userID,
		"message":       "User is authenticated",
	}, "Authentication status"))
}

// DebugToken - Temporary endpoint to debug JWT tokens
func (h *AuthHandler) DebugToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("NO_AUTH_HEADER"), "No Authorization header")
		return
	}

	// Extract token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("INVALID_AUTH_FORMAT"), "Invalid Authorization format")
		return
	}

	tokenString := parts[1]

	// Manually validate the token using JWT service
	claims, err := h.jwtService.ValidateAccessToken(r.Context(), tokenString)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Token validation failed")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"valid": true,
		"claims": map[string]interface{}{
			"user_id":      claims.UserID,
			"device_id":    claims.DeviceID,
			"role":         claims.Role,
			"session_type": claims.SessionType,
			"jti":          claims.JTI,
			"expires_at":   claims.ExpiresAt,
		},
		"message": "Token is valid",
	}, "Token validation successful"))
}

// ============================================
// USER MANAGEMENT METHODS
// ============================================

// GetUserByID handles user retrieval by ID - PROTECTED
func (h *AuthHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	user, err := h.userService.GetUserByID(ctx, userID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get user")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User retrieved successfully"))
	h.logger.Debug("User retrieved via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUserByID"),
	)
}

// GetUserByPhonePublic handles user retrieval by phone number - PUBLIC (No JWT required)
func (h *AuthHandler) GetUserByPhonePublic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	phoneNumber := chi.URLParam(r, "phoneNumber")
	if phoneNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("phone number is required"), "Phone number is required")
		return
	}

	// Sanitize input
	phoneNumber = util.SanitizeInput(phoneNumber)

	user, err := h.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		// Return 404 for not found, but don't expose internal errors
		if errors.Is(err, service.ErrUserNotFound) {
			h.respondWithError(w, http.StatusNotFound, err, "User not found")
			return
		}
		// For other errors, return generic error message
		h.respondWithError(w, http.StatusInternalServerError,
			errors.New("internal server error"), "Failed to get user by phone")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	// Return minimal user info for existence check
	response := map[string]interface{}{
		"user_exists": true,
		"user_id":     user.UserID.String(),
		"is_verified": user.IsVerified,
		"is_blocked":  user.IsBlocked,
		"is_banned":   user.IsBanned,
		"data_region": user.DataRegion,
		"created_at":  user.CreatedAt,
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "User found"))
	h.logger.Debug("User retrieved by phone via public API",
		util.String("phone", phoneNumber),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUserByPhonePublic"),
	)
}

// UpdateUser handles user updates - PROTECTED
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req service.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	user, err := h.userService.UpdateUser(ctx, userID, &req)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))
	h.logger.Info("User updated via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUser"),
	)
}

// UpdateLastLogin handles last login updates - PROTECTED
func (h *AuthHandler) UpdateLastLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	if err := h.userService.UpdateLastLogin(ctx, userID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update last login")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Last login updated successfully"))
	h.logger.Debug("Last login updated via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateLastLogin"),
	)
}

// UserHealthCheck handles user service health check
func (h *AuthHandler) UserHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.userService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err, "Service unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Service is healthy"))
}

// ============================================
// HELPER METHODS
// ============================================

// Helper methods
func (h *AuthHandler) hasMPIN(ctx context.Context, userID uuid.UUID) bool {
	status, err := h.mpinService.GetMPINStatus(ctx, userID)
	return err == nil && status != nil
}

func (h *AuthHandler) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func (h *AuthHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("Auth HTTP error",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// getStatusCode determines the appropriate HTTP status code for an error
func (h *AuthHandler) getStatusCode(err error) int {
	switch {
	case errors.Is(err, service.ErrUserNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, service.ErrUserAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, service.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, service.ErrUserBanned), errors.Is(err, service.ErrUserBlocked):
		return http.StatusForbidden
	case errors.Is(err, service.ErrKYCRequired):
		return http.StatusPreconditionFailed
	default:
		return http.StatusInternalServerError
	}
}

// getForgotMPINStatusCode determines status code for MPIN forgot errors
func (h *AuthHandler) getForgotMPINStatusCode(err error) int {
	errMsg := err.Error()
	if strings.Contains(errMsg, "untrusted device") || strings.Contains(errMsg, "blocked") {
		return http.StatusForbidden
	}
	if strings.Contains(errMsg, "not found") {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// sanitizeUser removes sensitive data from user before sending in response
func (h *AuthHandler) sanitizeUser(user *models.User) {
	// Clear encrypted phone data
	user.PhoneEncrypted = ""
	user.PhoneKeyID = uuid.Nil
	// Note: We keep phone hash for identification but not the encrypted version
}