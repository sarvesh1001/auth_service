package handler

import (
	"auth-service/internal/contextkeys"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	appErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// ========== CONTEXT KEY CONSTANTS ==========
// These must match the keys used in the service layer.

var validate = validator.New()

func init() {
	validate.RegisterValidation("alphanumdash", func(fl validator.FieldLevel) bool {
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(fl.Field().String())
	})
	validate.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		value := fl.Field().String()
		re := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
		return re.MatchString(value)
	})
}

// AuthHandler handles authentication and user-related endpoints.
type AuthHandler struct {
	userOTPService *service.UserOTPService
	mpinService    *service.MPINService
	sessionService *service.SessionService
	userService    *service.UserService
	companyService *service.CompanyService
	deviceService  *service.DeviceService
	jwtService     *service.JWTService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	userOTPService *service.UserOTPService,
	mpinService *service.MPINService,
	sessionService *service.SessionService,
	userService *service.UserService,
	companyService *service.CompanyService,
	deviceService *service.DeviceService,
	jwtService *service.JWTService,
) *AuthHandler {
	return &AuthHandler{
		userOTPService: userOTPService,
		mpinService:    mpinService,
		sessionService: sessionService,
		userService:    userService,
		companyService: companyService,
		deviceService:  deviceService,
		jwtService:     jwtService,
	}
}

// ---------- Context injection helpers ----------

// ---------- Helper functions for context injection ----------

func (h *AuthHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
// handler/auth_handler.go

func (h *AuthHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *AuthHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// ---------- Error mapping ----------

func (h *AuthHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	switch {
	case errors.Is(err, appErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, appErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, appErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, appErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, appErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, appErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"

	// OTP errors
	case errors.Is(err, appErrors.ErrOTPRateLimitExceeded),
		errors.Is(err, appErrors.ErrOTPAttemptsExceeded),
		errors.Is(err, appErrors.ErrDailyQuotaExceeded):
		return http.StatusTooManyRequests, err.Error()
	case errors.Is(err, appErrors.ErrOTPNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, appErrors.ErrOTPInvalid),
		errors.Is(err, appErrors.ErrOTPExpired),
		errors.Is(err, appErrors.ErrOTPReplayAttempt):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, appErrors.ErrOTPAlreadyVerified):
		return http.StatusConflict, err.Error()
	case errors.Is(err, appErrors.ErrOTPBlocked):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, appErrors.ErrPhoneNotRegistered):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, appErrors.ErrSecurityCheckFailed):
		return http.StatusForbidden, err.Error()

	// MPIN errors
	case errors.Is(err, appErrors.ErrAdminMPINNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, appErrors.ErrAdminMPINInvalid):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, appErrors.ErrAdminMPINLocked):
		return http.StatusLocked, err.Error()
	case errors.Is(err, appErrors.ErrAdminMPINAlreadyExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, appErrors.ErrAdminMPINTooWeak):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, appErrors.ErrAdminMPINRateLimitExceeded),
		errors.Is(err, appErrors.ErrAdminMPINAttemptsExceeded):
		return http.StatusTooManyRequests, err.Error()

	// Device errors
	case errors.Is(err, appErrors.ErrDeviceNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, appErrors.ErrDeviceAlreadyBound),
		errors.Is(err, appErrors.ErrDeviceAlreadyActive),
		errors.Is(err, appErrors.ErrTooManyDevices):
		return http.StatusConflict, err.Error()
	case errors.Is(err, appErrors.ErrDeviceNotTrusted),
		errors.Is(err, appErrors.ErrDeviceBlocked),
		errors.Is(err, appErrors.ErrDeviceNotActive):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, appErrors.ErrInvalidDeviceID),
		errors.Is(err, appErrors.ErrBindingTokenMismatch),
		errors.Is(err, appErrors.ErrDeviceBindingExpired),
		errors.Is(err, appErrors.ErrDeviceVerificationFailed):
		return http.StatusBadRequest, err.Error()

	// Admin/user errors
	case errors.Is(err, appErrors.ErrInvalidState),
		errors.Is(err, appErrors.ErrInvalidStatus),
		errors.Is(err, appErrors.ErrInvalidTransition):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, appErrors.ErrAdminInactive):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, appErrors.ErrRoleInUse):
		return http.StatusConflict, err.Error()
	case errors.Is(err, appErrors.ErrSystemRole):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, appErrors.ErrSuperAdminRequired):
		return http.StatusForbidden, err.Error()

	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Public routes registration ----------

// RegisterPublicRoutes registers all public authentication endpoints.
// @Summary Register public auth routes
// @Tags auth-public
func (h *AuthHandler) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth", func(r chi.Router) {
		r.Post("/login/initiate", h.InitiateLogin)
		r.Post("/login/verify-otp", h.VerifyOTPLogin)
		r.Get("/companies/by-employee-phone", h.GetCompanyByEmployeePhonePublic)
		r.Post("/login/verify-mpin", h.VerifyMPINLogin)
		r.Post("/mpin/setup", h.SetupMPIN)
		r.Post("/otp/send", h.SendOTP)
		r.Post("/mpin/forgot/send-otp", h.SendForgotMPINOTP)
		r.Post("/mpin/forgot/verify-otp", h.VerifyForgotMPINOTP)
		r.Post("/mpin/forgot", h.ForgotMPIN)
		r.Post("/mpin/change", h.ChangeMPIN)
		r.Post("/refresh", h.RefreshTokens)
		r.Get("/debug-token", h.DebugToken)
	})
}

// RegisterProtectedRoutes registers routes that require authentication.
func (h *AuthHandler) RegisterProtectedRoutes(r chi.Router) {
	r.Get("/auth/validate", h.ValidateSession)
	r.Get("/auth/status", h.GetAuthStatus)
	r.Post("/auth/logout", h.Logout)
	r.Post("/auth/logout/all", h.LogoutAllDevices)
	r.Get("/users/{userID}", h.GetUserByID)
	r.Put("/users/{userID}", h.UpdateUser)
	r.Patch("/users/{userID}/last-login", h.UpdateLastLogin)
	r.Get("/users/health", h.UserHealthCheck)
	r.Route("/companies", func(r chi.Router) {
		r.Get("/{companyID}", h.GetCompany)
		r.Get("/{companyID}/employees", h.ListEmployees)
		r.Delete("/{companyID}/employees/{userID}", h.RemoveEmployee)
		r.Get("/context", h.GetCompanyContext)
		r.Post("/{companyID}/employees/{userID}/role", h.UpdateEmployeeRole)
		r.Get("/{companyID}/hierarchy", h.GetCompanyHierarchy)
		r.Route("/{companyID}/departments", func(r chi.Router) {
			r.Put("/{departmentID}", h.RenameDepartment)
			r.Post("/", h.AddDepartment)
		})
		r.Route("/{companyID}/managers", func(r chi.Router) {
			r.Post("/{managerID}/permissions", h.AssignManagerPermissions)
			r.Delete("/{managerID}/permissions", h.RevokeManagerPermissions)
		})
	})
}

// RegisterUserPublicRoutes registers public user endpoints.
func (h *AuthHandler) RegisterUserPublicRoutes(router chi.Router) {
	router.Route("/users", func(r chi.Router) {
		r.Get("/phone/{phoneNumber}", h.GetUserByPhonePublic)
		r.Get("/health", h.UserHealthCheck)
	})
}

// RegisterRoutes is a convenience method to register all routes.
func (h *AuthHandler) RegisterRoutes(router chi.Router) {
	h.RegisterPublicRoutes(router)
}

// ---------- Request/Response types ----------

type LoginFlowRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
}

type UserLoginFlowResponse struct {
	FlowState     string `json:"flow_state"`
	UserExists    bool   `json:"user_exists"`
	HasMPIN       bool   `json:"has_mpin"`
	MPINLocked    bool   `json:"mpin_locked"`
	DeviceTrusted bool   `json:"device_trusted"`
	Message       string `json:"message"`
	UserID        string `json:"user_id,omitempty"`
}

type MPINSetupPhoneRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	MPIN              string `json:"mpin" validate:"required,min=4,max=8"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type MPINVerifyPhoneRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	MPIN              string `json:"mpin" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	UserAgent         string `json:"user_agent,omitempty"`
	CompanyID         string `json:"company_id,omitempty"`
}

type MPINChangePhoneRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	CurrentMPIN       string `json:"current_mpin" validate:"required"`
	NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type MPINForgotPhoneRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type MPINForgotWithOTPPhoneRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
	OTPCode           string `json:"otp_code" validate:"required,len=6"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// ---------- Login initiation ----------

// InitiateLogin handles the first step of user login.
// @Summary Initiate user login
// @Description Determines the login flow based on user existence, MPIN status, and device trust.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body LoginFlowRequest true "Login initiation request"
// @Success 200 {object} map[string]interface{} "Login flow determined"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 403 {object} map[string]interface{} "User inactive"
// @Router /api/v1/auth/login/initiate [post]
func (h *AuthHandler) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	logger, _ := zap.NewDevelopment() // or zap.NewProduction()
	defer logger.Sync()

	ctx := h.injectClientIP(r.Context(), r)

	var req LoginFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("Invalid request body", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.DataRegion = util.SanitizeInput(req.DataRegion)

	logger.Debug("InitiateLogin request",
		zap.String("phone_number", req.PhoneNumber),
		zap.String("device_id", req.DeviceID),
		zap.String("fingerprint", req.DeviceFingerprint),
	)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		logger.Warn("GetUserByPhone failed", zap.Error(err))
		h.respondWithError(w, status, err, msg)
		return
	}
	if !user.IsActive {
		logger.Warn("User inactive", zap.String("user_id", user.UserID.String()))
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrAdminInactive, "Account is inactive. Please contact support.")
		return
	}

	response := &UserLoginFlowResponse{
		UserExists: true,
	}

	// --- CHECK DEVICE TRUST FIRST (always set) ---
	deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, user.UserID, req.DeviceID)
	if err != nil {
		logger.Error("IsDeviceTrusted failed",
			zap.String("user_id", user.UserID.String()),
			zap.String("device_id", req.DeviceID),
			zap.Error(err),
		)
		deviceTrusted = false // safe fallback
	}
	response.DeviceTrusted = deviceTrusted // always set

	logger.Info("Device trust result",
		zap.String("user_id", user.UserID.String()),
		zap.String("device_id", req.DeviceID),
		zap.Bool("device_trusted", deviceTrusted),
	)

	// --- MPIN status check ---
	mpinStatus, err := h.mpinService.GetMPINStatus(ctx, user.UserID)
	if err != nil {
		// MPIN not found – respond with OTP flow, but DeviceTrusted is already set
		response.FlowState = "existing_user_otp"
		response.Message = "Existing user - OTP verification required (no MPIN setup)"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	response.HasMPIN = true
	response.MPINLocked = mpinStatus.IsLocked

	// Determine flow based on MPIN lock and device trust
	if response.MPINLocked {
		response.FlowState = "mpin_locked"
		response.Message = "MPIN locked - OTP verification required"
	} else if deviceTrusted {
		response.FlowState = "existing_user_mpin"
		response.Message = "Trusted device - MPIN login available"
		response.UserID = user.UserID.String()
	} else {
		response.FlowState = "existing_user_otp"
		response.Message = "Untrusted device - OTP verification required"
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
}

// ---------- OTP verification ----------

// VerifyOTPLogin verifies OTP and binds device.
// @Summary Verify user OTP login
// @Description Verifies OTP for user login and binds the device.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "OTP verification request" example({"phone_number":"+919876543210","otp":"123456","device_id":"test-device-001","device_fingerprint":"test-fingerprint"})
// @Success 200 {object} map[string]interface{} "OTP verified, device trusted"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Authentication failed"
// @Failure 429 {object} map[string]interface{} "Rate limit or quota exceeded"
// @Router /api/v1/auth/login/verify-otp [post]
func (h *AuthHandler) VerifyOTPLogin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		OTP               string `json:"otp" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.OTP = util.SanitizeInput(req.OTP)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	otpVerifyReq := &service.UserOTPVerifyRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               req.OTP,
		Purpose:           "login",
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
	}

	otpResponse, err := h.userOTPService.UserVerifyOTP(ctx, otpVerifyReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrOTPInvalid, "Authentication failed")
		return
	}

	deviceReq := service.BindDeviceRequest{
		UserID:    user.UserID,
		DeviceID:  req.DeviceID,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}
	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		// non-critical
		_ = err
	}

	if mpinStatus, err := h.mpinService.GetMPINStatus(ctx, user.UserID); err == nil && mpinStatus.IsLocked {
		_ = h.mpinService.UnlockMPIN(ctx, user.UserID)
	}

	hasMPIN := h.hasMPIN(ctx, user.UserID)

	responseData := map[string]interface{}{
		"user_id":        user.UserID.String(),
		"device_trusted": true,
		"has_mpin":       hasMPIN,
		"mpin_locked":    false,
		"daily_quota": map[string]interface{}{
			"used":      otpResponse.QuotaUsed,
			"limit":     otpResponse.DailyQuota,
			"remaining": otpResponse.DailyQuota - otpResponse.QuotaUsed,
		},
	}
	if hasMPIN {
		responseData["next_step"] = "mpin_login"
		responseData["message"] = "OTP verification successful. Please use MPIN for daily authentication."
	} else {
		responseData["next_step"] = "setup_mpin"
		responseData["message"] = "OTP verification successful. Please setup MPIN for daily authentication."
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Device setup successful"))
}

// ---------- MPIN management ----------

// SetupMPIN sets up MPIN for a user.
// @Summary Setup user MPIN
// @Description Creates an MPIN for the user after successful OTP verification.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body MPINSetupPhoneRequest true "MPIN setup request"
// @Success 201 {object} map[string]interface{} "MPIN setup successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/auth/mpin/setup [post]
func (h *AuthHandler) SetupMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req MPINSetupPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	mpinReq := service.MPINSetupRequest{
		UserID:            user.UserID,
		MPIN:              req.MPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.SetupMPIN(ctx, &mpinReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
		"message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
	}, "MPIN setup successful"))
}

// ChangeMPIN changes a user's MPIN.
// @Summary Change user MPIN
// @Description Updates MPIN after verifying current MPIN.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body MPINChangePhoneRequest true "MPIN change request"
// @Success 200 {object} map[string]interface{} "MPIN changed"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/auth/mpin/change [post]
func (h *AuthHandler) ChangeMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req MPINChangePhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.CurrentMPIN = util.SanitizeInput(req.CurrentMPIN)
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	mpinChangeReq := service.MPINChangeRequest{
		UserID:            user.UserID,
		CurrentMPIN:       req.CurrentMPIN,
		NewMPIN:           req.NewMPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.ChangeMPIN(ctx, &mpinChangeReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "MPIN changed successfully",
	}, "MPIN change successful"))
}

// SendOTP sends an OTP for various purposes.
// @Summary Send OTP
// @Description Sends OTP for login, verification, password reset, or forgot MPIN.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "OTP send request" example({"phone_number":"+919876543210","device_id":"test-device-001","device_fingerprint":"test-fingerprint","purpose":"login"})
// @Success 200 {object} map[string]interface{} "OTP sent"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 429 {object} map[string]interface{} "Rate limit or quota exceeded"
// @Router /api/v1/auth/otp/send [post]
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
		Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset forgot_mpin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.Purpose = util.SanitizeInput(req.Purpose)

	otpSendReq := &service.UserOTPSendRequest{
		PhoneNumber:       req.PhoneNumber,
		Purpose:           req.Purpose,
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
		Provider:          "resend",
	}

	otpResponse, err := h.userOTPService.UserSendOTP(ctx, otpSendReq)
	if err != nil {
		if errors.Is(err, appErrors.ErrOTPRateLimitExceeded) || errors.Is(err, appErrors.ErrDailyQuotaExceeded) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", otpResponse.RetryAfter))
			h.respondWithJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"success":     false,
				"message":     otpResponse.Message,
				"expires_at":  otpResponse.ExpiresAt,
				"retry_after": otpResponse.RetryAfter,
			})
			return
		}
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !otpResponse.Success {
		h.respondWithError(w, http.StatusTooManyRequests, appErrors.ErrOTPRateLimitExceeded, otpResponse.Message)
		return
	}

	responseData := map[string]interface{}{
		"message":       "OTP sent successfully",
		"expires_at":    otpResponse.ExpiresAt,
		"attempts_left": otpResponse.AttemptsLeft,
	}
	if otpResponse.DailyQuota > 0 {
		responseData["daily_quota"] = map[string]interface{}{
			"used":      otpResponse.QuotaUsed,
			"limit":     otpResponse.DailyQuota,
			"remaining": otpResponse.DailyQuota - otpResponse.QuotaUsed,
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "OTP sent successfully"))
}

// ---------- Token refresh and logout ----------

// RefreshTokens refreshes JWT tokens.
// @Summary Refresh tokens
// @Description Issues new access and refresh tokens using a valid refresh token.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "Refresh token request" example({"refresh_token":"..."})
// @Success 200 {object} map[string]interface{} "New token pair"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid or expired refresh token"
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Tokens refreshed successfully"))
}

// Logout logs out a user by revoking the refresh token.
// @Summary Logout user
// @Description Revokes the provided refresh token, logging out the user from that device.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "Logout request" example({"refresh_token":"..."})
// @Success 200 {object} map[string]interface{} "Logged out"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/auth/logout [post]
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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Logged out successfully"))
}

// LogoutAllDevices logs out a user from all devices.
// @Summary Logout all devices
// @Description Revokes all refresh tokens for a user, logging them out from all devices.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "User ID" example({"user_id":"..."})
// @Success 200 {object} map[string]interface{} "Logged out from all devices"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/auth/logout/all [post]
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

	if err := h.sessionService.RevokeAllUserRefreshTokens(ctx, userID.String()); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Logged out from all devices successfully"))
}

// ---------- Session validation ----------

// ValidateSession validates the current session.
// @Summary Validate session
// @Description Checks if the provided JWT is valid and returns user info.
// @Tags auth-user
// @Produce json
// @Success 200 {object} map[string]interface{} "Session valid"
// @Failure 401 {object} map[string]interface{} "Invalid or missing token"
// @Router /api/v1/auth/validate [get]
func (h *AuthHandler) ValidateSession(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	deviceID := r.Context().Value("device_id")
	role := r.Context().Value("role")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Session validation failed")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"valid":     true,
		"user_id":   userID,
		"device_id": deviceID,
		"role":      role,
		"message":   "Session is valid",
	}, "Session validation successful"))
}

// GetAuthStatus returns the authentication status of the current user.
// @Summary Get authentication status
// @Description Returns whether the user is authenticated and their role.
// @Tags auth-user
// @Produce json
// @Success 200 {object} map[string]interface{} "Authentication status"
// @Failure 401 {object} map[string]interface{} "Not authenticated"
// @Router /api/v1/auth/status [get]
func (h *AuthHandler) GetAuthStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	role := r.Context().Value("role")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"authenticated": true,
		"user_id":       userID,
		"role":          role,
		"message":       "User is authenticated",
	}, "Authentication status"))
}

// DebugToken validates and returns token claims.
// @Summary Debug token
// @Description Validates the Bearer token and returns its claims.
// @Tags auth-user
// @Produce json
// @Success 200 {object} map[string]interface{} "Token claims"
// @Failure 401 {object} map[string]interface{} "Invalid token"
// @Router /api/v1/auth/debug-token [get]
func (h *AuthHandler) DebugToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "No Authorization header")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrInvalidInput, "Invalid Authorization format")
		return
	}

	tokenString := parts[1]
	claims, err := h.jwtService.ValidateAccessToken(r.Context(), tokenString)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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

// ---------- Company and user management ----------

// GetCompany retrieves company details.
// @Summary Get company
// @Description Retrieves company information by ID.
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Company details"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 404 {object} map[string]interface{} "Company not found"
// @Router /api/v1/companies/{companyID} [get]
func (h *AuthHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	company, err := h.companyService.GetCompany(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company retrieved successfully"))
}

// ListEmployees lists employees of a company.
// @Summary List employees
// @Description Lists active employees of a company with pagination.
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Page size" default(50)
// @Success 200 {object} map[string]interface{} "List of employees"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/companies/{companyID}/employees [get]
func (h *AuthHandler) ListEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page := h.getIntQueryParam(r, "page", 1)
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := (page - 1) * limit

	employees, total, err := h.companyService.ListActiveEmployees(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"employees": employees,
		"total":     total,
		"page":      page,
		"limit":     limit,
	}, "Employees retrieved successfully"))
}

// RemoveEmployee removes an employee from a company.
// @Summary Remove employee
// @Description Removes an employee from a company (terminates employment).
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Employee removed"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Router /api/v1/companies/{companyID}/employees/{userID} [delete]
func (h *AuthHandler) RemoveEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	removedBy := r.Context().Value("user_id")
	if removedBy == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	removedByID, err := uuid.Parse(removedBy.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.terminate")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	if err := h.companyService.RemoveEmployee(ctx, companyID, userID, removedByID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee removed successfully"))
}

// UpdateEmployeeRole updates the role of an employee.
// @Summary Update employee role
// @Description Changes the role assigned to an employee within a company.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Param body body object true "New role ID" example({"role_id":"..."})
// @Success 200 {object} map[string]interface{} "Role updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/employees/{userID}/role [post]
func (h *AuthHandler) UpdateEmployeeRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	updatedBy := r.Context().Value("user_id")
	if updatedBy == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	updatedByID, err := uuid.Parse(updatedBy.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	var req struct {
		RoleID uuid.UUID `json:"role_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.update")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.RoleID, updatedByID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role updated successfully"))
}

// GetCompanyHierarchy retrieves the company's organizational hierarchy.
// @Summary Get company hierarchy
// @Description Returns the reporting structure of the company.
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Hierarchy tree"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/companies/{companyID}/hierarchy [get]
func (h *AuthHandler) GetCompanyHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	hierarchy, err := h.companyService.GetCompanyHierarchy(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "Company hierarchy retrieved successfully"))
}

// AddDepartment adds a new department to a company.
// @Summary Add department
// @Description Creates a new department within a company.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Department details" example({"department_name":"Sales","system_department_id":"..."})
// @Success 201 {object} map[string]interface{} "Department created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/departments [post]
func (h *AuthHandler) AddDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	_, err = uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	var req struct {
		DepartmentName     string    `json:"department_name" validate:"required"`
		SystemDepartmentID uuid.UUID `json:"system_department_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.department.create")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	department, err := h.companyService.AddDepartment(ctx, companyID, req.DepartmentName, req.SystemDepartmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department added successfully"))
}

// RenameDepartment renames an existing department.
// @Summary Rename department
// @Description Updates the name of a department.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Param body body object true "New name" example({"department_name":"New Sales"})
// @Success 200 {object} map[string]interface{} "Department renamed"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/departments/{departmentID} [put]
func (h *AuthHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	_, err = uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	var req struct {
		DepartmentName string `json:"department_name" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "administrative.department.update")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))
}

// AssignManagerPermissions assigns permissions to a manager.
// @Summary Assign manager permissions
// @Description Grants specific permissions to a manager within a company.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param managerID path string true "Manager UUID"
// @Param body body object true "Permissions list" example({"permissions":["admin.user.view","admin.user.update"]})
// @Success 200 {object} map[string]interface{} "Permissions assigned"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/managers/{managerID}/permissions [post]
func (h *AuthHandler) AssignManagerPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	managerIDStr := chi.URLParam(r, "managerID")
	managerID, err := uuid.Parse(managerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid manager ID")
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	var req struct {
		Permissions []string `json:"permissions" validate:"required,min=1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.permission.assign")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	if err := h.companyService.AssignManagerPermissions(ctx, companyID, managerID, req.Permissions, userIDParsed); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Manager permissions assigned successfully"))
}

// RevokeManagerPermissions revokes permissions from a manager.
// @Summary Revoke manager permissions
// @Description Removes specific permissions from a manager within a company.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param managerID path string true "Manager UUID"
// @Param body body object true "Permissions list" example({"permissions":["admin.user.view"]})
// @Success 200 {object} map[string]interface{} "Permissions revoked"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/managers/{managerID}/permissions [delete]
func (h *AuthHandler) RevokeManagerPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	managerIDStr := chi.URLParam(r, "managerID")
	managerID, err := uuid.Parse(managerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid manager ID")
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	var req struct {
		Permissions []string `json:"permissions" validate:"required,min=1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.permission.revoke")
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
		return
	}

	if err := h.companyService.RevokeManagerPermissions(ctx, companyID, managerID, req.Permissions, userIDParsed); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Manager permissions revoked successfully"))
}

// ---------- User profile endpoints ----------

// GetUserByID retrieves a user by ID.
// @Summary Get user by ID
// @Description Returns user details for the given UUID.
// @Tags user
// @Produce json
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "User details"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/users/{userID} [get]
func (h *AuthHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	user, err := h.userService.GetUserByID(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.sanitizeUser(user)
	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User retrieved successfully"))
}

// GetUserByPhonePublic returns basic user info by phone number (public).
// @Summary Get user by phone (public)
// @Description Returns whether a user exists for the given phone number.
// @Tags user-public
// @Produce json
// @Param phoneNumber path string true "Phone number"
// @Success 200 {object} map[string]interface{} "User exists"
// @Failure 400 {object} map[string]interface{} "Invalid phone"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/users/phone/{phoneNumber} [get]
func (h *AuthHandler) GetUserByPhonePublic(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	phoneNumber := chi.URLParam(r, "phoneNumber")
	if phoneNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Phone number is required")
		return
	}
	phoneNumber = util.SanitizeInput(phoneNumber)

	user, err := h.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.sanitizeUser(user)
	response := map[string]interface{}{
		"user_exists": true,
		"username":    user.Username,
		"full_name":   user.FullName,
		"user_id":     user.UserID.String(),
		"is_verified": user.IsVerified,
		"is_active":   user.IsActive,
		"data_region": user.DataRegion,
		"created_at":  user.CreatedAt,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "User found"))
}

// UpdateUser updates a user's profile.
// @Summary Update user
// @Description Updates user profile fields.
// @Tags user
// @Accept json
// @Produce json
// @Param userID path string true "User UUID"
// @Param body body service.UserUpdateRequest true "Update fields"
// @Success 200 {object} map[string]interface{} "User updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/users/{userID} [put]
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.sanitizeUser(user)
	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))
}

// UpdateLastLogin updates the last login timestamp of a user.
// @Summary Update last login
// @Description Updates the last_login field for a user.
// @Tags user
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Last login updated"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/users/{userID}/last-login [patch]
func (h *AuthHandler) UpdateLastLogin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	if err := h.userService.UpdateLastLogin(ctx, userID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Last login updated successfully"))
}

// UserHealthCheck returns health status of the user service.
// @Summary User service health
// @Description Checks if the user service is operational.
// @Tags user
// @Produce json
// @Success 200 {object} map[string]interface{} "Service healthy"
// @Failure 503 {object} map[string]interface{} "Service unhealthy"
// @Router /api/v1/users/health [get]
func (h *AuthHandler) UserHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.userService.HealthCheck(ctx); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Service is healthy"))
}

// GetCompanyContext returns the company context for the current user.
// @Summary Get company context
// @Description Retrieves the user's role and permissions within the current company.
// @Tags company
// @Produce json
// @Success 200 {object} map[string]interface{} "Company context"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Not an active employee"
// @Failure 404 {object} map[string]interface{} "Company context not found"
// @Router /api/v1/companies/context [get]
func (h *AuthHandler) GetCompanyContext(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	companyID := r.Context().Value("company_id")
	if companyID == nil {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Token doesn't have company context")
		return
	}
	companyIDParsed, err := uuid.Parse(companyID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID in token")
		return
	}

	companyContext, err := h.companyService.GetCompanyContextForCompany(ctx, userIDParsed, companyIDParsed)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(companyContext, "Company context retrieved"))
}

// GetCompanyByEmployeePhonePublic retrieves companies where the given phone is an employee.
// @Summary Get companies by employee phone (public)
// @Description Returns a list of companies where the phone number is associated with an active employee.
// @Tags company-public
// @Produce json
// @Param phone query string true "Phone number"
// @Success 200 {object} map[string]interface{} "List of companies"
// @Failure 400 {object} map[string]interface{} "Invalid phone"
// @Failure 404 {object} map[string]interface{} "No companies found"
// @Router /api/v1/auth/companies/by-employee-phone [get]
func (h *AuthHandler) GetCompanyByEmployeePhonePublic(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	phoneNumber := r.URL.Query().Get("phone")
	if phoneNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Phone number parameter is required")
		return
	}
	if !strings.HasPrefix(phoneNumber, "+") && len(phoneNumber) > 0 && phoneNumber[0] != ' ' {
		phoneNumber = "+" + strings.TrimSpace(phoneNumber)
	}
	phoneNumber = util.SanitizeInput(phoneNumber)

	companies, err := h.companyService.GetCompaniesByEmployeePhone(ctx, phoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := make([]map[string]interface{}, len(companies))
	for i, company := range companies {
		responseData[i] = map[string]interface{}{
			"company_id":   company.CompanyID.String(),
			"company_name": company.CompanyName,
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Companies retrieved successfully"))
}

// ---------- MPIN forgot/verify ----------

// SendForgotMPINOTP sends an OTP for resetting MPIN.
// @Summary Send forgot MPIN OTP
// @Description Sends OTP to the user's phone for MPIN reset.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body MPINForgotPhoneRequest true "Forgot MPIN request"
// @Success 200 {object} map[string]interface{} "OTP sent"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/auth/mpin/forgot/send-otp [post]
func (h *AuthHandler) SendForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req MPINForgotPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	forgotReq := service.MPINForgotRequest{
		UserID:            user.UserID,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}
	if err := h.mpinService.ForgotMPIN(ctx, &forgotReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"message": "OTP sent to registered phone number for MPIN reset",
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "OTP sent successfully"))
}

// VerifyForgotMPINOTP verifies OTP and resets MPIN.
// @Summary Verify forgot MPIN OTP
// @Description Verifies OTP and sets a new MPIN.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body MPINForgotWithOTPPhoneRequest true "Reset MPIN request"
// @Success 200 {object} map[string]interface{} "MPIN reset successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/auth/mpin/forgot/verify-otp [post]
func (h *AuthHandler) VerifyForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req MPINForgotWithOTPPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.OTPCode = util.SanitizeInput(req.OTPCode)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	forgotOTPReq := service.MPINForgotWithOTPRequest{
		UserID:            user.UserID,
		NewMPIN:           req.NewMPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		OTPCode:           req.OTPCode,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}
	if err := h.mpinService.VerifyForgotMPINOTP(ctx, &forgotOTPReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "MPIN reset successfully",
	}, "MPIN reset successful"))
}

// ForgotMPIN is an alias for VerifyForgotMPINOTP (legacy).
// @Summary Forgot MPIN (legacy)
// @Description Resets MPIN using OTP verification (legacy endpoint).
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body object true "Reset MPIN request" example({"user_id":"...","new_mpin":"...","device_id":"...","device_fingerprint":"...","otp_code":"..."})
// @Success 200 {object} map[string]interface{} "MPIN reset successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /api/v1/auth/mpin/forgot [post]
func (h *AuthHandler) ForgotMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		UserID            string `json:"user_id" validate:"required"`
		NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
		OTPCode           string `json:"otp_code" validate:"required,len=6"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.OTPCode = util.SanitizeInput(req.OTPCode)

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	forgotReq := service.MPINForgotWithOTPRequest{
		UserID:            userID,
		NewMPIN:           req.NewMPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		OTPCode:           req.OTPCode,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}
	if err := h.mpinService.VerifyForgotMPINOTP(ctx, &forgotReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))
}

// ---------- MPIN login ----------

// VerifyMPINLogin authenticates a user via MPIN and issues tokens.
// @Summary Verify MPIN login
// @Description Authenticates user using MPIN and returns JWT tokens.
// @Tags auth-user
// @Accept json
// @Produce json
// @Param body body MPINVerifyPhoneRequest true "MPIN login request"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "MPIN verification failed"
// @Failure 403 {object} map[string]interface{} "Device not trusted or user/company inactive"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Router /api/v1/auth/login/verify-mpin [post]
func (h *AuthHandler) VerifyMPINLogin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req MPINVerifyPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)
	req.CompanyID = util.SanitizeInput(req.CompanyID)

	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !user.IsActive {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrAdminInactive, "Account is inactive. Please contact support.")
		return
	}

	employees, err := h.companyService.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	var activeEmployees []*models.CompanyEmployee
	for _, emp := range employees {
		if emp.IsActive {
			activeEmployees = append(activeEmployees, emp)
		}
	}
	if len(activeEmployees) == 0 {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "User is not an active employee in any company")
		return
	}

	var selectedCompanyID uuid.UUID
	var selectedEmployee *models.CompanyEmployee
	if req.CompanyID != "" {
		companyID, err := uuid.Parse(req.CompanyID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID format")
			return
		}
		for _, emp := range activeEmployees {
			if emp.CompanyID == companyID {
				selectedCompanyID = companyID
				selectedEmployee = emp
				break
			}
		}
		if selectedEmployee == nil {
			h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "User does not have access to the specified company")
			return
		}
	} else {
		if len(activeEmployees) > 1 {
			companyList := make([]map[string]string, len(activeEmployees))
			for i, emp := range activeEmployees {
				company, err := h.companyService.GetCompany(ctx, emp.CompanyID)
				if err != nil {
					continue
				}
				companyList[i] = map[string]string{
					"company_id":   emp.CompanyID.String(),
					"company_name": company.CompanyName,
				}
			}
			h.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success":   false,
				"error":     "MULTIPLE_COMPANIES",
				"message":   "User belongs to multiple companies. Please specify a company_id.",
				"companies": companyList,
			})
			return
		}
		selectedEmployee = activeEmployees[0]
		selectedCompanyID = selectedEmployee.CompanyID
	}

	company, err := h.companyService.GetCompany(ctx, selectedCompanyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !company.IsActive {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrInvalidState, "Company account is inactive")
		return
	}

	deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, user.UserID, req.DeviceID)
	if err != nil || !deviceTrusted {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrDeviceNotTrusted, "MPIN login not allowed on this device")
		return
	}

	mpinVerifyReq := service.MPINVerifyRequest{
		UserID:            user.UserID,
		MPIN:              req.MPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}
	mpinResult, err := h.mpinService.VerifyMPIN(ctx, &mpinVerifyReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !mpinResult.Verified {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrAdminMPINInvalid, "MPIN verification failed")
		return
	}

	companyContext, err := h.companyService.GetCompanyContextForCompany(ctx, user.UserID, selectedCompanyID)
	if err != nil {
		// continue without context
	}

	userRole := "user"
	if companyContext != nil {
		userRole = companyContext.RoleName
	}

	tokenReq := &service.IssueTokenPairRequest{
		UserID:      user.UserID.String(),
		Role:        userRole,
		DeviceID:    req.DeviceID,
		SessionType: "user",
		IPAddress:   h.getClientIP(r),
		CompanyID:   selectedCompanyID.String(),
	}
	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"tokens":       tokens,
		"user_id":      user.UserID.String(),
		"phone":        req.PhoneNumber,
		"company_id":   selectedCompanyID.String(),
		"company_name": company.CompanyName,
		"message":      "MPIN login successful",
	}
	if companyContext != nil {
		responseData["company_context"] = companyContext
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Login successful"))
}

// ---------- Search employee endpoints (protected) ----------

// SearchCompanyEmployees searches employees within a company.
// @Summary Search company employees
// @Description Searches employees by query and filters.
// @Tags company
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body models.CompanyEmployeeSearchRequest true "Search request"
// @Success 200 {object} map[string]interface{} "Search results"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/employees/search [post]
func (h *AuthHandler) SearchCompanyEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req models.CompanyEmployeeSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.CompanyID = companyID
	if req.Query == "" && req.SearchType == "" {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Either query or search_type is required")
		return
	}
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.SearchType == "" {
		req.SearchType = models.SearchTypeFulltext
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	// Permission check
	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
	if err != nil || companyContext.CompanyID != companyID.String() {
		hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
		if !hasPermission {
			h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
			return
		}
	}

	if req.SearchType == "advanced" && req.Query == "" {
		// Advanced filter-only search
		filters := map[string]interface{}{
			"company_id": companyID,
		}
		results, total, err := h.userService.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, req.Limit, req.Offset)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		responseData := map[string]interface{}{
			"employees":   results,
			"total":       total,
			"page":        req.Offset/req.Limit + 1,
			"page_size":   req.Limit,
			"has_more":    (req.Offset + req.Limit) < total,
			"company_id":  companyID.String(),
			"search_type": req.SearchType,
		}
		h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employees search completed"))
		return
	}

	results, total, err := h.userService.SearchCompanyEmployees(ctx, &req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"employees":   results,
		"total":       total,
		"page":        req.Offset/req.Limit + 1,
		"page_size":   req.Limit,
		"has_more":    (req.Offset + req.Limit) < total,
		"company_id":  companyID.String(),
		"search_type": req.SearchType,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employees search completed"))
}

// SearchCompanyEmployeesAdvanced performs advanced employee search with filters.
// @Summary Advanced employee search
// @Description Search employees with multiple filters (role, department, etc.).
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param role_id query string false "Role UUID"
// @Param department_id query string false "Department UUID"
// @Param reports_to query string false "Manager UUID"
// @Param is_active query boolean false "Active status"
// @Param hire_date_from query string false "Hire date from (RFC3339)"
// @Param hire_date_to query string false "Hire date to (RFC3339)"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Param page query int false "Page number" default(1)
// @Success 200 {object} map[string]interface{} "Search results"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/employees/search/advanced [get]
func (h *AuthHandler) SearchCompanyEmployeesAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	queryParams := r.URL.Query()
	filters := make(map[string]interface{})
	if roleID := queryParams.Get("role_id"); roleID != "" {
		roleUUID, err := uuid.Parse(roleID)
		if err == nil {
			filters["role_id"] = roleUUID
		}
	}
	if deptID := queryParams.Get("department_id"); deptID != "" {
		deptUUID, err := uuid.Parse(deptID)
		if err == nil {
			filters["department_id"] = deptUUID
		}
	}
	if reportsTo := queryParams.Get("reports_to"); reportsTo != "" {
		reportsToUUID, err := uuid.Parse(reportsTo)
		if err == nil {
			filters["reports_to"] = reportsToUUID
		}
	}
	if isActive := queryParams.Get("is_active"); isActive != "" {
		filters["is_active"] = strings.ToLower(isActive) == "true"
	}
	if hireDateFrom := queryParams.Get("hire_date_from"); hireDateFrom != "" {
		if date, err := time.Parse(time.RFC3339, hireDateFrom); err == nil {
			filters["hire_date_from"] = date
		}
	}
	if hireDateTo := queryParams.Get("hire_date_to"); hireDateTo != "" {
		if date, err := time.Parse(time.RFC3339, hireDateTo); err == nil {
			filters["hire_date_to"] = date
		}
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)
	page := h.getIntQueryParam(r, "page", 1)
	if r.URL.Query().Get("page") != "" {
		offset = (page - 1) * limit
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
	if err != nil || companyContext.CompanyID != companyID.String() {
		hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
		if !hasPermission {
			h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
			return
		}
	}

	users, total, err := h.userService.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"employees":  users,
		"total":      total,
		"page":       page,
		"page_size":  limit,
		"has_more":   (offset + limit) < total,
		"company_id": companyID.String(),
		"filters":    filters,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Advanced employee search completed"))
}

// GetCompanyEmployeeSuggestions returns employee suggestions for autocomplete.
// @Summary Employee suggestions
// @Description Returns employee name suggestions based on a prefix.
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param prefix query string true "Prefix to search"
// @Param limit query int false "Max results" default(10) maximum(20)
// @Success 200 {object} map[string]interface{} "List of suggestions"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/employees/suggestions [get]
func (h *AuthHandler) GetCompanyEmployeeSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Prefix parameter is required")
		return
	}
	prefix = util.SanitizeInput(prefix)
	limit := h.getIntQueryParam(r, "limit", 10)
	if limit > 20 {
		limit = 20
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
	if err != nil || companyContext.CompanyID != companyID.String() {
		hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
		if !hasPermission {
			h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
			return
		}
	}

	suggestions, err := h.userService.GetCompanyEmployeeSuggestions(ctx, companyID, prefix, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"suggestions": suggestions,
		"total":       len(suggestions),
		"company_id":  companyID.String(),
		"prefix":      prefix,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employee suggestions retrieved"))
}

// FindCompanyEmployeeByUsername finds an employee by username within a company.
// @Summary Find employee by username
// @Description Retrieves an employee's details by their username in a company.
// @Tags company
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param username path string true "Username"
// @Success 200 {object} map[string]interface{} "Employee found"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Employee not found"
// @Router /api/v1/companies/{companyID}/employees/username/{username} [get]
// FindCompanyEmployeeByUsername finds an employee by username within a company.
// Returns minimal employee information (user_id, employee_id, username, full_name).
func (h *AuthHandler) FindCompanyEmployeeByUsername(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	username := chi.URLParam(r, "username")
	if username == "" {
		h.respondWithError(w, http.StatusBadRequest, appErrors.ErrInvalidInput, "Username parameter is required")
		return
	}
	username = util.SanitizeInput(username)

	// Optional: Authentication / permission check
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, appErrors.ErrUnauthorized, "Authentication required")
		return
	}
	userIDParsed, err := uuid.Parse(userID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	// Validate that the user has access to this company
	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
	if err != nil || companyContext.CompanyID != companyID.String() {
		hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
		if !hasPermission {
			h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "Insufficient permissions")
			return
		}
	}

	// ✅ Use the new method that returns EmployeeSummary
	summary, err := h.userService.FindCompanyEmployeeSummaryByUsername(ctx, companyID, username)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	// Build response with minimal employee data
	responseData := map[string]interface{}{
		"employee":   summary,
		"company_id": companyID.String(),
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employee found"))
}

// ---------- Helper methods ----------

func (h *AuthHandler) hasMPIN(ctx context.Context, userID uuid.UUID) bool {
	status, err := h.mpinService.GetMPINStatus(ctx, userID)
	return err == nil && status != nil
}

func (h *AuthHandler) getIntQueryParam(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	var result int
	_, err := fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return defaultValue
	}
	return result
}

func (h *AuthHandler) sanitizeUser(user *models.User) {
	user.PhoneEncrypted = nil
	user.PhoneKeyID = uuid.Nil
	user.PhoneEncryptedDEK = ""
}

func (h *AuthHandler) getClientIP(r *http.Request) string {
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
	if cfConnectingIP := r.Header.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		if parsedIP := net.ParseIP(cfConnectingIP); parsedIP != nil {
			return cfConnectingIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
			return r.RemoteAddr
		}
		return ""
	}
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return host
	}
	return ""
}

func (h *AuthHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// GetUserPhoneNumberInCompany retrieves the decrypted phone number of a user
// within a specific company. Requires that the caller has the appropriate
// permission (e.g., hr.employee.view) via middleware.
// @Summary Get user phone number (company-scoped)
// @Description Returns the plaintext phone number of a user in the company.
// @Tags companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Phone number retrieved"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 403 {object} map[string]interface{} "Permission denied or user not in company"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/companies/{companyID}/users/{userID}/phone [get]
func (h *AuthHandler) GetUserPhoneNumberInCompany(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// Parse company and user IDs from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// Ensure the user is an active employee of this company
	isEmployee, err := h.userService.IsUserEmployeeOfCompany(ctx, userID, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to verify company membership")
		return
	}
	if !isEmployee {
		h.respondWithError(w, http.StatusForbidden, appErrors.ErrPermissionDenied, "User does not belong to this company")
		return
	}

	// Decrypt and return the phone number
	phone, err := h.userService.GetPhoneNumberByUserID(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	responseData := map[string]interface{}{
		"user_id":    userID.String(),
		"company_id": companyID.String(),
		"phone":      phone,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Phone number retrieved successfully"))
}
