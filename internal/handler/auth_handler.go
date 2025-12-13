// File: internal/handler/auth_handler.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"net/url" 
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
	validate.RegisterValidation("alphanumdash", func(fl validator.FieldLevel) bool {
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(fl.Field().String())
	})
	validate.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		value := fl.Field().String()
		re := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
		return re.MatchString(value)
	})
}

// AuthHandler handles HTTP requests for authentication and user operations
type AuthHandler struct {
	userOTPService *service.UserOTPService // UPDATED: UserOTPService for users
	mpinService    *service.MPINService
	sessionService *service.SessionService
	userService    *service.UserService
	companyService *service.CompanyService
	deviceService  *service.DeviceService
	jwtService     *service.JWTService
	logger         *zap.Logger
}

func NewAuthHandler(
	userOTPService *service.UserOTPService, // UPDATED: UserOTPService parameter
	mpinService *service.MPINService,
	sessionService *service.SessionService,
	userService *service.UserService,
	companyService *service.CompanyService,
	deviceService *service.DeviceService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		userOTPService: userOTPService, // UPDATED: Set UserOTPService
		mpinService:    mpinService,
		sessionService: sessionService,
		userService:    userService,
		companyService: companyService,
		deviceService:  deviceService,
		jwtService:     jwtService,
		logger:         logger,
	}
}
// Handler request structures for phone-based APIs
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
// ============================================
// ROUTE REGISTRATION
// ============================================

// RegisterPublicRoutes registers only public authentication routes
func (h *AuthHandler) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth", func(r chi.Router) {
		// Complete authentication flow (public)
		r.Post("/login/initiate", h.InitiateLogin)
		r.Post("/login/verify-otp", h.VerifyOTPLogin)
		r.Get("/companies/by-employee-phone", h.GetCompanyByEmployeePhonePublic)
		r.Post("/login/verify-mpin", h.VerifyMPINLogin)
		r.Post("/mpin/setup", h.SetupMPIN)
		r.Post("/otp/send", h.SendOTP)

		// MPIN Forgot Flow APIs
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

// RegisterProtectedRoutes registers routes that require authentication
func (h *AuthHandler) RegisterProtectedRoutes(r chi.Router) {
	// Auth protected routes
	r.Get("/auth/validate", h.ValidateSession)
	r.Get("/auth/status", h.GetAuthStatus)
	r.Post("/auth/logout", h.Logout)
	r.Post("/auth/logout/all", h.LogoutAllDevices)

	// User management routes (protected)
	r.Get("/users/{userID}", h.GetUserByID)
	r.Put("/users/{userID}", h.UpdateUser)
	r.Patch("/users/{userID}/last-login", h.UpdateLastLogin)
	r.Get("/users/health", h.UserHealthCheck)

	// Company management routes (protected)
	r.Route("/companies", func(r chi.Router) {
		r.Get("/{companyID}", h.GetCompany)
		r.Get("/{companyID}/employees", h.ListEmployees)
		r.Delete("/{companyID}/employees/{userID}", h.RemoveEmployee)
		r.Get("/context", h.GetCompanyContext)
		r.Post("/{companyID}/employees/{userID}/role", h.UpdateEmployeeRole)
		// r.Post("/{companyID}/employees/{userID}/department", h.UpdateEmployeeDepartment)
		r.Get("/{companyID}/hierarchy", h.GetCompanyHierarchy)

		// Owner operations
		r.Route("/{companyID}/departments", func(r chi.Router) {
			r.Put("/{departmentID}", h.RenameDepartment)
			r.Post("/", h.AddDepartment)
		})

		// Manager operations
		r.Route("/{companyID}/managers", func(r chi.Router) {
			// r.Post("/", h.AddManager)
			r.Post("/{managerID}/permissions", h.AssignManagerPermissions)
			r.Delete("/{managerID}/permissions", h.RevokeManagerPermissions)
		})
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
// AUTHENTICATION FLOW METHODS
// ============================================

// LoginFlowRequest for starting login process
type LoginFlowRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
}

// UserLoginFlowResponse returns available auth methods and flow state
type UserLoginFlowResponse struct {
	FlowState     string `json:"flow_state"`
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
	if err != nil {
		h.respondWithError(w, http.StatusNotFound,
			fmt.Errorf("USER_NOT_FOUND: Phone number not registered"),
			"User not found. Please contact your company administrator to be added to the system.")
		return
	}

	// Check user status
	if !user.IsActive {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("USER_INACTIVE: Account is inactive"),
			"Account is inactive. Please contact support.")
		return
	}

	response := &UserLoginFlowResponse{
		UserExists: true,
	}

	// Check MPIN status
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
		response.FlowState = "mpin_locked"
		response.Message = "MPIN locked - OTP verification required"
	} else if deviceTrusted {
		response.FlowState = "existing_user_mpin"
		response.DeviceTrusted = true
		response.Message = "Trusted device - MPIN login available"
		response.UserID = user.UserID.String()
	} else {
		response.FlowState = "existing_user_otp"
		response.Message = "Untrusted device - OTP verification required"
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))

	h.logger.Info("Login initiation completed",
		util.String("phone", req.PhoneNumber),
		util.Bool("user_exists", true),
		util.Bool("has_mpin", response.HasMPIN),
		util.Bool("mpin_locked", response.MPINLocked),
		util.Bool("device_trusted", deviceTrusted),
		util.String("flow_state", response.FlowState),
		util.Duration("duration", time.Since(startTime)),
	)
}

// VerifyOTPLogin handles OTP verification for login
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
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.OTP = util.SanitizeInput(req.OTP)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	// Get user - must exist
	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Authentication failed")
		return
	}

	// ✅ UPDATED: Use UserOTPService with UserOTPVerifyRequest
	otpVerifyReq := &service.UserOTPVerifyRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               req.OTP,
		Purpose:           "login",
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
	}

	// ✅ UPDATED: Call UserVerifyOTP method
	otpResponse, err := h.userOTPService.UserVerifyOTP(ctx, otpVerifyReq)
	if err != nil {
		h.handleUserOTPError(w, err) // UPDATED: Use user OTP error handler
		return
	}

	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("AUTHENTICATION_FAILED"),
			"Authentication failed")
		return
	}

	// Update device trust
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

	hasMPIN := h.hasMPIN(ctx, user.UserID)

	// Include quota information
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

	// If user has MPIN, they should proceed to MPIN login
	if hasMPIN {
		responseData["next_step"] = "mpin_login"
		responseData["message"] = "OTP verification successful. Please use MPIN for daily authentication."
	} else {
		responseData["next_step"] = "setup_mpin"
		responseData["message"] = "OTP verification successful. Please setup MPIN for daily authentication."
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Device setup successful"))

	h.logger.Info("OTP verification completed - device trusted",
		util.String("user_id", user.UserID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.Bool("has_mpin", hasMPIN),
		util.Int("daily_quota_used", otpResponse.QuotaUsed),
		util.Int("daily_quota_limit", otpResponse.DailyQuota),
		util.Duration("duration", time.Since(startTime)),
	)
}

// // VerifyMPINLogin handles MPIN verification for daily login
// func (h *AuthHandler) VerifyMPINLogin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req MPINVerifyPhoneRequest
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Sanitize inputs
//     req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
//     req.MPIN = util.SanitizeInput(req.MPIN)
//     req.DeviceID = util.SanitizeInput(req.DeviceID)
//     req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
//     req.UserAgent = util.SanitizeInput(req.UserAgent)

//     // Get user by phone number
//     user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
//     if err != nil {
//         h.respondWithError(w, http.StatusNotFound, err, "User not found")
//         return
//     }

//     // Check user status
//     if !user.IsActive {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("USER_INACTIVE: Account is inactive"),
//             "Account is inactive. Please contact support.")
//         return
//     }

//     // Check company subscription status if user has company
//     companyContext, err := h.companyService.GetCompanyContext(ctx, user.UserID)
//     if err != nil && !strings.Contains(err.Error(), "user is not an active employee") {
//         if strings.Contains(err.Error(), "subscription status:") {
//             h.respondWithError(w, http.StatusPaymentRequired, err, "Subscription issue")
//             return
//         }
//         h.logger.Warn("Company context check failed", util.ErrorField(err))
//     }

//     // Verify device trust
//     deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, user.UserID, req.DeviceID)
//     if err != nil || !deviceTrusted {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
//             "MPIN login not allowed on this device")
//         return
//     }

//     // ✅ UPDATED: Enhanced MPIN verification with device fingerprint
//     mpinVerifyReq := service.MPINVerifyRequest{
//         UserID:            user.UserID,
//         MPIN:              req.MPIN,
//         DeviceID:          req.DeviceID,
//         DeviceFingerprint: req.DeviceFingerprint,
//         IPAddress:         h.getClientIP(r),
//         UserAgent:         r.UserAgent(),
//     }

//     mpinResult, err := h.mpinService.VerifyMPIN(ctx, &mpinVerifyReq)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "MPIN verification failed")
//         return
//     }

//     if !mpinResult.Verified {
//         h.respondWithError(w, http.StatusUnauthorized,
//             fmt.Errorf("MPIN_VERIFICATION_FAILED: %s", mpinResult.Message),
//             "MPIN verification failed")
//         return
//     }

//     userRole := "user"
//     if companyContext != nil {
//         userRole = companyContext.RoleName
//     }

//     // Issue JWT token pair
//     tokenReq := &service.IssueTokenPairRequest{
//         UserID:      user.UserID.String(),
//         Role:        userRole,
//         DeviceID:    req.DeviceID,
//         SessionType: "user",
//         IPAddress:   h.getClientIP(r),
//     }

//     tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue tokens")
//         return
//     }

//     responseData := map[string]interface{}{
//         "tokens":  tokens,
//         "user_id": user.UserID.String(),
//         "phone":   req.PhoneNumber,
//         "message": "MPIN login successful",
//     }

//     if companyContext != nil {
//         responseData["company_context"] = companyContext
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Login successful"))

//     h.logger.Info("MPIN login completed with JWT tokens",
//         util.String("user_id", user.UserID.String()),
//         util.String("phone", req.PhoneNumber),
//         util.String("role", userRole),
//         util.Bool("has_company", companyContext != nil),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// SetupMPIN handles MPIN setup after registration
func (h *AuthHandler) SetupMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req MPINSetupPhoneRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Sanitize inputs
    req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
    req.UserAgent = util.SanitizeInput(req.UserAgent)

    // Get user by phone number
    user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "User not found")
        return
    }

    // ✅ UPDATED: Create service request with UserID (from phone lookup)
    mpinReq := service.MPINSetupRequest{
        UserID:            user.UserID,
        MPIN:              req.MPIN,
        DeviceID:          req.DeviceID,
        DeviceFingerprint: req.DeviceFingerprint,
        IPAddress:         h.getClientIP(r),
        UserAgent:         r.UserAgent(),
    }

    if err := h.mpinService.SetupMPIN(ctx, &mpinReq); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to setup MPIN")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
        "message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
    }, "MPIN setup successful"))

    h.logger.Info("MPIN setup completed",
        util.String("user_id", user.UserID.String()),
        util.String("phone", req.PhoneNumber),
        util.Duration("duration", time.Since(startTime)),
    )
}
// ============================================
// MPIN FORGOT FLOW METHODS
// ============================================

// // SendForgotMPINOTP sends OTP for forgot MPIN flow
// func (h *AuthHandler) SendForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	var req struct {
// 		UserID            string `json:"user_id" validate:"required"`
// 		DeviceID          string `json:"device_id" validate:"required"`
// 		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
// 		return
// 	}

// 	userID, err := uuid.Parse(req.UserID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	// Get user to get phone number
// 	user, err := h.userService.GetUserByID(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusNotFound, err, "User not found")
// 		return
// 	}

// 	// ✅ UPDATED: Use UserOTPService for sending forgot MPIN OTP
// 	otpSendReq := &service.UserOTPSendRequest{
// 		PhoneNumber:       user.PhoneNumber, // Get phone from user object
// 		Purpose:           "forgot_mpin",
// 		IPAddress:         h.getClientIP(r),
// 		DeviceID:          req.DeviceID,
// 		DeviceFingerprint: req.DeviceFingerprint,
// 		UserAgent:         r.UserAgent(),
// 	}

// 	// ✅ UPDATED: Call UserSendOTP method
// 	otpResponse, err := h.userOTPService.UserSendOTP(ctx, otpSendReq)
// 	if err != nil {
// 		h.handleUserOTPError(w, err) // UPDATED: Use user OTP error handler
// 		return
// 	}

// 	if !otpResponse.Success {
// 		h.respondWithError(w, http.StatusTooManyRequests,
// 			fmt.Errorf("OTP_SEND_FAILED"),
// 			otpResponse.Message)
// 		return
// 	}

// 	// Generate request ID for the forgot MPIN flow
// 	requestID := uuid.New().String()

// 	responseData := map[string]interface{}{
// 		"request_id": requestID,
// 		"message":    "OTP sent to registered phone number for MPIN reset",
// 		"expires_at": otpResponse.ExpiresAt,
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "OTP sent successfully"))

// 	h.logger.Info("Forgot MPIN OTP sent",
// 		util.String("user_id", userID.String()),
// 		util.String("phone", "***"),
// 		util.String("device_id", req.DeviceID),
// 		util.String("request_id", requestID),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // VerifyForgotMPINOTP handles OTP verification and MPIN reset
// func (h *AuthHandler) VerifyForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	var req service.MPINForgotWithOTPRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize inputs
// 	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
// 	req.OTPCode = util.SanitizeInput(req.OTPCode)
// 	req.DeviceID = util.SanitizeInput(req.DeviceID)
// 	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
// 	req.IPAddress = h.getClientIP(r)
// 	req.UserAgent = r.UserAgent()

// 	// Get user to get phone number for OTP verification
// 	user, err := h.userService.GetUserByID(ctx, req.UserID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusNotFound, err, "User not found")
// 		return
// 	}

// 	// ✅ UPDATED: First verify OTP using UserOTPService
// 	otpVerifyReq := &service.UserOTPVerifyRequest{
// 		PhoneNumber:       req.PhoneNumber, // Use from request, not user.PhoneNumber
// 		OTP:               req.OTPCode,
// 		Purpose:           "forgot_mpin",
// 		IPAddress:         req.IPAddress,
// 		DeviceID:          req.DeviceID,
// 		DeviceFingerprint: req.DeviceFingerprint,
// 		UserAgent:         req.UserAgent,
// 	}

// 	otpResponse, err := h.userOTPService.UserVerifyOTP(ctx, otpVerifyReq)
// 	if err != nil {
// 		h.handleUserOTPError(w, err)
// 		return
// 	}

// 	if !otpResponse.Success {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("OTP_VERIFICATION_FAILED"),
// 			"OTP verification failed")
// 		return
// 	}

// 	// ✅ UPDATED: Now reset MPIN using the service
// 	if err := h.mpinService.VerifyForgotMPINOTP(ctx, &req); err != nil {
// 		statusCode := h.getForgotMPINStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to reset MPIN")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))

// 	h.logger.Info("MPIN reset via forgot OTP flow",
// 		util.String("user_id", req.UserID.String()),
// 		util.String("device_id", req.DeviceID),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // ForgotMPIN handles MPIN reset on trusted devices (legacy endpoint - uses new flow internally)
// func (h *AuthHandler) ForgotMPIN(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	var req struct {
// 		UserID            string `json:"user_id" validate:"required"`
// 		NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
// 		DeviceID          string `json:"device_id" validate:"required"`
// 		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
// 		OTPCode           string `json:"otp_code" validate:"required,len=6"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize inputs
// 	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
// 	req.DeviceID = util.SanitizeInput(req.DeviceID)
// 	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
// 	req.OTPCode = util.SanitizeInput(req.OTPCode)

// 	userID, err := uuid.Parse(req.UserID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	// Get user to get phone number
// 	user, err := h.userService.GetUserByID(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusNotFound, err, "User not found")
// 		return
// 	}

// 	// ✅ UPDATED: First verify OTP using UserOTPService
// 	otpVerifyReq := &service.UserOTPVerifyRequest{
// 		PhoneNumber:       user.PhoneNumber,
// 		OTP:               req.OTPCode,
// 		Purpose:           "forgot_mpin",
// 		IPAddress:         h.getClientIP(r),
// 		DeviceID:          req.DeviceID,
// 		DeviceFingerprint: req.DeviceFingerprint,
// 		UserAgent:         r.UserAgent(),
// 	}

// 	otpResponse, err := h.userOTPService.UserVerifyOTP(ctx, otpVerifyReq)
// 	if err != nil {
// 		h.handleUserOTPError(w, err)
// 		return
// 	}

// 	if !otpResponse.Success {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("OTP_VERIFICATION_FAILED"),
// 			"OTP verification failed")
// 		return
// 	}

// 	// Use the new VerifyForgotMPINOTP method
// 	forgotReq := service.MPINForgotWithOTPRequest{
// 		UserID:            userID,
// 		NewMPIN:           req.NewMPIN,
// 		DeviceID:          req.DeviceID,
// 		DeviceFingerprint: req.DeviceFingerprint,
// 		OTPCode:           req.OTPCode,
// 		IPAddress:         h.getClientIP(r),
// 		UserAgent:         r.UserAgent(),
// 	}

// 	if err := h.mpinService.VerifyForgotMPINOTP(ctx, &forgotReq); err != nil {
// 		statusCode := h.getForgotMPINStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to reset MPIN")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))

// 	h.logger.Info("MPIN reset via forgot flow",
// 		util.String("user_id", userID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }
// ChangeMPIN handles MPIN change for users
// ChangeMPIN handles MPIN change for users
func (h *AuthHandler) ChangeMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req MPINChangePhoneRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Sanitize inputs
    req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
    req.CurrentMPIN = util.SanitizeInput(req.CurrentMPIN)
    req.NewMPIN = util.SanitizeInput(req.NewMPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
    req.UserAgent = util.SanitizeInput(req.UserAgent)

    // Get user by phone number
    user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "User not found")
        return
    }

    // Create MPIN change request
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
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to change MPIN")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "message": "MPIN changed successfully",
    }, "MPIN change successful"))

    h.logger.Info("MPIN changed successfully",
        util.String("user_id", user.UserID.String()),
        util.String("phone", req.PhoneNumber),
        util.String("device_id", req.DeviceID),
        util.String("user_agent", req.UserAgent),
        util.Duration("duration", time.Since(startTime)),
    )
}
// ============================================
// OTP MANAGEMENT METHODS
// ============================================
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// ✅ UPDATED: Use UserOTPService with UserOTPSendRequest
	otpSendReq := &service.UserOTPSendRequest{
		PhoneNumber:       req.PhoneNumber,
		Purpose:           req.Purpose,
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
		Provider:          "resend",
	}

	// ✅ UPDATED: Call UserSendOTP method
	otpResponse, err := h.userOTPService.UserSendOTP(ctx, otpSendReq)
	if err != nil {
		// 🔥 NEW: Handle rate limit response specially to include retry_after in response
		if errors.Is(err, service.ErrUserOTPRateLimitExceeded) || 
		   errors.Is(err, service.ErrUserDailyQuotaExceeded) {
			
			// 🔥 Set proper headers for 429 response
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", otpResponse.RetryAfter))
			w.Header().Set("Vary", "Origin")
			w.WriteHeader(http.StatusTooManyRequests)
			
			// 🔥 Return the exact same JSON structure as admin service
			response := map[string]interface{}{
				"success":    false,
				"message":    otpResponse.Message,
				"expires_at": otpResponse.ExpiresAt,
				"retry_after": otpResponse.RetryAfter,
			}
			
			json.NewEncoder(w).Encode(response)
			return
		}
		
		// For other errors, use the normal error handler
		h.handleUserOTPError(w, err)
		return
	}

	if !otpResponse.Success {
		// Handle other non-success cases
		h.respondWithError(w, http.StatusTooManyRequests,
			fmt.Errorf("OTP_SEND_FAILED"),
			otpResponse.Message)
		return
	}

	// Include quota information
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

	h.logger.Info("OTP sent",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("device_id", req.DeviceID),
		util.Int("daily_quota_used", otpResponse.QuotaUsed),
		util.Int("daily_quota_limit", otpResponse.DailyQuota),
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

	if err := h.sessionService.RevokeAllUserRefreshTokens(ctx, userID.String()); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to logout from all devices")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Logged out from all devices successfully"))
}

// ValidateSession checks if the current session is valid - PROTECTED
func (h *AuthHandler) ValidateSession(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	deviceID := r.Context().Value("device_id")
	role := r.Context().Value("role")

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
		"role":      role,
		"message":   "Session is valid",
	}, "Session validation successful"))
}

// GetAuthStatus returns authentication status - PROTECTED
func (h *AuthHandler) GetAuthStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	role := r.Context().Value("role")

	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("NOT_AUTHENTICATED: User not authenticated"),
			"Authentication required")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"authenticated": true,
		"user_id":       userID,
		"role":          role,
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

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("INVALID_AUTH_FORMAT"), "Invalid Authorization format")
		return
	}

	tokenString := parts[1]

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
// COMPANY MANAGEMENT HANDLERS
// ============================================

// GetCompany retrieves company details
func (h *AuthHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	company, err := h.companyService.GetCompany(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Company not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company retrieved successfully"))

	h.logger.Debug("Company retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ListEmployees retrieves employees for a company
func (h *AuthHandler) ListEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get page and limit from query params
	page := h.getIntQueryParam(r, "page", 1)
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := (page - 1) * limit

	employees, total, err := h.companyService.ListActiveEmployees(ctx, companyID, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list employees")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"employees": employees,
		"total":     total,
		"page":      page,
		"limit":     limit,
	}, "Employees retrieved successfully"))

	h.logger.Debug("Employees listed",
		util.String("company_id", companyID.String()),
		util.Int("count", len(employees)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// RemoveEmployee removes an employee from a company
func (h *AuthHandler) RemoveEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Get user ID from JWT context (the user removing the employee)
	removedBy := r.Context().Value("user_id")
	if removedBy == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
		return
	}

	removedByID, err := uuid.Parse(removedBy.(string))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.terminate")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to remove employees"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.RemoveEmployee(ctx, companyID, userID, removedByID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to remove employee")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee removed successfully"))

	h.logger.Info("Employee removed from company",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("removed_by", removedByID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateEmployeeRole updates an employee's role
func (h *AuthHandler) UpdateEmployeeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Get user ID from JWT context
	updatedBy := r.Context().Value("user_id")
	if updatedBy == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
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

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.update")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to update employee roles"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.RoleID, updatedByID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update employee role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role updated successfully"))

	h.logger.Info("Employee role updated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("new_role_id", req.RoleID.String()),
		util.String("updated_by", updatedByID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// // UpdateEmployeeDepartment updates an employee's department
// func (h *AuthHandler) UpdateEmployeeDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	updatedBy := r.Context().Value("user_id")
// 	if updatedBy == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	updatedByID, err := uuid.Parse(updatedBy.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req struct {
// 		DepartmentID uuid.UUID `json:"department_id" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Check permission using bitmask
// 	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.update")
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
// 		return
// 	}
// 	if !hasPermission {
// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("PERMISSION_DENIED: User lacks permission to update employee departments"),
// 			"Insufficient permissions")
// 		return
// 	}

// 	if err := h.companyService.UpdateEmployeeDepartment(ctx, companyID, userID, req.DepartmentID, updatedByID); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to update employee department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee department updated successfully"))

// 	h.logger.Info("Employee department updated",
// 		util.String("company_id", companyID.String()),
// 		util.String("user_id", userID.String()),
// 		util.String("new_department_id", req.DepartmentID.String()),
// 		util.String("updated_by", updatedByID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // GetCompanyContext returns the company context for the authenticated user
// func (h *AuthHandler) GetCompanyContext(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
// 	if err != nil {
// 		if strings.Contains(err.Error(), "subscription status:") {
// 			h.respondWithError(w, http.StatusPaymentRequired, err, "Subscription issue")
// 			return
// 		}
// 		if strings.Contains(err.Error(), "user is not an active employee") {
// 			h.respondWithError(w, http.StatusForbidden, err, "Not an active employee")
// 			return
// 		}
// 		h.respondWithError(w, http.StatusNotFound, err, "Company context not found")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(companyContext, "Company context retrieved"))

// 	h.logger.Debug("Company context retrieved",
// 		util.String("user_id", userIDParsed.String()),
// 		util.String("company_id", companyContext.CompanyID),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// GetCompanyHierarchy returns the company organizational hierarchy
func (h *AuthHandler) GetCompanyHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	hierarchy, err := h.companyService.GetCompanyHierarchy(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company hierarchy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "Company hierarchy retrieved successfully"))

	h.logger.Debug("Company hierarchy retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ============================================
// OWNER OPERATIONS
// ============================================

// AddDepartment adds a new department (Owner only)
func (h *AuthHandler) AddDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get user ID from JWT context
	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
		return
	}

	userIDParsed, err := uuid.Parse(userID.(string))
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

	// Sanitize input
	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.department.create")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to add departments"),
			"Insufficient permissions")
		return
	}

	department, err := h.companyService.AddDepartment(ctx, companyID, req.DepartmentName, req.SystemDepartmentID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to add department")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department added successfully"))

	h.logger.Info("Department added",
		util.String("company_id", companyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", req.DepartmentName),
		util.String("system_department_id", req.SystemDepartmentID.String()),
		util.String("created_by", userIDParsed.String()),
		util.Duration("duration", time.Since(startTime)))
}

// // AddManager adds a new manager (Owner only)
// func (h *AuthHandler) AddManager(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req service.AddManagerRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.CompanyID = companyID

// 	// Sanitize inputs
// 	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
// 	req.RoleName = util.SanitizeInput(req.RoleName)

// 	// Check permissions using bitmask
// 	hasCreatePermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.create")
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
// 		return
// 	}
// 	hasAdminAccess, err := h.companyService.CheckPermissionFromContext(ctx, "admin.department.create")
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
// 		return
// 	}

// 	if !hasCreatePermission || !hasAdminAccess {
// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("PERMISSION_DENIED: User lacks permission to add managers"),
// 			"Insufficient permissions")
// 		return
// 	}

// 	if err := h.companyService.AddManager(ctx, &req); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to add manager")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))

// 	h.logger.Info("Manager added",
// 		util.String("company_id", companyID.String()),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("role_name", req.RoleName),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Int("permissions_count", len(req.Permissions)),
// 		util.String("added_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// AssignManagerPermissions assigns permissions to a manager (Owner only)
func (h *AuthHandler) AssignManagerPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Get user ID from JWT context
	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
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

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.permission.assign")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to assign permissions"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.AssignManagerPermissions(ctx, companyID, managerID, req.Permissions, userIDParsed); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to assign manager permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Manager permissions assigned successfully"))

	h.logger.Info("Manager permissions assigned",
		util.String("company_id", companyID.String()),
		util.String("manager_id", managerID.String()),
		util.Int("permissions_count", len(req.Permissions)),
		util.String("assigned_by", userIDParsed.String()),
		util.Duration("duration", time.Since(startTime)))
}

// RevokeManagerPermissions revokes permissions from a manager (Owner only)
func (h *AuthHandler) RevokeManagerPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Get user ID from JWT context
	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
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

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "admin.permission.revoke")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to revoke permissions"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.RevokeManagerPermissions(ctx, companyID, managerID, req.Permissions, userIDParsed); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to revoke manager permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Manager permissions revoked successfully"))

	h.logger.Info("Manager permissions revoked",
		util.String("company_id", companyID.String()),
		util.String("manager_id", managerID.String()),
		util.Int("permissions_count", len(req.Permissions)),
		util.String("revoked_by", userIDParsed.String()),
		util.Duration("duration", time.Since(startTime)))
}

// RenameDepartment renames a department (Owner only)
func (h *AuthHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Get user ID from JWT context
	userID := r.Context().Value("user_id")
	if userID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
		return
	}

	userIDParsed, err := uuid.Parse(userID.(string))
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

	// Sanitize input
	req.DepartmentName = util.SanitizeInput(req.DepartmentName)

	// Check permission using bitmask
	hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "administrative.department.update")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	if !hasPermission {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to rename departments"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to rename department")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))

	h.logger.Info("Department renamed",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.String("new_name", req.DepartmentName),
		util.String("updated_by", userIDParsed.String()),
		util.Duration("duration", time.Since(startTime)))
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

	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User retrieved successfully"))
	h.logger.Debug("User retrieved via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUserByID"),
	)
}

// GetUserByPhonePublic handles user retrieval by phone number - PUBLIC
func (h *AuthHandler) GetUserByPhonePublic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	phoneNumber := chi.URLParam(r, "phoneNumber")
	if phoneNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("phone number is required"), "Phone number is required")
		return
	}

	phoneNumber = util.SanitizeInput(phoneNumber)

	user, err := h.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			h.respondWithError(w, http.StatusNotFound, err, "User not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError,
			errors.New("internal server error"), "Failed to get user by phone")
		return
	}

	h.sanitizeUser(user)

	response := map[string]interface{}{
		"user_exists": true,
		"username":    user.Username,      // Add username
        "full_name":   user.FullName,      // Add full name
		"user_id":     user.UserID.String(),
		"is_verified": user.IsVerified,
		"is_active":   user.IsActive,
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

// ✅ UPDATED: Enhanced error handling for new error types
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
	case errors.Is(err, service.ErrOTPRateLimitExceeded):
		return http.StatusTooManyRequests
	case errors.Is(err, service.ErrDailyQuotaExceeded):
		return http.StatusTooManyRequests
	case errors.Is(err, service.ErrOTPReplayAttempt):
		return http.StatusBadRequest
	case errors.Is(err, service.ErrMPINNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrMPINInvalid):
		return http.StatusUnauthorized
	case errors.Is(err, service.ErrMPINLocked):
		return http.StatusLocked
	case errors.Is(err, service.ErrMPINAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, service.ErrMPINTooWeak):
		return http.StatusBadRequest
	case errors.Is(err, service.ErrDeviceNotBound):
		return http.StatusForbidden
	case errors.Is(err, service.ErrDeviceNotTrusted):
		return http.StatusForbidden
	case errors.Is(err, service.ErrMPINRateLimitExceeded):
		return http.StatusTooManyRequests
	case errors.Is(err, service.ErrMPINAttemptsExceeded):
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

func (h *AuthHandler) getForgotMPINStatusCode(err error) int {
	errMsg := err.Error()
	if strings.Contains(errMsg, "untrusted device") || strings.Contains(errMsg, "blocked") {
		return http.StatusForbidden
	}
	if strings.Contains(errMsg, "not found") {
		return http.StatusNotFound
	}
	if strings.Contains(errMsg, "rate limit") {
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

// ✅ NEW: User OTP error handler for UserOTPService specific errors
func (h *AuthHandler) handleUserOTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrUserOTPRateLimitExceeded):
		h.respondWithError(w, http.StatusTooManyRequests, err, "Too many attempts. Please try again later.")
	case errors.Is(err, service.ErrUserDailyQuotaExceeded):
		h.respondWithError(w, http.StatusTooManyRequests, err, "Daily OTP limit exceeded")
	case errors.Is(err, service.ErrUserOTPReplayAttempt):
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid OTP")
	case errors.Is(err, service.ErrUserPhoneNotRegistered):
		h.respondWithError(w, http.StatusNotFound, err, "Phone number not registered")
	case errors.Is(err, service.ErrUserSecurityCheckFailed):
		h.respondWithError(w, http.StatusForbidden, err, "Security check failed")
	case errors.Is(err, service.ErrUserOTPNotFound):
		h.respondWithError(w, http.StatusNotFound, err, "OTP not found or expired")
	case errors.Is(err, service.ErrUserOTPExpired):
		h.respondWithError(w, http.StatusBadRequest, err, "OTP has expired")
	case errors.Is(err, service.ErrUserOTPInvalid):
		h.respondWithError(w, http.StatusUnauthorized, err, "Invalid OTP")
	case errors.Is(err, service.ErrUserOTPAttemptsExceeded):
		h.respondWithError(w, http.StatusTooManyRequests, err, "Maximum OTP attempts exceeded")
	case errors.Is(err, service.ErrUserOTPAlreadyUsed):
		h.respondWithError(w, http.StatusBadRequest, err, "OTP has already been used")
	default:
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication failed")
	}
}

func (h *AuthHandler) sanitizeUser(user *models.User) {
	user.PhoneEncrypted = nil
	user.PhoneKeyID = uuid.Nil
	user.PhoneEncryptedDEK = ""
}

// ✅ UPDATED: Enhanced client IP extraction
func (h *AuthHandler) getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}

	// Try X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			return realIP
		}
	}

	// Try CF-Connecting-IP
	if cfConnectingIP := r.Header.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		if parsedIP := net.ParseIP(cfConnectingIP); parsedIP != nil {
			return cfConnectingIP
		}
	}

	// Fallback to RemoteAddr with validation
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

// SendForgotMPINOTP sends OTP for forgot MPIN flow
func (h *AuthHandler) SendForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req MPINForgotPhoneRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request")
        return
    }

    req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
    req.UserAgent = util.SanitizeInput(req.UserAgent)

    // Get user by phone number
    user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "User not found")
        return
    }

    // Create MPIN forgot request
    forgotReq := service.MPINForgotRequest{
        UserID:            user.UserID,
        DeviceID:          req.DeviceID,
        DeviceFingerprint: req.DeviceFingerprint,
        IPAddress:         h.getClientIP(r),
        UserAgent:         r.UserAgent(),
    }

    if err := h.mpinService.ForgotMPIN(ctx, &forgotReq); err != nil {
        statusCode := h.getForgotMPINStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to initiate forgot MPIN flow")
        return
    }

    responseData := map[string]interface{}{
        "message": "OTP sent to registered phone number for MPIN reset",
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "OTP sent successfully"))

    h.logger.Info("Forgot MPIN OTP sent",
        util.String("user_id", user.UserID.String()),
        util.String("phone", req.PhoneNumber),
        util.String("device_id", req.DeviceID),
        util.Duration("duration", time.Since(startTime)),
    )
}
// VerifyForgotMPINOTP handles OTP verification and MPIN reset
func (h *AuthHandler) VerifyForgotMPINOTP(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req MPINForgotWithOTPPhoneRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Sanitize inputs
    req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
    req.NewMPIN = util.SanitizeInput(req.NewMPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
    req.OTPCode = util.SanitizeInput(req.OTPCode)
    req.UserAgent = util.SanitizeInput(req.UserAgent)

    // Get user by phone number
    user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "User not found")
        return
    }

    // Create MPIN forgot with OTP request
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
        statusCode := h.getForgotMPINStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to verify OTP and reset MPIN")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "message": "MPIN reset successfully",
    }, "MPIN reset successful"))

    h.logger.Info("MPIN reset via forgot OTP flow",
        util.String("user_id", user.UserID.String()),
        util.String("phone", req.PhoneNumber),
        util.String("device_id", req.DeviceID),
        util.Duration("duration", time.Since(startTime)),
    )
}
// ForgotMPIN handles MPIN reset on trusted devices (legacy endpoint - uses new flow internally)
func (h *AuthHandler) ForgotMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Sanitize inputs
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.OTPCode = util.SanitizeInput(req.OTPCode)

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	// ✅ FIXED: Use the MPIN service's VerifyForgotMPINOTP method directly
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
		statusCode := h.getForgotMPINStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to reset MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))

	h.logger.Info("MPIN reset via forgot flow",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}



// ============================================
// COMPANY EMPLOYEE SEARCH HANDLERS
// ============================================

// SearchCompanyEmployees searches employees within a specific company
// SearchCompanyEmployees searches employees within a specific company
// SearchCompanyEmployees searches employees within a specific company
func (h *AuthHandler) SearchCompanyEmployees(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    // ADDED: Start logging
    h.logger.Info("Starting company employee search",
        util.String("method", r.Method),
        util.String("path", r.URL.Path),
        util.String("query", r.URL.RawQuery))

    companyIDStr := chi.URLParam(r, "companyID")
    
    // ADDED: Log raw company ID before parsing
    h.logger.Debug("Raw company ID from URL",
        util.String("company_id_str", companyIDStr))
    
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        // ADDED: Enhanced error logging
        h.logger.Error("Invalid company ID",
            util.String("company_id", companyIDStr),
            util.ErrorField(err))
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    // ADDED: Log parsed company ID
    h.logger.Debug("Parsed company ID successfully",
        util.String("company_id", companyID.String()))

    var req models.CompanyEmployeeSearchRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        // ADDED: Enhanced error logging for JSON decode
        h.logger.Error("Failed to decode request body",
            util.ErrorField(err),
            util.String("content_type", r.Header.Get("Content-Type")),
            util.Int64("content_length", r.ContentLength))
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // ADDED: Log request details before processing
    h.logger.Debug("Decoded request body",
        util.String("query", req.Query),
        util.String("search_type", req.SearchType),
        util.Any("filters", req.Filters),
        util.Int("limit", req.Limit),
        util.Int("offset", req.Offset),
        util.Bool("has_company_id", req.CompanyID != uuid.Nil))

    // Set company ID from URL param
    req.CompanyID = companyID

    // Validate required fields
    if req.Query == "" && req.SearchType == "" {
        h.logger.Warn("Missing query and search_type",
            util.String("company_id", companyID.String()))
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("QUERY_OR_SEARCH_TYPE_REQUIRED"), 
            "Either query or search_type is required")
        return
    }

    // Set default values
    if req.Limit <= 0 || req.Limit > 100 {
        h.logger.Debug("Setting default limit",
            util.Int("old_limit", req.Limit),
            util.Int("new_limit", 50))
        req.Limit = 50
    }
    if req.Offset < 0 {
        h.logger.Debug("Setting default offset",
            util.Int("old_offset", req.Offset),
            util.Int("new_offset", 0))
        req.Offset = 0
    }
    if req.SearchType == "" {
        h.logger.Debug("Setting default search type",
            util.String("old_search_type", req.SearchType),
            util.String("new_search_type", models.SearchTypeFulltext))
        req.SearchType = models.SearchTypeFulltext
    }

    // ADDED: Log final request configuration
    h.logger.Debug("Request configuration after defaults",
        util.String("company_id", companyID.String()),
        util.String("query", req.Query),
        util.String("search_type", req.SearchType),
        util.Int("limit", req.Limit),
        util.Int("offset", req.Offset),
        util.Any("filters", req.Filters))

    // Check permissions - user must be part of the company
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.logger.Error("User ID not found in context")
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.logger.Error("Invalid user ID in token",
            util.String("user_id_raw", userID.(string)),
            util.ErrorField(err))
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    // ADDED: Log user attempting search
    h.logger.Debug("User attempting search",
        util.String("user_id", userIDParsed.String()),
        util.String("company_id", companyID.String()))

    // Verify user belongs to the company
    companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
    if err != nil {
        h.logger.Debug("User not found in company context, checking admin permissions",
            util.String("user_id", userIDParsed.String()),
            util.ErrorField(err))
        
        // User is not an employee in any company, check admin permission
        hasPermission, permErr := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
        if !hasPermission {
            h.logger.Warn("Permission denied for user (not in company and not admin)",
                util.String("user_id", userIDParsed.String()),
                util.String("company_id", companyID.String()),
                util.ErrorField(permErr))
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("PERMISSION_DENIED: User not authorized to search in this company"),
                "Insufficient permissions")
            return
        }
        // Admin user can continue
        h.logger.Debug("Admin permission granted for search",
            util.String("user_id", userIDParsed.String()))
    } else if companyContext.CompanyID != companyID.String() {
        h.logger.Debug("User in different company, checking admin permissions",
            util.String("user_id", userIDParsed.String()),
            util.String("user_company", companyContext.CompanyID),
            util.String("target_company", companyID.String()))
        
        // User is in a different company, check admin permission
        hasPermission, permErr := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
        if !hasPermission {
            h.logger.Warn("Permission denied for user (different company and not admin)",
                util.String("user_id", userIDParsed.String()),
                util.String("user_company", companyContext.CompanyID),
                util.String("target_company", companyID.String()),
                util.ErrorField(permErr))
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("PERMISSION_DENIED: User not authorized to search in this company"),
                "Insufficient permissions")
            return
        }
        h.logger.Debug("Admin permission granted for cross-company search",
            util.String("user_id", userIDParsed.String()))
    } else {
        h.logger.Debug("User is part of target company, permission granted",
            util.String("user_id", userIDParsed.String()),
            util.String("company_id", companyID.String()))
    }

    // For fulltext search, ensure query is provided
    if req.SearchType == models.SearchTypeFulltext && req.Query == "" {
        h.logger.Warn("Query required for fulltext search",
            util.String("search_type", req.SearchType))
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("QUERY_REQUIRED_FOR_FULLTEXT"),
            "Query is required for fulltext search")
        return
    }

    // For advanced search, handle different cases
    if req.SearchType == "advanced" { // Changed from models.SearchTypeAdvanced to "advanced"
        h.logger.Debug("Processing advanced search",
            util.String("query", req.Query),
            util.Any("filters", req.Filters))
        
        // For advanced search without query, use different method
        if req.Query == "" {
            h.logger.Debug("Advanced search without query, using filter-based search")
            filters := map[string]interface{}{
                "company_id": companyID,
            }
            
            // ADDED: Log before calling advanced search
            h.logger.Debug("Calling SearchCompanyEmployeesAdvanced",
                util.String("company_id", companyID.String()),
                util.Any("filters", filters),
                util.Int("limit", req.Limit),
                util.Int("offset", req.Offset))
            
            results, total, err := h.userService.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, req.Limit, req.Offset)
            if err != nil {
                // ADDED: Enhanced error logging for advanced search
                h.logger.Error("Failed to search company employees (advanced) - DETAILED",
                    util.ErrorField(err),
                    util.String("company_id", companyID.String()),
                    util.Any("filters", filters),
                    util.Int("limit", req.Limit),
                    util.Int("offset", req.Offset))
                h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search employees")
                return
            }
            
            // ADDED: Success logging for advanced search
            h.logger.Debug("Advanced search completed successfully",
                util.Int("results", len(results)),
                util.Int("total", total),
                util.String("company_id", companyID.String()))
            
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
    }

    // Use the standard search for other cases
    h.logger.Debug("Calling SearchCompanyEmployees service method",
        util.String("company_id", companyID.String()),
        util.String("query", req.Query),
        util.String("search_type", req.SearchType),
        util.Int("limit", req.Limit),
        util.Int("offset", req.Offset))
    
    results, total, err := h.userService.SearchCompanyEmployees(ctx, &req)
    if err != nil {
        // ADDED: Enhanced error logging for standard search
        h.logger.Error("Failed to search company employees - DETAILED",
            util.ErrorField(err),
            util.String("company_id", companyID.String()),
            util.String("query", req.Query),
            util.String("search_type", req.SearchType),
            util.Any("filters", req.Filters),
            util.Int("limit", req.Limit),
            util.Int("offset", req.Offset))
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search employees")
        return
    }

    // ADDED: Success logging for standard search
    h.logger.Debug("Search completed successfully",
        util.Int("results", len(results)),
        util.Int("total", total),
        util.String("company_id", companyID.String()),
        util.String("search_type", req.SearchType))

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

    h.logger.Info("Company employees search completed",
        util.String("company_id", companyID.String()),
        util.String("query", req.Query),
        util.String("search_type", req.SearchType),
        util.Int("results", len(results)),
        util.Int("total", total),
        util.Duration("duration", time.Since(startTime)))
}
// SearchCompanyEmployeesAdvanced searches employees with advanced filters
func (h *AuthHandler) SearchCompanyEmployeesAdvanced(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    companyIDStr := chi.URLParam(r, "companyID")
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    // Parse query parameters
    queryParams := r.URL.Query()
    filters := make(map[string]interface{})

    // Parse optional filters
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

    // Parse pagination
    limit := h.getIntQueryParam(r, "limit", 50)
    offset := h.getIntQueryParam(r, "offset", 0)
    page := h.getIntQueryParam(r, "page", 1)
    
    // If page is provided, calculate offset
    if r.URL.Query().Get("page") != "" {
        offset = (page - 1) * limit
    }

    // Check permissions
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    // Verify user belongs to the company
    companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
    if err != nil || companyContext.CompanyID != companyID.String() {
        // Check if user has permission to search in any company (admin permission)
        hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
        if !hasPermission {
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("PERMISSION_DENIED: User not authorized to search in this company"),
                "Insufficient permissions")
            return
        }
    }

    users, total, err := h.userService.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, limit, offset)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search employees")
        return
    }

    responseData := map[string]interface{}{
        "employees":   users,
        "total":       total,
        "page":        page,
        "page_size":   limit,
        "has_more":    (offset + limit) < total,
        "company_id":  companyID.String(),
        "filters":     filters,
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Advanced employee search completed"))

    h.logger.Info("Company advanced employee search completed",
        util.String("company_id", companyID.String()),
        util.Int("results", len(users)),
        util.Int("total", total),
        util.Any("filters", filters),
        util.Duration("duration", time.Since(startTime)))
}

// GetCompanyEmployeeSuggestions returns employee suggestions for autocomplete within a company
func (h *AuthHandler) GetCompanyEmployeeSuggestions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    companyIDStr := chi.URLParam(r, "companyID")
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    prefix := r.URL.Query().Get("prefix")
    if prefix == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("PREFIX_REQUIRED"),
            "Prefix parameter is required")
        return
    }

    prefix = util.SanitizeInput(prefix)
    
    limit := h.getIntQueryParam(r, "limit", 10)
    if limit > 20 {
        limit = 20
    }

    // Check permissions
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    // Verify user belongs to the company
    companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
    if err != nil || companyContext.CompanyID != companyID.String() {
        // Check if user has permission to search in any company (admin permission)
        hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
        if !hasPermission {
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("PERMISSION_DENIED: User not authorized to search in this company"),
                "Insufficient permissions")
            return
        }
    }

    suggestions, err := h.userService.GetCompanyEmployeeSuggestions(ctx, companyID, prefix, limit)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get employee suggestions")
        return
    }

    responseData := map[string]interface{}{
        "suggestions": suggestions,
        "total":       len(suggestions),
        "company_id":  companyID.String(),
        "prefix":      prefix,
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employee suggestions retrieved"))

    h.logger.Info("Company employee suggestions retrieved",
        util.String("company_id", companyID.String()),
        util.String("prefix", prefix),
        util.Int("suggestions", len(suggestions)),
        util.Duration("duration", time.Since(startTime)))
}

// FindCompanyEmployeeByUsername finds an employee by username within a company
func (h *AuthHandler) FindCompanyEmployeeByUsername(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    companyIDStr := chi.URLParam(r, "companyID")
    companyID, err := uuid.Parse(companyIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
        return
    }

    username := chi.URLParam(r, "username")
    if username == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("USERNAME_REQUIRED"),
            "Username parameter is required")
        return
    }

    username = util.SanitizeInput(username)

    // Check permissions
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    // Verify user belongs to the company
    companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
    if err != nil || companyContext.CompanyID != companyID.String() {
        // Check if user has permission to search in any company (admin permission)
        hasPermission, _ := h.companyService.CheckPermissionFromContext(ctx, "admin.company.view")
        if !hasPermission {
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("PERMISSION_DENIED: User not authorized to search in this company"),
                "Insufficient permissions")
            return
        }
    }

    employee, err := h.userService.FindCompanyEmployeeByUsername(ctx, companyID, username)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Employee not found")
        return
    }

    h.sanitizeUser(employee)
    
    responseData := map[string]interface{}{
        "employee":   employee,
        "company_id": companyID.String(),
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Employee found"))

    h.logger.Info("Company employee found by username",
        util.String("company_id", companyID.String()),
        util.String("username", username),
        util.String("employee_id", employee.UserID.String()),
        util.Duration("duration", time.Since(startTime)))
}


func (h *AuthHandler) VerifyMPINLogin(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req MPINVerifyPhoneRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Sanitize inputs
    req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
    req.UserAgent = util.SanitizeInput(req.UserAgent)
    req.CompanyID = util.SanitizeInput(req.CompanyID)

    // Get user by phone number
    user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "User not found")
        return
    }

    // Check user status
    if !user.IsActive {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("USER_INACTIVE: Account is inactive"),
            "Account is inactive. Please contact support.")
        return
    }

    // Get all active employee records for this user
    employees, err := h.companyService.GetEmployeesByUser(ctx, user.UserID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user employment info")
        return
    }

    // Filter active employees
    var activeEmployees []*models.CompanyEmployee
    for _, emp := range employees {
        if emp.IsActive {
            activeEmployees = append(activeEmployees, emp)
        }
    }

    if len(activeEmployees) == 0 {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("NO_ACTIVE_EMPLOYMENT: User is not an active employee in any company"),
            "User is not an active employee in any company")
        return
    }

    var selectedCompanyID uuid.UUID
    var selectedEmployee *models.CompanyEmployee

    // If company ID is provided, use it
    if req.CompanyID != "" {
        companyID, err := uuid.Parse(req.CompanyID)
        if err != nil {
            h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID format")
            return
        }

        // Find the specific employee record for this company
        for _, emp := range activeEmployees {
            if emp.CompanyID == companyID {
                selectedCompanyID = companyID
                selectedEmployee = emp
                break
            }
        }

        if selectedEmployee == nil {
            h.respondWithError(w, http.StatusForbidden,
                fmt.Errorf("COMPANY_ACCESS_DENIED: User is not an active employee in the specified company"),
                "User does not have access to the specified company")
            return
        }
    } else {
        // If no company specified and user has multiple companies, return error with company list
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

            h.respondWithError(w, http.StatusBadRequest,
                fmt.Errorf("MULTIPLE_COMPANIES: User belongs to multiple companies"),
                "Please specify which company you want to log into")
            h.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
                "success": false,
                "error":   "MULTIPLE_COMPANIES",
                "message": "User belongs to multiple companies. Please specify a company_id.",
                "companies": companyList,
            })
            return
        }

        // Only one company - use it
        selectedEmployee = activeEmployees[0]
        selectedCompanyID = selectedEmployee.CompanyID
    }

    // Check company subscription status
    company, err := h.companyService.GetCompany(ctx, selectedCompanyID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company info")
        return
    }

    if !company.IsActive {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("COMPANY_INACTIVE: Company account is inactive"),
            "Company account is inactive")
        return
    }

    // Verify device trust for THIS specific company
    deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, user.UserID, req.DeviceID)
    if err != nil || !deviceTrusted {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
            "MPIN login not allowed on this device")
        return
    }

    // ✅ Enhanced MPIN verification with device fingerprint
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
        h.respondWithError(w, http.StatusUnauthorized, err, "MPIN verification failed")
        return
    }

    if !mpinResult.Verified {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("MPIN_VERIFICATION_FAILED: %s", mpinResult.Message),
            "MPIN verification failed")
        return
    }

    // Get company context for THIS specific company
    companyContext, err := h.companyService.GetCompanyContextForCompany(ctx, user.UserID, selectedCompanyID)
    if err != nil {
        h.logger.Warn("Company context check failed", util.ErrorField(err))
        // Continue without company context if there's an error
    }

    userRole := "user"
    if companyContext != nil {
        userRole = companyContext.RoleName
    }

    // Issue JWT token pair WITH the specific company ID
    tokenReq := &service.IssueTokenPairRequest{
        UserID:      user.UserID.String(),
        Role:        userRole,
        DeviceID:    req.DeviceID,
        SessionType: "user",
        IPAddress:   h.getClientIP(r),
        CompanyID:   selectedCompanyID.String(), // Pass the specific company ID
    }

    tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue tokens")
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

    h.logger.Info("MPIN login completed with JWT tokens",
        util.String("user_id", user.UserID.String()),
        util.String("phone", req.PhoneNumber),
        util.String("company_id", selectedCompanyID.String()),
        util.String("role", userRole),
        util.Duration("duration", time.Since(startTime)),
    )
}



func (h *AuthHandler) GetCompanyContext(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    // Get user ID from JWT context
    userID := r.Context().Value("user_id")
    if userID == nil {
        h.respondWithError(w, http.StatusUnauthorized,
            fmt.Errorf("UNAUTHORIZED: User not authenticated"),
            "Authentication required")
        return
    }

    userIDParsed, err := uuid.Parse(userID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
        return
    }

    // Get company ID from JWT context
    companyID := r.Context().Value("company_id")
    if companyID == nil {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("NO_COMPANY_CONTEXT: Token doesn't have company context"),
            "Token doesn't have company context")
        return
    }

    companyIDParsed, err := uuid.Parse(companyID.(string))
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID in token")
        return
    }

    // Get company context for THIS specific company
    companyContext, err := h.companyService.GetCompanyContextForCompany(ctx, userIDParsed, companyIDParsed)
    if err != nil {
        if strings.Contains(err.Error(), "subscription status:") {
            h.respondWithError(w, http.StatusPaymentRequired, err, "Subscription issue")
            return
        }
        if strings.Contains(err.Error(), "employee not found") {
            h.respondWithError(w, http.StatusForbidden, err, "Not an active employee in this company")
            return
        }
        h.respondWithError(w, http.StatusNotFound, err, "Company context not found")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(companyContext, "Company context retrieved"))

    h.logger.Debug("Company context retrieved",
        util.String("user_id", userIDParsed.String()),
        util.String("company_id", companyIDParsed.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

// Add this middleware to validate JWT with company context
func (h *AuthHandler) CompanyContextMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("NO_AUTH_HEADER"), "No Authorization header")
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("INVALID_AUTH_FORMAT"), "Invalid Authorization format")
            return
        }

        tokenString := parts[1]

        claims, err := h.jwtService.ValidateAccessToken(r.Context(), tokenString)
        if err != nil {
            h.respondWithError(w, http.StatusUnauthorized, err, "Token validation failed")
            return
        }

        // Add company ID to context if it exists
        ctx := r.Context()
        ctx = context.WithValue(ctx, "user_id", claims.UserID)
        ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
        ctx = context.WithValue(ctx, "role", claims.Role)
        ctx = context.WithValue(ctx, "session_type", claims.SessionType)
        ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
        
        if claims.CompanyID != "" {
            ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
        }

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}


// internal/handler/auth_handler.go
func (h *AuthHandler) GetCompanyByEmployeePhonePublic(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    // Get raw query parameter to handle plus signs properly
    query := r.URL.RawQuery
    phoneNumber := ""
    
    // Parse query parameters manually to handle plus signs
    if query != "" {
        pairs := strings.Split(query, "&")
        for _, pair := range pairs {
            parts := strings.Split(pair, "=")
            if len(parts) == 2 && parts[0] == "phone" {
                // Decode the phone number
                decoded, err := url.QueryUnescape(parts[1])
                if err == nil {
                    phoneNumber = decoded
                } else {
                    phoneNumber = parts[1]
                }
                break
            }
        }
    }
    
    if phoneNumber == "" {
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("PHONE_REQUIRED: Phone number is required"),
            "Phone number parameter is required")
        return
    }

    // Ensure phone number starts with +
    if !strings.HasPrefix(phoneNumber, "+") && len(phoneNumber) > 0 && phoneNumber[0] != ' ' {
        phoneNumber = "+" + strings.TrimSpace(phoneNumber)
    }
    
    // Sanitize input
    phoneNumber = util.SanitizeInput(phoneNumber)
    
    // Call the NEW service method to get ALL companies
    companies, err := h.companyService.GetCompaniesByEmployeePhone(ctx, phoneNumber)
    if err != nil {
        if strings.Contains(err.Error(), "not found") || 
           strings.Contains(err.Error(), "is not an employee") {
            h.respondWithError(w, http.StatusNotFound, err, "No companies found for this employee phone")
            return
        }
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get companies")
        return
    }

    // Return array of companies
    responseData := make([]map[string]interface{}, len(companies))
    for i, company := range companies {
        responseData[i] = map[string]interface{}{
            "company_id":   company.CompanyID.String(),
            "company_name": company.CompanyName,
        }
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Companies retrieved successfully"))

    h.logger.Info("Companies retrieved by employee phone",
        util.String("phone", phoneNumber),
        util.Int("company_count", len(companies)),
        util.Duration("duration", time.Since(startTime)),
    )
}