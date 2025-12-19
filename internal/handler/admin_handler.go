// handler/admin_handler.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"strconv"  // Add this
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"math/bits"
	"github.com/golang-jwt/jwt/v5"  
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// AdminHandler handles admin related HTTP endpoints
type AdminHandler struct {
	adminService   *service.AdminService
	companyService *service.CompanyService
	userService    *service.UserService
	otpService     *service.OTPService
	mpinService    *service.AdminMPINService
	deviceService  *service.AdminDeviceService
	sessionService *service.SessionService
	jwtService     *service.JWTService
	logger         *zap.Logger
}

func NewAdminHandler(
	adminService *service.AdminService,
	companyService *service.CompanyService,
	userService *service.UserService,
	otpService *service.OTPService,
	mpinService *service.AdminMPINService,
	deviceService *service.AdminDeviceService,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) *AdminHandler {
	return &AdminHandler{
		adminService:   adminService,
		companyService: companyService,
		userService:    userService,
		otpService:     otpService,
		mpinService:    mpinService,
		deviceService:  deviceService,
		sessionService: sessionService,
		jwtService:     jwtService,
		logger:         logger,
	}
}

func (h *AdminHandler) RegisterRoutes(router chi.Router) {
	// Admin Authentication Routes (public - no auth middleware)
	router.Route("/admin-auth", func(r chi.Router) {
		r.Post("/login/initiate", h.InitiateAdminLogin)
		r.Post("/init-owner", h.InitializeOwner)
		r.Post("/login/verify-otp", h.VerifyAdminOTPLogin)
		r.Post("/login/verify-mpin", h.VerifyAdminMPINLogin)
		r.Post("/mpin/setup", h.SetupAdminMPIN)
		r.Post("/mpin/change", h.ChangeAdminMPIN)
		r.Post("/mpin/forgot", h.ForgotAdminMPIN)
		r.Post("/mpin/forgot/verify", h.VerifyForgotAdminMPIN)
		r.Post("/refresh", h.RefreshAdminTokens)
		r.Post("/logout", h.LogoutAdmin)
		r.Get("/health", h.HealthCheck)
	})
}

// ===== ADMIN AUTHENTICATION FLOW =====

// LoginFlowResponse defines the response for admin login flow
type LoginFlowResponse struct {
	UserExists    bool   `json:"user_exists"`
	HasMPIN       bool   `json:"has_mpin"`
	MPINLocked    bool   `json:"mpin_locked"`
	DeviceTrusted bool   `json:"device_trusted"`
	FlowState     string `json:"flow_state"`
	Message       string `json:"message"`
	UserID        string `json:"user_id,omitempty"`
}

func (h *AdminHandler) InitiateAdminLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	h.logger.Debug("🔍 InitiateAdminLogin called",
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID))

	// ✅ CHECK: Admin exists in handler (not in OTP service)
	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	adminExists := err == nil && admin != nil

	response := &LoginFlowResponse{
		UserExists: adminExists,
	}

	if !adminExists {
		response.FlowState = "new_user"
		response.Message = "New admin - OTP verification required for setup"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	h.logger.Debug("🔍 Checking MPIN status for admin",
		util.String("admin_id", admin.AdminID.String()))

	// Use AdminMPINService method
	mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID)
	if err != nil {
		h.logger.Error("❌ Error getting MPIN status",
			util.ErrorField(err),
			util.String("admin_id", admin.AdminID.String()))
		response.FlowState = "existing_user_otp"
		response.Message = "Existing admin - OTP verification required (no MPIN setup)"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	h.logger.Debug("📊 MPIN Status Result",
		util.String("admin_id", admin.AdminID.String()),
		util.Bool("exists", mpinStatus.Exists),
		util.Bool("is_locked", mpinStatus.IsLocked))

	// ✅ CRITICAL: Only set HasMPIN to true if MPIN actually exists
	response.HasMPIN = mpinStatus.Exists
	response.MPINLocked = mpinStatus.IsLocked

	// Use AdminDeviceService method
	deviceTrusted, _ := h.deviceService.IsDeviceTrusted(ctx, admin.AdminID, req.DeviceID)

	h.logger.Debug("📊 Final Login Flow Decision",
		util.String("admin_id", admin.AdminID.String()),
		util.Bool("has_mpin", response.HasMPIN),
		util.Bool("mpin_locked", response.MPINLocked),
		util.Bool("device_trusted", deviceTrusted))

	// Update flow logic based on MPIN existence
	if !mpinStatus.Exists {
		response.FlowState = "existing_user_otp"
		response.Message = "Existing admin - OTP verification required (no MPIN setup)"
	} else if response.MPINLocked {
		response.FlowState = "mpin_locked"
		response.Message = "MPIN locked - OTP verification required"
	} else if deviceTrusted {
		response.FlowState = "existing_user_mpin"
		response.DeviceTrusted = true
		response.Message = "Trusted device - MPIN login available"
		response.UserID = admin.AdminID.String()
	} else {
		response.FlowState = "existing_user_otp"
		response.Message = "Untrusted device - OTP verification required"
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin login flow determined"))

	h.logger.Info("✅ Admin login initiation completed",
		util.String("phone", req.PhoneNumber),
		util.Bool("admin_exists", adminExists),
		util.Bool("has_mpin", response.HasMPIN),
		util.Bool("mpin_locked", response.MPINLocked),
		util.Bool("device_trusted", deviceTrusted),
		util.String("flow_state", response.FlowState),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ✅ UPDATED: VerifyAdminOTPLogin - removed device trust check (handled by OTP service)
func (h *AdminHandler) VerifyAdminOTPLogin(w http.ResponseWriter, r *http.Request) {
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

	otpVerifyReq := service.OTPVerifyRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               req.OTP,
		Purpose:           "admin_login",
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(), // ✅ CRITICAL: ADDED THIS LINE
	}

	otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
	if err != nil {
		h.handleOTPError(w, err)
		return
	}

	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("AUTHENTICATION_FAILED"),
			"Authentication failed")
		return
	}

	// ✅ CHECK: Admin exists in handler
	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Authentication failed")
		return
	}

	// Device binding handled by OTP service internally
	deviceReq := service.AdminBindDeviceRequest{
		AdminID:           admin.AdminID,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		h.logger.Warn("Failed to update device trust for admin", util.ErrorField(err))
	}

	if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
		if err := h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID); err != nil {
			h.logger.Warn("Failed to unlock MPIN after OTP verification", util.ErrorField(err))
		}
	}

	// ✅ ENHANCE: Include quota information in response
	dailyUsed := otpResponse.QuotaUsed
	dailyLimit := otpResponse.DailyQuota

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"admin_id":       admin.AdminID.String(),
		"device_trusted": true,
		"has_mpin":       h.hasMPIN(ctx, admin.AdminID),
		"mpin_locked":    false,
		"daily_quota": map[string]interface{}{
			"used":      dailyUsed,
			"limit":     dailyLimit,
			"remaining": dailyLimit - dailyUsed,
		},
		"message": "OTP verification successful. Device is now trusted.",
	}, "Admin device setup successful"))

	h.logger.Info("Admin OTP verification completed - device trusted",
		util.String("admin_id", admin.AdminID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.Int("daily_quota_used", dailyUsed),
		util.Int("daily_quota_limit", dailyLimit),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) VerifyAdminMPINLogin(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req struct {
        AdminID           string `json:"admin_id" validate:"required"`
        MPIN              string `json:"mpin" validate:"required"`
        DeviceID          string `json:"device_id" validate:"required"`
        DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
        UserAgent         string `json:"user_agent"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

    adminID, err := uuid.Parse(req.AdminID)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    // ✅ CHECK: Device trust handled by MPIN service
    deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, adminID, req.DeviceID)
    if err != nil || !deviceTrusted {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
            "MPIN login not allowed on this device")
        return
    }

    // ✅ FIXED: Enhanced IP handling with validation
    ipAddress := h.getClientIP(r)
    if ipAddress == "" {
        h.logger.Warn("Invalid IP address detected, using safe default",
            util.String("admin_id", adminID.String()),
            util.String("device_id", req.DeviceID))
        ipAddress = "0.0.0.0"
    }

    mpinVerifyReq := &service.AdminMPINVerifyRequest{
        AdminID:           adminID,
        MPIN:              req.MPIN,
        DeviceID:          req.DeviceID,
        DeviceFingerprint: req.DeviceFingerprint,
        IPAddress:         ipAddress,
        UserAgent:         r.UserAgent(),
    }

    mpinResult, err := h.mpinService.VerifyAdminMPIN(ctx, mpinVerifyReq)
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

    admin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get admin details")
        return
    }

    // ✅ FIXED: Use bitmask fields
    tokenReq := &service.IssueTokenPairRequest{
        UserID:         admin.AdminID.String(),
        Role:           admin.GetRoleString(),
        DeviceID:       req.DeviceID,
        SessionType:    "admin",
        IPAddress:      ipAddress,
        AdminRoleMask:  admin.AdminRoleMask,
        PermissionMask: admin.AdminPermissionMask,
    }

    tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue JWT tokens")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "tokens":  tokens,
        "admin": map[string]interface{}{
            "admin_id":              admin.AdminID.String(),
            "role_mask":             admin.AdminRoleMask,
            "permission_mask":       admin.AdminPermissionMask,
            "role_string":           admin.GetRoleString(),
            "permission_names":      admin.GetPermissionNames(),
        },
        "message": "Admin MPIN login successful",
    }, "Admin login successful"))

    h.logger.Info("Admin MPIN login completed with JWT tokens",
        util.String("admin_id", adminID.String()),
        util.Uint64("role_mask", admin.AdminRoleMask),
        util.String("ip_address", ipAddress),
        util.Duration("duration", time.Since(startTime)),
    )
}


// UpdateAdminPermissions updates admin permissions (needs conversion from string to bitmask)
func (h *AdminHandler) UpdateAdminPermissions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
        return
    }

    var req struct {
        Permissions []string `json:"permissions"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if len(req.Permissions) == 0 {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("empty permissions"), "Permissions list cannot be empty")
        return
    }

    // ✅ FIXED: Convert permission names to bitmask
    permissionMask := make([]uint64, 4)
    for _, permName := range req.Permissions {
        if bitIndex, exists := models.AdminPermissionBitIndices[permName]; exists {
            permissionMask = models.SetPermission(permissionMask, bitIndex, true)
        } else {
            h.logger.Warn("Unknown permission name", util.String("permission", permName))
        }
    }

    if err := h.adminService.UpdateAdminPermissions(ctx, adminID, permissionMask, requesterID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to update permissions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "permission_mask": permissionMask,
        "permission_names": req.Permissions,
    }, "Admin permissions updated successfully"))
    
    h.logger.Info("Admin permissions updated via HTTP",
        util.String("admin_id", adminID.String()),
        util.Strings("permissions", req.Permissions),
        util.Duration("duration", time.Since(startTime)),
    )
}
func (h *AdminHandler) SetupAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		AdminID           string `json:"admin_id" validate:"required"`
		MPIN              string `json:"mpin" validate:"required,min=6,max=8"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
		UserAgent         string `json:"user_agent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	adminID, err := uuid.Parse(req.AdminID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	mpinReq := &service.AdminMPINSetupRequest{
		AdminID:           adminID,
		MPIN:              req.MPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         req.UserAgent,
	}

	if err := h.mpinService.SetupAdminMPIN(ctx, mpinReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to setup MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
		"message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
	}, "Admin MPIN setup successful"))

	h.logger.Info("Admin MPIN setup completed (no tokens issued)",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ✅ NEW: ChangeAdminMPIN handler
func (h *AdminHandler) ChangeAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		AdminID           string `json:"admin_id" validate:"required"`
		CurrentMPIN       string `json:"current_mpin" validate:"required"`
		NewMPIN           string `json:"new_mpin" validate:"required,min=6,max=8"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
		UserAgent         string `json:"user_agent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.CurrentMPIN = util.SanitizeInput(req.CurrentMPIN)
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	adminID, err := uuid.Parse(req.AdminID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	mpinReq := &service.AdminMPINChangeRequest{
		AdminID:           adminID,
		CurrentMPIN:       req.CurrentMPIN,
		NewMPIN:           req.NewMPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(), // ✅ ADD THIS LINE
	}

	if err := h.mpinService.ChangeAdminMPIN(ctx, mpinReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to change MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "MPIN changed successfully",
	}, "Admin MPIN change successful"))

	h.logger.Info("Admin MPIN changed successfully",
		util.String("admin_id", adminID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ✅ UPDATED: ForgotAdminMPIN - removed device trust check (handled by OTP service)
func (h *AdminHandler) ForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
		UserAgent         string `json:"user_agent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON request for ForgotAdminMPIN", util.ErrorField(err))
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)
	req.UserAgent = util.SanitizeInput(req.UserAgent)

	h.logger.Info("📩 ForgotAdminMPIN Request Received",
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.String("device_fingerprint", req.DeviceFingerprint),
		util.String("user_agent", req.UserAgent),
		util.String("endpoint", "/admin/forgot-mpin"),
	)

	// ✅ CHECK: Admin exists in handler
	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil || admin == nil {
		h.logger.Warn("Admin not found for ForgotAdminMPIN",
			util.String("phone", req.PhoneNumber),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusNotFound, fmt.Errorf("phone not registered"), "Phone not registered")
		return
	}

	clientIP := h.getClientIP(r)

	// Build forgot request - device trust handled by OTP service internally
	forgotReq := &service.AdminMPINForgotRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         clientIP,
		UserAgent:         req.UserAgent,
	}

	// STEP 4: Trigger MPIN Forgot service
	if err := h.mpinService.ForgotAdminMPIN(ctx, forgotReq); err != nil {
		h.logger.Error("Failed to initiate ForgotAdminMPIN",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to initiate forgot MPIN process")
		return
	}

	// SUCCESS
	h.logger.Info("🎉 ForgotAdminMPIN initiated successfully",
		util.String("admin_id", admin.AdminID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "OTP sent to your registered phone number for MPIN reset",
	}, "Forgot MPIN initiated"))
}

// ✅ UPDATED: VerifyForgotAdminMPIN - removed device trust check (handled by OTP service)
func (h *AdminHandler) VerifyForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		NewMPIN           string `json:"new_mpin" validate:"required,min=6,max=8"`
		OTPCode           string `json:"otp_code" validate:"required,len=6"`
		DeviceFingerprint string `json:"device_fingerprint"`
		UserAgent         string `json:"user_agent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.OTPCode = util.SanitizeInput(req.OTPCode)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	// ✅ CHECK: Admin exists in handler
	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil || admin == nil {
		h.respondWithError(w, http.StatusNotFound, fmt.Errorf("phone not registered"), "Phone not registered")
		return
	}

	// Device trust handled by OTP service internally during OTP verification
	clientIP := h.getClientIP(r)

	// 🔥 Verify OTP + Reset MPIN
	forgotReq := &service.AdminMPINForgotWithOTPRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		NewMPIN:           req.NewMPIN,
		OTPCode:           req.OTPCode,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         clientIP,
		UserAgent:         r.UserAgent(), // ✅ CRITICAL: ADDED THIS LINE
	}

	if err := h.mpinService.VerifyForgotAdminMPINOTP(ctx, forgotReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to reset MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "MPIN reset successfully. You can now login with your new MPIN.",
	}, "Admin MPIN reset successful"))

	h.logger.Info("Admin MPIN reset via forgot flow completed",
		util.String("admin_id", admin.AdminID.String()),
		util.String("phone", req.PhoneNumber),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ✅ NEW: ChangeAdminMPINByAdmin handler (admin changes another admin's MPIN)
func (h *AdminHandler) ChangeAdminMPINByAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// 🔥 NEW OVERRIDE: Allow if session_type = "admin"
	if !h.hasAdminOrPermission(r, "read_users") {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED"),
			"You don't have permission to change admin MPIN")
		return
	}

	// Parse request body
	var req struct {
		AdminID string `json:"admin_id" validate:"required"`
		NewMPIN string `json:"new_mpin" validate:"required,min=6,max=8"`
		Reason  string `json:"reason,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.Reason = util.SanitizeInput(req.Reason)

	// Validate AdminID
	adminID, err := uuid.Parse(req.AdminID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	// Get requester admin ID
	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Prepare request for service layer
	changeReq := &service.AdminMPINAdminChangeRequest{
		AdminID:   adminID,
		NewMPIN:   req.NewMPIN,
		ChangedBy: requesterID,
		Reason:    req.Reason,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(), // ✅ ADD THIS LINE
	}

	// Call service
	if err := h.mpinService.ChangeAdminMPINByAdmin(ctx, changeReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to change admin MPIN")
		return
	}

	// Response
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "Admin MPIN changed successfully by administrator",
	}, "Admin MPIN change by admin successful"))

	// Log
	h.logger.Warn("Admin MPIN changed by another admin",
		util.String("admin_id", adminID.String()),
		util.String("changed_by", requesterID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) RefreshAdminTokens(w http.ResponseWriter, r *http.Request) {
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

	h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Admin tokens refreshed successfully"))
}

func (h *AdminHandler) LogoutAdmin(w http.ResponseWriter, r *http.Request) {
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

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin logged out successfully"))
}

// ===== ENHANCED COMPANY MANAGEMENT WITH RBAC FLOW =====

// CreateCompanyRequest defines the request for creating a company with RBAC setup
type CreateCompanyRequest struct {
	CompanyName        string   `json:"company_name" validate:"required"`
	OwnerPhone         string   `json:"owner_phone" validate:"required"`
	OwnerUsername      string   `json:"owner_username" validate:"required,username"`
	OwnerFullName      string   `json:"owner_full_name" validate:"required,max=255"`
	SubscriptionTier   string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
	MaxEmployees       int      `json:"max_employees" validate:"required,min=1,max=2000"`
	DataRegion         string   `json:"data_region" validate:"required"`
	SubscriptionMonths int      `json:"subscription_months" validate:"required,min=1,max=36"`
	SubscriptionDays   int      `json:"subscription_days" validate:"min=0,max=30"`
	Departments        []string `json:"departments"`
}
func (h *AdminHandler) CreateCompany(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
        return
    }

    var req CreateCompanyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Validate the request
    if err := validate.Struct(req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
        return
    }

    // Create company using enhanced service
    companyReq := service.CreateCompanyRequest{
        CompanyName:        req.CompanyName,
        OwnerPhone:         req.OwnerPhone,
        OwnerUsername:      req.OwnerUsername,
        OwnerFullName:      req.OwnerFullName,
        SubscriptionTier:   req.SubscriptionTier,
        MaxEmployees:       req.MaxEmployees,
        DataRegion:         req.DataRegion,
        SubscriptionMonths: req.SubscriptionMonths,
        SubscriptionDays:   req.SubscriptionDays,
        Departments:        req.Departments,
    }

    company, err := h.companyService.CreateCompany(ctx, &companyReq, adminID)
    if err != nil {
        // ✅ UPDATED: Only check for company name conflict
        if strings.Contains(err.Error(), "company with name") && strings.Contains(err.Error(), "already exists") {
            h.respondWithError(w, http.StatusConflict, err, "Company with this name already exists for the owner")
            return
        }
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to create company")
        return
    }

    // Get the actual owner user details
    actualOwnerUser, err := h.userService.GetUserByPhone(ctx, req.OwnerPhone)
    var actualUsername, actualFullName string
    if err == nil && actualOwnerUser != nil {
        actualUsername = actualOwnerUser.Username
        actualFullName = actualOwnerUser.FullName
    } else {
        actualUsername = req.OwnerUsername
        actualFullName = req.OwnerFullName
    }

    response := map[string]interface{}{
        "success": true,
        "message": "Company created successfully with RBAC setup",
        "data": map[string]interface{}{
            "company_id":        company.CompanyID.String(),
            "company_name":      company.CompanyName,
            "owner_username":    actualUsername,
            "owner_full_name":   actualFullName,
            "owner_phone":       req.OwnerPhone,
            "owner_user_id":     company.OwnerUserID.String(),
            "subscription_tier": company.SubscriptionTier,
            "departments":       len(req.Departments),
            "created_at":        company.CreatedAt,
            "note":              "User may have been assigned a different username if the requested one was already taken",
        },
    }

    h.respondWithJSON(w, http.StatusCreated, response)

    h.logger.Info("Company created by admin with full RBAC setup",
        util.String("company_id", company.CompanyID.String()),
        util.String("company_name", company.CompanyName),
        util.String("owner_phone", req.OwnerPhone),
        util.String("owner_username", actualUsername),
        util.String("owner_full_name", actualFullName),
        util.String("subscription_tier", req.SubscriptionTier),
        util.Int("department_count", len(req.Departments)),
        util.String("created_by", adminID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}
// ===== DEPARTMENT MANAGEMENT =====

// // CreateDepartmentRequest defines the request for creating a department
// type CreateDepartmentRequest struct {
// 	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
// 	DepartmentName     string     `json:"department_name" validate:"required"`
// 	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
// 	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
// 	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
// }

// ===== ROLE MANAGEMENT =====

// // CreateRoleRequest defines the request for creating a role
// type CreateRoleRequest struct {
// 	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
// 	RoleName      string      `json:"role_name" validate:"required"`
// 	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
// 	Description   string      `json:"description,omitempty"`
// 	DepartmentIDs []uuid.UUID `json:"department_ids"` // Roles can be assigned to multiple departments
// 	PermissionIDs []uuid.UUID `json:"permission_ids"` // Direct permission assignments
// }

// func (h *AdminHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	adminID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
// 		return
// 	}

// 	var req CreateRoleRequest

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Convert to service request
// 	roleReq := service.CreateRoleRequest{
// 		CompanyID:     req.CompanyID,
// 		RoleName:      req.RoleName,
// 		RoleLevel:     req.RoleLevel,
// 		Description:   req.Description,
// 		DepartmentIDs: req.DepartmentIDs,
// 		PermissionIDs: req.PermissionIDs,
// 		CreatedBy:     adminID,
// 	}

// 	role, err := h.companyService.CreateRole(ctx, &roleReq)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to create role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))

// 	h.logger.Info("Role created by admin",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("role_id", role.RoleID.String()),
// 		util.String("role_name", req.RoleName),
// 		util.Int("role_level", req.RoleLevel),
// 		util.Int("department_count", len(req.DepartmentIDs)),
// 		util.Int("permission_count", len(req.PermissionIDs)),
// 		util.String("created_by", adminID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // GetCompanyRoles retrieves all roles for a company
func (h *AdminHandler) GetCompanyRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)
	_ = h.getBoolQueryParam(r, "include_permissions", false)

	roles, total, err := h.companyService.GetRolesByCompany(ctx, companyID, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company roles")
		return
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"count":      len(roles),
			"total":      total,
			"limit":      limit,
			"offset":     offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company roles retrieved successfully"))

	h.logger.Debug("Company roles retrieved",
		util.String("company_id", companyID.String()),
		util.Int("count", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== PERMISSION MANAGEMENT =====

// GetSystemDepartments retrieves all global system departments
func (h *AdminHandler) GetSystemDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	systemDepts, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(systemDepts, "System departments retrieved successfully"))

	h.logger.Debug("System departments retrieved",
		util.Int("count", len(systemDepts)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetPermissionsByModule retrieves permissions by module
func (h *AdminHandler) GetPermissionsByModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	module := chi.URLParam(r, "module")
	if module == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("module required"), "Module is required")
		return
	}

	permissions, err := h.companyService.GetPermissionsByModule(ctx, module)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions by module")
		return
	}

	response := map[string]interface{}{
		"permissions": permissions,
		"meta": map[string]interface{}{
			"module": module,
			"count":  len(permissions),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Permissions retrieved by module"))

	h.logger.Debug("Permissions retrieved by module",
		util.String("module", module),
		util.Int("count", len(permissions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAllPermissions retrieves all permissions with optional filtering
func (h *AdminHandler) GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	module := r.URL.Query().Get("module")
	category := r.URL.Query().Get("category")
	tier := r.URL.Query().Get("tier")

	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get permissions")
		return
	}

	response := map[string]interface{}{
		"permissions": permissions,
		"meta": map[string]interface{}{
			"count":    len(permissions),
			"module":   module,
			"category": category,
			"tier":     tier,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "All permissions retrieved successfully"))

	h.logger.Debug("All permissions retrieved",
		util.Int("count", len(permissions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// // GrantRolePermissions grants permissions to a role
// func (h *AdminHandler) GrantRolePermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	adminID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
// 		return
// 	}

// 	roleIDStr := chi.URLParam(r, "roleID")
// 	roleID, err := uuid.Parse(roleIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
// 		return
// 	}

// 	var req struct {
// 		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	grantReq := service.GrantRolePermissionsRequest{
// 		RoleID:        roleID,
// 		PermissionIDs: req.PermissionIDs,
// 	}

// 	if err := h.companyService.GrantRolePermissions(ctx, &grantReq); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to grant role permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permissions granted to role successfully"))

// 	h.logger.Info("Permissions granted to role",
// 		util.String("role_id", roleID.String()),
// 		util.Int("permission_count", len(req.PermissionIDs)),
// 		util.String("granted_by", adminID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // UpdateEmployeeRole updates employee role and department
// func (h *AdminHandler) UpdateEmployeeRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	adminID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
// 		return
// 	}

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

// 	var req struct {
// 		RoleID       uuid.UUID `json:"role_id" validate:"required"`
// 		DepartmentID uuid.UUID `json:"department_id" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Update role
// 	if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.RoleID, adminID); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to update employee role")
// 		return
// 	}

// 	// // Update department
// 	// if err := h.companyService.UpdateEmployeeDepartment(ctx, companyID, userID, req.DepartmentID, adminID); err != nil {
// 	// 	statusCode := h.getStatusCode(err)
// 	// 	h.respondWithError(w, statusCode, err, "Failed to update employee department")
// 	// 	return
// 	// }

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role and department updated successfully"))

// 	h.logger.Info("Employee role and department updated",
// 		util.String("company_id", companyID.String()),
// 		util.String("user_id", userID.String()),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.String("updated_by", adminID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // GetEmployeePermissions retrieves permissions for an employee
// func (h *AdminHandler) GetEmployeePermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get employee permissions")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"permissions": permissions,
// 		"meta": map[string]interface{}{
// 			"user_id": userID.String(),
// 			"count":   len(permissions),
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employee permissions retrieved successfully"))

// 	h.logger.Debug("Employee permissions retrieved",
// 		util.String("user_id", userID.String()),
// 		util.Int("permission_count", len(permissions)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// // CheckEmployeePermission checks if an employee has a specific permission
// func (h *AdminHandler) CheckEmployeePermission(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	var req service.PermissionCheckRequest

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	result, err := h.companyService.CheckPermission(ctx, &req)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to check permission")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(result, "Permission check completed"))

// 	h.logger.Debug("Employee permission check completed",
// 		util.String("company_id", req.CompanyID.String()),
// 		util.String("user_id", req.UserID.String()),
// 		util.String("permission", req.PermissionName),
// 		util.Bool("has_permission", result.HasPermission),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// ===== COMPANY ORGANIZATIONAL HIERARCHY =====

// GetCompanyHierarchy retrieves the organizational hierarchy for a company
func (h *AdminHandler) GetCompanyHierarchy(w http.ResponseWriter, r *http.Request) {
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

	response := map[string]interface{}{
		"hierarchy": hierarchy,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"count":      len(hierarchy),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company hierarchy retrieved successfully"))

	h.logger.Debug("Company hierarchy retrieved",
		util.String("company_id", companyID.String()),
		util.Int("employee_count", len(hierarchy)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// // GetUserHierarchy retrieves the hierarchy context for a user across companies
// func (h *AdminHandler) GetUserHierarchy(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	userIDStr := chi.URLParam(r, "userID")
// 	userID, err := uuid.Parse(userIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
// 		return
// 	}

// 	hierarchy, err := h.companyService.GetUserHierarchy(ctx, userID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user hierarchy")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"hierarchy": hierarchy,
// 		"meta": map[string]interface{}{
// 			"user_id": userID.String(),
// 			"count":   len(hierarchy),
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "User hierarchy retrieved successfully"))

// 	h.logger.Debug("User hierarchy retrieved",
// 		util.String("user_id", userID.String()),
// 		util.Int("company_count", len(hierarchy)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// ===== BULK OPERATIONS =====

// ===== ENHANCED COMPANY STATS WITH RBAC =====

// GetCompanyRBACStats retrieves comprehensive RBAC statistics for a company
func (h *AdminHandler) GetCompanyRBACStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get department load
	deptLoad, err := h.companyService.GetDepartmentLoad(ctx, companyID)
	if err != nil {
		h.logger.Warn("Failed to get department load", util.ErrorField(err))
	}

	// Get role distribution
	roleDist, err := h.companyService.GetRoleDistribution(ctx, companyID)
	if err != nil {
		h.logger.Warn("Failed to get role distribution", util.ErrorField(err))
	}

	// Get company stats
	stats, err := h.companyService.GetCompanyStats(ctx, companyID)
	if err != nil {
		h.logger.Warn("Failed to get company stats", util.ErrorField(err))
	}

	response := map[string]interface{}{
		"department_load":   deptLoad,
		"role_distribution": roleDist,
		"company_stats":     stats,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"timestamp":  time.Now().UTC(),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company RBAC statistics retrieved successfully"))

	h.logger.Debug("Company RBAC stats retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== EXISTING COMPANY MANAGEMENT METHODS =====

// GetCompany retrieves company details by ID
func (h *AdminHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
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

	h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company details retrieved"))

	h.logger.Debug("Company retrieved by admin",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompaniesByStatus retrieves companies by status (active, inactive)
func (h *AdminHandler) GetCompaniesByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("status required"), "Status is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	var companies []*models.Company
	var total int
	var err error

	switch status {
	case "active":
		companies, total, err = h.companyService.ListCompanies(ctx, limit, offset)
	case "inactive":
		// You might need to implement a separate method for inactive companies
		// For now, we'll filter from all companies
		allCompanies, _, err := h.companyService.ListCompanies(ctx, 1000, 0)
		if err != nil {
			h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies")
			return
		}

		var inactiveCompanies []*models.Company
		for _, company := range allCompanies {
			if !company.IsActive {
				inactiveCompanies = append(inactiveCompanies, company)
			}
		}

		// Apply pagination
		start := offset
		if start > len(inactiveCompanies) {
			start = len(inactiveCompanies)
		}
		end := start + limit
		if end > len(inactiveCompanies) {
			end = len(inactiveCompanies)
		}

		companies = inactiveCompanies[start:end]
		total = len(inactiveCompanies)
	default:
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid status"), "Status must be active or inactive")
		return
	}

	if err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by status")
		return
	}

	response := map[string]interface{}{
		"companies": companies,
		"meta": map[string]interface{}{
			"status": status,
			"count":  len(companies),
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by status"))

	h.logger.Debug("Companies retrieved by status",
		util.String("status", status),
		util.Int("count", len(companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetRecentCompanies retrieves recently created companies
func (h *AdminHandler) GetRecentCompanies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	limit := h.getIntQueryParam(r, "limit", 50)

	companies, total, err := h.companyService.ListCompanies(ctx, limit, 0)
	if err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to get recent companies")
		return
	}

	response := map[string]interface{}{
		"companies": companies,
		"meta": map[string]interface{}{
			"count": len(companies),
			"total": total,
			"limit": limit,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Recent companies retrieved"))

	h.logger.Debug("Recent companies retrieved",
		util.Int("count", len(companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompaniesByTier retrieves companies by subscription tier
func (h *AdminHandler) GetCompaniesByTier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	tier := chi.URLParam(r, "tier")
	if tier == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("tier required"), "Subscription tier is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	companies, total, err := h.companyService.ListCompaniesByTier(ctx, tier, limit, offset)
	if err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by tier")
		return
	}

	response := map[string]interface{}{
		"companies": companies,
		"meta": map[string]interface{}{
			"tier":   tier,
			"count":  len(companies),
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by tier"))

	h.logger.Debug("Companies retrieved by tier",
		util.String("tier", tier),
		util.Int("count", len(companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompaniesWithExpiringSubscription retrieves companies whose subscription ends soon
func (h *AdminHandler) GetCompaniesWithExpiringSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get days parameter (default to 30 days)
	days := h.getIntQueryParam(r, "days", 30)
	if days <= 0 || days > 365 {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("invalid days parameter"),
			"Days must be between 1 and 365")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)

	companies, err := h.companyService.GetCompaniesWithExpiringSubscription(ctx, days, limit)
	if err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies with expiring subscriptions")
		return
	}

	response := map[string]interface{}{
		"companies": companies,
		"meta": map[string]interface{}{
			"days":  days,
			"count": len(companies),
			"limit": limit,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies with expiring subscriptions retrieved"))

	h.logger.Debug("Companies with expiring subscriptions retrieved",
		util.Int("days", days),
		util.Int("count", len(companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// DeactivateCompany deactivates a company
func (h *AdminHandler) DeactivateCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req struct {
		Reason string `json:"reason" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("reason required"), "Deactivation reason is required")
		return
	}

	if err := h.companyService.DeactivateCompany(ctx, companyID, req.Reason, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to deactivate company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company deactivated successfully"))

	h.logger.Info("Company deactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("deactivated_by", adminID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ReactivateCompany reactivates a company
func (h *AdminHandler) ReactivateCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	if err := h.companyService.ReactivateCompany(ctx, companyID, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to reactivate company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company reactivated successfully"))

	h.logger.Info("Company reactivated by admin",
		util.String("company_id", companyID.String()),
		util.String("reactivated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateSubscription updates company subscription
func (h *AdminHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req struct {
		Tier         string `json:"tier" validate:"required,oneof=basic premium enterprise"`
		Status       string `json:"status" validate:"required,oneof=active inactive pending ended"`
		MaxEmployees int    `json:"max_employees" validate:"required,min=1,max=2000"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.companyService.UpdateSubscription(ctx, companyID, req.Tier, req.Status, req.MaxEmployees, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to update subscription")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription updated successfully"))

	h.logger.Info("Company subscription updated",
		util.String("company_id", companyID.String()),
		util.String("tier", req.Tier),
		util.String("status", req.Status),
		util.Int("max_employees", req.MaxEmployees),
		util.String("updated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanyEmployees lists employees for a company
func (h *AdminHandler) GetCompanyEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Parse pagination
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	employees, total, err := h.companyService.ListEmployees(ctx, companyID, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list employees")
		return
	}

	response := map[string]interface{}{
		"employees": employees,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"count":      len(employees),
			"total":      total,
			"limit":      limit,
			"offset":     offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employees retrieved successfully"))

	h.logger.Debug("Company employees listed by admin",
		util.String("company_id", companyID.String()),
		util.Int("count", len(employees)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanyStats retrieves company statistics
func (h *AdminHandler) GetCompanyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	stats, err := h.companyService.GetCompanyStats(ctx, companyID)
	if err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to get company stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Company statistics retrieved successfully"))

	h.logger.Debug("Company stats retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ExtendSubscription extends company subscription
func (h *AdminHandler) ExtendSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req struct {
		AdditionalMonths int `json:"additional_months" validate:"min=0,max=36"`
		AdditionalDays   int `json:"additional_days" validate:"min=0,max=30"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.AdditionalMonths == 0 && req.AdditionalDays == 0 {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("either additional_months or additional_days must be provided"),
			"Either additional_months or additional_days must be provided")
		return
	}

	if err := h.companyService.ExtendSubscription(ctx, companyID, req.AdditionalMonths, req.AdditionalDays, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to extend subscription")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))

	h.logger.Info("Company subscription extended by admin",
		util.String("company_id", companyID.String()),
		util.Int("additional_months", req.AdditionalMonths),
		util.Int("additional_days", req.AdditionalDays),
		util.String("extended_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== EXISTING USER MANAGEMENT METHODS =====

func (h *AdminHandler) BanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, _ := h.getRequesterAdminID(r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req struct {
		Reason string `json:"reason" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	banReq := service.BanUserRequest{
		UserID:   userID,
		BannedBy: requesterID,
		Reason:   req.Reason,
	}

	if err := h.userService.BanUser(ctx, &banReq); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to ban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User banned successfully"))

	h.logger.Info("User banned by admin",
		util.String("user_id", userID.String()),
		util.String("banned_by", requesterID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, _ := h.getRequesterAdminID(r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	// Add request body parsing for the reason
	var req struct {
		Reason string `json:"reason" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("reason required"), "Unban reason is required")
		return
	}

	// Now call with all required parameters
	if err := h.userService.UnbanUser(ctx, userID, requesterID, req.Reason); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to unban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))

	h.logger.Info("User unbanned by admin",
		util.String("user_id", userID.String()),
		util.String("unbanned_by", requesterID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateUserKYC - Admin approves/rejects user KYC
func (h *AdminHandler) UpdateUserKYC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req struct {
		Status string `json:"status" validate:"required,oneof=pending verified rejected under_review expired"`
		Level  string `json:"level" validate:"required,oneof=basic advanced full"`
		Reason string `json:"reason,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	kycReq := service.KYCUpdateRequest{
		UserID:     userID,
		Status:     strings.ToLower(req.Status),
		Level:      req.Level,
		Reason:     req.Reason,
		VerifiedBy: adminID,
	}

	if err := h.userService.UpdateKYCStatus(ctx, &kycReq); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user KYC")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User KYC status updated successfully"))

	h.logger.Info("User KYC status updated by admin",
		util.String("user_id", userID.String()),
		util.String("status", req.Status),
		util.String("level", req.Level),
		util.String("updated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ListUsersByKYCStatus - Admin views users filtered by KYC status
func (h *AdminHandler) ListUsersByKYCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("status required"), "KYC status is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)

	users, total, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by KYC status")
		return
	}

	// Sanitize users to remove sensitive fields
	for _, u := range users {
		h.sanitizeUserForAdmin(u)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"status": status,
			"count":  len(users),
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Users retrieved by KYC status successfully"))

	h.logger.Debug("Admin retrieved users by KYC status",
		util.String("status", status),
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetRecentlyActiveUsers gets users active since the given time
func (h *AdminHandler) GetRecentlyActiveUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Default to last 7 days
	days := h.getIntQueryParam(r, "days", 7)
	since := time.Now().AddDate(0, 0, -days)
	limit := h.getIntQueryParam(r, "limit", 100)

	users, err := h.userService.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get recently active users")
		return
	}

	// Sanitize users
	for _, u := range users {
		h.sanitizeUserForAdmin(u)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"since": since.Format(time.RFC3339),
			"days":  days,
			"count": len(users),
			"limit": limit,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Recently active users retrieved successfully"))

	h.logger.Debug("Recently active users retrieved",
		util.Int("days", days),
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== EXISTING ADMIN MANAGEMENT METHODS =====

// func (h *AdminHandler) ChangeOwnerPhone(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req struct {
// 		NewPhone string `json:"new_phone"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.NewPhone = strings.TrimSpace(req.NewPhone)
// 	if req.NewPhone == "" {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("new_phone required"), "New phone is required")
// 		return
// 	}

// 	if err := h.adminService.ChangeOwnerPhone(ctx, requesterID, req.NewPhone); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to change owner phone")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Owner phone updated successfully"))
// 	h.logger.Info("Owner phone changed via HTTP",
// 		util.String("admin_id", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// func (h *AdminHandler) InviteAdmin(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	requesterRole, err := h.getRequesterRole(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req struct {
// 		Phone     string `json:"phone"`
// 		RoleLevel string `json:"role_level"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.Phone = strings.TrimSpace(req.Phone)
// 	req.RoleLevel = strings.TrimSpace(strings.ToLower(req.RoleLevel))

// 	if req.Phone == "" || req.RoleLevel == "" {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("missing fields"), "Phone and role level are required")
// 		return
// 	}

// 	if !h.isValidRoleLevel(req.RoleLevel) {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
// 		return
// 	}

// 	admin, err := h.adminService.InviteAdmin(ctx, req.Phone, req.RoleLevel, requesterID, requesterRole)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to invite user as admin")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "User invited as admin successfully"))
// 	h.logger.Info("User invited as admin via HTTP",
// 		util.String("admin_id", admin.AdminID.String()),
// 		util.String("role_level", req.RoleLevel),
// 		util.String("invited_by", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	adminIDStr := chi.URLParam(r, "adminID")
// 	adminID, err := uuid.Parse(adminIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
// 		return
// 	}

// 	var req struct {
// 		NewRole string `json:"new_role"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.NewRole = strings.TrimSpace(strings.ToLower(req.NewRole))
// 	if !h.isValidRoleLevel(req.NewRole) {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
// 		return
// 	}

// 	if err := h.adminService.PromoteAdmin(ctx, adminID, req.NewRole, requesterID); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to promote admin")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin role updated successfully"))
// 	h.logger.Info("Admin promoted via HTTP",
// 		util.String("admin_id", adminID.String()),
// 		util.String("new_role", req.NewRole),
// 		util.String("promoted_by", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

func (h *AdminHandler) RemoveAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	if err := h.adminService.RemoveAdmin(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to remove admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin removed successfully"))
	h.logger.Info("Admin removed via HTTP",
		util.String("admin_id", adminID.String()),
		util.String("removed_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) DeactivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	if err := h.adminService.DeactivateAdmin(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to deactivate admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin deactivated successfully"))
	h.logger.Info("Admin deactivated via HTTP",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) ActivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	if err := h.adminService.ActivateAdmin(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to activate admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin activated successfully"))
	h.logger.Info("Admin activated via HTTP",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) UpdateAdminPermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	adminIDStr := chi.URLParam(r, "adminID")
// 	adminID, err := uuid.Parse(adminIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
// 		return
// 	}

// 	var req struct {
// 		Permissions []string `json:"permissions"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if len(req.Permissions) == 0 {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("empty permissions"), "Permissions list cannot be empty")
// 		return
// 	}

// 	if err := h.adminService.UpdateAdminPermissions(ctx, adminID, req.Permissions, requesterID); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to update permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin permissions updated successfully"))
// 	h.logger.Info("Admin permissions updated via HTTP",
// 		util.String("admin_id", adminID.String()),
// 		util.Strings("permissions", req.Permissions),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

func (h *AdminHandler) GetAdminByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = h.getRequesterAdminID(r)

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	admin, err := h.adminService.GetAdmin(ctx, adminID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin retrieved successfully"))
	h.logger.Debug("Admin retrieved via HTTP",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminByPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = h.getRequesterAdminID(r)

	phone := chi.URLParam(r, "phone")
	if phone == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("phone required"), "Phone is required")
		return
	}

	admin, err := h.adminService.GetAdminByPhone(ctx, phone)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin by phone")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin retrieved successfully"))
	h.logger.Debug("Admin retrieved by phone via HTTP",
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = h.getRequesterAdminID(r)

	limit := h.getIntQueryParam(r, "limit", 50)

	// Simple active admins list only
	admins, err := h.adminService.GetActiveAdmins(ctx, limit)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to list admins")
		return
	}

	if admins == nil {
		admins = []*models.AdminUser{}
	}

	response := successResponse(map[string]interface{}{
		"admins": admins,
		"count":  len(admins),
	}, "Admins retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Admins listed via HTTP",
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminsByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = h.getRequesterAdminID(r)

	status := chi.URLParam(r, "status") // "active" or "inactive"
	limit := h.getIntQueryParam(r, "limit", 50)

	var admins []*models.AdminUser
	var err error

	if status == "active" {
		admins, err = h.adminService.GetActiveAdmins(ctx, limit)
	} else if status == "inactive" {
		admins, err = h.adminService.GetInactiveAdmins(ctx, limit)
	} else {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid status"), "Status must be 'active' or 'inactive'")
		return
	}

	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admins by status")
		return
	}

	response := successResponse(map[string]interface{}{
		"admins": admins,
		"status": status,
		"count":  len(admins),
	}, "Admins retrieved by status")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Admins retrieved by status",
		util.String("status", status),
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	_, _ = h.getRequesterAdminID(r)

// 	roleLevel := strings.ToLower(chi.URLParam(r, "roleLevel"))
// 	if !h.isValidRoleLevel(roleLevel) {
// 		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
// 		return
// 	}

// 	admins, err := h.adminService.GetAdminsByRole(ctx, roleLevel)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get admins by role")
// 		return
// 	}

// 	if admins == nil {
// 		admins = []*models.AdminUser{}
// 	}

// 	response := successResponse(map[string]interface{}{
// 		"admins": admins,
// 		"role":   roleLevel,
// 		"count":  len(admins),
// 	}, "Admins retrieved successfully")

// 	h.respondWithJSON(w, http.StatusOK, response)
// 	h.logger.Debug("Admins retrieved by role via HTTP",
// 		util.String("role", roleLevel),
// 		util.Int("count", len(admins)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// InitializeOwner initializes the system owner (first admin)
func (h *AdminHandler) InitializeOwner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		Phone string `json:"phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.Phone = strings.TrimSpace(req.Phone)
	if req.Phone == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("phone required"), "Phone is required")
		return
	}

	owner, err := h.adminService.InitializeOwner(ctx, req.Phone)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to initialize owner")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(owner, "Owner initialized successfully"))
	h.logger.Info("Owner initialized via HTTP",
		util.String("admin_id", owner.AdminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== HEALTH & STATISTICS =====

func (h *AdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.adminService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err, "Admin service unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "admin",
	}, "Admin service is healthy"))
}

func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	stats, err := h.adminService.GetStats(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin statistics retrieved successfully"))
	h.logger.Debug("Admin stats retrieved via HTTP",
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== HELPER METHODS =====

func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
	h.logger.Debug("🔍 hasMPIN helper called", util.String("admin_id", adminID.String()))

	status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
	if err != nil {
		h.logger.Warn("❌ Error in hasMPIN helper",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()))
		return false
	}

	result := status != nil && status.Exists
	h.logger.Debug("📊 hasMPIN result",
		util.String("admin_id", adminID.String()),
		util.Bool("result", result))

	return result
}

// ✅ NEW: Helper method to check admin permissions
func (h *AdminHandler) hasPermission(r *http.Request, permission string) bool {
	permissions, ok := r.Context().Value("admin_permissions").([]string)
	if !ok {
		return false
	}
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// ✅ UPDATED: Enhanced error handling for OTP operations
func (h *AdminHandler) handleOTPError(w http.ResponseWriter, err error) {
	var otpErr *service.OTPError
	if errors.As(err, &otpErr) {
		switch otpErr.Code {
		case "RATE_LIMIT_EXCEEDED":
			h.respondWithError(w, http.StatusTooManyRequests, err, "Too many attempts. Please try again later.")
		case "DAILY_QUOTA_EXCEEDED":
			h.respondWithError(w, http.StatusTooManyRequests, err, "Daily OTP limit exceeded")
		case "ACCOUNT_LOCKED":
			h.respondWithError(w, http.StatusLocked, err, "Account temporarily locked")
		case "RESEND_COOLDOWN":
			h.respondWithError(w, http.StatusTooManyRequests, err, "Please wait before requesting a new OTP")
		case "REPLAY_ATTEMPT":
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid OTP")
		case "PHONE_NOT_REGISTERED":
			h.respondWithError(w, http.StatusNotFound, err, "Phone number not registered")
		default:
			h.respondWithError(w, http.StatusUnauthorized, err, "Authentication failed")
		}
	} else {
		h.respondWithError(w, http.StatusUnauthorized, err, "Authentication failed")
	}
}

func (h *AdminHandler) getIntQueryParam(r *http.Request, key string, defaultValue int) int {
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

func (h *AdminHandler) getBoolQueryParam(r *http.Request, key string, defaultValue bool) bool {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value) == "true"
}

func (h *AdminHandler) getStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}

	errMsg := err.Error()

	if strings.Contains(errMsg, "not found") {
		return http.StatusNotFound
	}
	if strings.Contains(errMsg, "already exists") || strings.Contains(errMsg, "already has an owner") {
		return http.StatusConflict
	}
	if strings.Contains(errMsg, "not registered") {
		return http.StatusBadRequest
	}
	if strings.Contains(errMsg, "unauthorized") || strings.Contains(errMsg, "permission") {
		return http.StatusForbidden
	}
	if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
		return http.StatusBadRequest
	}

	return http.StatusInternalServerError
}

func (h *AdminHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

func (h *AdminHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("Admin HTTP error response",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// func (h *AdminHandler) isValidRoleLevel(role string) bool {
// 	switch role {
// 	case models.AdminRoleLevelOwner:
// 		return true
// 	case models.AdminRoleLevelSuperEmployee:
// 		return true
// 	case models.AdminRoleLevelEmployee:
// 		return true
// 	default:
// 		return false
// 	}
// }

// func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
// 	userID, ok := r.Context().Value("user_id").(string)
// 	if !ok || userID == "" {
// 		return uuid.Nil, fmt.Errorf("user ID not found in request context")
// 	}

// 	adminID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return uuid.Nil, fmt.Errorf("invalid admin ID in request context")
// 	}

// 	return adminID, nil
// }

// func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
//     userID, ok := r.Context().Value("user_id").(string)
//     if !ok || userID == "" {
//         return uuid.Nil, fmt.Errorf("user ID not found in request context")
//     }

//     adminID, err := uuid.Parse(userID)
//     if err != nil {
//         return uuid.Nil, fmt.Errorf("invalid admin ID in request context")
//     }

//     return adminID, nil
// }

func (h *AdminHandler) getRequesterRole(r *http.Request) (string, error) {
	role, ok := r.Context().Value("admin_role_level").(string)
	if !ok || role == "" {
		return "", fmt.Errorf("admin role not found in request context")
	}
	return role, nil
}

// ✅ FIXED: Enhanced client IP extraction with robust validation
func (h *AdminHandler) getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// ✅ ENHANCED: Validate IP format with proper parsing
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

	// Try Forwarded header
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		if strings.Contains(forwarded, "for=") {
			parts := strings.Split(forwarded, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "for=") {
					ip := strings.TrimPrefix(part, "for=")
					ip = strings.Trim(ip, `"`)
					// Handle IPv6 addresses in brackets and ports
					if idx := strings.LastIndex(ip, ":"); idx != -1 {
						// Check if it's IPv6 with port
						if strings.Contains(ip, "]") {
							// IPv6 with port format: [::1]:8080
							if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx < idx {
								ip = ip[:bracketIdx+1]
							}
						} else if !strings.Contains(ip, ".") {
							// Likely IPv6 without brackets
							ip = ip
						} else {
							// IPv4 with port
							ip = ip[:idx]
						}
					}
					if parsedIP := net.ParseIP(ip); parsedIP != nil {
						return ip
					}
				}
			}
		}
	}

	// ✅ ENHANCED: Fallback to RemoteAddr with proper parsing and validation
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try to parse as IP directly
		if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
			return r.RemoteAddr
		}
		// ✅ FIX: Return empty string instead of invalid IP to prevent marshaling issues
		return ""
	}

	// ✅ ENHANCED: Final validation with safe fallback
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return host
	}

	// ✅ FIX: Return empty string for invalid IPs to prevent marshaling issues
	return ""
}

// sanitizeUserForAdmin removes sensitive fields before returning users to admin endpoints
func (h *AdminHandler) sanitizeUserForAdmin(u *models.User) {
	if u == nil {
		return
	}
	// Remove or zero sensitive fields
	u.PhoneEncrypted = nil
	u.PhoneKeyID = uuid.Nil
	u.PhoneEncryptedDEK = ""
	// Keep phone_hash and other non-sensitive fields for admin listing
}

// GetCompanyDepartments retrieves all departments for a company
func (h *AdminHandler) GetCompanyDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get user ID from context
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
			"Authentication required")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
		return
	}

	// Check session type first - admin has full access
	sessionType, _ := ctx.Value("session_type").(string)
	accessMethod := "none"

	if sessionType == "admin" {
		accessMethod = "admin"
		// Admin can access any company's departments
	} else {
		// For non-admin users, check if they belong to the company
		isEmployee, err := h.companyService.IsUserActiveEmployee(ctx, companyID, userID)
		if err != nil || !isEmployee {
			h.respondWithError(w, http.StatusForbidden,
				fmt.Errorf("ACCESS_DENIED: User is not an employee of this company"),
				"You don't have permission to view departments for this company")
			return
		}

		// Check if user has permission to view departments
		hasPermission, err := h.companyService.CheckPermissionFromContext(ctx, "administrative.department.view")
		if err != nil {
			h.logger.Warn("Permission check failed",
				util.String("user_id", userID.String()),
				util.String("company_id", companyID.String()),
				util.ErrorField(err))
		}

		if hasPermission {
			accessMethod = "permission"
		} else {
			// Check if user is company owner
			isOwner, err := h.isCompanyOwner(r, companyID)
			if err != nil {
				h.logger.Warn("Owner check failed",
					util.String("user_id", userID.String()),
					util.String("company_id", companyID.String()),
					util.ErrorField(err))
			} else if isOwner {
				accessMethod = "owner"
			} else {
				h.respondWithError(w, http.StatusForbidden,
					fmt.Errorf("ACCESS_DENIED: No permission to view company departments"),
					"You don't have permission to view departments for this company")
				return
			}
		}
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	departments, total, err := h.companyService.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company departments")
		return
	}

	response := map[string]interface{}{
		"departments": departments,
		"meta": map[string]interface{}{
			"company_id":    companyID.String(),
			"count":         len(departments),
			"total":         total,
			"limit":         limit,
			"offset":        offset,
			"access_method": accessMethod,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company departments retrieved successfully"))

	h.logger.Info("Company departments retrieved",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("access_method", accessMethod),
		util.Int("count", len(departments)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// Fix the helper method to check if user is company owner
func (h *AdminHandler) isCompanyOwner(r *http.Request, companyID uuid.UUID) (bool, error) {
	ctx := r.Context()

	// Get user ID from context
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return false, fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return false, fmt.Errorf("invalid user ID in context")
	}

	// Get company directly from repository to avoid permission issues
	company, err := h.companyService.GetCompany(ctx, companyID)
	if err != nil {
		return false, fmt.Errorf("company not found: %w", err)
	}

	return company.OwnerUserID == userID, nil
}

// Temporary debug endpoint - remove in production
func (h *AdminHandler) DebugCompanyDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	// Get all departments without pagination for debugging
	departments, total, err := h.companyService.GetDepartmentsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get departments")
		return
	}

	// Get company info
	company, err := h.companyService.GetCompany(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company")
		return
	}

	response := map[string]interface{}{
		"company": map[string]interface{}{
			"id":            company.CompanyID,
			"name":          company.CompanyName,
			"owner_user_id": company.OwnerUserID,
		},
		"departments": departments,
		"total_count": total,
		"debug_info": map[string]interface{}{
			"company_id":       companyID.String(),
			"department_count": len(departments),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Debug department info"))
}

// NEW: Admin override — admins always allowed
func (h *AdminHandler) hasAdminOrPermission(r *http.Request, permission string) bool {
	sessionType, _ := r.Context().Value("session_type").(string)
	if sessionType == "admin" {
		return true
	}
	return h.hasPermission(r, permission)
}

// ===== ADVANCED COMPANY SEARCH ENDPOINTS =====

// SearchCompanies searches companies with advanced text search
func (h *AdminHandler) SearchCompanies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("QUERY_REQUIRED"), "Search query is required")
		return
	}

	// Parse pagination
	limit := h.getIntQueryParam(r, "limit", 20)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Parse search type
	searchType := r.URL.Query().Get("search_type")
	if searchType == "" {
		searchType = "all" // auto-detect based on query length
	}

	// Parse sort parameters
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "relevance"
	}
	sortOrder := r.URL.Query().Get("sort_order")
	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Parse filters
	var filters *models.CompanySearchFilters
	tier := r.URL.Query().Get("tier")
	status := r.URL.Query().Get("status")
	region := r.URL.Query().Get("region")

	if tier != "" || status != "" || region != "" {
		filters = &models.CompanySearchFilters{
			SubscriptionTier:   tier,
			SubscriptionStatus: status,
			DataRegion:        region,
		}
	}

	// Build search request
	searchReq := &service.SearchCompaniesRequest{
		Query:      query,
		SearchType: searchType,
		Filters:    filters,
		Limit:      limit,
		Offset:     offset,
		SortBy:     sortBy,
		SortOrder:  sortOrder,
	}

	// Execute search
	searchResp, err := h.companyService.SearchCompanies(ctx, searchReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search companies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Company search completed"))

	h.logger.Info("Company search executed by admin",
		util.String("admin_id", adminID.String()),
		util.String("query", query),
		util.String("search_type", searchType),
		util.Int("results", len(searchResp.Companies)),
		util.Int("total", searchResp.Total),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SearchCompaniesByOwner searches companies owned by a specific user
func (h *AdminHandler) SearchCompaniesByOwner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse owner ID from URL
	ownerIDStr := chi.URLParam(r, "ownerID")
	ownerID, err := uuid.Parse(ownerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid owner ID")
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("QUERY_REQUIRED"), "Search query is required")
		return
	}

	// Parse pagination
	limit := h.getIntQueryParam(r, "limit", 20)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Parse optional active filter
	var isActive *bool
	if activeParam := r.URL.Query().Get("active"); activeParam != "" {
		active := activeParam == "true"
		isActive = &active
	}

	// Execute search
	searchResp, err := h.companyService.SearchCompaniesByOwner(ctx, ownerID, query, isActive, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search owner companies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Owner company search completed"))

	h.logger.Info("Owner company search executed by admin",
		util.String("admin_id", adminID.String()),
		util.String("owner_id", ownerID.String()),
		util.String("query", query),
		util.Int("results", len(searchResp.Companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanySuggestions provides autocomplete suggestions for company names
func (h *AdminHandler) GetCompanySuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse prefix from query
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("PREFIX_REQUIRED"), "Prefix is required for suggestions")
		return
	}

	// Parse limit
	limit := h.getIntQueryParam(r, "limit", 10)

	// Get suggestions
	suggestions, err := h.companyService.GetCompanySuggestions(ctx, prefix, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get suggestions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Company suggestions retrieved"))

	h.logger.Debug("Company suggestions retrieved by admin",
		util.String("admin_id", adminID.String()),
		util.String("prefix", prefix),
		util.Int("suggestions", len(suggestions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanySearchAnalytics gets analytics about company search performance
func (h *AdminHandler) GetCompanySearchAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Get search analytics
	analytics, err := h.companyService.GetCompanySearchAnalytics(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get search analytics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(analytics, "Company search analytics retrieved"))

	h.logger.Info("Company search analytics retrieved by admin",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// BenchmarkCompanySearch benchmarks search performance
func (h *AdminHandler) BenchmarkCompanySearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	var req struct {
		TestQueries []string `json:"test_queries"`
		Iterations  int      `json:"iterations" validate:"min=1,max=100"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Default queries if not provided
	if len(req.TestQueries) == 0 {
		req.TestQueries = []string{
			"tech",
			"solution",
			"enterprise",
			"global",
			"innov",
			"corp",
			"group",
			"limited",
		}
	}

	if req.Iterations == 0 {
		req.Iterations = 10
	}

	// Run benchmark
	results, err := h.companyService.BenchmarkCompanySearch(ctx, req.TestQueries, req.Iterations)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to run search benchmark")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Search benchmark completed"))

	h.logger.Info("Company search benchmark executed by admin",
		util.String("admin_id", adminID.String()),
		util.Int("test_queries", len(req.TestQueries)),
		util.Int("iterations", req.Iterations),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetUserSuggestions provides autocomplete suggestions for usernames and full names
func (h *AdminHandler) GetUserSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse prefix from query
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("PREFIX_REQUIRED"), "Prefix is required for suggestions")
		return
	}

	// Parse limit
	limit := h.getIntQueryParam(r, "limit", 10)

	// Get suggestions
	suggestions, err := h.userService.GetUserSuggestions(ctx, prefix, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user suggestions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "User suggestions retrieved"))

	h.logger.Debug("User suggestions retrieved by admin",
		util.String("admin_id", adminID.String()),
		util.String("prefix", prefix),
		util.Int("suggestions", len(suggestions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SearchUsersAdvanced searches users with advanced filters
func (h *AdminHandler) SearchUsersAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse query parameters for filters
	filters := make(map[string]interface{})

	if username := r.URL.Query().Get("username"); username != "" {
		filters["username"] = username
	}
	if fullName := r.URL.Query().Get("full_name"); fullName != "" {
		filters["full_name"] = fullName
	}
	if phoneHash := r.URL.Query().Get("phone_hash"); phoneHash != "" {
		filters["phone_hash"] = phoneHash
	}
	if kycStatus := r.URL.Query().Get("kyc_status"); kycStatus != "" {
		filters["kyc_status"] = kycStatus
	}
	if dataRegion := r.URL.Query().Get("data_region"); dataRegion != "" {
		filters["data_region"] = dataRegion
	}
	if isVerified := r.URL.Query().Get("is_verified"); isVerified != "" {
		filters["is_verified"] = isVerified == "true"
	}
	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		filters["is_active"] = isActive == "true"
	}
	if deviceID := r.URL.Query().Get("device_id"); deviceID != "" {
		filters["device_id"] = deviceID
	}
	if deviceFingerprint := r.URL.Query().Get("device_fingerprint"); deviceFingerprint != "" {
		filters["device_fingerprint"] = deviceFingerprint
	}

	// Parse pagination
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Execute advanced search
	users, total, err := h.userService.SearchUsersAdvanced(ctx, filters, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users with advanced filters")
		return
	}

	// Sanitize users before returning
	for _, user := range users {
		h.sanitizeUserForAdmin(user)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"count":   len(users),
			"total":   total,
			"limit":   limit,
			"offset":  offset,
			"filters": filters,
			"has_more": offset+limit < total,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Advanced user search completed"))

	h.logger.Info("Advanced user search executed by admin",
		util.String("admin_id", adminID.String()),
		util.Any("filters", filters),
		util.Int("results", len(users)),
		util.Int("total", total),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SearchUsersByUsername searches users by username (partial match)
func (h *AdminHandler) SearchUsersByUsername(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse username from query
	username := r.URL.Query().Get("username")
	if username == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("USERNAME_REQUIRED"), "Username is required")
		return
	}

	// Parse limit
	limit := h.getIntQueryParam(r, "limit", 20)

	// Search by username
	users, err := h.userService.SearchUsersByUsername(ctx, username, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users by username")
		return
	}

	// Sanitize users before returning
	for _, user := range users {
		h.sanitizeUserForAdmin(user)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"username":    username,
			"count":       len(users),
			"limit":       limit,
			"search_type": "partial_match",
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Username search completed"))

	h.logger.Info("Username search executed by admin",
		util.String("admin_id", adminID.String()),
		util.String("username", username),
		util.Int("results", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SearchUsersByFullName searches users by full name (partial match)
func (h *AdminHandler) SearchUsersByFullName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse full name from query
	fullName := r.URL.Query().Get("full_name")
	if fullName == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("FULL_NAME_REQUIRED"), "Full name is required")
		return
	}

	// Parse limit
	limit := h.getIntQueryParam(r, "limit", 20)

	// Search by full name
	users, err := h.userService.SearchUsersByFullName(ctx, fullName, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users by full name")
		return
	}

	// Sanitize users before returning
	for _, user := range users {
		h.sanitizeUserForAdmin(user)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"full_name":   fullName,
			"count":       len(users),
			"limit":       limit,
			"search_type": "partial_match",
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Full name search completed"))

	h.logger.Info("Full name search executed by admin",
		util.String("admin_id", adminID.String()),
		util.String("full_name", fullName),
		util.Int("results", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateUser updates user information (username, full_name, etc.) - ADMIN ONLY
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	var req struct {
		Username          *string `json:"username,omitempty" validate:"omitempty,min=3,max=100,alphanum"`
		FullName          *string `json:"full_name,omitempty" validate:"omitempty,max=255"`
		DeviceID          *string `json:"device_id,omitempty"`
		DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
		DataRegion        *string `json:"data_region,omitempty" validate:"omitempty,oneof=us eu as"`
		IsVerified        *bool   `json:"is_verified,omitempty"`
		IsActive          *bool   `json:"is_active,omitempty"`
		KYCStatus         *string `json:"kyc_status,omitempty" validate:"omitempty,oneof=pending verified rejected under_review expired"`
		KYCLevel          *string `json:"kyc_level,omitempty" validate:"omitempty,oneof=basic advanced full"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Convert to service request
	updateReq := &service.UserUpdateRequest{
		Username:          req.Username,
		FullName:          req.FullName,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		DataRegion:        req.DataRegion,
		IsVerified:        req.IsVerified,
		IsActive:          req.IsActive,
		KYCStatus:         req.KYCStatus,
		KYCLevel:          req.KYCLevel,
	}

	// Call service to update user
	user, err := h.userService.UpdateUser(ctx, userID, updateReq)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already taken") {
			statusCode = http.StatusConflict
		} else if strings.Contains(err.Error(), "invalid") {
			statusCode = http.StatusBadRequest
		}
		h.respondWithError(w, statusCode, err, "Failed to update user")
		return
	}

	// Sanitize sensitive data
	h.sanitizeUserForAdmin(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))

	h.logger.Info("User updated by admin",
		util.String("admin_id", adminID.String()),
		util.String("user_id", userID.String()),
		util.Any("updates", req),
		util.Duration("duration", time.Since(startTime)),
	)
}


// GetBannedUsers returns users with is_active = false
func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
        return
    }

    // Parse pagination
    limit := h.getIntQueryParam(r, "limit", 100)
    offset := h.getIntQueryParam(r, "offset", 0)

    // Get banned users
    users, total, err := h.userService.GetBannedUsers(ctx, limit, offset)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
        return
    }

    // Sanitize sensitive data before returning
    sanitizedUsers := make([]map[string]interface{}, len(users))
    for i, user := range users {
        sanitizedUsers[i] = map[string]interface{}{
            "user_id":           user.UserID,
            "username":          user.Username,
            "full_name":         user.FullName,
            "phone_hash":        user.PhoneHash,
            "kyc_status":        user.KYCStatus,
            "kyc_level":         user.KYCLevel,
            "is_verified":       user.IsVerified,
            "is_active":         user.IsActive,
            "data_region":       user.DataRegion,
            "created_at":        user.CreatedAt,
            "updated_at":        user.UpdatedAt,
            "last_login":        user.LastLogin,
            "device_id":         user.DeviceID,
            "device_fingerprint": user.DeviceFingerprint,
        }
    }

    response := map[string]interface{}{
        "users": sanitizedUsers,
        "meta": map[string]interface{}{
            "count":    len(sanitizedUsers),
            "total":    total,
            "limit":    limit,
            "offset":   offset,
            "has_more": offset+limit < total,
        },
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Banned users retrieved successfully"))

    h.logger.Info("Banned users retrieved by admin",
        util.String("admin_id", adminID.String()),
        util.Int("count", len(users)),
        util.Int("total", total),
        util.Duration("duration", time.Since(startTime)))
}

// ===== CHANGES NEEDED IN ADMIN HANDLER =====

// REMOVE THESE OLD METHODS (using role strings):
// func (h *AdminHandler) ChangeOwnerPhone(w http.ResponseWriter, r *http.Request)
// func (h *AdminHandler) InviteAdmin(w http.ResponseWriter, r *http.Request) - old version
// func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request) - old version
// func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) - old version

// ADD/UPDATE THESE METHODS WITH BITMASK:

// // ChangeAdminPhone changes admin phone with hierarchy checks
// func (h *AdminHandler) ChangeAdminPhone(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req struct {
//         TargetAdminID string `json:"target_admin_id" validate:"required"`
//         NewPhone      string `json:"new_phone" validate:"required,phone"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     targetAdminID, err := uuid.Parse(req.TargetAdminID)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid target admin ID")
//         return
//     }

//     if err := h.adminService.ChangeAdminPhone(ctx, targetAdminID, req.NewPhone, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to change admin phone")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin phone updated successfully"))
//     h.logger.Info("Admin phone changed via HTTP",
//         util.String("requester_id", requesterID.String()),
//         util.String("target_admin_id", targetAdminID.String()),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// // ChangeOwnPhone allows admin to change their own phone
// func (h *AdminHandler) ChangeOwnPhone(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req struct {
//         NewPhone string `json:"new_phone" validate:"required,phone"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Use the same service method but target self
//     if err := h.adminService.ChangeAdminPhone(ctx, requesterID, req.NewPhone, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to change phone")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Phone updated successfully"))
//     h.logger.Info("Admin changed own phone via HTTP",
//         util.String("admin_id", requesterID.String()),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// InviteAdminWithBitmask invites admin using bitmask
func (h *AdminHandler) InviteAdminWithBitmask(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    var req struct {
        Phone    string `json:"phone" validate:"required,phone"`
        RoleMask uint64 `json:"role_mask" validate:"required"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    admin, err := h.adminService.InviteAdmin(ctx, req.Phone, req.RoleMask, requesterID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invite admin")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "Admin invited successfully"))
    h.logger.Info("Admin invited via HTTP (bitmask)",
        util.String("admin_id", admin.AdminID.String()),
        util.Uint64("role_mask", req.RoleMask),
        util.String("invited_by", requesterID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

// // GetAdminsByRoleMask retrieves admins by role mask
// func (h *AdminHandler) GetAdminsByRoleMask(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     roleMaskStr := chi.URLParam(r, "roleMask")
//     roleMask, err := strconv.ParseUint(roleMaskStr, 10, 64)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role mask")
//         return
//     }

//     admins, err := h.adminService.GetAdminsByRole(ctx, roleMask)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to get admins by role")
//         return
//     }

//     response := successResponse(map[string]interface{}{
//         "admins": admins,
//         "role_mask": roleMask,
//         "count": len(admins),
//     }, "Admins retrieved by role mask")

//     h.respondWithJSON(w, http.StatusOK, response)
//     h.logger.Debug("Admins retrieved by role mask via HTTP",
//         util.String("requester_id", requesterID.String()),
//         util.Uint64("role_mask", roleMask),
//         util.Int("count", len(admins)),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// // GetAdminsByRoleMask retrieves admins by role mask
// func (h *AdminHandler) GetAdminsByRoleMask(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     // FIX: Change "roleMask" to "roleLevel" to match the route parameter
//     roleMaskStr := chi.URLParam(r, "roleLevel")  // Changed from "roleMask"
//     if roleMaskStr == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("role level is required"), "Role level is required")
//         return
//     }

//     roleMask, err := strconv.ParseUint(roleMaskStr, 10, 64)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid role mask")
//         return
//     }

//     admins, err := h.adminService.GetAdminsByRole(ctx, roleMask)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to get admins by role")
//         return
//     }

//     response := successResponse(map[string]interface{}{
//         "admins": admins,
//         "role_mask": roleMask,
//         "count": len(admins),
//     }, "Admins retrieved by role mask")

//     h.respondWithJSON(w, http.StatusOK, response)
//     h.logger.Debug("Admins retrieved by role mask via HTTP",
//         util.String("requester_id", requesterID.String()),
//         util.Uint64("role_mask", roleMask),
//         util.Int("count", len(admins)),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }
// ===== PERMISSION MANAGEMENT HANDLERS =====




// GetAdminPermissions retrieves all permissions for an admin
func (h *AdminHandler) GetAdminPermissions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    permissions, err := h.adminService.GetAdminPermissions(ctx, adminID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admin permissions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "permissions": permissions,
        "count": len(permissions),
    }, "Admin permissions retrieved successfully"))
    
    h.logger.Debug("Admin permissions retrieved",
        util.String("admin_id", adminID.String()),
        util.Int("permission_count", len(permissions)),
        util.Duration("duration", time.Since(startTime)),
    )
}


// GetAdminPermissionMask retrieves raw permission mask
func (h *AdminHandler) GetAdminPermissionMask(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    permissionMask, err := h.adminService.GetAdminPermissionMask(ctx, adminID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get permission mask")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "permission_mask": permissionMask,
        "segments": len(permissionMask),
        "total_bits": len(permissionMask) * 64,
    }, "Admin permission mask retrieved successfully"))
    
    h.logger.Debug("Admin permission mask retrieved",
        util.String("admin_id", adminID.String()),
        util.Int("segments", len(permissionMask)),
        util.Duration("duration", time.Since(startTime)),
    )
}

// Helper function to check if requester is admin (from context)
func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
    userID, ok := r.Context().Value("user_id").(string)
    if !ok || userID == "" {
        return uuid.Nil, fmt.Errorf("user ID not found in request context")
    }

    // For admin sessions, user_id is admin_id
    adminID, err := uuid.Parse(userID)
    if err != nil {
        return uuid.Nil, fmt.Errorf("invalid admin ID in request context")
    }

    return adminID, nil
}

// Helper to get admin role mask from context (if needed)
func (h *AdminHandler) getRequesterAdminRoleMask(r *http.Request) (uint64, error) {
    // Try to get from JWT token context first (most reliable)
    if roleMask, ok := r.Context().Value("admin_role_mask").(uint64); ok && roleMask != 0 {
        return roleMask, nil
    }
    
    // If not in context, try to get from the session token
    authHeader := r.Header.Get("Authorization")
    if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
        token := strings.TrimPrefix(authHeader, "Bearer ")
        
        // Parse token without validation to check claims
        parser := jwt.NewParser()
        claims := &models.JWTClaims{}
        _, _, err := parser.ParseUnverified(token, claims)
        
        if err == nil && claims.AdminRoleMask != 0 {
            h.logger.Debug("Extracted admin role mask from unverified token",
                util.Uint64("admin_role_mask", claims.AdminRoleMask))
            return claims.AdminRoleMask, nil
        }
    }
    
    // Fallback: get admin from database
    adminID, err := h.getRequesterAdminID(r)
    if err != nil {
        return 0, fmt.Errorf("failed to get admin ID: %w", err)
    }
    
    ctx := r.Context()
    admin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        return 0, fmt.Errorf("failed to get admin: %w", err)
    }
    
    return admin.AdminRoleMask, nil
}
// GetAdminsByRole - legacy compatibility method
func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    roleLevel := chi.URLParam(r, "roleLevel")
    
    // Convert legacy role string to role mask
    var roleMask uint64
    switch roleLevel {
    case "owner":
        roleMask = models.RoleMaskOwner
    case "super_employee":
        roleMask = models.RoleMaskSuperEmployee
    case "employee":
        roleMask = models.RoleMaskEmployee
    default:
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("invalid role"), "Invalid role level")
        return
    }

    admins, err := h.adminService.GetAdminsByRole(ctx, roleMask)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admins by role")
        return
    }

    response := successResponse(map[string]interface{}{
        "admins": admins,
        "role":   roleLevel,
        "count":  len(admins),
    }, "Admins retrieved successfully")

    h.respondWithJSON(w, http.StatusOK, response)
    h.logger.Debug("Admins retrieved by role via HTTP",
        util.String("requester_id", requesterID.String()),
        util.String("role", roleLevel),
        util.Int("count", len(admins)),
        util.Duration("duration", time.Since(startTime)),
    )
}


// ===== ENHANCED ADMIN MANAGEMENT WITH DEPARTMENT BITMASK =====

// // InviteAdminWithDepartments invites admin with specific departments and permissions
// func (h *AdminHandler) InviteAdminWithDepartments(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req struct {
//         Phone           string   `json:"phone" validate:"required,phone"`
//         RoleMask        uint64   `json:"role_mask" validate:"required"`
//         Departments     []string `json:"departments" validate:"required,min=1"`
//         Permissions     []string `json:"permissions,omitempty"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Validate role mask
//     if !h.isValidRoleMask(req.RoleMask) {
//         h.respondWithError(w, http.StatusBadRequest, 
//             fmt.Errorf("invalid role mask"), "Invalid role mask provided")
//         return
//     }

//     // Check if requester has permission to invite admin
//     if !h.hasAdminPermission(r, "admin.user.create") {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("PERMISSION_DENIED"),
//             "You don't have permission to invite admins")
//         return
//     }

//     // Get system departments to validate
//     systemDepts, err := h.companyService.GetSystemDepartments(ctx)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, 
//             "Failed to validate departments")
//         return
//     }

//     // Validate requested departments exist in system
//     validDeptNames := make([]string, 0)
//     for _, deptName := range req.Departments {
//         found := false
//         for _, sysDept := range systemDepts {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 validDeptNames = append(validDeptNames, deptName)
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             h.logger.Warn("Invalid department name requested",
//                 util.String("department", deptName))
//         }
//     }

//     if len(validDeptNames) == 0 {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("no valid departments provided"),
//             "No valid departments found. Please check department names")
//         return
//     }

//     // Check if requester has access to requested departments
//     requester, err := h.adminService.GetAdmin(ctx, requesterID)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, 
//             "Failed to validate requester permissions")
//         return
//     }

//     if !requester.IsOwner() {
//         for _, deptName := range validDeptNames {
//             hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, requesterID, deptName)
//             if err != nil || !hasAccess {
//                 h.respondWithError(w, http.StatusForbidden,
//                     fmt.Errorf("permission denied for department: %s", deptName),
//                     "You don't have access to all requested departments")
//                 return
//             }
//         }
//     }

//     // Check if requester has requested permissions (for admin permissions)
//     for _, permName := range req.Permissions {
//         if strings.HasPrefix(permName, "admin.") {
//             if !requester.HasPermission(permName) {
//                 h.respondWithError(w, http.StatusForbidden,
//                     fmt.Errorf("permission denied: %s", permName),
//                     "You don't have permission to grant: "+permName)
//                 return
//             }
//         }
//     }

//     // Call service to invite admin
//     admin, err := h.adminService.InviteAdminWithDepartments(
//         ctx, 
//         req.Phone, 
//         req.RoleMask, 
//         validDeptNames, 
//         req.Permissions, 
//         requesterID,
//     )
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to invite admin")
//         return
//     }

//     // Get accessible departments and permissions for response
//     accessibleDepartments := admin.GetAccessibleDepartments()
//     permissionNames := admin.GetPermissionNames()

//     h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
//         "admin": admin,
//         "accessible_departments": accessibleDepartments,
//         "permissions": permissionNames,
//         "message": "Admin invited successfully with department access",
//     }, "Admin invited successfully"))

//     h.logger.Info("Admin invited with departments",
//         util.String("admin_id", admin.AdminID.String()),
//         util.Uint64("role_mask", req.RoleMask),
//         util.Strings("departments", validDeptNames),
//         util.Strings("permissions", req.Permissions),
//         util.String("invited_by", requesterID.String()),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// UpdateAdminDepartments updates admin's accessible departments
func (h *AdminHandler) UpdateAdminDepartments(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    var req struct {
        Departments []string `json:"departments" validate:"required,min=1"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Check if requester has permission
    if !h.hasAdminPermission(r, "admin.department.update") {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "You don't have permission to update admin departments")
        return
    }

    // Get target admin
    targetAdmin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Admin not found")
        return
    }

    // Check hierarchy - can't modify owner or same/higher level
    requester, err := h.adminService.GetAdmin(ctx, requesterID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, 
            "Failed to validate requester")
        return
    }

    if !requester.CanManageEmployee(targetAdmin.AdminRoleMask) {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("HIERARCHY_VIOLATION"),
            "You cannot modify departments for this admin")
        return
    }

    // Get system departments to validate
    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, 
            "Failed to validate departments")
        return
    }

    // Validate requested departments exist in system
    validDeptNames := make([]string, 0)
    for _, deptName := range req.Departments {
        found := false
        for _, sysDept := range systemDepts {
            if strings.EqualFold(sysDept.Name, deptName) {
                validDeptNames = append(validDeptNames, deptName)
                found = true
                break
            }
        }
        if !found {
            h.logger.Warn("Invalid department name requested",
                util.String("department", deptName))
        }
    }

    if len(validDeptNames) == 0 {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("no valid departments provided"),
            "No valid departments found. Please check department names")
        return
    }

    // Check if requester has access to requested departments
    if !requester.IsOwner() {
        for _, deptName := range validDeptNames {
            hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, requesterID, deptName)
            if err != nil || !hasAccess {
                h.respondWithError(w, http.StatusForbidden,
                    fmt.Errorf("permission denied for department: %s", deptName),
                    "You don't have access to all requested departments")
                return
            }
        }
    }

    // Update admin departments
    err = h.adminService.UpdateAdminDepartments(ctx, adminID, validDeptNames, requesterID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to update admin departments")
        return
    }

    // Get updated admin details
    admin, depts, perms, err := h.adminService.GetAdminWithDetails(ctx, adminID)
    if err != nil {
        h.logger.Warn("Failed to get updated admin details", util.ErrorField(err))
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "admin": admin,
        "accessible_departments": depts,
        "permissions": perms,
        "message": "Admin departments updated successfully",
    }, "Admin departments updated"))

    h.logger.Info("Admin departments updated",
        util.String("admin_id", adminID.String()),
        util.Strings("new_departments", validDeptNames),
        util.String("updated_by", requesterID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

// GetAdminWithDetails retrieves admin details including accessible departments
func (h *AdminHandler) GetAdminWithDetails(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    admin, depts, perms, err := h.adminService.GetAdminWithDetails(ctx, adminID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admin details")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "admin": admin,
        "accessible_departments": depts,
        "permissions": perms,
        "department_bitmask": admin.DepartmentBitmask,
        "role_mask": admin.AdminRoleMask,
        "permission_mask": admin.AdminPermissionMask,
    }, "Admin details retrieved successfully"))

    h.logger.Debug("Admin details retrieved with departments",
        util.String("admin_id", adminID.String()),
        util.Int("department_count", len(depts)),
        util.Int("permission_count", len(perms)),
        util.Duration("duration", time.Since(startTime)),
    )
}

// CheckAdminDepartmentAccess checks if admin has access to specific department
func (h *AdminHandler) CheckAdminDepartmentAccess(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    departmentName := r.URL.Query().Get("department")
    if departmentName == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("department parameter required"), 
            "Department name is required")
        return
    }

    hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, adminID, departmentName)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to check department access")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "has_access": hasAccess,
        "department": departmentName,
        "admin_id": adminID.String(),
    }, "Department access check completed"))

    h.logger.Debug("Admin department access checked",
        util.String("admin_id", adminID.String()),
        util.String("department", departmentName),
        util.Bool("has_access", hasAccess),
        util.Duration("duration", time.Since(startTime)),
    )
}

// GetAdminsByDepartment retrieves admins who have access to specific department
func (h *AdminHandler) GetAdminsByDepartment(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    departmentName := chi.URLParam(r, "departmentName")
    if departmentName == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("department name required"), 
            "Department name is required")
        return
    }

    // Get all admins and filter by department access
    limit := h.getIntQueryParam(r, "limit", 50)
    allAdmins, err := h.adminService.GetActiveAdmins(ctx, 1000) // Get large batch
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admins")
        return
    }

    // Filter admins by department access
    var filteredAdmins []*models.AdminUser
    for _, admin := range allAdmins {
        hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, admin.AdminID, departmentName)
        if err == nil && hasAccess {
            filteredAdmins = append(filteredAdmins, admin)
            if len(filteredAdmins) >= limit {
                break
            }
        }
    }

    // Get detailed information for each admin
    var result []map[string]interface{}
    for _, admin := range filteredAdmins {
        _, depts, perms, _ := h.adminService.GetAdminWithDetails(ctx, admin.AdminID)
        
        result = append(result, map[string]interface{}{
            "admin_id":                admin.AdminID.String(),
            "role_mask":               admin.AdminRoleMask,
            "role_string":             admin.GetRoleString(),
            "accessible_departments":  depts,
            "permissions":             perms,
            "department_bitmask":      admin.DepartmentBitmask,
            "is_active":               admin.IsActive,
            "created_at":              admin.AdminCreatedAt,
        })
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "admins": result,
        "department": departmentName,
        "count": len(result),
        "total_checked": len(allAdmins),
    }, "Admins by department retrieved successfully"))

    h.logger.Debug("Admins retrieved by department",
        util.String("department", departmentName),
        util.Int("result_count", len(result)),
        util.Duration("duration", time.Since(startTime)),
    )
}

// ===== HELPER METHODS =====

// isValidRoleMask validates role mask value
func (h *AdminHandler) isValidRoleMask(roleMask uint64) bool {
    // Valid role masks: Owner (1), SuperEmployee (2), Employee (4)
    validMasks := map[uint64]bool{
        models.RoleMaskOwner: true,
        models.RoleMaskSuperEmployee: true,
        models.RoleMaskEmployee: true,
    }
    return validMasks[roleMask]
}

// hasAdminPermission checks if requester has specific admin permission
func (h *AdminHandler) hasAdminPermission(r *http.Request, permission string) bool {
    sessionType, _ := r.Context().Value("session_type").(string)
    if sessionType != "admin" {
        return false
    }
    
    // Get permission mask from context
    permMask, ok := r.Context().Value("permission_mask").([]uint64)
    if !ok {
        return false
    }
    
    // Check permission bit
    bitIndex, exists := models.AdminPermissionBitIndices[permission]
    if !exists {
        return false
    }
    
    return models.HasPermission(permMask, bitIndex)
}

// ===== SYSTEM DEPARTMENT BITMASK UTILITIES =====

// GetSystemDepartmentsWithBitmask returns system departments with their bitmask values
func (h *AdminHandler) GetSystemDepartmentsWithBitmask(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
        return
    }

    // Format response with bitmask details
    var result []map[string]interface{}
    for _, dept := range systemDepts {
        result = append(result, map[string]interface{}{
			"department_id": dept.SystemDepartmentID.String(),
            "name":           dept.Name,
            "module_code":    dept.ModuleCode,
            "description":    dept.Description,
            "bitmask":        dept.Bitmask,
            "bitmask_hex":    fmt.Sprintf("0x%X", dept.Bitmask),
			"bit_position": bits.TrailingZeros64(dept.Bitmask),
        })
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "departments": result,
        "total_count": len(result),
        "max_departments": 16,
        "bitmask_range": "0-15 (16 bits)",
        "all_departments_bitmask": models.DeptBitmaskAll,
        "all_departments_bitmask_hex": fmt.Sprintf("0x%X", models.DeptBitmaskAll),
    }, "System departments with bitmask retrieved"))

    h.logger.Debug("System departments with bitmask retrieved",
        util.Int("count", len(result)),
        util.Duration("duration", time.Since(startTime)),
    )
}

// Helper function to convert department names to bitmask
func (h *AdminHandler) convertDepartmentNamesToBitmask(ctx context.Context, departmentNames []string) (uint64, error) {
    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        return 0, fmt.Errorf("failed to get system departments: %w", err)
    }
    
    var bitmask uint64
    for _, deptName := range departmentNames {
        found := false
        for _, sysDept := range systemDepts {
            if strings.EqualFold(sysDept.Name, deptName) {
                bitmask |= sysDept.Bitmask
                found = true
                break
            }
        }
        if !found {
            return bitmask, fmt.Errorf("invalid department: %s", deptName)
        }
    }
    return bitmask, nil
}

// Helper function to get department names from bitmask
func (h *AdminHandler) getDepartmentNamesFromBitmask(ctx context.Context, bitmask uint64) ([]string, error) {
    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get system departments: %w", err)
    }
    
    var departments []string
    for _, sysDept := range systemDepts {
        if bitmask&sysDept.Bitmask != 0 {
            departments = append(departments, sysDept.Name)
        }
    }
    return departments, nil
}

// Check if admin can manage another admin based on role hierarchy
func (h *AdminHandler) canManageAdmin(requester, target *models.AdminUser) bool {
    // Owner can manage everyone
    if requester.IsOwner() {
        return true
    }
    
    // Super employee can manage employees
    if requester.IsSuperEmployee() && target.IsEmployee() {
        return true
    }
    
    // Employee cannot manage anyone
    return false
}


func (h *AdminHandler) DebugPermissionCalculation(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    // Test with HR and Finance departments
    departmentNames := []string{"HR", "Finance"}
    permissionNames := []string{"admin.user.view", "admin.department.view"}
    
    // Get system departments
    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
        return
    }
    
    // Calculate bitmask
    var deptBitmask uint64
    accessibleModules := make(map[string]bool)
    
    for _, deptName := range departmentNames {
        for _, sysDept := range systemDepts {
            if strings.EqualFold(sysDept.Name, deptName) {
                deptBitmask |= sysDept.Bitmask
                accessibleModules[sysDept.ModuleCode] = true
                break
            }
        }
    }
    
    // Get permissions for modules
    var modulePermissions []string
    for module := range accessibleModules {
        perms, err := h.companyService.GetPermissionsByModule(ctx, module)
        if err == nil {
            for _, perm := range perms {
                modulePermissions = append(modulePermissions, perm.PermissionName)
            }
        }
    }
    
    // Build final permission mask
    permissionMask := make([]uint64, 4)
    allPermissions := append(modulePermissions, permissionNames...)
    
    for _, permName := range allPermissions {
        if bitIndex, exists := models.AdminPermissionBitIndices[permName]; exists {
            permissionMask = models.SetPermission(permissionMask, bitIndex, true)
        }
    }
    
    h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
        "department_names": departmentNames,
        "department_bitmask": deptBitmask,
        "accessible_modules": accessibleModules,
        "module_permissions": modulePermissions,
        "admin_permissions": permissionNames,
        "all_permissions": allPermissions,
        "permission_mask": permissionMask,
        "permission_mask_debug": fmt.Sprintf("%v", permissionMask),
        "permission_names": allPermissions,
    })
}


func (h *AdminHandler) ChangeAdminPhone(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    // Get requester role mask from JWT token context
    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.logger.Warn("Failed to get admin role mask from token",
            util.String("admin_id", requesterID.String()),
            util.ErrorField(err))
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    // Verify role mask is 1 (owner) from the token
    if requesterRoleMask != models.RoleMaskOwner {
        h.logger.Warn("Non-owner attempting to change admin phone",
            util.String("admin_id", requesterID.String()),
            util.Uint64("role_mask", requesterRoleMask))
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can change admin phone numbers")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    var req struct {
        NewPhone string `json:"new_phone" validate:"required,phone"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Verify token has admin session type
    sessionType, _ := ctx.Value("session_type").(string)
    if sessionType != "admin" {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("INVALID_SESSION_TYPE"),
            "Admin session required")
        return
    }

    if err := h.adminService.ChangeAdminPhone(ctx, adminID, req.NewPhone, requesterID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to change admin phone")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin phone updated successfully"))
    h.logger.Info("Admin phone changed by owner via HTTP",
        util.String("requester_id", requesterID.String()),
        util.String("target_admin_id", adminID.String()),
        util.Uint64("requester_role_mask", requesterRoleMask),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) ChangeOwnPhone(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    // Get requester role mask from JWT token context
    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.logger.Warn("Failed to get admin role mask from token",
            util.String("admin_id", requesterID.String()),
            util.ErrorField(err))
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    // Verify role mask is 1 (owner) from the token
    if requesterRoleMask != models.RoleMaskOwner {
        h.logger.Warn("Non-owner attempting to change own phone via admin endpoint",
            util.String("admin_id", requesterID.String()),
            util.Uint64("role_mask", requesterRoleMask))
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can change phone numbers")
        return
    }

    var req struct {
        NewPhone string `json:"new_phone" validate:"required,phone"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Verify token has admin session type
    sessionType, _ := ctx.Value("session_type").(string)
    if sessionType != "admin" {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("INVALID_SESSION_TYPE"),
            "Admin session required")
        return
    }

    if err := h.adminService.ChangeAdminPhone(ctx, requesterID, req.NewPhone, requesterID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to change phone")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Phone updated successfully"))
    h.logger.Info("Owner changed own phone via HTTP",
        util.String("admin_id", requesterID.String()),
        util.Uint64("requester_role_mask", requesterRoleMask),
        util.Duration("duration", time.Since(startTime)),
    )
}
func (h *AdminHandler) InviteAdminWithDepartments(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    var req struct {
        Phone       string   `json:"phone" validate:"required,phone"`
        RoleMask    uint64   `json:"role_mask" validate:"required"`
        Departments []string `json:"departments" validate:"required,min=1"`
        Permissions []string `json:"permissions,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if !h.isValidRoleMask(req.RoleMask) {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("invalid role mask"), "Invalid role mask provided")
        return
    }

    if req.RoleMask == models.RoleMaskEmployee {
        for _, permName := range req.Permissions {
            if strings.HasPrefix(permName, "admin.") {
                h.respondWithError(w, http.StatusBadRequest,
                    fmt.Errorf("employee cannot have admin permissions"),
                    "Employee role cannot be assigned admin permissions")
                return
            }
        }
    }

    if !h.hasAdminPermission(r, "admin.user.create") {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "You don't have permission to invite admins")
        return
    }

    systemDepts, err := h.companyService.GetSystemDepartments(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err,
            "Failed to validate departments")
        return
    }

    validDeptNames := make([]string, 0)
    for _, deptName := range req.Departments {
        found := false
        for _, sysDept := range systemDepts {
            if strings.EqualFold(sysDept.Name, deptName) {
                validDeptNames = append(validDeptNames, deptName)
                found = true
                break
            }
        }
        if !found {
            h.logger.Warn("Invalid department name requested",
                util.String("department", deptName))
        }
    }

    if len(validDeptNames) == 0 {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("no valid departments provided"),
            "No valid departments found. Please check department names")
        return
    }

    requester, err := h.adminService.GetAdmin(ctx, requesterID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err,
            "Failed to validate requester permissions")
        return
    }

    if !requester.IsOwner() {
        for _, deptName := range validDeptNames {
            hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, requesterID, deptName)
            if err != nil || !hasAccess {
                h.respondWithError(w, http.StatusForbidden,
                    fmt.Errorf("permission denied for department: %s", deptName),
                    "You don't have access to all requested departments")
                return
            }
        }
    }

    for _, permName := range req.Permissions {
        if strings.HasPrefix(permName, "admin.") {
            if !requester.HasPermission(permName) {
                h.respondWithError(w, http.StatusForbidden,
                    fmt.Errorf("permission denied: %s", permName),
                    "You don't have permission to grant: "+permName)
                return
            }
        }
    }

    finalPermissions := make([]string, 0)
    if req.RoleMask == models.RoleMaskEmployee {
        for _, permName := range req.Permissions {
            if !strings.HasPrefix(permName, "admin.") {
                finalPermissions = append(finalPermissions, permName)
            } else {
                h.logger.Warn("Filtered out admin permission for employee",
                    util.String("permission", permName))
            }
        }
    } else {
        finalPermissions = req.Permissions
    }

    admin, err := h.adminService.InviteAdminWithDepartments(
        ctx,
        req.Phone,
        req.RoleMask,
        validDeptNames,
        finalPermissions,
        requesterID,
    )
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invite admin")
        return
    }

    accessibleDepartments := admin.GetAccessibleDepartments()
    permissionNames := admin.GetPermissionNames()

    // FIXED: Build response data as map, not Response struct
    responseData := map[string]interface{}{
        "admin": admin,
        "accessible_departments": accessibleDepartments,
        "permissions": permissionNames,
        "message": "Admin invited successfully with department access",
    }

    // FIXED: Add warning to data map, not Response struct
    if req.RoleMask == models.RoleMaskEmployee && len(req.Permissions) != len(finalPermissions) {
        responseData["warning"] = "Admin permissions were removed as employees cannot have admin permissions"
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(responseData, "Admin invited successfully"))

    h.logger.Info("Admin invited with departments",
        util.String("admin_id", admin.AdminID.String()),
        util.Uint64("role_mask", req.RoleMask),
        util.Strings("departments", validDeptNames),
        util.Strings("permissions", finalPermissions),
        util.String("invited_by", requesterID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}
// GetAdminsByRoleMask retrieves admins by role mask
func (h *AdminHandler) GetAdminsByRoleMask(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    // FIX: Change "roleMask" to "roleLevel" to match the route parameter
    roleMaskStr := chi.URLParam(r, "roleLevel")  // Changed from "roleMask"
    if roleMaskStr == "" {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("role level is required"), "Role level is required")
        return
    }

    roleMask, err := strconv.ParseUint(roleMaskStr, 10, 64)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid role mask")
        return
    }

    admins, err := h.adminService.GetAdminsByRole(ctx, roleMask)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admins by role")
        return
    }

    // FIX: Changed this part to use map[string]interface{} instead of indexing Response struct
    responseData := map[string]interface{}{
        "admins": admins,
        "role_mask": roleMask,
        "count": len(admins),
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Admins retrieved by role mask"))

    h.logger.Debug("Admins retrieved by role mask via HTTP",
        util.String("requester_id", requesterID.String()),
        util.Uint64("role_mask", roleMask),
        util.Int("count", len(admins)),
        util.Duration("duration", time.Since(startTime)),
    )
}


// 

// 
func (h *AdminHandler) CheckAdminPermission(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    if requesterRoleMask != models.RoleMaskOwner {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can check admin permissions")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    permissionName := r.URL.Query().Get("permission")
    if permissionName == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("permission parameter required"), "Permission parameter is required")
        return
    }

    targetAdmin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
        return
    }

    // Check if the target is a super employee (role mask 2)
    if targetAdmin.AdminRoleMask != models.RoleMaskSuperEmployee {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_TARGET_ROLE"),
            "Permission check is only applicable for super employees (role mask 2)")
        return
    }

    hasPermission, err := h.adminService.CheckAdminPermission(ctx, adminID, permissionName)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to check permission")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "has_permission": hasPermission,
        "permission": permissionName,
    }, "Permission check completed"))

    h.logger.Debug("Admin permission checked",
        util.String("admin_id", adminID.String()),
        util.String("permission", permissionName),
        util.Bool("has_permission", hasPermission),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) PromoteAdminWithBitmask(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    requesterID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    if requesterRoleMask != models.RoleMaskOwner {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can promote admins")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
        return
    }

    var req struct {
        NewRoleMask uint64 `json:"new_role_mask" validate:"required"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if req.NewRoleMask == models.RoleMaskOwner {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_ROLE_MASK"),
            "Cannot promote to owner role")
        return
    }

    // Note: Permissions will be cleared for both role mask 2 and 4
    if err := h.adminService.PromoteAdmin(ctx, adminID, req.NewRoleMask, requesterID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to promote admin")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "message": fmt.Sprintf("Admin promoted successfully to role mask %d. All permissions have been cleared.", req.NewRoleMask),
        "role_mask": req.NewRoleMask,
        "permissions_cleared": true,
    }, "Admin promoted successfully"))

    h.logger.Info("Admin promoted via HTTP (bitmask)",
        util.String("admin_id", adminID.String()),
        util.Uint64("new_role_mask", req.NewRoleMask),
        util.String("promoted_by", requesterID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) GrantPermissionToAdmin(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    grantedBy, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    if requesterRoleMask != models.RoleMaskOwner {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can grant permissions")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    permissionName := chi.URLParam(r, "permissionName")
    if permissionName == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("permission name required"), "Permission name is required")
        return
    }

    targetAdmin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
        return
    }

    // FIXED: Changed from RoleMaskEmployee to RoleMaskSuperEmployee
    if targetAdmin.AdminRoleMask != models.RoleMaskSuperEmployee {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_TARGET_ROLE"),
            "Permissions can only be assigned to super employees (role mask 2)")
        return
    }

    if err := h.adminService.GrantPermissionToAdmin(ctx, adminID, permissionName, grantedBy); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to grant permission")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permission granted successfully"))
    h.logger.Info("Permission granted to admin",
        util.String("admin_id", adminID.String()),
        util.String("permission", permissionName),
        util.String("granted_by", grantedBy.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) RevokePermissionFromAdmin(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    revokedBy, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    if requesterRoleMask != models.RoleMaskOwner {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can revoke permissions")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    permissionName := chi.URLParam(r, "permissionName")
    if permissionName == "" {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("permission name required"), "Permission name is required")
        return
    }

    targetAdmin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
        return
    }

    // FIXED: Changed from RoleMaskEmployee to RoleMaskSuperEmployee
    if targetAdmin.AdminRoleMask != models.RoleMaskSuperEmployee {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_TARGET_ROLE"),
            "Permissions can only be revoked from super employees (role mask 2)")
        return
    }

    if err := h.adminService.RevokePermissionFromAdmin(ctx, adminID, permissionName, revokedBy); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to revoke permission")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permission revoked successfully"))
    h.logger.Info("Permission revoked from admin",
        util.String("admin_id", adminID.String()),
        util.String("permission", permissionName),
        util.String("revoked_by", revokedBy.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) BatchUpdatePermissions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    updatedBy, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
        return
    }

    requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
        return
    }

    if requesterRoleMask != models.RoleMaskOwner {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("PERMISSION_DENIED"),
            "Only system owner can batch update permissions")
        return
    }

    adminIDStr := chi.URLParam(r, "adminID")
    adminID, err := uuid.Parse(adminIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
        return
    }

    var req struct {
        PermissionsToGrant  []string `json:"permissions_to_grant"`
        PermissionsToRevoke []string `json:"permissions_to_revoke"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    targetAdmin, err := h.adminService.GetAdmin(ctx, adminID)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
        return
    }

    // FIXED: Changed from RoleMaskEmployee to RoleMaskSuperEmployee
    if targetAdmin.AdminRoleMask != models.RoleMaskSuperEmployee {
        h.respondWithError(w, http.StatusBadRequest,
            fmt.Errorf("INVALID_TARGET_ROLE"),
            "Permissions can only be assigned to super employees (role mask 2)")
        return
    }

    if err := h.adminService.BatchUpdatePermissions(ctx, adminID,
        req.PermissionsToGrant, req.PermissionsToRevoke, updatedBy); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to batch update permissions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
        "granted": req.PermissionsToGrant,
        "revoked": req.PermissionsToRevoke,
        "total_changes": len(req.PermissionsToGrant) + len(req.PermissionsToRevoke),
    }, "Permissions batch updated successfully"))

    h.logger.Info("Admin permissions batch updated",
        util.String("admin_id", adminID.String()),
        util.String("updated_by", updatedBy.String()),
        util.Int("granted_count", len(req.PermissionsToGrant)),
        util.Int("revoked_count", len(req.PermissionsToRevoke)),
        util.Duration("duration", time.Since(startTime)),
    )
}