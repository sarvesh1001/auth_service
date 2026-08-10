package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/contextkeys"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// Context keys for injection

// AdminHandler handles HTTP requests for admin management, authentication, and RBAC.
type AdminHandler struct {
	adminService   *service.AdminService
	companyService *service.CompanyService
	userService    *service.UserService
	otpService     *service.OTPService
	mpinService    *service.AdminMPINService
	deviceService  *service.AdminDeviceService
	sessionService *service.SessionService
	jwtService     *service.JWTService
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(
	adminService *service.AdminService,
	companyService *service.CompanyService,
	userService *service.UserService,
	otpService *service.OTPService,
	mpinService *service.AdminMPINService,
	deviceService *service.AdminDeviceService,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
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
	}
}

// ---------- Helper functions for context injection ----------

func (h *AdminHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *AdminHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		// Use the shared context key type
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *AdminHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// ---------- Error mapping ----------

// mapServiceError maps custom error types to HTTP status codes and messages.
func (h *AdminHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"

	// Device errors
	case errors.Is(err, customErrors.ErrDeviceNotFound),
		errors.Is(err, customErrors.ErrDeviceAlreadyBound),
		errors.Is(err, customErrors.ErrDeviceNotTrusted),
		errors.Is(err, customErrors.ErrDeviceBlocked),
		errors.Is(err, customErrors.ErrInvalidDeviceID),
		errors.Is(err, customErrors.ErrBindingTokenMismatch),
		errors.Is(err, customErrors.ErrDeviceBindingExpired),
		errors.Is(err, customErrors.ErrDeviceAlreadyActive),
		errors.Is(err, customErrors.ErrDeviceNotActive),
		errors.Is(err, customErrors.ErrTooManyDevices),
		errors.Is(err, customErrors.ErrDeviceVerificationFailed):
		// all device errors are client-facing, map to appropriate status
		if errors.Is(err, customErrors.ErrDeviceNotFound) {
			return http.StatusNotFound, err.Error()
		}
		if errors.Is(err, customErrors.ErrDeviceAlreadyBound) ||
			errors.Is(err, customErrors.ErrDeviceAlreadyActive) ||
			errors.Is(err, customErrors.ErrTooManyDevices) {
			return http.StatusConflict, err.Error()
		}
		if errors.Is(err, customErrors.ErrDeviceNotTrusted) ||
			errors.Is(err, customErrors.ErrDeviceBlocked) {
			return http.StatusForbidden, err.Error()
		}
		if errors.Is(err, customErrors.ErrInvalidDeviceID) ||
			errors.Is(err, customErrors.ErrBindingTokenMismatch) ||
			errors.Is(err, customErrors.ErrDeviceBindingExpired) ||
			errors.Is(err, customErrors.ErrDeviceVerificationFailed) {
			return http.StatusBadRequest, err.Error()
		}
		return http.StatusBadRequest, err.Error()

	// MPIN errors
	case errors.Is(err, customErrors.ErrAdminMPINNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrAdminMPINInvalid):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrAdminMPINLocked):
		return http.StatusLocked, err.Error()
	case errors.Is(err, customErrors.ErrAdminMPINAlreadyExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrAdminMPINTooWeak):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrAdminMPINRateLimitExceeded),
		errors.Is(err, customErrors.ErrAdminMPINAttemptsExceeded):
		return http.StatusTooManyRequests, err.Error()

	// OTP errors
	case errors.Is(err, customErrors.ErrOTPRateLimitExceeded),
		errors.Is(err, customErrors.ErrOTPAttemptsExceeded),
		errors.Is(err, customErrors.ErrDailyQuotaExceeded):
		return http.StatusTooManyRequests, err.Error()
	case errors.Is(err, customErrors.ErrOTPNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrOTPInvalid),
		errors.Is(err, customErrors.ErrOTPExpired),
		errors.Is(err, customErrors.ErrOTPReplayAttempt):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrOTPAlreadyVerified):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrOTPBlocked):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrPhoneNotRegistered):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrSecurityCheckFailed):
		return http.StatusForbidden, err.Error()

	// Admin/user errors
	case errors.Is(err, customErrors.ErrInvalidState),
		errors.Is(err, customErrors.ErrInvalidStatus),
		errors.Is(err, customErrors.ErrInvalidTransition):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrAdminInactive):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrRoleInUse):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrSystemRole):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrSuperAdminRequired):
		return http.StatusForbidden, err.Error()

	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Login flows ----------

// LoginFlowResponse represents the response for login initiation.
type LoginFlowResponse struct {
	UserExists    bool   `json:"user_exists"`
	HasMPIN       bool   `json:"has_mpin"`
	MPINLocked    bool   `json:"mpin_locked"`
	DeviceTrusted bool   `json:"device_trusted"`
	FlowState     string `json:"flow_state"`
	Message       string `json:"message"`
	UserID        string `json:"user_id,omitempty"`
}

// InitiateAdminLogin handles the first step of admin login.
// @Summary Initiate admin login
// @Description Determines the login flow based on admin existence, MPIN status, and device trust.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Login initiation request" example({"phone_number":"+917206583437","device_id":"test-device-001","device_fingerprint":"test-fingerprint-v1"})
// @Success 200 {object} map[string]interface{} "Login flow determined"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /api/v1/admin-auth/login/initiate [post]
func (h *AdminHandler) InitiateAdminLogin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	// Extract client IP from context (injected by injectClientIP)
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = r.RemoteAddr // fallback
	}

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

	mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID)
	if err != nil {
		response.FlowState = "existing_user_otp"
		response.Message = "Existing admin - OTP verification required (no MPIN setup)"
		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
		return
	}

	response.HasMPIN = mpinStatus.Exists
	response.MPINLocked = mpinStatus.IsLocked

	// ✅ CORRECT: Use the admin‑specific trust check
	deviceTrusted, _, err := h.mpinService.CheckAdminDeviceTrust(
		ctx,
		admin.AdminID,
		req.DeviceID,
		ip, // IP from context
		req.DeviceFingerprint,
	)
	if err != nil {
		// Log error but treat as untrusted for safety
		zap.L().Warn("Failed to check admin device trust",
			zap.String("admin_id", admin.AdminID.String()),
			zap.String("device_id", req.DeviceID),
			zap.Error(err),
		)
		deviceTrusted = false
	}

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
}

// VerifyAdminOTPLogin verifies OTP and binds device.
// @Summary Verify admin OTP login
// @Description Verifies OTP for admin login and binds the device.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "OTP verification request" example({"phone_number":"+917206583437","otp":"123456","device_id":"test-device-001","device_fingerprint":"test-fingerprint-v1"})
// @Success 200 {object} map[string]interface{} "OTP verified, device trusted"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Authentication failed"
// @Failure 429 {object} map[string]interface{} "Rate limit or quota exceeded"
// @Router /api/v1/admin-auth/login/verify-otp [post]
func (h *AdminHandler) VerifyAdminOTPLogin(w http.ResponseWriter, r *http.Request) {
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

	otpVerifyReq := service.OTPVerifyRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               req.OTP,
		Purpose:           "admin_login",
		IPAddress:         h.getClientIP(r),
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
	}

	otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized, customErrors.ErrOTPInvalid, "Authentication failed")
		return
	}

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	deviceReq := service.AdminBindDeviceRequest{
		AdminID:           admin.AdminID,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}
	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		// non-critical, continue
		_ = err
	}

	if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
		_ = h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID)
	}

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
}

const MaxPermissionBits = 800

func newEmptyPermissionMask() []uint64 {
	segments := (MaxPermissionBits + 63) / 64
	return make([]uint64, segments)
}

func newFullPermissionMask() []uint64 {
	segments := (MaxPermissionBits + 63) / 64
	mask := make([]uint64, segments)
	for i := 0; i < segments; i++ {
		mask[i] = ^uint64(0)
	}
	return mask
}

// VerifyAdminMPINLogin handles MPIN-based login.
// @Summary Verify admin MPIN login
// @Description Authenticates admin using MPIN and issues JWT tokens.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "MPIN login request" example({"phone_number":"+917206583437","mpin":"123456","device_id":"test-device-001","device_fingerprint":"test-fingerprint-v1"})
// @Success 200 {object} map[string]interface{} "Login successful, returns tokens and admin data"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "MPIN verification failed"
// @Failure 404 {object} map[string]interface{} "Admin not found"
// @Router /api/v1/admin-auth/login/verify-mpin [post]
func (h *AdminHandler) VerifyAdminMPINLogin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		MPIN              string `json:"mpin" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
		UserAgent         string `json:"user_agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	mpinVerifyReq := &service.AdminMPINVerifyRequest{
		AdminID:           admin.AdminID,
		MPIN:              req.MPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         req.UserAgent,
	}

	mpinResult, err := h.mpinService.VerifyAdminMPIN(ctx, mpinVerifyReq)
	if err != nil || !mpinResult.Verified {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	permissionMask, err := h.adminService.GetAdminPermissionMask(ctx, admin.AdminID)
	if err != nil {
		if admin.IsSuperAdmin() {
			permissionMask = newFullPermissionMask()
		} else {
			permissionMask = newEmptyPermissionMask()
		}
	}

	_ = h.adminService.RecordAdminLogin(ctx, admin.AdminID)
	_ = h.adminService.ResetAdminFailedLoginAttempts(ctx, admin.AdminID)

	tokenReq := &service.IssueTokenPairRequest{
		UserID:         admin.AdminID.String(),
		Role:           admin.GetRoleString(),
		DeviceID:       req.DeviceID,
		SessionType:    "admin",
		IPAddress:      h.getClientIP(r),
		PermissionMask: permissionMask,
		CompanyID:      "",
	}
	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	adminWithPerms, err := h.adminService.GetAdminWithPermissions(ctx, admin.AdminID, admin.AdminID)
	if err != nil {
		// continue without extra permissions
	}

	responseData := map[string]interface{}{
		"tokens": tokens,
		"admin": map[string]interface{}{
			"admin_id":    admin.AdminID.String(),
			"role_type":   admin.RoleType,
			"role_string": admin.GetRoleString(),
			"username":    admin.Username,
			"full_name":   admin.FullName,
			"is_active":   admin.IsActive,
		},
		"message": "Admin MPIN login successful",
	}

	if adminWithPerms != nil {
		permissionNames := make([]string, 0, len(adminWithPerms.Permissions))
		for _, perm := range adminWithPerms.Permissions {
			permissionNames = append(permissionNames, perm.PermissionName)
		}
		departmentNames := make([]string, 0, len(adminWithPerms.Departments))
		for _, dept := range adminWithPerms.Departments {
			departmentNames = append(departmentNames, dept.Name)
		}
		responseData["admin"].(map[string]interface{})["permissions"] = permissionNames
		responseData["admin"].(map[string]interface{})["departments"] = departmentNames
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Admin login successful"))
}

// SetupAdminMPIN sets up MPIN for an admin.
// @Summary Setup admin MPIN
// @Description Creates an MPIN for the admin after successful OTP verification.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "MPIN setup request" example({"admin_id":"...","mpin":"123456","device_id":"test-device-001"})
// @Success 201 {object} map[string]interface{} "MPIN setup successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/admin-auth/mpin/setup [post]
func (h *AdminHandler) SetupAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		AdminID           string `json:"admin_id" validate:"required"`
		MPIN              string `json:"mpin" validate:"required,min=6,max=8"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
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

	mpinReq := &service.AdminMPINSetupRequest{
		AdminID:           adminID,
		MPIN:              req.MPIN,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.SetupAdminMPIN(ctx, mpinReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Admin MPIN setup successful"))
}

// ChangeAdminMPIN changes an admin's MPIN.
// @Summary Change admin MPIN
// @Description Updates MPIN after verifying current MPIN.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "MPIN change request" example({"admin_id":"...","current_mpin":"123456","new_mpin":"654321","device_id":"test-device-001"})
// @Success 200 {object} map[string]interface{} "MPIN changed"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/admin-auth/mpin/change [post]
func (h *AdminHandler) ChangeAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		AdminID           string `json:"admin_id" validate:"required"`
		CurrentMPIN       string `json:"current_mpin" validate:"required"`
		NewMPIN           string `json:"new_mpin" validate:"required,min=6,max=8"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
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
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.ChangeAdminMPIN(ctx, mpinReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin MPIN change successful"))
}

// ForgotAdminMPIN initiates the forgot MPIN flow.
// @Summary Forgot admin MPIN
// @Description Sends OTP to admin's phone for MPIN reset.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Forgot MPIN request" example({"phone_number":"+917206583437","device_id":"test-device-001"})
// @Success 200 {object} map[string]interface{} "Forgot MPIN initiated"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Phone not registered"
// @Router /api/v1/admin-auth/mpin/forgot [post]
func (h *AdminHandler) ForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		DeviceFingerprint string `json:"device_fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil || admin == nil {
		h.respondWithError(w, http.StatusNotFound, customErrors.ErrPhoneNotRegistered, "Phone not registered")
		return
	}

	forgotReq := &service.AdminMPINForgotRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.ForgotAdminMPIN(ctx, forgotReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Forgot MPIN initiated"))
}

// VerifyForgotAdminMPIN verifies OTP and resets MPIN.
// @Summary Verify forgot admin MPIN
// @Description Verifies OTP and sets a new MPIN.
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Reset MPIN request" example({"phone_number":"+917206583437","device_id":"test-device-001","new_mpin":"654321","otp_code":"123456"})
// @Success 200 {object} map[string]interface{} "MPIN reset successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Phone not registered"
// @Router /api/v1/admin-auth/mpin/forgot/verify [post]
func (h *AdminHandler) VerifyForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		PhoneNumber       string `json:"phone_number" validate:"required"`
		DeviceID          string `json:"device_id" validate:"required"`
		NewMPIN           string `json:"new_mpin" validate:"required,min=6,max=8"`
		OTPCode           string `json:"otp_code" validate:"required,len=6"`
		DeviceFingerprint string `json:"device_fingerprint"`
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

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil || admin == nil {
		h.respondWithError(w, http.StatusNotFound, customErrors.ErrPhoneNotRegistered, "Phone not registered")
		return
	}

	forgotReq := &service.AdminMPINForgotWithOTPRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		NewMPIN:           req.NewMPIN,
		OTPCode:           req.OTPCode,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         h.getClientIP(r),
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.VerifyForgotAdminMPINOTP(ctx, forgotReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin MPIN reset successful"))
}

// ---------- Admin Role CRUD ----------

// CreateAdminRole creates a new admin role.
// @Summary Create admin role
// @Description Creates a new admin role with specified permissions.
// @Tags admin-roles
// @Accept json
// @Produce json
// @Param body body models.AdminRoleCreateRequest true "Role details"
// @Success 201 {object} map[string]interface{} "Role created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Role name already exists"
// @Router /api/v1/admin/roles [post]
func (h *AdminHandler) CreateAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req models.AdminRoleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.RoleType != models.RoleTypeEmployee && req.RoleType != models.RoleTypeManager {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role type must be 1 (employee) or 2 (manager)")
		return
	}

	role, err := h.adminService.CreateAdminRole(ctx, &req, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Admin role created successfully"))
}

// GetAdminRole retrieves a specific admin role.
// @Summary Get admin role by ID
// @Tags admin-roles
// @Produce json
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "Role details"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Router /api/v1/admin/roles/{roleID} [get]
func (h *AdminHandler) GetAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	role, err := h.adminService.GetAdminRole(ctx, roleID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Admin role retrieved successfully"))
}

// GetAdminRoles lists admin roles with pagination and filtering.
// @Summary List admin roles
// @Tags admin-roles
// @Produce json
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Param role_type query int false "Filter by role type (1=employee, 2=manager)"
// @Success 200 {object} map[string]interface{} "List of roles with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Router /api/v1/admin/roles [get]
func (h *AdminHandler) GetAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	var roleType *int
	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
		rt, err := strconv.Atoi(roleTypeStr)
		if err == nil {
			roleType = &rt
		}
	}

	roles, total, err := h.adminService.GetAdminRoles(ctx, requesterID, limit, offset, roleType)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(roles),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin roles retrieved successfully"))
}

// UpdateAdminRole updates an existing admin role.
// @Summary Update admin role
// @Tags admin-roles
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body models.AdminRoleUpdateRequest true "Update fields"
// @Success 200 {object} map[string]interface{} "Updated role"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Router /api/v1/admin/roles/{roleID} [put]
func (h *AdminHandler) UpdateAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	var updates models.AdminRoleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	role, err := h.adminService.UpdateAdminRole(ctx, roleID, &updates, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Admin role updated successfully"))
}

// DeleteAdminRole deletes an admin role.
// @Summary Delete admin role
// @Tags admin-roles
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "Role deleted"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Role in use"
// @Router /api/v1/admin/roles/{roleID} [delete]
func (h *AdminHandler) DeleteAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	if err := h.adminService.DeleteAdminRole(ctx, roleID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin role deleted successfully"))
}

// ---------- Admin User CRUD ----------

// CreateAdminUser creates a new admin user.
// @Summary Create admin user
// @Tags admin-users
// @Accept json
// @Produce json
// @Param body body models.AdminCreateRequest true "Admin details"
// @Success 201 {object} map[string]interface{} "Admin created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins [post]
func (h *AdminHandler) CreateAdminUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req models.AdminCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	admin, err := h.adminService.CreateAdminUser(ctx, &req, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "Admin user created successfully"))
}

// GetAdminUser retrieves a specific admin user.
// @Summary Get admin user
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin details"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 404 {object} map[string]interface{} "Admin not found"
// @Router /api/v1/admin/admins/{adminID} [get]
func (h *AdminHandler) GetAdminUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	admin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin user retrieved successfully"))
}

// UpdateAdminUser updates an admin user.
// @Summary Update admin user
// @Tags admin-users
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body map[string]interface{} true "Update fields"
// @Success 200 {object} map[string]interface{} "Admin updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID} [put]
func (h *AdminHandler) UpdateAdminUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.UpdateAdminUser(ctx, adminID, updates, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user updated successfully"))
}

// DeleteAdminUser deletes an admin user.
// @Summary Delete admin user
// @Tags admin-users
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin deleted"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID} [delete]
func (h *AdminHandler) DeleteAdminUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := h.adminService.DeleteAdminUser(ctx, adminID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user deleted successfully"))
}

// UpdateAdminProfile updates admin's profile (username, full_name).
// @Summary Update admin profile
// @Tags admin-users
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body models.AdminProfileUpdateRequest true "Profile fields"
// @Success 200 {object} map[string]interface{} "Profile updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/profile [put]
func (h *AdminHandler) UpdateAdminProfile(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	var req models.AdminProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	updates := make(map[string]interface{})
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.FullName != "" {
		updates["full_name"] = req.FullName
	}
	if len(updates) == 0 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "At least one field (username or full_name) must be provided")
		return
	}

	if err := h.adminService.UpdateAdminUser(ctx, adminID, updates, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin profile updated successfully"))
}

// ChangeAdminPhone changes the admin's phone number.
// @Summary Change admin phone
// @Tags admin-users
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body object true "New phone" example({"new_phone":"+919876543210"})
// @Success 200 {object} map[string]interface{} "Phone updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/phone [put]
func (h *AdminHandler) ChangeAdminPhone(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		NewPhone string `json:"new_phone" validate:"required,phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.UpdateAdminPhone(ctx, adminID, req.NewPhone, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin phone updated successfully"))
}

// UpdateAdminReportsTo updates the reporting manager for an admin.
// @Summary Update admin reports_to
// @Tags admin-users
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body object true "Reports to" example({"reports_to":"some-uuid"})
// @Success 200 {object} map[string]interface{} "Reports_to updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/reports-to [put]
func (h *AdminHandler) UpdateAdminReportsTo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		ReportsTo *string `json:"reports_to,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	var reportsToUUID *uuid.UUID
	if req.ReportsTo != nil && *req.ReportsTo != "" {
		reportsTo, err := uuid.Parse(*req.ReportsTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid reports_to UUID format")
			return
		}
		reportsToUUID = &reportsTo
	}

	if err := h.adminService.UpdateAdminReportsTo(ctx, adminID, reportsToUUID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin reports_to updated successfully"))
}

// ---------- Admin Permissions ----------

// GetAdminPermissions retrieves all permissions for an admin.
// @Summary Get admin permissions
// @Tags admin-permissions
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "List of permissions"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/permissions [get]
func (h *AdminHandler) GetAdminPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	permissions, err := h.adminService.GetAdminPermissions(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "Admin permissions retrieved successfully"))
}

// ActivateAdmin activates an admin user.
// @Summary Activate admin
// @Tags admin-users
// @Post
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin activated"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/activate [post]
func (h *AdminHandler) ActivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := h.adminService.ActivateAdmin(ctx, adminID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin activated successfully"))
}

// DeactivateAdmin deactivates an admin user.
// @Summary Deactivate admin
// @Tags admin-users
// @Post
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin deactivated"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/deactivate [post]
func (h *AdminHandler) DeactivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := h.adminService.DeactivateAdmin(ctx, adminID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin deactivated successfully"))
}

// ---------- Admin Avatar ----------

// SetAdminAvatar sets the avatar for an admin.
// @Summary Set admin avatar
// @Tags admin-avatar
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body object true "Avatar data" example({"avatar_hash":"...","avatar_object_key":"...","avatar_mime_type":"image/jpeg"})
// @Success 200 {object} map[string]interface{} "Avatar set"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/avatar [post]
func (h *AdminHandler) SetAdminAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		AvatarHash      string `json:"avatar_hash" validate:"required"`
		AvatarObjectKey string `json:"avatar_object_key" validate:"required"`
		AvatarMimeType  string `json:"avatar_mime_type" validate:"required,oneof=image/jpeg image/jpg image/png image/gif image/webp image/svg+xml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.SetAdminAvatar(ctx, adminID, req.AvatarHash, req.AvatarObjectKey, req.AvatarMimeType, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin avatar set successfully"))
}

// GetAdminAvatar retrieves the admin's avatar.
// @Summary Get admin avatar
// @Tags admin-avatar
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Avatar details"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 404 {object} map[string]interface{} "Avatar not found"
// @Router /api/v1/admin/admins/{adminID}/avatar [get]
func (h *AdminHandler) GetAdminAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatar, err := h.adminService.GetAdminAvatar(ctx, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(avatar, "Admin avatar retrieved successfully"))
}

// DeactivateAdminAvatar removes the admin's avatar.
// @Summary Deactivate admin avatar
// @Tags admin-avatar
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Avatar removed"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/avatar [delete]
func (h *AdminHandler) DeactivateAdminAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := h.adminService.DeactivateAdminAvatar(ctx, adminID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin avatar deactivated successfully"))
}

// ---------- Helper methods ----------

func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
	status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
	if err != nil {
		return false
	}
	return status != nil && status.Exists
}

func (h *AdminHandler) getIntQueryParam(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	result, err := strconv.Atoi(value)
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

func (h *AdminHandler) getClientIP(r *http.Request) string {
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

func (h *AdminHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AdminHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// ============================
// AVATAR & HIERARCHY HANDLERS
// ============================

// GetAdminAvatarWithFallback retrieves admin avatar with initials fallback.
// @Summary Get admin avatar with fallback
// @Tags admin-avatar
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Avatar and initials"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 404 {object} map[string]interface{} "Admin not found"
// @Router /api/v1/admin/admins/{adminID}/avatar/with-fallback [get]
func (h *AdminHandler) GetAdminAvatarWithFallback(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatar, initials, err := h.adminService.GetAdminAvatarWithFallback(ctx, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"avatar":     avatar,
		"initials":   initials,
		"has_avatar": avatar != nil,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin avatar with fallback retrieved successfully"))
}

// GetDirectReports retrieves direct reports of an admin.
// @Summary Get direct reports
// @Tags admin-hierarchy
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "List of direct reports"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/direct-reports [get]
func (h *AdminHandler) GetDirectReports(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	directReports, err := h.adminService.GetDirectReports(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(directReports, "Direct reports retrieved successfully"))
}

// GetReportingChain retrieves the reporting chain (upward) for an admin.
// @Summary Get reporting chain
// @Tags admin-hierarchy
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Reporting chain list"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/reporting-chain [get]
func (h *AdminHandler) GetReportingChain(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	reportingChain, err := h.adminService.GetReportingChain(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(reportingChain, "Reporting chain retrieved successfully"))
}

// GetAdminHierarchy retrieves the full hierarchy (both up and down) for an admin.
// @Summary Get admin hierarchy
// @Tags admin-hierarchy
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Full hierarchy tree"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/hierarchy [get]
func (h *AdminHandler) GetAdminHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	hierarchy, err := h.adminService.GetAdminHierarchy(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "Admin hierarchy retrieved successfully"))
}

// ============================
// SEARCH ROUTE REGISTRATION
// ============================

// RegisterSearchRoutes registers all search-related admin endpoints.
// @Tags admin-search
func (h *AdminHandler) RegisterSearchRoutes(router chi.Router) {
	router.Route("/search", func(r chi.Router) {
		r.Get("/admins", h.SearchAdmins)
		r.Get("/admins/advanced", h.SearchAdminsAdvanced)
		r.Get("/admins/name", h.SearchAdminsByName)
		r.Get("/admins/employees", h.SearchAdminEmployees)
		r.Get("/admins/managers", h.SearchAdminManagers)
		r.Get("/admins/suggestions", h.GetAdminSuggestions)
		r.Get("/admins/analytics", h.GetAdminSearchAnalytics)
		r.Get("/roles", h.SearchAdminRoles)
	})
}

// ============================
// SEARCH HANDLERS
// ============================

// GetAdminSuggestions returns admin suggestions based on a prefix.
// @Summary Get admin suggestions
// @Tags admin-search
// @Produce json
// @Param prefix query string true "Search prefix"
// @Param limit query int false "Max results" default(10)
// @Param exclude_owner query bool false "Exclude owner admins"
// @Param role_type query int false "Filter by role type"
// @Success 200 {object} map[string]interface{} "List of suggestions"
// @Failure 400 {object} map[string]interface{} "Missing prefix"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/suggestions [get]
func (h *AdminHandler) GetAdminSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Prefix is required for suggestions")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 10)
	excludeOwner := h.getBoolQueryParam(r, "exclude_owner", false)

	var roleTypeFilter *int
	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
		rt, err := strconv.Atoi(roleTypeStr)
		if err == nil {
			roleTypeFilter = &rt
		}
	}

	suggestions, err := h.adminService.GetAdminSuggestions(ctx, prefix, requesterID, roleTypeFilter, excludeOwner, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Admin suggestions retrieved successfully"))
}

// GetAdminSearchAnalytics returns search analytics for admin search.
// @Summary Get admin search analytics
// @Tags admin-search
// @Produce json
// @Success 200 {object} map[string]interface{} "Search analytics"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/analytics [get]
func (h *AdminHandler) GetAdminSearchAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	stats, err := h.adminService.GetStats(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin search analytics retrieved successfully"))
}

// SearchAdminRoles searches admin roles by query.
// @Summary Search admin roles
// @Tags admin-search
// @Produce json
// @Param q query string true "Search query"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Missing query"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/search [get]
func (h *AdminHandler) SearchAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Search query is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	roles, total, err := h.adminService.SearchAdminRoles(ctx, query, requesterID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(roles),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin roles search completed successfully"))
}

// ============================
// HELPER METHODS (kept as is)
// ============================

// getRequesterAdminID extracts the admin ID from the request context.
func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		return uuid.Nil, customErrors.ErrUnauthorized
	}
	return uuid.Parse(userID)
}

// hasMPIN checks if an admin has an MPIN set.

// handleOTPError handles OTP-specific errors (unchanged).
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

// ============================
// COMPANY HANDLERS
// ============================

// validateCreateCompanyRequest validates company creation input.
func validateCreateCompanyRequest(req CreateCompanyRequest) error {
	// (unchanged, keep as is)
	if strings.TrimSpace(req.CompanyName) == "" {
		return fmt.Errorf("company_name is required")
	}
	if strings.TrimSpace(req.OwnerPhone) == "" {
		return fmt.Errorf("owner_phone is required")
	}
	if strings.TrimSpace(req.OwnerUsername) == "" {
		return fmt.Errorf("owner_username is required")
	}
	if len(req.OwnerUsername) < 3 || len(req.OwnerUsername) > 100 {
		return fmt.Errorf("owner_username must be between 3 and 100 characters")
	}
	if strings.TrimSpace(req.OwnerFullName) == "" {
		return fmt.Errorf("owner_full_name is required")
	}
	if len(req.OwnerFullName) > 255 {
		return fmt.Errorf("owner_full_name must be at most 255 characters")
	}
	if strings.TrimSpace(req.OwnerPositionTitle) == "" {
		return fmt.Errorf("owner_position_title is required")
	}
	if len(req.OwnerPositionTitle) > 255 {
		return fmt.Errorf("owner_position_title must be at most 255 characters")
	}
	validTiers := map[string]bool{
		"basic": true, "premium": true, "enterprise": true,
	}
	if !validTiers[req.SubscriptionTier] {
		return fmt.Errorf("subscription_tier must be one of: basic, premium, enterprise")
	}
	if req.MaxEmployees < 1 || req.MaxEmployees > 2000 {
		return fmt.Errorf("max_employees must be between 1 and 2000")
	}
	if req.MaxDepartments < 1 || req.MaxDepartments > 100 {
		return fmt.Errorf("max_departments must be between 1 and 100")
	}
	totalDepartments := len(req.Departments) + 1
	if totalDepartments > req.MaxDepartments {
		return fmt.Errorf(
			"requested %d departments exceeds max_departments limit of %d",
			totalDepartments,
			req.MaxDepartments,
		)
	}
	if strings.TrimSpace(req.DataRegion) == "" {
		return fmt.Errorf("data_region is required")
	}
	if req.SubscriptionMonths < 1 || req.SubscriptionMonths > 36 {
		return fmt.Errorf("subscription_months must be between 1 and 36")
	}
	if req.SubscriptionDays < 0 || req.SubscriptionDays > 30 {
		return fmt.Errorf("subscription_days must be between 0 and 30")
	}
	return nil
}

// GetCompany retrieves a company by ID.
// @Summary Get company by ID
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Company details"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 404 {object} map[string]interface{} "Company not found"
// @Router /api/v1/admin/companies/{companyID} [get]
func (h *AdminHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
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

	h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company details retrieved"))
}

// GetRecentCompanies lists recent companies.
// @Summary List recent companies
// @Tags admin-companies
// @Produce json
// @Param limit query int false "Page size" default(50)
// @Success 200 {object} map[string]interface{} "List of companies with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Router /api/v1/admin/companies [get]
func (h *AdminHandler) GetRecentCompanies(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	limit := h.getIntQueryParam(r, "limit", 50)
	companies, total, err := h.companyService.ListCompanies(ctx, limit, 0)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// SearchCompanies searches companies by query with filters.
// @Summary Search companies
// @Tags admin-companies
// @Produce json
// @Param q query string true "Search query"
// @Param limit query int false "Page size" default(20)
// @Param offset query int false "Offset" default(0)
// @Param search_type query string false "Search type (all, name, etc.)" default(all)
// @Param sort_by query string false "Sort field" default(relevance)
// @Param tier query string false "Filter by tier"
// @Param status query string false "Filter by status"
// @Param region query string false "Filter by region"
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Missing query"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/search [get]
func (h *AdminHandler) SearchCompanies(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Search query is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	offset := h.getIntQueryParam(r, "offset", 0)

	searchType := r.URL.Query().Get("search_type")
	if searchType == "" {
		searchType = "all"
	}
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "relevance"
	}

	var filters *models.CompanySearchFilters
	tier := r.URL.Query().Get("tier")
	status := r.URL.Query().Get("status")
	region := r.URL.Query().Get("region")
	if tier != "" || status != "" || region != "" {
		filters = &models.CompanySearchFilters{
			SubscriptionTier:   tier,
			SubscriptionStatus: status,
			DataRegion:         region,
		}
	}

	searchReq := &service.SearchCompaniesRequest{
		Query:      query,
		SearchType: searchType,
		Filters:    filters,
		Limit:      limit,
		Offset:     offset,
		SortBy:     sortBy,
		SortOrder:  "desc",
	}
	searchResp, err := h.companyService.SearchCompanies(ctx, searchReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Company search completed"))
}

// GetCompanySuggestions returns company name suggestions based on prefix.
// @Summary Get company suggestions
// @Tags admin-companies
// @Produce json
// @Param prefix query string true "Prefix"
// @Param limit query int false "Max results" default(10)
// @Success 200 {object} map[string]interface{} "List of suggestions"
// @Failure 400 {object} map[string]interface{} "Missing prefix"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/suggestions [get]
func (h *AdminHandler) GetCompanySuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Prefix is required for suggestions")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 10)
	suggestions, err := h.companyService.GetCompanySuggestions(ctx, prefix, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Company suggestions retrieved"))
}

// GetCompanySearchAnalytics returns analytics for company search.
// @Summary Get company search analytics
// @Tags admin-companies
// @Produce json
// @Success 200 {object} map[string]interface{} "Search analytics"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/analytics/search [get]
func (h *AdminHandler) GetCompanySearchAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	analytics, err := h.companyService.GetCompanySearchAnalytics(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(analytics, "Company search analytics retrieved"))
}

// BenchmarkCompanySearch runs a benchmark test for company search.
// @Summary Benchmark company search
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param body body object false "Test queries and iterations" example({"test_queries":["tech","solution"],"iterations":10})
// @Success 200 {object} map[string]interface{} "Benchmark results"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/search/benchmark [post]
func (h *AdminHandler) BenchmarkCompanySearch(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	_, err := h.getRequesterAdminID(r)
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

	if len(req.TestQueries) == 0 {
		req.TestQueries = []string{
			"tech", "solution", "enterprise", "global",
			"innov", "corp", "group", "limited",
		}
	}
	if req.Iterations == 0 {
		req.Iterations = 10
	}

	results, err := h.companyService.BenchmarkCompanySearch(ctx, req.TestQueries, req.Iterations)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Search benchmark completed"))
}

// SearchCompaniesByOwner searches companies owned by a specific user.
// @Summary Search companies by owner
// @Tags admin-companies
// @Produce json
// @Param ownerID path string true "Owner UUID"
// @Param q query string true "Search query"
// @Param limit query int false "Page size" default(20)
// @Param offset query int false "Offset" default(0)
// @Param active query bool false "Filter by active status"
// @Success 200 {object} map[string]interface{} "Search results"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/owner/{ownerID}/search [get]
func (h *AdminHandler) SearchCompaniesByOwner(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	ownerIDStr := chi.URLParam(r, "ownerID")
	ownerID, err := uuid.Parse(ownerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid owner ID")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Search query is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	offset := h.getIntQueryParam(r, "offset", 0)

	var isActive *bool
	if activeParam := r.URL.Query().Get("active"); activeParam != "" {
		active := activeParam == "true"
		isActive = &active
	}

	searchResp, err := h.companyService.SearchCompaniesByOwner(ctx, ownerID, query, isActive, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Owner company search completed"))
}

// GetCompanyEmployees lists employees of a company.
// @Summary List company employees
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Employees with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/employees [get]
func (h *AdminHandler) GetCompanyEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	employees, total, err := h.companyService.ListEmployees(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// GetCompanyDepartments lists departments of a company.
// @Summary List company departments
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Departments with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/departments [get]
func (h *AdminHandler) GetCompanyDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	departments, total, err := h.companyService.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"departments": departments,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"count":      len(departments),
			"total":      total,
			"limit":      limit,
			"offset":     offset,
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company departments retrieved successfully"))
}

// GetCompanyStats returns statistics for a company.
// @Summary Get company statistics
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Company stats"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/stats [get]
func (h *AdminHandler) GetCompanyStats(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	stats, err := h.companyService.GetCompanyStats(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Company statistics retrieved successfully"))
}

// UpdateSubscription updates a company's subscription.
// @Summary Update company subscription
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Subscription details" example({"tier":"premium","status":"active","max_employees":500})
// @Success 200 {object} map[string]interface{} "Subscription updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/subscription [put]
func (h *AdminHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription updated successfully"))
}

// ExtendSubscription extends a company's subscription duration.
// @Summary Extend subscription
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Extension details" example({"additional_months":3,"additional_days":0})
// @Success 200 {object} map[string]interface{} "Subscription extended"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/subscription/extend [post]
func (h *AdminHandler) ExtendSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Either additional_months or additional_days must be provided")
		return
	}

	if err := h.companyService.ExtendSubscription(ctx, companyID, req.AdditionalMonths, req.AdditionalDays, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))
}

// DeactivateCompany deactivates a company.
// @Summary Deactivate company
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body object true "Deactivation reason" example({"reason":"Violation of terms"})
// @Success 200 {object} map[string]interface{} "Company deactivated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/deactivate [post]
func (h *AdminHandler) DeactivateCompany(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := h.companyService.DeactivateCompany(ctx, companyID, req.Reason, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company deactivated successfully"))
}

// ReactivateCompany reactivates a previously deactivated company.
// @Summary Reactivate company
// @Tags admin-companies
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Company reactivated"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/reactivate [post]
func (h *AdminHandler) ReactivateCompany(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company reactivated successfully"))
}

// GetCompaniesByStatus lists companies filtered by status.
// @Summary Get companies by status
// @Tags admin-companies
// @Produce json
// @Param status path string true "Status (active/inactive)"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Companies with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid status"
// @Router /api/v1/admin/companies/status/{status} [get]
func (h *AdminHandler) GetCompaniesByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Status is required")
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
		allCompanies, _, err := h.companyService.ListCompanies(ctx, 1000, 0)
		if err != nil {
			statusCode, msg := h.mapServiceError(err)
			h.respondWithError(w, statusCode, err, msg)
			return
		}
		var inactiveCompanies []*models.Company
		for _, company := range allCompanies {
			if !company.IsActive {
				inactiveCompanies = append(inactiveCompanies, company)
			}
		}
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
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Status must be active or inactive")
		return
	}
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, err, msg)
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
}

// GetCompaniesByTier lists companies by subscription tier.
// @Summary Get companies by tier
// @Tags admin-companies
// @Produce json
// @Param tier path string true "Subscription tier (basic/premium/enterprise)"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Companies with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid tier"
// @Router /api/v1/admin/companies/tier/{tier} [get]
func (h *AdminHandler) GetCompaniesByTier(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	tier := chi.URLParam(r, "tier")
	if tier == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Subscription tier is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	companies, total, err := h.companyService.ListCompaniesByTier(ctx, tier, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// GetCompaniesWithExpiringSubscription lists companies with subscriptions expiring within a given number of days.
// @Summary Get companies with expiring subscriptions
// @Tags admin-companies
// @Produce json
// @Param days query int false "Days threshold" default(30)
// @Param limit query int false "Page size" default(50)
// @Success 200 {object} map[string]interface{} "Companies with expiring subscriptions"
// @Failure 400 {object} map[string]interface{} "Invalid days parameter"
// @Router /api/v1/admin/companies/expiring [get]
func (h *AdminHandler) GetCompaniesWithExpiringSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	days := h.getIntQueryParam(r, "days", 30)
	if days <= 0 || days > 365 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Days must be between 1 and 365")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	companies, err := h.companyService.GetCompaniesWithExpiringSubscription(ctx, days, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// GetCompanyHierarchy retrieves the full employee hierarchy of a company.
// @Summary Get company hierarchy
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Hierarchy tree"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/hierarchy [get]
func (h *AdminHandler) GetCompanyHierarchy(w http.ResponseWriter, r *http.Request) {
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

	response := map[string]interface{}{
		"hierarchy": hierarchy,
		"meta": map[string]interface{}{
			"company_id": companyID.String(),
			"count":      len(hierarchy),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company hierarchy retrieved successfully"))
}

// GetCompanyRBACStats returns RBAC statistics for a company.
// @Summary Get company RBAC statistics
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "RBAC stats (department load, role distribution, etc.)"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/rbac-stats [get]
func (h *AdminHandler) GetCompanyRBACStats(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	deptLoad, err := h.companyService.GetDepartmentLoad(ctx, companyID)
	if err != nil {
		// non-critical, continue
		_ = err
	}
	roleDist, err := h.companyService.GetRoleDistribution(ctx, companyID)
	if err != nil {
		_ = err
	}
	stats, err := h.companyService.GetCompanyStats(ctx, companyID)
	if err != nil {
		_ = err
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
}

// GetCompanyRoles lists all roles within a company.
// @Summary Get company roles
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Roles with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Router /api/v1/admin/companies/{companyID}/roles [get]
func (h *AdminHandler) GetCompanyRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	roles, total, err := h.companyService.GetRolesByCompany(ctx, companyID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// ============================
// USER MANAGEMENT HANDLERS
// ============================

// SearchUsersAdvanced performs advanced user search with filters.
// @Summary Advanced user search
// @Tags admin-user-management
// @Produce json
// @Param username query string false "Filter by username"
// @Param full_name query string false "Filter by full name"
// @Param phone_hash query string false "Filter by phone hash"
// @Param kyc_status query string false "Filter by KYC status"
// @Param data_region query string false "Filter by data region"
// @Param is_verified query bool false "Filter by verified status"
// @Param is_active query bool false "Filter by active status"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/search/advanced [get]
func (h *AdminHandler) SearchUsersAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

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

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	users, total, err := h.userService.SearchUsersAdvanced(ctx, filters, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	for _, user := range users {
		h.sanitizeUserForAdmin(user)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"count":    len(users),
			"total":    total,
			"limit":    limit,
			"offset":   offset,
			"filters":  filters,
			"has_more": offset+limit < total,
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Advanced user search completed"))
}

// SearchUsersByUsername searches users by username (partial match).
// @Summary Search users by username
// @Tags admin-user-management
// @Produce json
// @Param username query string true "Username to search"
// @Param limit query int false "Max results" default(20)
// @Success 200 {object} map[string]interface{} "Matching users with metadata"
// @Failure 400 {object} map[string]interface{} "Missing username"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/search/username [get]
func (h *AdminHandler) SearchUsersByUsername(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Username is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	users, err := h.userService.SearchUsersByUsername(ctx, username, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

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
}

// SearchUsersByFullName searches users by full name (partial match).
// @Summary Search users by full name
// @Tags admin-user-management
// @Produce json
// @Param full_name query string true "Full name to search"
// @Param limit query int false "Max results" default(20)
// @Success 200 {object} map[string]interface{} "Matching users with metadata"
// @Failure 400 {object} map[string]interface{} "Missing full name"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/search/full-name [get]
func (h *AdminHandler) SearchUsersByFullName(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	fullName := r.URL.Query().Get("full_name")
	if fullName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Full name is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	users, err := h.userService.SearchUsersByFullName(ctx, fullName, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

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
}

// GetUserSuggestions returns user suggestions based on a prefix.
// @Summary Get user suggestions
// @Tags admin-user-management
// @Produce json
// @Param prefix query string true "Prefix for suggestion"
// @Param limit query int false "Max results" default(10)
// @Success 200 {object} map[string]interface{} "List of suggestions"
// @Failure 400 {object} map[string]interface{} "Missing prefix"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/suggestions [get]
func (h *AdminHandler) GetUserSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Prefix is required for suggestions")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 10)
	suggestions, err := h.userService.GetUserSuggestions(ctx, prefix, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "User suggestions retrieved"))
}

// UpdateUser updates a user's details (admin only).
// @Summary Update user
// @Tags admin-user-management
// @Accept json
// @Produce json
// @Param userID path string true "User UUID"
// @Param body body object true "Update fields" example({"username":"newuser","full_name":"New Name","is_active":true})
// @Success 200 {object} map[string]interface{} "Updated user"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/{userID} [put]
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	_, err := h.getRequesterAdminID(r)
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
		Username          *string `json:"username,omitempty"`
		FullName          *string `json:"full_name,omitempty"`
		DeviceID          *string `json:"device_id,omitempty"`
		DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
		DataRegion        *string `json:"data_region,omitempty"`
		IsVerified        *bool   `json:"is_verified,omitempty"`
		IsActive          *bool   `json:"is_active,omitempty"`
		KYCStatus         *string `json:"kyc_status,omitempty"`
		KYCLevel          *string `json:"kyc_level,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

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

	user, err := h.userService.UpdateUser(ctx, userID, updateReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.sanitizeUserForAdmin(user)
	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))
}

// UpdateUserKYC updates a user's KYC status.
// @Summary Update user KYC
// @Tags admin-user-management
// @Accept json
// @Produce json
// @Param userID path string true "User UUID"
// @Param body body object true "KYC update" example({"status":"verified","level":"full","reason":"Document verified"})
// @Success 200 {object} map[string]interface{} "KYC updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/{userID}/kyc [patch]
func (h *AdminHandler) UpdateUserKYC(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User KYC status updated successfully"))
}

// BanUser bans a user with a reason.
// @Summary Ban user
// @Tags admin-user-management
// @Accept json
// @Produce json
// @Param userID path string true "User UUID"
// @Param body body object true "Ban reason" example({"reason":"Violation of terms"})
// @Success 200 {object} map[string]interface{} "User banned"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/{userID}/ban [post]
func (h *AdminHandler) BanUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User banned successfully"))
}

// UnbanUser unbans a previously banned user.
// @Summary Unban user
// @Tags admin-user-management
// @Accept json
// @Produce json
// @Param userID path string true "User UUID"
// @Param body body object true "Unban reason" example({"reason":"Appeal accepted"})
// @Success 200 {object} map[string]interface{} "User unbanned"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/{userID}/unban [post]
func (h *AdminHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
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
		Reason string `json:"reason" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.userService.UnbanUser(ctx, userID, requesterID, req.Reason); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))
}

// GetBannedUsers lists all banned users.
// @Summary Get banned users
// @Tags admin-user-management
// @Produce json
// @Param limit query int false "Page size" default(100)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "List of banned users with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/banned [get]
func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)

	users, total, err := h.userService.GetBannedUsers(ctx, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	sanitizedUsers := make([]map[string]interface{}, len(users))
	for i, user := range users {
		sanitizedUsers[i] = map[string]interface{}{
			"user_id":            user.UserID,
			"username":           user.Username,
			"full_name":          user.FullName,
			"phone_hash":         user.PhoneHash,
			"kyc_status":         user.KYCStatus,
			"kyc_level":          user.KYCLevel,
			"is_verified":        user.IsVerified,
			"is_active":          user.IsActive,
			"data_region":        user.DataRegion,
			"created_at":         user.CreatedAt,
			"updated_at":         user.UpdatedAt,
			"last_login":         user.LastLogin,
			"device_id":          user.DeviceID,
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
}

// ============================
// TOKEN & SESSION HANDLERS
// ============================

// RefreshAdminTokens refreshes the access token using a refresh token.
// @Summary Refresh admin tokens
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Refresh token" example({"refresh_token":"..."})
// @Success 200 {object} map[string]interface{} "New token pair"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid refresh token"
// @Router /api/v1/admin-auth/refresh [post]
func (h *AdminHandler) RefreshAdminTokens(w http.ResponseWriter, r *http.Request) {
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

	h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Admin tokens refreshed successfully"))
}

// LogoutAdmin invalidates the refresh token.
// @Summary Logout admin
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Refresh token" example({"refresh_token":"..."})
// @Success 200 {object} map[string]interface{} "Logged out"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/admin-auth/logout [post]
func (h *AdminHandler) LogoutAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin logged out successfully"))
}

// ============================
// HEALTH & STATS
// ============================

// HealthCheck returns the health status of the admin service.
// @Summary Admin health check
// @Tags admin-health
// @Produce json
// @Success 200 {object} map[string]interface{} "Service healthy"
// @Failure 503 {object} map[string]interface{} "Service unhealthy"
// @Router /api/v1/admin-auth/health [get]
func (h *AdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if err := h.adminService.HealthCheck(ctx); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "admin",
	}, "Admin service is healthy"))
}

// GetStats returns system statistics for admins.
// @Summary Get admin stats
// @Tags admin-stats
// @Produce json
// @Success 200 {object} map[string]interface{} "Statistics"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/stats [get]
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	stats, err := h.adminService.GetStats(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin statistics retrieved successfully"))
}

// ============================
// ADMIN MPIN ADMINISTRATION
// ============================

// ChangeAdminMPINByAdmin allows one admin to change another's MPIN (super-admin/manager only).
// @Summary Change admin MPIN by admin
// @Tags admin-auth
// @Accept json
// @Produce json
// @Param body body object true "Change request" example({"admin_id":"...","new_mpin":"123456","reason":"Reset due to security"})
// @Success 200 {object} map[string]interface{} "MPIN changed"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/mpin/change-by-admin [post]
func (h *AdminHandler) ChangeAdminMPINByAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		AdminID string `json:"admin_id" validate:"required"`
		NewMPIN string `json:"new_mpin" validate:"required,min=6,max=8"`
		Reason  string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.NewMPIN = util.SanitizeInput(req.NewMPIN)
	req.Reason = util.SanitizeInput(req.Reason)

	adminID, err := uuid.Parse(req.AdminID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	changeReq := &service.AdminMPINAdminChangeRequest{
		AdminID:   adminID,
		NewMPIN:   req.NewMPIN,
		ChangedBy: requesterID,
		Reason:    req.Reason,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if err := h.mpinService.ChangeAdminMPINByAdmin(ctx, changeReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "Admin MPIN changed successfully by administrator",
	}, "Admin MPIN change by admin successful"))
}

// ============================
// ADMIN WITH PERMISSIONS
// ============================

// GetAdminWithPermissions returns an admin with their permissions.
// @Summary Get admin with permissions
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin with permissions"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/with-permissions [get]
func (h *AdminHandler) GetAdminWithPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	adminWithPerms, err := h.adminService.GetAdminWithPermissions(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(adminWithPerms, "Admin with permissions retrieved successfully"))
}

// ============================
// ADMIN ROLE DEPARTMENT MANAGEMENT
// ============================

// GetAdminRoleDepartments retrieves departments associated with an admin role.
// @Summary Get admin role departments
// @Tags admin-roles
// @Produce json
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "List of departments"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/{roleID}/departments [get]
func (h *AdminHandler) GetAdminRoleDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	departments, err := h.adminService.GetAdminRoleDepartments(ctx, roleID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(departments, "Admin role departments retrieved successfully"))
}

// AssignDepartmentToAdminRole assigns a department to an admin role.
// @Summary Assign department to admin role
// @Tags admin-roles
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body object true "Department ID" example({"department_id":"..."})
// @Success 200 {object} map[string]interface{} "Department assigned"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/{roleID}/departments/{departmentID} [post]
func (h *AdminHandler) AssignDepartmentToAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	var req struct {
		DepartmentID string `json:"department_id" validate:"required,uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	departmentID, err := uuid.Parse(req.DepartmentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	if err := h.adminService.AssignDepartmentToAdminRole(ctx, roleID, departmentID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department assigned to admin role successfully"))
}

// RemoveDepartmentFromAdminRole removes a department from an admin role.
// @Summary Remove department from admin role
// @Tags admin-roles
// @Param roleID path string true "Role UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Department removed"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/{roleID}/departments/{departmentID} [delete]
func (h *AdminHandler) RemoveDepartmentFromAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	if err := h.adminService.RemoveDepartmentFromAdminRole(ctx, roleID, departmentID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department removed from admin role successfully"))
}

// ============================
// BULK & LIST OPERATIONS
// ============================

// BulkUpdateReportsTo updates the reports-to manager for multiple admins.
// @Summary Bulk update reports_to
// @Tags admin-hierarchy
// @Accept json
// @Produce json
// @Param body body object true "Bulk update" example({"admin_ids":["id1","id2"],"reports_to":"manager-id"})
// @Success 200 {object} map[string]interface{} "Update successful"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/bulk-update-reports-to [post]
func (h *AdminHandler) BulkUpdateReportsTo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req struct {
		AdminIDs  []string `json:"admin_ids" validate:"required,min=1"`
		ReportsTo *string  `json:"reports_to,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	adminIDs := make([]uuid.UUID, len(req.AdminIDs))
	for i, adminIDStr := range req.AdminIDs {
		adminID, err := uuid.Parse(adminIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, fmt.Sprintf("Invalid admin ID at index %d", i))
			return
		}
		adminIDs[i] = adminID
	}

	var reportsToUUID *uuid.UUID
	if req.ReportsTo != nil && *req.ReportsTo != "" {
		reportsTo, err := uuid.Parse(*req.ReportsTo)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid reports_to UUID format")
			return
		}
		reportsToUUID = &reportsTo
	}

	if err := h.adminService.BulkUpdateReportsTo(ctx, adminIDs, reportsToUUID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Bulk reports_to update successful"))
}

// GetAdminsByRole retrieves admins assigned to a specific role.
// @Summary Get admins by role
// @Tags admin-users
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/role/{roleID} [get]
func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	admins, err := h.adminService.GetAdminsByRole(ctx, roleID, limit, offset, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": admins,
		"meta": map[string]interface{}{
			"role_id": roleID.String(),
			"limit":   limit,
			"offset":  offset,
			"count":   len(admins),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins by role retrieved successfully"))
}

// GetAdminsByRoleType retrieves admins by role type (employee/manager).
// @Summary Get admins by role type
// @Tags admin-users
// @Produce json
// @Param roleType path int true "Role type (1=employee, 2=manager, 3=super admin)"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Param include_inactive query bool false "Include inactive admins"
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid role type"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/role-type/{roleType} [get]
func (h *AdminHandler) GetAdminsByRoleType(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleTypeStr := chi.URLParam(r, "roleType")
	roleType, err := strconv.Atoi(roleTypeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role type")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)
	includeInactive := h.getBoolQueryParam(r, "include_inactive", false)

	admins, err := h.adminService.GetAdminsByRoleType(ctx, roleType, requesterID, includeInactive, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": admins,
		"meta": map[string]interface{}{
			"role_type":        roleType,
			"include_inactive": includeInactive,
			"limit":            limit,
			"offset":           offset,
			"count":            len(admins),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins by role type retrieved successfully"))
}

// GetAvailableManagers returns managers available to be assigned as reports_to.
// @Summary Get available managers
// @Tags admin-hierarchy
// @Produce json
// @Param exclude_id query string false "Admin ID to exclude"
// @Success 200 {object} map[string]interface{} "List of managers"
// @Failure 400 {object} map[string]interface{} "Invalid exclude_id"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/available-managers [get]
func (h *AdminHandler) GetAvailableManagers(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var excludeID *uuid.UUID
	if excludeIDStr := r.URL.Query().Get("exclude_id"); excludeIDStr != "" {
		excludeUUID, err := uuid.Parse(excludeIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid exclude_id")
			return
		}
		excludeID = &excludeUUID
	}

	managers, err := h.adminService.GetAvailableManagers(ctx, excludeID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(managers, "Available managers retrieved successfully"))
}

// GetAdminWithReportsToName returns an admin with the reports-to name included.
// @Summary Get admin with reports_to name
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin with reports_to name"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/with-reports-to-name [get]
func (h *AdminHandler) GetAdminWithReportsToName(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	admin, err := h.adminService.GetAdminWithReportsToName(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin with reports_to name retrieved successfully"))
}

// GetAdminWithDetails returns admin with permissions and department names.
// @Summary Get admin with details
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Admin with permission and department names"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/details [get]
func (h *AdminHandler) GetAdminWithDetails(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
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

	admin, permissionNames, departmentNames, err := h.adminService.GetAdminWithDetails(ctx, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admin":            admin,
		"permission_names": permissionNames,
		"department_names": departmentNames,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin with details retrieved successfully"))
}

// ============================
// AVATAR INFO HANDLERS
// ============================

// GetAvatarInfo retrieves avatar metadata for an admin.
// @Summary Get avatar info
// @Tags admin-avatar
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Avatar metadata"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 404 {object} map[string]interface{} "Avatar not found"
// @Router /api/v1/admin/admins/{adminID}/avatar/info [get]
func (h *AdminHandler) GetAvatarInfo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatarInfo, err := h.adminService.GetAvatarInfo(ctx, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(avatarInfo, "Avatar info retrieved successfully"))
}

// BulkGetAvatarInfo retrieves avatar info for multiple admins.
// @Summary Bulk get avatar info
// @Tags admin-avatar
// @Accept json
// @Produce json
// @Param body body object true "Admin IDs" example({"admin_ids":["id1","id2"]})
// @Success 200 {object} map[string]interface{} "Avatar info list"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/bulk-avatar-info [post]
func (h *AdminHandler) BulkGetAvatarInfo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	var req struct {
		AdminIDs []string `json:"admin_ids" validate:"required,min=1,max=100"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	adminIDs := make([]uuid.UUID, len(req.AdminIDs))
	for i, adminIDStr := range req.AdminIDs {
		adminID, err := uuid.Parse(adminIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, fmt.Sprintf("Invalid admin ID at index %d", i))
			return
		}
		adminIDs[i] = adminID
	}

	avatarInfos, err := h.adminService.BulkGetAvatarInfo(ctx, adminIDs)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"avatar_infos": avatarInfos,
		"meta": map[string]interface{}{
			"requested_count": len(adminIDs),
			"retrieved_count": len(avatarInfos),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Bulk avatar info retrieved successfully"))
}

// ============================
// PERMISSION CHECK HANDLERS
// ============================

// CheckAdminPermission checks if an admin has a specific permission.
// @Summary Check admin permission
// @Tags admin-permissions
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param permission query string true "Permission name"
// @Success 200 {object} map[string]interface{} "Permission check result"
// @Failure 400 {object} map[string]interface{} "Missing permission parameter"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/permissions/check [get]
func (h *AdminHandler) CheckAdminPermission(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	permissionName := r.URL.Query().Get("permission")
	if permissionName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Permission name is required")
		return
	}

	if requesterID != adminID {
		requesterAdmin, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !requesterAdmin.IsOwner() && !requesterAdmin.IsSuperEmployee() {
			h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot check permissions for other admins")
			return
		}
	}

	hasPermission, err := h.adminService.CheckAdminPermission(ctx, adminID, permissionName)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"has_permission": hasPermission,
		"permission":     permissionName,
		"admin_id":       adminID.String(),
	}, "Permission check completed"))
}

// ============================
// PERMISSION MASK & REPORTS
// ============================

// GetAdminPermissionMask retrieves the permission bitmask for an admin.
// @Summary Get admin permission mask
// @Tags admin-permissions
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Permission mask with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/permissions/mask [get]
func (h *AdminHandler) GetAdminPermissionMask(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot view permission mask for this admin")
				return
			}
		}
	}

	permissionMask, err := h.adminService.GetAdminPermissionMask(ctx, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"permission_mask": permissionMask,
		"segments":        len(permissionMask),
		"total_bits":      len(permissionMask) * 64,
		"admin_id":        adminID.String(),
	}, "Permission mask retrieved successfully"))
}

// CanAssignReportsTo checks if an admin can assign reports to a target admin.
// @Summary Check if assigner can assign reports to target
// @Tags admin-hierarchy
// @Produce json
// @Param assignerID path string true "Assigner admin UUID"
// @Param targetID path string true "Target admin UUID"
// @Success 200 {object} map[string]interface{} "Result with reason"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{assignerID}/can-assign/{targetID} [get]
func (h *AdminHandler) CanAssignReportsTo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	assignerIDStr := chi.URLParam(r, "assignerID")
	assignerID, err := uuid.Parse(assignerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid assigner admin ID")
		return
	}

	targetIDStr := chi.URLParam(r, "targetID")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid target admin ID")
		return
	}

	if requesterID != assignerID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot check assign permissions for other admins")
			return
		}
	}

	canAssign, err := h.adminService.CanAssignReportsTo(ctx, assignerID, targetID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"can_assign":  canAssign,
		"assigner_id": assignerID.String(),
		"target_id":   targetID.String(),
		"reason":      getCanAssignReason(canAssign),
	}, "Assign permissions check completed"))
}

// ResetAdminFailedLoginAttempts resets failed login attempts for an admin.
// @Summary Reset admin failed login attempts
// @Tags admin-auth
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Reset confirmation"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/reset-failed-login [post]
func (h *AdminHandler) ResetAdminFailedLoginAttempts(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot reset failed login attempts for this admin")
				return
			}
		}
	}

	if err := h.adminService.ResetAdminFailedLoginAttempts(ctx, adminID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message":  "Failed login attempts reset successfully",
		"admin_id": adminID.String(),
	}, "Failed login attempts reset"))
}

// CheckAdminDepartmentAccess checks if an admin has access to a specific department.
// @Summary Check admin department access
// @Tags admin-permissions
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param department path string true "Department name"
// @Success 200 {object} map[string]interface{} "Access result"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/department-access/{department} [get]
func (h *AdminHandler) CheckAdminDepartmentAccess(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	departmentName := chi.URLParam(r, "department")
	if departmentName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Department name is required")
		return
	}

	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot check department access for this admin")
				return
			}
		}
	}

	hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, adminID, departmentName)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"has_access": hasAccess,
		"department": departmentName,
		"admin_id":   adminID.String(),
	}, "Department access check completed"))
}

// ============================
// HELPER FUNCTIONS (internal)
// ============================

// canManageAdmin determines if a manager can manage a target admin.
func (h *AdminHandler) canManageAdmin(manager, target *models.AdminUser) bool {
	if manager.IsOwner() {
		return true
	}
	if manager.IsSuperEmployee() && target.IsEmployee() {
		return true
	}
	if manager.IsManager() && target.IsEmployee() {
		return true
	}
	return false
}

// getCanAssignReason returns a human-readable reason for the assign permission result.
func getCanAssignReason(canAssign bool) string {
	if canAssign {
		return "Assigner has sufficient permissions and hierarchy allows"
	}
	return "Assigner lacks permissions or hierarchy violation"
}

// ============================
// ADMIN SEARCH HANDLERS
// ============================

// SearchAdminsWithFilters performs an admin search with filters.
// @Summary Search admins with filters
// @Tags admin-search
// @Produce json
// @Param q query string false "Search query"
// @Param search_type query string false "Search type (all/partial/fulltext)" default(all)
// @Param role_type query int false "Filter by role type"
// @Param include_inactive query bool false "Include inactive admins"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search [get]
func (h *AdminHandler) SearchAdminsWithFilters(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("search_type")
	if searchType == "" {
		searchType = "all"
	}
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	includeInactive := false
	if inactiveParam := r.URL.Query().Get("include_inactive"); inactiveParam != "" {
		includeInactive = inactiveParam == "true"
	}

	var roleTypeFilter *int
	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
		rt, err := strconv.Atoi(roleTypeStr)
		if err == nil {
			roleTypeFilter = &rt
		}
	}

	req := &models.AdminSearchRequest{
		Query:           query,
		SearchType:      searchType,
		RoleTypeFilter:  roleTypeFilter,
		IncludeInactive: includeInactive,
		Limit:           limit,
		Offset:          offset,
	}

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin search completed successfully"))
}

// GetAdminsByDepartment retrieves admins belonging to a department.
// @Summary Get admins by department
// @Tags admin-users
// @Produce json
// @Param departmentID path string true "Department UUID"
// @Param include_inactive query bool false "Include inactive admins"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid department ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/departments/{departmentID}/admins [get]
func (h *AdminHandler) GetAdminsByDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
		return
	}

	includeInactive := h.getBoolQueryParam(r, "include_inactive", false)
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	admins, total, err := h.adminService.GetAdminsByDepartment(ctx, departmentID, requesterID, includeInactive, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": admins,
		"meta": map[string]interface{}{
			"department_id": departmentID.String(),
			"total":         total,
			"limit":         limit,
			"offset":        offset,
			"count":         len(admins),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins by department retrieved successfully"))
}

// SearchAdmins performs a simple admin search (alias for SearchAdminsWithFilters with default parameters).
// @Summary Search admins (basic)
// @Tags admin-search
// @Produce json
// @Param q query string true "Search query"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Param search_type query string false "Search type (partial/fulltext)" default(partial)
// @Param include_inactive query bool false "Include inactive admins"
// @Param role_type query int false "Filter by role type"
// @Success 200 {object} map[string]interface{} "Search results"
// @Failure 400 {object} map[string]interface{} "Missing query"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search [get]
func (h *AdminHandler) SearchAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Search query is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)
	searchType := r.URL.Query().Get("search_type")
	if searchType == "" {
		searchType = "partial"
	}

	req := &models.AdminSearchRequest{
		Query:           query,
		SearchType:      searchType,
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: h.getBoolQueryParam(r, "include_inactive", false),
	}
	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
		roleType, err := strconv.Atoi(roleTypeStr)
		if err == nil {
			req.RoleTypeFilter = &roleType
		}
	}

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"results": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin search completed successfully"))
}

// SearchAdminsAdvanced performs an advanced search with multiple filters.
// @Summary Advanced admin search
// @Tags admin-search
// @Produce json
// @Param q query string false "Search query"
// @Param role_id query string false "Filter by role ID"
// @Param department_id query string false "Filter by department ID"
// @Param reports_to query string false "Filter by reports-to admin ID"
// @Param created_after query string false "Filter by creation date (RFC3339)"
// @Param created_before query string false "Filter by creation date (RFC3339)"
// @Param sort_by query string false "Sort field" default(relevance)
// @Param sort_order query string false "Sort order (asc/desc)" default(desc)
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/advanced [get]
func (h *AdminHandler) SearchAdminsAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var filters models.AdminSearchFilter
	if roleIDStr := r.URL.Query().Get("role_id"); roleIDStr != "" {
		roleID, err := uuid.Parse(roleIDStr)
		if err == nil {
			filters.RoleID = &roleID
		}
	}
	if deptIDStr := r.URL.Query().Get("department_id"); deptIDStr != "" {
		deptID, err := uuid.Parse(deptIDStr)
		if err == nil {
			filters.DepartmentID = &deptID
		}
	}
	if reportsToStr := r.URL.Query().Get("reports_to"); reportsToStr != "" {
		reportsTo, err := uuid.Parse(reportsToStr)
		if err == nil {
			filters.ReportsTo = &reportsTo
		}
	}
	if createdAfterStr := r.URL.Query().Get("created_after"); createdAfterStr != "" {
		createdAfter, err := time.Parse(time.RFC3339, createdAfterStr)
		if err == nil {
			filters.CreatedAfter = &createdAfter
		}
	}
	if createdBeforeStr := r.URL.Query().Get("created_before"); createdBeforeStr != "" {
		createdBefore, err := time.Parse(time.RFC3339, createdBeforeStr)
		if err == nil {
			filters.CreatedBefore = &createdBefore
		}
	}

	req := &models.AdminAdvancedSearchRequest{
		Query:     r.URL.Query().Get("q"),
		Filters:   filters,
		Limit:     h.getIntQueryParam(r, "limit", 50),
		Offset:    h.getIntQueryParam(r, "offset", 0),
		SortBy:    r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}
	if req.SortBy == "" {
		req.SortBy = "relevance"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	results, total, err := h.adminService.SearchAdminsAdvanced(ctx, requesterID, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"results": results,
		"meta": map[string]interface{}{
			"total":      total,
			"limit":      req.Limit,
			"offset":     req.Offset,
			"count":      len(results),
			"sort_by":    req.SortBy,
			"sort_order": req.SortOrder,
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Advanced admin search completed"))
}

// ============================
// SYSTEM & PERMISSION HANDLERS
// ============================

// GetSystemDepartments retrieves system-level departments.
// @Summary Get system departments
// @Tags admin-system
// @Produce json
// @Success 200 {object} map[string]interface{} "List of system departments"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/system/departments [get]
func (h *AdminHandler) GetSystemDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	systemDepts, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(systemDepts, "System departments retrieved successfully"))
}

// GetPermissionsByModule retrieves permissions for a specific module.
// @Summary Get permissions by module
// @Tags admin-system
// @Produce json
// @Param module path string true "Module name"
// @Success 200 {object} map[string]interface{} "Permissions with metadata"
// @Failure 400 {object} map[string]interface{} "Missing module"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/system/permissions/module/{module} [get]
func (h *AdminHandler) GetPermissionsByModule(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	module := chi.URLParam(r, "module")
	if module == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Module is required")
		return
	}

	permissions, err := h.companyService.GetPermissionsByModule(ctx, module)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// GetAllPermissions retrieves all available permissions with optional filters.
// @Summary Get all permissions
// @Tags admin-system
// @Produce json
// @Param module query string false "Filter by module"
// @Param category query string false "Filter by category"
// @Param tier query string false "Filter by tier"
// @Success 200 {object} map[string]interface{} "Permissions with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/system/permissions [get]
func (h *AdminHandler) GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	module := r.URL.Query().Get("module")
	category := r.URL.Query().Get("category")
	tier := r.URL.Query().Get("tier")

	permissions, err := h.companyService.GetAllPermissions(ctx, module, category, tier)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
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
}

// ============================
// ADDITIONAL SEARCH HANDLERS
// ============================

// SearchAdminsByName searches admins by name.
// @Summary Search admins by name
// @Tags admin-search
// @Produce json
// @Param name query string true "Name to search"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 400 {object} map[string]interface{} "Missing name"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/name [get]
func (h *AdminHandler) SearchAdminsByName(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Name is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminsByName(ctx, name, requesterID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins found by name"))
}

// SearchAdminEmployees searches employee-type admins.
// @Summary Search admin employees
// @Tags admin-search
// @Produce json
// @Param q query string false "Search query"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/employees [get]
func (h *AdminHandler) SearchAdminEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminEmployees(ctx, query, requesterID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin employees found"))
}

// SearchAdminManagers searches manager-type admins.
// @Summary Search admin managers
// @Tags admin-search
// @Produce json
// @Param q query string false "Search query"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/search/managers [get]
func (h *AdminHandler) SearchAdminManagers(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminManagers(ctx, query, requesterID, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin managers found"))
}

// ============================
// UTILITY HELPERS (internal)
// ============================

// sanitizeUserForAdmin removes sensitive fields from a user object.
func (h *AdminHandler) sanitizeUserForAdmin(u *models.User) {
	if u == nil {
		return
	}
	u.PhoneEncrypted = nil
	u.PhoneKeyID = uuid.Nil
	u.PhoneEncryptedDEK = ""
}

// maskPhoneNumber masks a phone number for display.
func maskPhoneNumber(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}
	return "****" + phone[len(phone)-4:]
}

// ============================
// SUPER ADMIN HANDLERS
// ============================

// InitSuperAdminHandler initializes the default super admin if none exists.
// @Summary Initialize super admin
// @Tags admin-setup
// @Produce json
// @Success 200 {object} map[string]interface{} "Super admin status"
// @Failure 500 {object} map[string]interface{} "Initialization failed"
// @Router /api/v1/setup/super-admin [post]
func (h *AdminHandler) InitSuperAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	existingAdmin, err := h.adminService.GetSuperAdmin(ctx)
	if err == nil && existingAdmin != nil {
		h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
			"super_admin_exists": true,
			"admin_id":           existingAdmin.AdminID.String(),
			"username":           existingAdmin.Username,
			"full_name":          existingAdmin.FullName,
			"role_type":          existingAdmin.RoleType,
			"role_string":        existingAdmin.GetRoleString(),
			"is_active":          existingAdmin.IsActive,
			"created_at":         existingAdmin.AdminCreatedAt,
			"message":            "Super admin already exists",
		}, "Super admin already initialized"))
		return
	}

	admin, err := h.adminService.InitDefaultSuperAdmin(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"super_admin_exists": true,
		"admin_id":           admin.AdminID.String(),
		"username":           admin.Username,
		"full_name":          admin.FullName,
		"role_type":          admin.RoleType,
		"role_string":        admin.GetRoleString(),
		"phone_number":       "+917206583437",
		"is_active":          admin.IsActive,
		"created_at":         admin.AdminCreatedAt,
		"message":            "Default super admin (Sarvesh Chhabra) initialized successfully",
	}, "Super admin initialization complete"))
}

// CheckSuperAdminStatusHandler checks if a super admin exists.
// @Summary Check super admin status
// @Tags admin-setup
// @Produce json
// @Success 200 {object} map[string]interface{} "Status with admin info if exists"
// @Failure 500 {object} map[string]interface{} "Internal error"
// @Router /api/v1/setup/super-admin/status [get]
func (h *AdminHandler) CheckSuperAdminStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	initialized, admin, err := h.adminService.CheckAndInitSuperAdmin(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	var adminInfo map[string]interface{}
	if admin != nil {
		adminInfo = map[string]interface{}{
			"admin_id":    admin.AdminID.String(),
			"username":    admin.Username,
			"full_name":   admin.FullName,
			"role_type":   admin.RoleType,
			"role_string": admin.GetRoleString(),
			"is_active":   admin.IsActive,
			"created_at":  admin.AdminCreatedAt,
		}
	}

	response := map[string]interface{}{
		"super_admin_exists": admin != nil,
		"initialized":        initialized,
		"admin":              adminInfo,
		"message":            getSuperAdminStatusMessage(initialized, admin),
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Super admin status retrieved"))
}

// getSuperAdminStatusMessage returns a status message based on super admin existence.
func getSuperAdminStatusMessage(initialized bool, admin *models.AdminUser) string {
	if admin == nil {
		return "Super admin does not exist"
	}
	if initialized {
		return "Super admin was just initialized"
	}
	return "Super admin already exists"
}

// HealthCheckHandler performs a health check on the service.
// @Summary Service health check
// @Tags admin-health
// @Produce json
// @Success 200 {object} map[string]interface{} "Service healthy"
// @Failure 503 {object} map[string]interface{} "Service unhealthy"
// @Router /api/v1/health [get]
func (h *AdminHandler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if err := h.adminService.HealthCheck(ctx); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	exists, _, _ := h.adminService.CheckAndInitSuperAdmin(ctx)
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"status":            "healthy",
		"service":           "auth-service",
		"super_admin_setup": exists,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	}, "Service is healthy"))
}

// ============================
// ADMIN ROLE DETAILS HANDLERS
// ============================

// GetAdminRoleWithDetails retrieves a role with its departments and permissions.
// @Summary Get admin role with details
// @Tags admin-roles
// @Produce json
// @Param roleID path string true "Role UUID"
// @Success 200 {object} map[string]interface{} "Role with departments and permissions"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/{roleID}/details [get]
func (h *AdminHandler) GetAdminRoleWithDetails(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	role, departments, permissions, err := h.adminService.GetAdminRoleWithDetails(ctx, roleID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"role":        role,
		"departments": departments,
		"permissions": permissions,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin role details retrieved successfully"))
}

// GetEmployeeAdminRoles retrieves all employee-type admin roles.
// @Summary Get employee admin roles
// @Tags admin-roles
// @Produce json
// @Success 200 {object} map[string]interface{} "List of employee roles"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/employee [get]
func (h *AdminHandler) GetEmployeeAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roles, err := h.adminService.GetEmployeeAdminRoles(ctx, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"count":     len(roles),
			"role_type": "employee",
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employee admin roles retrieved successfully"))
}

// GetManagerAdminRoles retrieves all manager-type admin roles.
// @Summary Get manager admin roles
// @Tags admin-roles
// @Produce json
// @Success 200 {object} map[string]interface{} "List of manager roles"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/manager [get]
func (h *AdminHandler) GetManagerAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roles, err := h.adminService.GetManagerAdminRoles(ctx, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"count":     len(roles),
			"role_type": "manager",
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Manager admin roles retrieved successfully"))
}

// GetAdminRolesByType retrieves admin roles by role type.
// @Summary Get admin roles by type
// @Tags admin-roles
// @Produce json
// @Param roleType path int true "Role type (1=employee, 2=manager, 3=super admin)"
// @Success 200 {object} map[string]interface{} "Roles with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid role type"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/roles/type/{roleType} [get]
func (h *AdminHandler) GetAdminRolesByType(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roleTypeStr := chi.URLParam(r, "roleType")
	roleType, err := strconv.Atoi(roleTypeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role type. Must be an integer")
		return
	}

	validRoleTypes := []int{models.RoleTypeEmployee, models.RoleTypeManager, models.RoleTypeSuperAdmin}
	isValid := false
	for _, validType := range validRoleTypes {
		if roleType == validType {
			isValid = true
			break
		}
	}
	if !isValid {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role type must be 1 (employee), 2 (manager), or 3 (super admin)")
		return
	}

	roles, err := h.adminService.GetAdminRolesByType(ctx, roleType, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	roleTypeString := ""
	switch roleType {
	case models.RoleTypeEmployee:
		roleTypeString = "employee"
	case models.RoleTypeManager:
		roleTypeString = "manager"
	case models.RoleTypeSuperAdmin:
		roleTypeString = "super_admin"
	default:
		roleTypeString = "unknown"
	}

	response := map[string]interface{}{
		"roles": roles,
		"meta": map[string]interface{}{
			"count":            len(roles),
			"role_type":        roleType,
			"role_type_string": roleTypeString,
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin roles by type retrieved successfully"))
}

// ============================
// ADMIN LISTING HANDLERS
// ============================

// ListAdmins lists admins with optional filters (alias for SearchAdminsWithFilters).
// @Summary List admins
// @Tags admin-users
// @Produce json
// @Param query query string false "Search query"
// @Param role_type query int false "Filter by role type"
// @Param include_inactive query bool false "Include inactive admins"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Admins with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins [get]
func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	req := &models.AdminSearchRequest{
		Query:           r.URL.Query().Get("query"),
		SearchType:      "fulltext",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: h.getBoolQueryParam(r, "include_inactive", false),
	}
	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
		roleType, err := strconv.Atoi(roleTypeStr)
		if err == nil {
			req.RoleTypeFilter = &roleType
		}
	}

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins listed successfully"))
}

// GetAllAdmins retrieves all admins (including inactive).
// @Summary Get all admins
// @Tags admin-users
// @Produce json
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "All admins with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/all [get]
func (h *AdminHandler) GetAllAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: true,
	})
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "All admins retrieved successfully"))
}

// GetActiveAdmins retrieves only active admins.
// @Summary Get active admins
// @Tags admin-users
// @Produce json
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Active admins with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/active [get]
func (h *AdminHandler) GetActiveAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: false,
	})
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"admins": results,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(results),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Active admins retrieved successfully"))
}

// ============================
// INACTIVE ADMINS
// ============================

// GetInactiveAdmins retrieves all inactive admins.
// @Summary Get inactive admins
// @Tags admin-users
// @Produce json
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Inactive admins with metadata"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/inactive [get]
func (h *AdminHandler) GetInactiveAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: true,
	})
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	var inactiveAdmins []*models.AdminUserSearchResult
	for _, admin := range results {
		if !admin.IsActive {
			inactiveAdmins = append(inactiveAdmins, admin)
		}
	}

	totalInactive := 0
	if total > 0 {
		allResults, _, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
			Query:           "",
			SearchType:      "all",
			Limit:           1000,
			Offset:          0,
			IncludeInactive: true,
		})
		if err == nil {
			for _, admin := range allResults {
				if !admin.IsActive {
					totalInactive++
				}
			}
		} else {
			totalInactive = int(float64(len(inactiveAdmins)) / float64(len(results)) * float64(total))
		}
	}

	response := map[string]interface{}{
		"admins": inactiveAdmins,
		"meta": map[string]interface{}{
			"total":  totalInactive,
			"limit":  limit,
			"offset": offset,
			"count":  len(inactiveAdmins),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Inactive admins retrieved successfully"))
}

// ============================
// EMPLOYEE & MANAGER ROLE CREATION
// ============================

// CreateEmployeeRole creates a new employee-type admin role.
// @Summary Create employee role
// @Tags admin-roles
// @Accept json
// @Produce json
// @Param body body models.EmployeeRoleCreateRequest true "Employee role details"
// @Success 201 {object} map[string]interface{} "Role created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Role name already exists"
// @Router /api/v1/admin/roles/employee [post]
func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req models.EmployeeRoleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
	if err != nil {
		// Ignore "not found" errors, treat others as internal
		if !strings.Contains(err.Error(), "admin role not found") && !strings.Contains(err.Error(), "admin role is nil") {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
	} else if existingRole != nil {
		h.respondWithError(w, http.StatusConflict, customErrors.ErrDuplicate, "Role name already exists")
		return
	}

	internalReq := models.AdminRoleCreateRequest{
		RoleName:    req.RoleName,
		RoleType:    models.RoleTypeEmployee,
		Description: req.Description,
	}

	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	deptMap := make(map[string]*models.SystemDepartment)
	departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentPermissions))

	for _, deptPerm := range req.DepartmentPermissions {
		dept, exists := deptMap[deptPerm.DepartmentName]
		if !exists {
			found := false
			for _, sysDept := range systemDepartments {
				if sysDept.Name == deptPerm.DepartmentName {
					dept = sysDept
					deptMap[deptPerm.DepartmentName] = sysDept
					found = true
					break
				}
			}
			if !found {
				h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
				return
			}
		}

		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
		if err != nil {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
		validPerms := make(map[string]bool)
		for _, perm := range permissions {
			validPerms[perm.PermissionName] = true
		}
		for _, permName := range deptPerm.Permissions {
			if !validPerms[permName] {
				h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, fmt.Sprintf("Permission %s does not exist in department %s (module: %s)", permName, deptPerm.DepartmentName, dept.ModuleCode))
				return
			}
		}
		departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
	}
	internalReq.DepartmentIDs = departmentIDs

	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		// Override if duplicate role name
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
			msg = "Role name already exists"
		}
		h.respondWithError(w, status, err, msg)
		return
	}

	// Grant permissions per department
	for _, deptPerm := range req.DepartmentPermissions {
		dept := deptMap[deptPerm.DepartmentName]
		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
		if err != nil {
			// non-critical, continue
			continue
		}
		permMap := make(map[string]uuid.UUID)
		for _, perm := range permissions {
			permMap[perm.PermissionName] = perm.PermissionID
		}
		for _, permName := range deptPerm.Permissions {
			permID, exists := permMap[permName]
			if !exists {
				continue
			}
			_ = h.adminService.GrantPermissionToAdminRole(ctx, role.AdminRoleID, permID, requesterID)
		}
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
}

// CreateManagerRole creates a new manager-type admin role.
// @Summary Create manager role
// @Tags admin-roles
// @Accept json
// @Produce json
// @Param body body models.ManagerRoleCreateRequest true "Manager role details"
// @Success 201 {object} map[string]interface{} "Role created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Role name already exists"
// @Router /api/v1/admin/roles/manager [post]
func (h *AdminHandler) CreateManagerRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req models.ManagerRoleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.RoleName == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Role name is required")
		return
	}
	if len(req.DepartmentNames) == 0 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "At least one department is required")
		return
	}

	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
	if err != nil {
		if !strings.Contains(err.Error(), "admin role not found") && !strings.Contains(err.Error(), "admin role is nil") {
			status, msg := h.mapServiceError(err)
			h.respondWithError(w, status, err, msg)
			return
		}
	} else if existingRole != nil {
		h.respondWithError(w, http.StatusConflict, customErrors.ErrDuplicate, fmt.Sprintf("Role '%s' already exists", req.RoleName))
		return
	}

	internalReq := models.AdminRoleCreateRequest{
		RoleName:    req.RoleName,
		RoleType:    models.RoleTypeManager,
		Description: req.Description,
	}

	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	deptIDMap := make(map[string]uuid.UUID)
	for _, dept := range systemDepartments {
		deptIDMap[dept.Name] = dept.SystemDepartmentID
	}
	for _, deptName := range req.DepartmentNames {
		deptID, exists := deptIDMap[deptName]
		if !exists {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, fmt.Sprintf("Department '%s' does not exist", deptName))
			return
		}
		internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, deptID)
	}

	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Manager role created successfully"))
}

// ============================
// ADMIN PHONE NUMBER
// ============================

// GetAdminPhoneNumber retrieves the phone number of an admin (with masking).
// @Summary Get admin phone number
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "Phone number (masked and raw)"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/phone [get]
func (h *AdminHandler) GetAdminPhoneNumber(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	phoneNumber, err := h.adminService.GetAdminPhoneNumber(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	maskedPhone := maskPhoneNumber(phoneNumber)
	response := map[string]interface{}{
		"phone_number":     phoneNumber,
		"masked_phone":     maskedPhone,
		"admin_id":         adminID.String(),
		"accessed_by":      requesterID.String(),
		"access_timestamp": time.Now().UTC(),
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin phone number retrieved successfully"))
}

// ============================
// USER KYC & RECENT ACTIVITY
// ============================

// ListUsersByKYCStatus lists users by KYC status.
// @Summary List users by KYC status
// @Tags admin-user-management
// @Produce json
// @Param status path string true "KYC status (pending, verified, rejected, under_review, expired)"
// @Param limit query int false "Page size" default(100)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Users with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid status or limit"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/kyc/{status} [get]
func (h *AdminHandler) ListUsersByKYCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "KYC status is required")
		return
	}

	validStatuses := map[string]bool{
		"pending": true, "verified": true, "rejected": true,
		"under_review": true, "expired": true,
	}
	if !validStatuses[status] {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Invalid KYC status. Must be: pending, verified, rejected, under_review, or expired")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)
	if limit <= 0 || limit > 1000 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Limit must be between 1 and 1000")
		return
	}

	users, total, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, offset)
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	sanitizedUsers := make([]map[string]interface{}, len(users))
	for i, user := range users {
		sanitizedUsers[i] = h.sanitizeUserForAdminResponse(user)
	}

	response := map[string]interface{}{
		"users": sanitizedUsers,
		"meta": map[string]interface{}{
			"kyc_status": status,
			"total":      total,
			"limit":      limit,
			"offset":     offset,
			"count":      len(users),
			"has_more":   offset+limit < total,
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Users retrieved by KYC status"))
}

// GetRecentlyActiveUsers retrieves users active within the last N days.
// @Summary Get recently active users
// @Tags admin-user-management
// @Produce json
// @Param days query int false "Days threshold" default(7)
// @Param limit query int false "Page size" default(100)
// @Success 200 {object} map[string]interface{} "Users with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid days or limit"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/user-management/recently-active [get]
func (h *AdminHandler) GetRecentlyActiveUsers(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	days := h.getIntQueryParam(r, "days", 7)
	limit := h.getIntQueryParam(r, "limit", 100)
	if days <= 0 || days > 365 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Days must be between 1 and 365")
		return
	}
	if limit <= 0 || limit > 1000 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Limit must be between 1 and 1000")
		return
	}

	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	users, err := h.userService.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	sanitizedUsers := make([]map[string]interface{}, len(users))
	for i, user := range users {
		sanitizedUsers[i] = h.sanitizeUserForAdminResponse(user)
	}

	response := map[string]interface{}{
		"users": sanitizedUsers,
		"meta": map[string]interface{}{
			"days":         days,
			"since":        since.Format(time.RFC3339),
			"limit":        limit,
			"count":        len(users),
			"retrieved_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Recently active users retrieved"))
}

// ============================
// ADMIN DEPARTMENTS
// ============================

// GetAdminDepartments retrieves departments accessible to an admin.
// @Summary Get admin departments
// @Tags admin-users
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Success 200 {object} map[string]interface{} "List of departments"
// @Failure 400 {object} map[string]interface{} "Invalid admin ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/departments [get]
func (h *AdminHandler) GetAdminDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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

	departments, err := h.adminService.GetAdminDepartments(ctx, adminID, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"departments": departments,
		"meta": map[string]interface{}{
			"admin_id": adminID.String(),
			"count":    len(departments),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin departments retrieved successfully"))
}

// UpdateAdminUserRole updates the role of an admin user.
// @Summary Update admin user role
// @Tags admin-users
// @Accept json
// @Produce json
// @Param adminID path string true "Admin UUID"
// @Param body body object true "New role ID" example({"new_role_id":"..."})
// @Success 200 {object} map[string]interface{} "Role updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/admins/{adminID}/role [put]
func (h *AdminHandler) UpdateAdminUserRole(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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
		NewRoleID string `json:"new_role_id" validate:"required,uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	newRoleID, err := uuid.Parse(req.NewRoleID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	if err := h.adminService.UpdateAdminUserRole(ctx, adminID, newRoleID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user role updated successfully"))
}

// ============================
// POSITION HANDLERS
// ============================

// GetPosition retrieves a position by ID.
// @Summary Get position
// @Tags admin-positions
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param positionID path string true "Position UUID"
// @Success 200 {object} map[string]interface{} "Position details"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/positions/{positionID} [get]
func (h *AdminHandler) GetPosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
		return
	}

	position, err := h.companyService.GetPosition(ctx, positionID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	if position.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Position not found in this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(position, "Position retrieved successfully"))
}

// DeletePosition deletes a position.
// @Summary Delete position
// @Tags admin-positions
// @Param companyID path string true "Company UUID"
// @Param positionID path string true "Position UUID"
// @Success 200 {object} map[string]interface{} "Position deleted"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/positions/{positionID} [delete]
func (h *AdminHandler) DeletePosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
		return
	}

	existingPosition, err := h.companyService.GetPosition(ctx, positionID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if existingPosition.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot delete position in another company")
		return
	}

	if err := h.companyService.DeletePosition(ctx, positionID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Position deleted successfully"))
}

// ============================
// DEPARTMENT HIERARCHY HANDLERS
// ============================

// UpdateDepartmentParent updates the parent of a department.
// @Summary Update department parent
// @Tags admin-departments
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Param body body service.UpdateDepartmentParentRequest true "New parent ID"
// @Success 200 {object} map[string]interface{} "Parent updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/parent [put]
func (h *AdminHandler) UpdateDepartmentParent(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	var req service.UpdateDepartmentParentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.DepartmentID = departmentID

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot update department in another company")
		return
	}

	if err := h.companyService.UpdateDepartmentParent(ctx, &req, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department parent updated successfully"))
}

// GetDepartmentChildren retrieves child departments.
// @Summary Get department children
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "List of child departments"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/children [get]
func (h *AdminHandler) GetDepartmentChildren(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot access department in another company")
		return
	}

	children, err := h.companyService.GetDepartmentChildren(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(children, "Department children retrieved successfully"))
}

// GetDepartmentTree retrieves the full department tree.
// @Summary Get department tree
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Department tree"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/tree [get]
func (h *AdminHandler) GetDepartmentTree(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot access department in another company")
		return
	}

	tree, err := h.companyService.GetDepartmentTree(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(tree, "Department tree retrieved successfully"))
}

// GetDepartmentParents retrieves the parent chain of a department.
// @Summary Get department parents
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "List of parent departments"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/parents [get]
func (h *AdminHandler) GetDepartmentParents(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot access department in another company")
		return
	}

	parents, err := h.companyService.GetDepartmentParents(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(parents, "Department parents retrieved successfully"))
}

// MoveDepartmentWithEmployees moves a department along with its employees.
// @Summary Move department with employees
// @Tags admin-departments
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Param body body object true "New parent ID" example({"new_parent_department_id":"..."})
// @Success 200 {object} map[string]interface{} "Department moved"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/move [post]
func (h *AdminHandler) MoveDepartmentWithEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	var req struct {
		NewParentDepartmentID *uuid.UUID `json:"new_parent_department_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot move department in another company")
		return
	}

	if err := h.companyService.MoveDepartmentWithEmployees(ctx, departmentID, req.NewParentDepartmentID, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department moved successfully"))
}

// GetRootDepartments retrieves root departments of a company.
// @Summary Get root departments
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "List of root departments"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/root [get]
func (h *AdminHandler) GetRootDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	departments, err := h.companyService.GetRootDepartments(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(departments, "Root departments retrieved successfully"))
}

// ValidateDepartmentHierarchy validates if a department move would create a valid hierarchy.
// @Summary Validate department hierarchy
// @Tags admin-departments
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Param body body object true "New parent ID" example({"new_parent_department_id":"..."})
// @Success 200 {object} map[string]interface{} "Validation result"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/validate-hierarchy [post]
func (h *AdminHandler) ValidateDepartmentHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

	var req struct {
		NewParentDepartmentID *uuid.UUID `json:"new_parent_department_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	department, err := h.companyService.GetDepartment(ctx, departmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if department.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot validate department in another company")
		return
	}

	valid, err := h.companyService.ValidateDepartmentHierarchy(ctx, departmentID, req.NewParentDepartmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"is_valid": valid,
		"message":  "Department hierarchy validation completed",
	}
	if !valid {
		response["message"] = "Department move would create invalid hierarchy"
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Hierarchy validation completed"))
}

// ============================
// COMPANY INFO & DEPARTMENT QUOTA
// ============================

// GetCompanyByID retrieves a company by ID (alias for admin use).
// @Summary Get company by ID
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Company details"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/admin/companies/{companyID}/info [get]
func (h *AdminHandler) GetCompanyByID(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	company, err := h.companyService.GetCompanyByID(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    company,
	})
}

// GetActiveDepartmentCount returns the count of active departments in a company.
// @Summary Get active department count
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Active departments count"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/admin/companies/{companyID}/active-departments-count [get]
func (h *AdminHandler) GetActiveDepartmentCount(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	count, err := h.companyService.GetActiveDepartmentCount(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"active_departments": count,
		},
	})
}

// GetCompanyDepartmentInfo retrieves department quota and usage info for a company.
// @Summary Get company department info
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Department quota and usage"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/admin/companies/{companyID}/department-info [get]
func (h *AdminHandler) GetCompanyDepartmentInfo(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	info, err := h.companyService.GetCompanyDepartmentInfo(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    info,
	})
}

// CheckDepartmentLimit checks if a company can create more departments.
// @Summary Check department limit
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "Creation allowed"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 409 {object} map[string]interface{} "Limit reached"
// @Router /api/v1/admin/companies/{companyID}/check-department-limit [get]
func (h *AdminHandler) CheckDepartmentLimit(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	if err := h.companyService.CheckDepartmentLimit(ctx, companyID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Department creation allowed",
	})
}

// ============================
// UPDATE MAX DEPARTMENTS
// ============================

// UpdateMaxDepartmentsRequest represents the request to update max departments.
type UpdateMaxDepartmentsRequest struct {
	MaxDepartments int `json:"max_departments"`
}

// UpdateMaxDepartments updates the maximum number of departments allowed for a company.
// @Summary Update max departments
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body UpdateMaxDepartmentsRequest true "New max departments"
// @Success 200 {object} map[string]interface{} "Updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/max-departments [put]
func (h *AdminHandler) UpdateMaxDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	var req UpdateMaxDepartmentsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.MaxDepartments < 1 || req.MaxDepartments > 100 {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "max_departments must be between 1 and 100")
		return
	}

	if err := h.companyService.UpdateMaxDepartments(ctx, companyID, req.MaxDepartments); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Max departments updated successfully",
	})
}

// ============================
// DEPARTMENT SOFT DELETE & ACTIVATE
// ============================

// SoftDeleteDepartment soft-deletes a department.
// @Summary Soft delete department
// @Tags admin-departments
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/soft [delete]
func (h *AdminHandler) SoftDeleteDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid companyID")
		return
	}

	departmentID, err := uuid.Parse(chi.URLParam(r, "departmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid departmentID")
		return
	}

	if err := h.companyService.SoftDeleteDepartment(ctx, companyID, departmentID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Department soft deleted successfully",
	})
}

// ActivateDepartment activates a department.
// @Summary Activate department
// @Tags admin-departments
// @Param companyID path string true "Company UUID"
// @Param departmentID path string true "Department UUID"
// @Success 200 {object} map[string]interface{} "Activated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid IDs"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/departments/{departmentID}/activate [patch]
func (h *AdminHandler) ActivateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid companyID")
		return
	}

	departmentID, err := uuid.Parse(chi.URLParam(r, "departmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid departmentID")
		return
	}

	if err := h.companyService.ActivateDepartment(ctx, companyID, departmentID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Department activated successfully",
	})
}

// ============================
// CREATE SUB-DEPARTMENT
// ============================

// CreateSubDepartmentRequest represents the request to create a sub-department.
type CreateSubDepartmentRequest struct {
	DepartmentName string `json:"department_name" validate:"required"`
}

// CreateSubDepartment creates a sub-department under a parent department.
// @Summary Create sub-department
// @Tags admin-departments
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param parentDepartmentID path string true "Parent Department UUID"
// @Param body body CreateSubDepartmentRequest true "Department name"
// @Success 201 {object} map[string]interface{} "Sub-department created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/departments/{parentDepartmentID}/sub-departments [post]
func (h *AdminHandler) CreateSubDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid companyID")
		return
	}

	parentDeptIDStr := chi.URLParam(r, "parentDepartmentID")
	if parentDeptIDStr == "" {
		parentDeptIDStr = chi.URLParam(r, "departmentID")
	}
	parentDeptID, err := uuid.Parse(parentDeptIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid parentDepartmentID")
		return
	}

	var req CreateSubDepartmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.DepartmentName) == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "department_name is required")
		return
	}

	dept, err := h.companyService.CreateSubDepartment(ctx, companyID, parentDeptID, req.DepartmentName)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    dept,
	})
}

// ============================
// ADMIN ADD DEPARTMENT
// ============================

// AdminAddDepartmentRequest represents the request to add a department.
type AdminAddDepartmentRequest struct {
	DepartmentName     string    `json:"department_name"`
	SystemDepartmentID uuid.UUID `json:"system_department_id"`
}

// AdminAddDepartment adds a new department to a company (admin only).
// @Summary Add department (admin)
// @Tags admin-departments
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body AdminAddDepartmentRequest true "Department details"
// @Success 201 {object} map[string]interface{} "Department created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/admin/companies/{companyID}/departments [post]
func (h *AdminHandler) AdminAddDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	var req AdminAddDepartmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.DepartmentName) == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "department_name is required")
		return
	}

	department, err := h.companyService.AdminAddDepartment(ctx, companyID, req.DepartmentName, req.SystemDepartmentID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Department added successfully",
		"data": map[string]interface{}{
			"department_id":   department.DepartmentID.String(),
			"department_name": department.DepartmentName,
			"company_id":      department.CompanyID.String(),
			"is_active":       department.IsActive,
			"created_at":      department.CreatedAt,
		},
	})
}

// ============================
// DEPARTMENT SEARCH & SUGGESTIONS
// ============================

// SearchDepartments searches departments within a company.
// @Summary Search departments
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param q query string false "Search query"
// @Param limit query int false "Page size" default(20)
// @Param offset query int false "Offset" default(0)
// @Param include_inactive query bool false "Include inactive departments"
// @Success 200 {object} map[string]interface{} "Search results with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/companies/{companyID}/departments/search [get]
func (h *AdminHandler) SearchDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	includeInactiveStr := r.URL.Query().Get("include_inactive")

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}
	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	includeInactive := false
	if includeInactiveStr == "true" {
		includeInactive = true
	}

	searchReq := &service.SearchDepartmentsRequest{
		Query:           query,
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: includeInactive,
	}

	response, err := h.companyService.SearchDepartments(ctx, companyID, searchReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Departments search completed successfully"))
}

// GetDepartmentSuggestions returns department name suggestions based on a prefix.
// @Summary Get department suggestions
// @Tags admin-departments
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param prefix query string true "Prefix"
// @Param limit query int false "Max results" default(10)
// @Success 200 {object} map[string]interface{} "Suggestions"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/companies/{companyID}/departments/suggestions [get]
func (h *AdminHandler) GetDepartmentSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Prefix parameter is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50 {
			limit = l
		}
	}

	suggestions, err := h.companyService.GetDepartmentSuggestions(ctx, companyID, prefix, limit)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Department suggestions retrieved"))
}

// ============================
// POSITION CRUD
// ============================

// CreatePositionRequest is the request payload for creating a position.
type CreatePositionRequest struct {
	CompanyID          uuid.UUID `json:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id"`
	Title              string    `json:"title"`
	IsOpen             *bool     `json:"is_open"`
	IsSchedulable      *bool     `json:"is_schedulable"`
	AttendanceRequired *bool     `json:"attendance_required"`
	OvertimeAllowed    *bool     `json:"overtime_allowed"`
	WorkCenterCode     string    `json:"work_center_code"`
}

// CreatePosition creates a new position.
// @Summary Create position
// @Tags admin-positions
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param body body service.CreatePositionRequest true "Position details"
// @Success 201 {object} map[string]interface{} "Position created"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/companies/{companyID}/positions [post]
func (h *AdminHandler) CreatePosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req service.CreatePositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.CompanyID = companyID

	if req.IsOpen == nil {
		defaultVal := true
		req.IsOpen = &defaultVal
	}
	if req.IsSchedulable == nil {
		defaultVal := true
		req.IsSchedulable = &defaultVal
	}
	if req.AttendanceRequired == nil {
		defaultVal := true
		req.AttendanceRequired = &defaultVal
	}
	if req.OvertimeAllowed == nil {
		defaultVal := false
		req.OvertimeAllowed = &defaultVal
	}

	position, err := h.companyService.CreatePosition(ctx, &req, requesterID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	response := map[string]interface{}{
		"position_id":         position.PositionID.String(),
		"title":               position.Title,
		"department_id":       position.DepartmentID.String(),
		"company_id":          position.CompanyID.String(),
		"is_open":             position.IsOpen,
		"is_schedulable":      position.IsSchedulable,
		"attendance_required": position.AttendanceRequired,
		"overtime_allowed":    position.OvertimeAllowed,
		"work_center_code":    position.WorkCenterCode,
		"created_at":          position.CreatedAt,
		"updated_at":          position.UpdatedAt,
	}
	h.respondWithJSON(w, http.StatusCreated, successResponse(response, "Position created successfully"))
}

// ListPositions lists positions for a company with filters.
// @Summary List positions
// @Tags admin-positions
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param department_id query string false "Filter by department ID"
// @Param only_open query bool false "Only open positions"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Positions with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/companies/{companyID}/positions [get]
func (h *AdminHandler) ListPositions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)
	onlyOpen := h.getBoolQueryParam(r, "only_open", false)

	var departmentID *uuid.UUID
	if deptIDStr := r.URL.Query().Get("department_id"); deptIDStr != "" {
		deptID, err := uuid.Parse(deptIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
			return
		}
		departmentID = &deptID
	}

	positions, total, err := h.companyService.ListPositions(ctx, companyID, departmentID, onlyOpen, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	positionResponses := make([]map[string]interface{}, len(positions))
	for i, pos := range positions {
		positionResponses[i] = map[string]interface{}{
			"position_id":         pos.PositionID.String(),
			"title":               pos.Title,
			"department_id":       pos.DepartmentID.String(),
			"department_name":     pos.DepartmentName,
			"company_id":          pos.CompanyID.String(),
			"is_open":             pos.IsOpen,
			"is_schedulable":      pos.IsSchedulable,
			"attendance_required": pos.AttendanceRequired,
			"overtime_allowed":    pos.OvertimeAllowed,
			"work_center_code":    pos.WorkCenterCode,
			"work_center_name":    pos.WorkCenterName,
			"created_at":          pos.CreatedAt,
			"updated_at":          pos.UpdatedAt,
		}
	}

	response := map[string]interface{}{
		"positions": positionResponses,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(positions),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Positions listed successfully"))
}

// UpdatePosition updates a position.
// @Summary Update position
// @Tags admin-positions
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param positionID path string true "Position UUID"
// @Param body body service.UpdatePositionRequest true "Update fields"
// @Success 200 {object} map[string]interface{} "Position updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/positions/{positionID} [put]
func (h *AdminHandler) UpdatePosition(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
		return
	}

	var req service.UpdatePositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.PositionID = positionID

	existingPosition, err := h.companyService.GetPosition(ctx, positionID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if existingPosition.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot update position in another company")
		return
	}

	if err := h.companyService.UpdatePosition(ctx, &req, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Position updated successfully"))
}

// UpdatePositionStatus updates the status flags of a position.
// @Summary Update position status
// @Tags admin-positions
// @Accept json
// @Produce json
// @Param companyID path string true "Company UUID"
// @Param positionID path string true "Position UUID"
// @Param body body object true "Status flags" example({"is_open":false,"is_schedulable":true})
// @Success 200 {object} map[string]interface{} "Status updated"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Router /api/v1/companies/{companyID}/positions/{positionID}/status [patch]
func (h *AdminHandler) UpdatePositionStatus(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	positionIDStr := chi.URLParam(r, "positionID")
	positionID, err := uuid.Parse(positionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid position ID")
		return
	}

	var req struct {
		IsOpen             *bool   `json:"is_open,omitempty"`
		IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
		AttendanceRequired *bool   `json:"attendance_required,omitempty"`
		OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
		WorkCenterCode     *string `json:"work_center_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	existingPosition, err := h.companyService.GetPosition(ctx, positionID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if existingPosition.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "Cannot update position in another company")
		return
	}

	updateReq := &service.UpdatePositionRequest{
		PositionID:         positionID,
		Title:              existingPosition.Title,
		DepartmentID:       existingPosition.DepartmentID,
		IsOpen:             existingPosition.IsOpen,
		IsSchedulable:      &existingPosition.IsSchedulable,
		AttendanceRequired: &existingPosition.AttendanceRequired,
		OvertimeAllowed:    &existingPosition.OvertimeAllowed,
		WorkCenterCode:     existingPosition.WorkCenterCode,
	}
	if req.IsOpen != nil {
		updateReq.IsOpen = *req.IsOpen
	}
	if req.IsSchedulable != nil {
		updateReq.IsSchedulable = req.IsSchedulable
	}
	if req.AttendanceRequired != nil {
		updateReq.AttendanceRequired = req.AttendanceRequired
	}
	if req.OvertimeAllowed != nil {
		updateReq.OvertimeAllowed = req.OvertimeAllowed
	}
	if req.WorkCenterCode != nil {
		updateReq.WorkCenterCode = req.WorkCenterCode
	}

	if err := h.companyService.UpdatePosition(ctx, updateReq, requesterID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Position status updated successfully"))
}

// GetOpenPositions retrieves open positions for a company.
// @Summary Get open positions
// @Tags admin-positions
// @Produce json
// @Param company_id query string true "Company UUID"
// @Param is_open query bool false "Filter by open status"
// @Param limit query int false "Page size" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} map[string]interface{} "Open positions with metadata"
// @Failure 400 {object} map[string]interface{} "Missing company_id"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/companies/{companyID}/positions/open [get]
func (h *AdminHandler) GetOpenPositions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "company_id is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var isOpen *bool
	if isOpenStr := r.URL.Query().Get("is_open"); isOpenStr != "" {
		openVal, err := strconv.ParseBool(isOpenStr)
		if err == nil {
			isOpen = &openVal
		}
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	positions, total, err := h.companyService.GetOpenPositions(ctx, companyID, isOpen, limit, offset)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	positionResponses := make([]map[string]interface{}, len(positions))
	for i, pos := range positions {
		positionResponses[i] = map[string]interface{}{
			"position_id":         pos.PositionID.String(),
			"title":               pos.Title,
			"is_open":             pos.IsOpen,
			"is_schedulable":      pos.IsSchedulable,
			"attendance_required": pos.AttendanceRequired,
			"overtime_allowed":    pos.OvertimeAllowed,
			"work_center_code":    pos.WorkCenterCode,
			"work_center_name":    pos.WorkCenterName,
			"department_id":       pos.DepartmentID.String(),
			"company_id":          pos.CompanyID.String(),
			"created_at":          pos.CreatedAt,
			"updated_at":          pos.UpdatedAt,
		}
	}

	response := map[string]interface{}{
		"positions": positionResponses,
		"meta": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(positions),
		},
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Open positions retrieved successfully"))
}

// ============================
// CREATE COMPANY
// ============================

// CreateCompanyRequest is the request payload for creating a company.
type CreateCompanyRequest struct {
	CompanyName             string   `json:"company_name" validate:"required,max=255"`
	OwnerPhone              string   `json:"owner_phone" validate:"required"`
	OwnerUsername           string   `json:"owner_username" validate:"required,min=3,max=100,alphanum"`
	OwnerFullName           string   `json:"owner_full_name" validate:"required,max=255"`
	OwnerPositionTitle      string   `json:"owner_position_title" validate:"required,max=255"`
	SubscriptionTier        string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
	MaxEmployees            int      `json:"max_employees" validate:"required,min=1,max=2000"`
	MaxDepartments          int      `json:"max_departments" validate:"required,min=1,max=100"`
	DataRegion              string   `json:"data_region" validate:"required"`
	SubscriptionMonths      int      `json:"subscription_months" validate:"required,min=1,max=36"`
	SubscriptionDays        int      `json:"subscription_days" validate:"min=0,max=30"`
	Departments             []string `json:"departments"`
	FinancialYearStartMonth int      `json:"financial_year_start_month" validate:"required,min=1,max=12"`
	WorkCenterCode          string   `json:"work_center_code" validate:"required,max=100"`
	WorkCenterName          string   `json:"work_center_name" validate:"required,max=255"`
	WorkCenterDesc          *string  `json:"work_center_description,omitempty"`
	WorkCenterTZ            string   `json:"work_center_timezone" validate:"required"`
	WorkCenterActive        bool     `json:"work_center_is_active"`
	PositionWorkCenterCode  *string  `json:"position_work_center_code,omitempty"`
}

// CreateCompany creates a new company (admin only).
// @Summary Create company
// @Tags admin-companies
// @Accept json
// @Produce json
// @Param body body CreateCompanyRequest true "Company creation details"
// @Success 201 {object} map[string]interface{} "Company created"
// @Failure 400 {object} map[string]interface{} "Validation failed"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Company already exists"
// @Router /api/v1/admin/companies [post]
func (h *AdminHandler) CreateCompany(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

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

	if err := validateCreateCompanyRequest(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Validation failed")
		return
	}

	companyReq := service.CreateCompanyRequest{
		CompanyName:             req.CompanyName,
		OwnerPhone:              req.OwnerPhone,
		OwnerUsername:           req.OwnerUsername,
		OwnerFullName:           req.OwnerFullName,
		OwnerPositionTitle:      req.OwnerPositionTitle,
		SubscriptionTier:        req.SubscriptionTier,
		MaxEmployees:            req.MaxEmployees,
		MaxDepartments:          req.MaxDepartments,
		DataRegion:              req.DataRegion,
		SubscriptionMonths:      req.SubscriptionMonths,
		SubscriptionDays:        req.SubscriptionDays,
		Departments:             req.Departments,
		FinancialYearStartMonth: req.FinancialYearStartMonth,
		WorkCenterCode:          req.WorkCenterCode,
		WorkCenterName:          req.WorkCenterName,
		WorkCenterDesc:          req.WorkCenterDesc,
		WorkCenterTZ:            req.WorkCenterTZ,
		WorkCenterActive:        req.WorkCenterActive,
		PositionWorkCenterCode:  req.PositionWorkCenterCode,
	}

	company, err := h.companyService.CreateCompany(ctx, &companyReq, adminID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
			msg = "Company already exists for this owner"
		}
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Company created successfully",
		"data": map[string]interface{}{
			"company_id":        company.CompanyID.String(),
			"company_name":      company.CompanyName,
			"owner_user_id":     company.OwnerUserID.String(),
			"subscription_tier": company.SubscriptionTier,
			"max_departments":   company.MaxDepartments,
			"departments":       len(req.Departments) + 1,
			"created_at":        company.CreatedAt,
		},
	})
}

// sanitizeUserForAdminResponse returns a sanitized map for admin responses.
func (h *AdminHandler) sanitizeUserForAdminResponse(user *models.User) map[string]interface{} {
	if user == nil {
		return nil
	}
	return map[string]interface{}{
		"user_id":            user.UserID,
		"username":           user.Username,
		"full_name":          user.FullName,
		"phone_hash":         user.PhoneHash,
		"kyc_status":         user.KYCStatus,
		"kyc_level":          user.KYCLevel,
		"kyc_verified_at":    user.KYCVerifiedAt,
		"is_verified":        user.IsVerified,
		"is_active":          user.IsActive,
		"data_region":        user.DataRegion,
		"created_at":         user.CreatedAt,
		"updated_at":         user.UpdatedAt,
		"last_login":         user.LastLogin,
		"device_id":          user.DeviceID,
		"device_fingerprint": user.DeviceFingerprint,
	}
}

// GetDeactivatedDepartments godoc
// @Summary Get deactivated departments
// @Description Retrieves a list of all departments that are inactive (is_active = false) for a given company.
// @Tags admin-companies
// @Produce json
// @Param companyID path string true "Company UUID"
// @Success 200 {object} map[string]interface{} "List of deactivated departments"
// @Failure 400 {object} map[string]interface{} "Invalid company ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /api/v1/admin/companies/{companyID}/deactivated-departments [get]
func (h *AdminHandler) GetDeactivatedDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// Authenticate admin
	_, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Parse company ID from URL parameter (e.g., /companies/{companyID}/deactivated-departments)
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company_id")
		return
	}

	departments, err := h.companyService.GetDeactivatedDepartments(ctx, companyID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	// Ensure the response is always an array (not null)
	if departments == nil {
		departments = []*models.Department{}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    departments,
	})
}
