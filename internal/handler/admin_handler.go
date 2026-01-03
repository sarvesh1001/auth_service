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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

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
	// Admin authentication routes
	router.Route("/admin-auth", func(r chi.Router) {
		r.Post("/login/initiate", h.InitiateAdminLogin)
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

	// Admin management routes (protected)
	router.Route("/admin", func(r chi.Router) {
		// Role Management
		r.Post("/roles", h.CreateAdminRole)
		r.Post("/employee", h.CreateEmployeeRole) // NEW
		r.Post("/manager", h.CreateManagerRole)   // NEW
		r.Get("/roles", h.GetAdminRoles)
		r.Get("/roles/{roleID}", h.GetAdminRole)
		r.Put("/roles/{roleID}", h.UpdateAdminRole)
		r.Delete("/roles/{roleID}", h.DeleteAdminRole)

		// Admin User Management
		r.Post("/users", h.CreateAdminUser)
		r.Get("/users", h.ListAdmins)
		r.Get("/users/{adminID}", h.GetAdminUser)
		r.Put("/users/{adminID}", h.UpdateAdminUser)
		r.Delete("/users/{adminID}", h.DeleteAdminUser)

		// Admin Profile Management
		r.Put("/users/{adminID}/profile", h.UpdateAdminProfile)
		r.Put("/users/{adminID}/phone", h.ChangeAdminPhone)
		r.Put("/users/{adminID}/reports-to", h.UpdateAdminReportsTo)

		// Department Management
		// r.Put("/users/{adminID}/departments", h.UpdateAdminDepartments)

		// Permission Management
		r.Get("/users/{adminID}/permissions", h.GetAdminPermissions)
		// r.Post("/users/{adminID}/permissions/grant", h.GrantPermissionToAdmin)
		// r.Post("/users/{adminID}/permissions/revoke", h.RevokePermissionFromAdmin)
		// r.Post("/users/{adminID}/permissions/batch", h.BatchUpdatePermissions)

		// Status Management
		r.Post("/users/{adminID}/activate", h.ActivateAdmin)
		r.Post("/users/{adminID}/deactivate", h.DeactivateAdmin)

		// Avatar Management
		r.Post("/users/{adminID}/avatar", h.SetAdminAvatar)
		r.Get("/users/{adminID}/avatar", h.GetAdminAvatar)
		r.Delete("/users/{adminID}/avatar", h.DeactivateAdminAvatar)
		r.Get("/users/{adminID}/avatar/with-fallback", h.GetAdminAvatarWithFallback)

		// Hierarchy Management
		r.Get("/users/{adminID}/direct-reports", h.GetDirectReports)
		r.Get("/users/{adminID}/reporting-chain", h.GetReportingChain)
		r.Get("/users/{adminID}/hierarchy", h.GetAdminHierarchy)

		// Search Routes
		h.RegisterSearchRoutes(r)
	})

	// Company Management Routes (maintain existing)
	router.Route("/companies", func(r chi.Router) {
		r.Post("/", h.CreateCompany)
		r.Get("/", h.GetRecentCompanies)
		r.Get("/search", h.SearchCompanies)
		r.Get("/suggestions", h.GetCompanySuggestions)
		r.Get("/analytics/search", h.GetCompanySearchAnalytics)
		r.Post("/search/benchmark", h.BenchmarkCompanySearch)

		// Company by ID routes
		r.Route("/{companyID}", func(r chi.Router) {
			r.Get("/", h.GetCompany)
			r.Get("/stats", h.GetCompanyStats)
			r.Get("/employees", h.GetCompanyEmployees)
			r.Get("/departments", h.GetCompanyDepartments)
			r.Get("/hierarchy", h.GetCompanyHierarchy)
			r.Get("/rbac-stats", h.GetCompanyRBACStats)
			r.Get("/roles", h.GetCompanyRoles)
			r.Put("/subscription", h.UpdateSubscription)
			r.Post("/subscription/extend", h.ExtendSubscription)
			r.Post("/deactivate", h.DeactivateCompany)
			r.Post("/reactivate", h.ReactivateCompany)
		})

		// Company by status/tier
		r.Get("/status/{status}", h.GetCompaniesByStatus)
		r.Get("/tier/{tier}", h.GetCompaniesByTier)
		r.Get("/expiring", h.GetCompaniesWithExpiringSubscription)

		// Owner-specific company search
		r.Get("/owner/{ownerID}/search", h.SearchCompaniesByOwner)
	})

	// User Management Routes (maintain existing)
	router.Route("/users", func(r chi.Router) {
		r.Get("/search/advanced", h.SearchUsersAdvanced)
		r.Get("/search/username", h.SearchUsersByUsername)
		r.Get("/search/full-name", h.SearchUsersByFullName)
		r.Get("/suggestions", h.GetUserSuggestions)
		r.Get("/kyc/{status}", h.ListUsersByKYCStatus)
		r.Get("/recently-active", h.GetRecentlyActiveUsers)
		r.Get("/banned", h.GetBannedUsers)

		// User by ID routes
		r.Route("/{userID}", func(r chi.Router) {
			r.Put("/", h.UpdateUser)
			r.Put("/kyc", h.UpdateUserKYC)
			r.Post("/ban", h.BanUser)
			r.Post("/unban", h.UnbanUser)
		})
	})

	// System Management
	router.Route("/system", func(r chi.Router) {
		r.Get("/departments", h.GetSystemDepartments)
		r.Get("/permissions", h.GetAllPermissions)
		r.Get("/permissions/module/{module}", h.GetPermissionsByModule)
	})
}

// ==================== Admin Authentication Methods ====================

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
	deviceTrusted, _ := h.deviceService.IsDeviceTrusted(ctx, admin.AdminID, req.DeviceID)

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
	h.logger.Info("Admin login initiation completed",
		util.String("phone", req.PhoneNumber),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
		UserAgent:         r.UserAgent(),
	}

	otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
	if err != nil {
		h.handleOTPError(w, err)
		return
	}

	if !otpResponse.Success {
		h.respondWithError(w, http.StatusUnauthorized,
			errors.New("AUTHENTICATION_FAILED"),
			"Authentication failed")
		return
	}

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Authentication failed")
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
		h.logger.Warn("Failed to update device trust for admin", util.ErrorField(err))
	}

	if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
		if err := h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID); err != nil {
			h.logger.Warn("Failed to unlock MPIN after OTP verification", util.ErrorField(err))
		}
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

	h.logger.Info("Admin OTP verification completed",
		util.String("admin_id", admin.AdminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) VerifyAdminMPINLogin(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	var req struct {
// 		AdminID           string `json:"admin_id" validate:"required"`
// 		MPIN              string `json:"mpin" validate:"required"`
// 		DeviceID          string `json:"device_id" validate:"required"`
// 		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.MPIN = util.SanitizeInput(req.MPIN)
// 	req.DeviceID = util.SanitizeInput(req.DeviceID)
// 	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

// 	adminID, err := uuid.Parse(req.AdminID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
// 		return
// 	}

// 	deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, adminID, req.DeviceID)
// 	if err != nil || !deviceTrusted {
// 		h.respondWithError(w, http.StatusForbidden,
// 			errors.New("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
// 			"MPIN login not allowed on this device")
// 		return
// 	}

// 	ipAddress := h.getClientIP(r)
// 	if ipAddress == "" {
// 		ipAddress = "0.0.0.0"
// 	}

// 	mpinVerifyReq := &service.AdminMPINVerifyRequest{
// 		AdminID:           adminID,
// 		MPIN:              req.MPIN,
// 		DeviceID:          req.DeviceID,
// 		DeviceFingerprint: req.DeviceFingerprint,
// 		IPAddress:         ipAddress,
// 		UserAgent:         r.UserAgent(),
// 	}

// 	mpinResult, err := h.mpinService.VerifyAdminMPIN(ctx, mpinVerifyReq)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "MPIN verification failed")
// 		return
// 	}

// 	if !mpinResult.Verified {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("MPIN_VERIFICATION_FAILED: %s", mpinResult.Message),
// 			"MPIN verification failed")
// 		return
// 	}

// 	admin, err := h.adminService.GetAdmin(ctx, adminID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get admin details")
// 		return
// 	}

// 	tokenReq := &service.IssueTokenPairRequest{
// 		UserID:         admin.AdminID.String(),
// 		Role:           admin.GetRoleString(),
// 		DeviceID:       req.DeviceID,
// 		SessionType:    "admin",
// 		IPAddress:      ipAddress,
// 		AdminRoleMask:  admin.AdminRoleMask,
// 		PermissionMask: admin.AdminPermissionMask,
// 	}

// 	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue JWT tokens")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
// 		"tokens": tokens,
// 		"admin": map[string]interface{}{
// 			"admin_id":         admin.AdminID.String(),
// 			"role_mask":        admin.AdminRoleMask,
// 			"permission_mask":  admin.AdminPermissionMask,
// 			"role_string":      admin.GetRoleString(),
// 			"permission_names": admin.GetPermissionNames(),
// 		},
// 		"message": "Admin MPIN login successful",
// 	}, "Admin login successful"))

//		h.logger.Info("Admin MPIN login completed",
//			util.String("admin_id", adminID.String()),
//			util.Duration("duration", time.Since(startTime)),
//		)
//	}
func (h *AdminHandler) VerifyAdminMPINLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	// Get admin by phone
	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
		return
	}

	// Verify MPIN
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
		h.respondWithError(w, http.StatusUnauthorized, err, "MPIN verification failed")
		return
	}

	// Get admin permission mask
	permissionMask, err := h.adminService.GetAdminPermissionMask(ctx, admin.AdminID)
	if err != nil {
		h.logger.Warn("Failed to get admin permission mask, using default",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err))
		// Use full access as fallback for super admin
		if admin.IsSuperAdmin() {
			permissionMask = []uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
		} else {
			permissionMask = []uint64{0, 0, 0, 0}
		}
	}

	// Record successful login
	if err := h.adminService.RecordAdminLogin(ctx, admin.AdminID); err != nil {
		h.logger.Warn("Failed to record admin login",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err))
	}

	// Reset failed login attempts
	if err := h.adminService.ResetAdminFailedLoginAttempts(ctx, admin.AdminID); err != nil {
		h.logger.Warn("Failed to reset admin failed attempts",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err))
	}

	// Issue JWT tokens (not session token)
	tokenReq := &service.IssueTokenPairRequest{
		UserID:         admin.AdminID.String(),
		Role:           admin.GetRoleString(),
		DeviceID:       req.DeviceID,
		SessionType:    "admin",
		IPAddress:      h.getClientIP(r),
		PermissionMask: permissionMask,
		CompanyID:      "", // Empty for admin sessions
	}

	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue JWT tokens")
		return
	}

	// Get admin with more details
	adminWithPerms, err := h.adminService.GetAdminWithPermissions(ctx, admin.AdminID, admin.AdminID)
	if err != nil {
		h.logger.Warn("Failed to get admin permissions",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err))
	}

	// Build response
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

	// Add permissions if available
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

	h.logger.Info("Admin MPIN login completed with JWT tokens",
		util.String("admin_id", admin.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== MPIN Management Methods ====================

func (h *AdminHandler) SetupAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to setup MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Admin MPIN setup successful"))
	h.logger.Info("Admin MPIN setup completed",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) ChangeAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to change MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin MPIN change successful"))
	h.logger.Info("Admin MPIN changed successfully",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) ForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		h.respondWithError(w, http.StatusNotFound, fmt.Errorf("phone not registered"), "Phone not registered")
		return
	}

	clientIP := h.getClientIP(r)
	forgotReq := &service.AdminMPINForgotRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         clientIP,
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.ForgotAdminMPIN(ctx, forgotReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to initiate forgot MPIN process")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Forgot MPIN initiated"))
	h.logger.Info("ForgotAdminMPIN initiated",
		util.String("admin_id", admin.AdminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) VerifyForgotAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		h.respondWithError(w, http.StatusNotFound, fmt.Errorf("phone not registered"), "Phone not registered")
		return
	}

	clientIP := h.getClientIP(r)
	forgotReq := &service.AdminMPINForgotWithOTPRequest{
		AdminID:           admin.AdminID,
		PhoneNumber:       req.PhoneNumber,
		DeviceID:          req.DeviceID,
		NewMPIN:           req.NewMPIN,
		OTPCode:           req.OTPCode,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         clientIP,
		UserAgent:         r.UserAgent(),
	}

	if err := h.mpinService.VerifyForgotAdminMPINOTP(ctx, forgotReq); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to reset MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin MPIN reset successful"))
	h.logger.Info("Admin MPIN reset via forgot flow",
		util.String("admin_id", admin.AdminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Admin Role Management Methods ====================

func (h *AdminHandler) CreateAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Validate role type
	if req.RoleType != models.RoleTypeEmployee && req.RoleType != models.RoleTypeManager {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("invalid role type"),
			"Role type must be 1 (employee) or 2 (manager)")
		return
	}

	role, err := h.adminService.CreateAdminRole(ctx, &req, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create admin role")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Admin role created successfully"))
	h.logger.Info("Admin role created",
		util.String("role_id", role.AdminRoleID.String()),
		util.String("created_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Admin role retrieved successfully"))
	h.logger.Debug("Admin role retrieved",
		util.String("role_id", roleID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin roles")
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
	h.logger.Debug("Admin roles retrieved",
		util.Int("count", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) UpdateAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update admin role")
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(role, "Admin role updated successfully"))
	h.logger.Info("Admin role updated",
		util.String("role_id", roleID.String()),
		util.String("updated_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) DeleteAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to delete admin role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin role deleted successfully"))
	h.logger.Info("Admin role deleted",
		util.String("role_id", roleID.String()),
		util.String("deleted_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Admin User Management Methods ====================
func (h *AdminHandler) CreateAdminUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Service will handle phone encryption and hashing
	admin, err := h.adminService.CreateAdminUser(ctx, &req, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create admin user")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "Admin user created successfully"))
	h.logger.Info("Admin user created",
		util.String("admin_id", admin.AdminID.String()),
		util.String("created_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) GetAdminUser(w http.ResponseWriter, r *http.Request) {
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

	admin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin user retrieved successfully"))
	h.logger.Debug("Admin user retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) UpdateAdminUser(w http.ResponseWriter, r *http.Request) {
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

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.UpdateAdminUser(ctx, adminID, updates, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update admin user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user updated successfully"))
	h.logger.Info("Admin user updated",
		util.String("admin_id", adminID.String()),
		util.String("updated_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) DeleteAdminUser(w http.ResponseWriter, r *http.Request) {
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

	if err := h.adminService.DeleteAdminUser(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to delete admin user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user deleted successfully"))
	h.logger.Info("Admin user deleted",
		util.String("admin_id", adminID.String()),
		util.String("deleted_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Admin Profile Management ====================
func (h *AdminHandler) UpdateAdminProfile(w http.ResponseWriter, r *http.Request) {
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

	var req models.AdminProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Create updates map for service method
	updates := make(map[string]interface{})
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.FullName != "" {
		updates["full_name"] = req.FullName
	}

	if len(updates) == 0 {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("NO_FIELDS_TO_UPDATE"),
			"At least one field (username or full_name) must be provided")
		return
	}

	// Use UpdateAdminUser instead of separate methods
	if err := h.adminService.UpdateAdminUser(ctx, adminID, updates, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update admin profile")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin profile updated successfully"))
	h.logger.Info("Admin profile updated",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) ChangeAdminPhone(w http.ResponseWriter, r *http.Request) {
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
		NewPhone string `json:"new_phone" validate:"required,phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.UpdateAdminPhone(ctx, adminID, req.NewPhone, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to change admin phone")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin phone updated successfully"))
	h.logger.Info("Admin phone changed",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) UpdateAdminReportsTo(w http.ResponseWriter, r *http.Request) {
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update admin reports_to")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin reports_to updated successfully"))
	h.logger.Info("Admin reports_to updated",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Department Management ====================

// ==================== Permission Management ====================

func (h *AdminHandler) GetAdminPermissions(w http.ResponseWriter, r *http.Request) {
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

	permissions, err := h.adminService.GetAdminPermissions(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(permissions, "Admin permissions retrieved successfully"))
	h.logger.Debug("Admin permissions retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Status Management ====================

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
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	if err := h.adminService.ActivateAdmin(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to activate admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin activated successfully"))
	h.logger.Info("Admin activated",
		util.String("admin_id", adminID.String()),
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
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	if err := h.adminService.DeactivateAdmin(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to deactivate admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin deactivated successfully"))
	h.logger.Info("Admin deactivated",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Avatar Management ====================

func (h *AdminHandler) SetAdminAvatar(w http.ResponseWriter, r *http.Request) {
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
		AvatarHash      string `json:"avatar_hash" validate:"required"`
		AvatarObjectKey string `json:"avatar_object_key" validate:"required"`
		AvatarMimeType  string `json:"avatar_mime_type" validate:"required,oneof=image/jpeg image/jpg image/png image/gif image/webp image/svg+xml"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.adminService.SetAdminAvatar(ctx, adminID, req.AvatarHash, req.AvatarObjectKey, req.AvatarMimeType, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to set admin avatar")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin avatar set successfully"))
	h.logger.Info("Admin avatar set",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatar, err := h.adminService.GetAdminAvatar(ctx, adminID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin avatar")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(avatar, "Admin avatar retrieved successfully"))
	h.logger.Debug("Admin avatar retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) DeactivateAdminAvatar(w http.ResponseWriter, r *http.Request) {
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

	if err := h.adminService.DeactivateAdminAvatar(ctx, adminID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to deactivate admin avatar")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin avatar deactivated successfully"))
	h.logger.Info("Admin avatar deactivated",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminAvatarWithFallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatar, initials, err := h.adminService.GetAdminAvatarWithFallback(ctx, adminID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin avatar with fallback")
		return
	}

	response := map[string]interface{}{
		"avatar":     avatar,
		"initials":   initials,
		"has_avatar": avatar != nil,
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin avatar with fallback retrieved successfully"))
	h.logger.Debug("Admin avatar with fallback retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Hierarchy Management ====================

func (h *AdminHandler) GetDirectReports(w http.ResponseWriter, r *http.Request) {
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

	directReports, err := h.adminService.GetDirectReports(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get direct reports")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(directReports, "Direct reports retrieved successfully"))
	h.logger.Debug("Direct reports retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("count", len(directReports)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetReportingChain(w http.ResponseWriter, r *http.Request) {
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

	reportingChain, err := h.adminService.GetReportingChain(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get reporting chain")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(reportingChain, "Reporting chain retrieved successfully"))
	h.logger.Debug("Reporting chain retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("levels", len(reportingChain)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminHierarchy(w http.ResponseWriter, r *http.Request) {
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

	hierarchy, err := h.adminService.GetAdminHierarchy(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin hierarchy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(hierarchy, "Admin hierarchy retrieved successfully"))
	h.logger.Debug("Admin hierarchy retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("levels", len(hierarchy)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Search Routes Registration ====================

func (h *AdminHandler) RegisterSearchRoutes(router chi.Router) {
	router.Route("/search", func(r chi.Router) {
		// Admin search
		r.Get("/admins", h.SearchAdmins)
		r.Get("/admins/advanced", h.SearchAdminsAdvanced)
		r.Get("/admins/name", h.SearchAdminsByName)
		r.Get("/admins/employees", h.SearchAdminEmployees)
		r.Get("/admins/managers", h.SearchAdminManagers)
		r.Get("/admins/suggestions", h.GetAdminSuggestions)
		r.Get("/admins/analytics", h.GetAdminSearchAnalytics)

		// Role-based search
		// r.Get("/admins/role/{roleMask}", h.SearchAdminsByRoleAndName)

		// Role search
		r.Get("/roles", h.SearchAdminRoles)
	})
}

// ==================== Admin Search Methods ====================

func (h *AdminHandler) GetAdminSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("PREFIX_REQUIRED"),
			"Prefix is required for suggestions")
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin suggestions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Admin suggestions retrieved successfully"))
	h.logger.Debug("Admin suggestions retrieved",
		util.String("prefix", prefix),
		util.Int("suggestions", len(suggestions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminSearchAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Check authentication but don't use the ID
	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	stats, err := h.adminService.GetStats(ctx)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin search analytics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin search analytics retrieved successfully"))
	h.logger.Debug("Admin search analytics retrieved",
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("QUERY_REQUIRED"),
			"Search query is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	roles, total, err := h.adminService.SearchAdminRoles(ctx, query, requesterID, limit, offset)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admin roles")
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
	h.logger.Info("Admin roles search executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", query),
		util.Int("results", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	limit := h.getIntQueryParam(r, "limit", 50)
// 	offset := h.getIntQueryParam(r, "offset", 0)

// 	// Create search request with proper type
// 	req := &models.AdminSearchRequest{
// 		Query:           "", // Empty query to get all
// 		SearchType:      "fulltext",
// 		Limit:           limit,
// 		Offset:          offset,
// 		IncludeInactive: h.getBoolQueryParam(r, "include_inactive", false),
// 	}

// 	if roleTypeStr := r.URL.Query().Get("role_type"); roleTypeStr != "" {
// 		roleType, err := strconv.Atoi(roleTypeStr)
// 		if err == nil {
// 			req.RoleTypeFilter = &roleType
// 		}
// 	}

// 	// Use SearchAdminsWithFilters instead of SearchAdminUsers
// 	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, req)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to list admins")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"admins": results,
// 		"meta": map[string]interface{}{
// 			"total":  total,
// 			"limit":  limit,
// 			"offset": offset,
// 			"count":  len(results),
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admins listed successfully"))
// 	h.logger.Debug("Admins listed",
// 		util.Int("count", len(results)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// ==================== Helper Methods ====================

func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		return uuid.Nil, errors.New("user ID not found in request context")
	}
	return uuid.Parse(userID)
}

func (h *AdminHandler) getRequesterAdminRoleMask(r *http.Request) (uint64, error) {
	if roleMask, ok := r.Context().Value("admin_role_mask").(uint64); ok && roleMask != 0 {
		return roleMask, nil
	}
	return 0, errors.New("admin role mask not found in context")
}

func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
	status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
	if err != nil {
		return false
	}
	return status != nil && status.Exists
}

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

func (h *AdminHandler) getStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}

	errMsg := err.Error()

	// Check for duplicate role constraint violation (PostgreSQL error)
	if strings.Contains(errMsg, "duplicate key value violates unique constraint") &&
		strings.Contains(errMsg, "admin_roles_role_name_key") {
		return http.StatusConflict
	}

	// Check for other duplicate key violations
	if strings.Contains(errMsg, "duplicate key") ||
		strings.Contains(errMsg, "violates unique constraint") {
		return http.StatusConflict
	}

	// Check for custom "already exists" errors
	if strings.Contains(errMsg, "already exists") ||
		strings.Contains(errMsg, "already taken") ||
		strings.Contains(errMsg, "already in use") {
		return http.StatusConflict
	}

	// Check for not found errors
	if strings.Contains(errMsg, "not found") ||
		strings.Contains(errMsg, "does not exist") ||
		strings.Contains(errMsg, "no such") {
		return http.StatusNotFound
	}

	// Check for authentication/authorization errors
	if strings.Contains(errMsg, "unauthorized") ||
		strings.Contains(errMsg, "Unauthorized") ||
		strings.Contains(errMsg, "forbidden") ||
		strings.Contains(errMsg, "Forbidden") {
		return http.StatusForbidden
	}

	// Check for permission errors
	if strings.Contains(errMsg, "permission") ||
		strings.Contains(errMsg, "Permission") ||
		strings.Contains(errMsg, "cannot access") ||
		strings.Contains(errMsg, "cannot view") ||
		strings.Contains(errMsg, "cannot update") ||
		strings.Contains(errMsg, "cannot delete") {
		return http.StatusForbidden
	}

	// Check for validation errors
	if strings.Contains(errMsg, "invalid") ||
		strings.Contains(errMsg, "Invalid") ||
		strings.Contains(errMsg, "cannot be empty") ||
		strings.Contains(errMsg, "required") ||
		strings.Contains(errMsg, "must be") ||
		strings.Contains(errMsg, "should be") ||
		strings.Contains(errMsg, "expected") {
		return http.StatusBadRequest
	}

	// Check for rate limiting/throttling
	if strings.Contains(errMsg, "rate limit") ||
		strings.Contains(errMsg, "too many requests") ||
		strings.Contains(errMsg, "throttled") {
		return http.StatusTooManyRequests
	}

	// Check for service unavailable/maintenance
	if strings.Contains(errMsg, "service unavailable") ||
		strings.Contains(errMsg, "maintenance") ||
		strings.Contains(errMsg, "temporarily") {
		return http.StatusServiceUnavailable
	}

	// Check for not implemented
	if strings.Contains(errMsg, "not implemented") ||
		strings.Contains(errMsg, "not supported") {
		return http.StatusNotImplemented
	}

	// Check for database connection errors
	if strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "database") ||
		strings.Contains(errMsg, "sql:") ||
		strings.Contains(errMsg, "pq:") {
		return http.StatusInternalServerError
	}

	// Default to internal server error
	return http.StatusInternalServerError
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

// ==================== Company Management Methods (Maintained from original) ====================

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
		if strings.Contains(err.Error(), "company with name") && strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, err, "Company with this name already exists for the owner")
			return
		}
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create company")
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Company created successfully with RBAC setup",
		"data": map[string]interface{}{
			"company_id":        company.CompanyID.String(),
			"company_name":      company.CompanyName,
			"owner_phone":       req.OwnerPhone,
			"owner_user_id":     company.OwnerUserID.String(),
			"subscription_tier": company.SubscriptionTier,
			"departments":       len(req.Departments),
			"created_at":        company.CreatedAt,
		},
	}

	h.respondWithJSON(w, http.StatusCreated, response)
	h.logger.Info("Company created by admin",
		util.String("company_id", company.CompanyID.String()),
		util.String("created_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
	h.logger.Debug("Company retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

func (h *AdminHandler) SearchCompanies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("QUERY_REQUIRED"), "Search query is required")
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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search companies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Company search completed"))
	h.logger.Info("Company search executed",
		util.String("admin_id", adminID.String()),
		util.String("query", query),
		util.Int("results", len(searchResp.Companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetCompanySuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("PREFIX_REQUIRED"), "Prefix is required for suggestions")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 10)
	suggestions, err := h.companyService.GetCompanySuggestions(ctx, prefix, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get suggestions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "Company suggestions retrieved"))
	h.logger.Debug("Company suggestions retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("suggestions", len(suggestions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetCompanySearchAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	analytics, err := h.companyService.GetCompanySearchAnalytics(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get search analytics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(analytics, "Company search analytics retrieved"))
	h.logger.Info("Company search analytics retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to run search benchmark")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(results, "Search benchmark completed"))
	h.logger.Info("Company search benchmark executed",
		util.String("admin_id", adminID.String()),
		util.Int("iterations", req.Iterations),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchCompaniesByOwner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
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
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("QUERY_REQUIRED"), "Search query is required")
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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search owner companies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(searchResp, "Owner company search completed"))
	h.logger.Info("Owner company search executed",
		util.String("admin_id", adminID.String()),
		util.String("owner_id", ownerID.String()),
		util.Int("results", len(searchResp.Companies)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetCompanyEmployees(w http.ResponseWriter, r *http.Request) {
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
	h.logger.Debug("Company employees listed",
		util.String("company_id", companyID.String()),
		util.Int("count", len(employees)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetCompanyDepartments(w http.ResponseWriter, r *http.Request) {
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

	departments, total, err := h.companyService.GetDepartmentsByCompany(ctx, companyID, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company departments")
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
	h.logger.Info("Company departments retrieved",
		util.String("company_id", companyID.String()),
		util.Int("count", len(departments)),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
		util.String("updated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
			errors.New("either additional_months or additional_days must be provided"),
			"Either additional_months or additional_days must be provided")
		return
	}

	if err := h.companyService.ExtendSubscription(ctx, companyID, req.AdditionalMonths, req.AdditionalDays, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to extend subscription")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))
	h.logger.Info("Company subscription extended",
		util.String("company_id", companyID.String()),
		util.String("extended_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

	if err := h.companyService.DeactivateCompany(ctx, companyID, req.Reason, adminID); err != nil {
		h.respondWithError(w, h.getStatusCode(err), err, "Failed to deactivate company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company deactivated successfully"))
	h.logger.Info("Company deactivated",
		util.String("company_id", companyID.String()),
		util.String("deactivated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
	h.logger.Info("Company reactivated",
		util.String("company_id", companyID.String()),
		util.String("reactivated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetCompaniesByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("status required"), "Status is required")
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
			h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies")
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
		h.respondWithError(w, http.StatusBadRequest, errors.New("invalid status"), "Status must be active or inactive")
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

func (h *AdminHandler) GetCompaniesByTier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	tier := chi.URLParam(r, "tier")
	if tier == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("tier required"), "Subscription tier is required")
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

func (h *AdminHandler) GetCompaniesWithExpiringSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	days := h.getIntQueryParam(r, "days", 30)
	if days <= 0 || days > 365 {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("invalid days parameter"),
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

func (h *AdminHandler) GetCompanyRBACStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	deptLoad, err := h.companyService.GetDepartmentLoad(ctx, companyID)
	if err != nil {
		h.logger.Warn("Failed to get department load", util.ErrorField(err))
	}

	roleDist, err := h.companyService.GetRoleDistribution(ctx, companyID)
	if err != nil {
		h.logger.Warn("Failed to get role distribution", util.ErrorField(err))
	}

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

// ==================== User Management Methods (Maintained from original) ====================

func (h *AdminHandler) SearchUsersAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users with advanced filters")
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
	h.logger.Info("Advanced user search executed",
		util.String("admin_id", adminID.String()),
		util.Int("results", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchUsersByUsername(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("USERNAME_REQUIRED"), "Username is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	users, err := h.userService.SearchUsersByUsername(ctx, username, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users by username")
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
	h.logger.Info("Username search executed",
		util.String("admin_id", adminID.String()),
		util.String("username", username),
		util.Int("results", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchUsersByFullName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	fullName := r.URL.Query().Get("full_name")
	if fullName == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("FULL_NAME_REQUIRED"), "Full name is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 20)
	users, err := h.userService.SearchUsersByFullName(ctx, fullName, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users by full name")
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
	h.logger.Info("Full name search executed",
		util.String("admin_id", adminID.String()),
		util.String("full_name", fullName),
		util.Int("results", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetUserSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("PREFIX_REQUIRED"), "Prefix is required for suggestions")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 10)
	suggestions, err := h.userService.GetUserSuggestions(ctx, prefix, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user suggestions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(suggestions, "User suggestions retrieved"))
	h.logger.Debug("User suggestions retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("suggestions", len(suggestions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user")
		return
	}

	h.sanitizeUserForAdmin(user)
	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))
	h.logger.Info("User updated",
		util.String("admin_id", adminID.String()),
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
	h.logger.Info("User KYC status updated",
		util.String("user_id", userID.String()),
		util.String("updated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) BanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to ban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User banned successfully"))
	h.logger.Info("User banned",
		util.String("user_id", userID.String()),
		util.String("banned_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to unban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))
	h.logger.Info("User unbanned",
		util.String("user_id", userID.String()),
		util.String("unbanned_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)

	users, total, err := h.userService.GetBannedUsers(ctx, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
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
	h.logger.Info("Banned users retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("count", len(users)),
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

func (h *AdminHandler) ChangeAdminMPINByAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to change admin MPIN")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message": "Admin MPIN changed successfully by administrator",
	}, "Admin MPIN change by admin successful"))

	h.logger.Warn("Admin MPIN changed by another admin",
		util.String("admin_id", adminID.String()),
		util.String("changed_by", requesterID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) ChangeOwnPhone(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
// 	if err != nil {
// 		h.logger.Warn("Failed to get admin role mask from token",
// 			util.String("admin_id", requesterID.String()),
// 			util.ErrorField(err))
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
// 		return
// 	}

// 	if requesterRoleMask != models.RoleMaskOwner {
// 		h.logger.Warn("Non-owner attempting to change own phone via admin endpoint",
// 			util.String("admin_id", requesterID.String()),
// 			util.Uint64("role_mask", requesterRoleMask))
// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("PERMISSION_DENIED"),
// 			"Only system owner can change phone numbers")
// 		return
// 	}

// 	var req struct {
// 		NewPhone string `json:"new_phone" validate:"required,phone"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	sessionType, _ := ctx.Value("session_type").(string)
// 	if sessionType != "admin" {
// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("INVALID_SESSION_TYPE"),
// 			"Admin session required")
// 		return
// 	}

// 	// Call service method (will be added to service)
// 	if err := h.adminService.UpdateAdminPhone(ctx, requesterID, req.NewPhone, requesterID); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to change phone")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Phone updated successfully"))
// 	h.logger.Info("Owner changed own phone via HTTP",
// 		util.String("admin_id", requesterID.String()),
// 		util.Uint64("requester_role_mask", requesterRoleMask),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// func (h *AdminHandler) CheckAdminDepartmentAccess(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     departmentName := r.URL.Query().Get("department")
//     if departmentName == "" {
//         h.respondWithError(w, http.StatusBadRequest,
//             fmt.Errorf("department parameter required"),
//             "Department name is required")
//         return
//     }

//     hasAccess, err := h.adminService.CheckAdminDepartmentAccess(ctx, adminID, departmentName)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to check department access")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
//         "has_access": hasAccess,
//         "department": departmentName,
//         "admin_id": adminID.String(),
//     }, "Department access check completed"))

//     h.logger.Debug("Admin department access checked",
//         util.String("admin_id", adminID.String()),
//         util.String("department", departmentName),
//         util.Bool("has_access", hasAccess),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

func (h *AdminHandler) GetAdminWithPermissions(w http.ResponseWriter, r *http.Request) {
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

	adminWithPerms, err := h.adminService.GetAdminWithPermissions(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin with permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(adminWithPerms, "Admin with permissions retrieved successfully"))
	h.logger.Debug("Admin with permissions retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminRoleDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Pass the requesterID to the service method
	departments, err := h.adminService.GetAdminRoleDepartments(ctx, roleID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin role departments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(departments, "Admin role departments retrieved successfully"))
	h.logger.Debug("Admin role departments retrieved",
		util.String("role_id", roleID.String()),
		util.Int("department_count", len(departments)),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) AssignDepartmentToAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Pass the requesterID to the service method
	if err := h.adminService.AssignDepartmentToAdminRole(ctx, roleID, departmentID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to assign department to admin role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department assigned to admin role successfully"))
	h.logger.Info("Department assigned to admin role",
		util.String("role_id", roleID.String()),
		util.String("department_id", departmentID.String()),
		util.String("assigned_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) RemoveDepartmentFromAdminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to remove department from admin role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department removed from admin role successfully"))
	h.logger.Info("Department removed from admin role",
		util.String("role_id", roleID.String()),
		util.String("department_id", departmentID.String()),
		util.String("removed_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) BulkUpdateReportsTo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to bulk update reports_to")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Bulk reports_to update successful"))
	h.logger.Info("Bulk reports_to update",
		util.Int("admin_count", len(adminIDs)),
		util.String("updated_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) GetAllAdmins(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	limit := h.getIntQueryParam(r, "limit", 50)
// 	offset := h.getIntQueryParam(r, "offset", 0)

// 	// Use AdminUserSearchRequest with no filters to get all admins
// 	req := &models.AdminUserSearchRequest{
// 		Query:           "",
// 		SearchType:      "all",
// 		IncludeInactive: true, // Include both active and inactive
// 		Limit:           limit,
// 		Offset:          offset,
// 	}

// 	admins, total, err := h.adminService.SearchAdminUsers(ctx, req, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get all admins")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"admins": admins,
// 		"meta": map[string]interface{}{
// 			"total":  total,
// 			"limit":  limit,
// 			"offset": offset,
// 			"count":  len(admins),
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "All admins retrieved successfully"))
// 	h.logger.Debug("All admins retrieved",
// 		util.Int("count", len(admins)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }
// func (h *AdminHandler) GetActiveAdmins(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	limit := h.getIntQueryParam(r, "limit", 50)
// 	offset := h.getIntQueryParam(r, "offset", 0)

// 	// Use AdminUserSearchRequest
// 	req := &models.AdminUserSearchRequest{
// 		Query:           "",
// 		SearchType:      "all",
// 		IncludeInactive: false, // Set to false for active admins
// 		Limit:           limit,
// 		Offset:          offset,
// 	}

// 	admins, total, err := h.adminService.SearchAdminUsers(ctx, req, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get active admins")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"admins": admins,
// 		"meta": map[string]interface{}{
// 			"total":  total,
// 			"limit":  limit,
// 			"offset": offset,
// 			"count":  len(admins),
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Active admins retrieved successfully"))
// 	h.logger.Debug("Active admins retrieved",
// 		util.Int("count", len(admins)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }
// func (h *AdminHandler) GetInactiveAdmins(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	limit := h.getIntQueryParam(r, "limit", 50)
// 	offset := h.getIntQueryParam(r, "offset", 0)

// 	// Use AdminUserSearchRequest instead of AdminSearchRequest
// 	req := &models.AdminUserSearchRequest{
// 		Query:           "",
// 		SearchType:      "all",
// 		IncludeInactive: true,
// 		Limit:           limit,
// 		Offset:          offset,
// 	}

// 	admins, total, err := h.adminService.SearchAdminUsers(ctx, req, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get inactive admins")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"admins": admins,
// 		"meta": map[string]interface{}{
// 			"total":  total,
// 			"limit":  limit,
// 			"offset": offset,
// 			"count":  len(admins),
// 		},
// 	}

//		h.respondWithJSON(w, http.StatusOK, successResponse(response, "Inactive admins retrieved successfully"))
//		h.logger.Debug("Inactive admins retrieved",
//			util.Int("count", len(admins)),
//			util.Duration("duration", time.Since(startTime)),
//		)
//	}
func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admins by role")
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
	h.logger.Debug("Admins by role retrieved",
		util.String("role_id", roleID.String()),
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) GetAdminsByRoleType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Call the correct service method
	admins, err := h.adminService.GetAdminsByRoleType(ctx, roleType, requesterID, includeInactive, limit, offset)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admins by role type")
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
	h.logger.Debug("Admins by role type retrieved",
		util.Int("role_type", roleType),
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) GetAvailableManagers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get available managers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(managers, "Available managers retrieved successfully"))
	h.logger.Debug("Available managers retrieved",
		util.Int("count", len(managers)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminWithReportsToName(w http.ResponseWriter, r *http.Request) {
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

	admin, err := h.adminService.GetAdminWithReportsToName(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin with reports_to name")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin with reports_to name retrieved successfully"))
	h.logger.Debug("Admin with reports_to name retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) GetAdminWithDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Declare err variable
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin with details")
		return
	}

	response := map[string]interface{}{
		"admin":            admin,
		"permission_names": permissionNames,
		"department_names": departmentNames,
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin with details retrieved successfully"))
	h.logger.Debug("Admin with details retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("permission_count", len(permissionNames)),
		util.Int("department_count", len(departmentNames)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) GetAdminOwner(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	// Declare err variable
// 	_, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	// Check if requester is owner
// 	requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
// 	if err != nil || requesterRoleMask != models.RoleMaskOwner {
// 		h.respondWithError(w, http.StatusForbidden,
// 			errors.New("PERMISSION_DENIED"),
// 			"Only system owner can access this endpoint")
// 		return
// 	}

// 	admin, err := h.adminService.GetAdminOwner(ctx)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get admin owner")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin owner retrieved successfully"))
// 	h.logger.Debug("Admin owner retrieved",
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

func (h *AdminHandler) GetAvatarInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	avatarInfo, err := h.adminService.GetAvatarInfo(ctx, adminID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get avatar info")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(avatarInfo, "Avatar info retrieved successfully"))
	h.logger.Debug("Avatar info retrieved",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) BulkGetAvatarInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to bulk get avatar info")
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
	h.logger.Debug("Bulk avatar info retrieved",
		util.Int("requested_count", len(adminIDs)),
		util.Int("retrieved_count", len(avatarInfos)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Missing Permission Methods ====================
func (h *AdminHandler) CheckAdminPermission(w http.ResponseWriter, r *http.Request) {
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

	permissionName := r.URL.Query().Get("permission")
	if permissionName == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("permission parameter required"),
			"Permission name is required")
		return
	}

	// Check if requester can view target admin's permissions
	if requesterID != adminID {
		// Get requester to check permissions
		requesterAdmin, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get requester admin")
			return
		}

		// Only owner or super employee can check other admins' permissions
		if !requesterAdmin.IsOwner() && !requesterAdmin.IsSuperEmployee() {
			h.respondWithError(w, http.StatusForbidden,
				errors.New("PERMISSION_DENIED"),
				"Cannot check permissions for other admins")
			return
		}
	}

	hasPermission, err := h.adminService.CheckAdminPermission(ctx, adminID, permissionName)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to check permission")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"has_permission": hasPermission,
		"permission":     permissionName,
		"admin_id":       adminID.String(),
	}, "Permission check completed"))

	h.logger.Debug("Admin permission check",
		util.String("requester_id", requesterID.String()),
		util.String("admin_id", adminID.String()),
		util.String("permission", permissionName),
		util.Bool("has_permission", hasPermission),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) GetAdminPermissionMask(w http.ResponseWriter, r *http.Request) {
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

	// Check if requester can view target admin's permission mask
	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID) // Get requester admin
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get requester admin")
			return
		}

		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusNotFound, err, "Target admin not found")
			return
		}

		// Check if requester can manage target admin
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden,
					errors.New("PERMISSION_DENIED"),
					"Cannot view permission mask for this admin")
				return
			}
		}
	}

	permissionMask, err := h.adminService.GetAdminPermissionMask(ctx, adminID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get permission mask")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"permission_mask": permissionMask,
		"segments":        len(permissionMask),
		"total_bits":      len(permissionMask) * 64,
		"admin_id":        adminID.String(),
	}, "Permission mask retrieved successfully"))

	h.logger.Debug("Admin permission mask retrieved",
		util.String("requester_id", requesterID.String()),
		util.String("admin_id", adminID.String()),
		util.Int("segments", len(permissionMask)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Missing Reports To Methods ====================

func (h *AdminHandler) CanAssignReportsTo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Check if requester is authorized
	if requesterID != assignerID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get requester admin")
			return
		}

		// Only owner or super employee can check other admins' permissions
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			h.respondWithError(w, http.StatusForbidden,
				errors.New("PERMISSION_DENIED"),
				"Cannot check assign permissions for other admins")
			return
		}
	}

	canAssign, err := h.adminService.CanAssignReportsTo(ctx, assignerID, targetID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to check assign permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"can_assign":  canAssign,
		"assigner_id": assignerID.String(),
		"target_id":   targetID.String(),
		"reason":      getCanAssignReason(canAssign),
	}, "Assign permissions check completed"))

	h.logger.Debug("Can assign reports to check",
		util.String("requester_id", requesterID.String()),
		util.String("assigner_id", assignerID.String()),
		util.String("target_id", targetID.String()),
		util.Bool("can_assign", canAssign),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Missing Failed Login Management ====================

func (h *AdminHandler) ResetAdminFailedLoginAttempts(w http.ResponseWriter, r *http.Request) {
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

	// Check if requester can reset failed attempts
	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get requester admin")
			return
		}

		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusNotFound, err, "Target admin not found")
			return
		}

		// Only owner or super employee can reset other admins' failed attempts
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden,
					errors.New("PERMISSION_DENIED"),
					"Cannot reset failed login attempts for this admin")
				return
			}
		}
	}

	if err := h.adminService.ResetAdminFailedLoginAttempts(ctx, adminID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to reset failed login attempts")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"message":  "Failed login attempts reset successfully",
		"admin_id": adminID.String(),
	}, "Failed login attempts reset"))

	h.logger.Info("Admin failed login attempts reset",
		util.String("requester_id", requesterID.String()),
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Missing Department Access Methods ====================

func (h *AdminHandler) CheckAdminDepartmentAccess(w http.ResponseWriter, r *http.Request) {
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

	departmentName := chi.URLParam(r, "department")
	if departmentName == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("department parameter required"),
			"Department name is required")
		return
	}

	// Check if requester can view target admin's department access
	if requesterID != adminID {
		requester, err := h.adminService.GetAdminUser(ctx, requesterID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get requester admin")
			return
		}

		targetAdmin, err := h.adminService.GetAdminUser(ctx, adminID, requesterID)
		if err != nil {
			h.respondWithError(w, http.StatusNotFound, err, "Target admin not found")
			return
		}

		// Check if requester can manage target admin
		if !requester.IsOwner() && !requester.IsSuperEmployee() {
			if !h.canManageAdmin(requester, targetAdmin) {
				h.respondWithError(w, http.StatusForbidden,
					errors.New("PERMISSION_DENIED"),
					"Cannot check department access for this admin")
				return
			}
		}
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
		"admin_id":   adminID.String(),
	}, "Department access check completed"))

	h.logger.Debug("Admin department access check",
		util.String("requester_id", requesterID.String()),
		util.String("admin_id", adminID.String()),
		util.String("department", departmentName),
		util.Bool("has_access", hasAccess),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ==================== Missing Promotion Methods ====================

// ==================== Missing Owner Management ====================

// ==================== Missing Department Bitmask Methods ====================

// ==================== Helper Functions ====================

func (h *AdminHandler) canManageAdmin(manager, target *models.AdminUser) bool {
	// Owner can manage everyone
	if manager.IsOwner() {
		return true
	}

	// Super employee can manage employees
	if manager.IsSuperEmployee() && target.IsEmployee() {
		return true
	}

	// Managers can only manage employees in their departments
	if manager.IsManager() && target.IsEmployee() {
		// This is a simplified check - you'll need to implement actual department access check
		return true
	}

	return false
}

func getCanAssignReason(canAssign bool) string {
	if canAssign {
		return "Assigner has sufficient permissions and hierarchy allows"
	}
	return "Assigner lacks permissions or hierarchy violation"
}

func getRoleStringFromMask(roleMask uint64) string {
	switch roleMask {
	case 1:
		return "Employee"
	case 2:
		return "Manager"
	case 4:
		return "Super Admin"
	default:
		return "Unknown"
	}
}

func (h *AdminHandler) SearchAdminsWithFilters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("search_type")
	if searchType == "" {
		searchType = "all"
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	var includeInactive bool
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admins with filters")
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
	h.logger.Info("Admin search with filters executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", query),
		util.Int("results", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAdminsByDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admins by department")
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
	h.logger.Debug("Admins by department retrieved",
		util.String("department_id", departmentID.String()),
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}
func (h *AdminHandler) SearchAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("QUERY_REQUIRED"),
			"Search query is required")
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admins")
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
	h.logger.Info("Admin search executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", query),
		util.Int("results", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchAdminsAdvanced(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	// Parse query parameters into AdminAdvancedSearchRequest
	var filters models.AdminSearchFilter

	// Parse various filter parameters
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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admins")
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
	h.logger.Info("Advanced admin search executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", req.Query),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetSystemDepartments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Simply check if user is authenticated, don't need the ID
	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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
func (h *AdminHandler) GetPermissionsByModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Simply check if user is authenticated, don't need the ID
	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

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

// ==================== Admin Search Methods (Add these) ====================

func (h *AdminHandler) SearchAdminsByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("NAME_REQUIRED"),
			"Name is required")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	results, total, err := h.adminService.SearchAdminsByName(ctx, name, requesterID, limit, offset)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admins by name")
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
	h.logger.Info("Admin search by name executed",
		util.String("requester_id", requesterID.String()),
		util.String("name", name),
		util.Int("results", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchAdminEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admin employees")
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
	h.logger.Info("Admin employees search executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", query),
		util.Int("results", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SearchAdminManagers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to search admin managers")
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
	h.logger.Info("Admin managers search executed",
		util.String("requester_id", requesterID.String()),
		util.String("query", query),
		util.Int("results", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

// // GetAdminPhoneNumber retrieves and decrypts an admin's phone number (super admin only)
// func (h *AdminHandler) GetAdminPhoneNumber(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	// Get requester ID
// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	// Get target admin ID from URL
// 	adminIDStr := chi.URLParam(r, "adminID")
// 	adminID, err := uuid.Parse(adminIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
// 		return
// 	}

// 	// Check if requester is owner by verifying their role mask
// 	requesterRoleMask, err := h.getRequesterAdminRoleMask(r)
// 	if err != nil {
// 		h.logger.Warn("Failed to get admin role mask from token",
// 			util.String("admin_id", requesterID.String()),
// 			util.ErrorField(err))
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unable to verify admin role")
// 		return
// 	}

// 	// Only owner (super admin) can access decrypted phone numbers
// 	if requesterRoleMask != models.RoleMaskOwner {
// 		h.logger.Warn("Non-owner attempting to access admin phone number",
// 			util.String("requester_id", requesterID.String()),
// 			util.String("target_admin_id", adminID.String()),
// 			util.Uint64("requester_role_mask", requesterRoleMask))

// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("PERMISSION_DENIED"),
// 			"Only system owner can access decrypted phone numbers")
// 		return
// 	}

// 	// Check if session type is admin
// 	sessionType, ok := ctx.Value("session_type").(string)
// 	if !ok || sessionType != "admin" {
// 		h.respondWithError(w, http.StatusForbidden,
// 			fmt.Errorf("INVALID_SESSION_TYPE"),
// 			"Admin session required")
// 		return
// 	}

// 	// Call service method
// 	phoneNumber, err := h.adminService.GetAdminPhoneNumber(ctx, adminID, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to get admin phone number")
// 		return
// 	}

// 	// Create response (mask part of the phone number for security)
// 	maskedPhone := maskPhoneNumber(phoneNumber)

// 	response := map[string]interface{}{
// 		"phone_number":     phoneNumber,
// 		"masked_phone":     maskedPhone,
// 		"admin_id":         adminID.String(),
// 		"accessed_by":      requesterID.String(),
// 		"access_timestamp": time.Now().UTC(),
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin phone number retrieved successfully"))

// 	h.logger.Info("Admin phone number accessed",
// 		util.String("requester_id", requesterID.String()),
// 		util.String("target_admin_id", adminID.String()),
// 		util.Bool("is_owner", true),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// Helper function to mask phone number for logging/response
func maskPhoneNumber(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}
	return "****" + phone[len(phone)-4:]
}

// ==================== Super Admin Initialization ====================
// ==================== Super Admin Initialization ====================

// InitDefaultSuperAdminHandler initializes the default super admin (Sarvesh Chhabra)
// This is a public endpoint for initial system setup
func (h *AdminHandler) InitSuperAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	h.logger.Info("Default super admin initialization request received",
		util.String("source_ip", h.getClientIP(r)),
		util.String("user_agent", r.UserAgent()))

	// Check if super admin already exists first
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

		h.logger.Info("Super admin already exists - returning existing admin",
			util.String("admin_id", existingAdmin.AdminID.String()),
			util.String("username", existingAdmin.Username))
		return
	}

	// Initialize default super admin (Sarvesh Chhabra)
	admin, err := h.adminService.InitDefaultSuperAdmin(ctx)
	if err != nil {
		h.logger.Error("Failed to initialize default super admin",
			util.ErrorField(err),
			util.String("source_ip", h.getClientIP(r)))

		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to initialize super admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"super_admin_exists": true,
		"admin_id":           admin.AdminID.String(),
		"username":           admin.Username,
		"full_name":          admin.FullName,
		"role_type":          admin.RoleType,
		"role_string":        admin.GetRoleString(),
		"phone_number":       "+917206583437", // Returning for reference
		"is_active":          admin.IsActive,
		"created_at":         admin.AdminCreatedAt,
		"message":            "Default super admin (Sarvesh Chhabra) initialized successfully",
	}, "Super admin initialization complete"))

	h.logger.Info("Default super admin initialized successfully",
		util.String("admin_id", admin.AdminID.String()),
		util.String("username", admin.Username),
		util.Duration("duration", time.Since(startTime)))
}

// CheckSuperAdminStatusHandler checks if super admin exists (public endpoint)
func (h *AdminHandler) CheckSuperAdminStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	initialized, admin, err := h.adminService.CheckAndInitSuperAdmin(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to check super admin status")
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

	h.logger.Debug("Super admin status checked",
		util.Bool("exists", admin != nil),
		util.Bool("initialized", initialized),
		util.Duration("duration", time.Since(startTime)))
}

// Helper function for status messages
func getSuperAdminStatusMessage(initialized bool, admin *models.AdminUser) string {
	if admin == nil {
		return "Super admin does not exist"
	}
	if initialized {
		return "Super admin was just initialized"
	}
	return "Super admin already exists"
}

// HealthCheckHandler is a public health check endpoint
func (h *AdminHandler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check database connectivity
	if err := h.adminService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err, "Service unhealthy")
		return
	}

	// Check super admin status
	exists, _, _ := h.adminService.CheckAndInitSuperAdmin(ctx)

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"status":            "healthy",
		"service":           "auth-service",
		"super_admin_setup": exists,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	}, "Service is healthy"))
}

// Helper function for phone maski

// handler/admin_handler.go - Add these new handler methods

// func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req models.EmployeeRoleCreateRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Convert to the internal request format
// 	internalReq := models.AdminRoleCreateRequest{
// 		RoleName:    req.RoleName,
// 		RoleType:    models.RoleTypeEmployee, // Employee role
// 		Description: req.Description,
// 	}

// 	// Get department IDs and validate permissions
// 	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
// 		return
// 	}

// 	deptIDMap := make(map[string]uuid.UUID)
// 	for _, dept := range systemDepartments {
// 		deptIDMap[dept.Name] = dept.SystemDepartmentID
// 	}

// 	// Validate department permissions
// 	for _, deptPerm := range req.DepartmentPermissions {
// 		deptID, exists := deptIDMap[deptPerm.DepartmentName]
// 		if !exists {
// 			h.respondWithError(w, http.StatusBadRequest,
// 				fmt.Errorf("department not found: %s", deptPerm.DepartmentName),
// 				fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
// 			return
// 		}

// 		// Get permissions for this department
// 		permissions, err := h.companyService.GetPermissionsByModule(ctx, deptPerm.DepartmentName)
// 		if err != nil {
// 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get department permissions")
// 			return
// 		}

// 		// Create a set of valid permissions for this department
// 		validPerms := make(map[string]bool)
// 		for _, perm := range permissions {
// 			validPerms[perm.PermissionName] = true
// 		}

// 		// Validate each permission
// 		for _, permName := range deptPerm.Permissions {
// 			if !validPerms[permName] {
// 				h.respondWithError(w, http.StatusBadRequest,
// 					fmt.Errorf("permission not found in department"),
// 					fmt.Sprintf("Permission %s does not exist in department %s", permName, deptPerm.DepartmentName))
// 				return
// 			}
// 		}

// 		// Store department ID
// 		internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, deptID)
// 	}

// 	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to create employee role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
// 	h.logger.Info("Employee role created",
// 		util.String("role_id", role.AdminRoleID.String()),
// 		util.String("created_by", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// func (h *AdminHandler) CreateManagerRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req models.ManagerRoleCreateRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Convert to the internal request format
// 	internalReq := models.AdminRoleCreateRequest{
// 		RoleName:    req.RoleName,
// 		RoleType:    models.RoleTypeManager, // Manager role
// 		Description: req.Description,
// 	}

// 	// Get department IDs
// 	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
// 		return
// 	}

// 	deptIDMap := make(map[string]uuid.UUID)
// 	for _, dept := range systemDepartments {
// 		deptIDMap[dept.Name] = dept.SystemDepartmentID
// 	}

// 	// Validate department names and get IDs
// 	for _, deptName := range req.DepartmentNames {
// 		deptID, exists := deptIDMap[deptName]
// 		if !exists {
// 			h.respondWithError(w, http.StatusBadRequest,
// 				fmt.Errorf("department not found: %s", deptName),
// 				fmt.Sprintf("Department %s does not exist", deptName))
// 			return
// 		}
// 		internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, deptID)
// 	}

// 	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to create manager role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Manager role created successfully"))
// 	h.logger.Info("Manager role created",
// 		util.String("role_id", role.AdminRoleID.String()),
// 		util.String("created_by", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()
//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req models.EmployeeRoleCreateRequest
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     internalReq := models.AdminRoleCreateRequest{
//         RoleName:    req.RoleName,
//         RoleType:    models.RoleTypeEmployee,
//         Description: req.Description,
//     }

//     systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
//         return
//     }

//     // Create map from department name to department object
//     deptMap := make(map[string]*models.SystemDepartment)
//     for _, dept := range systemDepartments {
//         deptMap[dept.Name] = dept
//     }

//     for _, deptPerm := range req.DepartmentPermissions {
//         dept, exists := deptMap[deptPerm.DepartmentName]
//         if !exists {
//             h.respondWithError(w, http.StatusBadRequest,
//                 fmt.Errorf("department not found: %s", deptPerm.DepartmentName),
//                 fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
//             return
//         }

//         // Get module code from department and use it to fetch permissions
//         moduleCode := dept.ModuleCode // This should be 'sales' for department 'Sales'
//         permissions, err := h.companyService.GetPermissionsByModule(ctx, moduleCode)
//         if err != nil {
//             h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get department permissions")
//             return
//         }

//         validPerms := make(map[string]bool)
//         for _, perm := range permissions {
//             validPerms[perm.PermissionName] = true
//         }

//         for _, permName := range deptPerm.Permissions {
//             if !validPerms[permName] {
//                 h.respondWithError(w, http.StatusBadRequest,
//                     fmt.Errorf("permission not found in department"),
//                     fmt.Sprintf("Permission %s does not exist in department %s (module: %s)",
//                         permName, deptPerm.DepartmentName, moduleCode))
//                 return
//             }
//         }

//         internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, dept.SystemDepartmentID)
//     }

//     role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to create employee role")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
//     h.logger.Info("Employee role created",
//         util.String("role_id", role.AdminRoleID.String()),
//         util.String("created_by", requesterID.String()),
//         util.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()
// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req models.EmployeeRoleCreateRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Create the base role
// 	internalReq := models.AdminRoleCreateRequest{
// 		RoleName:    req.RoleName,
// 		RoleType:    models.RoleTypeEmployee,
// 		Description: req.Description,
// 	}

// 	// Get system departments
// 	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
// 		return
// 	}

// 	// Map department names to IDs and collect department IDs
// 	deptMap := make(map[string]*models.SystemDepartment)
// 	departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentPermissions))

// 	for _, deptPerm := range req.DepartmentPermissions {
// 		dept, exists := deptMap[deptPerm.DepartmentName]
// 		if !exists {
// 			// Find the department in system departments
// 			for _, sysDept := range systemDepartments {
// 				if sysDept.Name == deptPerm.DepartmentName {
// 					dept = sysDept
// 					deptMap[deptPerm.DepartmentName] = sysDept
// 					break
// 				}
// 			}
// 			if dept == nil {
// 				h.respondWithError(w, http.StatusBadRequest,
// 					fmt.Errorf("department not found: %s", deptPerm.DepartmentName),
// 					fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
// 				return
// 			}
// 		}

// 		// Validate permissions exist for this department/module
// 		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
// 		if err != nil {
// 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get department permissions")
// 			return
// 		}

// 		// Build a map of valid permission names for this module
// 		validPerms := make(map[string]bool)
// 		for _, perm := range permissions {
// 			validPerms[perm.PermissionName] = true
// 		}

// 		// Validate each requested permission
// 		for _, permName := range deptPerm.Permissions {
// 			if !validPerms[permName] {
// 				h.respondWithError(w, http.StatusBadRequest,
// 					fmt.Errorf("permission not found in department"),
// 					fmt.Sprintf("Permission %s does not exist in department %s (module: %s)",
// 						permName, deptPerm.DepartmentName, dept.ModuleCode))
// 				return
// 			}
// 		}

// 		departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
// 	}

// 	internalReq.DepartmentIDs = departmentIDs

// 	// Create the role first
// 	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to create employee role")
// 		return
// 	}

// 	// Now grant the specific permissions for each department
// 	for _, deptPerm := range req.DepartmentPermissions {
// 		dept := deptMap[deptPerm.DepartmentName]

// 		// Get all permissions for this module to find their IDs
// 		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
// 		if err != nil {
// 			h.logger.Warn("Failed to get permissions for granting",
// 				zap.String("role_id", role.AdminRoleID.String()),
// 				zap.String("department", dept.Name),
// 				zap.Error(err))
// 			continue
// 		}

// 		// Create a map of permission name to ID
// 		permMap := make(map[string]uuid.UUID)
// 		for _, perm := range permissions {
// 			permMap[perm.PermissionName] = perm.PermissionID
// 		}

// 		// Grant each specified permission
// 		for _, permName := range deptPerm.Permissions {
// 			permID, exists := permMap[permName]
// 			if !exists {
// 				h.logger.Warn("Permission not found for granting",
// 					zap.String("role_id", role.AdminRoleID.String()),
// 					zap.String("permission", permName))
// 				continue
// 			}

// 			// Grant this specific permission to the role
// 			if err := h.adminService.GrantPermissionToAdminRole(ctx, role.AdminRoleID, permID, requesterID); err != nil {
// 				h.logger.Warn("Failed to grant permission to role",
// 					zap.String("role_id", role.AdminRoleID.String()),
// 					zap.String("permission_id", permID.String()),
// 					zap.Error(err))
// 			}
// 		}
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
// 	h.logger.Info("Employee role created",
// 		zap.String("role_id", role.AdminRoleID.String()),
// 		zap.String("created_by", requesterID.String()),
// 		zap.Duration("duration", time.Since(startTime)),
// 	)
// }

func (h *AdminHandler) GetAdminRoleWithDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin role details")
		return
	}

	response := map[string]interface{}{
		"role":        role,
		"departments": departments,
		"permissions": permissions,
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin role details retrieved successfully"))

	h.logger.Info("Admin role details retrieved",
		util.String("role_id", roleID.String()),
		util.String("requester_id", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetEmployeeAdminRoles handles GET /admin/employee-roles
func (h *AdminHandler) GetEmployeeAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roles, err := h.adminService.GetEmployeeAdminRoles(ctx, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get employee admin roles")
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
	h.logger.Info("Employee admin roles retrieved",
		util.String("requester_id", requesterID.String()),
		util.Int("count", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetManagerAdminRoles handles GET /admin/manager-roles
func (h *AdminHandler) GetManagerAdminRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	roles, err := h.adminService.GetManagerAdminRoles(ctx, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get manager admin roles")
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
	h.logger.Info("Manager admin roles retrieved",
		util.String("requester_id", requesterID.String()),
		util.Int("count", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAdminRolesByType handles GET /admin/roles/type/{roleType}
func (h *AdminHandler) GetAdminRolesByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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

	// Validate role type
	validRoleTypes := []int{models.RoleTypeEmployee, models.RoleTypeManager, models.RoleTypeSuperAdmin}
	isValid := false
	for _, validType := range validRoleTypes {
		if roleType == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("invalid role type: %d", roleType),
			"Role type must be 1 (employee), 2 (manager), or 3 (super admin)")
		return
	}

	roles, err := h.adminService.GetAdminRolesByType(ctx, roleType, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin roles by type")
		return
	}

	// Get role type string for response
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
	h.logger.Info("Admin roles by type retrieved",
		util.String("requester_id", requesterID.String()),
		util.Int("role_type", roleType),
		util.Int("count", len(roles)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req models.EmployeeRoleCreateRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Check if role with the same name already exists BEFORE trying to create
// 	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
// 	if err != nil && !strings.Contains(err.Error(), "admin role not found") {
// 		// If error is not "not found", log but continue (not critical)
// 		h.logger.Warn("Failed to check existing role",
// 			zap.String("role_name", req.RoleName),
// 			zap.Error(err))
// 	}

// 	if existingRole != nil {
// 		h.respondWithError(w, http.StatusConflict,
// 			fmt.Errorf("role with name '%s' already exists", req.RoleName),
// 			"Role name already exists")
// 		return
// 	}

// 	internalReq := models.AdminRoleCreateRequest{
// 		RoleName:    req.RoleName,
// 		RoleType:    models.RoleTypeEmployee,
// 		Description: req.Description,
// 	}

// 	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
// 		return
// 	}

// 	deptMap := make(map[string]*models.SystemDepartment)
// 	departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentPermissions))

// 	for _, deptPerm := range req.DepartmentPermissions {
// 		dept, exists := deptMap[deptPerm.DepartmentName]
// 		if !exists {
// 			for _, sysDept := range systemDepartments {
// 				if sysDept.Name == deptPerm.DepartmentName {
// 					dept = sysDept
// 					deptMap[deptPerm.DepartmentName] = sysDept
// 					break
// 				}
// 			}
// 			if dept == nil {
// 				h.respondWithError(w, http.StatusBadRequest,
// 					fmt.Errorf("department not found: %s", deptPerm.DepartmentName),
// 					fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
// 				return
// 			}
// 		}

// 		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
// 		if err != nil {
// 			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get department permissions")
// 			return
// 		}

// 		validPerms := make(map[string]bool)
// 		for _, perm := range permissions {
// 			validPerms[perm.PermissionName] = true
// 		}

// 		for _, permName := range deptPerm.Permissions {
// 			if !validPerms[permName] {
// 				h.respondWithError(w, http.StatusBadRequest,
// 					fmt.Errorf("permission not found in department"),
// 					fmt.Sprintf("Permission %s does not exist in department %s (module: %s)",
// 						permName, deptPerm.DepartmentName, dept.ModuleCode))
// 				return
// 			}
// 		}

// 		departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
// 	}

// 	internalReq.DepartmentIDs = departmentIDs

// 	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		// Check for duplicate key error from database
// 		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
// 			statusCode = http.StatusConflict
// 			err = fmt.Errorf("role with name '%s' already exists", req.RoleName)
// 		}
// 		h.respondWithError(w, statusCode, err, "Failed to create employee role")
// 		return
// 	}

// 	// Grant permissions to the role
// 	for _, deptPerm := range req.DepartmentPermissions {
// 		dept := deptMap[deptPerm.DepartmentName]
// 		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
// 		if err != nil {
// 			h.logger.Warn("Failed to get permissions for granting",
// 				zap.String("role_id", role.AdminRoleID.String()),
// 				zap.String("department", dept.Name),
// 				zap.Error(err))
// 			continue
// 		}

// 		permMap := make(map[string]uuid.UUID)
// 		for _, perm := range permissions {
// 			permMap[perm.PermissionName] = perm.PermissionID
// 		}

// 		for _, permName := range deptPerm.Permissions {
// 			permID, exists := permMap[permName]
// 			if !exists {
// 				h.logger.Warn("Permission not found for granting",
// 					zap.String("role_id", role.AdminRoleID.String()),
// 					zap.String("permission", permName))
// 				continue
// 			}

// 			if err := h.adminService.GrantPermissionToAdminRole(ctx, role.AdminRoleID, permID, requesterID); err != nil {
// 				h.logger.Warn("Failed to grant permission to role",
// 					zap.String("role_id", role.AdminRoleID.String()),
// 					zap.String("permission_id", permID.String()),
// 					zap.Error(err))
// 			}
// 		}
// 	}

//		h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
//		h.logger.Info("Employee role created",
//			zap.String("role_id", role.AdminRoleID.String()),
//			zap.String("created_by", requesterID.String()),
//			zap.Duration("duration", time.Since(startTime)),
//		)
//	}
func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

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
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to list admins")
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
	h.logger.Debug("Admins listed",
		util.Int("count", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetAllAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Get ALL admins including inactive
	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: true, // Include inactive users
	})

	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get all admins")
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
	h.logger.Debug("All admins retrieved",
		util.Int("count", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetActiveAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Get only ACTIVE admins
	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: false, // Only active users
	})

	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get active admins")
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
	h.logger.Debug("Active admins retrieved",
		util.Int("count", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetInactiveAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	// We need to filter inactive admins differently since the service method doesn't have an "inactive only" flag
	// Let's get all admins and filter them, or create a new service method
	results, total, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
		Query:           "",
		SearchType:      "all",
		Limit:           limit,
		Offset:          offset,
		IncludeInactive: true, // Include both active and inactive
	})

	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get inactive admins")
		return
	}

	// Filter for inactive admins only
	var inactiveAdmins []*models.AdminUserSearchResult
	for _, admin := range results {
		if !admin.IsActive {
			inactiveAdmins = append(inactiveAdmins, admin)
		}
	}

	// Calculate total inactive count (for pagination)
	// This is a simplified approach - in production you'd want a separate DB query
	totalInactive := 0
	if total > 0 {
		// For simplicity, estimate based on current page ratio
		// Better to create a separate repository method
		allResults, _, err := h.adminService.SearchAdminsWithFilters(ctx, requesterID, &models.AdminSearchRequest{
			Query:           "",
			SearchType:      "all",
			Limit:           1000, // Large limit to get all
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
			// Fallback: use current page ratio
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
	h.logger.Debug("Inactive admins retrieved",
		util.Int("count", len(inactiveAdmins)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// func (h *AdminHandler) CreateManagerRole(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	requesterID, err := h.getRequesterAdminID(r)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
// 		return
// 	}

// 	var req models.ManagerRoleCreateRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Validate request
// 	if req.RoleName == "" {
// 		h.respondWithError(w, http.StatusBadRequest,
// 			fmt.Errorf("role name cannot be empty"),
// 			"Role name is required")
// 		return
// 	}

// 	if len(req.DepartmentNames) == 0 {
// 		h.respondWithError(w, http.StatusBadRequest,
// 			fmt.Errorf("at least one department must be specified"),
// 			"At least one department is required")
// 		return
// 	}

// 	// Check if role with same name already exists
// 	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
// 	if err != nil && !strings.Contains(err.Error(), "admin role not found") {
// 		h.respondWithError(w, http.StatusInternalServerError, err,
// 			"Failed to check existing roles")
// 		return
// 	}

// 	if existingRole != nil {
// 		h.respondWithError(w, http.StatusConflict,
// 			fmt.Errorf("role with name '%s' already exists", req.RoleName),
// 			fmt.Sprintf("Role '%s' already exists", req.RoleName))
// 		return
// 	}

// 	internalReq := models.AdminRoleCreateRequest{
// 		RoleName:    req.RoleName,
// 		RoleType:    models.RoleTypeManager,
// 		Description: req.Description,
// 	}

// 	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err,
// 			"Failed to get system departments")
// 		return
// 	}

// 	deptIDMap := make(map[string]uuid.UUID)
// 	for _, dept := range systemDepartments {
// 		deptIDMap[dept.Name] = dept.SystemDepartmentID
// 	}

// 	for _, deptName := range req.DepartmentNames {
// 		deptID, exists := deptIDMap[deptName]
// 		if !exists {
// 			h.respondWithError(w, http.StatusBadRequest,
// 				fmt.Errorf("department not found: %s", deptName),
// 				fmt.Sprintf("Department '%s' does not exist", deptName))
// 			return
// 		}
// 		internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, deptID)
// 	}

// 	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to create manager role")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Manager role created successfully"))

// 	h.logger.Info("Manager role created",
// 		util.String("role_id", role.AdminRoleID.String()),
// 		util.String("created_by", requesterID.String()),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

func (h *AdminHandler) CreateEmployeeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()
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

	// Check if role name already exists
	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
	if err != nil {
		// Only log if it's not a "not found" error
		if !strings.Contains(err.Error(), "admin role not found") && !strings.Contains(err.Error(), "admin role is nil") {
			h.logger.Warn("Failed to check existing role",
				zap.String("role_name", req.RoleName),
				zap.Error(err))
		}
	} else if existingRole != nil {
		h.respondWithError(w, http.StatusConflict,
			fmt.Errorf("role with name '%s' already exists", req.RoleName),
			"Role name already exists")
		return
	}

	// Create internal request
	internalReq := models.AdminRoleCreateRequest{
		RoleName:    req.RoleName,
		RoleType:    models.RoleTypeEmployee,
		Description: req.Description,
	}

	// Get system departments
	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get system departments")
		return
	}

	deptMap := make(map[string]*models.SystemDepartment)
	departmentIDs := make([]uuid.UUID, 0, len(req.DepartmentPermissions))

	// Validate departments and permissions
	for _, deptPerm := range req.DepartmentPermissions {
		dept, exists := deptMap[deptPerm.DepartmentName]
		if !exists {
			// Find the department in system departments
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
				h.respondWithError(w, http.StatusBadRequest,
					fmt.Errorf("department not found: %s", deptPerm.DepartmentName),
					fmt.Sprintf("Department %s does not exist", deptPerm.DepartmentName))
				return
			}
		}

		// Get permissions for this department/module
		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get department permissions")
			return
		}

		// Validate permissions exist in department
		validPerms := make(map[string]bool)
		for _, perm := range permissions {
			validPerms[perm.PermissionName] = true
		}

		for _, permName := range deptPerm.Permissions {
			if !validPerms[permName] {
				h.respondWithError(w, http.StatusBadRequest,
					fmt.Errorf("permission not found in department"),
					fmt.Sprintf("Permission %s does not exist in department %s (module: %s)",
						permName, deptPerm.DepartmentName, dept.ModuleCode))
				return
			}
		}

		departmentIDs = append(departmentIDs, dept.SystemDepartmentID)
	}

	internalReq.DepartmentIDs = departmentIDs

	// Create the role
	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			statusCode = http.StatusConflict
			err = fmt.Errorf("role with name '%s' already exists", req.RoleName)
		}
		h.respondWithError(w, statusCode, err, "Failed to create employee role")
		return
	}

	// Grant permissions to the role
	for _, deptPerm := range req.DepartmentPermissions {
		dept := deptMap[deptPerm.DepartmentName]
		permissions, err := h.companyService.GetPermissionsByModule(ctx, dept.ModuleCode)
		if err != nil {
			h.logger.Warn("Failed to get permissions for granting",
				zap.String("role_id", role.AdminRoleID.String()),
				zap.String("department", dept.Name),
				zap.Error(err))
			continue
		}

		// Map permission names to IDs
		permMap := make(map[string]uuid.UUID)
		for _, perm := range permissions {
			permMap[perm.PermissionName] = perm.PermissionID
		}

		// Grant each permission
		for _, permName := range deptPerm.Permissions {
			permID, exists := permMap[permName]
			if !exists {
				h.logger.Warn("Permission not found for granting",
					zap.String("role_id", role.AdminRoleID.String()),
					zap.String("permission", permName))
				continue
			}

			if err := h.adminService.GrantPermissionToAdminRole(ctx, role.AdminRoleID, permID, requesterID); err != nil {
				h.logger.Warn("Failed to grant permission to role",
					zap.String("role_id", role.AdminRoleID.String()),
					zap.String("permission_id", permID.String()),
					zap.Error(err))
			}
		}
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Employee role created successfully"))
	h.logger.Info("Employee role created",
		zap.String("role_id", role.AdminRoleID.String()),
		zap.String("created_by", requesterID.String()),
		zap.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) CreateManagerRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()
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
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("role name cannot be empty"),
			"Role name is required")
		return
	}

	if len(req.DepartmentNames) == 0 {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("at least one department must be specified"),
			"At least one department is required")
		return
	}

	// Check if role already exists
	existingRole, err := h.adminService.GetAdminRoleByName(ctx, req.RoleName)
	if err != nil {
		// Only return error if it's not a "not found" error
		if !strings.Contains(err.Error(), "admin role not found") && !strings.Contains(err.Error(), "admin role is nil") {
			h.respondWithError(w, http.StatusInternalServerError, err,
				"Failed to check existing roles")
			return
		}
	} else if existingRole != nil {
		h.respondWithError(w, http.StatusConflict,
			fmt.Errorf("role with name '%s' already exists", req.RoleName),
			fmt.Sprintf("Role '%s' already exists", req.RoleName))
		return
	}

	// Create internal request
	internalReq := models.AdminRoleCreateRequest{
		RoleName:    req.RoleName,
		RoleType:    models.RoleTypeManager,
		Description: req.Description,
	}

	// Get system departments
	systemDepartments, err := h.companyService.GetSystemDepartments(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err,
			"Failed to get system departments")
		return
	}

	// Map department names to IDs
	deptIDMap := make(map[string]uuid.UUID)
	for _, dept := range systemDepartments {
		deptIDMap[dept.Name] = dept.SystemDepartmentID
	}

	// Validate and collect department IDs
	for _, deptName := range req.DepartmentNames {
		deptID, exists := deptIDMap[deptName]
		if !exists {
			h.respondWithError(w, http.StatusBadRequest,
				fmt.Errorf("department not found: %s", deptName),
				fmt.Sprintf("Department '%s' does not exist", deptName))
			return
		}
		internalReq.DepartmentIDs = append(internalReq.DepartmentIDs, deptID)
	}

	// Create the role
	role, err := h.adminService.CreateAdminRole(ctx, &internalReq, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create manager role")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Manager role created successfully"))
	h.logger.Info("Manager role created",
		util.String("role_id", role.AdminRoleID.String()),
		util.String("created_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAdminPhoneNumber retrieves and decrypts an admin's phone number (super admin only)
func (h *AdminHandler) GetAdminPhoneNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get requester ID
	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	// Get target admin ID from URL
	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	// Call service method
	phoneNumber, err := h.adminService.GetAdminPhoneNumber(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin phone number")
		return
	}

	// Create response (mask part of the phone number for security)
	maskedPhone := maskPhoneNumber(phoneNumber)

	response := map[string]interface{}{
		"phone_number":     phoneNumber,
		"masked_phone":     maskedPhone,
		"admin_id":         adminID.String(),
		"accessed_by":      requesterID.String(),
		"access_timestamp": time.Now().UTC(),
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin phone number retrieved successfully"))

	h.logger.Info("Admin phone number accessed",
		util.String("requester_id", requesterID.String()),
		util.String("target_admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) ListUsersByKYCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get requester admin ID for authorization
	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Get KYC status from URL parameter
	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("STATUS_REQUIRED"), "KYC status is required")
		return
	}

	// Validate KYC status
	validStatuses := map[string]bool{
		"pending": true, "verified": true, "rejected": true,
		"under_review": true, "expired": true,
	}
	if !validStatuses[status] {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("INVALID_KYC_STATUS"),
			"Invalid KYC status. Must be: pending, verified, rejected, under_review, or expired")
		return
	}

	// Get pagination parameters
	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Validate limit
	if limit <= 0 || limit > 1000 {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("INVALID_LIMIT"),
			"Limit must be between 1 and 1000")
		return
	}

	// Call service method
	users, total, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by KYC status")
		return
	}

	// Sanitize user data for admin response
	sanitizedUsers := make([]map[string]interface{}, len(users))
	for i, user := range users {
		sanitizedUsers[i] = h.sanitizeUserForAdminResponse(user)
	}

	// Prepare response
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

	h.logger.Info("Users retrieved by KYC status",
		util.String("admin_id", adminID.String()),
		util.String("kyc_status", status),
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) GetRecentlyActiveUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get requester admin ID for authorization
	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	// Get query parameters
	days := h.getIntQueryParam(r, "days", 7)
	limit := h.getIntQueryParam(r, "limit", 100)

	// Validate parameters
	if days <= 0 || days > 365 {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("INVALID_DAYS_RANGE"),
			"Days must be between 1 and 365")
		return
	}

	if limit <= 0 || limit > 1000 {
		h.respondWithError(w, http.StatusBadRequest,
			errors.New("INVALID_LIMIT"),
			"Limit must be between 1 and 1000")
		return
	}

	// Calculate since time
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	// Call service method
	users, err := h.userService.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get recently active users")
		return
	}

	// Sanitize user data for admin response
	sanitizedUsers := make([]map[string]interface{}, len(users))
	for i, user := range users {
		sanitizedUsers[i] = h.sanitizeUserForAdminResponse(user)
	}

	// Prepare response
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

	h.logger.Info("Recently active users retrieved",
		util.String("admin_id", adminID.String()),
		util.Int("days", days),
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// Helper method to sanitize user data for admin response
func (h *AdminHandler) sanitizeUserForAdminResponse(user *models.User) map[string]interface{} {
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

// GetAdminDepartments gets all departments assigned to an admin user
func (h *AdminHandler) GetAdminDepartments(w http.ResponseWriter, r *http.Request) {
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

	departments, err := h.adminService.GetAdminDepartments(ctx, adminID, requesterID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admin departments")
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

	h.logger.Debug("Admin departments retrieved",
		util.String("requester_id", requesterID.String()),
		util.String("admin_id", adminID.String()),
		util.Int("department_count", len(departments)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateAdminUserRole updates an admin user's role
func (h *AdminHandler) UpdateAdminUserRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get requester admin ID (who is making the change)
	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	// Get admin ID from URL parameter
	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	// Parse request body
	var req struct {
		NewRoleID string `json:"new_role_id" validate:"required,uuid"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate new role ID
	newRoleID, err := uuid.Parse(req.NewRoleID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	// Call the service method
	if err := h.adminService.UpdateAdminUserRole(ctx, adminID, newRoleID, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update admin user role")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin user role updated successfully"))

	h.logger.Info("Admin user role updated",
		util.String("admin_id", adminID.String()),
		util.String("new_role_id", newRoleID.String()),
		util.String("updated_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}
