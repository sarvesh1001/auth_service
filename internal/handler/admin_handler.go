// handler/admin_handler.go
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

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
		r.Post("/login/verify-otp", h.VerifyAdminOTPLogin)
		r.Post("/login/verify-mpin", h.VerifyAdminMPINLogin)
		r.Post("/mpin/setup", h.SetupAdminMPIN)
		r.Post("/refresh", h.RefreshAdminTokens)
		r.Post("/logout", h.LogoutAdmin)
		r.Get("/health", h.HealthCheck)
	})
}

// ===== HELPER RESPONSE
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
		util.Bool("has_mpin", response.HasMPIN), // This should now be accurate
		util.Bool("mpin_locked", response.MPINLocked),
		util.Bool("device_trusted", deviceTrusted),
		util.String("flow_state", response.FlowState),
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
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.OTP = util.SanitizeInput(req.OTP)
	req.DeviceID = util.SanitizeInput(req.DeviceID)
	req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

	otpVerifyReq := service.OTPVerifyRequest{
		PhoneNumber: req.PhoneNumber,
		OTP:         req.OTP,
		Purpose:     "admin_login",
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

	admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
		return
	}

	deviceReq := service.AdminBindDeviceRequest{
		AdminID:   admin.AdminID,
		DeviceID:  req.DeviceID,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
		h.logger.Warn("Failed to update device trust for admin", util.ErrorField(err))
	}

	if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
		if err := h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID); err != nil {
			h.logger.Warn("Failed to unlock MPIN after OTP verification", util.ErrorField(err))
		}
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"admin_id":       admin.AdminID.String(),
		"device_trusted": true,
		"has_mpin":       h.hasMPIN(ctx, admin.AdminID),
		"mpin_locked":    false,
		"message":        "OTP verification successful. Device is now trusted.",
	}, "Admin device setup successful"))

	h.logger.Info("Admin OTP verification completed - device trusted (no tokens issued)",
		util.String("admin_id", admin.AdminID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
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

	deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, adminID, req.DeviceID)
	if err != nil || !deviceTrusted {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
			"MPIN login not allowed on this device")
		return
	}

	mpinVerifyReq := service.AdminMPINVerifyRequest{
		AdminID:  adminID,
		MPIN:     req.MPIN,
		DeviceID: req.DeviceID,
	}

	mpinResult, err := h.mpinService.VerifyAdminMPIN(ctx, &mpinVerifyReq)
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

	tokenReq := &service.IssueTokenPairRequest{
		UserID:           admin.AdminID.String(),
		Role:             "admin",
		DeviceID:         req.DeviceID,
		SessionType:      "admin",
		IPAddress:        h.getClientIP(r),
		AdminRoleLevel:   admin.AdminRoleLevel,
		AdminPermissions: admin.AdminPermissions,
	}

	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue JWT tokens")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"tokens":  tokens,
		"admin":   admin,
		"message": "Admin MPIN login successful",
	}, "Admin login successful"))

	h.logger.Info("Admin MPIN login completed with JWT tokens",
		util.String("admin_id", adminID.String()),
		util.String("role_level", admin.AdminRoleLevel),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) SetupAdminMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		AdminID  string `json:"admin_id" validate:"required"`
		MPIN     string `json:"mpin" validate:"required,min=4,max=6"`
		DeviceID string `json:"device_id" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.MPIN = util.SanitizeInput(req.MPIN)
	req.DeviceID = util.SanitizeInput(req.DeviceID)

	adminID, err := uuid.Parse(req.AdminID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
		return
	}

	mpinReq := service.AdminMPINSetupRequest{
		AdminID:  adminID,
		MPIN:     req.MPIN,
		DeviceID: req.DeviceID,
	}

	if err := h.mpinService.SetupAdminMPIN(ctx, &mpinReq); err != nil {
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
	SubscriptionTier   string   `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
	MaxEmployees       int      `json:"max_employees" validate:"required,min=1,max=2000"`
	DataRegion         string   `json:"data_region" validate:"required"`
	SubscriptionMonths int      `json:"subscription_months" validate:"required,min=1,max=36"`
	SubscriptionDays   int      `json:"subscription_days" validate:"min=0,max=30"`
	Departments        []string `json:"departments"` // Departments to create for this company
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

	// Create company using enhanced service (now includes department setup)
	companyReq := service.CreateCompanyRequest{
		CompanyName:        req.CompanyName,
		OwnerPhone:         req.OwnerPhone,
		SubscriptionTier:   req.SubscriptionTier,
		MaxEmployees:       req.MaxEmployees,
		DataRegion:         req.DataRegion,
		SubscriptionMonths: req.SubscriptionMonths,
		SubscriptionDays:   req.SubscriptionDays,
		Departments:        req.Departments, // Pass departments to service
	}

	company, err := h.companyService.CreateCompany(ctx, &companyReq, adminID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, err, "Company with this name already exists for the owner")
			return
		}
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create company")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(company, "Company created successfully with RBAC setup"))

	h.logger.Info("Company created by admin with full RBAC setup",
		util.String("company_id", company.CompanyID.String()),
		util.String("company_name", company.CompanyName),
		util.String("owner_phone", req.OwnerPhone),
		util.String("subscription_tier", req.SubscriptionTier),
		util.Int("department_count", len(req.Departments)),
		util.String("created_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== DEPARTMENT MANAGEMENT =====

// CreateDepartmentRequest defines the request for creating a department
type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	DepartmentHead     *uuid.UUID `json:"department_head,omitempty"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
}

func (h *AdminHandler) CreateDepartment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	var req CreateDepartmentRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Convert to service request
	deptReq := service.CreateDepartmentRequest{
		CompanyID:          req.CompanyID,
		DepartmentName:     req.DepartmentName,
		SystemDepartmentID: req.SystemDepartmentID,
		DepartmentHead:     req.DepartmentHead,
		ParentDepartmentID: req.ParentDepartmentID,
	}

	department, err := h.companyService.CreateDepartment(ctx, &deptReq)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create department")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department created successfully"))

	h.logger.Info("Department created by admin",
		util.String("company_id", req.CompanyID.String()),
		util.String("department_id", department.DepartmentID.String()),
		util.String("department_name", req.DepartmentName),
		util.String("created_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// // GetCompanyDepartments retrieves all departments for a company
// func (h *AdminHandler) GetCompanyDepartments(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	limit := h.getIntQueryParam(r, "limit", 50)
// 	offset := h.getIntQueryParam(r, "offset", 0)

// 	departments, total, err := h.companyService.GetDepartmentsByCompany(ctx, companyID, limit, offset)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get company departments")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"departments": departments,
// 		"meta": map[string]interface{}{
// 			"company_id": companyID.String(),
// 			"count":      len(departments),
// 			"total":      total,
// 			"limit":      limit,
// 			"offset":     offset,
// 		},
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Company departments retrieved successfully"))

// 	h.logger.Debug("Company departments retrieved",
// 		util.String("company_id", companyID.String()),
// 		util.Int("count", len(departments)),
// 		util.Duration("duration", time.Since(startTime)),
// 	)
// }

// ===== ROLE MANAGEMENT =====

// CreateRoleRequest defines the request for creating a role
type CreateRoleRequest struct {
	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
	RoleName      string      `json:"role_name" validate:"required"`
	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
	Description   string      `json:"description,omitempty"`
	DepartmentIDs []uuid.UUID `json:"department_ids"` // Roles can be assigned to multiple departments
	PermissionIDs []uuid.UUID `json:"permission_ids"` // Direct permission assignments
}

func (h *AdminHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	var req CreateRoleRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Convert to service request
	roleReq := service.CreateRoleRequest{
		CompanyID:     req.CompanyID,
		RoleName:      req.RoleName,
		RoleLevel:     req.RoleLevel,
		Description:   req.Description,
		DepartmentIDs: req.DepartmentIDs,
		PermissionIDs: req.PermissionIDs,
		CreatedBy:     adminID,
	}

	role, err := h.companyService.CreateRole(ctx, &roleReq)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create role")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(role, "Role created successfully"))

	h.logger.Info("Role created by admin",
		util.String("company_id", req.CompanyID.String()),
		util.String("role_id", role.RoleID.String()),
		util.String("role_name", req.RoleName),
		util.Int("role_level", req.RoleLevel),
		util.Int("department_count", len(req.DepartmentIDs)),
		util.Int("permission_count", len(req.PermissionIDs)),
		util.String("created_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanyRoles retrieves all roles for a company
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

// GrantRolePermissions grants permissions to a role
func (h *AdminHandler) GrantRolePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	adminID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
		return
	}

	roleIDStr := chi.URLParam(r, "roleID")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid role ID")
		return
	}

	var req struct {
		PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	grantReq := service.GrantRolePermissionsRequest{
		RoleID:        roleID,
		PermissionIDs: req.PermissionIDs,
	}

	if err := h.companyService.GrantRolePermissions(ctx, &grantReq); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to grant role permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permissions granted to role successfully"))

	h.logger.Info("Permissions granted to role",
		util.String("role_id", roleID.String()),
		util.Int("permission_count", len(req.PermissionIDs)),
		util.String("granted_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// UpdateEmployeeRole updates employee role and department
func (h *AdminHandler) UpdateEmployeeRole(w http.ResponseWriter, r *http.Request) {
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

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	var req struct {
		RoleID       uuid.UUID `json:"role_id" validate:"required"`
		DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Update role
	if err := h.companyService.UpdateEmployeeRole(ctx, companyID, userID, req.RoleID, adminID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update employee role")
		return
	}

	// Update department
	if err := h.companyService.UpdateEmployeeDepartment(ctx, companyID, userID, req.DepartmentID, adminID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update employee department")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee role and department updated successfully"))

	h.logger.Info("Employee role and department updated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("role_id", req.RoleID.String()),
		util.String("department_id", req.DepartmentID.String()),
		util.String("updated_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetEmployeePermissions retrieves permissions for an employee
func (h *AdminHandler) GetEmployeePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	permissions, err := h.companyService.GetUserPermissions(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get employee permissions")
		return
	}

	response := map[string]interface{}{
		"permissions": permissions,
		"meta": map[string]interface{}{
			"user_id": userID.String(),
			"count":   len(permissions),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employee permissions retrieved successfully"))

	h.logger.Debug("Employee permissions retrieved",
		util.String("user_id", userID.String()),
		util.Int("permission_count", len(permissions)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// CheckEmployeePermission checks if an employee has a specific permission
func (h *AdminHandler) CheckEmployeePermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.PermissionCheckRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	result, err := h.companyService.CheckPermission(ctx, &req)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to check permission")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(result, "Permission check completed"))

	h.logger.Debug("Employee permission check completed",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", req.UserID.String()),
		util.String("permission", req.PermissionName),
		util.Bool("has_permission", result.HasPermission),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

// GetUserHierarchy retrieves the hierarchy context for a user across companies
func (h *AdminHandler) GetUserHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	hierarchy, err := h.companyService.GetUserHierarchy(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user hierarchy")
		return
	}

	response := map[string]interface{}{
		"hierarchy": hierarchy,
		"meta": map[string]interface{}{
			"user_id": userID.String(),
			"count":   len(hierarchy),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "User hierarchy retrieved successfully"))

	h.logger.Debug("User hierarchy retrieved",
		util.String("user_id", userID.String()),
		util.Int("company_count", len(hierarchy)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== BULK OPERATIONS =====

// BulkAssignRoles bulk assigns roles to multiple users
func (h *AdminHandler) BulkAssignRoles(w http.ResponseWriter, r *http.Request) {
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
		Assignments []service.BulkAssignment `json:"assignments" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	results, err := h.companyService.BulkAssignRoles(ctx, companyID, req.Assignments, adminID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to bulk assign roles")
		return
	}

	response := map[string]interface{}{
		"results": results,
		"meta": map[string]interface{}{
			"company_id":       companyID.String(),
			"assignment_count": len(req.Assignments),
			"processed_count":  len(results),
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Bulk role assignment completed"))

	h.logger.Info("Bulk role assignment completed",
		util.String("company_id", companyID.String()),
		util.Int("assignment_count", len(req.Assignments)),
		util.String("assigned_by", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	limit := h.getIntQueryParam(r, "limit", 100)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Use search with is_active filter
	filters := map[string]interface{}{
		"is_active": false,
	}

	users, total, err := h.userService.SearchUsers(ctx, filters, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
		return
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"count":  len(users),
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Banned users retrieved successfully"))

	h.logger.Debug("Banned users retrieved by admin",
		util.Int("count", len(users)),
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

// SearchUsers searches users with various filters
func (h *AdminHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	limit := h.getIntQueryParam(r, "limit", 50)
	offset := h.getIntQueryParam(r, "offset", 0)

	// Parse query parameters for filters
	filters := make(map[string]interface{})

	if phoneHash := r.URL.Query().Get("phone_hash"); phoneHash != "" {
		filters["phone_hash"] = phoneHash
	}
	if deviceID := r.URL.Query().Get("device_id"); deviceID != "" {
		filters["device_id"] = deviceID
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

	users, total, err := h.userService.SearchUsers(ctx, filters, limit, offset)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search users")
		return
	}

	// Sanitize users
	for _, u := range users {
		h.sanitizeUserForAdmin(u)
	}

	response := map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"count":   len(users),
			"total":   total,
			"limit":   limit,
			"offset":  offset,
			"filters": filters,
		},
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Users search completed successfully"))

	h.logger.Debug("Users search completed",
		util.Any("filters", filters),
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

func (h *AdminHandler) ChangeOwnerPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req struct {
		NewPhone string `json:"new_phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.NewPhone = strings.TrimSpace(req.NewPhone)
	if req.NewPhone == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("new_phone required"), "New phone is required")
		return
	}

	if err := h.adminService.ChangeOwnerPhone(ctx, requesterID, req.NewPhone); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to change owner phone")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Owner phone updated successfully"))
	h.logger.Info("Owner phone changed via HTTP",
		util.String("admin_id", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) InviteAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	requesterRole, err := h.getRequesterRole(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	var req struct {
		Phone     string `json:"phone"`
		RoleLevel string `json:"role_level"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.Phone = strings.TrimSpace(req.Phone)
	req.RoleLevel = strings.TrimSpace(strings.ToLower(req.RoleLevel))

	if req.Phone == "" || req.RoleLevel == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("missing fields"), "Phone and role level are required")
		return
	}

	if !h.isValidRoleLevel(req.RoleLevel) {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
		return
	}

	admin, err := h.adminService.InviteAdmin(ctx, req.Phone, req.RoleLevel, requesterID, requesterRole)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to invite user as admin")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "User invited as admin successfully"))
	h.logger.Info("User invited as admin via HTTP",
		util.String("admin_id", admin.AdminID.String()),
		util.String("role_level", req.RoleLevel),
		util.String("invited_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request) {
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
		NewRole string `json:"new_role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.NewRole = strings.TrimSpace(strings.ToLower(req.NewRole))
	if !h.isValidRoleLevel(req.NewRole) {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
		return
	}

	if err := h.adminService.PromoteAdmin(ctx, adminID, req.NewRole, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to promote admin")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin role updated successfully"))
	h.logger.Info("Admin promoted via HTTP",
		util.String("admin_id", adminID.String()),
		util.String("new_role", req.NewRole),
		util.String("promoted_by", requesterID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

	if err := h.adminService.UpdateAdminPermissions(ctx, adminID, req.Permissions, requesterID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update permissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin permissions updated successfully"))
	h.logger.Info("Admin permissions updated via HTTP",
		util.String("admin_id", adminID.String()),
		util.Strings("permissions", req.Permissions),
		util.Duration("duration", time.Since(startTime)),
	)
}

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

func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = h.getRequesterAdminID(r)

	roleLevel := strings.ToLower(chi.URLParam(r, "roleLevel"))
	if !h.isValidRoleLevel(roleLevel) {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
		return
	}

	admins, err := h.adminService.GetAdminsByRole(ctx, roleLevel)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get admins by role")
		return
	}

	if admins == nil {
		admins = []*models.AdminUser{}
	}

	response := successResponse(map[string]interface{}{
		"admins": admins,
		"role":   roleLevel,
		"count":  len(admins),
	}, "Admins retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Admins retrieved by role via HTTP",
		util.String("role", roleLevel),
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
//
//	func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
//		status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
//		return err == nil && status != nil && status.Exists // ✅ Check the Exists field
//	}
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

func (h *AdminHandler) isValidRoleLevel(role string) bool {
	switch role {
	case models.AdminRoleLevelOwner:
		return true
	case models.AdminRoleLevelSuperEmployee:
		return true
	case models.AdminRoleLevelEmployee:
		return true
	default:
		return false
	}
}

func (h *AdminHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		return uuid.Nil, fmt.Errorf("user ID not found in request context")
	}

	adminID, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid admin ID in request context")
	}

	return adminID, nil
}

func (h *AdminHandler) getRequesterRole(r *http.Request) (string, error) {
	role, ok := r.Context().Value("admin_role_level").(string)
	if !ok || role == "" {
		return "", fmt.Errorf("admin role not found in request context")
	}
	return role, nil
}

// client IP extraction robust helper
func (h *AdminHandler) getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// Validate IP format
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

	// Fallback to RemoteAddr with proper parsing
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try to parse as IP directly
		if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
			return r.RemoteAddr
		}
		// Return a safe default if all parsing fails
		return "127.0.0.1"
	}

	// Final validation
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return host
	}

	// Safe fallback
	return "127.0.0.1"
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
