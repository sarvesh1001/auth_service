// internal/handler/auth_handler.go
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
	companyService *service.CompanyService
	deviceService  *service.DeviceService
	jwtService     *service.JWTService
	logger         *zap.Logger
}

func NewAuthHandler(
	otpService *service.OTPService,
	mpinService *service.MPINService,
	sessionService *service.SessionService,
	userService *service.UserService,
	companyService *service.CompanyService,
	deviceService *service.DeviceService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		otpService:     otpService,
		mpinService:    mpinService,
		sessionService: sessionService,
		userService:    userService,
		companyService: companyService,
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
		r.Post("/mpin/setup", h.SetupMPIN)

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
		// r.Post("/{companyID}/employees", h.AddEmployee)
		r.Delete("/{companyID}/employees/{userID}", h.RemoveEmployee)
		r.Get("/context", h.GetCompanyContext)
		r.Post("/{companyID}/employees/{userID}/role", h.UpdateEmployeeRole)
		r.Post("/{companyID}/employees/{userID}/department", h.UpdateEmployeeDepartment)
		r.Get("/{companyID}/hierarchy", h.GetCompanyHierarchy)

		// 🔥 PHASE 2 - OWNER OPERATIONS
		r.Route("/{companyID}/departments", func(r chi.Router) {
			r.Put("/{departmentID}", h.RenameDepartment)
			r.Post("/", h.AddDepartment)
		})

		// Manager operations
		r.Route("/{companyID}/managers", func(r chi.Router) {
			r.Post("/", h.AddManager)
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
// PHASE 2 - OWNER OPERATIONS
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

// AddManager adds a new manager (Owner only)
func (h *AuthHandler) AddManager(w http.ResponseWriter, r *http.Request) {
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

	var req service.AddManagerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.CompanyID = companyID

	// Sanitize inputs
	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
	req.RoleName = util.SanitizeInput(req.RoleName)

	// Check permissions using bitmask
	hasCreatePermission, err := h.companyService.CheckPermissionFromContext(ctx, "hr.employee.create")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}
	hasAdminAccess, err := h.companyService.CheckPermissionFromContext(ctx, "admin.department.create")
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Permission check failed")
		return
	}

	if !hasCreatePermission || !hasAdminAccess {
		h.respondWithError(w, http.StatusForbidden,
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to add managers"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.AddManager(ctx, &req); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to add manager")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))

	h.logger.Info("Manager added",
		util.String("company_id", companyID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("role_name", req.RoleName),
		util.String("department_id", req.DepartmentID.String()),
		util.Int("permissions_count", len(req.Permissions)),
		util.String("added_by", userIDParsed.String()),
		util.Duration("duration", time.Since(startTime)))
}

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

// ============================================
// UPDATED EMPLOYEE MANAGEMENT FOR PHASE 2 & 3
// ============================================

// // AddEmployee handles employee addition by both Owner and Manager
// func (h *AuthHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get user ID from JWT context (the user adding the employee)
// 	addedBy := r.Context().Value("user_id")
// 	if addedBy == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	addedByID, err := uuid.Parse(addedBy.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req service.AddEmployeeRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	req.CompanyID = companyID

// 	// Sanitize inputs
// 	req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
// 	req.EmployeeID = util.SanitizeInput(req.EmployeeID)

// 	// Check if the user adding the employee is a manager
// 	employee, err := h.companyService.GetEmployee(ctx, companyID, addedByID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusForbidden, err, "User is not an employee of the company")
// 		return
// 	}

// 	role, err := h.companyService.GetRole(ctx, employee.RoleID)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get user role")
// 		return
// 	}

// 	var addErr error

// 	// If user is manager (role level <= 200), use ManagerAddEmployee
// 	if role.RoleLevel <= 200 && role.RoleLevel > 0 {
// 		addErr = h.companyService.ManagerAddEmployee(ctx, &req, addedByID)
// 	} else {
// 		// Owner or higher role - use regular AddEmployee
// 		addErr = h.companyService.AddEmployee(ctx, &req)
// 	}

// 	if addErr != nil {
// 		statusCode := h.getStatusCode(addErr)
// 		h.respondWithError(w, statusCode, addErr, "Failed to add employee")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))

// 	h.logger.Info("Employee added to company",
// 		util.String("company_id", companyID.String()),
// 		util.String("added_by", addedByID.String()),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("employee_id", req.EmployeeID),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

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

// VerifyOTPLogin handles OTP verification for device setup/recovery
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

	// Get user - must exist
	user, err := h.userService.GetUserByPhone(ctx, req.PhoneNumber)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "User not found")
		return
	}

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

	responseData := map[string]interface{}{
		"user_id":        user.UserID.String(),
		"device_trusted": true,
		"has_mpin":       hasMPIN,
		"mpin_locked":    false,
		"message":        "OTP verification successful. Device is now trusted.",
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

	h.logger.Info("OTP verification completed - device trusted (no tokens issued)",
		util.String("user_id", user.UserID.String()),
		util.String("phone", req.PhoneNumber),
		util.String("device_id", req.DeviceID),
		util.Bool("has_mpin", hasMPIN),
		util.Duration("duration", time.Since(startTime)),
	)
}

// VerifyMPINLogin handles MPIN verification for daily login
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

	// Get user - must exist
	user, err := h.userService.GetUserByID(ctx, userID)
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

	// Check company subscription status if user has company
	companyContext, err := h.companyService.GetCompanyContext(ctx, userID)
	if err != nil && !strings.Contains(err.Error(), "user is not an active employee") {
		if strings.Contains(err.Error(), "subscription status:") {
			h.respondWithError(w, http.StatusPaymentRequired, err, "Subscription issue")
			return
		}
		h.logger.Warn("Company context check failed", util.ErrorField(err))
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

	userRole := "user"
	if companyContext != nil {
		// Use the role from company context - no need for type assertion
		userRole = companyContext.RoleName
	}
	// Issue JWT token pair
	tokenReq := &service.IssueTokenPairRequest{
		UserID:      userID.String(),
		Role:        userRole,
		DeviceID:    req.DeviceID,
		SessionType: "user",
		IPAddress:   h.getClientIP(r),
	}

	tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue tokens")
		return
	}

	responseData := map[string]interface{}{
		"tokens":  tokens,
		"user_id": userID.String(),
		"message": "MPIN login successful",
	}

	if companyContext != nil {
		responseData["company_context"] = companyContext
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(responseData, "Login successful"))

	h.logger.Info("MPIN login completed with JWT tokens",
		util.String("user_id", userID.String()),
		util.String("role", userRole),
		util.Bool("has_company", companyContext != nil),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SetupMPINRequest for MPIN setup
type SetupMPINRequest struct {
	UserID   string `json:"user_id" validate:"required"`
	MPIN     string `json:"mpin" validate:"required,min=4,max=6"`
	DeviceID string `json:"device_id" validate:"required"`
}

// SetupMPIN handles MPIN setup after registration
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

	// Verify user exists
	_, err = h.userService.GetUserByID(ctx, userID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err, "User not found")
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

	h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
		"message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
	}, "MPIN setup successful"))

	h.logger.Info("MPIN setup completed",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
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

// UpdateEmployeeDepartment updates an employee's department
func (h *AuthHandler) UpdateEmployeeDepartment(w http.ResponseWriter, r *http.Request) {
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
		DepartmentID uuid.UUID `json:"department_id" validate:"required"`
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
			fmt.Errorf("PERMISSION_DENIED: User lacks permission to update employee departments"),
			"Insufficient permissions")
		return
	}

	if err := h.companyService.UpdateEmployeeDepartment(ctx, companyID, userID, req.DepartmentID, updatedByID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update employee department")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Employee department updated successfully"))

	h.logger.Info("Employee department updated",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("new_department_id", req.DepartmentID.String()),
		util.String("updated_by", updatedByID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetCompanyContext returns the company context for the authenticated user
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

	companyContext, err := h.companyService.GetCompanyContext(ctx, userIDParsed)
	if err != nil {
		if strings.Contains(err.Error(), "subscription status:") {
			h.respondWithError(w, http.StatusPaymentRequired, err, "Subscription issue")
			return
		}
		if strings.Contains(err.Error(), "user is not an active employee") {
			h.respondWithError(w, http.StatusForbidden, err, "Not an active employee")
			return
		}
		h.respondWithError(w, http.StatusNotFound, err, "Company context not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(companyContext, "Company context retrieved"))

	h.logger.Debug("Company context retrieved",
		util.String("user_id", userIDParsed.String()),
		util.String("company_id", companyContext.CompanyID),
		util.Duration("duration", time.Since(startTime)),
	)
}

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
// MPIN FORGOT FLOW METHODS
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

func (h *AuthHandler) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
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
	return http.StatusInternalServerError
}

func (h *AuthHandler) sanitizeUser(user *models.User) {
	user.PhoneEncrypted = nil
	user.PhoneKeyID = uuid.Nil
	user.PhoneEncryptedDEK = ""
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

	// Check permission using bitmask - MAKE SURE THIS PERMISSION MATCHES
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

	// 🔥 CRITICAL: Make sure this calls RenameDepartment, NOT UpdateDepartment
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
