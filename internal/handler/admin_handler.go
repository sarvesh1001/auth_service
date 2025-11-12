// handler/admin_handler.go
package handler

import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "strconv"
    "strings"
    "time"
    // "encoding/base64"

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
    otpService     *service.OTPService
    mpinService    *service.AdminMPINService
    deviceService  *service.AdminDeviceService
    sessionService *service.SessionService
    userService    *service.UserService
    jwtService     *service.JWTService
    logger         *zap.Logger
}

func NewAdminHandler(
    adminService *service.AdminService,
    companyService *service.CompanyService,
    otpService *service.OTPService,
    mpinService *service.AdminMPINService,
    deviceService *service.AdminDeviceService,
    sessionService *service.SessionService,
    userService *service.UserService,
    jwtService *service.JWTService,
    logger *zap.Logger,
) *AdminHandler {
    return &AdminHandler{
        adminService:   adminService,
        companyService: companyService,
        otpService:     otpService,
        mpinService:    mpinService,
        deviceService:  deviceService,
        sessionService: sessionService,
        userService:    userService,
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

    // Admin Management Routes (protected - rely on router-level middleware)
    router.Route("/admins", func(r chi.Router) {
        r.Get("/", h.ListAdmins)
        r.Get("/stats", h.GetStats)
        r.Post("/invite", h.InviteAdmin)
        r.Get("/{adminID}", h.GetAdminByID)
        r.Get("/phone/{phone}", h.GetAdminByPhone)
        r.Get("/role/{roleLevel}", h.GetAdminsByRole)
        r.Get("/status/{status}", h.GetAdminsByStatus) // NEW: Simple status filter
        r.Patch("/{adminID}/role", h.PromoteAdmin)
        r.Patch("/{adminID}/permissions", h.UpdateAdminPermissions)
        r.Patch("/{adminID}/deactivate", h.DeactivateAdmin)
        r.Patch("/{adminID}/activate", h.ActivateAdmin)
        r.Delete("/{adminID}", h.RemoveAdmin)
        r.Patch("/owner/phone", h.ChangeOwnerPhone)
    })

    // Company Management Routes (protected - rely on router-level middleware)
    router.Route("/admins/companies", func(r chi.Router) {
        r.Post("/", h.CreateCompany)
        // ❌ REMOVED: r.Get("/", h.ListCompanies) // Multi-filter endpoint removed
        // r.Get("/tier/{tier}", h.GetCompaniesByTier)
        // r.Get("/tier/{tier}/status/{status}", h.GetCompaniesByTierAndStatus)
        // r.Get("/subscription-date-range", h.GetCompaniesBySubscriptionDateRange)

        r.Get("/{companyID}", h.GetCompany)
        r.Patch("/{companyID}/block", h.BlockCompany)
        r.Patch("/{companyID}/unblock", h.UnblockCompany)
        r.Patch("/{companyID}/subscription", h.UpdateSubscription)
        r.Patch("/{companyID}/extend", h.ExtendSubscription)
        r.Get("/{companyID}/employees", h.GetCompanyEmployees)
    })

    // User Management Routes (protected - rely on router-level middleware)
    router.Route("/admins/users", func(r chi.Router) {
        r.Patch("/{userID}/kyc", h.UpdateUserKYC)
        r.Post("/{userID}/ban", h.BanUser)
        r.Post("/{userID}/unban", h.UnbanUser)
        r.Get("/banned", h.GetBannedUsers)
        r.Get("/kyc/{status}", h.ListUsersByKYCStatus)
    })
}

// ===== ADMIN AUTHENTICATION FLOW =====

// LoginFlowResponse defines the response for admin login flow
type LoginFlowResponse struct {
    UserExists     bool   `json:"user_exists"`
    HasMPIN        bool   `json:"has_mpin"`
    MPINLocked     bool   `json:"mpin_locked"`
    DeviceTrusted  bool   `json:"device_trusted"`
    FlowState      string `json:"flow_state"`
    Message        string `json:"message"`
    UserID         string `json:"user_id,omitempty"`
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

    // Use AdminMPINService method
    mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID)
    if err != nil {
        response.FlowState = "existing_user_otp"
        response.Message = "Existing admin - OTP verification required (no MPIN setup)"
        h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
        return
    }

    response.HasMPIN = true
    response.MPINLocked = mpinStatus.IsLocked

    // Use AdminDeviceService method
    deviceTrusted, _ := h.deviceService.IsDeviceTrusted(ctx, admin.AdminID, req.DeviceID)

    if response.MPINLocked {
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
        zap.String("phone", req.PhoneNumber),
        zap.Bool("admin_exists", adminExists),
        zap.Bool("has_mpin", response.HasMPIN),
        zap.Bool("mpin_locked", response.MPINLocked),
        zap.Bool("device_trusted", deviceTrusted),
        zap.String("flow_state", response.FlowState),
        zap.Duration("duration", time.Since(startTime)),
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
        h.logger.Warn("Failed to update device trust for admin", zap.Error(err))
    }

    if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
        if err := h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID); err != nil {
            h.logger.Warn("Failed to unlock MPIN after OTP verification", zap.Error(err))
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
        zap.String("admin_id", admin.AdminID.String()),
        zap.String("phone", req.PhoneNumber),
        zap.String("device_id", req.DeviceID),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.String("role_level", admin.AdminRoleLevel),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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

// ===== COMPANY MANAGEMENT =====

// CreateCompany creates a new company and auto-creates owner user if needed
func (h *AdminHandler) CreateCompany(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    adminID, err := h.getRequesterAdminID(r)
    if err != nil {
        h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
        return
    }

    var req struct {
        CompanyName      string  `json:"company_name" validate:"required"`
        OwnerPhone       string  `json:"owner_phone" validate:"required"`
        SubscriptionTier string  `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
        MonthlyPremium   float64 `json:"monthly_premium" validate:"required,min=0"`
        MaxEmployees     int     `json:"max_employees" validate:"required,min=1,max=2000"`
        DataRegion       string  `json:"data_region" validate:"required"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Validate required fields
    if req.CompanyName == "" || req.OwnerPhone == "" || req.SubscriptionTier == "" {
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("missing required fields"), 
            "Company name, owner phone, and subscription tier are required")
        return
    }

    // Create company using service
    companyReq := service.CreateCompanyRequest{
        CompanyName:      req.CompanyName,
        OwnerPhone:       req.OwnerPhone,
        SubscriptionTier: req.SubscriptionTier,
        MonthlyPremium:   req.MonthlyPremium,
        MaxEmployees:     req.MaxEmployees,
        DataRegion:       req.DataRegion,
        CreatedByAdmin:   adminID,
    }

    company, err := h.companyService.CreateCompany(ctx, &companyReq)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to create company")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(company, "Company created successfully"))

    h.logger.Info("Company created by admin with auto-created owner",
        zap.String("company_id", company.CompanyID.String()),
        zap.String("company_name", company.CompanyName),
        zap.String("owner_phone", company.OwnerPhone),
        zap.String("created_by", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ❌ REMOVED: ListCompanies method with multiple filters

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
        zap.String("company_id", companyID.String()),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// BlockCompany blocks a company
func (h *AdminHandler) BlockCompany(w http.ResponseWriter, r *http.Request) {
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
            fmt.Errorf("reason required"), "Block reason is required")
        return
    }

    if err := h.companyService.BlockCompany(ctx, companyID, req.Reason, adminID); err != nil {
        h.respondWithError(w, h.getStatusCode(err), err, "Failed to block company")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company blocked successfully"))

    h.logger.Info("Company blocked by admin",
        zap.String("company_id", companyID.String()),
        zap.String("blocked_by", adminID.String()),
        zap.String("reason", req.Reason),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// UnblockCompany unblocks a company
func (h *AdminHandler) UnblockCompany(w http.ResponseWriter, r *http.Request) {
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

    if err := h.companyService.UnblockCompany(ctx, companyID, adminID); err != nil {
        h.respondWithError(w, h.getStatusCode(err), err, "Failed to unblock company")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company unblocked successfully"))

    h.logger.Info("Company unblocked by admin",
        zap.String("company_id", companyID.String()),
        zap.String("unblocked_by", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        Tier         string  `json:"tier" validate:"required,oneof=basic premium enterprise"`
        Premium      float64 `json:"premium" validate:"required,min=0"`
        MaxEmployees int     `json:"max_employees" validate:"required,min=1,max=2000"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if err := h.companyService.UpdateSubscription(ctx, companyID, req.Tier, req.Premium, req.MaxEmployees, adminID); err != nil {
        h.respondWithError(w, h.getStatusCode(err), err, "Failed to update subscription")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription updated successfully"))

    h.logger.Info("Company subscription updated",
        zap.String("company_id", companyID.String()),
        zap.String("tier", req.Tier),
        zap.Float64("premium", req.Premium),
        zap.Int("max_employees", req.MaxEmployees),
        zap.String("updated_by", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        Months int `json:"months" validate:"required,min=1,max=36"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if err := h.companyService.ExtendSubscription(ctx, companyID, req.Months, adminID); err != nil {
        h.respondWithError(w, h.getStatusCode(err), err, "Failed to extend subscription")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))

    h.logger.Info("Company subscription extended",
        zap.String("company_id", companyID.String()),
        zap.Int("months", req.Months),
        zap.String("updated_by", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
    )
}
// GetCompaniesByStatus retrieves companies by status (active, inactive, blocked)
func (h *AdminHandler) GetCompaniesByStatus(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    status := chi.URLParam(r, "status")
    if status == "" {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("status required"), "Status is required")
        return
    }

    limit := h.getIntQueryParam(r, "limit", 50)

    var companies []*models.Company
    var err error

    switch status {
    case "active":
        companies, err = h.companyService.GetCompaniesByActiveStatus(ctx, true, limit)
    case "inactive":
        companies, err = h.companyService.GetCompaniesByActiveStatus(ctx, false, limit)
    case "blocked":
        companies, err = h.companyService.GetCompaniesByBlockedStatus(ctx, true, limit)
    default:
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid status"), "Status must be active, inactive, or blocked")
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
            "limit":  limit,
        },
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by status"))

    h.logger.Debug("Companies retrieved by status",
        zap.String("status", status),
        zap.Int("count", len(companies)),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// GetRecentCompanies retrieves recently created companies
func (h *AdminHandler) GetRecentCompanies(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    limit := h.getIntQueryParam(r, "limit", 50)

    companies, err := h.companyService.GetRecentCompanies(ctx, limit)
    if err != nil {
        h.respondWithError(w, h.getStatusCode(err), err, "Failed to get recent companies")
        return
    }

    response := map[string]interface{}{
        "companies": companies,
        "meta": map[string]interface{}{
            "count": len(companies),
            "limit": limit,
        },
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Recent companies retrieved"))

    h.logger.Debug("Recent companies retrieved",
        zap.Int("count", len(companies)),
        zap.Duration("duration", time.Since(startTime)),
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
    page := h.getIntQueryParam(r, "page", 1)
    limit := h.getIntQueryParam(r, "limit", 50)

    employees, total, err := h.companyService.ListEmployees(ctx, companyID, page, limit)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list employees")
        return
    }

    response := map[string]interface{}{
        "employees": employees,
        "meta": map[string]interface{}{
            "page":  page,
            "limit": limit,
            "total": total,
        },
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employees retrieved successfully"))

    h.logger.Debug("Company employees listed by admin",
        zap.String("company_id", companyID.String()),
        zap.Int("count", len(employees)),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ===== USER MANAGEMENT =====

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
        zap.String("user_id", userID.String()),
        zap.String("banned_by", requesterID.String()),
        zap.String("reason", req.Reason),
        zap.Duration("duration", time.Since(startTime)),
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

    if err := h.userService.UnbanUser(ctx, userID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to unban user")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))

    h.logger.Info("User unbanned by admin",
        zap.String("user_id", userID.String()),
        zap.String("unbanned_by", requesterID.String()),
        zap.Duration("duration", time.Since(startTime)),
    )
}

func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    limitStr := r.URL.Query().Get("limit")
    pageToken := r.URL.Query().Get("page_token")

    limit := 100
    if limitStr != "" {
        parsedLimit, err := strconv.Atoi(limitStr)
        if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
            h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid limit"), "Limit must be between 1 and 1000")
            return
        }
        limit = parsedLimit
    }

    users, nextPageToken, err := h.userService.GetBannedUsers(ctx, limit, pageToken)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
        return
    }

    response := successResponse(users, "Banned users retrieved successfully")
    if nextPageToken != "" {
        response.Meta = &Meta{
            PageToken: nextPageToken,
            PageSize:  limit,
            Total:     len(users),
        }
    }

    h.respondWithJSON(w, http.StatusOK, response)

    h.logger.Debug("Banned users retrieved by admin",
        zap.Int("count", len(users)),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// UpdateUserKYC - Admin approves/rejects user KYC (replaces company KYC)
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
        Status string `json:"status" validate:"required,oneof=approved rejected pending"`
        Level  string `json:"level,omitempty"`
        Reason string `json:"reason,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    kycReq := service.KYCUpdateRequest{
        UserID: userID,
        Status: strings.ToLower(req.Status),
        Level:  req.Level,
        Reason: req.Reason,
    }

    if err := h.userService.UpdateKYCStatus(ctx, &kycReq); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to update user KYC")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User KYC status updated successfully"))

    h.logger.Info("User KYC status updated by admin",
        zap.String("user_id", userID.String()),
        zap.String("status", req.Status),
        zap.String("level", req.Level),
        zap.String("updated_by", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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

    limitStr := r.URL.Query().Get("limit")
    pageToken := r.URL.Query().Get("page_token")

    limit := 100
    if limitStr != "" {
        parsedLimit, err := strconv.Atoi(limitStr)
        if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
            h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid limit"), "Limit must be between 1 and 1000")
            return
        }
        limit = parsedLimit
    }

    users, nextPageToken, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, pageToken)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by KYC status")
        return
    }

    // Sanitize users if you want to remove sensitive fields
    for _, u := range users {
        h.sanitizeUserForAdmin(u)
    }

    response := successResponse(users, "Users retrieved successfully")
    if nextPageToken != "" {
        response.Meta = &Meta{
            PageToken: nextPageToken,
            PageSize:  limit,
            Total:     len(users),
        }
    }

    h.respondWithJSON(w, http.StatusOK, response)
    h.logger.Debug("Admin retrieved users by KYC status",
        zap.String("status", status),
        zap.Int("count", len(users)),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ===== OWNER MANAGEMENT =====

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
        zap.String("admin_id", owner.AdminID.String()),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ===== ADMIN MANAGEMENT =====

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
        zap.String("admin_id", requesterID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", admin.AdminID.String()),
        zap.String("role_level", req.RoleLevel),
        zap.String("invited_by", requesterID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.String("new_role", req.NewRole),
        zap.String("promoted_by", requesterID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.String("removed_by", requesterID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.Strings("permissions", req.Permissions),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("admin_id", adminID.String()),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ✅ SIMPLIFIED: ListAdmins - Remove complex multi-filtering
func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    _, _ = h.getRequesterAdminID(r)

    limitStr := r.URL.Query().Get("limit")

    limit := 50
    if limitStr != "" {
        if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
            limit = parsed
        }
    }

    // Simple active admins list only - remove role/status combination logic
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
        zap.Int("count", len(admins)),
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ✅ NEW: Simple admin status filter
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
        zap.String("status", status),
        zap.Int("count", len(admins)),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.String("role", roleLevel),
        zap.Int("count", len(admins)),
        zap.Duration("duration", time.Since(startTime)),
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
        zap.Duration("duration", time.Since(startTime)),
    )
}

// ============================================================
// OPTIMIZED COMPANY QUERIES WITH SIMPLE FILTERS
// ============================================================

// // GetCompaniesByTier retrieves companies by subscription tier
// func (h *AdminHandler) GetCompaniesByTier(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     tier := chi.URLParam(r, "tier")
//     if tier == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("tier required"), "Subscription tier is required")
//         return
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)
//     if limit <= 0 || limit > 1000 {
//         limit = 50
//     }

//     companies, err := h.companyService.GetCompaniesByTier(ctx, tier, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by tier")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "tier":  tier,
//             "count": len(companies),
//             "limit": limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by tier"))

//     h.logger.Debug("Companies retrieved by tier",
//         zap.String("tier", tier),
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // // ✅ UPDATE GetCompaniesByTierAndStatus to use in-memory filtering
// func (h *AdminHandler) GetCompaniesByTierAndStatus(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     tier := chi.URLParam(r, "tier")
//     status := chi.URLParam(r, "status")
    
//     if tier == "" || status == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("tier and status required"), "Tier and status are required")
//         return
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)

//     // Step 1: Get companies by tier first
//     companies, err := h.companyService.GetCompaniesByTier(ctx, tier, limit*2) // Get more for filtering
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by tier")
//         return
//     }

//     // Step 2: Filter by status in memory
//     var filteredCompanies []*models.Company
//     for _, company := range companies {
//         switch status {
//         case "active":
//             if company.IsActive && !company.IsBlocked {
//                 filteredCompanies = append(filteredCompanies, company)
//             }
//         case "inactive":
//             if !company.IsActive && !company.IsBlocked {
//                 filteredCompanies = append(filteredCompanies, company)
//             }
//         case "blocked":
//             if company.IsBlocked {
//                 filteredCompanies = append(filteredCompanies, company)
//             }
//         }
        
//         // Apply limit after filtering
//         if len(filteredCompanies) >= limit {
//             break
//         }
//     }

//     response := map[string]interface{}{
//         "companies": filteredCompanies,
//         "meta": map[string]interface{}{
//             "tier":   tier,
//             "status": status,
//             "count":  len(filteredCompanies),
//             "limit":  limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by tier and status"))
// }
// // GetCompaniesBySubscriptionDateRange retrieves companies by subscription date range
// func (h *AdminHandler) GetCompaniesBySubscriptionDateRange(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     // Parse date parameters
//     startDateStr := r.URL.Query().Get("start_date")
//     endDateStr := r.URL.Query().Get("end_date")
    
//     if startDateStr == "" || endDateStr == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("dates required"), "Start date and end date are required")
//         return
//     }

//     // Parse dates (expecting RFC3339 or YYYY-MM-DD format)
//     startDate, err := time.Parse("2006-01-02", startDateStr)
//     if err != nil {
//         // Try RFC3339 format
//         startDate, err = time.Parse(time.RFC3339, startDateStr)
//         if err != nil {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid start date"), "Start date must be in YYYY-MM-DD or RFC3339 format")
//             return
//         }
//     }

//     endDate, err := time.Parse("2006-01-02", endDateStr)
//     if err != nil {
//         // Try RFC3339 format
//         endDate, err = time.Parse(time.RFC3339, endDateStr)
//         if err != nil {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid end date"), "End date must be in YYYY-MM-DD or RFC3339 format")
//             return
//         }
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)
//     if limit <= 0 || limit > 1000 {
//         limit = 50
//     }

//     companies, err := h.companyService.GetCompaniesBySubscriptionDateRange(ctx, startDate, endDate, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by subscription date range")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "start_date": startDate.Format("2006-01-02"),
//             "end_date":   endDate.Format("2006-01-02"),
//             "count":      len(companies),
//             "limit":      limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by subscription date range"))

//     h.logger.Debug("Companies retrieved by subscription date range",
//         zap.Time("start_date", startDate),
//         zap.Time("end_date", endDate),
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// ===== HELPER FUNCTIONS =====

func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
    status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
    return err == nil && status != nil && status.Exists
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
        h.logger.Error("Failed to encode JSON response", zap.Error(err))
    }
}

func (h *AdminHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
    h.logger.Warn("Admin HTTP error response",
        zap.Error(err),
        zap.Int("status_code", statusCode),
        zap.String("message", message),
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


// GetCompaniesWithExpiringSubscription retrieves companies whose subscription ends soon
func (h *AdminHandler) GetCompaniesWithExpiringSubscription(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    // Get days parameter (default to 7 days)
    days := h.getIntQueryParam(r, "days", 7)
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
        zap.Int("days", days),
        zap.Int("count", len(companies)),
        zap.Duration("duration", time.Since(startTime)),
    )
}
// sanitizeUserForAdmin removes sensitive fields before returning users to admin endpoints
func (h *AdminHandler) sanitizeUserForAdmin(u *models.User) {
    if u == nil {
        return
    }
    // Remove or zero sensitive fields
    u.PhoneEncrypted = ""
    u.PhoneKeyID = uuid.Nil
    // Keep phone_hash and other non-sensitive fields for admin listing
}

// // Response structures
// type Response struct {
//     Success bool        `json:"success"`
//     Data    interface{} `json:"data"`
//     Message string      `json:"message"`
//     Meta    *Meta       `json:"meta,omitempty"`
// }

// type Meta struct {
//     PageToken string `json:"page_token,omitempty"`
//     PageSize  int    `json:"page_size,omitempty"`
//     Total     int    `json:"total,omitempty"`
// }

// func successResponse(data interface{}, message string) *Response {
//     return &Response{
//         Success: true,
//         Data:    data,
//         Message: message,
//     }
// }

// func errorResponse(err error, message string) *Response {
//     return &Response{
//         Success: false,
//         Data:    map[string]string{"error": err.Error()},
//         Message: message,
//     }
// }


// // handler/admin_handler.go
// package handler

// import (
//     "context"
//     "encoding/json"
//     "fmt"
//     "net"
//     "net/http"
//     "strconv"
//     "strings"
//     "time"
//     "encoding/base64"

//     "github.com/go-chi/chi/v5"
//     "github.com/google/uuid"
//     "go.uber.org/zap"

//     "auth-service/internal/models"
//     "auth-service/internal/service"
//     "auth-service/internal/util"
// )

// // AdminHandler handles admin related HTTP endpoints
// type AdminHandler struct {
//     adminService   *service.AdminService
//     companyService *service.CompanyService
//     otpService     *service.OTPService
//     mpinService    *service.AdminMPINService
//     deviceService  *service.AdminDeviceService
//     sessionService *service.SessionService
//     userService    *service.UserService
//     jwtService     *service.JWTService
//     logger         *zap.Logger
// }

// func NewAdminHandler(
//     adminService *service.AdminService,
//     companyService *service.CompanyService,
//     otpService *service.OTPService,
//     mpinService *service.AdminMPINService,
//     deviceService *service.AdminDeviceService,
//     sessionService *service.SessionService,
//     userService *service.UserService,
//     jwtService *service.JWTService,
//     logger *zap.Logger,
// ) *AdminHandler {
//     return &AdminHandler{
//         adminService:   adminService,
//         companyService: companyService,
//         otpService:     otpService,
//         mpinService:    mpinService,
//         deviceService:  deviceService,
//         sessionService: sessionService,
//         userService:    userService,
//         jwtService:     jwtService,
//         logger:         logger,
//     }
// }
// func (h *AdminHandler) RegisterRoutes(router chi.Router) {
//     // Admin Authentication Routes (public - no auth middleware)
//     router.Route("/admin-auth", func(r chi.Router) {
//         r.Post("/login/initiate", h.InitiateAdminLogin)
//         r.Post("/login/verify-otp", h.VerifyAdminOTPLogin)
//         r.Post("/login/verify-mpin", h.VerifyAdminMPINLogin)
//         r.Post("/mpin/setup", h.SetupAdminMPIN)
//         r.Post("/refresh", h.RefreshAdminTokens)
//         r.Post("/logout", h.LogoutAdmin)
//         r.Get("/health", h.HealthCheck)
//     })

//     // Admin Management Routes (protected - rely on router-level middleware)
//     router.Route("/admins", func(r chi.Router) {
//         // Remove: r.Use(h.adminAuthMiddleware)
//         r.Get("/", h.ListAdmins)
//         r.Get("/stats", h.GetStats)
//         r.Post("/invite", h.InviteAdmin)
//         r.Get("/{adminID}", h.GetAdminByID)
//         r.Get("/phone/{phone}", h.GetAdminByPhone)
//         r.Get("/role/{roleLevel}", h.GetAdminsByRole)
//         r.Patch("/{adminID}/role", h.PromoteAdmin)
//         r.Patch("/{adminID}/permissions", h.UpdateAdminPermissions)
//         r.Patch("/{adminID}/deactivate", h.DeactivateAdmin)
//         r.Patch("/{adminID}/activate", h.ActivateAdmin)
//         r.Delete("/{adminID}", h.RemoveAdmin)
//         r.Patch("/owner/phone", h.ChangeOwnerPhone)
//     })

//     // Company Management Routes (protected - rely on router-level middleware)
//     router.Route("/admins/companies", func(r chi.Router) {
//         // Remove: r.Use(h.adminAuthMiddleware)
//         r.Post("/", h.CreateCompany)
//         r.Get("/", h.ListCompanies)
//         r.Get("/tier/{tier}", h.GetCompaniesByTier)
//         r.Get("/tier/{tier}/status/{status}", h.GetCompaniesByTierAndStatus)
//         r.Get("/subscription-date-range", h.GetCompaniesBySubscriptionDateRange)

//         r.Get("/{companyID}", h.GetCompany)
//         r.Patch("/{companyID}/block", h.BlockCompany)
//         r.Patch("/{companyID}/unblock", h.UnblockCompany)
//         r.Patch("/{companyID}/subscription", h.UpdateSubscription)
//         r.Patch("/{companyID}/extend", h.ExtendSubscription)
//         r.Get("/{companyID}/employees", h.GetCompanyEmployees)
//     })

//     // User Management Routes (protected - rely on router-level middleware)
//     router.Route("/admins/users", func(r chi.Router) {
//         // Remove: r.Use(h.adminAuthMiddleware)
//         r.Patch("/{userID}/kyc", h.UpdateUserKYC)
//         r.Post("/{userID}/ban", h.BanUser)
//         r.Post("/{userID}/unban", h.UnbanUser)
//         r.Get("/banned", h.GetBannedUsers)
//         r.Get("/kyc/{status}", h.ListUsersByKYCStatus)
//     })
// }
// // ===== ADMIN AUTHENTICATION FLOW =====

// // LoginFlowResponse defines the response for admin login flow
// type LoginFlowResponse struct {
//     UserExists     bool   `json:"user_exists"`
//     HasMPIN        bool   `json:"has_mpin"`
//     MPINLocked     bool   `json:"mpin_locked"`
//     DeviceTrusted  bool   `json:"device_trusted"`
//     FlowState      string `json:"flow_state"`
//     Message        string `json:"message"`
//     UserID         string `json:"user_id,omitempty"`
// }

// func (h *AdminHandler) InitiateAdminLogin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req struct {
//         PhoneNumber       string `json:"phone_number" validate:"required"`
//         DeviceID          string `json:"device_id" validate:"required"`
//         DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
//     req.DeviceID = util.SanitizeInput(req.DeviceID)
//     req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

//     admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
//     adminExists := err == nil && admin != nil

//     response := &LoginFlowResponse{
//         UserExists: adminExists,
//     }

//     if !adminExists {
//         response.FlowState = "new_user"
//         response.Message = "New admin - OTP verification required for setup"
//         h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
//         return
//     }

//     // Use AdminMPINService method
//     mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID)
//     if err != nil {
//         response.FlowState = "existing_user_otp"
//         response.Message = "Existing admin - OTP verification required (no MPIN setup)"
//         h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
//         return
//     }

//     response.HasMPIN = true
//     response.MPINLocked = mpinStatus.IsLocked

//     // Use AdminDeviceService method
//     deviceTrusted, _ := h.deviceService.IsDeviceTrusted(ctx, admin.AdminID, req.DeviceID)

//     if response.MPINLocked {
//         response.FlowState = "mpin_locked"
//         response.Message = "MPIN locked - OTP verification required"
//     } else if deviceTrusted {
//         response.FlowState = "existing_user_mpin"
//         response.DeviceTrusted = true
//         response.Message = "Trusted device - MPIN login available"
//         response.UserID = admin.AdminID.String()
//     } else {
//         response.FlowState = "existing_user_otp"
//         response.Message = "Untrusted device - OTP verification required"
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Admin login flow determined"))

//     h.logger.Info("Admin login initiation completed",
//         zap.String("phone", req.PhoneNumber),
//         zap.Bool("admin_exists", adminExists),
//         zap.Bool("has_mpin", response.HasMPIN),
//         zap.Bool("mpin_locked", response.MPINLocked),
//         zap.Bool("device_trusted", deviceTrusted),
//         zap.String("flow_state", response.FlowState),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) VerifyAdminOTPLogin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req struct {
//         PhoneNumber       string `json:"phone_number" validate:"required"`
//         OTP               string `json:"otp" validate:"required"`
//         DeviceID          string `json:"device_id" validate:"required"`
//         DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.PhoneNumber = util.SanitizeInput(req.PhoneNumber)
//     req.OTP = util.SanitizeInput(req.OTP)
//     req.DeviceID = util.SanitizeInput(req.DeviceID)
//     req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

//     otpVerifyReq := service.OTPVerifyRequest{
//         PhoneNumber: req.PhoneNumber,
//         OTP:         req.OTP,
//         Purpose:     "admin_login",
//         IPAddress:   h.getClientIP(r),
//     }

//     otpResponse, err := h.otpService.VerifyOTP(ctx, &otpVerifyReq)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Invalid OTP")
//         return
//     }

//     if !otpResponse.Success {
//         h.respondWithError(w, http.StatusUnauthorized,
//             fmt.Errorf("OTP_VERIFICATION_FAILED: OTP verification failed"),
//             "OTP verification failed")
//         return
//     }

//     admin, err := h.adminService.GetAdminByPhone(ctx, req.PhoneNumber)
//     if err != nil {
//         h.respondWithError(w, http.StatusNotFound, err, "Admin not found")
//         return
//     }

//     deviceReq := service.AdminBindDeviceRequest{
//         AdminID:   admin.AdminID,
//         DeviceID:  req.DeviceID,
//         IPAddress: h.getClientIP(r),
//         UserAgent: r.UserAgent(),
//     }

//     if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
//         h.logger.Warn("Failed to update device trust for admin", zap.Error(err))
//     }

//     if mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID); err == nil && mpinStatus.IsLocked {
//         if err := h.mpinService.UnlockAdminMPIN(ctx, admin.AdminID); err != nil {
//             h.logger.Warn("Failed to unlock MPIN after OTP verification", zap.Error(err))
//         }
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
//         "admin_id":       admin.AdminID.String(),
//         "device_trusted": true,
//         "has_mpin":       h.hasMPIN(ctx, admin.AdminID),
//         "mpin_locked":    false,
//         "message":        "OTP verification successful. Device is now trusted.",
//     }, "Admin device setup successful"))

//     h.logger.Info("Admin OTP verification completed - device trusted (no tokens issued)",
//         zap.String("admin_id", admin.AdminID.String()),
//         zap.String("phone", req.PhoneNumber),
//         zap.String("device_id", req.DeviceID),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) VerifyAdminMPINLogin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req struct {
//         AdminID           string `json:"admin_id" validate:"required"`
//         MPIN              string `json:"mpin" validate:"required"`
//         DeviceID          string `json:"device_id" validate:"required"`
//         DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.MPIN = util.SanitizeInput(req.MPIN)
//     req.DeviceID = util.SanitizeInput(req.DeviceID)
//     req.DeviceFingerprint = util.SanitizeInput(req.DeviceFingerprint)

//     adminID, err := uuid.Parse(req.AdminID)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, adminID, req.DeviceID)
//     if err != nil || !deviceTrusted {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
//             "MPIN login not allowed on this device")
//         return
//     }

//     mpinVerifyReq := service.AdminMPINVerifyRequest{
//         AdminID:  adminID,
//         MPIN:     req.MPIN,
//         DeviceID: req.DeviceID,
//     }

//     mpinResult, err := h.mpinService.VerifyAdminMPIN(ctx, &mpinVerifyReq)
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

//     admin, err := h.adminService.GetAdmin(ctx, adminID)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get admin details")
//         return
//     }

//     tokenReq := &service.IssueTokenPairRequest{
//         UserID:           admin.AdminID.String(),
//         Role:             "admin",
//         DeviceID:         req.DeviceID,
//         SessionType:      "admin",
//         IPAddress:        h.getClientIP(r),
//         AdminRoleLevel:   admin.AdminRoleLevel,
//         AdminPermissions: admin.AdminPermissions,
//     }

//     tokens, err := h.sessionService.IssueTokenPair(ctx, tokenReq)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to issue JWT tokens")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
//         "tokens":  tokens,
//         "admin":   admin,
//         "message": "Admin MPIN login successful",
//     }, "Admin login successful"))

//     h.logger.Info("Admin MPIN login completed with JWT tokens",
//         zap.String("admin_id", adminID.String()),
//         zap.String("role_level", admin.AdminRoleLevel),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) SetupAdminMPIN(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req struct {
//         AdminID  string `json:"admin_id" validate:"required"`
//         MPIN     string `json:"mpin" validate:"required,min=4,max=6"`
//         DeviceID string `json:"device_id" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.MPIN = util.SanitizeInput(req.MPIN)
//     req.DeviceID = util.SanitizeInput(req.DeviceID)

//     adminID, err := uuid.Parse(req.AdminID)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID")
//         return
//     }

//     mpinReq := service.AdminMPINSetupRequest{
//         AdminID:  adminID,
//         MPIN:     req.MPIN,
//         DeviceID: req.DeviceID,
//     }

//     if err := h.mpinService.SetupAdminMPIN(ctx, &mpinReq); err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to setup MPIN")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(map[string]interface{}{
//         "message": "MPIN setup successfully. You can now use MPIN for daily authentication.",
//     }, "Admin MPIN setup successful"))

//     h.logger.Info("Admin MPIN setup completed (no tokens issued)",
//         zap.String("admin_id", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) RefreshAdminTokens(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     var req struct {
//         RefreshToken string `json:"refresh_token" validate:"required"`
//     }
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     ipAddress := h.getClientIP(r)

//     tokenPair, err := h.sessionService.RefreshTokenPair(ctx, req.RefreshToken, ipAddress)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Failed to refresh tokens")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Admin tokens refreshed successfully"))
// }

// func (h *AdminHandler) LogoutAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     var req struct {
//         RefreshToken string `json:"refresh_token" validate:"required"`
//     }
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if err := h.sessionService.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to logout")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin logged out successfully"))
// }

// // ===== COMPANY MANAGEMENT =====

// // CreateCompany creates a new company and auto-creates owner user if needed
// func (h *AdminHandler) CreateCompany(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     var req struct {
//         CompanyName      string  `json:"company_name" validate:"required"`
//         OwnerPhone       string  `json:"owner_phone" validate:"required"`
//         SubscriptionTier string  `json:"subscription_tier" validate:"required,oneof=basic premium enterprise"`
//         MonthlyPremium   float64 `json:"monthly_premium" validate:"required,min=0"`
//         MaxEmployees     int     `json:"max_employees" validate:"required,min=1,max=2000"`
//         DataRegion       string  `json:"data_region" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     // Validate required fields
//     if req.CompanyName == "" || req.OwnerPhone == "" || req.SubscriptionTier == "" {
//         h.respondWithError(w, http.StatusBadRequest, 
//             fmt.Errorf("missing required fields"), 
//             "Company name, owner phone, and subscription tier are required")
//         return
//     }

//     // Create company using service
//     companyReq := service.CreateCompanyRequest{
//         CompanyName:      req.CompanyName,
//         OwnerPhone:       req.OwnerPhone,
//         SubscriptionTier: req.SubscriptionTier,
//         MonthlyPremium:   req.MonthlyPremium,
//         MaxEmployees:     req.MaxEmployees,
//         DataRegion:       req.DataRegion,
//         CreatedByAdmin:   adminID,
//     }

//     company, err := h.companyService.CreateCompany(ctx, &companyReq)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to create company")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(company, "Company created successfully"))

//     h.logger.Info("Company created by admin with auto-created owner",
//         zap.String("company_id", company.CompanyID.String()),
//         zap.String("company_name", company.CompanyName),
//         zap.String("owner_phone", company.OwnerPhone),
//         zap.String("created_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // // ListCompanies retrieves companies with pagination and filters
// // func (h *AdminHandler) ListCompanies(w http.ResponseWriter, r *http.Request) {
// //     ctx := r.Context()
// //     startTime := time.Now()

// //     // Parse pagination parameters
// //     page := h.getIntQueryParam(r, "page", 1)
// //     limit := h.getIntQueryParam(r, "limit", 25)
// //     if limit <= 0 || limit > 1000 {
// //         limit = 25
// //     }

// //     // Parse filters
// //     name := strings.TrimSpace(r.URL.Query().Get("name"))
// //     tier := strings.TrimSpace(r.URL.Query().Get("tier"))
// //     status := strings.TrimSpace(r.URL.Query().Get("status"))

// //     // Build filter
// //     filter := models.CompanyFilter{
// //         NameContains:     name,
// //         SubscriptionTier: tier,
// //         Status:           status,
// //     }

// //     // Use CompanyService instead of AdminService for company operations
// //     companies, total, err := h.companyService.ListCompanies(ctx, filter, page, limit)
// //     if err != nil {
// //         h.respondWithError(w, h.getStatusCode(err), err, "Failed to list companies")
// //         return
// //     }

// //     response := map[string]interface{}{
// //         "companies": companies,
// //         "meta": map[string]interface{}{
// //             "page":  page,
// //             "limit": limit,
// //             "total": total,
// //         },
// //     }

// //     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved successfully"))

// //     h.logger.Debug("Companies listed by admin",
// //         zap.Int("count", len(companies)),
// //         zap.Duration("duration", time.Since(startTime)),
// //     )
// // }



// // In admin_handler.go - Update ListCompanies method
// func (h *AdminHandler) ListCompanies(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     // Parse pagination parameters - prefer cursor-based pagination
//     pageSize := h.getIntQueryParam(r, "limit", 25)
//     if pageSize <= 0 || pageSize > 100 {
//         pageSize = 25
//     }

//     pageState := r.URL.Query().Get("page_state")

//     // Parse filters
//     name := strings.TrimSpace(r.URL.Query().Get("name"))
//     tier := strings.TrimSpace(r.URL.Query().Get("tier"))
//     status := strings.TrimSpace(r.URL.Query().Get("status"))

//     // Build filter
//     filter := models.CompanyFilter{
//         NameContains:     name,
//         SubscriptionTier: tier,
//         Status:           status,
//     }

//     // Use cursor-based pagination for better performance
//     companies, nextPageState, err := h.companyService.ListCompaniesWithPaging(ctx, filter, pageSize, []byte(pageState))
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to list companies")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "page_size":   pageSize,
//             "page_state":  base64.StdEncoding.EncodeToString(nextPageState),
//             "has_more":    len(nextPageState) > 0,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved successfully"))

//     h.logger.Debug("Companies listed by admin",
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }
// // GetCompany retrieves company details by ID
// func (h *AdminHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     company, err := h.companyService.GetCompany(ctx, companyID)
//     if err != nil {
//         h.respondWithError(w, http.StatusNotFound, err, "Company not found")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company details retrieved"))

//     h.logger.Debug("Company retrieved by admin",
//         zap.String("company_id", companyID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // BlockCompany blocks a company
// func (h *AdminHandler) BlockCompany(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     var req struct {
//         Reason string `json:"reason" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if req.Reason == "" {
//         h.respondWithError(w, http.StatusBadRequest, 
//             fmt.Errorf("reason required"), "Block reason is required")
//         return
//     }

//     if err := h.companyService.BlockCompany(ctx, companyID, req.Reason, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to block company")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company blocked successfully"))

//     h.logger.Info("Company blocked by admin",
//         zap.String("company_id", companyID.String()),
//         zap.String("blocked_by", adminID.String()),
//         zap.String("reason", req.Reason),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // UnblockCompany unblocks a company
// func (h *AdminHandler) UnblockCompany(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     if err := h.companyService.UnblockCompany(ctx, companyID, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to unblock company")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company unblocked successfully"))

//     h.logger.Info("Company unblocked by admin",
//         zap.String("company_id", companyID.String()),
//         zap.String("unblocked_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // UpdateSubscription updates company subscription
// func (h *AdminHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     var req struct {
//         Tier         string  `json:"tier" validate:"required,oneof=basic premium enterprise"`
//         Premium      float64 `json:"premium" validate:"required,min=0"`
//         MaxEmployees int     `json:"max_employees" validate:"required,min=1,max=2000"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if err := h.companyService.UpdateSubscription(ctx, companyID, req.Tier, req.Premium, req.MaxEmployees, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to update subscription")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription updated successfully"))

//     h.logger.Info("Company subscription updated",
//         zap.String("company_id", companyID.String()),
//         zap.String("tier", req.Tier),
//         zap.Float64("premium", req.Premium),
//         zap.Int("max_employees", req.MaxEmployees),
//         zap.String("updated_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ExtendSubscription extends company subscription
// func (h *AdminHandler) ExtendSubscription(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     var req struct {
//         Months int `json:"months" validate:"required,min=1,max=36"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if err := h.companyService.ExtendSubscription(ctx, companyID, req.Months, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to extend subscription")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))

//     h.logger.Info("Company subscription extended",
//         zap.String("company_id", companyID.String()),
//         zap.Int("months", req.Months),
//         zap.String("updated_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // GetCompanyEmployees lists employees for a company
// func (h *AdminHandler) GetCompanyEmployees(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     companyIDStr := chi.URLParam(r, "companyID")
//     companyID, err := uuid.Parse(companyIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
//         return
//     }

//     // Parse pagination
//     page := h.getIntQueryParam(r, "page", 1)
//     limit := h.getIntQueryParam(r, "limit", 50)

//     employees, total, err := h.companyService.ListEmployees(ctx, companyID, page, limit)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to list employees")
//         return
//     }

//     response := map[string]interface{}{
//         "employees": employees,
//         "meta": map[string]interface{}{
//             "page":  page,
//             "limit": limit,
//             "total": total,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Employees retrieved successfully"))

//     h.logger.Debug("Company employees listed by admin",
//         zap.String("company_id", companyID.String()),
//         zap.Int("count", len(employees)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ===== USER MANAGEMENT =====

// func (h *AdminHandler) BanUser(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, _ := h.getRequesterAdminID(r)

//     userIDStr := chi.URLParam(r, "userID")
//     userID, err := uuid.Parse(userIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
//         return
//     }

//     var req struct {
//         Reason string `json:"reason" validate:"required"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     banReq := service.BanUserRequest{
//         UserID:   userID,
//         BannedBy: requesterID,
//         Reason:   req.Reason,
//     }

//     if err := h.userService.BanUser(ctx, &banReq); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to ban user")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User banned successfully"))

//     h.logger.Info("User banned by admin",
//         zap.String("user_id", userID.String()),
//         zap.String("banned_by", requesterID.String()),
//         zap.String("reason", req.Reason),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, _ := h.getRequesterAdminID(r)

//     userIDStr := chi.URLParam(r, "userID")
//     userID, err := uuid.Parse(userIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
//         return
//     }

//     if err := h.userService.UnbanUser(ctx, userID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to unban user")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))

//     h.logger.Info("User unbanned by admin",
//         zap.String("user_id", userID.String()),
//         zap.String("unbanned_by", requesterID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     limitStr := r.URL.Query().Get("limit")
//     pageToken := r.URL.Query().Get("page_token")

//     limit := 100
//     if limitStr != "" {
//         parsedLimit, err := strconv.Atoi(limitStr)
//         if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid limit"), "Limit must be between 1 and 1000")
//             return
//         }
//         limit = parsedLimit
//     }

//     users, nextPageToken, err := h.userService.GetBannedUsers(ctx, limit, pageToken)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
//         return
//     }

//     response := successResponse(users, "Banned users retrieved successfully")
//     if nextPageToken != "" {
//         response.Meta = &Meta{
//             PageToken: nextPageToken,
//             PageSize:  limit,
//             Total:     len(users),
//         }
//     }

//     h.respondWithJSON(w, http.StatusOK, response)

//     h.logger.Debug("Banned users retrieved by admin",
//         zap.Int("count", len(users)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // UpdateUserKYC - Admin approves/rejects user KYC (replaces company KYC)
// func (h *AdminHandler) UpdateUserKYC(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     userIDStr := chi.URLParam(r, "userID")
//     userID, err := uuid.Parse(userIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
//         return
//     }

//     var req struct {
//         Status string `json:"status" validate:"required,oneof=approved rejected pending"`
//         Level  string `json:"level,omitempty"`
//         Reason string `json:"reason,omitempty"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     kycReq := service.KYCUpdateRequest{
//         UserID: userID,
//         Status: strings.ToLower(req.Status),
//         Level:  req.Level,
//         Reason: req.Reason,
//     }

//     if err := h.userService.UpdateKYCStatus(ctx, &kycReq); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to update user KYC")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User KYC status updated successfully"))

//     h.logger.Info("User KYC status updated by admin",
//         zap.String("user_id", userID.String()),
//         zap.String("status", req.Status),
//         zap.String("level", req.Level),
//         zap.String("updated_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ListUsersByKYCStatus - Admin views users filtered by KYC status
// func (h *AdminHandler) ListUsersByKYCStatus(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     status := chi.URLParam(r, "status")
//     if status == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("status required"), "KYC status is required")
//         return
//     }

//     limitStr := r.URL.Query().Get("limit")
//     pageToken := r.URL.Query().Get("page_token")

//     limit := 100
//     if limitStr != "" {
//         parsedLimit, err := strconv.Atoi(limitStr)
//         if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid limit"), "Limit must be between 1 and 1000")
//             return
//         }
//         limit = parsedLimit
//     }

//     users, nextPageToken, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, pageToken)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by KYC status")
//         return
//     }

//     // Sanitize users if you want to remove sensitive fields
//     for _, u := range users {
//         h.sanitizeUserForAdmin(u)
//     }

//     response := successResponse(users, "Users retrieved successfully")
//     if nextPageToken != "" {
//         response.Meta = &Meta{
//             PageToken: nextPageToken,
//             PageSize:  limit,
//             Total:     len(users),
//         }
//     }

//     h.respondWithJSON(w, http.StatusOK, response)
//     h.logger.Debug("Admin retrieved users by KYC status",
//         zap.String("status", status),
//         zap.Int("count", len(users)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ===== OWNER MANAGEMENT =====

// func (h *AdminHandler) InitializeOwner(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     var req struct {
//         Phone string `json:"phone"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.Phone = strings.TrimSpace(req.Phone)
//     if req.Phone == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("phone required"), "Phone is required")
//         return
//     }

//     owner, err := h.adminService.InitializeOwner(ctx, req.Phone)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to initialize owner")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(owner, "Owner initialized successfully"))
//     h.logger.Info("Owner initialized via HTTP",
//         zap.String("admin_id", owner.AdminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ===== ADMIN MANAGEMENT =====

// func (h *AdminHandler) ChangeOwnerPhone(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req struct {
//         NewPhone string `json:"new_phone"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.NewPhone = strings.TrimSpace(req.NewPhone)
//     if req.NewPhone == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("new_phone required"), "New phone is required")
//         return
//     }

//     if err := h.adminService.ChangeOwnerPhone(ctx, requesterID, req.NewPhone); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to change owner phone")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Owner phone updated successfully"))
//     h.logger.Info("Owner phone changed via HTTP",
//         zap.String("admin_id", requesterID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) InviteAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     requesterRole, err := h.getRequesterRole(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     var req struct {
//         Phone     string `json:"phone"`
//         RoleLevel string `json:"role_level"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.Phone = strings.TrimSpace(req.Phone)
//     req.RoleLevel = strings.TrimSpace(strings.ToLower(req.RoleLevel))

//     if req.Phone == "" || req.RoleLevel == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("missing fields"), "Phone and role level are required")
//         return
//     }

//     if !h.isValidRoleLevel(req.RoleLevel) {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
//         return
//     }

//     admin, err := h.adminService.InviteAdmin(ctx, req.Phone, req.RoleLevel, requesterID, requesterRole)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to invite user as admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(admin, "User invited as admin successfully"))
//     h.logger.Info("User invited as admin via HTTP",
//         zap.String("admin_id", admin.AdminID.String()),
//         zap.String("role_level", req.RoleLevel),
//         zap.String("invited_by", requesterID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     var req struct {
//         NewRole string `json:"new_role"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.NewRole = strings.TrimSpace(strings.ToLower(req.NewRole))
//     if !h.isValidRoleLevel(req.NewRole) {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
//         return
//     }

//     if err := h.adminService.PromoteAdmin(ctx, adminID, req.NewRole, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to promote admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin role updated successfully"))
//     h.logger.Info("Admin promoted via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.String("new_role", req.NewRole),
//         zap.String("promoted_by", requesterID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) RemoveAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     if err := h.adminService.RemoveAdmin(ctx, adminID, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to remove admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin removed successfully"))
//     h.logger.Info("Admin removed via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.String("removed_by", requesterID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) DeactivateAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     if err := h.adminService.DeactivateAdmin(ctx, adminID, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to deactivate admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin deactivated successfully"))
//     h.logger.Info("Admin deactivated via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) ActivateAdmin(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     if err := h.adminService.ActivateAdmin(ctx, adminID, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to activate admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin activated successfully"))
//     h.logger.Info("Admin activated via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) UpdateAdminPermissions(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     requesterID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
//         return
//     }

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     var req struct {
//         Permissions []string `json:"permissions"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if len(req.Permissions) == 0 {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("empty permissions"), "Permissions list cannot be empty")
//         return
//     }

//     if err := h.adminService.UpdateAdminPermissions(ctx, adminID, req.Permissions, requesterID); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to update permissions")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin permissions updated successfully"))
//     h.logger.Info("Admin permissions updated via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.Strings("permissions", req.Permissions),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) GetAdminByID(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     _, _ = h.getRequesterAdminID(r)

//     adminIDStr := chi.URLParam(r, "adminID")
//     adminID, err := uuid.Parse(adminIDStr)
//     if err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
//         return
//     }

//     admin, err := h.adminService.GetAdmin(ctx, adminID)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to get admin")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin retrieved successfully"))
//     h.logger.Debug("Admin retrieved via HTTP",
//         zap.String("admin_id", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) GetAdminByPhone(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     _, _ = h.getRequesterAdminID(r)

//     phone := chi.URLParam(r, "phone")
//     if phone == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("phone required"), "Phone is required")
//         return
//     }

//     admin, err := h.adminService.GetAdminByPhone(ctx, phone)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to get admin by phone")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(admin, "Admin retrieved successfully"))
//     h.logger.Debug("Admin retrieved by phone via HTTP",
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     _, _ = h.getRequesterAdminID(r)

//     roleLevel := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("role")))
//     status := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
//     limitStr := r.URL.Query().Get("limit")

//     limit := 50
//     if limitStr != "" {
//         if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
//             limit = parsed
//         }
//     }

//     var admins []*models.AdminUser
//     var err error

//     if roleLevel != "" && h.isValidRoleLevel(roleLevel) {
//         admins, err = h.adminService.GetAdminsByRole(ctx, roleLevel)
//     } else if status == "active" {
//         admins, err = h.adminService.GetActiveAdmins(ctx, limit)
//     } else {
//         admins, err = h.adminService.GetActiveAdmins(ctx, limit)
//     }

//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to list admins")
//         return
//     }

//     if status == "inactive" && admins != nil {
//         var inactiveAdmins []*models.AdminUser
//         for _, admin := range admins {
//             if !admin.IsActive {
//                 inactiveAdmins = append(inactiveAdmins, admin)
//             }
//         }
//         admins = inactiveAdmins
//     }

//     if admins == nil {
//         admins = []*models.AdminUser{}
//     }

//     response := successResponse(map[string]interface{}{
//         "admins": admins,
//         "count":  len(admins),
//     }, "Admins retrieved successfully")

//     h.respondWithJSON(w, http.StatusOK, response)
//     h.logger.Debug("Admins listed via HTTP",
//         zap.Int("count", len(admins)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     _, _ = h.getRequesterAdminID(r)

//     roleLevel := strings.ToLower(chi.URLParam(r, "roleLevel"))
//     if !h.isValidRoleLevel(roleLevel) {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid role"), "Invalid role level")
//         return
//     }

//     admins, err := h.adminService.GetAdminsByRole(ctx, roleLevel)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to get admins by role")
//         return
//     }

//     if admins == nil {
//         admins = []*models.AdminUser{}
//     }

//     response := successResponse(map[string]interface{}{
//         "admins": admins,
//         "role":   roleLevel,
//         "count":  len(admins),
//     }, "Admins retrieved successfully")

//     h.respondWithJSON(w, http.StatusOK, response)
//     h.logger.Debug("Admins retrieved by role via HTTP",
//         zap.String("role", roleLevel),
//         zap.Int("count", len(admins)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ===== HEALTH & STATISTICS =====

// func (h *AdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     if err := h.adminService.HealthCheck(ctx); err != nil {
//         h.respondWithError(w, http.StatusServiceUnavailable, err, "Admin service unhealthy")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
//         "status":  "healthy",
//         "service": "admin",
//     }, "Admin service is healthy"))
// }

// func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     stats, err := h.adminService.GetStats(ctx)
//     if err != nil {
//         h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get stats")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin statistics retrieved successfully"))
//     h.logger.Debug("Admin stats retrieved via HTTP",
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ===== HELPER FUNCTIONS =====

// func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
//     status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
//     return err == nil && status != nil && status.Exists
// }

// func (h *AdminHandler) getIntQueryParam(r *http.Request, key string, defaultValue int) int {
//     value := r.URL.Query().Get(key)
//     if value == "" {
//         return defaultValue
//     }
//     var result int
//     _, err := fmt.Sscanf(value, "%d", &result)
//     if err != nil {
//         return defaultValue
//     }
//     return result
// }

// func (h *AdminHandler) getStatusCode(err error) int {
//     if err == nil {
//         return http.StatusOK
//     }

//     errMsg := err.Error()

//     if strings.Contains(errMsg, "not found") {
//         return http.StatusNotFound
//     }
//     if strings.Contains(errMsg, "already exists") || strings.Contains(errMsg, "already has an owner") {
//         return http.StatusConflict
//     }
//     if strings.Contains(errMsg, "not registered") {
//         return http.StatusBadRequest
//     }
//     if strings.Contains(errMsg, "unauthorized") || strings.Contains(errMsg, "permission") {
//         return http.StatusForbidden
//     }
//     if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
//         return http.StatusBadRequest
//     }

//     return http.StatusInternalServerError
// }

// func (h *AdminHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
//     w.Header().Set("Content-Type", "application/json")
//     w.WriteHeader(statusCode)
//     if err := json.NewEncoder(w).Encode(data); err != nil {
//         h.logger.Error("Failed to encode JSON response", zap.Error(err))
//     }
// }

// func (h *AdminHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
//     h.logger.Warn("Admin HTTP error response",
//         zap.Error(err),
//         zap.Int("status_code", statusCode),
//         zap.String("message", message),
//     )
//     h.respondWithJSON(w, statusCode, errorResponse(err, message))
// }

// func (h *AdminHandler) isValidRoleLevel(role string) bool {
//     switch role {
//     case models.AdminRoleLevelOwner:
//         return true
//     case models.AdminRoleLevelSuperEmployee:
//         return true
//     case models.AdminRoleLevelEmployee:
//         return true
//     default:
//         return false
//     }
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

// func (h *AdminHandler) getRequesterRole(r *http.Request) (string, error) {
//     role, ok := r.Context().Value("admin_role_level").(string)
//     if !ok || role == "" {
//         return "", fmt.Errorf("admin role not found in request context")
//     }
//     return role, nil
// }

// // client IP extraction robust helper
// func (h *AdminHandler) getClientIP(r *http.Request) string {
//     // Try X-Forwarded-For first
//     if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
//         if ips := strings.Split(forwarded, ","); len(ips) > 0 {
//             ip := strings.TrimSpace(ips[0])
//             // Validate IP format
//             if parsedIP := net.ParseIP(ip); parsedIP != nil {
//                 return ip
//             }
//         }
//     }

//     // Try X-Real-IP
//     if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
//         if parsedIP := net.ParseIP(realIP); parsedIP != nil {
//             return realIP
//         }
//     }

//     // Try CF-Connecting-IP
//     if cfConnectingIP := r.Header.Get("CF-Connecting-IP"); cfConnectingIP != "" {
//         if parsedIP := net.ParseIP(cfConnectingIP); parsedIP != nil {
//             return cfConnectingIP
//         }
//     }

//     // Try Forwarded header
//     if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
//         if strings.Contains(forwarded, "for=") {
//             parts := strings.Split(forwarded, ";")
//             for _, part := range parts {
//                 part = strings.TrimSpace(part)
//                 if strings.HasPrefix(part, "for=") {
//                     ip := strings.TrimPrefix(part, "for=")
//                     ip = strings.Trim(ip, `"`)
//                     // Handle IPv6 addresses in brackets and ports
//                     if idx := strings.LastIndex(ip, ":"); idx != -1 {
//                         // Check if it's IPv6 with port
//                         if strings.Contains(ip, "]") {
//                             // IPv6 with port format: [::1]:8080
//                             if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx < idx {
//                                 ip = ip[:bracketIdx+1]
//                             }
//                         } else if !strings.Contains(ip, ".") {
//                             // Likely IPv6 without brackets
//                             ip = ip
//                         } else {
//                             // IPv4 with port
//                             ip = ip[:idx]
//                         }
//                     }
//                     if parsedIP := net.ParseIP(ip); parsedIP != nil {
//                         return ip
//                     }
//                 }
//             }
//         }
//     }

//     // Fallback to RemoteAddr with proper parsing
//     host, _, err := net.SplitHostPort(r.RemoteAddr)
//     if err != nil {
//         // If SplitHostPort fails, try to parse as IP directly
//         if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
//             return r.RemoteAddr
//         }
//         // Return a safe default if all parsing fails
//         return "127.0.0.1"
//     }

//     // Final validation
//     if parsedIP := net.ParseIP(host); parsedIP != nil {
//         return host
//     }

//     // Safe fallback
//     return "127.0.0.1"
// }

// // sanitizeUserForAdmin removes sensitive fields before returning users to admin endpoints
// func (h *AdminHandler) sanitizeUserForAdmin(u *models.User) {
//     if u == nil {
//         return
//     }
//     // Remove or zero sensitive fields
//     u.PhoneEncrypted = ""
//     u.PhoneKeyID = uuid.Nil
//     // Keep phone_hash and other non-sensitive fields for admin listing
// }

// // // adminAuthMiddleware validates admin JWT tokens
// // func (h *AdminHandler) adminAuthMiddleware(next http.Handler) http.Handler {
// //     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// //         authHeader := r.Header.Get("Authorization")
// //         if authHeader == "" {
// //             h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("missing authorization header"), "Authentication required")
// //             return
// //         }

// //         // Extract token from "Bearer <token>"
// //         parts := strings.Split(authHeader, " ")
// //         if len(parts) != 2 || parts[0] != "Bearer" {
// //             h.respondWithError(w, http.StatusUnauthorized, fmt.Errorf("invalid authorization format"), "Invalid authorization header format")
// //             return
// //         }

// //         token := parts[1]
        
// //         // Validate token using JWT service
// //         claims, err := h.jwtService.ValidateToken(token)
// //         if err != nil {
// //             h.respondWithError(w, http.StatusUnauthorized, err, "Invalid or expired token")
// //             return
// //         }

// //         // Check if user has admin role
// //         if claims.Role != "admin" {
// //             h.respondWithError(w, http.StatusForbidden, fmt.Errorf("insufficient permissions"), "Admin access required")
// //             return
// //         }

// //         // Add claims to context
// //         ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
// //         ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
// //         ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)

// //         next.ServeHTTP(w, r.WithContext(ctx))
// //     })
// // }



// // ============================================================
// // NEW: Optimized Company Query APIs with Simple Filters
// // ============================================================

// // GetCompaniesByTier retrieves companies by subscription tier
// func (h *AdminHandler) GetCompaniesByTier(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     tier := chi.URLParam(r, "tier")
//     if tier == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("tier required"), "Subscription tier is required")
//         return
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)
//     if limit <= 0 || limit > 1000 {
//         limit = 50
//     }

//     companies, err := h.companyService.GetCompaniesByTier(ctx, tier, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by tier")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "tier":  tier,
//             "count": len(companies),
//             "limit": limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by tier"))

//     h.logger.Debug("Companies retrieved by tier",
//         zap.String("tier", tier),
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // GetCompaniesByTierAndStatus retrieves companies by tier and status
// func (h *AdminHandler) GetCompaniesByTierAndStatus(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     tier := chi.URLParam(r, "tier")
//     status := chi.URLParam(r, "status")
    
//     if tier == "" || status == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("tier and status required"), "Tier and status are required")
//         return
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)
//     if limit <= 0 || limit > 1000 {
//         limit = 50
//     }

//     var companies []*models.Company
//     var err error

//     switch status {
//     case "active":
//         companies, err = h.companyService.GetCompaniesByTierAndActive(ctx, tier, true, limit)
//     case "inactive":
//         companies, err = h.companyService.GetCompaniesByTierAndActive(ctx, tier, false, limit)
//     case "blocked":
//         companies, err = h.companyService.GetCompaniesByTierAndBlocked(ctx, tier, true, limit)
//     case "unblocked":
//         companies, err = h.companyService.GetCompaniesByTierAndBlocked(ctx, tier, false, limit)
//     default:
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid status"), "Status must be active, inactive, blocked, or unblocked")
//         return
//     }

//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by tier and status")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "tier":   tier,
//             "status": status,
//             "count":  len(companies),
//             "limit":  limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by tier and status"))

//     h.logger.Debug("Companies retrieved by tier and status",
//         zap.String("tier", tier),
//         zap.String("status", status),
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // GetCompaniesBySubscriptionDateRange retrieves companies by subscription date range
// func (h *AdminHandler) GetCompaniesBySubscriptionDateRange(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     // Parse date parameters
//     startDateStr := r.URL.Query().Get("start_date")
//     endDateStr := r.URL.Query().Get("end_date")
    
//     if startDateStr == "" || endDateStr == "" {
//         h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("dates required"), "Start date and end date are required")
//         return
//     }

//     // Parse dates (expecting RFC3339 or YYYY-MM-DD format)
//     startDate, err := time.Parse("2006-01-02", startDateStr)
//     if err != nil {
//         // Try RFC3339 format
//         startDate, err = time.Parse(time.RFC3339, startDateStr)
//         if err != nil {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid start date"), "Start date must be in YYYY-MM-DD or RFC3339 format")
//             return
//         }
//     }

//     endDate, err := time.Parse("2006-01-02", endDateStr)
//     if err != nil {
//         // Try RFC3339 format
//         endDate, err = time.Parse(time.RFC3339, endDateStr)
//         if err != nil {
//             h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid end date"), "End date must be in YYYY-MM-DD or RFC3339 format")
//             return
//         }
//     }

//     limit := h.getIntQueryParam(r, "limit", 50)
//     if limit <= 0 || limit > 1000 {
//         limit = 50
//     }

//     companies, err := h.companyService.GetCompaniesBySubscriptionDateRange(ctx, startDate, endDate, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to get companies by subscription date range")
//         return
//     }

//     response := map[string]interface{}{
//         "companies": companies,
//         "meta": map[string]interface{}{
//             "start_date": startDate.Format("2006-01-02"),
//             "end_date":   endDate.Format("2006-01-02"),
//             "count":      len(companies),
//             "limit":      limit,
//         },
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(response, "Companies retrieved by subscription date range"))

//     h.logger.Debug("Companies retrieved by subscription date range",
//         zap.Time("start_date", startDate),
//         zap.Time("end_date", endDate),
//         zap.Int("count", len(companies)),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }
