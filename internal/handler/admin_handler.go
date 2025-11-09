// internal/handler/admin_handler.go
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

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "go.uber.org/zap"

    "auth-service/internal/models"
    "auth-service/internal/service"
    "auth-service/internal/util"
)

type AdminHandler struct {
    adminService   *service.AdminService
    otpService     *service.OTPService
    mpinService    *service.AdminMPINService  // ✅ Changed to AdminMPINService
    deviceService  *service.AdminDeviceService // ✅ Changed to AdminDeviceService
    sessionService *service.SessionService
    userService    *service.UserService
    jwtService     *service.JWTService
    logger         *zap.Logger
}

func NewAdminHandler(
    adminService *service.AdminService,
    otpService *service.OTPService,
    mpinService *service.AdminMPINService,   // ✅ Changed to AdminMPINService
    deviceService *service.AdminDeviceService, // ✅ Changed to AdminDeviceService
    sessionService *service.SessionService,
    userService *service.UserService,
    jwtService *service.JWTService,
    logger *zap.Logger,
) *AdminHandler {
    return &AdminHandler{
        adminService:   adminService,
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
    // Empty - routes defined in router.go
}

// ===== ADMIN AUTHENTICATION FLOW =====

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

    // ✅ FIXED: Use AdminMPINService method without EntityType
    mpinStatus, err := h.mpinService.GetAdminMPINStatus(ctx, admin.AdminID)
    if err != nil {
        response.FlowState = "existing_user_otp"
        response.Message = "Existing admin - OTP verification required (no MPIN setup)"
        h.respondWithJSON(w, http.StatusOK, successResponse(response, "Login flow determined"))
        return
    }

    response.HasMPIN = true
    response.MPINLocked = mpinStatus.IsLocked

    // ✅ FIXED: Use AdminDeviceService method without EntityType
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

    // ✅ FIXED: Use AdminBindDeviceRequest without EntityType fields
    deviceReq := service.AdminBindDeviceRequest{
        AdminID:   admin.AdminID,
        DeviceID:  req.DeviceID,
        IPAddress: h.getClientIP(r),
        UserAgent: r.UserAgent(),
    }

    if _, err := h.deviceService.BindDevice(ctx, deviceReq); err != nil {
        h.logger.Warn("Failed to update device trust for admin", zap.Error(err))
    }

    // ✅ FIXED: Use AdminMPINService method without EntityType
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

    // ✅ FIXED: Use AdminDeviceService method without EntityType
    deviceTrusted, err := h.deviceService.IsDeviceTrusted(ctx, adminID, req.DeviceID)
    if err != nil || !deviceTrusted {
        h.respondWithError(w, http.StatusForbidden,
            fmt.Errorf("UNTRUSTED_DEVICE: Device not trusted for MPIN login"),
            "MPIN login not allowed on this device")
        return
    }

    // ✅ FIXED: Use AdminMPINVerifyRequest without EntityType
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

    // ✅ FIXED: Use AdminMPINSetupRequest without EntityType
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

// ===== PROTECTED ENDPOINTS =====

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

func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    _, _ = h.getRequesterAdminID(r)

    roleLevel := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("role")))
    status := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
    limitStr := r.URL.Query().Get("limit")

    limit := 50
    if limitStr != "" {
        if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
            limit = parsed
        }
    }

    var admins []*models.AdminUser
    var err error

    if roleLevel != "" && h.isValidRoleLevel(roleLevel) {
        admins, err = h.adminService.GetAdminsByRole(ctx, roleLevel)
    } else if status == "active" {
        admins, err = h.adminService.GetActiveAdmins(ctx, limit)
    } else {
        admins, err = h.adminService.GetActiveAdmins(ctx, limit)
    }

    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to list admins")
        return
    }

    if status == "inactive" && admins != nil {
        var inactiveAdmins []*models.AdminUser
        for _, admin := range admins {
            if !admin.IsActive {
                inactiveAdmins = append(inactiveAdmins, admin)
            }
        }
        admins = inactiveAdmins
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

// ===== HELPER FUNCTIONS =====

func (h *AdminHandler) hasMPIN(ctx context.Context, adminID uuid.UUID) bool {
    // ✅ FIXED: Use AdminMPINService method without EntityType
    status, err := h.mpinService.GetAdminMPINStatus(ctx, adminID)
    return err == nil && status != nil && status.Exists
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
    case models.RoleLevelOwner:
        return true
    case models.RoleLevelSuperEmployee:
        return true
    case models.RoleLevelEmployee:
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
// internal/handler/admin_handler.go

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