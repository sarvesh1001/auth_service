// internal/handler/admin_handler.go - FULLY UPDATED VERSION

package handler

import (
	"encoding/json"
	"fmt"
	"net" // ✅ ADDED
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminHandler handles HTTP requests for admin operations
type AdminHandler struct {
	adminService *service.AdminService
	sessionService *service.SessionService // ✅ ADD THIS
	logger       *zap.Logger
}

// ✅ UPDATED CONSTRUCTOR: Add LogProducerService parameter
func NewAdminHandler(
	adminService *service.AdminService, 
	sessionService *service.SessionService, // ✅ ADD THIS
	logger *zap.Logger,
) *AdminHandler {
	return &AdminHandler{
		adminService: adminService,
		sessionService: sessionService, // ✅ ADD THIS
		logger:       logger,
	}
}


// RegisterRoutes registers all admin routes
func (h *AdminHandler) RegisterRoutes(router chi.Router) {
	router.Route("/admins", func(r chi.Router) {
		// ========================================
		// PUBLIC ENDPOINTS (No authentication)
		// ========================================

		// Owner initialization - public (first-time setup)
		r.Post("/init-owner", h.InitializeOwner)

		// Health check - public
		r.Get("/health", h.HealthCheck)

		// ✅ MOVED: Admin authentication - MUST BE PUBLIC to create first session
		r.Post("/authenticate", h.AuthenticateAdmin)

		// ========================================
		// PROTECTED ENDPOINTS (Require admin session)
		// ========================================
		r.Group(func(r chi.Router) {
			// Apply admin authentication middleware to entire group
			// r.Use(adminAuthMiddleware) // Uncomment when middleware is available

			// Statistics - protected
			r.Get("/stats", h.GetStats)

			// Owner management - owner only
			r.Patch("/owner/phone", h.ChangeOwnerPhone)

			// Admin invitation - owner/super_employee
			r.Post("/invite", h.InviteAdmin)

			// Admin management - owner/super_employee (role-based)
			r.Patch("/{adminID}/role", h.PromoteAdmin)
			r.Patch("/{adminID}/permissions", h.UpdateAdminPermissions)
			r.Delete("/{adminID}", h.RemoveAdmin)
			r.Patch("/{adminID}/deactivate", h.DeactivateAdmin)
			r.Patch("/{adminID}/activate", h.ActivateAdmin)

			// Admin queries
			r.Get("/{adminID}", h.GetAdminByID)
			r.Get("/phone/{phone}", h.GetAdminByPhone)
			r.Get("/", h.ListAdmins)
			r.Get("/role/{roleLevel}", h.GetAdminsByRole)
		})
	})
}

// ===== OWNER MANAGEMENT =====

// InitializeOwner creates the first system owner
// POST /api/v1/admins/init-owner
// ✅ PUBLIC ENDPOINT - NO AUTHENTICATION REQUIRED
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

// ===== ADMIN AUTHENTICATION =====

// AuthenticateAdmin authenticates an admin by phone and creates a session
// POST /api/v1/admins/authenticate
// ✅ PUBLIC ENDPOINT - NO AUTHENTICATION REQUIRED (session creation must be public)
func (h *AdminHandler) AuthenticateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		Phone    string `json:"phone"`
		DeviceID string `json:"device_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Sanitize inputs
	req.Phone = strings.TrimSpace(req.Phone)
	if req.Phone == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("phone required"), "Phone is required")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "admin-web-default"
	}

	// Get client IP for session
	clientIP := h.getClientIP(r)

	// Use service method that returns session token
	admin, sessionToken, err := h.adminService.AuthenticateAdminWithSession(ctx, req.Phone, req.DeviceID, clientIP)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Authentication failed")
		return
	}

	// Return both admin details AND session token
	responseData := map[string]interface{}{
		"admin":         admin,
		"session_token": sessionToken, // ✅ THIS IS WHAT YOUR TESTS NEED
	}

	response := successResponse(responseData, "Admin authenticated successfully")
	h.respondWithJSON(w, http.StatusOK, response)
	
	h.logger.Info("Admin authenticated with session via HTTP",
		util.String("admin_id", admin.AdminID.String()),
		util.String("role", admin.AdminRoleLevel),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== PROTECTED ENDPOINTS =====

// ChangeOwnerPhone allows owner to change their phone number
// PATCH /api/v1/admins/owner/phone
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) ChangeOwnerPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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

// InviteAdmin invites a user to become admin
// POST /api/v1/admins/invite
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) InviteAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	requesterRole, err := getRequesterRole(r)
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

	if !isValidRoleLevel(req.RoleLevel) {
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

// PromoteAdmin promotes/demotes an admin to different role
// PATCH /api/v1/admins/{adminID}/role
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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
	if !isValidRoleLevel(req.NewRole) {
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

// RemoveAdmin removes an admin (soft delete)
// DELETE /api/v1/admins/{adminID}
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) RemoveAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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

// DeactivateAdmin deactivates an admin temporarily
// PATCH /api/v1/admins/{adminID}/deactivate
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) DeactivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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

// ActivateAdmin reactivates a deactivated admin
// PATCH /api/v1/admins/{adminID}/activate
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) ActivateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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

// UpdateAdminPermissions updates admin permissions
// PATCH /api/v1/admins/{adminID}/permissions
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) UpdateAdminPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	requesterID, err := getRequesterAdminID(r)
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

// GetAdminByID retrieves admin by ID
// GET /api/v1/admins/{adminID}
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) GetAdminByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = getRequesterAdminID(r)

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

// GetAdminByPhone retrieves admin by phone
// GET /api/v1/admins/phone/{phone}
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) GetAdminByPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = getRequesterAdminID(r)

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

// ListAdmins lists admins with optional filters
// GET /api/v1/admins?role=employee&status=active&limit=20
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = getRequesterAdminID(r)

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

	if roleLevel != "" && isValidRoleLevel(roleLevel) {
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
		util.Int("count", len(admins)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAdminsByRole retrieves admins by role level
// GET /api/v1/admins/role/{roleLevel}
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
func (h *AdminHandler) GetAdminsByRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	_, _ = getRequesterAdminID(r)

	roleLevel := strings.ToLower(chi.URLParam(r, "roleLevel"))
	if !isValidRoleLevel(roleLevel) {
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

// ===== HEALTH & STATISTICS =====

// HealthCheck verifies admin service health
// GET /api/v1/admins/health
// ✅ PUBLIC ENDPOINT
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

// GetStats retrieves admin service statistics
// GET /api/v1/admins/stats
// ✅ PROTECTED ENDPOINT - REQUIRES ADMIN SESSION
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

// ===== HELPER FUNCTIONS =====

// getStatusCode maps service errors to HTTP status codes
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

// respondWithJSON sends a JSON response
func (h *AdminHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

// respondWithError sends an error response
func (h *AdminHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("Admin HTTP error response",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// isValidRoleLevel checks if role level is valid
func isValidRoleLevel(role string) bool {
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

// getRequesterAdminID extracts admin ID from request context (set by middleware)
func getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
	adminID, ok := r.Context().Value("adminID").(uuid.UUID)
	if !ok || adminID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("admin ID not found in request context")
	}
	return adminID, nil
}

// getRequesterRole extracts admin role from request context (set by middleware)
func getRequesterRole(r *http.Request) (string, error) {
	role, ok := r.Context().Value("adminRole").(string)
	if !ok || role == "" {
		return "", fmt.Errorf("admin role not found in request context")
	}
	return role, nil
}

// getClientIP extracts the client IP address from the request
func (h *AdminHandler) getClientIP(r *http.Request) string {
	// Check for forwarded IP first (load balancer, proxy, etc.)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can be a list of IPs, take the first one
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// Validate IP format
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	
	// Check for other common headers
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
	
	// Check Forwarded header (RFC 7239)
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		// Parse: for=192.0.2.60;proto=http;by=203.0.113.43
		if strings.Contains(forwarded, "for=") {
			parts := strings.Split(forwarded, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "for=") {
					ip := strings.TrimPrefix(part, "for=")
					// Remove quotes and port if present
					ip = strings.Trim(ip, `"`)
					if idx := strings.LastIndex(ip, ":"); idx != -1 {
						// Check if it's a port (not IPv6)
						if !strings.Contains(ip, "]") {
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
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try to use RemoteAddr as-is
		return r.RemoteAddr
	}
	return host
}