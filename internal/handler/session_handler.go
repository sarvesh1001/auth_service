// internal/handler/session_handler.go - UPDATED
package handler

import (
    "encoding/json"
    "errors"
    "net/http"
    "strconv"
    "time"  
    "fmt"
    "auth-service/internal/service"
    "auth-service/internal/util"
    "strings"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

type SessionHandler struct {
    sessionService *service.SessionService
    logger         *zap.Logger
}

func NewSessionHandler(sessionService *service.SessionService, logger *zap.Logger) *SessionHandler {
    return &SessionHandler{
        sessionService: sessionService,
        logger:         logger,
    }
}

var (
    ErrSessionNotFound = errors.New("session not found")
    ErrInvalidInput    = errors.New("invalid input")
    ErrSessionExpired  = errors.New("session expired")
)
// ✅ NEW: RegisterPublicRoutes registers public session routes
func (h *SessionHandler) RegisterPublicRoutes(router chi.Router) {
    router.Route("/sessions", func(r chi.Router) {
        r.Post("/", h.CreateSession)
        r.Post("/admin", h.CreateAdminSession) // ✅ NEW: Admin session creation
        r.Get("/health", h.HealthCheck)
    })
}

// ✅ NEW: RegisterProtectedRoutes registers protected session routes
func (h *SessionHandler) RegisterProtectedRoutes(router chi.Router) {
    router.Route("/sessions", func(r chi.Router) {
        r.Get("/user/{userID}", h.GetSessionByUserID)
        r.Get("/token/{token}", h.GetSessionByToken)
        r.Patch("/user/{userID}/activity", h.UpdateSessionActivity)
        r.Delete("/user/{userID}", h.InvalidateSession)
        r.Delete("/token/{token}", h.InvalidateSessionByToken)
        r.Post("/user/{userID}/refresh", h.RefreshSession)

        // ✅ NEW: Admin session operations
        r.Delete("/admin/user/{userID}", h.InvalidateAdminSessions)
        r.Get("/admin/user/{userID}/count", h.GetActiveAdminSessionsCount)

        // Bulk operations
        r.Post("/invalidate-batch", h.InvalidateSessionsBatch)
        r.Post("/batch", h.GetSessionsBatch)
        r.Post("/cleanup", h.CleanupExpiredSessions)

        // Device management
        r.Get("/device/{deviceID}", h.GetSessionsByDevice)
        r.Delete("/device/{deviceID}", h.InvalidateDeviceSessions)
        r.Get("/user/{userID}/count", h.GetActiveSessionsCount)

        // Health & stats
        r.Get("/stats", h.GetSessionStats)
    })
}

// ✅ DEPRECATED: Original RegisterRoutes for backward compatibility
func (h *SessionHandler) RegisterRoutes(router chi.Router) {
    router.Route("/sessions", func(r chi.Router) {
        r.Post("/", h.CreateSession)
        r.Post("/admin", h.CreateAdminSession) // ✅ NEW: Admin session creation
        r.Get("/user/{userID}", h.GetSessionByUserID)
        r.Get("/token/{token}", h.GetSessionByToken)
        r.Patch("/user/{userID}/activity", h.UpdateSessionActivity)
        r.Delete("/user/{userID}", h.InvalidateSession)
        r.Delete("/token/{token}", h.InvalidateSessionByToken)
        r.Post("/user/{userID}/refresh", h.RefreshSession)

        // ✅ NEW: Admin session operations
        r.Delete("/admin/user/{userID}", h.InvalidateAdminSessions)
        r.Get("/admin/user/{userID}/count", h.GetActiveAdminSessionsCount)

        // Bulk operations
        r.Post("/invalidate-batch", h.InvalidateSessionsBatch)
        r.Post("/batch", h.GetSessionsBatch)
        r.Post("/cleanup", h.CleanupExpiredSessions)

        // Device management
        r.Get("/device/{deviceID}", h.GetSessionsByDevice)
        r.Delete("/device/{deviceID}", h.InvalidateDeviceSessions)
        r.Get("/user/{userID}/count", h.GetActiveSessionsCount)

        // Health & stats
        r.Get("/health", h.HealthCheck)
        r.Get("/stats", h.GetSessionStats)
    })
}

// ✅ NEW: CreateAdminSession handles admin session creation
// POST /api/v1/sessions/admin
func (h *SessionHandler) CreateAdminSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req service.CreateAdminSessionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Validate required fields
    if req.AdminID == uuid.Nil {
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("admin_id required"), "Admin ID is required")
        return
    }
    // ✅ FIXED: Use AdminRoleMask instead of AdminRoleLevel
    if req.AdminRoleMask == 0 {
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("admin_role_mask required"), "Admin role mask is required")
        return
    }
    if req.DeviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, 
            fmt.Errorf("device_id required"), "Device ID is required")
        return
    }

    // Get client IP
    req.IPAddress = h.getClientIP(r)

    session, err := h.sessionService.CreateAdminSession(ctx, &req)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to create admin session")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(session, "Admin session created successfully"))
    h.logger.Info("Admin session created via HTTP",
        util.String("admin_id", req.AdminID.String()),
        // ✅ FIXED: Use AdminRoleMask for logging
        util.Uint64("role_mask", req.AdminRoleMask),
        util.Duration("duration", time.Since(startTime)),
    )
}
// ✅ NEW: InvalidateAdminSessions invalidates all admin sessions for a user
// DELETE /api/v1/sessions/admin/user/{userID}
func (h *SessionHandler) InvalidateAdminSessions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    if err := h.sessionService.InvalidateAdminSessions(ctx, userID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invalidate admin sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Admin sessions invalidated successfully"))
    h.logger.Info("Admin sessions invalidated via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

// ✅ NEW: GetActiveAdminSessionsCount gets count of admin sessions for a user
// GET /api/v1/sessions/admin/user/{userID}/count
func (h *SessionHandler) GetActiveAdminSessionsCount(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    count, err := h.sessionService.GetActiveAdminSessionsCount(ctx, userID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get admin session count")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]int{
        "admin_sessions_count": count,
    }, "Admin session count retrieved successfully"))
    h.logger.Debug("Admin session count retrieved via HTTP",
        util.String("user_id", userID.String()),
        util.Int("count", count),
        util.Duration("duration", time.Since(startTime)),
    )
}

// ===== EXISTING METHODS (UPDATED WITH BETTER ERROR HANDLING) =====

func (h *SessionHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req service.CreateSessionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Validate required fields
    if req.UserID == uuid.Nil {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("user_id required"), "User ID is required")
        return
    }
    if req.DeviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("device_id required"), "Device ID is required")
        return
    }

    // Set default session type to "user" if not specified
    if req.SessionType == "" {
        req.SessionType = "user"
    }

    // Get client IP
    req.IPAddress = h.getClientIP(r)

    session, err := h.sessionService.CreateSession(ctx, &req)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to create session")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(session, "Session created successfully"))
    h.logger.Info("Session created via HTTP",
        util.String("user_id", req.UserID.String()),
        util.String("session_type", req.SessionType),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetSessionByUserID(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    session, err := h.sessionService.GetSessionByUserID(ctx, userID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Session not found")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(session, "Session retrieved successfully"))
    h.logger.Debug("Session retrieved via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetSessionByToken(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    token := chi.URLParam(r, "token")
    if token == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("token required"), "Session token required")
        return
    }

    session, err := h.sessionService.GetSessionByToken(ctx, token)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Session not found")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(session, "Session retrieved successfully"))
    h.logger.Debug("Session retrieved by token via HTTP",
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) UpdateSessionActivity(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    ipAddress := h.getClientIP(r)

    if err := h.sessionService.UpdateSessionActivity(ctx, userID, ipAddress); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to update session activity")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session activity updated"))
    h.logger.Debug("Session activity updated via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) InvalidateSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    if err := h.sessionService.InvalidateSession(ctx, userID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invalidate session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session invalidated successfully"))
    h.logger.Info("Session invalidated via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) InvalidateSessionByToken(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    token := chi.URLParam(r, "token")
    if token == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("token required"), "Session token required")
        return
    }

    if err := h.sessionService.InvalidateSessionByToken(ctx, token); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invalidate session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session invalidated successfully"))
    h.logger.Info("Session invalidated by token via HTTP",
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    newToken, err := h.sessionService.RefreshSession(ctx, userID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to refresh session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
        "token": newToken,
    }, "Session refreshed successfully"))
    h.logger.Info("Session refreshed via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) InvalidateSessionsBatch(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req struct {
        UserIDs []string `json:"user_ids"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if len(req.UserIDs) == 0 {
        h.respondWithError(w, http.StatusBadRequest, errors.New("empty batch"), "No user IDs provided")
        return
    }

    userIDs := make([]uuid.UUID, 0, len(req.UserIDs))
    for _, idStr := range req.UserIDs {
        id, err := uuid.Parse(idStr)
        if err != nil {
            h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in batch")
            return
        }
        userIDs = append(userIDs, id)
    }

    if err := h.sessionService.InvalidateSessionsBatch(ctx, userIDs); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invalidate sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Sessions invalidated successfully"))
    h.logger.Info("Batch sessions invalidated via HTTP",
        util.Int("count", len(userIDs)),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetSessionsBatch(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req struct {
        UserIDs []string `json:"user_ids"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    if len(req.UserIDs) == 0 {
        h.respondWithError(w, http.StatusBadRequest, errors.New("empty batch"), "No user IDs provided")
        return
    }

    userIDs := make([]uuid.UUID, 0, len(req.UserIDs))
    for _, idStr := range req.UserIDs {
        id, err := uuid.Parse(idStr)
        if err != nil {
            continue // Skip invalid IDs
        }
        userIDs = append(userIDs, id)
    }

    sessions, err := h.sessionService.GetSessionsBatch(ctx, userIDs)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(sessions, "Sessions retrieved successfully"))
    h.logger.Debug("Batch sessions retrieved via HTTP",
        util.Int("count", len(sessions)),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) CleanupExpiredSessions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    batchSizeStr := r.URL.Query().Get("batch_size")
    batchSize := 1000
    if batchSizeStr != "" {
        if parsed, err := strconv.Atoi(batchSizeStr); err == nil {
            batchSize = parsed
        }
    }

    cleaned, err := h.sessionService.CleanupExpiredSessions(ctx, batchSize)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to cleanup sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]int{
        "cleaned": cleaned,
    }, "Cleanup completed successfully"))
    h.logger.Info("Expired sessions cleanup via HTTP",
        util.Int("cleaned", cleaned),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetSessionsByDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    deviceID := chi.URLParam(r, "deviceID")
    if deviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("device ID required"), "Device ID required")
        return
    }

    limitStr := r.URL.Query().Get("limit")
    limit := 100
    if limitStr != "" {
        if parsed, err := strconv.Atoi(limitStr); err == nil {
            limit = parsed
        }
    }

    sessions, err := h.sessionService.GetSessionsByDevice(ctx, deviceID, limit)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(sessions, "Sessions retrieved successfully"))
    h.logger.Debug("Device sessions retrieved via HTTP",
        util.String("device_id", deviceID),
        util.Int("count", len(sessions)),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) InvalidateDeviceSessions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    deviceID := chi.URLParam(r, "deviceID")
    if deviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("device ID required"), "Device ID required")
        return
    }

    if err := h.sessionService.InvalidateDeviceSessions(ctx, deviceID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to invalidate device sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Device sessions invalidated successfully"))
    h.logger.Info("Device sessions invalidated via HTTP",
        util.String("device_id", deviceID),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetActiveSessionsCount(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    count, err := h.sessionService.GetActiveSessionsCount(ctx, userID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get session count")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]int{
        "count": count,
    }, "Session count retrieved successfully"))
    h.logger.Debug("Session count retrieved via HTTP",
        util.String("user_id", userID.String()),
        util.Int("count", count),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    if err := h.sessionService.HealthCheck(ctx); err != nil {
        h.respondWithError(w, http.StatusServiceUnavailable, err, "Session service unhealthy")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session service is healthy"))
}

func (h *SessionHandler) GetSessionStats(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    stats, err := h.sessionService.GetSessionStats(ctx)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get stats")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Stats retrieved successfully"))
}

// ===== HELPER METHODS =====

// ✅ NEW: getStatusCode determines appropriate HTTP status code
func (h *SessionHandler) getStatusCode(err error) int {
    if err == nil {
        return http.StatusOK
    }

    errMsg := err.Error()

    if errors.Is(err, ErrSessionNotFound) || strings.Contains(errMsg, "not found") {
        return http.StatusNotFound
    }
    if errors.Is(err, ErrInvalidInput) || strings.Contains(errMsg, "invalid") {
        return http.StatusBadRequest
    }
    if errors.Is(err, ErrSessionExpired) || strings.Contains(errMsg, "expired") {
        return http.StatusUnauthorized
    }
    if strings.Contains(errMsg, "unauthorized") || strings.Contains(errMsg, "permission") {
        return http.StatusForbidden
    }

    return http.StatusInternalServerError
}
// ✅ NEW: Add missing fmt import and error types
// Make sure to add this import: "fmt"

func (h *SessionHandler) getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return xff
    }
    // Check X-Real-IP header
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    return r.RemoteAddr
}

func (h *SessionHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(data)
}

func (h *SessionHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
    h.logger.Warn("Session HTTP error",
        util.ErrorField(err),
        util.Int("status_code", statusCode),
        util.String("message", message),
    )
    h.respondWithJSON(w, statusCode, errorResponse(err, message))
}
