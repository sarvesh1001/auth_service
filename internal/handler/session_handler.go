// internal/handler/session_handler.go
package handler

import (
    "encoding/json"
    "errors"
    "net/http"
    "strconv"
    "time"

    "auth-service/internal/service"
    "auth-service/internal/util"

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

func (h *SessionHandler) RegisterRoutes(router chi.Router) {
    router.Route("/sessions", func(r chi.Router) {
        r.Post("/", h.CreateSession)
        r.Get("/user/{userID}", h.GetSessionByUserID)
        r.Get("/token/{token}", h.GetSessionByToken)
        r.Patch("/user/{userID}/activity", h.UpdateSessionActivity)
        r.Delete("/user/{userID}", h.InvalidateSession)
        r.Delete("/token/{token}", h.InvalidateSessionByToken)
        r.Post("/user/{userID}/refresh", h.RefreshSession)

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

func (h *SessionHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()

    var req service.CreateSessionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    // Get client IP
    req.IPAddress = h.getClientIP(r)

    session, err := h.sessionService.CreateSession(ctx, &req)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create session")
        return
    }

    h.respondWithJSON(w, http.StatusCreated, successResponse(session, "Session created successfully"))
    h.logger.Info("Session created via HTTP",
        util.String("user_id", req.UserID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
}

func (h *SessionHandler) GetSessionByUserID(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    session, err := h.sessionService.GetSessionByUserID(ctx, userID)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Session not found")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(session, "Session retrieved successfully"))
}

func (h *SessionHandler) GetSessionByToken(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    token := chi.URLParam(r, "token")
    if token == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("token required"), "Session token required")
        return
    }

    session, err := h.sessionService.GetSessionByToken(ctx, token)
    if err != nil {
        h.respondWithError(w, http.StatusNotFound, err, "Session not found")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(session, "Session retrieved successfully"))
}

func (h *SessionHandler) UpdateSessionActivity(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    ipAddress := h.getClientIP(r)

    if err := h.sessionService.UpdateSessionActivity(ctx, userID, ipAddress); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update session activity")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session activity updated"))
}

func (h *SessionHandler) InvalidateSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    if err := h.sessionService.InvalidateSession(ctx, userID); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to invalidate session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session invalidated successfully"))
}

func (h *SessionHandler) InvalidateSessionByToken(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    token := chi.URLParam(r, "token")
    if token == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("token required"), "Session token required")
        return
    }

    if err := h.sessionService.InvalidateSessionByToken(ctx, token); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to invalidate session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Session invalidated successfully"))
}

func (h *SessionHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    newToken, err := h.sessionService.RefreshSession(ctx, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to refresh session")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
        "token": newToken,
    }, "Session refreshed successfully"))
}

func (h *SessionHandler) InvalidateSessionsBatch(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    var req struct {
        UserIDs []string `json:"user_ids"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
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
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to invalidate sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Sessions invalidated successfully"))
}

func (h *SessionHandler) GetSessionsBatch(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    var req struct {
        UserIDs []string `json:"user_ids"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }

    userIDs := make([]uuid.UUID, 0, len(req.UserIDs))
    for _, idStr := range req.UserIDs {
        id, err := uuid.Parse(idStr)
        if err != nil {
            continue
        }
        userIDs = append(userIDs, id)
    }

    sessions, err := h.sessionService.GetSessionsBatch(ctx, userIDs)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(sessions, "Sessions retrieved successfully"))
}

func (h *SessionHandler) CleanupExpiredSessions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    batchSizeStr := r.URL.Query().Get("batch_size")
    batchSize := 1000
    if batchSizeStr != "" {
        if parsed, err := strconv.Atoi(batchSizeStr); err == nil {
            batchSize = parsed
        }
    }

    cleaned, err := h.sessionService.CleanupExpiredSessions(ctx, batchSize)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to cleanup sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]int{
        "cleaned": cleaned,
    }, "Cleanup completed successfully"))
}

func (h *SessionHandler) GetSessionsByDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

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
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(sessions, "Sessions retrieved successfully"))
}

func (h *SessionHandler) InvalidateDeviceSessions(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    deviceID := chi.URLParam(r, "deviceID")
    if deviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("device ID required"), "Device ID required")
        return
    }

    if err := h.sessionService.InvalidateDeviceSessions(ctx, deviceID); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to invalidate device sessions")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Device sessions invalidated successfully"))
}

func (h *SessionHandler) GetActiveSessionsCount(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }

    count, err := h.sessionService.GetActiveSessionsCount(ctx, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get session count")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(map[string]int{
        "count": count,
    }, "Session count retrieved successfully"))
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
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get stats")
        return
    }

    h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Stats retrieved successfully"))
}

// Helper methods

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
