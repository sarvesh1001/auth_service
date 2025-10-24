// internal/handler/mpin_handler.go

package handler

import (
    "encoding/json"
    "errors"
    "net/http"
    "strconv"
    "strings"
    "time"

    "auth-service/internal/service"
    "auth-service/internal/util"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

// MPINHandler handles HTTP requests for MPIN operations
type MPINHandler struct {
    mpinService *service.MPINService
    logger      *zap.Logger
}

// NewMPINHandler creates a new MPIN handler
func NewMPINHandler(mpinService *service.MPINService, logger *zap.Logger) *MPINHandler {
    return &MPINHandler{
        mpinService: mpinService,
        logger:      logger,
    }
}

// RegisterRoutes registers all MPIN routes
func (h *MPINHandler) RegisterRoutes(router chi.Router) {
    router.Route("/mpin", func(r chi.Router) {
        // Public routes
        r.Get("/health", h.HealthCheck)
        r.Get("/stats", h.GetMPINStats)
        
        // Protected routes (require authentication)
        r.Group(func(r chi.Router) {
            // User operations
            r.Post("/setup", h.SetupMPIN)
            r.Post("/verify", h.VerifyMPIN)
            r.Post("/change", h.ChangeMPIN)
            r.Post("/forgot", h.ForgotMPIN)  // ✅ NEW: Forgot MPIN endpoint
            r.Post("/reset", h.ResetMPIN)
            r.Post("/{userID}/unlock", h.UnlockMPIN)
            r.Get("/{userID}/status", h.GetMPINStatus)
            r.Patch("/{userID}/device", h.UpdateDeviceBinding)
            
            // Administrative operations
            r.Get("/locked", h.GetLockedMPINs)
            r.Post("/cleanup", h.CleanupExpiredLocks)
            r.Get("/device/{deviceID}", h.GetMPINsByDevice)
        })
    })
}

// SetupMPIN handles MPIN setup for new users
func (h *MPINHandler) SetupMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINSetupRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    
    if err := h.mpinService.SetupMPIN(ctx, &req); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to setup MPIN")
        return
    }
    
    h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "MPIN setup successfully"))
    h.logger.Info("MPIN setup via HTTP",
        util.String("user_id", req.UserID.String()),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "SetupMPIN"),
    )
}

// VerifyMPIN handles MPIN verification
// ✅ FIXED: VerifyMPIN handles MPIN verification
func (h *MPINHandler) VerifyMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINVerifyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    
    result, err := h.mpinService.VerifyMPIN(ctx, &req)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "MPIN verification failed")
        return
    }
    
    // ✅ FIX: Use different message based on verification result
    var message string
    if result.Verified {
        message = "MPIN verified successfully"
    } else {
        message = "MPIN verification failed: " + result.Message
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(result, message))
    h.logger.Info("MPIN verification result",
        util.String("user_id", req.UserID.String()),
        util.Bool("verified", result.Verified),
        util.Int("failed_attempts", result.FailedAttempts),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "VerifyMPIN"),
    )
}

// ChangeMPIN handles MPIN change (requires current MPIN)
func (h *MPINHandler) ChangeMPIN(w http.ResponseWriter, r *http.Request) {
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
        util.String("method", "ChangeMPIN"),
    )
}

// ✅ NEW: ForgotMPIN handles forgot MPIN request (no current MPIN needed, trusted device only)
// @Summary Forgot MPIN
// @Description Reset MPIN on trusted device without knowing current MPIN
// @Tags mpin
// @Accept json
// @Produce json
// @Param request body service.MPINForgotRequest true "Forgot MPIN request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/forgot [post]
func (h *MPINHandler) ForgotMPIN(w http.ResponseWriter, r *http.Request) {
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
        h.logger.Error("ForgotMPIN error",
            util.ErrorField(err),
            util.String("user_id", req.UserID.String()),
            util.String("device_id", req.DeviceID),
        )
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully on trusted device"))
    h.logger.Info("MPIN reset via forgot flow",
        util.String("user_id", req.UserID.String()),
        util.String("device_id", req.DeviceID),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "ForgotMPIN"),
    )
}

// ResetMPIN handles MPIN reset (admin operation)
func (h *MPINHandler) ResetMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINResetRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    if err := h.mpinService.ResetMPIN(ctx, &req); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to reset MPIN")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN reset successfully"))
    h.logger.Warn("MPIN reset via HTTP",
        util.String("user_id", req.UserID.String()),
        util.String("reset_by", req.ResetBy.String()),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "ResetMPIN"),
    )
}

// UnlockMPIN handles MPIN unlock
func (h *MPINHandler) UnlockMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
        return
    }
    
    if err := h.mpinService.UnlockMPIN(ctx, userID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to unlock MPIN")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN unlocked successfully"))
    h.logger.Info("MPIN unlocked via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "UnlockMPIN"),
    )
}

// GetMPINStatus handles MPIN status retrieval
func (h *MPINHandler) GetMPINStatus(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
        return
    }
    
    status, err := h.mpinService.GetMPINStatus(ctx, userID)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to get MPIN status")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(status, "MPIN status retrieved successfully"))
    h.logger.Debug("MPIN status retrieved via HTTP",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "GetMPINStatus"),
    )
}

// UpdateDeviceBinding handles device binding updates
func (h *MPINHandler) UpdateDeviceBinding(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
        return
    }
    
    var req struct {
        DeviceID string `json:"device_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    
    if err := h.mpinService.UpdateDeviceBinding(ctx, userID, req.DeviceID); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to update device binding")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Device binding updated successfully"))
    h.logger.Info("MPIN device binding updated via HTTP",
        util.String("user_id", userID.String()),
        util.String("device_id", req.DeviceID),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "UpdateDeviceBinding"),
    )
}

// GetLockedMPINs handles locked MPINs retrieval
func (h *MPINHandler) GetLockedMPINs(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    limitStr := r.URL.Query().Get("limit")
    limit := 100
    if limitStr != "" {
        parsedLimit, err := strconv.Atoi(limitStr)
        if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
            h.respondWithError(w, http.StatusBadRequest, errors.New("invalid limit"), "Limit must be between 1 and 1000")
            return
        }
        limit = parsedLimit
    }
    
    mpins, err := h.mpinService.GetLockedMPINs(ctx, limit)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get locked MPINs")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(mpins, "Locked MPINs retrieved successfully"))
    h.logger.Debug("Locked MPINs retrieved via HTTP",
        util.Int("count", len(mpins)),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "GetLockedMPINs"),
    )
}

// CleanupExpiredLocks handles expired lock cleanup
func (h *MPINHandler) CleanupExpiredLocks(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    cleaned, err := h.mpinService.CleanupExpiredLocks(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to cleanup expired locks")
        return
    }
    
    result := map[string]interface{}{
        "cleaned_locks": cleaned,
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(result, "Expired locks cleaned successfully"))
    h.logger.Info("MPIN cleanup completed via HTTP",
        util.Int("cleaned_locks", cleaned),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "CleanupExpiredLocks"),
    )
}

// GetMPINStats handles MPIN statistics
func (h *MPINHandler) GetMPINStats(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    stats, err := h.mpinService.GetMPINStats(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get MPIN stats")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(stats, "MPIN stats retrieved successfully"))
}

// GetMPINsByDevice handles device-based MPIN retrieval
func (h *MPINHandler) GetMPINsByDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    deviceID := chi.URLParam(r, "deviceID")
    if deviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, errors.New("device ID is required"), "Device ID is required")
        return
    }
    
    deviceID = util.SanitizeInput(deviceID)
    
    mpins, err := h.mpinService.GetMPINsByDevice(ctx, deviceID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get MPINs by device")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(mpins, "MPINs retrieved successfully"))
    h.logger.Debug("MPINs retrieved by device via HTTP",
        util.String("device_id", deviceID),
        util.Int("count", len(mpins)),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "GetMPINsByDevice"),
    )
}

// HealthCheck handles service health check
func (h *MPINHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    if err := h.mpinService.HealthCheck(ctx); err != nil {
        h.respondWithError(w, http.StatusServiceUnavailable, err, "MPIN service unhealthy")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN service is healthy"))
}

// ========== Helper Methods ==========

// respondWithJSON sends a JSON response
func (h *MPINHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    if err := json.NewEncoder(w).Encode(data); err != nil {
        h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
    }
}

// respondWithError sends an error response
func (h *MPINHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
    h.logger.Warn("MPIN HTTP error response",
        util.ErrorField(err),
        util.Int("status_code", statusCode),
        util.String("message", message),
    )
    h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// getStatusCode determines the appropriate HTTP status code for an error
func (h *MPINHandler) getStatusCode(err error) int {
    switch {
    case errors.Is(err, service.ErrMPINNotFound):
        return http.StatusNotFound
    case errors.Is(err, service.ErrMPINInvalid):
        return http.StatusUnauthorized
    case errors.Is(err, service.ErrMPINLocked):
        return http.StatusLocked
    case errors.Is(err, service.ErrMPINAlreadyExists):
        return http.StatusConflict
    case errors.Is(err, service.ErrInvalidInput):
        return http.StatusBadRequest
    case errors.Is(err, service.ErrPermissionDenied):
        return http.StatusForbidden
    default:
        return http.StatusInternalServerError
    }
}

// ✅ NEW: getForgotMPINStatusCode determines status code for forgot MPIN errors
func (h *MPINHandler) getForgotMPINStatusCode(err error) int {
    errMsg := err.Error()
    
    // Check for specific error messages from ForgotMPIN service
    if strings.Contains(errMsg, "untrusted device") {
        return http.StatusForbidden  // 403 - Can't reset on untrusted device
    }
    if strings.Contains(errMsg, "blocked") {
        return http.StatusForbidden  // 403 - Device is blocked
    }
    if strings.Contains(errMsg, "not found") {
        return http.StatusNotFound   // 404 - MPIN not found
    }
    
    return http.StatusInternalServerError // 500 - Generic error
}
