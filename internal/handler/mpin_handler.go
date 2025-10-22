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
        
        // Protected routes (require authentication)
        r.Group(func(r chi.Router) {
            // Add auth middleware here in production
            r.Post("/setup", h.SetupMPIN)
            r.Post("/verify", h.VerifyMPIN)
            r.Post("/change", h.ChangeMPIN)
            r.Post("/reset", h.ResetMPIN)
            r.Post("/{userID}/unlock", h.UnlockMPIN)
            r.Get("/{userID}/status", h.GetMPINStatus)
            r.Patch("/{userID}/device", h.UpdateDeviceBinding)
            
            // Administrative operations
            r.Get("/locked", h.GetLockedMPINs)
            r.Post("/cleanup", h.CleanupExpiredLocks)
            r.Get("/stats", h.GetMPINStats)
            r.Get("/device/{deviceID}", h.GetMPINsByDevice)
        })
    })
}

// SetupMPIN handles MPIN setup for new users
// @Summary Setup MPIN
// @Description Setup MPIN for a user
// @Tags mpin
// @Accept json
// @Produce json
// @Param request body service.MPINSetupRequest true "MPIN setup request"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 409 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/setup [post]
func (h *MPINHandler) SetupMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINSetupRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    // Sanitize inputs
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
// @Summary Verify MPIN
// @Description Verify user's MPIN
// @Tags mpin
// @Accept json
// @Produce json
// @Param request body service.MPINVerifyRequest true "MPIN verify request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 423 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/verify [post]
func (h *MPINHandler) VerifyMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINVerifyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    // Sanitize inputs
    req.MPIN = util.SanitizeInput(req.MPIN)
    req.DeviceID = util.SanitizeInput(req.DeviceID)
    
    result, err := h.mpinService.VerifyMPIN(ctx, &req)
    if err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "MPIN verification failed")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(result, "MPIN verified successfully"))
    h.logger.Info("MPIN verified via HTTP",
        util.String("user_id", req.UserID.String()),
        util.Bool("verified", result.Verified),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "VerifyMPIN"),
    )
}

// ChangeMPIN handles MPIN change
// @Summary Change MPIN
// @Description Change user's existing MPIN
// @Tags mpin
// @Accept json
// @Produce json
// @Param request body service.MPINChangeRequest true "MPIN change request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/change [post]
func (h *MPINHandler) ChangeMPIN(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.MPINChangeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    // Sanitize inputs
    req.CurrentMPIN = util.SanitizeInput(req.CurrentMPIN)
    req.NewMPIN = util.SanitizeInput(req.NewMPIN)
    
    if err := h.mpinService.ChangeMPIN(ctx, &req); err != nil {
        statusCode := h.getStatusCode(err)
        h.respondWithError(w, statusCode, err, "Failed to change MPIN")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN changed successfully"))
    h.logger.Info("MPIN changed via HTTP",
        util.String("user_id", req.UserID.String()),
        util.Duration("duration", time.Since(startTime)),
        util.String("method", "ChangeMPIN"),
    )
}

// ResetMPIN handles MPIN reset (admin operation)
// @Summary Reset MPIN
// @Description Reset user's MPIN (admin operation)
// @Tags mpin
// @Accept json
// @Produce json
// @Param request body service.MPINResetRequest true "MPIN reset request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/reset [post]
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
// @Summary Unlock MPIN
// @Description Unlock a locked MPIN
// @Tags mpin
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/{userID}/unlock [post]
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
// @Summary Get MPIN status
// @Description Get MPIN status for a user
// @Tags mpin
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/{userID}/status [get]
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
// @Summary Update device binding
// @Description Update MPIN device binding
// @Tags mpin
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body map[string]string true "Device binding request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/{userID}/device [patch]
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
// @Summary Get locked MPINs
// @Description Get list of locked MPINs with pagination
// @Tags mpin
// @Produce json
// @Param limit query int false "Page size (default: 100, max: 1000)"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/locked [get]
func (h *MPINHandler) GetLockedMPINs(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    limitStr := r.URL.Query().Get("limit")
    limit := 100 // default
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
// @Summary Cleanup expired locks
// @Description Cleanup expired MPIN locks
// @Tags mpin
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/cleanup [post]
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
// @Summary Get MPIN statistics
// @Description Get MPIN service statistics and metrics
// @Tags mpin
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/stats [get]
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
// @Summary Get MPINs by device
// @Description Get all MPINs associated with a device
// @Tags mpin
// @Produce json
// @Param deviceID path string true "Device ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /mpin/device/{deviceID} [get]
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
// @Summary Health check
// @Description Check if the MPIN service is healthy
// @Tags mpin
// @Produce json
// @Success 200 {object} Response
// @Router /mpin/health [get]
func (h *MPINHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    if err := h.mpinService.HealthCheck(ctx); err != nil {
        h.respondWithError(w, http.StatusServiceUnavailable, err, "MPIN service unhealthy")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "MPIN service is healthy"))
}

// Helper Methods

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
