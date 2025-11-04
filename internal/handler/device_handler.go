// File: internal/handler/device_handler.go
package handler

import (
    "encoding/json"
    "net"
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

// DeviceHandler handles device-related HTTP requests
type DeviceHandler struct {
    deviceService *service.DeviceService
    logger        *zap.Logger
}

// ✅ UPDATE CONSTRUCTOR: Add LogProducerService parameter
func NewDeviceHandler(
    deviceService *service.DeviceService, 
    logProducer *service.LogProducerService, // ✅ ADD THIS
    logger *zap.Logger,
) *DeviceHandler {
    
    // ✅ SET LOG PRODUCER ON SERVICE
    if logProducer != nil {
        deviceService.SetLogProducerService(logProducer)
    }
    
    return &DeviceHandler{
        deviceService: deviceService,
        logger:        logger,
    }
}

// RegisterRoutes registers all device routes
func (h *DeviceHandler) RegisterRoutes(r chi.Router) {
    r.Route("/devices", func(r chi.Router) {
        r.Post("/bind", h.BindDevice)
        r.Post("/validate", h.ValidateDevice)
        r.Get("/{userID}", h.GetActiveDevice)
        r.Delete("/{userID}", h.UnbindDevice)
        r.Get("/{userID}/history", h.GetDeviceHistory)
        r.Get("/search", h.GetUsersByDevice)
        r.Post("/cleanup", h.CleanupOrphanedDevices)
        r.Get("/health", h.HealthCheck)
        r.Get("/stats", h.GetStats)
    })
}

// getClientIP extracts the client IP address from the request
func (h *DeviceHandler) getClientIP(r *http.Request) string {
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

// BindDevice handles device binding
func (h *DeviceHandler) BindDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    startTime := time.Now()
    
    var req service.BindDeviceRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    // ✅ EXTRACT IP ADDRESS AND USER AGENT
    req.IPAddress = h.getClientIP(r)
    req.UserAgent = r.UserAgent()
    
    response, err := h.deviceService.BindDevice(ctx, req)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to bind device")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Device bound successfully"))
    
    h.logger.Info("Device bound via HTTP",
        util.String("user_id", req.UserID.String()),
        util.String("ip_address", req.IPAddress),
        util.Duration("duration", time.Since(startTime)))
}

// ValidateDevice handles device validation
func (h *DeviceHandler) ValidateDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    var req service.ValidateDeviceRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
        return
    }
    
    // ✅ EXTRACT IP ADDRESS
    req.IPAddress = h.getClientIP(r)
    
    response, err := h.deviceService.ValidateDevice(ctx, req)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to validate device")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(response, "Device validation completed"))
}

// GetActiveDevice retrieves active device
func (h *DeviceHandler) GetActiveDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }
    
    device, err := h.deviceService.GetActiveDevice(ctx, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get active device")
        return
    }
    
    if device == nil {
        h.respondWithJSON(w, http.StatusNotFound, errorResponse(nil, "No active device found"))
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(device, "Active device retrieved"))
}

// UnbindDevice handles device unbinding
func (h *DeviceHandler) UnbindDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }
    
    // ✅ EXTRACT IP ADDRESS
    ipAddress := h.getClientIP(r)
    
    if err := h.deviceService.UnbindDevice(ctx, userID, ipAddress); err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to unbind device")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Device unbound successfully"))
}

// GetDeviceHistory retrieves device history
func (h *DeviceHandler) GetDeviceHistory(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
        return
    }
    
    limitStr := r.URL.Query().Get("limit")
    limit := 100
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
            limit = parsedLimit
        }
    }
    
    history, err := h.deviceService.GetDeviceBindingHistory(ctx, userID, limit)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get device history")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(history, "Device history retrieved"))
}

// GetUsersByDevice finds users by device ID
func (h *DeviceHandler) GetUsersByDevice(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    deviceID := r.URL.Query().Get("device_id")
    if deviceID == "" {
        h.respondWithError(w, http.StatusBadRequest, nil, "device_id query parameter required")
        return
    }
    
    users, err := h.deviceService.GetUsersByDevice(ctx, deviceID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by device")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(users, "Users retrieved by device"))
}

// CleanupOrphanedDevices triggers cleanup
func (h *DeviceHandler) CleanupOrphanedDevices(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    daysStr := r.URL.Query().Get("days")
    days := 90 // Default 90 days
    if daysStr != "" {
        if parsedDays, err := strconv.Atoi(daysStr); err == nil && parsedDays > 0 {
            days = parsedDays
        }
    }
    
    count, err := h.deviceService.CleanupOrphanedDevices(ctx, time.Duration(days)*24*time.Hour)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to cleanup orphaned devices")
        return
    }
    
    result := map[string]interface{}{
        "cleaned_count": count,
        "days":          days,
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(result, "Orphaned devices cleaned up"))
}

// HealthCheck checks service health
func (h *DeviceHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    if err := h.deviceService.HealthCheck(ctx); err != nil {
        h.respondWithError(w, http.StatusServiceUnavailable, err, "Service unhealthy")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Service is healthy"))
}

// GetStats retrieves service statistics
func (h *DeviceHandler) GetStats(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    stats, err := h.deviceService.GetServiceStats(ctx)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get stats")
        return
    }
    
    h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Stats retrieved"))
}

// Helper methods (reuse from other handlers)

func (h *DeviceHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    if err := json.NewEncoder(w).Encode(data); err != nil {
        h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
    }
}

func (h *DeviceHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
    h.logger.Warn("HTTP error response",
        util.ErrorField(err),
        util.Int("status_code", statusCode),
        util.String("message", message))
    h.respondWithJSON(w, statusCode, errorResponse(err, message))
}
