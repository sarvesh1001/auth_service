package handler

import (
	"auth-service/internal/contextkeys"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// DeviceHandler handles device-related HTTP requests.
type DeviceHandler struct {
	deviceService *service.DeviceService
}

// NewDeviceHandler creates a new DeviceHandler.
func NewDeviceHandler(
	deviceService *service.DeviceService,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
	}
}

// ---------- Context injection ----------

func (h *DeviceHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *DeviceHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		// Use the shared context key type
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *DeviceHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// getClientIP extracts client IP.
func (h *DeviceHandler) getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RegisterRoutes registers all device routes.
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

// BindDevice binds a device to a user.
// @Summary Bind device
// @Description Associates a device ID with a user.
// @Tags devices
// @Accept json
// @Produce json
// @Param body body service.BindDeviceRequest true "Bind request"
// @Success 200 {object} map[string]interface{} "Device bound"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Binding failed"
// @Router /api/v1/devices/bind [post]
func (h *DeviceHandler) BindDevice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req service.BindDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.IPAddress = h.getClientIP(r)
	req.UserAgent = r.UserAgent()

	response, err := h.deviceService.BindDevice(ctx, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Device bound successfully"))
}

// ValidateDevice validates a device.
// @Summary Validate device
// @Description Checks if a device is trusted and valid.
// @Tags devices
// @Accept json
// @Produce json
// @Param body body service.ValidateDeviceRequest true "Validation request"
// @Success 200 {object} map[string]interface{} "Validation result"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Validation failed"
// @Router /api/v1/devices/validate [post]
func (h *DeviceHandler) ValidateDevice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req service.ValidateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}
	req.IPAddress = h.getClientIP(r)

	response, err := h.deviceService.ValidateDevice(ctx, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "Device validation completed"))
}

// GetActiveDevice retrieves the active device for a user.
// @Summary Get active device
// @Tags devices
// @Produce json
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Active device"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 404 {object} map[string]interface{} "No active device"
// @Router /api/v1/devices/{userID} [get]
func (h *DeviceHandler) GetActiveDevice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}

	device, err := h.deviceService.GetActiveDevice(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	if device == nil {
		h.respondWithError(w, http.StatusNotFound, customErrors.ErrNotFound, "No active device found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(device, "Active device retrieved"))
}

// UnbindDevice unbinds a device from a user.
// @Summary Unbind device
// @Tags devices
// @Param userID path string true "User UUID"
// @Success 200 {object} map[string]interface{} "Device unbound"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 500 {object} map[string]interface{} "Unbind failed"
// @Router /api/v1/devices/{userID} [delete]
func (h *DeviceHandler) UnbindDevice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID")
		return
	}
	ipAddress := h.getClientIP(r)

	if err := h.deviceService.UnbindDevice(ctx, userID, ipAddress); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Device unbound successfully"))
}

// GetDeviceHistory retrieves device binding history.
// @Summary Get device history
// @Tags devices
// @Produce json
// @Param userID path string true "User UUID"
// @Param limit query int false "Limit" default(100)
// @Success 200 {object} map[string]interface{} "History list"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Router /api/v1/devices/{userID}/history [get]
func (h *DeviceHandler) GetDeviceHistory(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

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
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(history, "Device history retrieved"))
}

// GetUsersByDevice finds users by device ID.
// @Summary Get users by device
// @Tags devices
// @Produce json
// @Param device_id query string true "Device ID"
// @Success 200 {object} map[string]interface{} "List of users"
// @Failure 400 {object} map[string]interface{} "Missing device_id"
// @Router /api/v1/devices/search [get]
func (h *DeviceHandler) GetUsersByDevice(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "device_id query parameter required")
		return
	}

	users, err := h.deviceService.GetUsersByDevice(ctx, deviceID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(users, "Users retrieved by device"))
}

// CleanupOrphanedDevices triggers cleanup of orphaned devices.
// @Summary Cleanup orphaned devices
// @Tags devices
// @Produce json
// @Param days query int false "Age in days" default(90)
// @Success 200 {object} map[string]interface{} "Cleanup result"
// @Failure 500 {object} map[string]interface{} "Cleanup failed"
// @Router /api/v1/devices/cleanup [post]
func (h *DeviceHandler) CleanupOrphanedDevices(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	daysStr := r.URL.Query().Get("days")
	days := 90
	if daysStr != "" {
		if parsedDays, err := strconv.Atoi(daysStr); err == nil && parsedDays > 0 {
			days = parsedDays
		}
	}

	count, err := h.deviceService.CleanupOrphanedDevices(ctx, time.Duration(days)*24*time.Hour)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"cleaned_count": count,
		"days":          days,
	}, "Orphaned devices cleaned up"))
}

// HealthCheck checks device service health.
// @Summary Device service health
// @Tags devices
// @Produce json
// @Success 200 {object} map[string]interface{} "Service healthy"
// @Failure 503 {object} map[string]interface{} "Service unhealthy"
// @Router /api/v1/devices/health [get]
func (h *DeviceHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)
	if err := h.deviceService.HealthCheck(ctx); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "device",
	}, "Service is healthy"))
}

// GetStats retrieves service statistics.
// @Summary Get device service stats
// @Tags devices
// @Produce json
// @Success 200 {object} map[string]interface{} "Statistics"
// @Failure 500 {object} map[string]interface{} "Failed to get stats"
// @Router /api/v1/devices/stats [get]
func (h *DeviceHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)
	stats, err := h.deviceService.GetServiceStats(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Stats retrieved"))
}

// ---------- Error mapping ----------
func (h *DeviceHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Response helpers ----------
func (h *DeviceHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *DeviceHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}
