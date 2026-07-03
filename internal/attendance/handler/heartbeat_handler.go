package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/device"
)

// DeviceHeartbeatHandler handles device heartbeat requests.
type DeviceHeartbeatHandler struct {
	heartbeatService device.HeartbeatService
	logger           *zap.Logger
}

// NewDeviceHeartbeatHandler creates a new handler.
func NewDeviceHeartbeatHandler(
	heartbeatService device.HeartbeatService,
	logger *zap.Logger,
) *DeviceHeartbeatHandler {
	return &DeviceHeartbeatHandler{
		heartbeatService: heartbeatService,
		logger:           logger,
	}
}

// DeviceHeartbeatPayload is the request payload.
type DeviceHeartbeatPayload struct {
	DeviceTime      *time.Time `json:"device_time"`
	FirmwareVersion *string    `json:"firmware_version"`
	IPAddress       *string    `json:"ip_address"`
}

// Heartbeat processes a device heartbeat.
func (h *DeviceHeartbeatHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce device session
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType != "device" {
		h.respondWithError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	// Extract context
	companyID, ok1 := ctx.Value("company_id").(uuid.UUID)
	deviceID, ok2 := ctx.Value("device_id").(string)
	sourceType, ok3 := ctx.Value("source_type").(string)
	if !ok1 || !ok2 || !ok3 {
		h.logger.Error("device context incomplete",
			zap.Any("company_id", ctx.Value("company_id")),
			zap.Any("device_id", ctx.Value("device_id")),
			zap.Any("source_type", ctx.Value("source_type")),
		)
		h.respondWithError(w, http.StatusUnauthorized, "device context missing")
		return
	}

	// Parse payload
	var payload DeviceHeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build service request
	req := &device.HeartbeatRequest{
		CompanyID:       companyID,
		DeviceID:        deviceID,
		SourceType:      sourceType,
		DeviceTime:      payload.DeviceTime,
		FirmwareVersion: payload.FirmwareVersion,
		IPAddress:       payload.IPAddress,
	}

	// Process
	if err := h.heartbeatService.Heartbeat(ctx, req); err != nil {
		h.logger.Warn("Device heartbeat failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to process heartbeat")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "heartbeat received",
	})
}

func (h *DeviceHeartbeatHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *DeviceHeartbeatHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
