package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/hr/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// REQUEST PAYLOAD
// ============================================

type DeviceHeartbeatPayload struct {
	DeviceTime      *time.Time `json:"device_time"`
	FirmwareVersion *string    `json:"firmware_version"`
	IPAddress       *string    `json:"ip_address"`
}

// ============================================
// HANDLER
// ============================================

type DeviceHeartbeatHandler struct {
	heartbeatService service.DeviceHeartbeatService
	logger           *zap.Logger
}

func NewDeviceHeartbeatHandler(
	heartbeatService service.DeviceHeartbeatService,
	logger *zap.Logger,
) *DeviceHeartbeatHandler {
	return &DeviceHeartbeatHandler{
		heartbeatService: heartbeatService,
		logger:           logger,
	}
}

// ============================================
// ENDPOINT
// ============================================

func (h *DeviceHeartbeatHandler) Heartbeat(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ─────────────────────────────
	// 1️⃣ Enforce DEVICE session
	// ─────────────────────────────
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType != "device" {
		h.respondWithError(
			w,
			http.StatusUnauthorized,
			"device authentication required",
		)
		return
	}

	// ─────────────────────────────
	// 2️⃣ Extract required context
	// ─────────────────────────────
	companyID, ok1 := ctx.Value("company_id").(uuid.UUID)
	deviceID, ok2 := ctx.Value("device_id").(string)
	sourceType, ok3 := ctx.Value("source_type").(string)

	if !ok1 || !ok2 || !ok3 {
		h.logger.Error("device context incomplete",
			zap.Any("company_id", ctx.Value("company_id")),
			zap.Any("device_id", ctx.Value("device_id")),
			zap.Any("source_type", ctx.Value("source_type")),
		)
		h.respondWithError(
			w,
			http.StatusUnauthorized,
			"device context missing",
		)
		return
	}

	// ─────────────────────────────
	// 3️⃣ Parse request payload
	// ─────────────────────────────
	var payload DeviceHeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.respondWithError(
			w,
			http.StatusBadRequest,
			"invalid request body",
		)
		return
	}

	// ─────────────────────────────
	// 4️⃣ Build service request
	// ─────────────────────────────
	req := &service.DeviceHeartbeatRequest{
		CompanyID:       companyID,
		DeviceID:        deviceID,
		SourceType:      sourceType,
		DeviceTime:      payload.DeviceTime,
		FirmwareVersion: payload.FirmwareVersion,
		IPAddress:       payload.IPAddress,
	}

	// ─────────────────────────────
	// 5️⃣ Process heartbeat
	// ─────────────────────────────
	if err := h.heartbeatService.Heartbeat(ctx, req); err != nil {
		h.logger.Warn(
			"Device heartbeat failed",
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		h.respondWithError(
			w,
			http.StatusInternalServerError,
			"failed to process heartbeat",
		)
		return
	}

	// ─────────────────────────────
	// 6️⃣ Success response
	// ─────────────────────────────
	h.respondWithJSON(
		w,
		http.StatusOK,
		map[string]interface{}{
			"success": true,
			"message": "heartbeat received",
		},
	)
}

// ============================================
// RESPONSE HELPERS
// ============================================

func (h *DeviceHeartbeatHandler) respondWithJSON(
	w http.ResponseWriter,
	statusCode int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error(
			"failed to encode response",
			zap.Error(err),
		)
	}
}

func (h *DeviceHeartbeatHandler) respondWithError(
	w http.ResponseWriter,
	statusCode int,
	message string,
) {
	h.respondWithJSON(
		w,
		statusCode,
		map[string]interface{}{
			"success": false,
			"error":   message,
		},
	)
}
