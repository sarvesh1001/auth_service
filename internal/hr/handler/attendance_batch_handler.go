package handler

import (
	"auth-service/internal/hr/models/attendance" // ✅ ADD THIS
	"encoding/json"
	"net/http"

	"auth-service/internal/hr/service"
	"auth-service/internal/util"

	"go.uber.org/zap"
)

// ============================================
// REQUEST PAYLOAD
// ============================================

type AttendanceBatchPayload struct {
	BatchRef string                      `json:"batch_ref"`
	Events   []service.OfflinePunchEvent `json:"events"`
}

// ============================================
// HANDLER
// ============================================

type AttendanceBatchHandler struct {
	batchIngestService service.AttendanceBatchIngestService
	logger             *zap.Logger
}

func NewAttendanceBatchHandler(
	batchIngestService service.AttendanceBatchIngestService,
	logger *zap.Logger,
) *AttendanceBatchHandler {
	return &AttendanceBatchHandler{
		batchIngestService: batchIngestService,
		logger:             logger,
	}
}

// ============================================
// ENDPOINT (DEVICE-ONLY, AUTH IN MIDDLEWARE)
// ============================================

func (h *AttendanceBatchHandler) BatchPunch(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// ------------------------------------------------------------------
	// TRUSTED CONTEXT (MUST be injected by DeviceAuthMiddleware)
	// ------------------------------------------------------------------
	authContext, ok := ctx.Value("device_auth_context").(*attendance.DeviceAuthContext)
	if !ok || authContext == nil {
		// Programming / wiring error — NOT a runtime auth failure
		panic("device_auth_context missing: DeviceAuthMiddleware misconfigured")
	}

	// ------------------------------------------------------------------
	// PARSE PAYLOAD
	// ------------------------------------------------------------------
	var payload AttendanceBatchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ------------------------------------------------------------------
	// VALIDATION
	// ------------------------------------------------------------------
	if payload.BatchRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_ref is required")
		return
	}

	if len(payload.Events) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "events cannot be empty")
		return
	}

	// ------------------------------------------------------------------
	// BUILD SERVICE REQUEST
	// ------------------------------------------------------------------
	req := &service.AttendanceBatchIngestRequest{
		CompanyID:  authContext.CompanyID,
		DeviceID:   authContext.DeviceID,
		SourceType: authContext.SourceType,
		BatchRef:   payload.BatchRef,
		Events:     payload.Events,
	}

	// ------------------------------------------------------------------
	// PROCESS (ASYNC / FIRE-AND-FORGET)
	// ------------------------------------------------------------------
	if err := h.batchIngestService.IngestBatch(ctx, req); err != nil {
		h.logger.Warn(
			"Attendance batch ingest failed",
			zap.String("batch_ref", payload.BatchRef),
			zap.String("device_id", authContext.DeviceID),
			zap.Error(err),
		)

		h.respondWithError(
			w,
			http.StatusInternalServerError,
			"failed to process batch",
		)
		return
	}

	// ------------------------------------------------------------------
	// ACCEPTED
	// ------------------------------------------------------------------
	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success":   true,
		"batch_ref": payload.BatchRef,
		"message":   "batch processing started",
	})
}

// ============================================
// RESPONSE HELPERS
// ============================================

func (h *AttendanceBatchHandler) respondWithJSON(
	w http.ResponseWriter,
	statusCode int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error(
			"failed to encode response",
			util.ErrorField(err),
		)
	}
}

func (h *AttendanceBatchHandler) respondWithError(
	w http.ResponseWriter,
	statusCode int,
	message string,
) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
