package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/batch"
)

type BatchPayload struct {
	BatchRef string                    `json:"batch_ref"`
	Events   []batch.OfflinePunchEvent `json:"events"`
}

type BatchHandler struct {
	batchIngestService batch.BatchIngestService
	logger             *zap.Logger
}

func NewBatchHandler(
	batchIngestService batch.BatchIngestService,
	logger *zap.Logger,
) *BatchHandler {
	return &BatchHandler{
		batchIngestService: batchIngestService,
		logger:             logger,
	}
}

// POST /attendance/batches
func (h *BatchHandler) BatchPunch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authContext, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext)
	if !ok || authContext == nil {
		panic("device_auth_context missing: DeviceAuthMiddleware misconfigured")
	}

	var payload BatchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if payload.BatchRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_ref is required")
		return
	}
	if len(payload.Events) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "events cannot be empty")
		return
	}

	req := &batch.BatchIngestRequest{
		CompanyID:  authContext.CompanyID,
		DeviceID:   authContext.DeviceID,
		SourceType: authContext.SourceType,
		BatchRef:   payload.BatchRef,
		Events:     payload.Events,
	}

	if err := h.batchIngestService.IngestBatch(ctx, req); err != nil {
		h.logger.Warn("Attendance batch ingest failed",
			zap.String("batch_ref", payload.BatchRef),
			zap.String("device_id", authContext.DeviceID),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to process batch")
		return
	}

	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success":   true,
		"batch_ref": payload.BatchRef,
		"message":   "batch processing started",
	})
}

// GET /attendance/batches/{batch_ref}
func (h *BatchHandler) GetBatchStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authContext, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext)
	if !ok || authContext == nil {
		panic("device_auth_context missing")
	}

	batchRef := chi.URLParam(r, "batch_ref")
	if batchRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_ref required")
		return
	}

	status, err := h.batchIngestService.GetStatus(ctx, authContext.CompanyID, authContext.DeviceID, batchRef)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "batch not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"batch_ref":      status.BatchRef,
		"status":         status.Status,
		"total_events":   status.TotalEvents,
		"received_at":    status.ReceivedAt,
		"processed_at":   status.ProcessedAt,
		"failure_reason": status.FailureReason,
	})
}

// GET /attendance/batches/{batch_ref}/failures
func (h *BatchHandler) GetBatchFailures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authContext, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext)
	if !ok || authContext == nil {
		panic("device_auth_context missing")
	}

	batchRef := chi.URLParam(r, "batch_ref")
	if batchRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_ref required")
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	failures, err := h.batchIngestService.GetFailures(
		ctx,
		authContext.CompanyID,
		authContext.DeviceID,
		batchRef,
		limit,
		offset,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch failures")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"batch_ref": batchRef,
		"count":     len(failures),
		"failures":  failures,
	})
}

func (h *BatchHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
	}
}

func (h *BatchHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
