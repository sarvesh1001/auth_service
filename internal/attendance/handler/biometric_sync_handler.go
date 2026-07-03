package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/service"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type BiometricSyncHandler struct {
	syncService service.BiometricSyncService
	logger      *zap.Logger
}

func NewBiometricSyncHandler(
	syncService service.BiometricSyncService,
	logger *zap.Logger,
) *BiometricSyncHandler {
	return &BiometricSyncHandler{
		syncService: syncService,
		logger:      logger,
	}
}

// getCompanyIDFromContext extracts the company UUID from the request context.

// ---------------------------------------------------------------------
// SyncEmbeddings – main device endpoint
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) SyncEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var input models.SyncEmbeddingsInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if input.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "company_id mismatch")
		return
	}

	resp, err := h.syncService.SyncEmbeddings(ctx, &input)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// FullSync – admin triggered full sync for a device
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) FullSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id required")
		return
	}

	modelVersion := r.URL.Query().Get("model_version")
	if modelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version query param required")
		return
	}

	resp, err := h.syncService.FullSync(ctx, companyID, deviceID, modelVersion)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// IncrementalSync – admin triggered incremental sync
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) IncrementalSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id required")
		return
	}

	modelVersion := r.URL.Query().Get("model_version")
	if modelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version query param required")
		return
	}

	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "since query param required (RFC3339)")
		return
	}
	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid since format, use RFC3339")
		return
	}

	resp, err := h.syncService.IncrementalSync(ctx, companyID, deviceID, modelVersion, since)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// ForceDeviceResync – reset a device's sync state
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) ForceDeviceResync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id required")
		return
	}

	err = h.syncService.ForceDeviceResync(ctx, companyID, deviceID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Device sync state reset, next request will be a full sync",
	})
}

// ---------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "biometric-sync",
	})
}

// ---------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *BiometricSyncHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
