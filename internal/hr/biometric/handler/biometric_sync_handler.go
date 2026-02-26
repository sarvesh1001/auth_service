package handler

import (
	"encoding/json"

	"net/http"
	"time"

	"auth-service/internal/hr/biometric/models"
	"auth-service/internal/hr/biometric/service"
	"auth-service/internal/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

// ---------------------------------------------------------------------
// SyncEmbeddings – main entry point for devices
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) SyncEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Ensure company is in context (enforced by auth middleware)
	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// 2. Actor info (optional, for audit; device may not have a user session)
	//    If your devices authenticate as a service account, you can get that ID.
	//    Here we just log if present.
	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID != uuid.Nil {
		h.logger.Debug("Device sync requested by user", zap.String("actor_id", actorID.String()))
	}

	// 3. Parse request
	var input models.SyncEmbeddingsInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 4. Enforce that the company in the request matches the authenticated company
	if input.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "company_id mismatch")
		return
	}

	// 5. Call service
	resp, err := h.syncService.SyncEmbeddings(ctx, &input)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// FullSync – (optional admin endpoint) force a full sync for a device
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) FullSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	modelVersion := r.URL.Query().Get("model_version")
	if modelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version query parameter is required")
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
// IncrementalSync – (optional admin endpoint) get changes since a time
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) IncrementalSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	modelVersion := r.URL.Query().Get("model_version")
	if modelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version query parameter is required")
		return
	}

	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "since query parameter is required (RFC3339)")
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
// ForceDeviceResync – reset a device’s sync state (forces full sync next)
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) ForceDeviceResync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
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
// Health check (optional)
// ---------------------------------------------------------------------
func (h *BiometricSyncHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	// If you have a repository check, call it; otherwise simple OK.
	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "biometric-sync",
	})
}

// ---------------------------------------------------------------------
// Response helpers (same as in enrollment handler, could be shared)
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
