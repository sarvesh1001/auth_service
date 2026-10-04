package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/batch"
)

type BatchFailureHandler struct {
	service batch.BatchFailureService
	logger  *zap.Logger
}

func NewBatchFailureHandler(
	service batch.BatchFailureService,
	logger *zap.Logger,
) *BatchFailureHandler {
	return &BatchFailureHandler{
		service: service,
		logger:  logger,
	}
}

// GET /attendance-device/batch/{batchRef}/failures
//
// Company scope is resolved from the request context:
//   - device sessions → device_auth_context.CompanyID
//   - admin sessions  → company_id context value
//
// Any other caller is rejected with 401.
func (h *BatchFailureHandler) GetFailures(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	var companyID uuid.UUID
	if authCtx, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext); ok && authCtx != nil {
		companyID = authCtx.CompanyID
	} else if cid, err := getCompanyIDFromContext(ctx); err == nil {
		companyID = cid
	}
	if companyID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	batchRef := chi.URLParam(r, "batchRef")
	if batchRef == "" {
		h.respondWithError(w, http.StatusBadRequest, "batch_ref is required")
		return
	}

	failures, err := h.service.GetFailures(ctx, companyID, batchRef)
	if err != nil {
		h.logger.Error(
			"failed to fetch attendance batch failures",
			zap.String("batch_ref", batchRef),
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch failures")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"batch_ref": batchRef,
		"count":     len(failures),
		"failures":  failures,
	})
}

func (h *BatchFailureHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
	}
}

func (h *BatchFailureHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}