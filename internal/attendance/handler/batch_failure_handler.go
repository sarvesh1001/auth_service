package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

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
func (h *BatchFailureHandler) GetFailures(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	batchRef := chi.URLParam(r, "batchRef")
	if batchRef == "" {
		http.Error(w, "batch_ref is required", http.StatusBadRequest)
		return
	}

	failures, err := h.service.GetFailures(ctx, batchRef)
	if err != nil {
		h.logger.Error(
			"failed to fetch attendance batch failures",
			zap.String("batch_ref", batchRef),
			zap.Error(err),
		)
		http.Error(w, "failed to fetch failures", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"batch_ref": batchRef,
		"count":     len(failures),
		"failures":  failures,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
