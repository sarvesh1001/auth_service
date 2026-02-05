package handler

import (
	"auth-service/internal/hr/service"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceOMHandler struct {
	omService service.AttendanceOMService
	logger    *zap.Logger
}

func NewAttendanceOMHandler(
	omService service.AttendanceOMService,
	logger *zap.Logger,
) *AttendanceOMHandler {
	return &AttendanceOMHandler{
		omService: omService,
		logger:    logger,
	}
}

func (h *AttendanceOMHandler) CanMarkAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	targetUserID, err := uuid.Parse(chi.URLParam(r, "targetUserID"))
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid target user id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	allowed, reason := h.omService.CanMarkAttendance(
		ctx,
		companyID,
		actorID,
		targetUserID,
	)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": allowed,
		"data": map[string]interface{}{
			"allowed": allowed,
			"reason":  reason,
		},
	})
}

func (h *AttendanceOMHandler) CanCorrectAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	targetUserID, err := uuid.Parse(chi.URLParam(r, "targetUserID"))
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid target user id")
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	allowed, reason := h.omService.CanCorrectAttendance(
		ctx,
		companyID,
		actorID,
		targetUserID,
	)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": allowed,
		"data": map[string]interface{}{
			"allowed": allowed,
			"reason":  reason,
		},
	})
}

func (h *AttendanceOMHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
	return getUserIDFromContext(ctx)
}

func (h *AttendanceOMHandler) respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *AttendanceOMHandler) respondError(w http.ResponseWriter, status int, msg string) {
	h.respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}
