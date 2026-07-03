package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/source"
)

// AttendanceSourceAdminHandler handles attendance source management.
type AttendanceSourceAdminHandler struct {
	sourceService source.SourceAdminService
	logger        *zap.Logger
}

// NewAttendanceSourceAdminHandler creates a new handler.
func NewAttendanceSourceAdminHandler(
	sourceService source.SourceAdminService,
	logger *zap.Logger,
) *AttendanceSourceAdminHandler {
	return &AttendanceSourceAdminHandler{
		sourceService: sourceService,
		logger:        logger,
	}
}

// ---- DTOs ----

type CreateAttendanceSourceRequest struct {
	SourceType string `json:"source_type"`
	Name       string `json:"name,omitempty"`
}

type UpdateAttendanceSourceStatusRequest struct {
	IsActive bool `json:"is_active"`
}

// ---- ListSources ----

func (h *AttendanceSourceAdminHandler) ListSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	activeOnly := r.URL.Query().Get("active_only") == "true"

	sources, err := h.sourceService.GetSourcesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.logger.Error("Failed to list attendance sources", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sources,
	})
}

// ---- CreateSource ----

func (h *AttendanceSourceAdminHandler) CreateSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req CreateAttendanceSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.SourceType = strings.TrimSpace(req.SourceType)
	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type required")
		return
	}

	source, err := h.sourceService.CreateSource(ctx, companyID, req.SourceType, req.Name, &actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    source,
	})
}

// ---- UpdateSourceStatus ----

func (h *AttendanceSourceAdminHandler) UpdateSourceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	sourceType := chi.URLParam(r, "sourceType")
	if sourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type required")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req UpdateAttendanceSourceStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.sourceService.UpdateSourceStatus(ctx, companyID, sourceType, req.IsActive, &actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "attendance source updated",
	})
}

// ---- Helpers ----

func (h *AttendanceSourceAdminHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType != "admin" {
		return uuid.Nil, errors.New("admin authentication required")
	}
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, errors.New("user_id missing from context")
	}
	return uuid.Parse(userIDStr)
}

func (h *AttendanceSourceAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceSourceAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
