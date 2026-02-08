package handler

import (
	"auth-service/internal/hr/service"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================================
// HANDLER
// =====================================================

type AttendanceSourceAdminHandler struct {
	sourceService service.AttendanceSourceAdminService
	logger        *zap.Logger
}

func NewAttendanceSourceAdminHandler(
	sourceService service.AttendanceSourceAdminService,
	logger *zap.Logger,
) *AttendanceSourceAdminHandler {
	return &AttendanceSourceAdminHandler{
		sourceService: sourceService,
		logger:        logger,
	}
}

// =====================================================
// REQUEST / RESPONSE DTOs
// =====================================================

type CreateAttendanceSourceRequest struct {
	SourceType string `json:"source_type"`
	Name       string `json:"name,omitempty"`
}

type UpdateAttendanceSourceStatusRequest struct {
	IsActive bool `json:"is_active"`
}

// =====================================================
// LIST SOURCES
// GET /admin/companies/{companyID}/attendance/sources
// =====================================================

func (h *AttendanceSourceAdminHandler) ListSources(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	activeOnly := r.URL.Query().Get("active_only") == "true"

	sources, err := h.sourceService.GetSourcesByCompany(
		ctx,
		companyID,
		activeOnly,
	)
	if err != nil {
		h.logger.Error("failed to list attendance sources", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sources,
	})
}

// =====================================================
// CREATE SOURCE (EXPLICIT ADMIN)
// POST /admin/companies/{companyID}/attendance/sources
// =====================================================

func (h *AttendanceSourceAdminHandler) CreateSource(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
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

	source, err := h.sourceService.CreateSource(
		ctx,
		companyID,
		req.SourceType,
		req.Name,
		&actorID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    source,
	})
}

// =====================================================
// ENABLE / DISABLE SOURCE
// PUT /admin/companies/{companyID}/attendance/sources/{sourceType}
// =====================================================

func (h *AttendanceSourceAdminHandler) UpdateSourceStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
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

	if err := h.sourceService.UpdateSourceStatus(
		ctx,
		companyID,
		sourceType,
		req.IsActive,
		&actorID,
	); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "attendance source updated",
	})
}

// =====================================================
// HELPERS
// =====================================================

func (h *AttendanceSourceAdminHandler) getAdminActor(
	ctx context.Context,
) (uuid.UUID, error) {

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

func (h *AttendanceSourceAdminHandler) respondWithJSON(
	w http.ResponseWriter,
	status int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceSourceAdminHandler) respondWithError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
