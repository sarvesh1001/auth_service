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

type AttendanceSourceAdminHandler struct {
	sourceService source.SourceAdminService
	logger        *zap.Logger
}

func NewAttendanceSourceAdminHandler(
	sourceService source.SourceAdminService,
	logger *zap.Logger,
) *AttendanceSourceAdminHandler {
	return &AttendanceSourceAdminHandler{
		sourceService: sourceService,
		logger:        logger,
	}
}

// canonicalSourceTypes is the whitelist used to normalize and validate
// source_type on both create and update. Keep in sync with
// service/source/canonicalSourceRules.
var canonicalSourceTypes = map[string]struct{}{
	"manual":     {},
	"mobile":     {},
	"web":        {},
	"biometric":  {},
	"kiosk":      {},
	"classroom":  {},
	"auto":       {},
	"system":     {},
	"correction": {},
}

// normalizeSourceType trims and lowercases a source type, then verifies it
// against the canonical list. Returns ("", false) if invalid.
func normalizeSourceType(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := canonicalSourceTypes[v]; !ok {
		return v, false
	}
	return v, true
}

type CreateAttendanceSourceRequest struct {
	SourceType string `json:"source_type"`
	Name       string `json:"name,omitempty"`
}

type UpdateAttendanceSourceStatusRequest struct {
	IsActive bool `json:"is_active"`
}

func (h *AttendanceSourceAdminHandler) ListSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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

func (h *AttendanceSourceAdminHandler) CreateSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
	normalized, ok := normalizeSourceType(req.SourceType)
	if !ok {
		h.respondWithError(w, http.StatusBadRequest, "invalid source_type")
		return
	}
	req.SourceType = normalized
	src, err := h.sourceService.CreateSource(ctx, companyID, req.SourceType, req.Name, &actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    src,
	})
}

// UpdateSourceStatus toggles a source's active state.
//
// FIX (Handler hygiene): previously accepted the raw `sourceType` from the
// URL with no trimming, lowercasing, or validation. `" MANUAL "` did not
// match `"manual"` punches. The path value is now normalized and validated
// against the same canonical list used by CreateSource.
func (h *AttendanceSourceAdminHandler) UpdateSourceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
		return
	}
	rawSourceType := chi.URLParam(r, "sourceType")
	normalized, ok := normalizeSourceType(rawSourceType)
	if !ok {
		h.respondWithError(w, http.StatusBadRequest, "invalid source_type")
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
	if err := h.sourceService.UpdateSourceStatus(ctx, companyID, normalized, req.IsActive, &actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "attendance source updated",
	})
}

func (h *AttendanceSourceAdminHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType != "admin" {
		return uuid.Nil, errors.New("admin authentication required")
	}
	return getUserIDFromContext(ctx)
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