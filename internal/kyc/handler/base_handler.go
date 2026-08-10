package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	kycErrors "auth-service/internal/kyc/errors"
)

type BaseHandler struct {
	logger *zap.Logger
}

// getUserIDFromContext extracts the user UUID from the request context.
func (h *BaseHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil, kycErrors.ErrUnauthorized
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, kycErrors.ErrUnauthorized
	}
}

// hasPermission is a placeholder – implement your real permission check.
func (h *BaseHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, perm string) bool {
	// TODO: call your auth/permission service
	return true
}

// respondWithJSON writes a JSON response with the given status code.
func (h *BaseHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError writes a standard error JSON response.
func (h *BaseHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// mapServiceError translates service-layer errors to HTTP status codes and messages.
func (h *BaseHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, kycErrors.ErrNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, kycErrors.ErrInvalidInput),
		errors.Is(err, kycErrors.ErrInvalidStatus),
		errors.Is(err, kycErrors.ErrInvalidDocumentType):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, kycErrors.ErrDuplicate):
		return http.StatusConflict, "duplicate record"
	case errors.Is(err, kycErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, kycErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, kycErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	case errors.Is(err, kycErrors.ErrDocumentNotFound):
		return http.StatusNotFound, "document not found"
	case errors.Is(err, kycErrors.ErrDocumentExpired):
		return http.StatusBadRequest, "document expired"
	case errors.Is(err, kycErrors.ErrDocumentAlreadyVerified):
		return http.StatusConflict, "document already verified"
	case errors.Is(err, kycErrors.ErrMissingRequiredDoc):
		return http.StatusBadRequest, "missing required document"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// parseUUIDParam extracts a UUID from a chi URL parameter.
func (h *BaseHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, kycErrors.ErrInvalidInput
	}
	return uuid.Parse(idStr)
}

// parsePagination extracts limit and offset from query parameters.
// Default limit = 20, max = 100, offset = 0.
func (h *BaseHandler) parsePagination(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return
}

// parseSort extracts sort field and direction from query parameters.
func (h *BaseHandler) parseSort(r *http.Request) (field, direction string) {
	field = r.URL.Query().Get("sort_by")
	if field == "" {
		field = "created_at"
	}
	direction = r.URL.Query().Get("sort_dir")
	if direction == "" {
		direction = "DESC"
	}
	if direction != "ASC" && direction != "DESC" {
		direction = "DESC"
	}
	return
}

// parseTimeRange extracts optional from/to time.Time from query parameters.
func (h *BaseHandler) parseTimeRange(r *http.Request) (from, to *time.Time) {
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = &t
		}
	}
	return
}

// getIdempotencyKey extracts the Idempotency-Key header.
func (h *BaseHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// getCompanyIDFromHeader extracts the X-Company-ID header (optional for KYC).
func (h *BaseHandler) getCompanyIDFromHeader(r *http.Request) (uuid.UUID, error) {
	header := r.Header.Get("X-Company-ID")
	if header == "" {
		return uuid.Nil, nil // not required for KYC
	}
	return uuid.Parse(header)
}
