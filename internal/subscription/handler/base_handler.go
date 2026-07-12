// handler/base_handler.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
)

// BaseHandler provides common HTTP handling methods for subscription handlers.
type BaseHandler struct {
	logger *zap.Logger
}

// NewBaseHandler creates a new BaseHandler.
func NewBaseHandler(logger *zap.Logger) *BaseHandler {
	return &BaseHandler{logger: logger}
}

// ---- Request parsing helpers ----

// getUserIDFromContext extracts the user ID from the request context.
// It expects the context to have a value with key "user_id".
func (h *BaseHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil, subErrors.ErrUnauthorized
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, subErrors.ErrUnauthorized
	}
}

// getCompanyIDFromHeader extracts the company ID from the X-Company-ID header.
func (h *BaseHandler) getCompanyIDFromHeader(r *http.Request) (uuid.UUID, error) {
	header := r.Header.Get("X-Company-ID")
	if header == "" {
		return uuid.Nil, fmt.Errorf("X-Company-ID header is required")
	}
	companyID, err := uuid.Parse(header)
	if err != nil || companyID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("invalid X-Company-ID header")
	}
	return companyID, nil
}

// parseUUIDParam extracts and parses a UUID from a URL path parameter.
func (h *BaseHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

// parsePagination extracts limit and offset from query parameters.
// It returns the raw parsed values without clamping negative numbers.
//   - If limit is missing or cannot be parsed, it defaults to 20.
//   - If limit is positive and > 100, it caps at 100 (to prevent abuse).
//   - If offset is missing or cannot be parsed, it defaults to 0.
//   - Negative values are returned as‑is – it is the handler's responsibility
//     to validate them and return 400 if required.
func (h *BaseHandler) parsePagination(r *http.Request) (limit, offset int) {
	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limit = 20 // default
	} else {
		if v, err := strconv.Atoi(limitStr); err == nil {
			limit = v
		} else {
			limit = 20 // fallback default if invalid
		}
	}
	// Cap positive limit to a maximum (e.g., 100)
	if limit > 100 {
		limit = 100
	}

	// Parse offset
	offsetStr := r.URL.Query().Get("offset")
	if offsetStr == "" {
		offset = 0
	} else {
		if v, err := strconv.Atoi(offsetStr); err == nil {
			offset = v
		} else {
			offset = 0 // fallback
		}
	}
	// Do NOT clamp negative offset – let handlers decide
	return
}

// getIdempotencyKey extracts the Idempotency-Key header.
func (h *BaseHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// ---- Response helpers ----

// respondWithJSON writes a JSON response with the given status code.
func (h *BaseHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError writes a standard error response.
func (h *BaseHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ---- Permission placeholder ----

// hasPermission checks if the user has a given permission.
// TODO: Replace with actual permission logic.
func (h *BaseHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, perm string) bool {
	// For now, allow all requests – implement proper authorization as needed.
	return true
}

// ---- Error mapping ----

// mapServiceError converts subscription service errors to HTTP status and message.
func (h *BaseHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, subErrors.ErrAddonNotFound):
		return http.StatusNotFound, "addon not found"
	case errors.Is(err, subErrors.ErrAddonAlreadyExists):
		return http.StatusConflict, "addon with this name already exists"
	case errors.Is(err, subErrors.ErrAddonInactive):
		return http.StatusBadRequest, "addon is inactive"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrInvalidStatusTransition):
		return http.StatusConflict, err.Error()
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "duplicate record"
	case errors.Is(err, subErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, subErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	default:
		// If it's a plain error with a message, we could return 400, but default to 500.
		return http.StatusInternalServerError, "internal server error"
	}
}
