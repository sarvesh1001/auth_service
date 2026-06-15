package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
)

type BaseHandler struct {
	logger *zap.Logger
}

// getUserIDFromContext extracts the user UUID from the request context.
// Adjust the context key ("user_id") to match your auth middleware.
func (h *BaseHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil, salesErrors.ErrUnauthorized
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, salesErrors.ErrUnauthorized
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
// mapServiceError translates service-layer errors to HTTP status codes and messages.
// mapServiceError translates service-layer errors to HTTP status codes and messages.
func (h *BaseHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, salesErrors.ErrNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, salesErrors.ErrInvalidInput),
		errors.Is(err, salesErrors.ErrInvalidAmount),
		errors.Is(err, salesErrors.ErrInvalidQuantity):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrDuplicate):
		return http.StatusConflict, "duplicate record"
	case errors.Is(err, salesErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidStateTransition): // ✅ NEW: return 409 Conflict
		return http.StatusConflict, err.Error()
	case errors.Is(err, salesErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, salesErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	case errors.Is(err, salesErrors.ErrInventoryItemNotFound):
		return http.StatusBadRequest, "inventory item not found or inactive"
	case errors.Is(err, salesErrors.ErrInvalidStatus),
		errors.Is(err, salesErrors.ErrInvalidTransition):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrCustomerInactive):
		return http.StatusBadRequest, "customer is inactive"
	case errors.Is(err, salesErrors.ErrProductInactive):
		return http.StatusBadRequest, "product is inactive"
	case errors.Is(err, salesErrors.ErrPaymentOverAlloc):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrCouponExpired):
		return http.StatusBadRequest, "coupon expired"
	case errors.Is(err, salesErrors.ErrCouponInactive):
		return http.StatusBadRequest, "coupon inactive"
	case errors.Is(err, salesErrors.ErrCouponUsageLimit):
		return http.StatusBadRequest, "coupon usage limit exceeded"
	case errors.Is(err, salesErrors.ErrOverRefund):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrStackingConflict): // ✅ NEW: stacking conflict → 400 Bad Request
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrAllocationExceedsInvoice):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrOverRefund):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, salesErrors.ErrPaymentTermInactive):
		return http.StatusBadRequest, "payment term is inactive"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// parseUUIDParam extracts a UUID from a chi URL parameter.
func (h *BaseHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, salesErrors.ErrInvalidInput
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
// Returns field, direction (default field = "created_at", direction = "DESC").
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
// The parameters are expected as RFC3339 strings.
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

func (h *BaseHandler) getCompanyIDFromQuery(r *http.Request) (uuid.UUID, error) {
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company_id query parameter is required")
	}
	return uuid.Parse(companyIDStr)
}

func parseUUIDParamCreditNote(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func parseUUIDParamInvoice(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func (h *BaseHandler) parseCompanyIDFromQuery(r *http.Request) (uuid.UUID, error) {
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company_id query parameter is required")
	}
	return uuid.Parse(companyIDStr)
}

func parseUUIDParamPayment(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func parseQueryUUID(r *http.Request, key string) (uuid.UUID, error) {
	val := r.URL.Query().Get(key)
	if val == "" {
		return uuid.Nil, fmt.Errorf("missing %s query parameter", key)
	}
	return uuid.Parse(val)
}

func parseQueryTime(r *http.Request, key string) (*time.Time, error) {
	val := r.URL.Query().Get(key)
	if val == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid %s format (RFC3339)", key)
	}
	return &t, nil
}

func parseQueryDecimal(r *http.Request, key string) (*decimal.Decimal, error) {
	val := r.URL.Query().Get(key)
	if val == "" {
		return nil, nil
	}
	d, err := decimal.NewFromString(val)
	if err != nil {
		return nil, fmt.Errorf("invalid %s decimal", key)
	}
	return &d, nil
}

func parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func (h *BaseHandler) parseTimeQuery(r *http.Request, paramName string) *time.Time {
	if s := r.URL.Query().Get(paramName); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return &t
		}
	}
	return nil
}

func parseUUIDParamReturn(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

func parseDecimal(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, nil
	}
	return decimal.NewFromString(s)
}

// getCompanyIDFromHeader extracts and validates the X-Company-ID header.
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
