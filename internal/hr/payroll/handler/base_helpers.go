package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/service"
	"auth-service/internal/locationctx"
)

// -----------------------------------------------------------------------------
// IP + idempotency injection (unchanged)
// -----------------------------------------------------------------------------

// getClientIP extracts the real client IP from the request.
func getClientIP(r *http.Request) string {
	// X-Forwarded-For (most common proxy header)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	// X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			return realIP
		}
	}
	// Cloudflare
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if parsedIP := net.ParseIP(cfIP); parsedIP != nil {
			return cfIP
		}
	}
	// Last resort: RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
			return r.RemoteAddr
		}
		return ""
	}
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return host
	}
	return ""
}

// getIdempotencyKey extracts the idempotency key from the request header.
func getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the context if present.
func injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// injectClientIP adds the client IP to the context.
func injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// injectCommonContext combines both injections.
func injectCommonContext(ctx context.Context, r *http.Request) context.Context {
	ctx = injectIdempotencyKey(ctx, r)
	ctx = injectClientIP(ctx, r)
	return ctx
}

// -----------------------------------------------------------------------------
// Location-scope helpers (new)
// -----------------------------------------------------------------------------

// mapPayrollLocationError writes the correct HTTP status for the three
// location-scope errors and returns true. Returns false otherwise, so the
// caller can continue its normal error handling.
//
// Handlers call this immediately after any service method that can produce
// these errors — writes and single-employee reads.
func mapPayrollLocationError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, service.ErrEmployeeOutsideScope):
		writeLocationError(w, http.StatusForbidden, err.Error())
		return true
	case errors.Is(err, service.ErrEmployeeHasNoLocation):
		writeLocationError(w, http.StatusBadRequest, err.Error())
		return true
	case errors.Is(err, service.ErrCompanyWideScopeRequired):
		writeLocationError(w, http.StatusForbidden, err.Error())
		return true
	}
	return false
}

// locationFilterFromCtx returns nil for admin/company-wide scope, or the
// location UUID for location-scoped requests. Handlers pass the return value
// into repository-filter structs.
//
// Missing context is treated as "no filter" — this is correct for admin
// sessions that bypass LocationValidationMiddleware.
func locationFilterFromCtx(ctx context.Context) *uuid.UUID {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil
	}
	if locCtx.Mode == locationctx.ScopeLocation {
		return locCtx.LocationID
	}
	return nil
}

// writeLocationError is the shared JSON error writer used by
// mapPayrollLocationError. Handlers keep their own respondWithError for the
// rest of their error paths; this exists so the helper doesn't need access to
// a specific handler instance.
func writeLocationError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
