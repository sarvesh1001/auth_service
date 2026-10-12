package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	attendancemodels "auth-service/internal/attendance/models"
	"auth-service/internal/locationctx"
)

// =============================================================================
// Location resolution — target location for a write
// =============================================================================
//
// resolveTargetLocation is the single source of truth for "which location_id
// should this create write to?".
//
// Middleware guarantees the following at this point:
//
//	ScopeAll      → caller sent "ALL", path is allow-listed for writes
//	ScopeLocation → caller sent a concrete UUID they have MANAGE on
//
// Rules:
//
//	ScopeAll      → body wins; nil means "company-wide"
//	ScopeLocation → body must be nil (falls back to active) or equal to the
//	                active location; anything else is a 403.
//
// This deliberately does NOT re-derive the caller's location set. Middleware
// already did that. Duplicating the logic here would create two answers.
//
// Error vars are exported so handlers and tests can assert on them.
var (
	ErrLocationRequired     = errors.New("location_id is required — you do not have company-wide access")
	ErrLocationOutsideScope = errors.New("location_id is outside your access scope")
	ErrLocationContext      = errors.New("location context missing from request")
)

func resolveTargetLocation(
	ctx context.Context,
	bodyLocationID *uuid.UUID,
) (*uuid.UUID, error) {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLocationContext, err)
	}

	switch locCtx.Mode {
	case locationctx.ScopeAll:
		// Company-wide caller: body decides. nil → company-wide row.
		return bodyLocationID, nil

	case locationctx.ScopeLocation:
		if locCtx.LocationID == nil {
			return nil, ErrLocationRequired
		}
		if bodyLocationID != nil && *bodyLocationID != *locCtx.LocationID {
			return nil, ErrLocationOutsideScope
		}
		return locCtx.LocationID, nil

	default:
		// Unknown mode — fail closed.
		return nil, ErrLocationContext
	}
}

// assertCanTouchLocation is the guard for update/delete/action operations
// where the target already exists and carries its own LocationID.
//
// Rules:
//
//	ScopeAll                 → allowed
//	ScopeLocation, row nil   → denied (company-wide rows are owner-only)
//	ScopeLocation, row match → allowed
//	ScopeLocation, row diff  → denied
func assertCanTouchLocation(
	ctx context.Context,
	rowLocationID *uuid.UUID,
) error {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLocationContext, err)
	}

	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}

	if locCtx.LocationID == nil {
		return ErrLocationRequired
	}
	if rowLocationID == nil {
		return ErrLocationOutsideScope
	}
	if *rowLocationID != *locCtx.LocationID {
		return ErrLocationOutsideScope
	}
	return nil
}

// writeLocationResolutionError maps location errors to HTTP responses.
// Handlers should call this once, in the error branch, instead of repeating
// the switch.
func writeLocationResolutionError(
	w http.ResponseWriter,
	logger *zap.Logger,
	err error,
) {
	switch {
	case errors.Is(err, ErrLocationRequired):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrLocationOutsideScope):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrLocationContext):
		writeError(w, http.StatusUnauthorized, "location context missing")
	default:
		if logger != nil {
			logger.Error("unexpected location resolution error", zap.Error(err))
		}
		writeError(w, http.StatusInternalServerError, "location resolution failed")
	}
}

// writeError is a low-level helper used by helper-internal error paths.
// Handlers with a logger should prefer their own respondWithError so the
// logger sees the event.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   message,
	})
	_, _ = w.Write(body)
}

// =============================================================================
// Company scope enforcement
// =============================================================================

func assertPathCompany(
	w http.ResponseWriter,
	ctxCompany uuid.UUID,
	pathCompany uuid.UUID,
	logger *zap.Logger,
) bool {
	if ctxCompany == pathCompany {
		return true
	}
	if logger != nil {
		logger.Warn("company mismatch between context and URL path",
			zap.String("ctx_company", ctxCompany.String()),
			zap.String("path_company", pathCompany.String()),
		)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"success":false,"error":"company mismatch"}`))
	return false
}

// =============================================================================
// Client IP resolution behind trusted proxies
// =============================================================================

var trustedProxyNets []*net.IPNet

func SetTrustedProxies(nets []*net.IPNet) {
	trustedProxyNets = nets
}

func isTrustedProxy(ip net.IP) bool {
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	peerIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peerIP); err == nil {
		peerIP = host
	}
	peer := net.ParseIP(peerIP)
	if peer != nil && isTrustedProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				xff = xff[:idx]
			}
			if xff = strings.TrimSpace(xff); xff != "" {
				return xff
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
	}
	return peerIP
}

// =============================================================================
// Device trust helper
// =============================================================================

func isTrustedDevice(ctx context.Context) bool {
	if v, ok := ctx.Value("is_trusted_device").(bool); ok {
		return v
	}
	if auth, ok := ctx.Value("device_auth_context").(*attendancemodels.DeviceAuthContext); ok && auth != nil {
		return auth.IsTrusted
	}
	return false
}
