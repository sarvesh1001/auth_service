package handler

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	attendancemodels "auth-service/internal/attendance/models"
)

// assertPathCompany verifies that the company ID in the URL path matches the
// caller's company from context. On mismatch it writes 403 and returns false.
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

// trustedProxyNets is the set of peer networks from which X-Forwarded-For
// and X-Real-IP are honored. Populate at startup via SetTrustedProxies.
var trustedProxyNets []*net.IPNet

// SetTrustedProxies configures which peers are allowed to forward client-IP
// headers. Call once at startup from config. Passing nil disables XFF trust.
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

// clientIP returns the caller's IP, honoring XFF only when the immediate
// peer is a configured trusted proxy. Always returns a bare IP (no port).
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

// isTrustedDevice reports whether the current request comes from a trusted
// device. Reads either the boolean "is_trusted_device" context value or the
// full DeviceAuthContext.
func isTrustedDevice(ctx context.Context) bool {
	if v, ok := ctx.Value("is_trusted_device").(bool); ok {
		return v
	}
	if auth, ok := ctx.Value("device_auth_context").(*attendancemodels.DeviceAuthContext); ok && auth != nil {
		return auth.IsTrusted
	}
	return false
}
