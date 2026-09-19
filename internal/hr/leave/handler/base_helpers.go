package handler

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// getClientIP extracts the real client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For (most common proxy header)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	// Fallback to X-Real-IP
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

// combine both injections into one helper
func injectCommonContext(ctx context.Context, r *http.Request) context.Context {
	ctx = injectIdempotencyKey(ctx, r)
	ctx = injectClientIP(ctx, r)
	return ctx
}
