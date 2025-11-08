package util

import( "html"
"net/http"
"strings")


// SanitizeInput escapes HTML/script-like characters
func SanitizeInput(s string) string {
	s = strings.TrimSpace(s)
	return html.EscapeString(s)
}

// =========================
// 🕵️ Utility: Suspicious Pattern Detector
// =========================
func ContainsSuspicious(s string) bool {
	badChars := []string{"<", ">", "$", "{", "}", "script", "onerror", "onload"}
	for _, c := range badChars {
		if strings.Contains(strings.ToLower(s), c) {
			return true
		}
	}
	return false
}

// GetClientIP extracts client IP from request
func GetClientIP(r *http.Request) string {
    // Check X-Forwarded-For header first
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        ips := strings.Split(xff, ",")
        if len(ips) > 0 {
            return strings.TrimSpace(ips[0])
        }
    }

    // Check X-Real-IP header
    if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
        return xrip
    }

    // Fall back to RemoteAddr
    ip := r.RemoteAddr
    if colon := strings.LastIndex(ip, ":"); colon != -1 {
        ip = ip[:colon]
    }
    return ip
}
