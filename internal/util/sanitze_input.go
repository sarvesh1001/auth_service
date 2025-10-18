package util

import( "html"
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