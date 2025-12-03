package security

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type BotDetector struct {
	suspiciousUAs    map[string]bool
	headlessBrowsers map[string]bool
	automationTools  map[string]bool
	mu               sync.RWMutex
}

func NewBotDetector() *BotDetector {
	bd := &BotDetector{
		suspiciousUAs:    make(map[string]bool),
		headlessBrowsers: make(map[string]bool),
		automationTools:  make(map[string]bool),
	}

	// Initialize known bot patterns
	bd.initializePatterns()
	return bd
}

func (bd *BotDetector) initializePatterns() {
	// Headless browsers and automation tools
	headlessPatterns := []string{
		"headless", "phantomjs", "selenium", "playwright", "puppeteer",
		"chrome-headless", "electron", "webdriver", "crawler", "spider",
		"bot", "scraper", "monitoring", "python-requests", "curl",
		"wget", "go-http-client", "java/", "http-client",
	}

	// Suspicious user agents
	suspiciousPatterns := []string{
		"",              // Empty UA
		"mozilla/4.0",   // Old Mozilla
		"libwww", "lwp", // Library UAs
	}

	// Automation tools
	automationPatterns := []string{
		"selenium", "webdriver", "puppeteer", "playwright",
		"appium", "testcafe", "cypress", "karma",
	}

	for _, pattern := range headlessPatterns {
		bd.headlessBrowsers[pattern] = true
	}

	for _, pattern := range suspiciousPatterns {
		bd.suspiciousUAs[pattern] = true
	}

	for _, pattern := range automationPatterns {
		bd.automationTools[pattern] = true
	}
}

type BotDetectionRequest struct {
	UserAgent      string
	IPAddress      string
	RequestLatency time.Duration
	HTTPHeaders    http.Header
	DeviceID       string
	PhoneNumber    string
}

type BotDetectionResult struct {
	IsBot            bool
	RiskScore        int
	DetectionReasons []string
	Confidence       string // "low", "medium", "high"
}

func (bd *BotDetector) Detect(req BotDetectionRequest) BotDetectionResult {
	result := BotDetectionResult{
		RiskScore:        0,
		DetectionReasons: []string{},
	}

	ua := strings.ToLower(req.UserAgent)

	// Check for empty User-Agent
	if req.UserAgent == "" {
		result.RiskScore += 30
		result.DetectionReasons = append(result.DetectionReasons, "empty_user_agent")
	}

	// Headless browser detection
	if bd.isHeadlessBrowser(ua) {
		result.RiskScore += 40
		result.DetectionReasons = append(result.DetectionReasons, "headless_browser")
	}

	// Automation tool detection
	if bd.isAutomationTool(ua) {
		result.RiskScore += 50
		result.DetectionReasons = append(result.DetectionReasons, "automation_tool")
	}

	// Suspicious user agent patterns
	if bd.isSuspiciousUA(ua) {
		result.RiskScore += 25
		result.DetectionReasons = append(result.DetectionReasons, "suspicious_user_agent")
	}

	// Unusually fast requests (bots respond too fast)
	if req.RequestLatency < 100*time.Millisecond {
		result.RiskScore += 20
		result.DetectionReasons = append(result.DetectionReasons, "unusually_fast_request")
	}

	// Android emulator detection
	if bd.isAndroidEmulator(ua) {
		result.RiskScore += 15
		result.DetectionReasons = append(result.DetectionReasons, "android_emulator")
	}

	// Missing common headers
	if !bd.hasCommonHeaders(req.HTTPHeaders) {
		result.RiskScore += 10
		result.DetectionReasons = append(result.DetectionReasons, "missing_common_headers")
	}

	// Determine if it's a bot and confidence level
	result.IsBot = result.RiskScore >= 40
	if result.RiskScore >= 70 {
		result.Confidence = "high"
	} else if result.RiskScore >= 40 {
		result.Confidence = "medium"
	} else {
		result.Confidence = "low"
	}

	return result
}

func (bd *BotDetector) isHeadlessBrowser(ua string) bool {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	for pattern := range bd.headlessBrowsers {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

func (bd *BotDetector) isAutomationTool(ua string) bool {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	for pattern := range bd.automationTools {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

func (bd *BotDetector) isSuspiciousUA(ua string) bool {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	for pattern := range bd.suspiciousUAs {
		if pattern == "" && ua == "" {
			return true
		}
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

func (bd *BotDetector) isAndroidEmulator(ua string) bool {
	emulatorPatterns := []string{
		"sdk_gphone", "android sdk built for", "emulator", "x86_64", "android_x86",
	}

	for _, pattern := range emulatorPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

func (bd *BotDetector) hasCommonHeaders(headers http.Header) bool {
	commonHeaders := []string{
		"accept",
		"accept-language",
		"accept-encoding",
	}

	for _, header := range commonHeaders {
		if headers.Get(header) == "" {
			return false
		}
	}
	return true
}

// Simple bot detection for quick checks
func (bd *BotDetector) QuickDetect(userAgent string, latency time.Duration) bool {
	if userAgent == "" {
		return true
	}

	ua := strings.ToLower(userAgent)

	// Quick checks for common bot patterns
	quickBotPatterns := []string{
		"headless", "selenium", "webdriver", "puppeteer", "playwright",
		"phantomjs", "bot", "crawler", "spider", "scraper",
	}

	for _, pattern := range quickBotPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	// Very fast requests
	if latency < 50*time.Millisecond {
		return true
	}

	return false
}
