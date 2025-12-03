package security

import (
	"auth-service/internal/util"
	"time"
)

type RiskEngine struct {
	botDetector  *BotDetector
	ipReputation *IPReputation
}

type RiskAssessmentRequest struct {
	UserAgent      string
	IPAddress      string
	DeviceID       string
	PhoneNumber    string
	Purpose        string
	RequestLatency time.Duration
	FailedAttempts int
	DailyOTPCount  int
	IsNewDevice    bool
	IsNewIP        bool
	HTTPHeaders    map[string]string
}

type RiskAssessment struct {
	RiskScore   int      `json:"risk_score"`
	RiskLevel   string   `json:"risk_level"`
	BlockAction bool     `json:"block_action"`
	Reasons     []string `json:"reasons"`
	Confidence  string   `json:"confidence"`
}

func NewRiskEngine(botDetector *BotDetector, ipReputation *IPReputation) *RiskEngine {
	return &RiskEngine{
		botDetector:  botDetector,
		ipReputation: ipReputation,
	}
}

func (e *RiskEngine) AssessRisk(req RiskAssessmentRequest) RiskAssessment {

	// 🔥 BASIC LOGGING
	util.Info("AssessRisk called",
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.String("user_agent", req.UserAgent),
		util.String("device_id", req.DeviceID),
	)

	assessment := RiskAssessment{
		RiskScore: 0,
		Reasons:   []string{},
	}

	// ===============================================================
	// SECURITY BYPASS FOR LOGIN & ADMIN_LOGIN
	// ===============================================================
	if req.Purpose == "login" || req.Purpose == "admin_login" {

		util.Info("Login/Admin Login Risk Check Started",
			util.String("purpose", req.Purpose),
		)

		botReq := BotDetectionRequest{
			UserAgent:      req.UserAgent,
			IPAddress:      req.IPAddress,
			RequestLatency: req.RequestLatency,
			DeviceID:       req.DeviceID,
			PhoneNumber:    req.PhoneNumber,
		}

		botResult := e.botDetector.Detect(botReq)

		if botResult.IsBot {
			util.Warn("Bot detected", util.Strings("reasons", botResult.DetectionReasons))
			assessment.RiskScore += botResult.RiskScore
			assessment.Reasons = append(assessment.Reasons, botResult.DetectionReasons...)
		}

		ipInfo := e.ipReputation.CheckIP(req.IPAddress)
		if ipInfo != nil {
			util.Info("IP Reputation Triggered",
				util.Int("ip_score", ipInfo.RiskScore),
			)

			assessment.RiskScore += ipInfo.RiskScore

			if ipInfo.IsTOR {
				assessment.Reasons = append(assessment.Reasons, "tor_network")
			}
			if ipInfo.IsVPN {
				assessment.Reasons = append(assessment.Reasons, "vpn_proxy_detected")
			}
			if ipInfo.IsDataCenter {
				assessment.Reasons = append(assessment.Reasons, "datacenter_ip")
			}
		}

		if req.FailedAttempts > 5 {
			util.Warn("High failed attempts", util.Int("failed_attempts", req.FailedAttempts))
			assessment.RiskScore += 15
			assessment.Reasons = append(assessment.Reasons, "high_failed_attempts")
		}

		if req.DailyOTPCount > 10 {
			util.Warn("High daily OTP usage", util.Int("otp_count", req.DailyOTPCount))
			assessment.RiskScore += 10
			assessment.Reasons = append(assessment.Reasons, "high_daily_otp_volume")
		}

		if req.RequestLatency < 50*time.Millisecond {
			util.Warn("Request too fast", util.Duration("latency", req.RequestLatency))
			assessment.RiskScore += 20
			assessment.Reasons = append(assessment.Reasons, "too_fast_request")
		}

		assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
		assessment.BlockAction = assessment.RiskScore >= 150
		assessment.Confidence = e.calculateConfidence(assessment.RiskScore)

		util.Info("Login Risk Assessment Complete",
			util.Int("risk_score", assessment.RiskScore),
			util.String("risk_level", assessment.RiskLevel),
		)

		return assessment
	}

	// ===============================================================
	// STRICT RISK ASSESSMENT FOR FORGOT_MPIN
	// ===============================================================
	if req.Purpose == "forgot_mpin" {

		util.Info("Forgot MPIN Risk Check Started")

		botReq := BotDetectionRequest{
			UserAgent:      req.UserAgent,
			IPAddress:      req.IPAddress,
			RequestLatency: req.RequestLatency,
			DeviceID:       req.DeviceID,
			PhoneNumber:    req.PhoneNumber,
		}

		botResult := e.botDetector.Detect(botReq)
		if botResult.IsBot {
			util.Warn("Bot detected in forgot_mpin", util.Strings("reasons", botResult.DetectionReasons))
			assessment.RiskScore += botResult.RiskScore
			assessment.Reasons = append(assessment.Reasons, botResult.DetectionReasons...)
		}

		ipInfo := e.ipReputation.CheckIP(req.IPAddress)
		if ipInfo != nil {
			util.Info("IP check triggered", util.Int("ip_score", ipInfo.RiskScore))
			assessment.RiskScore += ipInfo.RiskScore
		}

		if req.FailedAttempts > 3 {
			util.Warn("Failed attempts high", util.Int("failed_attempts", req.FailedAttempts))
			assessment.RiskScore += 25
			assessment.Reasons = append(assessment.Reasons, "high_failed_attempts")
		}

		if req.DailyOTPCount > 5 {
			util.Warn("High OTP usage", util.Int("otp_count", req.DailyOTPCount))
			assessment.RiskScore += 20
			assessment.Reasons = append(assessment.Reasons, "high_daily_otp_volume")
		}

		if req.IsNewDevice {
			util.Warn("New Device Detected")
			assessment.Reasons = append(assessment.Reasons, "new_device")
			assessment.RiskScore += 20
		}

		if req.IsNewIP {
			util.Warn("New IP Detected")
			assessment.Reasons = append(assessment.Reasons, "new_ip")
			assessment.RiskScore += 15
		}

		if req.RequestLatency < 100*time.Millisecond {
			util.Warn("Fast request", util.Duration("latency", req.RequestLatency))
			assessment.RiskScore += 20
		}

		if assessment.RiskScore > 0 {
			assessment.RiskScore += 25
			assessment.Reasons = append(assessment.Reasons, "forgot_mpin_sensitive")
		}

		assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
		assessment.BlockAction = assessment.RiskScore >= 120
		assessment.Confidence = e.calculateConfidence(assessment.RiskScore)

		util.Info("Forgot MPIN Risk Complete",
			util.Int("risk_score", assessment.RiskScore),
			util.String("risk_level", assessment.RiskLevel),
		)

		return assessment
	}

	// ===============================================================
	// DEFAULT RISK ASSESSMENT (UNCHANGED LOGIC)
	// ===============================================================

	util.Info("Default Risk Assessment Started")

	botReq := BotDetectionRequest{
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		RequestLatency: req.RequestLatency,
		DeviceID:       req.DeviceID,
		PhoneNumber:    req.PhoneNumber,
	}

	botResult := e.botDetector.Detect(botReq)
	if botResult.IsBot {
		util.Warn("Bot detected", util.Strings("reasons", botResult.DetectionReasons))
		assessment.RiskScore += botResult.RiskScore
	}

	ipInfo := e.ipReputation.CheckIP(req.IPAddress)
	if ipInfo != nil {
		util.Info("IP Reputation Triggered", util.Int("ip_score", ipInfo.RiskScore))
		assessment.RiskScore += ipInfo.RiskScore
	}

	if req.FailedAttempts > 3 {
		util.Warn("Failed attempts high", util.Int("failed_attempts", req.FailedAttempts))
		assessment.RiskScore += 20
	}

	if req.DailyOTPCount > 5 {
		util.Warn("High OTP count!", util.Int("otp_count", req.DailyOTPCount))
		assessment.RiskScore += 15
	}

	if req.IsNewDevice {
		util.Warn("New device detected")
		assessment.RiskScore += 10
	}

	if req.IsNewIP {
		util.Warn("New IP detected")
		assessment.RiskScore += 5
	}

	if req.RequestLatency < 100*time.Millisecond {
		util.Warn("Fast request detected", util.Duration("latency", req.RequestLatency))
		assessment.RiskScore += 15
	}

	assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
	assessment.BlockAction = assessment.RiskScore >= 70
	assessment.Confidence = e.calculateConfidence(assessment.RiskScore)

	util.Info("Default Risk Complete",
		util.Int("risk_score", assessment.RiskScore),
		util.String("risk_level", assessment.RiskLevel),
	)

	return assessment
}

func (e *RiskEngine) calculateRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "very_low"
	}
}

func (e *RiskEngine) calculateConfidence(score int) string {
	switch {
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// Quick risk check
func (e *RiskEngine) QuickRiskCheck(ip, userAgent string, latency time.Duration, purpose string) (int, bool) {

	util.Info("QuickRiskCheck",
		util.String("ip", ip),
		util.String("ua", userAgent),
		util.Duration("latency", latency),
		util.String("purpose", purpose),
	)

	// DO NOT BLOCK for: login, admin_login, forgot_mpin
	// Let full risk engine handle those
	allowPurpose := purpose == "login" || purpose == "admin_login" || purpose == "forgot_mpin"

	// 1. Quick bot detection
	if e.botDetector.QuickDetect(userAgent, latency) {
		util.Warn("Quick bot detection triggered")

		if allowPurpose {
			return 80, false // allow, no block
		}
		return 80, true // block for other purposes (if added later)
	}

	// 2. IP reputation
	isRiskyIP, ipScore := e.ipReputation.QuickCheck(ip)
	if isRiskyIP {
		util.Warn("Risky IP detected", util.Int("ip_score", ipScore))

		if allowPurpose {
			return ipScore + 20, false // allow
		}
		return ipScore + 20, ipScore >= 50 // block only for non-login flows
	}

	// 3. Too fast (<50ms)
	if latency < 50*time.Millisecond {
		util.Warn("Request too fast in quick check")

		if allowPurpose {
			return 60, false // allow
		}
		return 60, true // block for non-login flows
	}

	return 0, false
}
