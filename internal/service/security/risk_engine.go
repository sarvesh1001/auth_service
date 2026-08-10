package security

import (
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
	assessment := RiskAssessment{
		RiskScore: 0,
		Reasons:   []string{},
	}

	// ----- Login / Admin Login -----
	if req.Purpose == "login" || req.Purpose == "admin_login" {
		botReq := BotDetectionRequest{
			UserAgent:      req.UserAgent,
			IPAddress:      req.IPAddress,
			RequestLatency: req.RequestLatency,
			DeviceID:       req.DeviceID,
			PhoneNumber:    req.PhoneNumber,
		}
		botResult := e.botDetector.Detect(botReq)
		if botResult.IsBot {
			assessment.RiskScore += botResult.RiskScore
			assessment.Reasons = append(assessment.Reasons, botResult.DetectionReasons...)
		}

		ipInfo := e.ipReputation.CheckIP(req.IPAddress)
		if ipInfo != nil {
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
			assessment.RiskScore += 15
			assessment.Reasons = append(assessment.Reasons, "high_failed_attempts")
		}
		if req.DailyOTPCount > 10 {
			assessment.RiskScore += 10
			assessment.Reasons = append(assessment.Reasons, "high_daily_otp_volume")
		}
		if req.RequestLatency < 50*time.Millisecond {
			assessment.RiskScore += 20
			assessment.Reasons = append(assessment.Reasons, "too_fast_request")
		}

		assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
		assessment.BlockAction = assessment.RiskScore >= 150
		assessment.Confidence = e.calculateConfidence(assessment.RiskScore)
		return assessment
	}

	// ----- Forgot MPIN -----
	if req.Purpose == "forgot_mpin" {
		botReq := BotDetectionRequest{
			UserAgent:      req.UserAgent,
			IPAddress:      req.IPAddress,
			RequestLatency: req.RequestLatency,
			DeviceID:       req.DeviceID,
			PhoneNumber:    req.PhoneNumber,
		}
		botResult := e.botDetector.Detect(botReq)
		if botResult.IsBot {
			assessment.RiskScore += botResult.RiskScore
			assessment.Reasons = append(assessment.Reasons, botResult.DetectionReasons...)
		}

		ipInfo := e.ipReputation.CheckIP(req.IPAddress)
		if ipInfo != nil {
			assessment.RiskScore += ipInfo.RiskScore
		}

		if req.FailedAttempts > 3 {
			assessment.RiskScore += 25
			assessment.Reasons = append(assessment.Reasons, "high_failed_attempts")
		}
		if req.DailyOTPCount > 5 {
			assessment.RiskScore += 20
			assessment.Reasons = append(assessment.Reasons, "high_daily_otp_volume")
		}
		if req.IsNewDevice {
			assessment.Reasons = append(assessment.Reasons, "new_device")
			assessment.RiskScore += 20
		}
		if req.IsNewIP {
			assessment.Reasons = append(assessment.Reasons, "new_ip")
			assessment.RiskScore += 15
		}
		if req.RequestLatency < 100*time.Millisecond {
			assessment.RiskScore += 20
		}
		if assessment.RiskScore > 0 {
			assessment.RiskScore += 25
			assessment.Reasons = append(assessment.Reasons, "forgot_mpin_sensitive")
		}

		assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
		assessment.BlockAction = assessment.RiskScore >= 150
		assessment.Confidence = e.calculateConfidence(assessment.RiskScore)
		return assessment
	}

	// ----- Default -----
	botReq := BotDetectionRequest{
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		RequestLatency: req.RequestLatency,
		DeviceID:       req.DeviceID,
		PhoneNumber:    req.PhoneNumber,
	}
	botResult := e.botDetector.Detect(botReq)
	if botResult.IsBot {
		assessment.RiskScore += botResult.RiskScore
	}

	ipInfo := e.ipReputation.CheckIP(req.IPAddress)
	if ipInfo != nil {
		assessment.RiskScore += ipInfo.RiskScore
	}

	if req.FailedAttempts > 3 {
		assessment.RiskScore += 20
	}
	if req.DailyOTPCount > 5 {
		assessment.RiskScore += 15
	}
	if req.IsNewDevice {
		assessment.RiskScore += 10
	}
	if req.IsNewIP {
		assessment.RiskScore += 5
	}
	if req.RequestLatency < 100*time.Millisecond {
		assessment.RiskScore += 15
	}

	assessment.RiskLevel = e.calculateRiskLevel(assessment.RiskScore)
	assessment.BlockAction = assessment.RiskScore >= 70
	assessment.Confidence = e.calculateConfidence(assessment.RiskScore)
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
	// DO NOT BLOCK for: login, admin_login, forgot_mpin
	allowPurpose := purpose == "login" || purpose == "admin_login" || purpose == "forgot_mpin"

	// 1. Quick bot detection
	if e.botDetector.QuickDetect(userAgent, latency) {
		if allowPurpose {
			return 80, false // allow
		}
		return 80, true // block for other purposes
	}

	// 2. IP reputation
	isRiskyIP, ipScore := e.ipReputation.QuickCheck(ip)
	if isRiskyIP {
		if allowPurpose {
			return ipScore + 20, false // allow
		}
		return ipScore + 20, ipScore >= 50 // block only for non-login flows
	}

	// 3. Too fast (<50ms)
	if latency < 50*time.Millisecond {
		if allowPurpose {
			return 60, false // allow
		}
		return 60, true // block for non-login flows
	}

	return 0, false
}
