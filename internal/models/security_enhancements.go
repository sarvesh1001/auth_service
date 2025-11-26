package models

import (
	"net"
	"time"
)

// ============================================
// IP REPUTATION MODELS
// ============================================

type IPReputation struct {
	IPAddress      net.IP    `db:"ip_address"`
	RiskScore      int       `db:"risk_score"` // 0-100, higher = more risky
	TotalRequests  int64     `db:"total_requests"`
	FailedAttempts int64     `db:"failed_attempts"`
	MaliciousFlags int       `db:"malicious_flags"` // Count of malicious activities
	FirstSeen      time.Time `db:"first_seen"`
	LastSeen       time.Time `db:"last_seen"`
	CountryCode    string    `db:"country_code"`
	ASN            string    `db:"asn"`
	IsWhitelisted  bool      `db:"is_whitelisted"`
	IsBlacklisted  bool      `db:"is_blacklisted"`
	ThreatTypes    []string  `db:"threat_types"` // e.g., ["botnet", "brute_force", "vpn"]
}

type IPThreatEvent struct {
	IPAddress net.IP    `db:"ip_address"`
	EventType string    `db:"event_type"` // "brute_force", "suspicious_geo", etc.
	EventTime time.Time `db:"event_time"`
	RiskScore int       `db:"risk_score"`
	Details   string    `db:"details"`
	UserAgent string    `db:"user_agent"`
}

// ============================================
// BRUTE FORCE SCORING MODELS
// ============================================

type BruteForceScore struct {
	Identifier  string    `db:"identifier"` // phone_hash + purpose or IP
	Score       int       `db:"score"`      // 0-100
	Factors     []string  `db:"factors"`    // ["high_failure_rate", "suspicious_geo", etc.]
	LastUpdated time.Time `db:"last_updated"`
	ExpiresAt   time.Time `db:"expires_at"`
}

type SecurityEvent struct {
	EventID   string    `db:"event_id"`
	EventType string    `db:"event_type"` // "otp_brute_force", "suspicious_activity"
	PhoneHash string    `db:"phone_hash"`
	IPAddress net.IP    `db:"ip_address"`
	DeviceID  string    `db:"device_id"`
	RiskScore int       `db:"risk_score"`
	Action    string    `db:"action"` // "blocked", "allowed", "challenged"
	Details   string    `db:"details"`
	CreatedAt time.Time `db:"created_at"`
}

// ============================================
// DYNAMIC COOLDOWN CONFIG
// ============================================

type DynamicCooldownConfig struct {
	BaseCooldown    time.Duration   `db:"base_cooldown"`
	MaxCooldown     time.Duration   `db:"max_cooldown"`
	RiskMultipliers map[int]float64 `db:"risk_multipliers"` // risk_score -> multiplier
}

// ============================================
// DAILY OTP LIMIT
// ============================================

type DailyOTPLimit struct {
	PhoneHash       string    `db:"phone_hash"`
	Date            string    `db:"date"` // YYYY-MM-DD
	TotalSent       int       `db:"total_sent"`
	TotalFailed     int       `db:"total_failed"`
	LastSentAt      time.Time `db:"last_sent_at"`
	IsLimitExceeded bool      `db:"is_limit_exceeded"`
}

// ============================================
// OTP REPLAY PROTECTION
// ============================================

type OTPReplayCache struct {
	OTPHash   string    `db:"otp_hash"`
	PhoneHash string    `db:"phone_hash"`
	Purpose   string    `db:"purpose"`
	UsedAt    time.Time `db:"used_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

// ============================================
// SMS PROVIDER FAILOVER
// ============================================

type SMSProvider struct {
	Name        string            `db:"name"`
	Priority    int               `db:"priority"`
	Enabled     bool              `db:"enabled"`
	SuccessRate float64           `db:"success_rate"`
	LastUsed    time.Time         `db:"last_used"`
	Config      map[string]string `db:"config"`
}

type SMSDeliveryAttempt struct {
	AttemptID    string    `db:"attempt_id"`
	Provider     string    `db:"provider"`
	PhoneNumber  string    `db:"phone_number"`
	Success      bool      `db:"success"`
	Error        string    `db:"error"`
	SentAt       time.Time `db:"sent_at"`
	ResponseTime int       `db:"response_time"` // ms
}
