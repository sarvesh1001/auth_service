// File: internal/models/log_events.go
// Kafka event models for logging system — SIMPLIFIED VERSION (only used fields)

package models

import "time"

// LogEventType defines the type of log event
type LogEventType string

const (
	LogEventTypeOTP      LogEventType = "otp"
	LogEventTypeMPIN     LogEventType = "mpin"
	LogEventTypeSecurity LogEventType = "security"
	LogEventTypeAdmin    LogEventType = "admin"
	LogEventTypeSession  LogEventType = "session"
	LogEventTypeUser     LogEventType = "user"
	LogEventTypeDevice   LogEventType = "device"
)

// LogLevel defines the severity of the log
type LogLevel string

const (
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarning LogLevel = "warning"
	LogLevelError   LogLevel = "error"
)

// LogEnvelope wraps all log events with metadata
type LogEnvelope struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	ServiceName string                 `json:"service_name"`
	Timestamp   time.Time              `json:"timestamp"`
	Environment string                 `json:"environment"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
}

// OTPLogEvent - OTP specific logs
type OTPLogEvent struct {
	LogEnvelope
	UserID        string `json:"user_id"`
	PhoneNumber   string `json:"phone_number"`
	Status        string `json:"status"`
	AttemptNumber int    `json:"attempt_number"`
	AttemptsLeft  int    `json:"attempts_left"`
	ErrorCode     string `json:"error_code,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	OTPProvider   string `json:"otp_provider,omitempty"`
	Duration      int64  `json:"duration_ms,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
}

// MPINLogEvent - MPIN specific logs
type MPINLogEvent struct {
	LogEnvelope
	UserID        string `json:"user_id"`
	EntityType    string `json:"entity_type"` // "user" or "admin
	Status        string `json:"status"`
	Attempts      int    `json:"attempts"`
	AttemptsLeft  int    `json:"attempts_left"`
	IsLocked      bool   `json:"is_locked"`
	ErrorCode     string `json:"error_code,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	DeviceTrust   string `json:"device_trust,omitempty"`
	Duration      int64  `json:"duration_ms,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
}

// SecurityLogEvent - Security/fraud logs
type SecurityLogEvent struct {
	LogEnvelope
	UserID        string                 `json:"user_id"`
	EventCategory string                 `json:"event_category"`
	Severity      string                 `json:"severity"`
	IPAddress     string                 `json:"ip_address"`
	DeviceID      string                 `json:"device_id"`
	Action        string                 `json:"action"`
	RiskScore     float64                `json:"risk_score"`
	Reason        string                 `json:"reason"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// AdminLogEvent - Admin operation logs
type AdminLogEvent struct {
	LogEnvelope
	AdminID      string                 `json:"admin_id"`
	AdminRole    string                 `json:"admin_role"`
	TargetUserID string                 `json:"target_user_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	Changes      map[string]interface{} `json:"changes"`
	Status       string                 `json:"status"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"` // ✅ ADD THIS LINE
	Duration     int64                  `json:"duration_ms,omitempty"`
}

// SessionLogEvent - Session logs
type SessionLogEvent struct {
	LogEnvelope
	UserID      string `json:"user_id"`
	SessionID   string `json:"session_id"`
	Status      string `json:"status"`
	DeviceID    string `json:"device_id"`
	IPAddress   string `json:"ip_address"`
	SessionType string `json:"session_type"`
	TTL         int64  `json:"ttl_seconds"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// In models.go, update UserLogEvent struct:
type UserLogEvent struct {
	LogEnvelope
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username,omitempty"`  // ADD THIS
	FullName    string                 `json:"full_name,omitempty"` // ADD THIS
	Action      string                 `json:"action"`
	PhoneNumber string                 `json:"phone_number,omitempty"`
	Status      string                 `json:"status"`
	DeviceID    string                 `json:"device_id,omitempty"`
	Changes     map[string]interface{} `json:"changes,omitempty"`
	ErrorCode   string                 `json:"error_code,omitempty"`
	Duration    int64                  `json:"duration_ms,omitempty"`
}

// DeviceLogEvent - Device binding and validation logs (SIMPLIFIED - only used fields)
type DeviceLogEvent struct {
	LogEnvelope
	UserID       string `json:"user_id"`
	EntityType   string `json:"entity_type"` // "user" or "admin"
	DeviceID     string `json:"device_id"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	BindToken    string `json:"bind_token,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	Duration     int64  `json:"duration_ms,omitempty"`
}
type AdminMPINLogEvent struct {
	LogEnvelope
	AdminID      string `json:"admin_id"`
	TargetUserID string `json:"target_user_id"`
	TargetPhone  string `json:"target_phone,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Action       string `json:"action"`

	// ✅ Add this
	UserAgent string `json:"user_agent,omitempty"`
}

// Add this struct to your existing log_events.go file
type AuditLogEvent struct {
	EventID     string      `json:"event_id"`
	AuditID     string      `json:"audit_id"`
	Timestamp   time.Time   `json:"timestamp"`
	EventType   string      `json:"event_type"` // Always "audit"
	CompanyID   *string     `json:"company_id,omitempty"`
	Module      string      `json:"module"`      // hr, attendance, leave, payroll, admin, system
	Action      string      `json:"action"`      // leave.approve, attendance.manual_add, etc.
	EntityType  string      `json:"entity_type"` // leave_request, attendance_event, etc.
	EntityID    *string     `json:"entity_id,omitempty"`
	ActorType   string      `json:"actor_type"` // user, admin, system
	ActorID     *string     `json:"actor_id,omitempty"`
	BeforeState interface{} `json:"before_state,omitempty"`
	AfterState  interface{} `json:"after_state,omitempty"`
	Metadata    interface{} `json:"metadata,omitempty"`
	Environment string      `json:"environment"`
	Version     string      `json:"version"`
	Message     string      `json:"message"`
	ServiceName string      `json:"service_name"`
}
