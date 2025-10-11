package model

import "time"

// -------------------- USER MODEL --------------------
type User struct {
	UserID        string    `json:"user_id" db:"user_id"`                     // UUID
	PhoneNumber   string    `json:"phone_number" db:"phone_number"`           // E.164 format (+91XXXXXXXXXX)
	CountryCode   string    `json:"country_code" db:"country_code"`           // e.g. "IN"
	DeviceID      string    `json:"device_id" db:"device_id"`                 // unique device identifier
	MPINHash      string    `json:"mpin_hash" db:"mpin_hash"`                 // hashed + salted MPIN
	IsVerified    bool      `json:"is_verified" db:"is_verified"`             // OTP verified
	IsActive      bool      `json:"is_active" db:"is_active"`                 // active status
	LastLoginAt   time.Time `json:"last_login_at" db:"last_login_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	LastLoginIP   string    `json:"last_login_ip" db:"last_login_ip"`         // for compliance
	LastLoginCity string    `json:"last_login_city" db:"last_login_city"`     // optional, for log traceability
}

// -------------------- OTP MODEL --------------------
type OTP struct {
	OTPID        string    `json:"otp_id" db:"otp_id"`                       // UUID
	PhoneNumber  string    `json:"phone_number" db:"phone_number"`
	OTPHash      string    `json:"otp_hash" db:"otp_hash"`                   // store hashed OTP only
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`               // expiry timestamp
	AttemptCount int       `json:"attempt_count" db:"attempt_count"`         // limit attempts
	IsUsed       bool      `json:"is_used" db:"is_used"`
	DeviceID     string    `json:"device_id" db:"device_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// -------------------- MPIN MODEL --------------------
type MPIN struct {
	UserID      string    `json:"user_id" db:"user_id"`
	MPINHash    string    `json:"mpin_hash" db:"mpin_hash"`                  // bcrypt/argon2 hash
	LastChanged time.Time `json:"last_changed" db:"last_changed"`
	IsBlocked   bool      `json:"is_blocked" db:"is_blocked"`                // after failed attempts
	RetryCount  int       `json:"retry_count" db:"retry_count"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// -------------------- DEVICE SESSION MODEL --------------------
type DeviceSession struct {
	SessionID     string    `json:"session_id" db:"session_id"`              // UUID
	UserID        string    `json:"user_id" db:"user_id"`
	DeviceID      string    `json:"device_id" db:"device_id"`
	IsActive      bool      `json:"is_active" db:"is_active"`                // only one active per user
	AuthToken     string    `json:"auth_token" db:"auth_token"`              // JWT or custom token
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	LastAccessed  time.Time `json:"last_accessed" db:"last_accessed"`
	RevokedReason string    `json:"revoked_reason" db:"revoked_reason"`      // e.g. "login from another device"
}

// -------------------- REPOSITORY INTERFACES --------------------

// UserRepository defines the interface for user data operations
type UserRepository interface {
	CreateUser(user *User) error
	GetUserByID(userID string) (*User, error)
	GetUserByPhone(phoneNumber string) (*User, error)
	UpdateUserVerificationStatus(userID string, isVerified bool) error
	UpdateUserMPINHash(userID string, mpinHash string) error
	UpdateUserDevice(userID string, deviceID string) error
	UpdateUserLastLogin(userID string, loginIP, loginCity string) error
	DeactivateUser(userID string) error
}

// OTPRepository defines the interface for OTP data operations
type OTPRepository interface {
	CreateOTP(otp *OTP) error
	GetOTPByPhone(phoneNumber string) (*OTP, error)
	MarkOTPUsed(otpID string) error
	IncrementOTPAttempt(otpID string) error
	DeleteExpiredOTPs() error
}

// MPINRepository defines the interface for MPIN data operations
type MPINRepository interface {
	CreateMPIN(mpin *MPIN) error
	GetMPINByUserID(userID string) (*MPIN, error)
	UpdateMPINHash(userID string, mpinHash string) error
	IncrementMPINRetry(userID string) error
	BlockMPIN(userID string) error
	ResetMPINRetryCount(userID string) error
}

// DeviceSessionRepository defines the interface for device session operations
type DeviceSessionRepository interface {
	CreateDeviceSession(session *DeviceSession) error
	GetActiveSessionByUserID(userID string) (*DeviceSession, error)
	RevokeSessionByUserID(userID string, reason string) error
	RevokeSessionByDeviceID(deviceID string, reason string) error
	UpdateSessionAccessTime(sessionID string) error
	ListUserSessions(userID string) ([]*DeviceSession, error)
}

// -------------------- CACHE INTERFACES --------------------

// OTPCache defines the interface for OTP caching operations
type OTPCache interface {
	SetOTP(phoneNumber, otpHash string, ttl time.Duration) error
	GetOTP(phoneNumber string) (string, error)
	DeleteOTP(phoneNumber string) error
	IncrementAttempts(phoneNumber string, ttl time.Duration) (int, error)
	ResetAttempts(phoneNumber string) error
}

// MPINCache defines the interface for MPIN caching operations
type MPINCache interface {
	SetMPINRetryCount(userID string, count int, ttl time.Duration) error
	GetMPINRetryCount(userID string) (int, error)
	IncrementMPINRetry(userID string, ttl time.Duration) (int, error)
	ResetMPINRetryCount(userID string) error
}

// SessionCache defines the interface for session caching operations
type SessionCache interface {
	SetActiveSession(userID, sessionID string, ttl time.Duration) error
	GetActiveSession(userID string) (string, error)
	InvalidateSession(userID string) error
	SetSessionData(sessionID string, data map[string]interface{}, ttl time.Duration) error
	GetSessionData(sessionID string) (map[string]interface{}, error)
}

// RateLimitCache defines the interface for rate limiting operations
type RateLimitCache interface {
	SetTemporaryLock(key string, ttl time.Duration) error
	IsUserLocked(key string) (bool, error)
	IncrementCounter(key string, ttl time.Duration) (int, error)
	ResetCounter(key string) error
}
