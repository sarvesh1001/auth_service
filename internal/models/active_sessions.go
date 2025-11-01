// internal/models/session.go
// UPDATE: Add SessionType field to existing ActiveSession struct

package models

import (
	"net"
	"time"
)

type ActiveSession struct {
	UserID             string    `db:"user_id" json:"user_id"`
	SessionToken       string    `db:"session_token" json:"session_token"`
	DeviceID           string    `db:"device_id" json:"device_id"`
	DeviceFingerprint  string    `db:"device_fingerprint" json:"device_fingerprint"`
	KYCVerified        bool      `db:"kyc_verified" json:"kyc_verified"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	LastActivity       time.Time `db:"last_activity" json:"last_activity"`
	ExpiresAt          time.Time `db:"expires_at" json:"expires_at"`
	IPAddress          net.IP    `db:"ip_address" json:"ip_address"`
	EncryptionKey      []byte    `db:"encryption_key" json:"encryption_key"`
	
	// ===== NEW FIELD FOR HYBRID ADMIN APPROACH =====
	SessionType       string    `db:"session_type" json:"session_type"`          // "user" or "admin"
    AdminRoleLevel    string    `db:"admin_role_level" json:"admin_role_level,omitempty"`
    AdminPermissions  []string  `db:"admin_permissions" json:"admin_permissions,omitempty"`
}


// SessionType constants
const (
	SessionTypeUser  = "user"
	SessionTypeAdmin = "admin"
)

// IsAdminSession checks if this is an admin session
func (s *ActiveSession) IsAdminSession() bool {
	return s.SessionType == SessionTypeAdmin
}

// IsUserSession checks if this is a user session
func (s *ActiveSession) IsUserSession() bool {
	return s.SessionType == SessionTypeUser || s.SessionType == ""
}

// SetAdminSession marks this session as admin session
func (s *ActiveSession) SetAdminSession() {
	s.SessionType = SessionTypeAdmin
}

// SetUserSession marks this session as user session
func (s *ActiveSession) SetUserSession() {
	s.SessionType = SessionTypeUser
}