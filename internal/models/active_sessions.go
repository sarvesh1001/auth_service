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
	
	// Session type
	SessionType        string    `db:"session_type" json:"session_type"` // "user" or "admin"
	
	// Bitmask fields for admin - ADDED
	AdminRoleMask      uint64    `db:"admin_role_mask" json:"admin_role_mask,omitempty"`
	AdminPermissionMask []uint64 `db:"admin_permission_mask" json:"admin_permission_mask,omitempty"`
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

// HasPermission checks if admin session has a specific permission
func (s *ActiveSession) HasPermission(permissionName string) bool {
	if s.SessionType != SessionTypeAdmin || s.AdminPermissionMask == nil {
		return false
	}
	
	bitIndex, exists := AdminPermissionBitIndices[permissionName]
	if !exists {
		return false
	}
	
	return HasPermission(s.AdminPermissionMask, bitIndex)
}