package models

import (
	"net"
	"time"

	"auth-service/internal/rbac" // Import rbac package
)

// PermissionMaskSegments defines the number of uint64 segments needed for permission mask
// 13 segments × 64 bits = 832 bits (enough for 800 permissions)
const PermissionMaskSegments = 13

type ActiveSession struct {
	UserID            string    `db:"user_id" json:"user_id"`
	SessionToken      string    `db:"session_token" json:"session_token"`
	DeviceID          string    `db:"device_id" json:"device_id"`
	DeviceFingerprint string    `db:"device_fingerprint" json:"device_fingerprint"`
	KYCVerified       bool      `db:"kyc_verified" json:"kyc_verified"`
	CreatedAt         time.Time `db:"created_at" json:"created_at"`
	LastActivity      time.Time `db:"last_activity" json:"last_activity"`
	ExpiresAt         time.Time `db:"expires_at" json:"expires_at"`
	IPAddress         net.IP    `db:"ip_address" json:"ip_address"`
	EncryptionKey     []byte    `db:"encryption_key" json:"encryption_key"`

	// Session type
	SessionType string `db:"session_type" json:"session_type"` // "user", "admin", "student", or "web"

	// Role and permissions
	Role           string   `db:"role" json:"role,omitempty"` // e.g., "super_admin", "admin_manager", "owner", "employee"
	PermissionMask []uint64 `db:"permission_mask" json:"permission_mask,omitempty"`
}

// IsAdminSession checks if this is an admin session
func (s *ActiveSession) IsAdminSession() bool {
	return s.SessionType == SessionTypeAdmin
}

// IsUserSession checks if this is a user session
func (s *ActiveSession) IsUserSession() bool {
	return s.SessionType == SessionTypeUser
}

// IsStudentSession checks if this is a student session
func (s *ActiveSession) IsStudentSession() bool {
	return s.SessionType == SessionTypeStudent
}

// IsWebSession checks if this is a web session
func (s *ActiveSession) IsWebSession() bool {
	return s.SessionType == SessionTypeWeb
}

// SetAdminSession marks this session as admin session
func (s *ActiveSession) SetAdminSession() {
	s.SessionType = SessionTypeAdmin
}

// SetUserSession marks this session as user session
func (s *ActiveSession) SetUserSession() {
	s.SessionType = SessionTypeUser
}

// SetStudentSession marks this session as student session
func (s *ActiveSession) SetStudentSession() {
	s.SessionType = SessionTypeStudent
}

// SetWebSession marks this session as web session
func (s *ActiveSession) SetWebSession() {
	s.SessionType = SessionTypeWeb
}

// HasPermission checks if session has a specific permission
func (s *ActiveSession) HasPermission(permissionName string) bool {
	if s.PermissionMask == nil || len(s.PermissionMask) == 0 {
		return false
	}

	// Use rbac package for permission checking
	return rbac.HasPermission(s.PermissionMask, permissionName)
}

// GetPermissions returns list of permission names from mask
func (s *ActiveSession) GetPermissions() []string {
	if s.PermissionMask == nil || len(s.PermissionMask) == 0 {
		return []string{}
	}

	// Use rbac package to get permissions from mask
	return rbac.GetPermissionsFromMask(s.PermissionMask)
}

// HasAnyPermission checks if session has any of the given permissions
func (s *ActiveSession) HasAnyPermission(permissions ...string) bool {
	if s.PermissionMask == nil || len(s.PermissionMask) == 0 {
		return false
	}

	return rbac.HasAnyPermission(s.PermissionMask, permissions...)
}

// HasAllPermissions checks if session has all of the given permissions
func (s *ActiveSession) HasAllPermissions(permissions ...string) bool {
	if s.PermissionMask == nil || len(s.PermissionMask) == 0 {
		return false
	}

	return rbac.HasAllPermissions(s.PermissionMask, permissions...)
}

// IsSuperAdmin checks if session has super admin role
func (s *ActiveSession) IsSuperAdmin() bool {
	return s.SessionType == SessionTypeAdmin && s.Role == RoleAdminSuperAdmin
}

// IsAdminManager checks if session has admin manager role
func (s *ActiveSession) IsAdminManager() bool {
	return s.SessionType == SessionTypeAdmin && s.Role == RoleAdminManager
}

// IsAdminEmployee checks if session has admin employee role
func (s *ActiveSession) IsAdminEmployee() bool {
	return s.SessionType == SessionTypeAdmin && s.Role == RoleAdminEmployee
}

// IsUserOwner checks if session has user owner role
func (s *ActiveSession) IsUserOwner() bool {
	return s.SessionType == SessionTypeUser && s.Role == RoleUserOwner
}

// IsSuperEmployee checks if session has super employee role
func (s *ActiveSession) IsSuperEmployee() bool {
	return s.SessionType == SessionTypeUser && s.Role == RoleUserSuperEmployee
}

// IsRegularEmployee checks if session has regular employee role
func (s *ActiveSession) IsRegularEmployee() bool {
	return s.SessionType == SessionTypeUser && s.Role == RoleUserEmployee
}

// GetRoleLevel returns hierarchical level of the role
func (s *ActiveSession) GetRoleLevel() int {
	switch s.Role {
	case RoleAdminSuperAdmin:
		return 3
	case RoleAdminManager:
		return 2
	case RoleAdminEmployee:
		return 1
	case RoleUserOwner:
		return 3
	case RoleUserSuperEmployee:
		return 2
	case RoleUserEmployee:
		return 1
	default:
		return 0
	}
}

// HasRoleAccess checks if session has required role level or higher
func (s *ActiveSession) HasRoleAccess(requiredRole string) bool {
	sessionLevel := s.GetRoleLevel()
	requiredLevel := s.getRoleLevelFromString(requiredRole)
	return sessionLevel >= requiredLevel
}

// Helper function to get role level from string
func (s *ActiveSession) getRoleLevelFromString(role string) int {
	switch role {
	case RoleAdminSuperAdmin:
		return 3
	case RoleAdminManager:
		return 2
	case RoleAdminEmployee:
		return 1
	case RoleUserOwner:
		return 3
	case RoleUserSuperEmployee:
		return 2
	case RoleUserEmployee:
		return 1
	default:
		return 0
	}
}

// CreateFullPermissionMask creates a mask with all bits set (using global segment count)
func (s *ActiveSession) CreateFullPermissionMask() []uint64 {
	mask := make([]uint64, PermissionMaskSegments)
	for i := range mask {
		mask[i] = ^uint64(0) // Set all bits to 1
	}
	return mask
}

// BuildPermissionMaskFromNames builds a permission mask from permission names
func (s *ActiveSession) BuildPermissionMaskFromNames(permissionNames []string) []uint64 {
	return rbac.BuildMaskFromPermissionNames(permissionNames)
}

// BuildPermissionMaskFromBitPositions builds a permission mask from bit positions
func (s *ActiveSession) BuildPermissionMaskFromBitPositions(bitPositions []uint64) []uint64 {
	return rbac.BuildMaskFromBitPositions(bitPositions)
}

// ============================================================================
// Constants
// ============================================================================

// Session type constants
const (
	SessionTypeUser    = "user"
	SessionTypeAdmin   = "admin"
	SessionTypeStudent = "student"
	SessionTypeWeb     = "web"
)

// Global helper function to create a full permission mask (using 13 segments)
func CreateFullPermissionMask() []uint64 {
	mask := make([]uint64, PermissionMaskSegments)
	for i := range mask {
		mask[i] = ^uint64(0)
	}
	return mask
}
