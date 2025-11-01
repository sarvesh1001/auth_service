// internal/models/admin.go - FINAL FIXED VERSION
// Fixes unused variable error

package models

import (
	"time"

	"github.com/google/uuid"
)

// AdminUser represents an admin user in the system
// Stored in the separate admin_users table for efficiency
type AdminUser struct {
	AdminID             uuid.UUID `db:"admin_id" json:"admin_id"`
	PhoneHash           string    `db:"phone_hash" json:"phone_hash"` // Link to user's phone
	AdminRoleLevel      string    `db:"admin_role_level" json:"admin_role_level"` // 'owner' | 'super_employee' | 'employee'
	AdminPermissions    []string  `db:"admin_permissions" json:"admin_permissions"` // List of permissions
	AdminCreatedAt      time.Time `db:"admin_created_at" json:"admin_created_at"`
	AdminCreatedBy      uuid.UUID `db:"admin_created_by" json:"admin_created_by"` // Which admin created this
	AdminUpdatedAt      time.Time `db:"admin_updated_at" json:"admin_updated_at"`
	IsActive            bool      `db:"is_active" json:"is_active"`
	DataAccessScope     []string  `db:"data_access_scope" json:"data_access_scope"` // ✅ FIXED: Changed to []string
	IPWhitelist         []string  `db:"ip_whitelist" json:"ip_whitelist"` // Optional IP restrictions
	FailedLoginAttempts int       `db:"failed_login_attempts" json:"failed_login_attempts"`
	LastLogin           time.Time `db:"last_login" json:"last_login"`
	PhoneEncrypted    string    // base64-encoded ciphertext
	PhoneKeyID        uuid.UUID // encryption key ID
	PhoneEncryptedDEK string    // base64-encoded encrypted DEK

}

// AdminRoleLevel constants
const (
	RoleLevelOwner         = "owner"           // Full system access, can manage all admins
	RoleLevelSuperEmployee = "super_employee"  // Can manage employees, moderate permissions
	RoleLevelEmployee      = "employee"        // Limited permissions, cannot manage admins
)

// Permission constants
const (
	PermissionReadUsers        = "read_users"
	PermissionWriteUsers       = "write_users"
	PermissionBanUsers         = "ban_users"
	PermissionUnbanUsers       = "unban_users"
	PermissionVerifyKYC        = "verify_kyc"
	PermissionManageAdmins     = "manage_admins"     // Only for owner and super_employee
	PermissionViewAuditLog     = "view_audit_log"
	PermissionExportData       = "export_data"
	PermissionDeleteUsers      = "delete_users"
	PermissionSystemConfig     = "system_config"     // Only for owner
)

// DataAccessScope constants
const (
	DataAccessGlobal    = "global"
	DataAccessRegionIN  = "region_in"
	DataAccessRegionUS  = "region_us"
	DataAccessRegionEU  = "region_eu"
)

// HasPermission checks if admin has a specific permission
func (a *AdminUser) HasPermission(permission string) bool {
	for _, p := range a.AdminPermissions {
		if p == permission {
			return true
		}
	}
	return false
}

// CanAccessRegion checks if admin can access specific region
func (a *AdminUser) CanAccessRegion(region string) bool {
	for _, scope := range a.DataAccessScope {
		if scope == DataAccessGlobal {
			return true
		}
		if scope == region {
			return true
		}
	}
	return false
}

// IsOwner checks if admin is owner (full access)
func (a *AdminUser) IsOwner() bool {
	return a.AdminRoleLevel == RoleLevelOwner
}

// IsSuperEmployee checks if admin is super employee
func (a *AdminUser) IsSuperEmployee() bool {
	return a.AdminRoleLevel == RoleLevelSuperEmployee
}

// IsEmployee checks if admin is regular employee
func (a *AdminUser) IsEmployee() bool {
	return a.AdminRoleLevel == RoleLevelEmployee
}

// CanManageAdmins checks if admin can manage other admins
// Only Owner and SuperEmployee can manage admins
func (a *AdminUser) CanManageAdmins() bool {
	return a.IsOwner() || a.IsSuperEmployee()
}

// CanEditSystemConfig checks if admin can edit system configuration
// Only Owner can edit system config
func (a *AdminUser) CanEditSystemConfig() bool {
	return a.IsOwner()
}

// CanManageEmployee checks if admin can manage an employee
// Owner can manage anyone, SuperEmployee can manage Employees only
func (a *AdminUser) CanManageEmployee(targetRole string) bool {
	if a.IsOwner() {
		return true // Owner can manage all
	}
	if a.IsSuperEmployee() {
		return targetRole == RoleLevelEmployee // SuperEmployee can only manage Employees
	}
	return false // Employee cannot manage anyone
}

// GetRoleHierarchy returns the hierarchy level of the role (higher = more permissions)
func (a *AdminUser) GetRoleHierarchy() int {
	switch a.AdminRoleLevel {
	case RoleLevelOwner:
		return 3
	case RoleLevelSuperEmployee:
		return 2
	case RoleLevelEmployee:
		return 1
	default:
		return 0
	}
}

// ✅ FINAL FIX: CanPromoteToRole - Removed unused variable
// CanPromoteToRole checks if current admin can promote someone to target role
func (a *AdminUser) CanPromoteToRole(targetRole string) bool {
	if !a.CanManageAdmins() {
		return false
	}

	// Helper function to get role hierarchy
	roleHierarchy := func(role string) int {
		switch role {
		case RoleLevelOwner:
			return 3
		case RoleLevelSuperEmployee:
			return 2
		case RoleLevelEmployee:
			return 1
		default:
			return 0
		}
	}

	// ✅ FIXED: Removed unused currentHierarchyLevel variable
	// Get target hierarchy level
	targetHierarchyLevel := roleHierarchy(targetRole)

	// Can only promote to roles at or below their own level
	// Owner can promote to any role
	// SuperEmployee can promote to Employee only
	if a.IsOwner() {
		return true // Owner can promote anyone
	}
	if a.IsSuperEmployee() {
		return targetHierarchyLevel <= 1 // SuperEmployee can only create Employees
	}
	return false
}
