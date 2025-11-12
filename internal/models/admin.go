package models

import (
	"time"

	"github.com/google/uuid"
)

// AdminUser represents an admin user in the system
type AdminUser struct {
	AdminID             uuid.UUID `db:"admin_id" json:"admin_id"`
	PhoneHash           string    `db:"phone_hash" json:"phone_hash"`
	AdminRoleLevel      string    `db:"admin_role_level" json:"admin_role_level"`
	AdminPermissions    []string  `db:"admin_permissions" json:"admin_permissions"`
	AdminCreatedAt      time.Time `db:"admin_created_at" json:"admin_created_at"`
	AdminCreatedBy      uuid.UUID `db:"admin_created_by" json:"admin_created_by"`
	AdminUpdatedAt      time.Time `db:"admin_updated_at" json:"admin_updated_at"`
	IsActive            bool      `db:"is_active" json:"is_active"`
	DataAccessScope     []string  `db:"data_access_scope" json:"data_access_scope"`
	IPWhitelist         []string  `db:"ip_whitelist" json:"ip_whitelist"`
	FailedLoginAttempts int       `db:"failed_login_attempts" json:"failed_login_attempts"`
	LastLogin           time.Time `db:"last_login" json:"last_login"`
	PhoneEncrypted      string    `db:"phone_encrypted" json:"phone_encrypted"`
	PhoneKeyID          uuid.UUID `db:"phone_key_id" json:"phone_key_id"`
	PhoneEncryptedDEK   string    `db:"phone_encrypted_dek" json:"phone_encrypted_dek"`
}

// AdminRoleLevel constants (namespaced)
const (
	AdminRoleLevelOwner         = "owner"          // Full system access
	AdminRoleLevelSuperEmployee = "super_employee" // Moderate access
	AdminRoleLevelEmployee      = "employee"       // Limited access
)

// Permission constants
const (
	PermissionReadUsers    = "read_users"
	PermissionWriteUsers   = "write_users"
	PermissionBanUsers     = "ban_users"
	PermissionUnbanUsers   = "unban_users"
	PermissionVerifyKYC    = "verify_kyc"
	PermissionManageAdmins = "manage_admins"
	PermissionViewAuditLog = "view_audit_log"
	PermissionExportData   = "export_data"
	PermissionDeleteUsers  = "delete_users"
	PermissionSystemConfig = "system_config"
)

// DataAccessScope constants
const (
	DataAccessGlobal   = "global"
	DataAccessRegionIN = "region_in"
	DataAccessRegionUS = "region_us"
	DataAccessRegionEU = "region_eu"
)

// Utility methods
func (a *AdminUser) HasPermission(permission string) bool {
	for _, p := range a.AdminPermissions {
		if p == permission {
			return true
		}
	}
	return false
}

func (a *AdminUser) CanAccessRegion(region string) bool {
	for _, scope := range a.DataAccessScope {
		if scope == DataAccessGlobal || scope == region {
			return true
		}
	}
	return false
}

func (a *AdminUser) IsOwner() bool {
	return a.AdminRoleLevel == AdminRoleLevelOwner
}

func (a *AdminUser) IsSuperEmployee() bool {
	return a.AdminRoleLevel == AdminRoleLevelSuperEmployee
}

func (a *AdminUser) IsEmployee() bool {
	return a.AdminRoleLevel == AdminRoleLevelEmployee
}

func (a *AdminUser) CanManageAdmins() bool {
	return a.IsOwner() || a.IsSuperEmployee()
}

func (a *AdminUser) CanEditSystemConfig() bool {
	return a.IsOwner()
}

func (a *AdminUser) CanManageEmployee(targetRole string) bool {
	if a.IsOwner() {
		return true
	}
	if a.IsSuperEmployee() {
		return targetRole == AdminRoleLevelEmployee
	}
	return false
}

func (a *AdminUser) GetRoleHierarchy() int {
	switch a.AdminRoleLevel {
	case AdminRoleLevelOwner:
		return 3
	case AdminRoleLevelSuperEmployee:
		return 2
	case AdminRoleLevelEmployee:
		return 1
	default:
		return 0
	}
}

func (a *AdminUser) CanPromoteToRole(targetRole string) bool {
	if !a.CanManageAdmins() {
		return false
	}

	roleHierarchy := func(role string) int {
		switch role {
		case AdminRoleLevelOwner:
			return 3
		case AdminRoleLevelSuperEmployee:
			return 2
		case AdminRoleLevelEmployee:
			return 1
		default:
			return 0
		}
	}

	targetHierarchyLevel := roleHierarchy(targetRole)

	if a.IsOwner() {
		return true
	}
	if a.IsSuperEmployee() {
		return targetHierarchyLevel <= 1
	}
	return false
}
