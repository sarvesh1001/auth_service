package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Admin role types
const (
	RoleTypeEmployee   = 1 // 1=Employee
	RoleTypeManager    = 2 // 2=Manager
	RoleTypeSuperAdmin = 4 // 4=Super Admin
)

// Role strings for JWT and session identification
const (
	RoleAdminSuperAdmin   = "super_admin"
	RoleAdminManager      = "admin_manager"
	RoleAdminEmployee     = "admin_employee"
	RoleUserOwner         = "owner"
	RoleUserSuperEmployee = "manager"
	RoleUserEmployee      = "employee"
)

// Role mask constants
const (
	RoleMaskEmployee   = 1
	RoleMaskManager    = 2
	RoleMaskOwner      = 4
	RoleMaskSuperAdmin = 4 // Same as Owner
)

// AdminUser represents an admin user in the system
type AdminUser struct {
	AdminID             uuid.UUID      `json:"admin_id" db:"admin_id"`
	PhoneHash           string         `json:"phone_hash" db:"phone_hash"`
	PhoneEncrypted      []byte         `json:"phone_encrypted,omitempty" db:"phone_encrypted"`
	PhoneKeyID          uuid.UUID      `json:"phone_key_id" db:"phone_key_id"`
	PhoneEncryptedDEK   string         `json:"phone_encrypted_dek,omitempty" db:"phone_encrypted_dek"`
	AdminRoleID         uuid.UUID      `json:"admin_role_id" db:"admin_role_id"`
	RoleType            int            `json:"role_type" db:"role_type"` // 1=Employee, 2=Manager, 4=Super Admin
	ReportsTo           *uuid.UUID     `json:"reports_to,omitempty" db:"reports_to"`
	AdminCreatedAt      time.Time      `json:"admin_created_at" db:"admin_created_at"`
	AdminCreatedBy      *uuid.UUID     `json:"admin_created_by,omitempty" db:"admin_created_by"`
	AdminUpdatedAt      time.Time      `json:"admin_updated_at" db:"admin_updated_at"`
	IsActive            bool           `json:"is_active" db:"is_active"`
	DataAccessScope     pq.StringArray `json:"data_access_scope" db:"data_access_scope"`
	IPWhitelist         pq.StringArray `json:"ip_whitelist" db:"ip_whitelist"`
	FailedLoginAttempts int            `json:"failed_login_attempts" db:"failed_login_attempts"`
	LastLogin           *time.Time     `json:"last_login,omitempty" db:"last_login"`
	Username            string         `json:"username" db:"username"`
	FullName            string         `json:"full_name" db:"full_name"`
	UserSearchTSV       string         `json:"-" db:"user_search_tsv"`
}

// IsOwner checks if the admin is a super admin (owner)
func (a *AdminUser) IsOwner() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// IsSuperEmployee checks if the admin is a manager (super employee)
func (a *AdminUser) IsSuperEmployee() bool {
	return a.RoleType == RoleTypeManager
}

// IsEmployee checks if the admin is an employee
func (a *AdminUser) IsEmployee() bool {
	return a.RoleType == RoleTypeEmployee
}

// IsManager checks if the admin is a manager
func (a *AdminUser) IsManager() bool {
	return a.RoleType == RoleTypeManager
}

// IsSuperAdmin checks if the admin is a super admin
func (a *AdminUser) IsSuperAdmin() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// GetRoleString returns the string representation of the role
func (a *AdminUser) GetRoleString() string {
	switch a.RoleType {
	case RoleTypeSuperAdmin:
		return RoleAdminSuperAdmin
	case RoleTypeManager:
		return RoleAdminManager
	case RoleTypeEmployee:
		return RoleAdminEmployee
	default:
		return ""
	}
}

// CanManage checks if this admin can manage another admin
func (a *AdminUser) CanManage(target *AdminUser) bool {
	// Owner can manage everyone
	if a.IsOwner() {
		return true
	}

	// Manager can manage employees
	if a.IsManager() && target.IsEmployee() {
		return true
	}

	// Employees can't manage anyone
	return false
}

// HasPermission checks if admin has a specific permission (placeholder - needs actual permission system)
func (a *AdminUser) HasPermission(permissionName string) bool {
	// TODO: Implement actual permission checking based on role and permissions
	// For now, return true for owner, manager for employee permissions
	if a.IsOwner() {
		return true
	}

	if a.IsManager() {
		// Managers have all employee permissions
		return true
	}

	// Employees have limited permissions
	return false
}

// AdminUserSearchResult represents search results for admin users
type AdminUserSearchResult struct {
	AdminID        uuid.UUID  `json:"admin_id" db:"admin_id"`
	Username       string     `json:"username" db:"username"`
	FullName       string     `json:"full_name" db:"full_name"`
	PhoneHash      string     `json:"phone_hash" db:"phone_hash"`
	RoleName       string     `json:"role_name" db:"role_name"`
	AdminRoleID    uuid.UUID  `json:"admin_role_id" db:"admin_role_id"`
	RoleType       int        `json:"role_type" db:"role_type"`
	ReportsTo      *uuid.UUID `json:"reports_to,omitempty" db:"reports_to"`
	ReportsToName  string     `json:"reports_to_name,omitempty" db:"reports_to_name"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	LastLogin      *time.Time `json:"last_login,omitempty" db:"last_login"`
	AdminCreatedAt time.Time  `json:"admin_created_at" db:"admin_created_at"`
	RelevanceScore float64    `json:"relevance_score" db:"relevance_score"`
	MatchType      string     `json:"match_type" db:"match_type"` // "all", "autocomplete", "fulltext"
}

// IsOwner checks if the admin is a super admin (owner)
func (a *AdminUserSearchResult) IsOwner() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// IsSuperEmployee checks if the admin is a manager (super employee)
func (a *AdminUserSearchResult) IsSuperEmployee() bool {
	return a.RoleType == RoleTypeManager
}

// IsEmployee checks if the admin is an employee
func (a *AdminUserSearchResult) IsEmployee() bool {
	return a.RoleType == RoleTypeEmployee
}

// IsManager checks if the admin is a manager
func (a *AdminUserSearchResult) IsManager() bool {
	return a.RoleType == RoleTypeManager
}

// IsSuperAdmin checks if the admin is a super admin
func (a *AdminUserSearchResult) IsSuperAdmin() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// GetRoleString returns the string representation of the role
func (a *AdminUserSearchResult) GetRoleString() string {
	switch a.RoleType {
	case RoleTypeSuperAdmin:
		return RoleAdminSuperAdmin
	case RoleTypeManager:
		return RoleAdminManager
	case RoleTypeEmployee:
		return RoleAdminEmployee
	default:
		return ""
	}
}

// AdminWithPermissions represents admin with full permissions and departments
type AdminWithPermissions struct {
	AdminID       uuid.UUID          `json:"admin_id" db:"admin_id"`
	Username      string             `json:"username" db:"username"`
	FullName      string             `json:"full_name" db:"full_name"`
	RoleName      string             `json:"role_name" db:"role_name"`
	RoleLevel     int                `json:"role_level" db:"role_level"`
	RoleType      int                `json:"role_type" db:"role_type"`
	Permissions   []Permission       `json:"permissions"`
	Departments   []SystemDepartment `json:"departments"`
	ReportsTo     *uuid.UUID         `json:"reports_to,omitempty" db:"reports_to"`
	ReportsToName string             `json:"reports_to_name,omitempty" db:"reports_to_name"`
	IsActive      bool               `json:"is_active" db:"is_active"`
	LastLogin     *time.Time         `json:"last_login,omitempty" db:"last_login"`
}

// IsOwner checks if the admin is a super admin (owner)
func (a *AdminWithPermissions) IsOwner() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// IsSuperEmployee checks if the admin is a manager (super employee)
func (a *AdminWithPermissions) IsSuperEmployee() bool {
	return a.RoleType == RoleTypeManager
}

// IsEmployee checks if the admin is an employee
func (a *AdminWithPermissions) IsEmployee() bool {
	return a.RoleType == RoleTypeEmployee
}

// IsManager checks if the admin is a manager
func (a *AdminWithPermissions) IsManager() bool {
	return a.RoleType == RoleTypeManager
}

// IsSuperAdmin checks if the admin is a super admin
func (a *AdminWithPermissions) IsSuperAdmin() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// GetRoleString returns the string representation of the role
func (a *AdminWithPermissions) GetRoleString() string {
	switch a.RoleType {
	case RoleTypeSuperAdmin:
		return RoleAdminSuperAdmin
	case RoleTypeManager:
		return RoleAdminManager
	case RoleTypeEmployee:
		return RoleAdminEmployee
	default:
		return ""
	}
}

type AdminUserSearchRequest struct {
	Query           string `json:"query"`
	RoleTypeFilter  *int   `json:"role_type_filter"`
	IncludeInactive bool   `json:"include_inactive"`
	SearchType      string `json:"search_type"`
	Limit           int    `json:"limit"`
	Offset          int    `json:"offset"`
}

// AdminRole represents an admin role
type AdminRole struct {
	AdminRoleID  uuid.UUID `json:"admin_role_id" db:"admin_role_id"`
	RoleName     string    `json:"role_name" db:"role_name"`
	RoleLevel    int       `json:"role_level" db:"role_level"`
	RoleType     int       `json:"role_type" db:"role_type"` // 1=Employee, 2=Manager, 4=Super Admin
	IsSystemRole bool      `json:"is_system_role" db:"is_system_role"`
	Description  string    `json:"description" db:"description"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// AdminHierarchy represents admin hierarchy structure
type AdminHierarchy struct {
	AdminID   uuid.UUID `json:"admin_id" db:"admin_id"`
	Username  string    `json:"username" db:"username"`
	FullName  string    `json:"full_name" db:"full_name"`
	RoleType  int       `json:"role_type" db:"role_type"`
	ReportsTo uuid.UUID `json:"reports_to" db:"reports_to"`
	Level     int       `json:"level" db:"level"`
	IsActive  bool      `json:"is_active" db:"is_active"`
}

// AdminSearchRequest represents admin search request
type AdminSearchRequest struct {
	Query           string `json:"query"`
	RoleTypeFilter  *int   `json:"role_type_filter,omitempty"`
	IncludeInactive bool   `json:"include_inactive"`
	SearchType      string `json:"search_type"` // "autocomplete" or "fulltext"
	Limit           int    `json:"limit"`
	Offset          int    `json:"offset"`
}

// AdminSearchFilter - For advanced filtering
type AdminSearchFilter struct {
	RoleID          *uuid.UUID `json:"role_id,omitempty"`
	DepartmentID    *uuid.UUID `json:"department_id,omitempty"`
	ReportsTo       *uuid.UUID `json:"reports_to,omitempty"`
	CreatedAfter    *time.Time `json:"created_after,omitempty"`
	CreatedBefore   *time.Time `json:"created_before,omitempty"`
	LastLoginAfter  *time.Time `json:"last_login_after,omitempty"`
	LastLoginBefore *time.Time `json:"last_login_before,omitempty"`
	HasAvatar       *bool      `json:"has_avatar,omitempty"`
	IPWhitelist     *string    `json:"ip_whitelist,omitempty"`
	DataAccessScope *string    `json:"data_access_scope,omitempty"`
}

// AdminAdvancedSearchRequest - Advanced search with multiple filters
type AdminAdvancedSearchRequest struct {
	Query           string            `json:"query,omitempty"`
	Filters         AdminSearchFilter `json:"filters,omitempty"`
	IncludeInactive bool              `json:"include_inactive,omitempty"` // Add this
	SortBy          string            `json:"sort_by,omitempty"`          // "username", "full_name", "created_at", "last_login", "role_type"
	SortOrder       string            `json:"sort_order,omitempty"`       // "asc", "desc"
	Limit           int               `json:"limit,omitempty"`
	Offset          int               `json:"offset,omitempty"`
}

// AdminSuggestion represents admin suggestion for autocomplete
type AdminSuggestion struct {
	AdminID       uuid.UUID  `json:"admin_id" db:"admin_id"`
	Username      string     `json:"username" db:"username"`
	FullName      string     `json:"full_name" db:"full_name"`
	RoleName      string     `json:"role_name" db:"role_name"`
	RoleLevel     int        `json:"role_level" db:"role_level"`
	RoleType      int        `json:"role_type" db:"role_type"`
	ReportsTo     *uuid.UUID `json:"reports_to,omitempty" db:"reports_to"`
	ReportsToName string     `json:"reports_to_name,omitempty" db:"reports_to_name"`
	Relevance     float64    `json:"relevance" db:"relevance"`
}

// IsOwner checks if the admin is a super admin (owner)
func (a *AdminSuggestion) IsOwner() bool {
	return a.RoleType == RoleTypeSuperAdmin
}

// IsSuperEmployee checks if the admin is a manager (super employee)
func (a *AdminSuggestion) IsSuperEmployee() bool {
	return a.RoleType == RoleTypeManager
}

// IsEmployee checks if the admin is an employee
func (a *AdminSuggestion) IsEmployee() bool {
	return a.RoleType == RoleTypeEmployee
}

// GetRoleString returns the string representation of the role
func (a *AdminSuggestion) GetRoleString() string {
	switch a.RoleType {
	case RoleTypeSuperAdmin:
		return RoleAdminSuperAdmin
	case RoleTypeManager:
		return RoleAdminManager
	case RoleTypeEmployee:
		return RoleAdminEmployee
	default:
		return ""
	}
}

// AdminCreateRequest represents admin creation request
type AdminCreateRequest struct {
	Username        string     `json:"username" validate:"required,min=3,max=100"`
	FullName        string     `json:"full_name" validate:"required,max=255"`
	PhoneNumber     string     `json:"phone_number" validate:"required"` // Changed from PhoneHash
	AdminRoleID     uuid.UUID  `json:"admin_role_id" validate:"required"`
	RoleType        int        `json:"role_type" validate:"required,oneof=1 2 4"`
	ReportsTo       *uuid.UUID `json:"reports_to,omitempty"`
	DataAccessScope []string   `json:"data_access_scope,omitempty"`
	IPWhitelist     []string   `json:"ip_whitelist,omitempty"`
}

// AdminProfileUpdateRequest represents admin profile update request
type AdminProfileUpdateRequest struct {
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=100"`
	FullName string `json:"full_name,omitempty" validate:"omitempty,max=255"`
}

// AdminUpdateRequest represents admin update request
type AdminUpdateRequest struct {
	Username        *string    `json:"username,omitempty" validate:"omitempty,min=3,max=100"`
	FullName        *string    `json:"full_name,omitempty" validate:"omitempty,max=255"`
	AdminRoleID     *uuid.UUID `json:"admin_role_id,omitempty"`
	RoleType        *int       `json:"role_type,omitempty" validate:"omitempty,oneof=1 2 4"`
	ReportsTo       *uuid.UUID `json:"reports_to,omitempty"`
	IsActive        *bool      `json:"is_active,omitempty"`
	DataAccessScope []string   `json:"data_access_scope,omitempty"`
	IPWhitelist     []string   `json:"ip_whitelist,omitempty"`
}

type SystemDepartment struct {
	SystemDepartmentID uuid.UUID `json:"system_department_id"`
	Name               string    `json:"name"`
	ModuleCode         string    `json:"module_code"`
	Description        string    `json:"description"`
	Bitmask            uint64    `json:"bitmask"`
}

// AdminRoleCreateRequest represents admin role creation request
type AdminRoleCreateRequest struct {
	RoleName      string      `json:"role_name" validate:"required"`
	RoleType      int         `json:"role_type" validate:"required,oneof=1 2 4"`
	DepartmentIDs []uuid.UUID `json:"department_ids" validate:"required,min=1"`
	Description   string      `json:"description"`
}

type AdminRoleUpdateRequest struct {
	RoleName           *string  `json:"role_name,omitempty"`
	Description        *string  `json:"description,omitempty"`
	AddDepartments     []string `json:"add_departments,omitempty"`    // Changed from []uuid.UUID to []string
	RemoveDepartments  []string `json:"remove_departments,omitempty"` // Changed from []uuid.UUID to []string
	AddPermissions     []string `json:"add_permissions,omitempty"`
	RemovePermissions  []string `json:"remove_permissions,omitempty"`
	ReplacePermissions []string `json:"replace_permissions,omitempty"`
}

// models.go - Add these new structs

// DepartmentPermission represents department with specific permissions
type DepartmentPermission struct {
	DepartmentName string   `json:"department_name" validate:"required"`
	Permissions    []string `json:"permissions" validate:"required,min=1"`
}

// EmployeeRoleCreateRequest represents employee role creation request
type EmployeeRoleCreateRequest struct {
	RoleName              string                 `json:"role_name" validate:"required"`
	DepartmentPermissions []DepartmentPermission `json:"department_permissions" validate:"required,min=1"`
	Description           string                 `json:"description"`
}

// ManagerRoleCreateRequest represents manager role creation request
type ManagerRoleCreateRequest struct {
	RoleName        string   `json:"role_name" validate:"required"`
	DepartmentNames []string `json:"department_names" validate:"required,min=1"`
	Description     string   `json:"description"`
}
