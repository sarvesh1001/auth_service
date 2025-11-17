package models

import (
	"time"

	"github.com/google/uuid"
)

// =========================================================
// USERS
// =========================================================

type User struct {
	UserID            uuid.UUID  `db:"user_id" json:"user_id"`
	PhoneHash         string     `db:"phone_hash" json:"phone_hash"`
	PhoneEncrypted    []byte     `db:"phone_encrypted" json:"phone_encrypted"`
	PhoneEncryptedDEK string     `db:"phone_encrypted_dek" json:"phone_encrypted_dek"`
	PhoneKeyID        uuid.UUID  `db:"phone_key_id" json:"phone_key_id"`
	DeviceID          string     `db:"device_id" json:"device_id"`
	DeviceFingerprint string     `db:"device_fingerprint" json:"device_fingerprint"`
	KYCStatus         string     `db:"kyc_status" json:"kyc_status"`
	KYCLevel          string     `db:"kyc_level" json:"kyc_level"`
	KYCVerifiedAt     *time.Time `db:"kyc_verified_at" json:"kyc_verified_at,omitempty"`
	IsVerified        bool       `db:"is_verified" json:"is_verified"`
	IsActive          bool       `db:"is_active" json:"is_active"`
	DataRegion        string     `db:"data_region" json:"data_region"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at" json:"updated_at"`
	LastLogin         *time.Time `db:"last_login" json:"last_login,omitempty"`
}

type UserStatusUpdate struct {
	UserID     uuid.UUID `db:"user_id"`
	IsVerified bool      `db:"is_verified"`
	IsActive   bool      `db:"is_active"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// UserDevice represents a device belonging to a user
type UserDevice struct {
	DeviceID   string    `db:"device_id" json:"device_id"`
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	DeviceType string    `db:"device_type" json:"device_type"`
	DeviceName string    `db:"device_name" json:"device_name"`
	OSVersion  string    `db:"os_version" json:"os_version"`
	AppVersion string    `db:"app_version" json:"app_version"`
	LastActive time.Time `db:"last_active" json:"last_active"`
	IsActive   bool      `db:"is_active" json:"is_active"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

type LoginAttempt struct {
	AttemptID     uuid.UUID `db:"attempt_id" json:"attempt_id"`
	UserID        uuid.UUID `db:"user_id" json:"user_id"`
	Success       bool      `db:"success" json:"success"`
	IPAddress     string    `db:"ip_address" json:"ip_address"`
	UserAgent     string    `db:"user_agent" json:"user_agent"`
	DeviceID      string    `db:"device_id" json:"device_id"`
	AttemptedAt   time.Time `db:"attempted_at" json:"attempted_at"`
	FailureReason string    `db:"failure_reason" json:"failure_reason,omitempty"`
}

type UserSearchFilters struct {
	PhoneHash      string    `json:"phone_hash,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	KYCStatus      string    `json:"kyc_status,omitempty"`
	DataRegion     string    `json:"data_region,omitempty"`
	IsVerified     *bool     `json:"is_verified,omitempty"`
	IsActive       *bool     `json:"is_active,omitempty"`
	CreatedAfter   time.Time `json:"created_after,omitempty"`
	CreatedBefore  time.Time `json:"created_before,omitempty"`
	LastLoginAfter time.Time `json:"last_login_after,omitempty"`
}

type UserGrowthMetrics struct {
	TotalUsers         int            `json:"total_users"`
	ActiveUsers        int            `json:"active_users"`
	NewUsers           int            `json:"new_users"`
	VerifiedUsers      int            `json:"verified_users"`
	KYCDistribution    map[string]int `json:"kyc_distribution"`
	RegionDistribution map[string]int `json:"region_distribution"`
	GrowthRate         float64        `json:"growth_rate"`
}

// =========================================================
// COMPANIES
// =========================================================

type Company struct {
	CompanyID             uuid.UUID  `db:"company_id" json:"company_id"`
	CompanyName           string     `db:"company_name" json:"company_name"`
	OwnerUserID           uuid.UUID  `db:"owner_user_id" json:"owner_user_id"`
	SubscriptionTier      string     `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus    string     `db:"subscription_status" json:"subscription_status"`
	MaxEmployees          int        `db:"max_employees" json:"max_employees"`
	DataRegion            string     `db:"data_region" json:"data_region"`
	IsActive              bool       `db:"is_active" json:"is_active"`
	CreatedAt             time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time  `db:"updated_at" json:"updated_at"`
	SubscriptionStartDate *time.Time `db:"subscription_start_date" json:"subscription_start_date,omitempty"`
	SubscriptionEndDate   *time.Time `db:"subscription_end_date" json:"subscription_end_date,omitempty"`
}

// =========================================================
// PERMISSIONS
// =========================================================

type Permission struct {
	PermissionID   uuid.UUID `db:"permission_id" json:"permission_id"`
	PermissionName string    `db:"permission_name" json:"permission_name"`
	Description    string    `db:"description" json:"description"`
	Category       string    `db:"category" json:"category"`
	Module         string    `db:"module" json:"module"`
	RequiresTier   string    `db:"requires_tier" json:"requires_tier"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

// =========================================================
// ROLES
// =========================================================

type Role struct {
	RoleID       uuid.UUID `db:"role_id" json:"role_id"`
	RoleName     string    `db:"role_name" json:"role_name"`
	RoleLevel    int       `db:"role_level" json:"role_level"`
	CompanyID    uuid.UUID `db:"company_id" json:"company_id"`
	IsSystemRole bool      `db:"is_system_role" json:"is_system_role"`
	Description  string    `db:"description" json:"description"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
}

type RolePermission struct {
	RoleID       uuid.UUID `db:"role_id" json:"role_id"`
	PermissionID uuid.UUID `db:"permission_id" json:"permission_id"`
	GrantedAt    time.Time `db:"granted_at" json:"granted_at"`
	GrantedBy    uuid.UUID `db:"granted_by" json:"granted_by"`
}

// NEW: Role ↔ Department mapping
type RoleDepartment struct {
	RoleID       uuid.UUID `db:"role_id" json:"role_id"`
	DepartmentID uuid.UUID `db:"department_id" json:"department_id"`
}

// NEW: Role with permissions
type RoleWithPermissions struct {
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
}

// =========================================================
// DEPARTMENTS
// =========================================================

// Matches system_departments table EXACTLY
type SystemDepartment struct {
	SystemDepartmentID uuid.UUID `json:"system_department_id" db:"system_department_id"`
	Name               string    `json:"name" db:"name"`
	ModuleCode         string    `json:"module_code" db:"module_code"`
	Description        string    `json:"description" db:"description"`
}

type Department struct {
	DepartmentID       uuid.UUID  `json:"department_id" db:"department_id"`
	CompanyID          uuid.UUID  `json:"company_id" db:"company_id"`
	DepartmentName     string     `json:"department_name" db:"department_name"`
	SystemDepartmentID *uuid.UUID `json:"system_department_id" db:"system_department_id"`
	DepartmentHead     *uuid.UUID `json:"department_head" db:"department_head"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id" db:"parent_department_id"`
	IsActive           bool       `json:"is_active" db:"is_active"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`

	// Joined fields (not actual db columns)
	SystemDepartmentName string `json:"system_department_name,omitempty" db:"-"`
	ModuleCode           string `json:"module_code,omitempty" db:"-"`
}

// NEW: Department with roles
type DepartmentWithRoles struct {
	Department Department  `json:"department"`
	RoleIDs    []uuid.UUID `json:"role_ids"`
}

// =========================================================
// COMPANY EMPLOYEES
// =========================================================

type CompanyEmployee struct {
	CompanyID    uuid.UUID  `db:"company_id" json:"company_id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	EmployeeID   string     `db:"employee_id" json:"employee_id"`
	RoleID       uuid.UUID  `db:"role_id" json:"role_id"`
	DepartmentID *uuid.UUID `db:"department_id" json:"department_id,omitempty"`
	HireDate     time.Time  `db:"hire_date" json:"hire_date"`
	IsActive     bool       `db:"is_active" json:"is_active"`
	ReportsTo    *uuid.UUID `db:"reports_to" json:"reports_to,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}
type EmployeeHierarchy struct {
	CompanyID    uuid.UUID  `json:"company_id"`
	UserID       uuid.UUID  `json:"user_id"`
	EmployeeID   string     `json:"employee_id"`
	RoleName     string     `json:"role_name"`
	RoleLevel    int        `json:"role_level"`
	DepartmentID *uuid.UUID `json:"department_id"`
	Department   string     `json:"department"`
	ReportsTo    *uuid.UUID `json:"reports_to"`
	IsActive     bool       `json:"is_active"`
}

// =========================================================
// PERMISSION CHECK RESULT
// =========================================================

type PermissionCheckResult struct {
	HasPermission bool            `json:"has_permission"`
	Checks        map[string]bool `json:"checks"`
	Message       string          `json:"message,omitempty"`
}

// =========================================================
// ENUM CONSTANTS
// =========================================================

const (
	KYCStatusPending     = "pending"
	KYCStatusVerified    = "verified"
	KYCStatusRejected    = "rejected"
	KYCStatusUnderReview = "under_review"
	KYCStatusExpired     = "expired"
)

const (
	KYCLevelBasic    = "basic"
	KYCLevelAdvanced = "advanced"
	KYCLevelFull     = "full"
)

const (
	SubscriptionTierBasic      = "basic"
	SubscriptionTierPremium    = "premium"
	SubscriptionTierEnterprise = "enterprise"
)

const (
	SubscriptionStatusActive   = "active"
	SubscriptionStatusInactive = "inactive"
	SubscriptionStatusPending  = "pending"
	SubscriptionStatusEnded    = "ended"
)

const (
	RoleLevelOwner   = 100
	RoleLevelManager = 200
	RoleLevelUser    = 300
	RoleLevelViewer  = 400
)

const (
	DataRegionUS = "us"
	DataRegionEU = "eu"
	DataRegionAS = "as"
)
